/*
 * memfd_create system call and file sealing support
 *
 * Adapted from Android 4.14 kernel for 3.10.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/hugetlb.h>
#include <linux/shmem_fs.h>
#include <linux/memfd.h>
#include <linux/pagevec.h>
#include <uapi/linux/memfd.h>

/*
 * We need a tag: a new tag would expand every radix_tree_node by 8 bytes,
 * so reuse a tag which we firmly believe is never set or cleared on tmpfs
 * or hugetlbfs because they are memory only filesystems.
 */
#define MEMFD_TAG_PINNED        PAGECACHE_TAG_TOWRITE
#define LAST_SCAN               4       /* about 150ms max */
#define SHMEM_TAG_PINNED        MEMFD_TAG_PINNED

/*
 * Setting SEAL_WRITE requires us to verify there's no pending writer. However,
 * via get_user_pages(), drivers might have some pending I/O without any active
 * user-space mappings (eg., direct-IO, AIO). Therefore, we look at all pages
 * and see whether it has an elevated ref-count. If so, we tag them and wait for
 * them to be dropped.
 * The caller must guarantee that no new user will acquire writable references
 * to those pages to avoid races.
 */
static void memfd_tag_pins(struct address_space *mapping)
{
	struct pagevec pvec;
	pgoff_t indices[PAGEVEC_SIZE];
	pgoff_t index = 0;
	int i;

	lru_add_drain();
	pagevec_init(&pvec, 0);

	while (1) {
		pvec.nr = shmem_find_get_pages_and_swap(mapping, index,
					PAGEVEC_SIZE, pvec.pages, indices);
		if (!pvec.nr)
			break;

		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			index = indices[i];

			if (radix_tree_exceptional_entry(page))
				continue;

			if (page_count(page) - page_mapcount(page) != 2) {
				spin_lock_irq(&mapping->tree_lock);
				radix_tree_tag_set(&mapping->page_tree, index,
						   SHMEM_TAG_PINNED);
				spin_unlock_irq(&mapping->tree_lock);
			}
		}
		
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			if (!radix_tree_exceptional_entry(page))
				page_cache_release(page);
		}
		pvec.nr = 0;
		index++;
		cond_resched();
	}
}

static int mapping_deny_writable(struct address_space *mapping)
{
	int ret = 0;
	mutex_lock(&mapping->i_mmap_mutex);
	if (mapping->i_mmap_writable > 0)
		ret = -EBUSY;
	mutex_unlock(&mapping->i_mmap_mutex);
	return ret;
}

static void mapping_allow_writable(struct address_space *mapping)
{
}

static int memfd_wait_for_pins(struct address_space *mapping)
{
	struct pagevec pvec;
	pgoff_t indices[PAGEVEC_SIZE];
	pgoff_t index = 0;
	int error = 0, scan;

	memfd_tag_pins(mapping);

	for (scan = 0; scan <= LAST_SCAN; scan++) {
		if (!radix_tree_tagged(&mapping->page_tree, SHMEM_TAG_PINNED))
			break;

		if (!scan)
			lru_add_drain_all();
		else if (schedule_timeout_killable((HZ << scan) / 200))
			scan = LAST_SCAN;

		pagevec_init(&pvec, 0);
		index = 0;
		while (1) {
			int i;
			pvec.nr = shmem_find_get_pages_and_swap(mapping, index,
						PAGEVEC_SIZE, pvec.pages, indices);
			if (!pvec.nr)
				break;

			for (i = 0; i < pagevec_count(&pvec); i++) {
				struct page *page = pvec.pages[i];
				index = indices[i];

				if (radix_tree_exceptional_entry(page))
					continue;

				if (page_count(page) - page_mapcount(page) != 2) {
					if (scan < LAST_SCAN)
						goto continue_scan;
					error = -EBUSY;
				}

				spin_lock_irq(&mapping->tree_lock);
				radix_tree_tag_clear(&mapping->page_tree,
						     index, SHMEM_TAG_PINNED);
				spin_unlock_irq(&mapping->tree_lock);
continue_scan:
				;
			}
			/*
			 * shmem_find_get_pages_and_swap includes swap entries,
			 * so we need to handle them or skip them.
			 * The above loop handles exceptional entries.
			 * We need to release pages.
			 */
			for (i = 0; i < pagevec_count(&pvec); i++) {
				struct page *page = pvec.pages[i];
				if (!radix_tree_exceptional_entry(page))
					page_cache_release(page);
			}
			pvec.nr = 0;
			index++;
			cond_resched();
		}
	}

	return error;
}

static unsigned int *memfd_file_seals_ptr(struct file *file)
{
	if (is_shmem_file(file))
		return &SHMEM_I(file_inode(file))->seals;

#ifdef CONFIG_HUGETLBFS
	if (is_file_hugepages(file))
		return &HUGETLBFS_I(file_inode(file))->seals;
#endif

	return NULL;
}

#define F_ALL_SEALS (F_SEAL_SEAL | \
		     F_SEAL_SHRINK | \
		     F_SEAL_GROW | \
		     F_SEAL_WRITE | \
		     F_SEAL_FUTURE_WRITE)

static int memfd_add_seals(struct file *file, unsigned int seals)
{
	struct inode *inode = file_inode(file);
	unsigned int *file_seals;
	int error;

	if (!(file->f_mode & FMODE_WRITE))
		return -EPERM;
	if (seals & ~(unsigned int)F_ALL_SEALS)
		return -EINVAL;

	mutex_lock(&inode->i_mutex);

	file_seals = memfd_file_seals_ptr(file);
	if (!file_seals) {
		error = -EINVAL;
		goto unlock;
	}

	if (*file_seals & F_SEAL_SEAL) {
		error = -EPERM;
		goto unlock;
	}

	if ((seals & F_SEAL_WRITE) && !(*file_seals & F_SEAL_WRITE)) {
		error = mapping_deny_writable(file->f_mapping);
		if (error)
			goto unlock;

		error = memfd_wait_for_pins(file->f_mapping);
		if (error) {
			mapping_allow_writable(file->f_mapping);
			goto unlock;
		}
	}

	*file_seals |= seals;
	error = 0;

unlock:
	mutex_unlock(&inode->i_mutex);
	return error;
}

static int memfd_get_seals(struct file *file)
{
	unsigned int *seals = memfd_file_seals_ptr(file);
	return seals ? *seals : -EINVAL;
}

long memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long error;

	switch (cmd) {
	case F_ADD_SEALS:
		/* disallow upper 32bit */
		if (arg > UINT_MAX)
			return -EINVAL;

		error = memfd_add_seals(file, arg);
		break;
	case F_GET_SEALS:
		error = memfd_get_seals(file);
		break;
	default:
		error = -EINVAL;
		break;
	}

	return error;
}
EXPORT_SYMBOL_GPL(memfd_fcntl);

#define MFD_NAME_PREFIX "memfd:"
#define MFD_NAME_PREFIX_LEN (sizeof(MFD_NAME_PREFIX) - 1)
#define MFD_NAME_MAX_LEN (NAME_MAX - MFD_NAME_PREFIX_LEN)

#define MFD_ALL_FLAGS (MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB)

SYSCALL_DEFINE2(memfd_create,
		const char __user *, uname,
		unsigned int, flags)
{
	unsigned int *file_seals;
	struct file *file;
	int fd, error;
	char *name;
	long len;

	if (!(flags & MFD_HUGETLB)) {
		if (flags & ~(unsigned int)MFD_ALL_FLAGS)
			return -EINVAL;
	} else {
		/* Allow huge page size encoding in flags. */
		if (flags & ~(unsigned int)(MFD_ALL_FLAGS |
				(MFD_HUGE_MASK << MFD_HUGE_SHIFT)))
			return -EINVAL;
	}

	/* length includes terminating zero */
	len = strnlen_user(uname, MFD_NAME_MAX_LEN + 1);
	if (len <= 0)
		return -EFAULT;
	if (len > MFD_NAME_MAX_LEN + 1)
		return -EINVAL;

	name = kmalloc(len + MFD_NAME_PREFIX_LEN, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	strcpy(name, MFD_NAME_PREFIX);
	if (copy_from_user(&name[MFD_NAME_PREFIX_LEN], uname, len)) {
		error = -EFAULT;
		goto err_name;
	}

	/* terminating-zero may have changed after strnlen_user() returned */
	if (name[len + MFD_NAME_PREFIX_LEN - 1]) {
		error = -EFAULT;
		goto err_name;
	}

	fd = get_unused_fd_flags((flags & MFD_CLOEXEC) ? O_CLOEXEC : 0);
	if (fd < 0) {
		error = fd;
		goto err_name;
	}

	if (flags & MFD_HUGETLB) {
		struct user_struct *user = NULL;

		file = hugetlb_file_setup(name, 0, VM_NORESERVE, &user,
					HUGETLB_ANONHUGE_INODE,
					(flags >> MFD_HUGE_SHIFT) &
					MFD_HUGE_MASK);
	} else
		file = shmem_file_setup(name, 0, VM_NORESERVE);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_fd;
	}
	file->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
	file->f_flags |= O_LARGEFILE;

	if (flags & MFD_ALLOW_SEALING) {
		file_seals = memfd_file_seals_ptr(file);
		*file_seals &= ~F_SEAL_SEAL;
	}

	fd_install(fd, file);
	kfree(name);
	return fd;

err_fd:
	put_unused_fd(fd);
err_name:
	kfree(name);
	return error;
}
