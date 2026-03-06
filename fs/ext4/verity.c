// SPDX-License-Identifier: GPL-2.0
/*
 * fs/ext4/verity.c: fs-verity support for ext4
 *
 * Copyright 2019 Google LLC
 */

/*
 * Implementation of fsverity_operations for ext4.
 *
 * ext4 stores the verity metadata (Merkle tree and fsverity_descriptor) past
 * the end of the file, starting at the first 64K boundary beyond i_size.  This
 * approach works because (a) verity files are readonly, and (b) pages fully
 * beyond i_size aren't visible to userspace but can be read/written internally
 * by ext4 with only some relatively small changes to ext4.  This approach
 * avoids having to depend on the EA_INODE feature and on rearchitecturing
 * ext4's xattr support to support paging multi-gigabyte xattrs into memory, and
 * to support encrypting xattrs.  Note that the verity metadata *must* be
 * encrypted when the file is, since it contains hashes of the plaintext data.
 *
 * Using a 64K boundary rather than a 4K one keeps things ready for
 * architectures with 64K pages, and it doesn't necessarily waste space on-disk
 * since there can be a hole between i_size and the start of the Merkle tree.
 */

#include <linux/quotaops.h>

#include "ext4.h"
#include "ext4_extents.h"
#include <linux/fsverity.h>
#include <linux/radix-tree.h>
#include "ext4.h"
#include "ext4_extents.h"
#include "ext4_jbd2.h"

static inline bool ext4_verity_in_progress(struct inode *inode)
{
	return ext4_test_inode_state(inode, EXT4_STATE_VERITY_IN_PROGRESS);
}

static inline loff_t ext4_verity_metadata_pos(const struct inode *inode)
{
	/*
	 * When verity is being enabled, use the cached original data size
	 * rather than the live i_size.  On kernel 3.10, ext4_write_end()
	 * extends i_size every time a Merkle tree block is written past EOF.
	 * This causes the metadata base position to shift with every write,
	 * scattering Merkle tree blocks across the disk at ~65KB intervals
	 * instead of contiguously, corrupting the tree and the filesystem.
	 */
	if (ext4_test_inode_state((struct inode *)inode,
				  EXT4_STATE_VERITY_IN_PROGRESS))
		return round_up(EXT4_I((struct inode *)inode)->i_verity_data_size,
				65536);
	return round_up(inode->i_size, 65536);
}

/*
 * Read some verity metadata from the inode.  __vfs_read() can't be used because
 * we need to read beyond i_size.
 */
static int pagecache_read(struct inode *inode, void *buf, size_t count,
			  loff_t pos)
{
	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct page *page;
		void *addr;

		page = read_mapping_page(inode->i_mapping, pos >> PAGE_SHIFT,
					 NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);

		addr = kmap_atomic(page);
		memcpy(buf, addr + offset_in_page(pos), n);
		kunmap_atomic(addr);

		put_page(page);

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

/*
 * Write some verity metadata to the inode for FS_IOC_ENABLE_VERITY.
 * kernel_write() can't be used because the file descriptor is readonly.
 */
static int pagecache_write(struct inode *inode, const void *buf, size_t count,
			   loff_t pos)
{
	if (pos + count > inode->i_sb->s_maxbytes)
		return -EFBIG;

	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct page *page;
		void *fsdata;
		void *addr;
		int res;

		res = pagecache_write_begin(NULL, inode->i_mapping, pos, n, 0,
					    &page, &fsdata);
		if (res)
			return res;

		addr = kmap_atomic(page);
		memcpy(addr + offset_in_page(pos), buf, n);
		kunmap_atomic(addr);

		res = pagecache_write_end(NULL, inode->i_mapping, pos, n, n,
					  page, fsdata);
		if (res < 0)
			return res;
		if (res != n)
			return -EIO;

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

static int ext4_begin_enable_verity(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for ext4_orphan_add() */
	handle_t *handle;
	int err;

	if (ext4_verity_in_progress(inode))
		return -EBUSY;

	/*
	 * Since the file was opened readonly, we have to initialize the jbd
	 * inode and quotas here and not rely on ->open() doing it.  This must
	 * be done before evicting the inline data.
	 */

	if (!EXT4_I(inode)->jinode) {
		struct jbd2_inode *jinode = jbd2_alloc_inode(GFP_KERNEL);
		if (!jinode)
			return -ENOMEM;
		if (cmpxchg(&EXT4_I(inode)->jinode, NULL, jinode)) {
			jbd2_free_inode(jinode);
		} else {
			jbd2_journal_init_jbd_inode(EXT4_I(inode)->jinode, inode);
		}
	}

	dquot_initialize(inode);

	err = ext4_convert_inline_data(inode);
	if (err)
		return err;

	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		ext4_warning(inode->i_sb,
			     "verity is only allowed on extent-based files");
		return -EOPNOTSUPP;
	}

	/*
	 * ext4 uses the last allocated block to find the verity descriptor, so
	 * we must remove any other blocks past EOF which might confuse things.
	 */
	ext4_truncate(inode);

	/*
	 * Cache the original data size before any Merkle tree writes can
	 * inflate i_size via ext4_write_end() on this 3.10 kernel.
	 */
	EXT4_I(inode)->i_verity_data_size = inode->i_size;

	handle = ext4_journal_start(inode, EXT4_HT_INODE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = ext4_orphan_add(handle, inode);
	if (err == 0)
		ext4_set_inode_state(inode, EXT4_STATE_VERITY_IN_PROGRESS);

	ext4_journal_stop(handle);
	return err;
}

/*
 * ext4 stores the verity descriptor beginning on the next filesystem block
 * boundary after the Merkle tree.  Then, the descriptor size is stored in the
 * last 4 bytes of the last allocated filesystem block --- which is either the
 * block in which the descriptor ends, or the next block after that if there
 * weren't at least 4 bytes remaining.
 *
 * We can't simply store the descriptor in an xattr because it *must* be
 * encrypted when ext4 encryption is used, but ext4 encryption doesn't encrypt
 * xattrs.  Also, if the descriptor includes a large signature blob it may be
 * too large to store in an xattr without the EA_INODE feature.
 */
static int ext4_write_verity_descriptor(struct inode *inode, const void *desc,
					size_t desc_size, u64 merkle_tree_size)
{
	const u64 desc_pos = round_up(ext4_verity_metadata_pos(inode) +
				      merkle_tree_size, (1 << inode->i_blkbits));
	const u64 desc_end = desc_pos + desc_size;
	const __le32 desc_size_disk = cpu_to_le32(desc_size);
	const u64 desc_size_pos = round_up(desc_end + sizeof(desc_size_disk),
					   (1 << inode->i_blkbits)) -
				  sizeof(desc_size_disk);
	int err;

	err = pagecache_write(inode, desc, desc_size, desc_pos);
	if (err)
		return err;

	return pagecache_write(inode, &desc_size_disk, sizeof(desc_size_disk),
			       desc_size_pos);
}

static int ext4_end_enable_verity(struct file *filp, const void *desc,
				  size_t desc_size, u64 merkle_tree_size)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for ext4_orphan_del() */
	handle_t *handle;
	int err = 0;
	int err2;

	if (desc != NULL) {
		/* Succeeded; write the verity descriptor. */
		err = ext4_write_verity_descriptor(inode, desc, desc_size,
						   merkle_tree_size);

		/* Write all pages before clearing VERITY_IN_PROGRESS. */
		if (!err)
			err = filemap_write_and_wait(inode->i_mapping);

		/*
		 * Force a journal commit to ensure all delayed-alloc block
		 * allocations (extent tree updates, block bitmap, etc.) for
		 * the Merkle tree and descriptor are committed to disk BEFORE
		 * we proceed to set EXT4_INODE_VERITY on the inode.
		 *
		 * Without this, a crash or reboot between the DA transaction
		 * and the VERITY-flag transaction leaves the inode claiming
		 * S_VERITY without the verity metadata extents in the extent
		 * tree, causing ext4_get_verity_descriptor_location to find the
		 * wrong (last data) extent and return desc_size=0 → -EUCLEAN.
		 */
		if (!err && EXT4_SB(inode->i_sb)->s_journal)
			err = ext4_force_commit(inode->i_sb);
	}

	/* If we failed, truncate anything we wrote past i_size. */
	if (desc == NULL || err)
		ext4_truncate(inode);

	/*
	 * On this kernel, pagecache_write through ext4_write_end may have
	 * extended i_size to cover the verity metadata blocks.  Restore i_size
	 * to the original data size (cached in i_verity_data_size by
	 * begin_enable_verity) so that the on-disk inode has the correct value.
	 * The verity metadata lives past i_size and is found via the last
	 * extent, not via i_size.
	 */
	if (desc != NULL && !err) {
		loff_t data_size = EXT4_I(inode)->i_verity_data_size;

		if (inode->i_size != data_size) {
			i_size_write(inode, data_size);
			EXT4_I(inode)->i_disksize = data_size;
		}
	}

	/*
	 * We must always clean up by clearing EXT4_STATE_VERITY_IN_PROGRESS and
	 * deleting the inode from the orphan list, even if something failed.
	 * If everything succeeded, we'll also set the verity bit in the same
	 * transaction.
	 */

	ext4_clear_inode_state(inode, EXT4_STATE_VERITY_IN_PROGRESS);

	handle = ext4_journal_start(inode, EXT4_HT_INODE, credits);
	if (IS_ERR(handle)) {
		ext4_orphan_del(NULL, inode);
		return PTR_ERR(handle);
	}

	err2 = ext4_orphan_del(handle, inode);
	if (err2)
		goto out_stop;

	if (desc != NULL && !err) {
		struct ext4_iloc iloc;

		err = ext4_reserve_inode_write(handle, inode, &iloc);
		if (err)
			goto out_stop;
		ext4_set_inode_flag(inode, EXT4_INODE_VERITY);
		ext4_set_inode_flags(inode);
		err = ext4_mark_iloc_dirty(handle, inode, &iloc);
	}
out_stop:
	ext4_journal_stop(handle);
	return err ?: err2;
}

static int ext4_get_verity_descriptor_location(struct inode *inode,
					       size_t *desc_size_ret,
					       u64 *desc_pos_ret)
{
	struct ext4_ext_path *path;
	struct ext4_extent *last_extent;
	u32 end_lblk;
	u64 desc_size_pos;
	__le32 desc_size_disk;
	u32 desc_size;
	u64 desc_pos;
	int err;

	/*
	 * Descriptor size is in last 4 bytes of last allocated block.
	 * See ext4_write_verity_descriptor().
	 */

	if (!ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		ext4_warning(inode->i_sb,
			"inode %lu: verity file doesn't use extents",
			inode->i_ino);
		return -EUCLEAN;
	}

	path = ext4_ext_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL);
	if (IS_ERR(path))
		return PTR_ERR(path);
	
	if (!path) {
		ext4_warning(inode->i_sb,
			"inode %lu: ext4_ext_find_extent returned NULL",
			inode->i_ino);
		return -EUCLEAN;
	}

	if (path->p_depth < 0) {
		ext4_warning(inode->i_sb,
			"inode %lu: invalid extent tree depth %d",
			inode->i_ino, path->p_depth);
		kfree(path);
		return -EUCLEAN;
	}

	last_extent = path[path->p_depth].p_ext;
	if (!last_extent) {
		ext4_warning(inode->i_sb,
			"inode %lu: verity file has no extents",
			inode->i_ino);
		ext4_ext_drop_refs(path);
		kfree(path);
		return -EUCLEAN;
	}

	end_lblk = le32_to_cpu(last_extent->ee_block) +
		   ext4_ext_get_actual_len(last_extent);
	desc_size_pos = (u64)end_lblk << inode->i_blkbits;
	ext4_ext_drop_refs(path);
	kfree(path);

	if (desc_size_pos < sizeof(desc_size_disk))
		goto bad;
	desc_size_pos -= sizeof(desc_size_disk);

	err = pagecache_read(inode, &desc_size_disk, sizeof(desc_size_disk),
			     desc_size_pos);
	if (err)
		return err;
	desc_size = le32_to_cpu(desc_size_disk);

	/*
	 * The descriptor is stored just before the desc_size_disk, but starting
	 * on a filesystem block boundary.
	 */

	if (desc_size == 0 || desc_size > INT_MAX || desc_size > desc_size_pos)
		goto bad;

	desc_pos = round_down(desc_size_pos - desc_size, (1 << inode->i_blkbits));
	if (desc_pos < ext4_verity_metadata_pos(inode)) {
		/*
		 * On kernel 3.10, i_size may have been incorrectly extended
		 * to include verity metadata. The descriptor location was
		 * found via the last extent which is always correct. Just
		 * warn and continue - ensure_verity_info will fix i_size.
		 */
		pr_warn("fs-verity: desc_pos %llu < metadata_pos %llu "
			"(i_size may include verity metadata)\n",
			desc_pos, ext4_verity_metadata_pos(inode));
	}

	*desc_size_ret = desc_size;
	*desc_pos_ret = desc_pos;
	return 0;

bad:
	ext4_warning(inode->i_sb,
		"inode %lu: verity descriptor missing or corrupted (S_VERITY set but descriptor unreadable)",
		inode->i_ino);
	return -EUCLEAN;
}

static int ext4_get_verity_descriptor(struct inode *inode, void *buf,
				      size_t buf_size)
{
	size_t desc_size = 0;
	u64 desc_pos = 0;
	int err;

	err = ext4_get_verity_descriptor_location(inode, &desc_size, &desc_pos);
	if (err)
		return err;

	if (buf_size) {
		if (desc_size > buf_size)
			return -ERANGE;
		err = pagecache_read(inode, buf, desc_size, desc_pos);
		if (err)
			return err;
	}
	return desc_size;
}

/*
 * Prefetch some pages from the file's Merkle tree.
 *
 * This is basically a stripped-down version of __do_page_cache_readahead()
 * which works on pages past i_size.
 */
static void ext4_merkle_tree_readahead(struct address_space *mapping,
				       pgoff_t start_index, unsigned long count)
{
	LIST_HEAD(pages);
	unsigned int nr_pages = 0;
	struct page *page;
	pgoff_t index;
	struct blk_plug plug;

	for (index = start_index; index < start_index + count; index++) {
		rcu_read_lock();
		page = radix_tree_lookup(&mapping->page_tree, index);
		rcu_read_unlock();
		if (!page) {
			page = __page_cache_alloc(mapping_gfp_mask(mapping) | __GFP_COLD | __GFP_NORETRY | __GFP_NOWARN);
			if (!page)
				break;
			page->index = index;
			list_add(&page->lru, &pages);
			nr_pages++;
		}
	}
	blk_start_plug(&plug);
	ext4_mpage_readpages(mapping, &pages, NULL, nr_pages);
	blk_finish_plug(&plug);
}

static struct page *ext4_read_merkle_tree_page(struct inode *inode,
					       pgoff_t index,
					       unsigned long num_ra_pages)
{
	struct page *page;

	index += ext4_verity_metadata_pos(inode) >> PAGE_SHIFT;

	page = find_get_page_flags(inode->i_mapping, index, FGP_ACCESSED);
	if (!page || !PageUptodate(page)) {
		if (page)
			put_page(page);
		else if (num_ra_pages > 1)
			ext4_merkle_tree_readahead(inode->i_mapping, index,
						   num_ra_pages);
		page = read_mapping_page(inode->i_mapping, index, NULL);
	}
	return page;
}

static int ext4_write_merkle_tree_block(struct inode *inode, const void *buf,
					u64 index, int log_blocksize)
{
	loff_t pos = ext4_verity_metadata_pos(inode) + (index << log_blocksize);

	return pagecache_write(inode, buf, 1 << log_blocksize, pos);
}

const struct fsverity_operations ext4_verityops = {
	.begin_enable_verity	= ext4_begin_enable_verity,
	.end_enable_verity	= ext4_end_enable_verity,
	.get_verity_descriptor	= ext4_get_verity_descriptor,
	.read_merkle_tree_page	= ext4_read_merkle_tree_page,
	.write_merkle_tree_block = ext4_write_merkle_tree_block,
};
