#ifndef _BINDER_COMPAT_H
#define _BINDER_COMPAT_H

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/atomic.h>

/* mmgrab: atomic_inc(&mm->mm_count) */
static inline void mmgrab(struct mm_struct *mm)
{
	atomic_inc(&mm->mm_count);
}

/* mmget_not_zero: atomic_inc_not_zero(&mm->mm_users) */
static inline int mmget_not_zero(struct mm_struct *mm)
{
	return atomic_inc_not_zero(&mm->mm_users);
}

/* mmput_async: just map to mmput for now */
#define mmput_async mmput

/* zap_page_range compat wrapper */
static inline void binder_zap_page_range(struct vm_area_struct *vma,
					 unsigned long address,
					 unsigned long size)
{
	zap_page_range(vma, address, size, NULL);
}
#define zap_page_range binder_zap_page_range

/* refcount compat */
typedef atomic_t refcount_t;

static inline void refcount_set(refcount_t *r, int n)
{
	atomic_set(r, n);
}

static inline unsigned int refcount_read(const refcount_t *r)
{
	return atomic_read(r);
}

static inline void refcount_inc(refcount_t *r)
{
	atomic_inc(r);
}

static inline bool refcount_dec_and_test(refcount_t *r)
{
	return atomic_dec_and_test(r);
}

/* API compat */
#define ANDROID_VENDOR_DATA(x) 
#define trace_android_vh_binder_set_priority(t, task)
#define trace_android_vh_binder_transaction_init(t)
#define trace_android_vh_binder_restore_priority(in_reply_to, current)

#define strscpy strlcpy

typedef unsigned int __poll_t;
typedef int vm_fault_t;

#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
};


#define MAX_USER_RT_PRIO 100
#define MAX_RT_PRIO MAX_USER_RT_PRIO
#define MAX_PRIO (MAX_RT_PRIO + 40)
#define DEFAULT_PRIO (MAX_RT_PRIO + 20)

#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)
#define USER_PRIO(p)		((p)-MAX_RT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
#define MAX_NICE	19
#define MIN_NICE	-20

static inline long rlimit_to_nice(long rlim_cur)
{
	return 20 - rlim_cur;
}

#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/poll.h>
#include <uapi/linux/eventpoll.h>

#ifndef EPOLLIN
#define EPOLLIN 0x00000001
#endif
#ifndef EPOLLHUP
#define EPOLLHUP 0x00000010
#endif
#ifndef POLLFREE
#define POLLFREE 0x4000 /* from older releases, or internal? */
/* Actually POLLFREE is 0x4000 in asm/poll.h in newer kernels. Check value. */
#define POLLFREE 0x4000
#endif

static inline int __close_fd_get_file(unsigned int fd, struct file **res)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return -ENOENT;

	/* In 3.10 we don't have atomic close_fd_get_file, so this is racy but best effort compat */
	sys_close(fd);
	*res = file;
	return 0;
}

#endif /* _BINDER_COMPAT_H */
