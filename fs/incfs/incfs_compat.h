/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INCFS_COMPAT_H
#define _INCFS_COMPAT_H

#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#ifndef inode_lock
#define inode_lock(inode) mutex_lock(&(inode)->i_mutex)
#endif

#ifndef inode_unlock
#define inode_unlock(inode) mutex_unlock(&(inode)->i_mutex)
#endif

#ifndef u64_to_user_ptr
#define u64_to_user_ptr(x) ((void __user *)(uintptr_t)(x))
#endif

#ifndef atomic_read_acquire
#define atomic_read_acquire(v) ({ \
	int __v = atomic_read(v); \
	smp_mb(); \
	__v; \
})
#endif

#ifndef atomic_set_release
#define atomic_set_release(v, i) do { \
	smp_mb(); \
	atomic_set(v, i); \
} while (0)
#endif


#ifndef MODULE_IMPORT_NS
#define MODULE_IMPORT_NS(ns)
#endif

#ifndef __poll_t
typedef unsigned int __poll_t;
#endif

#ifndef d_inode
#define d_inode(dentry) ((dentry)->d_inode)
#endif

#ifndef timespec64
#define timespec64 timespec
#define timespec64_to_timespec(ts) (ts)
#define timespec_to_timespec64(ts) (ts)
#endif

#ifndef cmpxchg_release
#define cmpxchg_release(ptr, old, new) \
({ \
	smp_mb(); \
	cmpxchg(ptr, old, new); \
})
#endif

static inline ssize_t incfs_kernel_read_compat(struct file *file, void *buf, size_t count, loff_t *pos)
{
    int ret = kernel_read(file, *pos, (char *)buf, count);
    if (ret > 0)
        *pos += ret;
    return ret;
}

static inline ssize_t incfs_kernel_write_compat(struct file *file, const void *buf, size_t count, loff_t *pos)
{
    /* 3.10 kernel_write: int kernel_write(struct file *file, const char *buf, size_t count, loff_t pos) */
    /* Note: 3.10 kernel_write takes pos by value, not pointer! And returns int. */
    int ret = kernel_write(file, (const char *)buf, count, *pos);
    if (ret > 0)
        *pos += ret;
    return ret;
}

static inline int incfs_vfs_fallocate_compat(struct file *file, int mode, loff_t offset, loff_t len)
{
    if (file->f_op->fallocate)
        return file->f_op->fallocate(file, mode, offset, len);
    return -EOPNOTSUPP;
}



#ifndef inode_lock_nested
#define inode_lock_nested(inode, subclass) mutex_lock_nested(&(inode)->i_mutex, subclass)
#endif

#ifndef d_really_is_positive
#define d_really_is_positive(d) ((d)->d_inode != NULL)
#endif

#ifndef d_really_is_negative
#define d_really_is_negative(d) ((d)->d_inode == NULL)
#endif

#ifndef SB_ACTIVE
#define SB_ACTIVE MS_ACTIVE
#endif

/* Compatibility wrappers for VFS functions */
static inline int vfs_link_compat(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, struct inode **delegated_inode)
{
    return vfs_link(old_dentry, dir, new_dentry);
}
#define vfs_link(o, d, n, del) vfs_link_compat(o, d, n, del)

static inline int vfs_unlink_compat(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
    return vfs_unlink(dir, dentry);
}
#define vfs_unlink(d, e, del) vfs_unlink_compat(d, e, del)

static inline int vfs_rename_compat(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, struct inode **delegated_inode, unsigned int flags)
{
    /* 3.10 vfs_rename does not support flags or delegated_inode */
    if (flags) return -EINVAL;
    return vfs_rename(old_dir, old_dentry, new_dir, new_dentry);
}
#define vfs_rename(od, oe, nd, ne, del, f) vfs_rename_compat(od, oe, nd, ne, del, f)



/* break_deleg_wait stub */
#define break_deleg_wait(inode) (0)

/* ksys_close replacement */
/* If ksys_close is used for fd, use sys_close if available or stub? */
/* In 3.10, sys_close is defined in syscalls.h. */
#include <linux/syscalls.h>
#define ksys_close(fd) sys_close(fd)

/* bin2hex implementation if missing */
#ifndef bin2hex
static inline char *bin2hex(char *dst, const void *src, size_t count)
{
    const unsigned char *_src = src;
    const char hex_asc[] = "0123456789abcdef";
    while (count--) {
        *dst++ = hex_asc[*_src >> 4];
        *dst++ = hex_asc[*_src & 0xf];
        _src++;
    }
    return dst;
}
#endif

#ifndef EPOLLIN
#define EPOLLIN 0x0001
#endif
#ifndef EPOLLRDNORM
#define EPOLLRDNORM 0x0040
#endif

/* AT_STATX defines stub */
#ifndef STATX_NLINK
#define STATX_NLINK 0
#define AT_STATX_SYNC_AS_STAT 0
#endif

/* vfs_getattr compat */
/* 5.4: int vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags) */
/* 3.10: int vfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat) */
static inline int vfs_getattr_compat(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    return vfs_getattr((struct path *)path, stat);
}
#define vfs_getattr(p, s, r, q) vfs_getattr_compat(p, s, r, q)

#endif /* _INCFS_COMPAT_H */


