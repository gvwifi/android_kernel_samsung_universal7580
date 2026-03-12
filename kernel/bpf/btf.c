/*
 * Minimal BTF (BPF Type Format) support backported for kernel 3.10
 *
 * This provides just enough BTF functionality to satisfy Android's
 * NetBpfLoad which requires BPF_BTF_LOAD to succeed. The BTF blob
 * is stored opaquely without full type verification.
 *
 * Copyright (c) 2018 Facebook (original BTF implementation)
 * Backport/stub by LineageOS for legacy kernel support.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include "bpf_compat.h"
#include <linux/btf.h>
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/idr.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/fcntl.h>

static DEFINE_IDR(btf_idr);
static DEFINE_SPINLOCK(btf_idr_lock);

static void btf_free(struct btf *btf)
{
	kvfree(btf->data);
	kfree(btf);
}

static void btf_free_rcu(struct rcu_head *rcu)
{
	struct btf *btf = container_of(rcu, struct btf, rcu);
	btf_free(btf);
}

void btf_put(struct btf *btf)
{
	if (btf && refcount_dec_and_test(&btf->refcnt)) {
		spin_lock_bh(&btf_idr_lock);
		idr_remove(&btf_idr, btf->id);
		spin_unlock_bh(&btf_idr_lock);
		call_rcu(&btf->rcu, btf_free_rcu);
	}
}

static int btf_alloc_id(struct btf *btf)
{
	int id;

	spin_lock_bh(&btf_idr_lock);
	id = idr_alloc_cyclic(&btf_idr, btf, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		btf->id = id;
	spin_unlock_bh(&btf_idr_lock);

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

/*
 * Minimal BTF header validation. We check the magic number, version,
 * and basic structural consistency but do not verify individual types.
 */
static struct btf *btf_parse(void __user *btf_data, u32 btf_data_size)
{
	struct btf_header hdr;
	struct btf *btf;
	void *data;

	if (btf_data_size < sizeof(struct btf_header))
		return ERR_PTR(-EINVAL);

	if (btf_data_size > (16 * 1024 * 1024))
		return ERR_PTR(-E2BIG);

	if (copy_from_user(&hdr, btf_data, sizeof(hdr)))
		return ERR_PTR(-EFAULT);

	if (hdr.magic != BTF_MAGIC)
		return ERR_PTR(-EINVAL);

	if (hdr.version != BTF_VERSION)
		return ERR_PTR(-EINVAL);

	if (hdr.flags)
		return ERR_PTR(-EINVAL);

	if (hdr.hdr_len < sizeof(struct btf_header))
		return ERR_PTR(-EINVAL);

	btf = kzalloc(sizeof(*btf), GFP_KERNEL);
	if (!btf)
		return ERR_PTR(-ENOMEM);

	data = vmalloc(btf_data_size);
	if (!data) {
		kfree(btf);
		return ERR_PTR(-ENOMEM);
	}

	if (copy_from_user(data, btf_data, btf_data_size)) {
		kvfree(data);
		kfree(btf);
		return ERR_PTR(-EFAULT);
	}

	btf->data = data;
	btf->data_size = btf_data_size;
	refcount_set(&btf->refcnt, 1);

	return btf;
}

static int btf_release(struct inode *inode, struct file *filp)
{
	btf_put(filp->private_data);
	return 0;
}

#ifdef CONFIG_PROC_FS
static int bpf_btf_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct btf *btf = filp->private_data;

	seq_printf(m, "btf_id:\t%u\n", btf->id);
	return 0;
}
#endif

const struct file_operations btf_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_btf_show_fdinfo,
#endif
	.release	= btf_release,
};

static int __btf_new_fd(struct btf *btf)
{
	return anon_inode_getfd("btf", &btf_fops, btf, O_RDONLY | O_CLOEXEC);
}

int btf_new_fd(const union bpf_attr *attr)
{
	struct btf *btf;
	int ret;

	btf = btf_parse(u64_to_user_ptr(attr->btf), attr->btf_size);
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	ret = btf_alloc_id(btf);
	if (ret) {
		btf_free(btf);
		return ret;
	}

	ret = __btf_new_fd(btf);
	if (ret < 0)
		btf_put(btf);

	return ret;
}

struct btf *btf_get_by_fd(int fd)
{
	struct btf *btf;
	struct fd f;

	f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);

	if (f.file->f_op != &btf_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	btf = f.file->private_data;
	refcount_inc(&btf->refcnt);
	fdput(f);

	return btf;
}

int btf_get_fd_by_id(u32 id)
{
	struct btf *btf;
	int fd;

	rcu_read_lock();
	btf = idr_find(&btf_idr, id);
	if (!btf || !refcount_inc_not_zero(&btf->refcnt))
		btf = ERR_PTR(-ENOENT);
	rcu_read_unlock();

	if (IS_ERR(btf))
		return PTR_ERR(btf);

	fd = __btf_new_fd(btf);
	if (fd < 0)
		btf_put(btf);

	return fd;
}

int btf_get_info_by_fd(const struct btf *btf,
		       const union bpf_attr *attr,
		       union bpf_attr __user *uattr)
{
	struct bpf_btf_info __user *uinfo;
	struct bpf_btf_info info;
	u32 info_len, data_len;
	void __user *ubtf;
	int ret = 0;

	uinfo = u64_to_user_ptr(attr->info.info);
	info_len = attr->info.info_len;

	if (info_len < sizeof(info))
		return -EINVAL;
	info_len = min_t(u32, info_len, sizeof(info));

	memset(&info, 0, sizeof(info));

	if (copy_from_user(&info, uinfo, info_len))
		return -EFAULT;

	info.id = btf->id;
	info.btf_size = btf->data_size;

	ubtf = u64_to_user_ptr(info.btf);
	data_len = info.btf_size;
	info.btf_size = btf->data_size;

	if (ubtf && data_len) {
		data_len = min_t(u32, data_len, btf->data_size);
		if (copy_to_user(ubtf, btf->data, data_len))
			return -EFAULT;
	}

	if (copy_to_user(uinfo, &info, info_len))
		return -EFAULT;
	if (put_user(info_len, &uattr->info.info_len))
		return -EFAULT;

	return ret;
}
