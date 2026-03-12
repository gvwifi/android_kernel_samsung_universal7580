/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook
 * Minimal BTF backport for kernel 3.10
 */
#ifndef _LINUX_BTF_H
#define _LINUX_BTF_H 1

#include <linux/types.h>
#include <linux/refcount.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>

struct btf {
	void *data;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct rcu_head rcu;
};

/* Functions exported by kernel/bpf/btf.c */
int btf_new_fd(const union bpf_attr *attr);
struct btf *btf_get_by_fd(int fd);
int btf_get_fd_by_id(u32 id);
void btf_put(struct btf *btf);
int btf_get_info_by_fd(const struct btf *btf,
		       const union bpf_attr *attr,
		       union bpf_attr __user *uattr);

#endif
