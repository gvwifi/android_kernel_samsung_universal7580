// SPDX-License-Identifier: GPL-2.0
/*
 * fs/verity/init.c: fs-verity module initialization and logging
 *
 * Copyright 2019 Google LLC
 */

#include "fsverity_private.h"

#include <linux/ratelimit.h>
#include <linux/sysctl.h>

void fsverity_msg(const struct inode *inode, const char *level,
		  const char *fmt, ...)
{
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	struct va_format vaf;
	va_list args;

	if (!__ratelimit(&rs))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	if (inode)
		printk("%sfs-verity (%s, inode %lu): %pV\n",
		       level, inode->i_sb->s_id, inode->i_ino, &vaf);
	else
		printk("%sfs-verity: %pV\n", level, &vaf);
	va_end(args);
}

#ifdef CONFIG_SYSCTL
/*
 * Create /proc/sys/fs/verity directory.
 * This is needed so that userspace (e.g. odsign) can detect fs-verity support
 * by checking for the existence of /proc/sys/fs/verity.
 * The "supported" sysctl is a read-only entry that always returns 1.
 */
static int fsverity_supported = 1;
static struct ctl_table_header *fsverity_sysctl_header;

static const struct ctl_path fsverity_sysctl_path[] = {
	{ .procname = "fs", },
	{ .procname = "verity", },
	{ }
};

static struct ctl_table fsverity_sysctl_table[] = {
	{
		.procname	= "supported",
		.data		= &fsverity_supported,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static int __init fsverity_sysctl_init(void)
{
	fsverity_sysctl_header = register_sysctl_paths(fsverity_sysctl_path,
						       fsverity_sysctl_table);
	if (!fsverity_sysctl_header) {
		pr_err("fs-verity: sysctl registration failed!\n");
		return -ENOMEM;
	}
	return 0;
}
#else
static inline int __init fsverity_sysctl_init(void)
{
	return 0;
}
#endif /* CONFIG_SYSCTL */

static int __init fsverity_init(void)
{
	int err;

	pr_info("fs-verity: initializing...\n");

	fsverity_check_hash_algs();

	err = fsverity_init_info_cache();
	if (err) {
		pr_err("fs-verity: info cache init failed: %d\n", err);
		return err;
	}

	err = fsverity_init_workqueue();
	if (err) {
		pr_err("fs-verity: workqueue init failed: %d\n", err);
		goto err_exit_info_cache;
	}

	err = fsverity_init_signature();
	if (err) {
		pr_err("fs-verity: signature init failed: %d\n", err);
		goto err_exit_workqueue;
	}

	err = fsverity_sysctl_init();
	if (err) {
		pr_err("fs-verity: sysctl init failed: %d\n", err);
		goto err_exit_signature;
	}

	pr_info("fs-verity: initialized successfully, /proc/sys/fs/verity registered\n");
	return 0;

err_exit_signature:
	/* No fsverity_exit_signature() needed */
err_exit_workqueue:
	fsverity_exit_workqueue();
err_exit_info_cache:
	fsverity_exit_info_cache();
	return err;
}
late_initcall(fsverity_init);
