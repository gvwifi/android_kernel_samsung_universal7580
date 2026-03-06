/*
 * usb_f_fs_init.c - FunctionFS filesystem registration for USB ConfigFS
 *
 * This module registers the FunctionFS filesystem when using USB ConfigFS.
 * When using legacy USB_G_ANDROID (g_ffs.c), that driver calls functionfs_init()
 * directly. But with USB ConfigFS, we need a separate module to register
 * the filesystem.
 *
 * Copyright (C) 2026 LineageOS
 * Based on code by Michal Nazarewicz
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>

/* External functions from f_fs.c */
extern int functionfs_init(void);
extern void functionfs_cleanup(void);

static int __init ffs_fs_init(void)
{
	return functionfs_init();
}

static void __exit ffs_fs_exit(void)
{
	functionfs_cleanup();
}

module_init(ffs_fs_init);
module_exit(ffs_fs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michal Nazarewicz");
MODULE_DESCRIPTION("FunctionFS filesystem registration for USB ConfigFS");
MODULE_ALIAS_FS("functionfs");
