#ifndef _KERNEL_BPF_COMPAT_H
#define _KERNEL_BPF_COMPAT_H

#include <linux/module.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>

char *bin2hex(char *dst, const void *src, size_t count);

/* Missing BPF Registers aliases in 3.10/4.14 transition? */
#ifndef BPF_REG_FP
#define BPF_REG_FP BPF_REG_10
#endif

#ifndef BPF_REG_ARG1
#define BPF_REG_ARG1 BPF_REG_1
#endif

/* Missing QDISC constant from sch_generic.h */
#ifndef QDISC_CB_PRIV_LEN
#define QDISC_CB_PRIV_LEN 20
#endif

/* Missing Helpers */
#ifndef prandom_init_once
static inline void prandom_init_once(void *state) { (void)state; }
#endif

#ifndef INIT_LIST_HEAD_RCU
#define INIT_LIST_HEAD_RCU(list) INIT_LIST_HEAD(list)
#endif

#ifndef TRACE_DEFINE_ENUM
#define TRACE_DEFINE_ENUM(x)
#endif

#ifndef __print_hex_str
#define __print_hex_str(buf, len) ""
#endif

/* Missing FMODE constants */
#ifndef FMODE_CAN_READ
#define FMODE_CAN_READ FMODE_READ
#endif
#ifndef FMODE_CAN_WRITE
#define FMODE_CAN_WRITE FMODE_WRITE
#endif

/* Missing u64_to_user_ptr */
#ifndef u64_to_user_ptr
#define u64_to_user_ptr(x) ((void __user *)(unsigned long)(x))
#endif

/* Security Stubs */
#ifndef security_bpf
static inline int security_bpf(int cmd, void *attr, unsigned int size) { return 0; }
#endif
#ifndef security_bpf_map
static inline int security_bpf_map(void *map, fmode_t fmode) { return 0; }
#endif
#ifndef security_bpf_map_alloc
static inline int security_bpf_map_alloc(void *map) { return 0; }
#endif
#ifndef security_bpf_prog
static inline int security_bpf_prog(void *prog) { return 0; }
#endif
#ifndef security_bpf_prog_alloc
static inline int security_bpf_prog_alloc(void *aux) { return 0; }
#endif
#ifndef security_bpf_prog_free
static inline void security_bpf_prog_free(void *aux) { }
#endif
#ifndef security_bpf_map_free
static inline void security_bpf_map_free(void *map) { }
#endif

#ifndef __vmalloc_node_flags_caller
#define __vmalloc_node_flags_caller(size, node, flags, caller) \
	__vmalloc(size, flags, PAGE_KERNEL)
#endif

/* Filesystem Compat */
#ifndef d_inode
#define d_inode(dentry) ((dentry)->d_inode)
#endif

#ifndef d_backing_inode
#define d_backing_inode(dentry) ((dentry)->d_inode)
#endif

#ifndef current_time
#define current_time(inode) CURRENT_TIME
#endif

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#ifndef sysfs_create_mount_point
static inline int sysfs_create_mount_point(struct kobject *parent, const char *name)
{
	struct kobject *kobj = kobject_create_and_add(name, parent);
	if (!kobj)
		return -ENOMEM;
	return 0;
}
#endif

#ifndef sysfs_remove_mount_point
#define sysfs_remove_mount_point(parent, name) do {} while(0)
#endif

#ifndef ktime_get_mono_fast_ns
#define ktime_get_mono_fast_ns() ktime_to_ns(ktime_get())
#endif

#ifndef netdev_notifier_info_to_dev
static inline struct net_device *netdev_notifier_info_to_dev(void *ptr)
{
	return (struct net_device *)ptr;
}
#endif

#ifndef ktime_get_boot_fast_ns
/* ktime_get_boot_ns might be missing in 3.10 too, check grep result. */
/* Fallback to monotonic if boot not available, or use ktime_get_boottime logic */
/* 3.10 has ktime_get_boottime that returns ktime_t */
#define ktime_get_boot_fast_ns() ktime_to_ns(ktime_get_boottime())
#endif

#ifndef __alloc_percpu_gfp
#define __alloc_percpu_gfp(size, align, gfp) __alloc_percpu(size, align)
#endif

#include <linux/list_nulls.h>

#ifndef hlist_nulls_entry_safe
#define hlist_nulls_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   (!is_a_nulls(____ptr)) ? hlist_nulls_entry(____ptr, type, member) : NULL; \
	})
#endif

#ifndef hlist_nulls_for_each_entry_safe
#define hlist_nulls_for_each_entry_safe(tpos, n, head, member)			\
	for (n = (head)->first;							\
	     (!is_a_nulls(n)) && ({ n = n->next; 1; }) &&			\
		({ tpos = hlist_nulls_entry(n->pprev, typeof(*tpos), member); 1; }); \
	     )
/* Wait, the iterator logic for SAFE loop is complex.
 * Standard list_for_each_entry_safe(pos, n, head, member):
 * for (pos = list_entry((head)->next, ...), n = list_entry(pos->member.next, ...);
 *      &pos->member != (head);
 *      pos = n, n = list_entry(n->member.next, ...))
 *
 * For hlist_nulls:
 * Iterate 'pos' (node*). Keep 'n' (node*) as next.
 * Start: pos = head->first.
 * Check: !is_a_nulls(pos).
 * Step: n = pos->next.
 * Body: tpos = entry(pos).
 * Next: pos = n.
 */
#undef hlist_nulls_for_each_entry_safe
#define hlist_nulls_for_each_entry_safe(tpos, n, head, member)                   \
	for (n = (head)->first;                                                  \
	     (!is_a_nulls(n)) &&                                                 \
		({ tpos = hlist_nulls_entry(n, typeof(*tpos), member);           \
		   n = n->next; 1; });                                           \
	     )
#endif

#ifndef perf_event_get
#define perf_event_get(fd) ({ (void)(fd); ERR_PTR(-EOPNOTSUPP); })
#endif

#ifndef perf_event_read_local
#define perf_event_read_local(event, value) ({ (void)(event); (void)(value); -EOPNOTSUPP; })
#endif

#endif /* _KERNEL_BPF_COMPAT_H */
