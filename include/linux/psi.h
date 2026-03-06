#ifndef _LINUX_PSI_H
#define _LINUX_PSI_H

#include <linux/jump_label.h>
#include <linux/psi_types.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/cgroup.h>

struct seq_file;
struct css_set;

#ifdef CONFIG_PSI

extern struct static_key psi_disabled;

void psi_init(void);

void psi_task_change(struct task_struct *task, int clear, int set);

void psi_memstall_tick(struct task_struct *task, int cpu);
void psi_memstall_enter(unsigned long *flags);
void psi_memstall_leave(unsigned long *flags);

static inline void psi_enqueue(struct task_struct *p, bool wakeup)
{
	int clear = 0, set = TSK_RUNNING;

	/* Simplified backport logic */
	/* if (p->in_iowait) clear |= TSK_IOWAIT; */

	psi_task_change(p, clear, set);
}

static inline void psi_dequeue(struct task_struct *p, bool sleep)
{
	int clear = TSK_RUNNING, set = 0;

	/* Simplified backport logic */
	/* if (sleep && p->in_iowait) set |= TSK_IOWAIT; */

	psi_task_change(p, clear, set);
}

static inline void psi_ttwu_dequeue(struct task_struct *p)
{
	/* Simplified backport: treat as dequeue */
	/* psi_task_change(p, TSK_RUNNING, 0); */
}

int psi_show(struct seq_file *s, struct psi_group *group, enum psi_res res);

#ifdef CONFIG_CGROUPS
int psi_cgroup_alloc(struct cgroup *cgrp);
void psi_cgroup_free(struct cgroup *cgrp);
void cgroup_move_task(struct task_struct *p, struct css_set *to);

struct psi_trigger *psi_trigger_create(struct psi_group *group,
			char *buf, size_t nbytes, enum psi_res res);
void psi_trigger_destroy(struct psi_trigger *t);

unsigned int psi_trigger_poll(void **trigger_ptr, struct file *file,
			      poll_table *wait);
#endif

#else /* CONFIG_PSI */

static inline void psi_init(void) {}

static inline void psi_task_change(struct task_struct *task, int clear, int set) {}

static inline void psi_memstall_tick(struct task_struct *task, int cpu) {}
static inline void psi_memstall_enter(unsigned long *flags) {}
static inline void psi_memstall_leave(unsigned long *flags) {}

static inline void psi_enqueue(struct task_struct *p, bool wakeup) {}
static inline void psi_dequeue(struct task_struct *p, bool sleep) {}
static inline void psi_ttwu_dequeue(struct task_struct *p) {}

#ifdef CONFIG_CGROUPS
static inline int psi_cgroup_alloc(struct cgroup *cgrp)
{
	return 0;
}
static inline void psi_cgroup_free(struct cgroup *cgrp)
{
}
static inline void cgroup_move_task(struct task_struct *p, struct css_set *to)
{
	rcu_assign_pointer(p->cgroups, to);
}
#endif

#endif /* CONFIG_PSI */

#endif /* _LINUX_PSI_H */
