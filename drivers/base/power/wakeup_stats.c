// SPDX-License-Identifier: GPL-2.0
/*
 * Wakeup statistics in sysfs - backported from kernel 5.4
 *
 * Creates /sys/class/wakeup/wakeupN/ entries for each wakeup source.
 * Required by Android 16's PowerStats HAL and batterystats.
 *
 * Copyright (c) 2019 Linux Foundation
 * Copyright (c) 2019 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2019 Google Inc.
 */

#include <linux/device.h>
#include <linux/hrtimer.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/pm_wakeup.h>

#include "power.h"

static struct class *wakeup_class;
static DEFINE_IDA(wakeup_ida);

/* Helper macros for 3.10 compatibility */
#define WAKEUP_ATTR_RO(_name)						\
static ssize_t _name##_show(struct device *dev,				\
			    struct device_attribute *attr, char *buf);	\
static DEVICE_ATTR(_name, 0444, _name##_show, NULL)

#define wakeup_attr(_name)						\
static ssize_t _name##_show(struct device *dev,				\
			    struct device_attribute *attr, char *buf)	\
{									\
	struct wakeup_source *ws = dev_get_drvdata(dev);		\
									\
	return sprintf(buf, "%lu\n", ws->_name);			\
}									\
static DEVICE_ATTR(_name, 0444, _name##_show, NULL)

wakeup_attr(active_count);
wakeup_attr(event_count);
wakeup_attr(wakeup_count);
wakeup_attr(expire_count);

static ssize_t active_time_ms_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct wakeup_source *ws = dev_get_drvdata(dev);
	ktime_t active_time =
		ws->active ? ktime_sub(ktime_get(), ws->last_time) : ktime_set(0, 0);

	return sprintf(buf, "%lld\n", ktime_to_ms(active_time));
}
static DEVICE_ATTR(active_time_ms, 0444, active_time_ms_show, NULL);

static ssize_t total_time_ms_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct wakeup_source *ws = dev_get_drvdata(dev);
	ktime_t active_time;
	ktime_t total_time = ws->total_time;

	if (ws->active) {
		active_time = ktime_sub(ktime_get(), ws->last_time);
		total_time = ktime_add(total_time, active_time);
	}
	return sprintf(buf, "%lld\n", ktime_to_ms(total_time));
}
static DEVICE_ATTR(total_time_ms, 0444, total_time_ms_show, NULL);

static ssize_t max_time_ms_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct wakeup_source *ws = dev_get_drvdata(dev);
	ktime_t active_time;
	ktime_t max_time = ws->max_time;

	if (ws->active) {
		active_time = ktime_sub(ktime_get(), ws->last_time);
		if (ktime_compare(active_time, max_time) > 0)
			max_time = active_time;
	}
	return sprintf(buf, "%lld\n", ktime_to_ms(max_time));
}
static DEVICE_ATTR(max_time_ms, 0444, max_time_ms_show, NULL);

static ssize_t last_change_ms_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct wakeup_source *ws = dev_get_drvdata(dev);

	return sprintf(buf, "%lld\n", ktime_to_ms(ws->last_time));
}
static DEVICE_ATTR(last_change_ms, 0444, last_change_ms_show, NULL);

static ssize_t name_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct wakeup_source *ws = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", ws->name);
}
static DEVICE_ATTR(name, 0444, name_show, NULL);

static ssize_t prevent_suspend_time_ms_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct wakeup_source *ws = dev_get_drvdata(dev);
	ktime_t prevent_sleep_time = ws->prevent_sleep_time;

	if (ws->active && ws->autosleep_enabled) {
		prevent_sleep_time = ktime_add(prevent_sleep_time,
			ktime_sub(ktime_get(), ws->start_prevent_time));
	}
	return sprintf(buf, "%lld\n", ktime_to_ms(prevent_sleep_time));
}
static DEVICE_ATTR(prevent_suspend_time_ms, 0444, prevent_suspend_time_ms_show, NULL);

static struct attribute *wakeup_source_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_active_count.attr,
	&dev_attr_event_count.attr,
	&dev_attr_wakeup_count.attr,
	&dev_attr_expire_count.attr,
	&dev_attr_active_time_ms.attr,
	&dev_attr_total_time_ms.attr,
	&dev_attr_max_time_ms.attr,
	&dev_attr_last_change_ms.attr,
	&dev_attr_prevent_suspend_time_ms.attr,
	NULL,
};

static struct attribute_group wakeup_source_group = {
	.attrs = wakeup_source_attrs,
};

static const struct attribute_group *wakeup_source_groups[] = {
	&wakeup_source_group,
	NULL,
};

static void device_create_release(struct device *dev)
{
	kfree(dev);
}

static struct device *wakeup_source_device_create(struct device *parent,
						  struct wakeup_source *ws)
{
	struct device *dev = NULL;
	int retval = -ENODEV;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		retval = -ENOMEM;
		goto error;
	}

	device_initialize(dev);
	dev->devt = MKDEV(0, 0);
	dev->class = wakeup_class;
	dev->parent = parent;
	dev->groups = wakeup_source_groups;
	dev->release = device_create_release;
	dev_set_drvdata(dev, ws);

	retval = kobject_set_name(&dev->kobj, "wakeup%d", ws->id);
	if (retval)
		goto error;

	retval = device_add(dev);
	if (retval)
		goto error;

	return dev;

error:
	put_device(dev);
	return ERR_PTR(retval);
}

/**
 * wakeup_source_sysfs_add - Add wakeup_source attributes to sysfs.
 * @parent: Device given wakeup source is associated with (or NULL if virtual).
 * @ws: Wakeup source to be added in sysfs.
 */
int wakeup_source_sysfs_add(struct device *parent, struct wakeup_source *ws)
{
	struct device *dev;

	ws->id = ida_simple_get(&wakeup_ida, 0, 0, GFP_KERNEL);
	if (ws->id < 0)
		return ws->id;

	dev = wakeup_source_device_create(parent, ws);
	if (IS_ERR(dev)) {
		ida_simple_remove(&wakeup_ida, ws->id);
		return PTR_ERR(dev);
	}
	ws->dev = dev;

	return 0;
}
EXPORT_SYMBOL_GPL(wakeup_source_sysfs_add);

/**
 * pm_wakeup_source_sysfs_add - Add wakeup_source attributes to sysfs
 * for a device if they're missing.
 * @parent: Device given wakeup source is associated with
 */
int pm_wakeup_source_sysfs_add(struct device *parent)
{
	if (!parent->power.wakeup || parent->power.wakeup->dev)
		return 0;

	return wakeup_source_sysfs_add(parent, parent->power.wakeup);
}
EXPORT_SYMBOL_GPL(pm_wakeup_source_sysfs_add);

/**
 * wakeup_source_sysfs_remove - Remove wakeup_source attributes from sysfs.
 * @ws: Wakeup source to be removed from sysfs.
 */
void wakeup_source_sysfs_remove(struct wakeup_source *ws)
{
	if (ws->dev) {
		device_unregister(ws->dev);
		ida_simple_remove(&wakeup_ida, ws->id);
		ws->dev = NULL;
	}
}
EXPORT_SYMBOL_GPL(wakeup_source_sysfs_remove);

static int __init wakeup_sources_sysfs_init(void)
{
	wakeup_class = class_create(THIS_MODULE, "wakeup");
	if (IS_ERR(wakeup_class))
		return PTR_ERR(wakeup_class);

	return 0;
}
postcore_initcall(wakeup_sources_sysfs_init);
