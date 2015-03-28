/*
 * Copyright(c) 2013-2015 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/export.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include "nd-private.h"
#include "libnd.h"
#include "nd.h"

LIST_HEAD(nd_bus_list);
DEFINE_MUTEX(nd_bus_list_mutex);
static DEFINE_IDA(nd_ida);

void nd_bus_lock(struct device *dev)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);

	if (!nd_bus)
		return;
	mutex_lock(&nd_bus->reconfig_mutex);
}
EXPORT_SYMBOL(nd_bus_lock);

void nd_bus_unlock(struct device *dev)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);

	if (!nd_bus)
		return;
	mutex_unlock(&nd_bus->reconfig_mutex);
}
EXPORT_SYMBOL(nd_bus_unlock);

bool is_nd_bus_locked(struct device *dev)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);

	if (!nd_bus)
		return false;
	return mutex_is_locked(&nd_bus->reconfig_mutex);
}
EXPORT_SYMBOL(is_nd_bus_locked);

u64 nd_fletcher64(void __iomem *addr, size_t len)
{
	u32 lo32 = 0;
	u64 hi32 = 0;
	int i;

	for (i = 0; i < len; i += 4) {
		lo32 = readl(addr + i);
		hi32 += lo32;
	}

	return hi32 << 32 | lo32;
}
EXPORT_SYMBOL_GPL(nd_fletcher64);

static void nd_bus_release(struct device *dev)
{
	struct nd_bus *nd_bus = container_of(dev, struct nd_bus, dev);

	ida_simple_remove(&nd_ida, nd_bus->id);
	kfree(nd_bus);
}

struct nd_bus *to_nd_bus(struct device *dev)
{
	struct nd_bus *nd_bus = container_of(dev, struct nd_bus, dev);

	WARN_ON(nd_bus->dev.release != nd_bus_release);
	return nd_bus;
}
EXPORT_SYMBOL_GPL(to_nd_bus);

struct nd_bus_descriptor *to_nd_desc(struct nd_bus *nd_bus)
{
	/* struct nd_bus definition is private to libnd */
	return nd_bus->nd_desc;
}
EXPORT_SYMBOL_GPL(to_nd_desc);

struct nd_bus *walk_to_nd_bus(struct device *nd_dev)
{
	struct device *dev;

	for (dev = nd_dev; dev; dev = dev->parent)
		if (dev->release == nd_bus_release)
			break;
	dev_WARN_ONCE(nd_dev, !dev, "invalid dev, not on nd bus\n");
	if (dev)
		return to_nd_bus(dev);
	return NULL;
}

static ssize_t commands_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int cmd, len = 0;
	struct nd_bus *nd_bus = to_nd_bus(dev);
	struct nd_bus_descriptor *nd_desc = nd_bus->nd_desc;

	for_each_set_bit(cmd, &nd_desc->dsm_mask, BITS_PER_LONG)
		len += sprintf(buf + len, "%s ", nd_bus_cmd_name(cmd));
	len += sprintf(buf + len, "\n");
	return len;
}
static DEVICE_ATTR_RO(commands);

static const char *nd_bus_provider(struct nd_bus *nd_bus)
{
	struct nd_bus_descriptor *nd_desc = nd_bus->nd_desc;
	struct device *parent = nd_bus->dev.parent;

	if (nd_desc->provider_name)
		return nd_desc->provider_name;
	else if (parent)
		return dev_name(parent);
	else
		return "unknown";
}

static ssize_t provider_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_bus *nd_bus = to_nd_bus(dev);

	return sprintf(buf, "%s\n", nd_bus_provider(nd_bus));
}
static DEVICE_ATTR_RO(provider);

static int flush_namespaces(struct device *dev, void *data)
{
	device_lock(dev);
	device_unlock(dev);
	return 0;
}

static int flush_regions_dimms(struct device *dev, void *data)
{
	device_lock(dev);
	device_unlock(dev);
	device_for_each_child(dev, NULL, flush_namespaces);
	return 0;
}

static ssize_t wait_probe_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	nd_synchronize();
	device_for_each_child(dev, NULL, flush_regions_dimms);
	return sprintf(buf, "1\n");
}
static DEVICE_ATTR_RO(wait_probe);

static struct attribute *nd_bus_attributes[] = {
	&dev_attr_commands.attr,
	&dev_attr_wait_probe.attr,
	&dev_attr_provider.attr,
	NULL,
};

struct attribute_group nd_bus_attribute_group = {
	.attrs = nd_bus_attributes,
};
EXPORT_SYMBOL_GPL(nd_bus_attribute_group);

struct nd_bus *__nd_bus_register(struct device *parent,
		struct nd_bus_descriptor *nd_desc, struct module *module)
{
	struct nd_bus *nd_bus = kzalloc(sizeof(*nd_bus), GFP_KERNEL);
	int rc;

	if (!nd_bus)
		return NULL;
	INIT_LIST_HEAD(&nd_bus->list);
	init_waitqueue_head(&nd_bus->probe_wait);
	nd_bus->id = ida_simple_get(&nd_ida, 0, 0, GFP_KERNEL);
	mutex_init(&nd_bus->reconfig_mutex);
	if (nd_bus->id < 0) {
		kfree(nd_bus);
		return NULL;
	}
	nd_bus->nd_desc = nd_desc;
	nd_bus->module = module;
	nd_bus->dev.parent = parent;
	nd_bus->dev.release = nd_bus_release;
	nd_bus->dev.groups = nd_desc->attr_groups;
	dev_set_name(&nd_bus->dev, "ndbus%d", nd_bus->id);
	rc = device_register(&nd_bus->dev);
	if (rc) {
		dev_dbg(&nd_bus->dev, "device registration failed: %d\n", rc);
		goto err;
	}

	rc = nd_bus_create_ndctl(nd_bus);
	if (rc)
		goto err;

	mutex_lock(&nd_bus_list_mutex);
	list_add_tail(&nd_bus->list, &nd_bus_list);
	mutex_unlock(&nd_bus_list_mutex);

	return nd_bus;
 err:
	put_device(&nd_bus->dev);
	return NULL;
}
EXPORT_SYMBOL_GPL(__nd_bus_register);

static int child_unregister(struct device *dev, void *data)
{
	/*
	 * the singular ndctl class device per bus needs to be
	 * "device_destroy"ed, so skip it here
	 *
	 * i.e. remove classless children
	 */
	if (dev->class)
		/* pass */;
	else
		nd_device_unregister(dev, ND_SYNC);
	return 0;
}

void nd_bus_unregister(struct nd_bus *nd_bus)
{
	if (!nd_bus)
		return;

	mutex_lock(&nd_bus_list_mutex);
	list_del_init(&nd_bus->list);
	mutex_unlock(&nd_bus_list_mutex);

	nd_synchronize();
	device_for_each_child(&nd_bus->dev, NULL, child_unregister);
	nd_bus_destroy_ndctl(nd_bus);

	device_unregister(&nd_bus->dev);
}
EXPORT_SYMBOL_GPL(nd_bus_unregister);

static __init int libnd_init(void)
{
	int rc;

	rc = nd_bus_init();
	if (rc)
		return rc;
	rc = nd_dimm_init();
	if (rc)
		goto err_dimm;
	rc = nd_region_init();
	if (rc)
		goto err_region;
	return 0;
 err_region:
	nd_dimm_exit();
 err_dimm:
	nd_bus_exit();
	return rc;
}

static __exit void libnd_exit(void)
{
	WARN_ON(!list_empty(&nd_bus_list));
	nd_region_exit();
	nd_dimm_exit();
	nd_bus_exit();
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
module_init(libnd_init);
module_exit(libnd_exit);
