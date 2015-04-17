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
#include <linux/ctype.h>
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

void nd_init_ndio(struct nd_io *ndio, nd_rw_bytes_fn rw_bytes,
		struct device *dev, struct gendisk *disk, unsigned long align)
{
	memset(ndio, 0, sizeof(*ndio));
	INIT_LIST_HEAD(&ndio->claims);
	INIT_LIST_HEAD(&ndio->list);
	spin_lock_init(&ndio->lock);
	ndio->dev = dev;
	ndio->disk = disk;
	ndio->align = align;
	ndio->rw_bytes = rw_bytes;
}
EXPORT_SYMBOL(nd_init_ndio);

void ndio_del_claim(struct nd_io_claim *ndio_claim)
{
	struct nd_io *ndio;
	struct device *holder;

	if (!ndio_claim)
		return;
	ndio = ndio_claim->parent;
	holder = ndio_claim->holder;

	dev_dbg(holder, "%s: drop %s\n", __func__, dev_name(ndio->dev));
	spin_lock(&ndio->lock);
	list_del(&ndio_claim->list);
	spin_unlock(&ndio->lock);
	put_device(ndio->dev);
	kfree(ndio_claim);
	put_device(holder);
}

struct nd_io_claim *ndio_add_claim(struct nd_io *ndio, struct device *holder,
		ndio_notify_remove_fn notify_remove)
{
	struct nd_io_claim *ndio_claim = kzalloc(sizeof(*ndio_claim), GFP_KERNEL);

	if (!ndio_claim)
		return NULL;

	INIT_LIST_HEAD(&ndio_claim->list);
	ndio_claim->parent = ndio;
	get_device(ndio->dev);

	spin_lock(&ndio->lock);
	list_add(&ndio_claim->list, &ndio->claims);
	spin_unlock(&ndio->lock);

	ndio_claim->holder = holder;
	ndio_claim->notify_remove = notify_remove;
	get_device(holder);

	return ndio_claim;
}

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

	WARN_ON(!list_empty(&nd_bus->ndios));

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

static bool is_uuid_sep(char sep)
{
	if (sep == '\n' || sep == '-' || sep == ':' || sep == '\0')
		return true;
	return false;
}

static int nd_uuid_parse(struct device *dev, u8 *uuid_out, const char *buf,
		size_t len)
{
	const char *str = buf;
	u8 uuid[16];
	int i;

	for (i = 0; i < 16; i++) {
		if (!isxdigit(str[0]) || !isxdigit(str[1])) {
			dev_dbg(dev, "%s: pos: %d buf[%zd]: %c buf[%zd]: %c\n",
					__func__, i, str - buf, str[0],
					str + 1 - buf, str[1]);
			return -EINVAL;
		}

		uuid[i] = (hex_to_bin(str[0]) << 4) | hex_to_bin(str[1]);
		str += 2;
		if (is_uuid_sep(*str))
			str++;
	}

	memcpy(uuid_out, uuid, sizeof(uuid));
	return 0;
}

/**
 * nd_uuid_store: common implementation for writing 'uuid' sysfs attributes
 * @dev: container device for the uuid property
 * @uuid_out: uuid buffer to replace
 * @buf: raw sysfs buffer to parse
 *
 * Enforce that uuids can only be changed while the device is disabled
 * (driver detached)
 * LOCKING: expects device_lock() is held on entry
 */
int nd_uuid_store(struct device *dev, u8 **uuid_out, const char *buf,
		size_t len)
{
	u8 uuid[16];
	int rc;

	if (dev->driver)
		return -EBUSY;

	rc = nd_uuid_parse(dev, uuid, buf, len);
	if (rc)
		return rc;

	kfree(*uuid_out);
	*uuid_out = kmemdup(uuid, sizeof(uuid), GFP_KERNEL);
	if (!(*uuid_out))
		return -ENOMEM;

	return 0;
}

ssize_t nd_sector_size_show(unsigned long current_lbasize,
		const unsigned long *supported, char *buf)
{
	ssize_t len = 0;
	int i;

	for (i = 0; supported[i]; i++)
		if (current_lbasize == supported[i])
			len += sprintf(buf + len, "[%ld] ", supported[i]);
		else
			len += sprintf(buf + len, "%ld ", supported[i]);
	len += sprintf(buf + len, "\n");
	return len;
}

ssize_t nd_sector_size_store(struct device *dev, const char *buf,
		unsigned long *current_lbasize, const unsigned long *supported)
{
	unsigned long lbasize;
	int rc, i;

	if (dev->driver)
		return -EBUSY;

	rc = kstrtoul(buf, 0, &lbasize);
	if (rc)
		return rc;

	for (i = 0; supported[i]; i++)
		if (lbasize == supported[i])
			break;

	if (supported[i]) {
		*current_lbasize = lbasize;
		return 0;
	} else {
		return -EINVAL;
	}
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

static ssize_t btt_seed_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_bus *nd_bus = to_nd_bus(dev);
	ssize_t rc;

	nd_bus_lock(dev);
	if (nd_bus->nd_btt)
		rc = sprintf(buf, "%s\n", dev_name(&nd_bus->nd_btt->dev));
	else
		rc = sprintf(buf, "\n");
	nd_bus_unlock(dev);

	return rc;
}
static DEVICE_ATTR_RO(btt_seed);

static struct attribute *nd_bus_attributes[] = {
	&dev_attr_commands.attr,
	&dev_attr_wait_probe.attr,
	&dev_attr_provider.attr,
	&dev_attr_btt_seed.attr,
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
	INIT_LIST_HEAD(&nd_bus->ndios);
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

	nd_bus->nd_btt = nd_btt_create(nd_bus);

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
