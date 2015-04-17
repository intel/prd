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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/fcntl.h>
#include <linux/async.h>
#include <linux/genhd.h>
#include <linux/ndctl.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/nd.h>
#include "nd-private.h"
#include "nd.h"

int nd_dimm_major;
static int nd_bus_major;
static struct class *nd_class;

static int to_nd_device_type(struct device *dev)
{
	if (is_nd_dimm(dev))
		return ND_DEVICE_DIMM;
	else if (is_nd_pmem(dev))
		return ND_DEVICE_REGION_PMEM;
	else if (is_nd_blk(dev))
		return ND_DEVICE_REGION_BLK;
	else if (is_nd_pmem(dev->parent) || is_nd_blk(dev->parent))
		return nd_region_to_namespace_type(to_nd_region(dev->parent));
	else if (is_nd_btt(dev))
		return ND_DEVICE_BTT;

	return 0;
}

static int nd_bus_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	return add_uevent_var(env, "MODALIAS=" ND_DEVICE_MODALIAS_FMT,
			to_nd_device_type(dev));
}

static int nd_bus_match(struct device *dev, struct device_driver *drv)
{
	struct nd_device_driver *nd_drv = to_nd_device_driver(drv);

	return test_bit(to_nd_device_type(dev), &nd_drv->type);
}

static struct module *to_bus_provider(struct device *dev)
{
	/* pin bus providers while regions are enabled */
	if (is_nd_pmem(dev) || is_nd_blk(dev)) {
		struct nd_bus *nd_bus = walk_to_nd_bus(dev);

		return nd_bus->module;
	}
	return NULL;
}

static int nd_bus_probe(struct device *dev)
{
	struct nd_device_driver *nd_drv = to_nd_device_driver(dev->driver);
	struct module *provider = to_bus_provider(dev);
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);
	int rc;

	if (!try_module_get(provider))
		return -ENXIO;

	nd_region_probe_start(nd_bus, dev);
	rc = nd_drv->probe(dev);
	nd_region_probe_end(nd_bus, dev, rc);

	dev_dbg(&nd_bus->dev, "%s.probe(%s) = %d\n", dev->driver->name,
			dev_name(dev), rc);

	/* check if our btt-seed has sprouted, and plant another */
	if (rc == 0 && is_nd_btt(dev) && dev == &nd_bus->nd_btt->dev) {
		const char *sep = "", *name = "", *status = "failed";

		nd_bus->nd_btt = nd_btt_create(nd_bus);
		if (nd_bus->nd_btt) {
			status = "succeeded";
			sep = ": ";
			name = dev_name(&nd_bus->nd_btt->dev);
		}
		dev_dbg(&nd_bus->dev, "btt seed creation %s%s%s\n",
				status, sep, name);
	}

	if (rc != 0)
		module_put(provider);
	return rc;
}

static int nd_bus_remove(struct device *dev)
{
	struct nd_device_driver *nd_drv = to_nd_device_driver(dev->driver);
	struct module *provider = to_bus_provider(dev);
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);
	int rc;

	rc = nd_drv->remove(dev);
	nd_region_notify_remove(nd_bus, dev, rc);

	dev_dbg(&nd_bus->dev, "%s.remove(%s) = %d\n", dev->driver->name,
			dev_name(dev), rc);
	module_put(provider);
	return rc;
}

static struct bus_type nd_bus_type = {
	.name = "nd",
	.uevent = nd_bus_uevent,
	.match = nd_bus_match,
	.probe = nd_bus_probe,
	.remove = nd_bus_remove,
};

static ASYNC_DOMAIN_EXCLUSIVE(nd_async_domain);

void nd_synchronize(void)
{
	async_synchronize_full_domain(&nd_async_domain);
}
EXPORT_SYMBOL_GPL(nd_synchronize);

static void nd_async_device_register(void *d, async_cookie_t cookie)
{
	struct device *dev = d;

	if (device_add(dev) != 0) {
		dev_err(dev, "%s: failed\n", __func__);
		put_device(dev);
	}
	put_device(dev);
}

static void nd_async_device_unregister(void *d, async_cookie_t cookie)
{
	struct device *dev = d;

	/* flush bus operations before delete */
	nd_bus_lock(dev);
	nd_bus_unlock(dev);

	device_unregister(dev);
	put_device(dev);
}

void __nd_device_register(struct device *dev)
{
	dev->bus = &nd_bus_type;
	get_device(dev);
	async_schedule_domain(nd_async_device_register, dev,
			&nd_async_domain);
}

void nd_device_register(struct device *dev)
{
	device_initialize(dev);
	__nd_device_register(dev);
}
EXPORT_SYMBOL(nd_device_register);

void nd_device_unregister(struct device *dev, enum nd_async_mode mode)
{
	switch (mode) {
	case ND_ASYNC:
		get_device(dev);
		async_schedule_domain(nd_async_device_unregister, dev,
				&nd_async_domain);
		break;
	case ND_SYNC:
		nd_synchronize();
		device_unregister(dev);
		break;
	}
}
EXPORT_SYMBOL(nd_device_unregister);

/**
 * __nd_driver_register() - register a region or a namespace driver
 * @nd_drv: driver to register
 * @owner: automatically set by nd_driver_register() macro
 * @mod_name: automatically set by nd_driver_register() macro
 */
int __nd_driver_register(struct nd_device_driver *nd_drv, struct module *owner,
		const char *mod_name)
{
	struct device_driver *drv = &nd_drv->drv;

	if (!nd_drv->type) {
		pr_debug("driver type bitmask not set (%pf)\n",
				__builtin_return_address(0));
		return -EINVAL;
	}

	if (!nd_drv->probe || !nd_drv->remove) {
		pr_debug("->probe() and ->remove() must be specified\n");
		return -EINVAL;
	}

	drv->bus = &nd_bus_type;
	drv->owner = owner;
	drv->mod_name = mod_name;

	return driver_register(drv);
}
EXPORT_SYMBOL(__nd_driver_register);

/**
 * nd_register_ndio() - register byte-aligned access capability for an nd-bdev
 * @disk: child gendisk of the ndio namepace device
 * @ndio: initialized ndio instance to register
 *
 * LOCKING: hold nd_bus_lock() over the creation of ndio->disk and the
 * subsequent nd_region_ndio event
 */
int nd_register_ndio(struct nd_io *ndio)
{
	struct nd_bus *nd_bus;
	struct device *dev;

	if (!ndio || !ndio->dev || !ndio->disk || !list_empty(&ndio->list)
			|| !ndio->rw_bytes || !list_empty(&ndio->claims)) {
		pr_debug("%s bad parameters from %pf\n", __func__,
				__builtin_return_address(0));
		return -EINVAL;
	}

	dev = ndio->dev;
	nd_bus = walk_to_nd_bus(dev);
	if (!nd_bus)
		return -EINVAL;

	WARN_ON_ONCE(!is_nd_bus_locked(&nd_bus->dev));
	list_add(&ndio->list, &nd_bus->ndios);

	/* TODO: generic infrastructure for 3rd party ndio claimers */
	nd_btt_notify_ndio(nd_bus, ndio);

	return 0;
}
EXPORT_SYMBOL(nd_register_ndio);

/**
 * __nd_unregister_ndio() - try to remove an ndio interface
 * @ndio: interface to remove
 */
static int __nd_unregister_ndio(struct nd_io *ndio)
{
	struct nd_io_claim *ndio_claim, *_n;
	struct nd_bus *nd_bus;
	LIST_HEAD(claims);

	nd_bus = walk_to_nd_bus(ndio->dev);
	if (!nd_bus || list_empty(&ndio->list))
		return -ENXIO;

	spin_lock(&ndio->lock);
	list_splice_init(&ndio->claims, &claims);
	spin_unlock(&ndio->lock);

	list_for_each_entry_safe(ndio_claim, _n, &claims, list)
		ndio_claim->notify_remove(ndio_claim);

	list_del_init(&ndio->list);

	return 0;
}

int nd_unregister_ndio(struct nd_io *ndio)
{
	struct device *dev = ndio->dev;
	int rc;

	nd_bus_lock(dev);
	rc = __nd_unregister_ndio(ndio);
	nd_bus_unlock(dev);

	/*
	 * Flush in case ->notify_remove() kicked off asynchronous device
	 * unregistration
	 */
	nd_synchronize();

	return rc;
}
EXPORT_SYMBOL(nd_unregister_ndio);

static struct nd_io *__ndio_lookup(struct nd_bus *nd_bus, const char *diskname)
{
	struct nd_io *ndio;

	list_for_each_entry(ndio, &nd_bus->ndios, list)
		if (strcmp(diskname, ndio->disk->disk_name) == 0)
			return ndio;

	return NULL;
}

struct nd_io *ndio_lookup(struct nd_bus *nd_bus, const char *diskname)
{
	struct nd_io *ndio;

	WARN_ON_ONCE(!is_nd_bus_locked(&nd_bus->dev));
	ndio = __ndio_lookup(nd_bus, diskname);

	return ndio;
}

static ssize_t modalias_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, ND_DEVICE_MODALIAS_FMT "\n",
			to_nd_device_type(dev));
}
static DEVICE_ATTR_RO(modalias);

static ssize_t devtype_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "%s\n", dev->type->name);
}
DEVICE_ATTR_RO(devtype);

static struct attribute *nd_device_attributes[] = {
	&dev_attr_modalias.attr,
	&dev_attr_devtype.attr,
	NULL,
};

/**
 * nd_device_attribute_group - generic attributes for all devices on an nd bus
 */
struct attribute_group nd_device_attribute_group = {
	.attrs = nd_device_attributes,
};
EXPORT_SYMBOL_GPL(nd_device_attribute_group);

int nd_bus_create_ndctl(struct nd_bus *nd_bus)
{
	dev_t devt = MKDEV(nd_bus_major, nd_bus->id);
	struct device *dev;

	dev = device_create(nd_class, &nd_bus->dev, devt, nd_bus, "ndctl%d",
			nd_bus->id);

	if (IS_ERR(dev)) {
		dev_dbg(&nd_bus->dev, "failed to register ndctl%d: %ld\n",
				nd_bus->id, PTR_ERR(dev));
		return PTR_ERR(dev);
	}
	return 0;
}

void nd_bus_destroy_ndctl(struct nd_bus *nd_bus)
{
	device_destroy(nd_class, MKDEV(nd_bus_major, nd_bus->id));
}

static const struct nd_cmd_desc const __nd_cmd_dimm_descs[] = {
	[ND_CMD_IMPLEMENTED] = { },
	[ND_CMD_SMART] = {
		.out_num = 2,
		.out_sizes = { 4, 8, },
	},
	[ND_CMD_SMART_THRESHOLD] = {
		.out_num = 2,
		.out_sizes = { 4, 8, },
	},
	[ND_CMD_DIMM_FLAGS] = {
		.out_num = 2,
		.out_sizes = { 4, 4 },
	},
	[ND_CMD_GET_CONFIG_SIZE] = {
		.out_num = 3,
		.out_sizes = { 4, 4, 4, },
	},
	[ND_CMD_GET_CONFIG_DATA] = {
		.in_num = 2,
		.in_sizes = { 4, 4, },
		.out_num = 2,
		.out_sizes = { 4, UINT_MAX, },
	},
	[ND_CMD_SET_CONFIG_DATA] = {
		.in_num = 3,
		.in_sizes = { 4, 4, UINT_MAX, },
		.out_num = 1,
		.out_sizes = { 4, },
	},
	[ND_CMD_VENDOR] = {
		.in_num = 3,
		.in_sizes = { 4, 4, UINT_MAX, },
		.out_num = 3,
		.out_sizes = { 4, 4, UINT_MAX, },
	},
};

struct nd_cmd_desc const *nd_cmd_dimm_desc(int cmd)
{
	if (cmd < ARRAY_SIZE(__nd_cmd_dimm_descs))
		return &__nd_cmd_dimm_descs[cmd];
	return NULL;
}
EXPORT_SYMBOL_GPL(nd_cmd_dimm_desc);

static const struct nd_cmd_desc const __nd_cmd_bus_descs[] = {
	[ND_CMD_IMPLEMENTED] = { },
	[ND_CMD_ARS_CAP] = {
		.in_num = 2,
		.in_sizes = { 8, 8, },
		.out_num = 2,
		.out_sizes = { 4, 4, },
	},
	[ND_CMD_ARS_START] = {
		.in_num = 4,
		.in_sizes = { 8, 8, 2, 6, },
		.out_num = 1,
		.out_sizes = { 4, },
	},
	[ND_CMD_ARS_QUERY] = {
		.out_num = 2,
		.out_sizes = { 4, UINT_MAX, },
	},
};

const struct nd_cmd_desc *nd_cmd_bus_desc(int cmd)
{
	if (cmd < ARRAY_SIZE(__nd_cmd_bus_descs))
		return &__nd_cmd_bus_descs[cmd];
	return NULL;
}
EXPORT_SYMBOL_GPL(nd_cmd_bus_desc);

u32 nd_cmd_in_size(struct nd_dimm *nd_dimm, int cmd,
		const struct nd_cmd_desc *desc, int idx, void *buf)
{
	if (idx >= desc->in_num)
		return UINT_MAX;

	if (desc->in_sizes[idx] < UINT_MAX)
		return desc->in_sizes[idx];

	if (nd_dimm && cmd == ND_CMD_SET_CONFIG_DATA && idx == 2) {
		struct nd_cmd_set_config_hdr *hdr = buf;

		return hdr->in_length;
	} else if (nd_dimm && cmd == ND_CMD_VENDOR && idx == 2) {
		struct nd_cmd_vendor_hdr *hdr = buf;

		return hdr->in_length;
	}

	return UINT_MAX;
}
EXPORT_SYMBOL_GPL(nd_cmd_in_size);

u32 nd_cmd_out_size(struct nd_dimm *nd_dimm, int cmd,
		const struct nd_cmd_desc *desc, int idx, const u32 *in_field,
		const u32 *out_field)
{
	if (idx >= desc->out_num)
		return UINT_MAX;

	if (desc->out_sizes[idx] < UINT_MAX)
		return desc->out_sizes[idx];

	if (nd_dimm && cmd == ND_CMD_GET_CONFIG_DATA && idx == 1)
		return in_field[1];
	else if (nd_dimm && cmd == ND_CMD_VENDOR && idx == 2)
		return out_field[1];
	else if (!nd_dimm && cmd == ND_CMD_ARS_QUERY && idx == 1)
		return ND_CMD_ARS_QUERY_MAX;

	return UINT_MAX;
}
EXPORT_SYMBOL_GPL(nd_cmd_out_size);

void wait_nd_bus_probe_idle(struct device *dev)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);

	do {
		if (nd_bus->probe_active == 0)
			break;
		nd_bus_unlock(&nd_bus->dev);
		wait_event(nd_bus->probe_wait, nd_bus->probe_active == 0);
		nd_bus_lock(&nd_bus->dev);
	} while (true);
}

/* set_config requires an idle interleave set */
static int nd_cmd_clear_to_send(struct nd_dimm *nd_dimm, unsigned int cmd)
{
	struct nd_bus *nd_bus;

	if (!nd_dimm || cmd != ND_CMD_SET_CONFIG_DATA)
		return 0;

	nd_bus = walk_to_nd_bus(&nd_dimm->dev);
	wait_nd_bus_probe_idle(&nd_bus->dev);

	if (atomic_read(&nd_dimm->busy))
		return -EBUSY;
	return 0;
}

static int __nd_ioctl(struct nd_bus *nd_bus, struct nd_dimm *nd_dimm,
		int read_only, unsigned int ioctl_cmd, unsigned long arg)
{
	struct nd_bus_descriptor *nd_desc = nd_bus->nd_desc;
	size_t buf_len = 0, in_len = 0, out_len = 0;
	static char out_env[ND_CMD_MAX_ENVELOPE];
	static char in_env[ND_CMD_MAX_ENVELOPE];
	const struct nd_cmd_desc *desc = NULL;
	unsigned int cmd = _IOC_NR(ioctl_cmd);
	void __user *p = (void __user *) arg;
	struct device *dev = &nd_bus->dev;
	const char *cmd_name, *dimm_name;
	unsigned long dsm_mask;
	void *buf;
	int rc, i;

	if (nd_dimm) {
		desc = nd_cmd_dimm_desc(cmd);
		cmd_name = nd_dimm_cmd_name(cmd);
		dsm_mask = nd_dimm->dsm_mask ? *(nd_dimm->dsm_mask) : 0;
		dimm_name = dev_name(&nd_dimm->dev);
	} else {
		desc = nd_cmd_bus_desc(cmd);
		cmd_name = nd_bus_cmd_name(cmd);
		dsm_mask = nd_desc->dsm_mask;
		dimm_name = "bus";
	}

	if (!desc || (desc->out_num + desc->in_num == 0) ||
			!test_bit(cmd, &dsm_mask))
		return -ENOTTY;

	/* fail write commands (when read-only) */
	if (read_only)
		switch (ioctl_cmd) {
		case ND_IOCTL_VENDOR:
		case ND_IOCTL_SET_CONFIG_DATA:
		case ND_IOCTL_ARS_START:
			dev_dbg(&nd_bus->dev, "'%s' command while read-only.\n",
					nd_dimm ? nd_dimm_cmd_name(cmd)
					: nd_bus_cmd_name(cmd));
			return -EPERM;
		default:
			break;
		}

	/* process an input envelope */
	for (i = 0; i < desc->in_num; i++) {
		u32 in_size, copy;

		in_size = nd_cmd_in_size(nd_dimm, cmd, desc, i, in_env);
		if (in_size == UINT_MAX) {
			dev_err(dev, "%s:%s unknown input size cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			return -ENXIO;
		}
		if (!access_ok(VERIFY_READ, p + in_len, in_size))
			return -EFAULT;
		if (in_len < sizeof(in_env))
			copy = min_t(u32, sizeof(in_env) - in_len, in_size);
		else
			copy = 0;
		if (copy && copy_from_user(&in_env[in_len], p + in_len, copy))
			return -EFAULT;
		in_len += in_size;
	}

	/* process an output envelope */
	for (i = 0; i < desc->out_num; i++) {
		u32 out_size = nd_cmd_out_size(nd_dimm, cmd, desc, i,
				(u32 *) in_env, (u32 *) out_env);
		u32 copy;

		if (out_size == UINT_MAX) {
			dev_dbg(dev, "%s:%s unknown output size cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			return -EFAULT;
		}
		if (!access_ok(VERIFY_WRITE, p + in_len + out_len, out_size))
			return -EFAULT;
		if (out_len < sizeof(out_env))
			copy = min_t(u32, sizeof(out_env) - out_len, out_size);
		else
			copy = 0;
		if (copy && copy_from_user(&out_env[out_len], p + in_len + out_len,
					copy))
			return -EFAULT;
		out_len += out_size;
	}

	buf_len = out_len + in_len;
	if (!access_ok(VERIFY_WRITE, p, sizeof(buf_len)))
		return -EFAULT;

	if (buf_len > ND_IOCTL_MAX_BUFLEN) {
		dev_dbg(dev, "%s:%s cmd: %s buf_len: %zd > %d\n", __func__,
				dimm_name, cmd_name, buf_len,
				ND_IOCTL_MAX_BUFLEN);
		return -EINVAL;
	}

	buf = vmalloc(buf_len);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, p, buf_len)) {
		rc = -EFAULT;
		goto out;
	}

	nd_bus_lock(&nd_bus->dev);
	rc = nd_cmd_clear_to_send(nd_dimm, cmd);
	if (rc)
		goto out_unlock;

	rc = nd_desc->ndctl(nd_desc, nd_dimm, cmd, buf, buf_len);
	if (rc < 0)
		goto out_unlock;
	if (copy_to_user(p, buf, buf_len))
		rc = -EFAULT;
 out_unlock:
	nd_bus_unlock(&nd_bus->dev);
 out:
	vfree(buf);
	return rc;
}

static long nd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long id = (long) file->private_data;
	int rc = -ENXIO, read_only;
	struct nd_bus *nd_bus;

	read_only = (O_RDWR != (file->f_flags & O_ACCMODE));
	mutex_lock(&nd_bus_list_mutex);
	list_for_each_entry(nd_bus, &nd_bus_list, list) {
		if (nd_bus->id == id) {
			rc = __nd_ioctl(nd_bus, NULL, read_only, cmd, arg);
			break;
		}
	}
	mutex_unlock(&nd_bus_list_mutex);

	return rc;
}

static int match_dimm(struct device *dev, void *data)
{
	long id = (long) data;

	if (is_nd_dimm(dev)) {
		struct nd_dimm *nd_dimm = to_nd_dimm(dev);

		return nd_dimm->id == id;
	}

	return 0;
}

static long nd_dimm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc = -ENXIO, read_only;
	struct nd_bus *nd_bus;

	read_only = (O_RDWR != (file->f_flags & O_ACCMODE));
	mutex_lock(&nd_bus_list_mutex);
	list_for_each_entry(nd_bus, &nd_bus_list, list) {
		struct device *dev = device_find_child(&nd_bus->dev,
				file->private_data, match_dimm);

		if (!dev)
			continue;

		rc = __nd_ioctl(nd_bus, to_nd_dimm(dev), read_only, cmd, arg);
		put_device(dev);
		break;
	}
	mutex_unlock(&nd_bus_list_mutex);

	return rc;
}

static int nd_open(struct inode *inode, struct file *file)
{
	long minor = iminor(inode);

	file->private_data = (void *) minor;
	return 0;
}

static const struct file_operations nd_bus_fops = {
	.owner = THIS_MODULE,
	.open = nd_open,
	.unlocked_ioctl = nd_ioctl,
	.compat_ioctl = nd_ioctl,
	.llseek = noop_llseek,
};

static const struct file_operations nd_dimm_fops = {
	.owner = THIS_MODULE,
	.open = nd_open,
	.unlocked_ioctl = nd_dimm_ioctl,
	.compat_ioctl = nd_dimm_ioctl,
	.llseek = noop_llseek,
};

int __init nd_bus_init(void)
{
	int rc;

	rc = bus_register(&nd_bus_type);
	if (rc)
		return rc;

	rc = register_chrdev(0, "ndctl", &nd_bus_fops);
	if (rc < 0)
		goto err_bus_chrdev;
	nd_bus_major = rc;

	rc = register_chrdev(0, "dimmctl", &nd_dimm_fops);
	if (rc < 0)
		goto err_dimm_chrdev;
	nd_dimm_major = rc;

	nd_class = class_create(THIS_MODULE, "nd");
	if (IS_ERR(nd_class))
		goto err_class;

	return 0;

 err_class:
	unregister_chrdev(nd_dimm_major, "dimmctl");
 err_dimm_chrdev:
	unregister_chrdev(nd_bus_major, "ndctl");
 err_bus_chrdev:
	bus_unregister(&nd_bus_type);

	return rc;
}

void nd_bus_exit(void)
{
	class_destroy(nd_class);
	unregister_chrdev(nd_bus_major, "ndctl");
	unregister_chrdev(nd_dimm_major, "dimmctl");
	bus_unregister(&nd_bus_type);
}
