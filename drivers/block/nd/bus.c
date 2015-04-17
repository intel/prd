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
#include "nfit.h"
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
		return ND_DEVICE_REGION_BLOCK;
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

static void nd_async_dimm_delete(void *d, async_cookie_t cookie)
{
	u32 nfit_handle;
	struct nd_dimm_delete *del_info = d;
	struct nd_bus *nd_bus = del_info->nd_bus;
	struct nd_mem *nd_mem = del_info->nd_mem;

	nfit_handle = readl(&nd_mem->nfit_mem_dcr->nfit_handle);

	mutex_lock(&nd_bus_list_mutex);
	radix_tree_delete(&nd_bus->dimm_radix, nfit_handle);
	mutex_unlock(&nd_bus_list_mutex);

	put_device(&nd_bus->dev);
	kfree(del_info);
}

void nd_dimm_delete(struct nd_dimm *nd_dimm)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(&nd_dimm->dev);
	struct nd_dimm_delete *del_info = nd_dimm->del_info;

	del_info->nd_bus = nd_bus;
	get_device(&nd_bus->dev);
	del_info->nd_mem = nd_dimm->nd_mem;
	async_schedule_domain(nd_async_dimm_delete, del_info,
			&nd_async_domain);
}

void nd_synchronize(void)
{
	async_synchronize_full_domain(&nd_async_domain);
}

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

	if (!nd_dimm || cmd != NFIT_CMD_SET_CONFIG_DATA)
		return 0;

	nd_bus = walk_to_nd_bus(&nd_dimm->dev);
	wait_nd_bus_probe_idle(&nd_bus->dev);

	if (atomic_read(&nd_dimm->busy))
		return -EBUSY;
	return 0;
}

static int __nd_ioctl(struct nd_bus *nd_bus, struct nd_dimm *nd_dimm,
		int read_only, unsigned int cmd, unsigned long arg)
{
	struct nfit_bus_descriptor *nfit_desc = nd_bus->nfit_desc;
	void __user *p = (void __user *) arg;
	unsigned long dsm_mask;
	size_t buf_len = 0;
	void *buf = NULL;
	int rc;

	/* check if the command is supported */
	dsm_mask = nd_dimm ? nd_dimm->dsm_mask : nfit_desc->dsm_mask;
	if (!test_bit(_IOC_NR(cmd), &dsm_mask))
		return -ENXIO;

	/* fail write commands (when read-only), or unknown commands */
	switch (cmd) {
	case NFIT_IOCTL_VENDOR:
	case NFIT_IOCTL_SET_CONFIG_DATA:
	case NFIT_IOCTL_ARS_START:
		if (read_only)
			return -EPERM;
		/* fallthrough */
	case NFIT_IOCTL_SMART:
	case NFIT_IOCTL_DIMM_FLAGS:
	case NFIT_IOCTL_GET_CONFIG_SIZE:
	case NFIT_IOCTL_GET_CONFIG_DATA:
	case NFIT_IOCTL_ARS_CAP:
	case NFIT_IOCTL_ARS_QUERY:
	case NFIT_IOCTL_SMART_THRESHOLD:
		break;
	default:
		pr_debug("%s: unknown cmd: %d\n", __func__, _IOC_NR(cmd));
		return -ENOTTY;
	}

	/* validate input buffer / determine size */
	switch (cmd) {
	case NFIT_IOCTL_SMART:
		buf_len = sizeof(struct nfit_cmd_smart);
		break;
	case NFIT_IOCTL_DIMM_FLAGS:
		buf_len = sizeof(struct nfit_cmd_dimm_flags);
		break;
	case NFIT_IOCTL_VENDOR: {
		struct nfit_cmd_vendor_hdr nfit_cmd_v;
		struct nfit_cmd_vendor_tail nfit_cmd_vt;

		if (!access_ok(VERIFY_WRITE, p, sizeof(nfit_cmd_v)))
			return -EFAULT;
		if (copy_from_user(&nfit_cmd_v, p, sizeof(nfit_cmd_v)))
			return -EFAULT;
		buf_len = sizeof(nfit_cmd_v) + nfit_cmd_v.in_length;
		if (!access_ok(VERIFY_WRITE, p + buf_len, sizeof(nfit_cmd_vt)))
			return -EFAULT;
		if (copy_from_user(&nfit_cmd_vt, p + buf_len,
					sizeof(nfit_cmd_vt)))
			return -EFAULT;
		buf_len += sizeof(nfit_cmd_vt) + nfit_cmd_vt.out_length;
		break;
	}
	case NFIT_IOCTL_SET_CONFIG_DATA: {
		struct nfit_cmd_set_config_hdr nfit_cmd_set;

		if (!access_ok(VERIFY_WRITE, p, sizeof(nfit_cmd_set)))
			return -EFAULT;
		if (copy_from_user(&nfit_cmd_set, p, sizeof(nfit_cmd_set)))
			return -EFAULT;
		/* include input buffer size and trailing status */
		buf_len = sizeof(nfit_cmd_set) + nfit_cmd_set.in_length + 4;
		break;
	}
	case NFIT_IOCTL_ARS_START:
		buf_len = sizeof(struct nfit_cmd_ars_start);
		break;
	case NFIT_IOCTL_GET_CONFIG_SIZE:
		buf_len = sizeof(struct nfit_cmd_get_config_size);
		break;
	case NFIT_IOCTL_GET_CONFIG_DATA: {
		struct nfit_cmd_get_config_data_hdr nfit_cmd_get;

		if (!access_ok(VERIFY_WRITE, p, sizeof(nfit_cmd_get)))
			return -EFAULT;
		if (copy_from_user(&nfit_cmd_get, p, sizeof(nfit_cmd_get)))
			return -EFAULT;
		buf_len = sizeof(nfit_cmd_get) + nfit_cmd_get.in_length;
		break;
	}
	case NFIT_IOCTL_ARS_CAP:
		buf_len = sizeof(struct nfit_cmd_ars_cap);
		break;
	case NFIT_IOCTL_ARS_QUERY: {
		struct nfit_cmd_ars_query nfit_cmd_query;

		if (!access_ok(VERIFY_WRITE, p, sizeof(nfit_cmd_query)))
			return -EFAULT;
		if (copy_from_user(&nfit_cmd_query, p, sizeof(nfit_cmd_query)))
			return -EFAULT;
		buf_len = sizeof(nfit_cmd_query) + nfit_cmd_query.out_length
			- offsetof(struct nfit_cmd_ars_query, out_length);
		break;
	}
	case NFIT_IOCTL_SMART_THRESHOLD:
		buf_len = sizeof(struct nfit_cmd_smart_threshold);
		break;
	}

	if (!access_ok(VERIFY_WRITE, p, sizeof(buf_len)))
		return -EFAULT;

	if (buf_len > ND_IOCTL_MAX_BUFLEN) {
		pr_debug("%s: buf_len: %zd > %d\n",
				__func__, buf_len, ND_IOCTL_MAX_BUFLEN);
		return -EINVAL;
	}

	if (buf_len < KMALLOC_MAX_SIZE)
		buf = kmalloc(buf_len, GFP_KERNEL);

	if (!buf)
		buf = vmalloc(buf_len);

	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, p, buf_len)) {
		rc = -EFAULT;
		goto out;
	}

	nd_bus_lock(&nd_bus->dev);
	rc = nd_cmd_clear_to_send(nd_dimm, _IOC_NR(cmd));
	if (rc)
		goto out_unlock;

	rc = nfit_desc->nfit_ctl(nfit_desc, nd_dimm, _IOC_NR(cmd), buf, buf_len);
	if (rc < 0)
		goto out_unlock;
	if (copy_to_user(p, buf, buf_len))
		rc = -EFAULT;
 out_unlock:
	nd_bus_unlock(&nd_bus->dev);
 out:
	if (is_vmalloc_addr(buf))
		vfree(buf);
	else
		kfree(buf);
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
