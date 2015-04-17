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
#include <linux/fcntl.h>
#include <linux/async.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include "nd-private.h"
#include "nfit.h"
#include "nd.h"

int nd_dimm_major;
static int nd_bus_major;
static struct class *nd_class;

struct bus_type nd_bus_type = {
	.name = "nd",
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

	rc = nfit_desc->nfit_ctl(nfit_desc, nd_dimm, _IOC_NR(cmd), buf, buf_len);
	if (rc < 0)
		goto out;
	if (copy_to_user(p, buf, buf_len))
		rc = -EFAULT;
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

void __exit nd_bus_exit(void)
{
	class_destroy(nd_class);
	unregister_chrdev(nd_bus_major, "ndctl");
	unregister_chrdev(nd_dimm_major, "dimmctl");
	bus_unregister(&nd_bus_type);
}
