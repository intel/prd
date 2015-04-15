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
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/async.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/io.h>
#include "nd-private.h"
#include "nfit.h"

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

static long nd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return -ENXIO;
}

static const struct file_operations nd_bus_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.unlocked_ioctl = nd_ioctl,
	.compat_ioctl = nd_ioctl,
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
		goto err_chrdev;
	nd_bus_major = rc;

	nd_class = class_create(THIS_MODULE, "nd");
	if (IS_ERR(nd_class))
		goto err_class;

	return 0;

 err_class:
	unregister_chrdev(nd_bus_major, "ndctl");
 err_chrdev:
	bus_unregister(&nd_bus_type);

	return rc;
}

void __exit nd_bus_exit(void)
{
	class_destroy(nd_class);
	unregister_chrdev(nd_bus_major, "ndctl");
	bus_unregister(&nd_bus_type);
}
