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

static int nd_bus_major;
static struct class *nd_class;

struct bus_type nd_bus_type = {
	.name = "nd",
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
