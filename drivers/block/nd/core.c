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
#include <linux/slab.h>
#include "nd-private.h"
#include "libnd.h"

static DEFINE_IDA(nd_ida);

static void nd_bus_release(struct device *dev)
{
	struct nd_bus *nd_bus = container_of(dev, struct nd_bus, dev);

	ida_simple_remove(&nd_ida, nd_bus->id);
	kfree(nd_bus);
}

struct nd_bus *nd_bus_register(struct device *parent,
		struct nd_bus_descriptor *nd_desc)
{
	struct nd_bus *nd_bus = kzalloc(sizeof(*nd_bus), GFP_KERNEL);
	int rc;

	if (!nd_bus)
		return NULL;
	nd_bus->id = ida_simple_get(&nd_ida, 0, 0, GFP_KERNEL);
	if (nd_bus->id < 0) {
		kfree(nd_bus);
		return NULL;
	}
	nd_bus->nd_desc = nd_desc;
	nd_bus->dev.parent = parent;
	nd_bus->dev.release = nd_bus_release;
	dev_set_name(&nd_bus->dev, "ndbus%d", nd_bus->id);
	rc = device_register(&nd_bus->dev);
	if (rc) {
		dev_dbg(&nd_bus->dev, "device registration failed: %d\n", rc);
		put_device(&nd_bus->dev);
		return NULL;
	}

	return nd_bus;
}
EXPORT_SYMBOL_GPL(nd_bus_register);

void nd_bus_unregister(struct nd_bus *nd_bus)
{
	if (!nd_bus)
		return;
	device_unregister(&nd_bus->dev);
}
EXPORT_SYMBOL_GPL(nd_bus_unregister);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
