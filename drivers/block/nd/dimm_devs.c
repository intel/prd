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
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include "nd-private.h"

static DEFINE_IDA(dimm_ida);

static void nd_dimm_release(struct device *dev)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);

	ida_simple_remove(&dimm_ida, nd_dimm->id);
	kfree(nd_dimm);
}

static struct device_type nd_dimm_device_type = {
	.name = "nd_dimm",
	.release = nd_dimm_release,
};

static bool is_nd_dimm(struct device *dev)
{
	return dev->type == &nd_dimm_device_type;
}

struct nd_dimm *to_nd_dimm(struct device *dev)
{
	struct nd_dimm *nd_dimm = container_of(dev, struct nd_dimm, dev);

	WARN_ON(!is_nd_dimm(dev));
	return nd_dimm;
}
EXPORT_SYMBOL_GPL(to_nd_dimm);

const char *nd_dimm_name(struct nd_dimm *nd_dimm)
{
	return dev_name(&nd_dimm->dev);
}
EXPORT_SYMBOL_GPL(nd_dimm_name);

void *nd_dimm_provider_data(struct nd_dimm *nd_dimm)
{
	return nd_dimm->provider_data;
}
EXPORT_SYMBOL_GPL(nd_dimm_provider_data);

struct nd_dimm *nd_dimm_create(struct nd_bus *nd_bus, void *provider_data,
		const struct attribute_group **groups, unsigned long flags)
{
	struct nd_dimm *nd_dimm = kzalloc(sizeof(*nd_dimm), GFP_KERNEL);
	struct device *dev;

	if (!nd_dimm)
		return NULL;

	nd_dimm->id = ida_simple_get(&dimm_ida, 0, 0, GFP_KERNEL);
	if (nd_dimm->id < 0) {
		kfree(nd_dimm);
		return NULL;
	}
	nd_dimm->provider_data = provider_data;
	nd_dimm->flags = flags;

	dev = &nd_dimm->dev;
	dev_set_name(dev, "nmem%d", nd_dimm->id);
	dev->parent = &nd_bus->dev;
	dev->type = &nd_dimm_device_type;
	dev->bus = &nd_bus_type;
	dev->groups = groups;
	if (device_register(dev) != 0) {
		put_device(dev);
		return NULL;
	}

	return nd_dimm;
}
EXPORT_SYMBOL_GPL(nd_dimm_create);
