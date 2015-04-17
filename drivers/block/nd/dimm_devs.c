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
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include "nd-private.h"
#include "nfit.h"
#include "nd.h"

static DEFINE_IDA(dimm_ida);

static void nd_dimm_release(struct device *dev)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);

	ida_simple_remove(&dimm_ida, nd_dimm->id);
	nd_dimm_delete(nd_dimm);
	kfree(nd_dimm);
}

static struct device_type nd_dimm_device_type = {
	.name = "nd_dimm",
	.release = nd_dimm_release,
};

bool is_nd_dimm(struct device *dev)
{
	return dev->type == &nd_dimm_device_type;
}

struct nd_dimm *to_nd_dimm(struct device *dev)
{
	struct nd_dimm *nd_dimm = container_of(dev, struct nd_dimm, dev);

	WARN_ON(!is_nd_dimm(dev));
	return nd_dimm;
}

static struct nfit_mem __iomem *to_nfit_mem(struct device *dev)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);
	struct nd_mem *nd_mem = nd_dimm->nd_mem;
	struct nfit_mem __iomem *nfit_mem = nd_mem->nfit_mem_dcr;

	return nfit_mem;
}

static struct nfit_dcr __iomem *to_nfit_dcr(struct device *dev)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);
	struct nd_mem *nd_mem = nd_dimm->nd_mem;
	struct nfit_dcr __iomem *nfit_dcr = nd_mem->nfit_dcr;

	return nfit_dcr;
}

u32 to_nfit_handle(struct nd_dimm *nd_dimm)
{
	struct nfit_mem __iomem *nfit_mem = nd_dimm->nd_mem->nfit_mem_dcr;

	return readl(&nfit_mem->nfit_handle);
}
EXPORT_SYMBOL(to_nfit_handle);

void *nd_dimm_get_pdata(struct nd_dimm *nd_dimm)
{
	if (nd_dimm)
		return nd_dimm->provider_data;
	return NULL;
}
EXPORT_SYMBOL(nd_dimm_get_pdata);

void nd_dimm_set_pdata(struct nd_dimm *nd_dimm, void *data)
{
	if (nd_dimm)
		nd_dimm->provider_data = data;
}
EXPORT_SYMBOL(nd_dimm_set_pdata);

unsigned long nd_dimm_get_dsm_mask(struct nd_dimm *nd_dimm)
{
	if (nd_dimm)
		return nd_dimm->dsm_mask;
	return 0;
}
EXPORT_SYMBOL(nd_dimm_get_dsm_mask);

void nd_dimm_set_dsm_mask(struct nd_dimm *nd_dimm, unsigned long dsm_mask)
{
	if (nd_dimm)
		nd_dimm->dsm_mask = dsm_mask;
}
EXPORT_SYMBOL(nd_dimm_set_dsm_mask);

static ssize_t handle_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%#x\n", to_nfit_handle(to_nd_dimm(dev)));
}
static DEVICE_ATTR_RO(handle);

static ssize_t phys_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nfit_mem __iomem *nfit_mem = to_nfit_mem(dev);

	return sprintf(buf, "%#x\n", readw(&nfit_mem->phys_id));
}
static DEVICE_ATTR_RO(phys_id);

static ssize_t vendor_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nfit_dcr __iomem *nfit_dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", readw(&nfit_dcr->vendor_id));
}
static DEVICE_ATTR_RO(vendor);

static ssize_t revision_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nfit_dcr __iomem *nfit_dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", readw(&nfit_dcr->revision_id));
}
static DEVICE_ATTR_RO(revision);

static ssize_t device_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nfit_dcr __iomem *nfit_dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", readw(&nfit_dcr->device_id));
}
static DEVICE_ATTR_RO(device);

static ssize_t format_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nfit_dcr __iomem *nfit_dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", readw(&nfit_dcr->fic));
}
static DEVICE_ATTR_RO(format);

static ssize_t serial_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nfit_dcr __iomem *nfit_dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", readl(&nfit_dcr->serial_number));
}
static DEVICE_ATTR_RO(serial);

static ssize_t commands_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);
	int cmd, len = 0;

	for_each_set_bit(cmd, &nd_dimm->dsm_mask, BITS_PER_LONG)
		len += sprintf(buf + len, "%s ", nfit_dimm_cmd_name(cmd));
	len += sprintf(buf + len, "\n");
	return len;
}
static DEVICE_ATTR_RO(commands);

static struct attribute *nd_dimm_attributes[] = {
	&dev_attr_handle.attr,
	&dev_attr_phys_id.attr,
	&dev_attr_vendor.attr,
	&dev_attr_device.attr,
	&dev_attr_format.attr,
	&dev_attr_serial.attr,
	&dev_attr_revision.attr,
	&dev_attr_commands.attr,
	NULL,
};

static umode_t nd_dimm_attr_visible(struct kobject *kobj, struct attribute *a, int n)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);

	if (a == &dev_attr_handle.attr || a == &dev_attr_phys_id.attr
			|| to_nfit_dcr(&nd_dimm->dev))
		return a->mode;
	else
		return 0;
}

static struct attribute_group nd_dimm_attribute_group = {
	.attrs = nd_dimm_attributes,
	.is_visible = nd_dimm_attr_visible,
};

static const struct attribute_group *nd_dimm_attribute_groups[] = {
	&nd_dimm_attribute_group,
	NULL,
};

static struct nd_dimm *nd_dimm_create(struct nd_bus *nd_bus,
		struct nd_mem *nd_mem)
{
	struct nd_dimm *nd_dimm = kzalloc(sizeof(*nd_dimm), GFP_KERNEL);
	struct nfit_bus_descriptor *nfit_desc = nd_bus->nfit_desc;
	struct device *dev;
	u32 nfit_handle;

	if (!nd_dimm)
		return NULL;

	nd_dimm->del_info = kzalloc(sizeof(struct nd_dimm_delete), GFP_KERNEL);
	if (!nd_dimm->del_info)
		goto err_del_info;
	nd_dimm->del_info->nd_bus = nd_bus;
	nd_dimm->del_info->nd_mem = nd_mem;

	nfit_handle = readl(&nd_mem->nfit_mem_dcr->nfit_handle);
	if (radix_tree_insert(&nd_bus->dimm_radix, nfit_handle, nd_dimm) != 0)
		goto err_radix;

	nd_dimm->id = ida_simple_get(&dimm_ida, 0, 0, GFP_KERNEL);
	if (nd_dimm->id < 0)
		goto err_ida;

	nd_dimm->nd_mem = nd_mem;
	dev = &nd_dimm->dev;
	dev_set_name(dev, "nmem%d", nd_dimm->id);
	dev->parent = &nd_bus->dev;
	dev->type = &nd_dimm_device_type;
	dev->bus = &nd_bus_type;
	dev->groups = nd_dimm_attribute_groups;
	dev->devt = MKDEV(nd_dimm_major, nd_dimm->id);
	if (nfit_desc->add_dimm)
		if (nfit_desc->add_dimm(nfit_desc, nd_dimm) != 0) {
			device_initialize(dev);
			put_device(dev);
			return NULL;
		}

	if (device_register(dev) != 0) {
		put_device(dev);
		return NULL;
	}

	return nd_dimm;
 err_ida:
	radix_tree_delete(&nd_bus->dimm_radix, nfit_handle);
 err_radix:
	kfree(nd_dimm->del_info);
 err_del_info:
	kfree(nd_dimm);
	return NULL;
}

int nd_bus_register_dimms(struct nd_bus *nd_bus)
{
	int rc = 0, dimm_count = 0;
	struct nd_mem *nd_mem;

	mutex_lock(&nd_bus_list_mutex);
	list_for_each_entry(nd_mem, &nd_bus->dimms, list) {
		struct nd_dimm *nd_dimm;
		u32 nfit_handle;

		nfit_handle = readl(&nd_mem->nfit_mem_dcr->nfit_handle);
		nd_dimm = nd_dimm_by_handle(nd_bus, nfit_handle);
		if (nd_dimm) {
			/*
			 * If for some reason we find multiple DCRs the
			 * first one wins
			 */
			dev_err(&nd_bus->dev, "duplicate DCR detected: %s\n",
				dev_name(&nd_dimm->dev));
			put_device(&nd_dimm->dev);
			continue;
		}

		if (!nd_dimm_create(nd_bus, nd_mem)) {
			rc = -ENOMEM;
			break;
		}
		dimm_count++;
	}
	mutex_unlock(&nd_bus_list_mutex);

	return rc;
}
