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
#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include "nd-private.h"
#include "nd.h"

static DEFINE_IDA(dimm_ida);

/*
 * Retrieve bus and dimm handle and return if this bus supports
 * get_config_data commands
 */
static int __validate_dimm(struct nd_dimm_drvdata *ndd)
{
	struct nd_dimm *nd_dimm;

	if (!ndd)
		return -EINVAL;

	nd_dimm = to_nd_dimm(ndd->dev);

	if (!nd_dimm->dsm_mask)
		return -ENXIO;
	if (!test_bit(ND_CMD_GET_CONFIG_DATA, nd_dimm->dsm_mask))
		return -ENXIO;

	return 0;
}

static int validate_dimm(struct nd_dimm_drvdata *ndd)
{
	int rc = __validate_dimm(ndd);

	if (rc && ndd)
		dev_dbg(ndd->dev, "%pf: %s error: %d\n",
				__builtin_return_address(0), __func__, rc);
	return rc;
}

/**
 * nd_dimm_init_nsarea - determine the geometry of a dimm's namespace area
 * @nd_dimm: dimm to initialize
 */
int nd_dimm_init_nsarea(struct nd_dimm_drvdata *ndd)
{
	struct nd_cmd_get_config_size *cmd = &ndd->nsarea;
	struct nd_bus *nd_bus = walk_to_nd_bus(ndd->dev);
	struct nd_bus_descriptor *nd_desc;
	int rc = validate_dimm(ndd);

	if (rc)
		return rc;

	if (cmd->config_size)
		return 0; /* already valid */

	memset(cmd, 0, sizeof(*cmd));
	nd_desc = nd_bus->nd_desc;
	return nd_desc->ndctl(nd_desc, to_nd_dimm(ndd->dev),
			ND_CMD_GET_CONFIG_SIZE, cmd, sizeof(*cmd));
}

int nd_dimm_init_config_data(struct nd_dimm_drvdata *ndd)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(ndd->dev);
	struct nd_cmd_get_config_data_hdr *cmd;
	struct nd_bus_descriptor *nd_desc;
	int rc = validate_dimm(ndd);
	u32 max_cmd_size, config_size;
	size_t offset;

	if (rc)
		return rc;

	if (ndd->data)
		return 0;

	if (ndd->nsarea.status || ndd->nsarea.max_xfer == 0
			|| ndd->nsarea.config_size < ND_LABEL_MIN_SIZE) {
		dev_dbg(ndd->dev, "failed to init config data area: (%d:%d)\n",
				ndd->nsarea.max_xfer, ndd->nsarea.config_size);
		return -ENXIO;
	}

	ndd->data = kmalloc(ndd->nsarea.config_size, GFP_KERNEL);
	if (!ndd->data)
		ndd->data = vmalloc(ndd->nsarea.config_size);

	if (!ndd->data)
		return -ENOMEM;

	max_cmd_size = min_t(u32, PAGE_SIZE, ndd->nsarea.max_xfer);
	cmd = kzalloc(max_cmd_size + sizeof(*cmd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	nd_desc = nd_bus->nd_desc;
	for (config_size = ndd->nsarea.config_size, offset = 0;
			config_size; config_size -= cmd->in_length,
			offset += cmd->in_length) {
		cmd->in_length = min(config_size, max_cmd_size);
		cmd->in_offset = offset;
		rc = nd_desc->ndctl(nd_desc, to_nd_dimm(ndd->dev),
				ND_CMD_GET_CONFIG_DATA, cmd,
				cmd->in_length + sizeof(*cmd));
		if (rc || cmd->status) {
			rc = -ENXIO;
			break;
		}
		memcpy(ndd->data + offset, cmd->out_buf, cmd->in_length);
	}
	dev_dbg(ndd->dev, "%s: len: %zd rc: %d\n", __func__, offset, rc);
	kfree(cmd);

	return rc;
}

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
EXPORT_SYMBOL_GPL(to_nd_dimm);

struct nd_dimm_drvdata *to_ndd(struct nd_mapping *nd_mapping)
{
	struct nd_dimm *nd_dimm = nd_mapping->nd_dimm;

	return dev_get_drvdata(&nd_dimm->dev);
}
EXPORT_SYMBOL(to_ndd);

const char *nd_dimm_name(struct nd_dimm *nd_dimm)
{
	return dev_name(&nd_dimm->dev);
}
EXPORT_SYMBOL_GPL(nd_dimm_name);

void *nd_dimm_provider_data(struct nd_dimm *nd_dimm)
{
	if (nd_dimm)
		return nd_dimm->provider_data;
	return NULL;
}
EXPORT_SYMBOL_GPL(nd_dimm_provider_data);

static ssize_t commands_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);
	int cmd, len = 0;

	if (!nd_dimm->dsm_mask)
		return sprintf(buf, "\n");

	for_each_set_bit(cmd, nd_dimm->dsm_mask, BITS_PER_LONG)
		len += sprintf(buf + len, "%s ", nd_dimm_cmd_name(cmd));
	len += sprintf(buf + len, "\n");
	return len;
}
static DEVICE_ATTR_RO(commands);

static ssize_t state_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);

	/*
	 * The state may be in the process of changing, userspace should
	 * quiesce probing if it wants a static answer
	 */
	nd_bus_lock(dev);
	nd_bus_unlock(dev);
	return sprintf(buf, "%s\n", atomic_read(&nd_dimm->busy)
			? "active" : "idle");
}
static DEVICE_ATTR_RO(state);

static struct attribute *nd_dimm_attributes[] = {
	&dev_attr_state.attr,
	&dev_attr_commands.attr,
	NULL,
};

struct attribute_group nd_dimm_attribute_group = {
	.attrs = nd_dimm_attributes,
};
EXPORT_SYMBOL_GPL(nd_dimm_attribute_group);

struct nd_dimm *nd_dimm_create(struct nd_bus *nd_bus, void *provider_data,
		const struct attribute_group **groups, unsigned long flags,
		unsigned long *dsm_mask)
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
	nd_dimm->dsm_mask = dsm_mask;
	atomic_set(&nd_dimm->busy, 0);
	dev = &nd_dimm->dev;
	dev_set_name(dev, "nmem%d", nd_dimm->id);
	dev->parent = &nd_bus->dev;
	dev->type = &nd_dimm_device_type;
	dev->devt = MKDEV(nd_dimm_major, nd_dimm->id);
	dev->groups = groups;
	nd_device_register(dev);

	return nd_dimm;
}
EXPORT_SYMBOL_GPL(nd_dimm_create);

/**
 * nd_pmem_available_dpa - for the given dimm+region account unallocated dpa
 * @nd_mapping: container of dpa-resource-root + labels
 * @nd_region: constrain available space check to this reference region
 * @overlap: calculate available space assuming this level of overlap
 *
 * Validate that a PMEM label, if present, aligns with the start of an
 * interleave set and truncate the available size at the lowest BLK
 * overlap point.
 *
 * The expectation is that this routine is called multiple times as it
 * probes for the largest BLK encroachment for any single member DIMM of
 * the interleave set.  Once that value is determined the PMEM-limit for
 * the set can be established.
 */
resource_size_t nd_pmem_available_dpa(struct nd_region *nd_region,
		struct nd_mapping *nd_mapping, resource_size_t *overlap)
{
	resource_size_t map_end, busy = 0, available, blk_start;
	struct nd_dimm_drvdata *ndd = to_ndd(nd_mapping);
	struct resource *res;
	const char *reason;

	if (!ndd)
		return 0;

	map_end = nd_mapping->start + nd_mapping->size - 1;
	blk_start = max(nd_mapping->start, map_end + 1 - *overlap);
	for_each_dpa_resource(ndd, res)
		if (res->start >= nd_mapping->start && res->start < map_end) {
			if (strncmp(res->name, "blk", 3) == 0)
				blk_start = min(blk_start, res->start);
			else if (res->start != nd_mapping->start) {
				reason = "misaligned to iset";
				goto err;
			} else {
				if (busy) {
					reason = "duplicate overlapping PMEM reservations?";
					goto err;
				}
				busy += resource_size(res);
				continue;
			}
		} else if (res->end >= nd_mapping->start && res->end <= map_end) {
			if (strncmp(res->name, "blk", 3) == 0) {
				/*
				 * If a BLK allocation overlaps the start of
				 * PMEM the entire interleave set may now only
				 * be used for BLK.
				 */
				blk_start = nd_mapping->start;
			} else {
				reason = "misaligned to iset";
				goto err;
			}
		} else if (nd_mapping->start > res->start
				&& nd_mapping->start < res->end) {
			/* total eclipse of the mapping */
			busy += nd_mapping->size;
			blk_start = nd_mapping->start;
		}

	*overlap = map_end + 1 - blk_start;
	available = blk_start - nd_mapping->start;
	if (busy < available)
		return available - busy;
	return 0;

 err:
	/*
	 * Something is wrong, PMEM must align with the start of the
	 * interleave set, and there can only be one allocation per set.
	 */
	nd_dbg_dpa(nd_region, ndd, res, "%s\n", reason);
	return 0;
}

void nd_dimm_free_dpa(struct nd_dimm_drvdata *ndd, struct resource *res)
{
	WARN_ON_ONCE(!is_nd_bus_locked(ndd->dev));
	kfree(res->name);
	__release_region(&ndd->dpa, res->start, resource_size(res));
}

struct resource *nd_dimm_allocate_dpa(struct nd_dimm_drvdata *ndd,
		struct nd_label_id *label_id, resource_size_t start,
		resource_size_t n)
{
	char *name = kmemdup(label_id, sizeof(*label_id), GFP_KERNEL);
	struct resource *res;

	if (!name)
		return NULL;

	WARN_ON_ONCE(!is_nd_bus_locked(ndd->dev));
	res = __request_region(&ndd->dpa, start, n, name, 0);
	if (!res)
		kfree(name);
	return res;
}

/**
 * nd_dimm_allocated_dpa - sum up the dpa currently allocated to this label_id
 * @nd_dimm: container of dpa-resource-root + labels
 * @label_id: dpa resource name of the form {pmem|blk}-<human readable uuid>
 */
resource_size_t nd_dimm_allocated_dpa(struct nd_dimm_drvdata *ndd,
		struct nd_label_id *label_id)
{
	resource_size_t allocated = 0;
	struct resource *res;

	for_each_dpa_resource(ndd, res)
		if (strcmp(res->name, label_id->id) == 0)
			allocated += resource_size(res);

	return allocated;
}

static int count_dimms(struct device *dev, void *c)
{
	int *count = c;

	if (is_nd_dimm(dev))
		(*count)++;
	return 0;
}

int nd_bus_validate_dimm_count(struct nd_bus *nd_bus, int dimm_count)
{
	int count = 0;
	/* Flush any possible dimm registration failures */
	nd_synchronize();

	device_for_each_child(&nd_bus->dev, &count, count_dimms);
	dev_dbg(&nd_bus->dev, "%s: count: %d\n", __func__, count);
	if (count != dimm_count)
		return -ENXIO;
	return 0;
}
EXPORT_SYMBOL_GPL(nd_bus_validate_dimm_count);
