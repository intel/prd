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
#include <linux/list_sort.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/io.h>
#include "nd-private.h"
#include "nfit.h"
#include "nd.h"

LIST_HEAD(nd_bus_list);
DEFINE_MUTEX(nd_bus_list_mutex);
static DEFINE_IDA(nd_ida);

static bool warn_checksum;
module_param(warn_checksum, bool, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(warn_checksum, "Turn checksum errors into warnings");

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

/**
 * nd_dimm_by_handle - lookup an nd_dimm by its corresponding nfit_handle
 * @nd_bus: parent bus of the dimm
 * @nfit_handle: handle from the memory-device-to-spa (nfit_mem) structure
 *
 * LOCKING: expect nd_bus_list_mutex() held at entry
 */
struct nd_dimm *nd_dimm_by_handle(struct nd_bus *nd_bus, u32 nfit_handle)
{
	struct nd_dimm *nd_dimm;

	WARN_ON_ONCE(!mutex_is_locked(&nd_bus_list_mutex));
	nd_dimm = radix_tree_lookup(&nd_bus->dimm_radix, nfit_handle);
	if (nd_dimm)
		get_device(&nd_dimm->dev);
	return nd_dimm;
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

static void nd_bus_release(struct device *dev)
{
	struct nd_bus *nd_bus = container_of(dev, struct nd_bus, dev);
	struct nd_memdev *nd_memdev, *_memdev;
	struct nd_spa *nd_spa, *_spa;
	struct nd_mem *nd_mem, *_mem;
	struct nd_dcr *nd_dcr, *_dcr;
	struct nd_bdw *nd_bdw, *_bdw;

	list_for_each_entry_safe(nd_spa, _spa, &nd_bus->spas, list) {
		list_del_init(&nd_spa->list);
		kfree(nd_spa->nd_set);
		kfree(nd_spa);
	}
	list_for_each_entry_safe(nd_dcr, _dcr, &nd_bus->dcrs, list) {
		list_del_init(&nd_dcr->list);
		kfree(nd_dcr);
	}
	list_for_each_entry_safe(nd_bdw, _bdw, &nd_bus->bdws, list) {
		list_del_init(&nd_bdw->list);
		kfree(nd_bdw);
	}
	list_for_each_entry_safe(nd_memdev, _memdev, &nd_bus->memdevs, list) {
		list_del_init(&nd_memdev->list);
		kfree(nd_memdev);
	}
	list_for_each_entry_safe(nd_mem, _mem, &nd_bus->dimms, list) {
		list_del_init(&nd_mem->list);
		kfree(nd_mem);
	}

	ida_simple_remove(&nd_ida, nd_bus->id);
	kfree(nd_bus);
}

struct nd_bus *to_nd_bus(struct device *dev)
{
	struct nd_bus *nd_bus = container_of(dev, struct nd_bus, dev);

	WARN_ON(nd_bus->dev.release != nd_bus_release);
	return nd_bus;
}

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

static ssize_t commands_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int cmd, len = 0;
	struct nd_bus *nd_bus = to_nd_bus(dev);
	struct nfit_bus_descriptor *nfit_desc = nd_bus->nfit_desc;

	for_each_set_bit(cmd, &nfit_desc->dsm_mask, BITS_PER_LONG)
		len += sprintf(buf + len, "%s ", nfit_bus_cmd_name(cmd));
	len += sprintf(buf + len, "\n");
	return len;
}
static DEVICE_ATTR_RO(commands);

static const char *nd_bus_provider(struct nd_bus *nd_bus)
{
	struct nfit_bus_descriptor *nfit_desc = nd_bus->nfit_desc;
	struct device *parent = nd_bus->dev.parent;

	if (nfit_desc->provider_name)
		return nfit_desc->provider_name;
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

static ssize_t revision_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_bus *nd_bus = to_nd_bus(dev);
	struct nfit __iomem *nfit = nd_bus->nfit_desc->nfit_base;

	return sprintf(buf, "%d\n", readb(&nfit->revision));
}
static DEVICE_ATTR_RO(revision);

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

static struct attribute *nd_bus_attributes[] = {
	&dev_attr_commands.attr,
	&dev_attr_wait_probe.attr,
	&dev_attr_provider.attr,
	&dev_attr_revision.attr,
	NULL,
};

static struct attribute_group nd_bus_attribute_group = {
	.attrs = nd_bus_attributes,
};

static const struct attribute_group *nd_bus_attribute_groups[] = {
	&nd_bus_attribute_group,
	NULL,
};

static void *nd_bus_new(struct device *parent,
		struct nfit_bus_descriptor *nfit_desc, struct module *module)
{
	struct nd_bus *nd_bus = kzalloc(sizeof(*nd_bus), GFP_KERNEL);
	int rc;

	if (!nd_bus)
		return NULL;
	INIT_LIST_HEAD(&nd_bus->spas);
	INIT_LIST_HEAD(&nd_bus->dcrs);
	INIT_LIST_HEAD(&nd_bus->bdws);
	INIT_LIST_HEAD(&nd_bus->memdevs);
	INIT_LIST_HEAD(&nd_bus->dimms);
	INIT_LIST_HEAD(&nd_bus->list);
	init_waitqueue_head(&nd_bus->probe_wait);
	INIT_RADIX_TREE(&nd_bus->dimm_radix, GFP_KERNEL);
	nd_bus->id = ida_simple_get(&nd_ida, 0, 0, GFP_KERNEL);
	mutex_init(&nd_bus->reconfig_mutex);
	if (nd_bus->id < 0) {
		kfree(nd_bus);
		return NULL;
	}
	nd_bus->nfit_desc = nfit_desc;
	nd_bus->module = module;
	nd_bus->dev.parent = parent;
	nd_bus->dev.release = nd_bus_release;
	nd_bus->dev.groups = nd_bus_attribute_groups;
	dev_set_name(&nd_bus->dev, "ndbus%d", nd_bus->id);
	rc = device_register(&nd_bus->dev);
	if (rc) {
		dev_dbg(&nd_bus->dev, "device registration failed: %d\n", rc);
		put_device(&nd_bus->dev);
		return NULL;
	}
	return nd_bus;
}

struct nfit_table_header {
	__le16 type;
	__le16 length;
};

const char *spa_type_name(u16 type)
{
	switch (type) {
	case NFIT_SPA_VOLATILE: return "volatile";
	case NFIT_SPA_PM: return "pmem";
	case NFIT_SPA_DCR: return "dimm-control-region";
	case NFIT_SPA_BDW: return "block-data-window";
	default: return "unknown";
	}
}

int nfit_spa_type(struct nfit_spa __iomem *nfit_spa)
{
	__u8 uuid[16];

	memcpy_fromio(uuid, &nfit_spa->type_uuid, sizeof(uuid));

	if (memcmp(&nfit_spa_uuid_volatile, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_VOLATILE;

	if (memcmp(&nfit_spa_uuid_pm, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_PM;

	if (memcmp(&nfit_spa_uuid_dcr, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_DCR;

	if (memcmp(&nfit_spa_uuid_bdw, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_BDW;

	if (memcmp(&nfit_spa_uuid_vdisk, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_VDISK;

	if (memcmp(&nfit_spa_uuid_vcd, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_VCD;

	if (memcmp(&nfit_spa_uuid_pdisk, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_PDISK;

	if (memcmp(&nfit_spa_uuid_pcd, uuid, sizeof(uuid)) == 0)
		return NFIT_SPA_PCD;

	return -1;
}

static void __iomem *add_table(struct nd_bus *nd_bus, void __iomem *table,
		const void __iomem *end)
{
	struct nfit_table_header __iomem *hdr;
	void *ret = NULL;

	if (table >= end)
		goto err;

	ret = ERR_PTR(-ENOMEM);
	hdr = (struct nfit_table_header __iomem *) table;
	switch (readw(&hdr->type)) {
	case NFIT_TABLE_SPA: {
		struct nd_spa *nd_spa = kzalloc(sizeof(*nd_spa), GFP_KERNEL);
		struct nfit_spa __iomem *nfit_spa = table;

		if (!nd_spa)
			goto err;
		INIT_LIST_HEAD(&nd_spa->list);
		nd_spa->nfit_spa = nfit_spa;
		list_add_tail(&nd_spa->list, &nd_bus->spas);
		dev_dbg(&nd_bus->dev, "%s: spa index: %d type: %s\n", __func__,
				readw(&nfit_spa->spa_index),
				spa_type_name(nfit_spa_type(nfit_spa)));
		break;
	}
	case NFIT_TABLE_MEM: {
		struct nd_memdev *nd_memdev = kzalloc(sizeof(*nd_memdev),
						     GFP_KERNEL);
		struct nfit_mem __iomem *nfit_mem = table;

		if (!nd_memdev)
			goto err;
		INIT_LIST_HEAD(&nd_memdev->list);
		nd_memdev->nfit_mem = nfit_mem;
		list_add_tail(&nd_memdev->list, &nd_bus->memdevs);
		dev_dbg(&nd_bus->dev, "%s: memdev handle: %#x spa: %d dcr: %d\n",
				__func__, readl(&nfit_mem->nfit_handle),
				readw(&nfit_mem->spa_index),
				readw(&nfit_mem->dcr_index));
		break;
	}
	case NFIT_TABLE_DCR: {
		struct nd_dcr *nd_dcr = kzalloc(sizeof(*nd_dcr), GFP_KERNEL);
		struct nfit_dcr __iomem *nfit_dcr = table;

		if (!nd_dcr)
			goto err;
		INIT_LIST_HEAD(&nd_dcr->list);
		nd_dcr->nfit_dcr = nfit_dcr;
		list_add_tail(&nd_dcr->list, &nd_bus->dcrs);
		dev_dbg(&nd_bus->dev, "%s: dcr index: %d num_bcw: %d\n",
				__func__, readw(&nfit_dcr->dcr_index),
				readw(&nfit_dcr->num_bcw));
		break;
	}
	case NFIT_TABLE_BDW: {
		struct nd_bdw *nd_bdw = kzalloc(sizeof(*nd_bdw), GFP_KERNEL);
		struct nfit_bdw __iomem *nfit_bdw = table;

		if (!nd_bdw)
			goto err;
		INIT_LIST_HEAD(&nd_bdw->list);
		nd_bdw->nfit_bdw = nfit_bdw;
		list_add_tail(&nd_bdw->list, &nd_bus->bdws);
		dev_dbg(&nd_bus->dev, "%s: bdw dcr: %d num_bdw: %d\n", __func__,
				readw(&nfit_bdw->dcr_index),
				readw(&nfit_bdw->num_bdw));
		break;
	}
	/* TODO */
	case NFIT_TABLE_IDT:
		dev_dbg(&nd_bus->dev, "%s: idt\n", __func__);
		break;
	case NFIT_TABLE_FLUSH:
		dev_dbg(&nd_bus->dev, "%s: flush\n", __func__);
		break;
	case NFIT_TABLE_SMBIOS:
		dev_dbg(&nd_bus->dev, "%s: smbios\n", __func__);
		break;
	default:
		dev_err(&nd_bus->dev, "unknown table '%d' parsing nfit\n",
				readw(&hdr->type));
		ret = ERR_PTR(-EINVAL);
		goto err;
	}

	return table + readw(&hdr->length);
 err:
	return (void __iomem *) ret;
}

void nd_mem_find_spa_bdw(struct nd_bus *nd_bus, struct nd_mem *nd_mem)
{
	u32 nfit_handle = readl(&nd_mem->nfit_mem_dcr->nfit_handle);
	u16 dcr_index = readw(&nd_mem->nfit_dcr->dcr_index);
	struct nd_spa *nd_spa;

	list_for_each_entry(nd_spa, &nd_bus->spas, list) {
		u16 spa_index = readw(&nd_spa->nfit_spa->spa_index);
		int type = nfit_spa_type(nd_spa->nfit_spa);
		struct nd_memdev *nd_memdev;

		if (type != NFIT_SPA_BDW)
			continue;

		list_for_each_entry(nd_memdev, &nd_bus->memdevs, list) {
			if (readw(&nd_memdev->nfit_mem->spa_index) != spa_index)
				continue;
			if (readl(&nd_memdev->nfit_mem->nfit_handle) != nfit_handle)
				continue;
			if (readw(&nd_memdev->nfit_mem->dcr_index) != dcr_index)
				continue;

			nd_mem->nfit_spa_bdw = nd_spa->nfit_spa;
			return;
		}
	}

	dev_dbg(&nd_bus->dev, "SPA-BDW not found for SPA-DCR %d\n",
			readw(&nd_mem->nfit_spa_dcr->spa_index));
	nd_mem->nfit_bdw = NULL;
}

static void nd_mem_add(struct nd_bus *nd_bus, struct nd_mem *nd_mem)
{
	u16 dcr_index = readw(&nd_mem->nfit_mem_dcr->dcr_index);
	u16 spa_index = readw(&nd_mem->nfit_spa_dcr->spa_index);
	struct nd_dcr *nd_dcr;
	struct nd_bdw *nd_bdw;

	list_for_each_entry(nd_dcr, &nd_bus->dcrs, list) {
		if (readw(&nd_dcr->nfit_dcr->dcr_index) != dcr_index)
			continue;
		nd_mem->nfit_dcr = nd_dcr->nfit_dcr;
		break;
	}

	if (!nd_mem->nfit_dcr) {
		dev_dbg(&nd_bus->dev, "SPA-DCR %d missing:%s%s\n",
				spa_index, nd_mem->nfit_mem_dcr ? "" : " MEMDEV",
				nd_mem->nfit_dcr ? "" : " DCR");
		kfree(nd_mem);
		return;
	}

	/*
	 * We've found enough to create an nd_dimm, optionally
	 * find an associated BDW
	 */
	list_add(&nd_mem->list, &nd_bus->dimms);

	list_for_each_entry(nd_bdw, &nd_bus->bdws, list) {
		if (readw(&nd_bdw->nfit_bdw->dcr_index) != dcr_index)
			continue;
		nd_mem->nfit_bdw = nd_bdw->nfit_bdw;
		break;
	}

	if (!nd_mem->nfit_bdw)
		return;

	nd_mem_find_spa_bdw(nd_bus, nd_mem);
}

static int nd_mem_cmp(void *priv, struct list_head *__a, struct list_head *__b)
{
	struct nd_mem *a = container_of(__a, typeof(*a), list);
	struct nd_mem *b = container_of(__b, typeof(*b), list);
	u32 handleA, handleB;

	handleA = readl(&a->nfit_mem_dcr->nfit_handle);
	handleB = readl(&b->nfit_mem_dcr->nfit_handle);
	if (handleA < handleB)
		return -1;
	else if (handleA > handleB)
		return 1;
	return 0;
}

static int nd_mem_init(struct nd_bus *nd_bus)
{
	struct nd_spa *nd_spa;

	/*
	 * For each SPA-DCR address range find its corresponding
	 * MEMDEV(s).  From each MEMDEV find the corresponding DCR.
	 * Then, try to find a SPA-BDW and a corresponding BDW that
	 * references the DCR.  Throw it all into an nd_mem object.
	 * Note, that BDWs are optional.
	 */
	list_for_each_entry(nd_spa, &nd_bus->spas, list) {
		u16 spa_index = readw(&nd_spa->nfit_spa->spa_index);
		int type = nfit_spa_type(nd_spa->nfit_spa);
		struct nd_mem *nd_mem, *found;
		struct nd_memdev *nd_memdev;
		u16 dcr_index;

		if (type != NFIT_SPA_DCR)
			continue;

		/* multiple dimms may share a SPA_DCR when interleaved */
		list_for_each_entry(nd_memdev, &nd_bus->memdevs, list) {
			if (readw(&nd_memdev->nfit_mem->spa_index) != spa_index)
				continue;
			found = NULL;
			dcr_index = readw(&nd_memdev->nfit_mem->dcr_index);
			list_for_each_entry(nd_mem, &nd_bus->dimms, list)
				if (readw(&nd_mem->nfit_mem_dcr->dcr_index)
						== dcr_index) {
					found = nd_mem;
					break;
			}
			if (found)
				continue;

			nd_mem = kzalloc(sizeof(*nd_mem), GFP_KERNEL);
			if (!nd_mem)
				return -ENOMEM;
			INIT_LIST_HEAD(&nd_mem->list);
			nd_mem->nfit_spa_dcr = nd_spa->nfit_spa;
			nd_mem->nfit_mem_dcr = nd_memdev->nfit_mem;
			nd_mem_add(nd_bus, nd_mem);
		}
	}

	list_sort(NULL, &nd_bus->dimms, nd_mem_cmp);

	return 0;
}

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

static struct nd_bus *nd_bus_probe(struct nd_bus *nd_bus)
{
	struct nfit_bus_descriptor *nfit_desc = nd_bus->nfit_desc;
	struct nfit __iomem *nfit = nfit_desc->nfit_base;
	void __iomem *base = nfit;
	const void __iomem *end;
	u8 sum, signature[4];
	u8 __iomem *data;
	size_t size, i;
	int rc;

	size = nd_bus->nfit_desc->nfit_size;
	if (size < sizeof(struct nfit))
		goto err;

	size = min_t(u32, size, readl(&nfit->length));
	data = (u8 __iomem *) base;
	for (i = 0, sum = 0; i < size; i++)
		sum += readb(data + i);
	if (sum != 0 && !warn_checksum) {
		dev_dbg(&nd_bus->dev, "%s: nfit checksum failure\n", __func__);
		goto err;
	}
	WARN_TAINT_ONCE(sum != 0, TAINT_FIRMWARE_WORKAROUND,
			"nfit checksum failure, continuing...\n");

	memcpy_fromio(signature, &nfit->signature, sizeof(signature));
	if (memcmp(signature, "NFIT", 4) != 0) {
		dev_dbg(&nd_bus->dev, "%s: nfit signature mismatch\n",
				__func__);
		goto err;
	}

	end = base + size;
	base += sizeof(struct nfit);
	base = add_table(nd_bus, base, end);
	while (!IS_ERR_OR_NULL(base))
		base = add_table(nd_bus, base, end);

	if (IS_ERR(base)) {
		dev_dbg(&nd_bus->dev, "%s: nfit table parsing error: %ld\n",
				__func__, PTR_ERR(base));
		goto err;
	}

	rc = nd_mem_init(nd_bus);
	if (rc)
		goto err;

	rc = nd_bus_init_interleave_sets(nd_bus);
	if (rc)
		goto err;

	rc = nd_bus_create_ndctl(nd_bus);
	if (rc)
		goto err;

	rc = nd_bus_register_dimms(nd_bus);
	if (rc)
		goto err_child;

	rc = nd_bus_register_regions(nd_bus);
	if (rc)
		goto err_child;

	mutex_lock(&nd_bus_list_mutex);
	list_add_tail(&nd_bus->list, &nd_bus_list);
	mutex_unlock(&nd_bus_list_mutex);

	return nd_bus;
 err_child:
	device_for_each_child(&nd_bus->dev, NULL, child_unregister);
	nd_bus_destroy_ndctl(nd_bus);
 err:
	put_device(&nd_bus->dev);
	return NULL;

}

struct nd_bus *__nfit_bus_register(struct device *parent,
		struct nfit_bus_descriptor *nfit_desc,
		struct module *module)
{
	static DEFINE_MUTEX(mutex);
	struct nd_bus *nd_bus;

	/* enforce single bus at a time registration */
	mutex_lock(&mutex);
	nd_bus = nd_bus_new(parent, nfit_desc, module);
	nd_bus = nd_bus_probe(nd_bus);
	mutex_unlock(&mutex);

	if (!nd_bus)
		return NULL;

	return nd_bus;
}
EXPORT_SYMBOL(__nfit_bus_register);

void nfit_bus_unregister(struct nd_bus *nd_bus)
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
EXPORT_SYMBOL(nfit_bus_unregister);

static __init int nd_core_init(void)
{
	int rc;

	BUILD_BUG_ON(sizeof(struct nfit) != 40);
	BUILD_BUG_ON(sizeof(struct nfit_spa) != 56);
	BUILD_BUG_ON(sizeof(struct nfit_mem) != 48);
	BUILD_BUG_ON(sizeof(struct nfit_idt) != 16);
	BUILD_BUG_ON(sizeof(struct nfit_smbios) != 8);
	BUILD_BUG_ON(sizeof(struct nfit_dcr) != 80);
	BUILD_BUG_ON(sizeof(struct nfit_bdw) != 40);

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

static __exit void nd_core_exit(void)
{
	WARN_ON(!list_empty(&nd_bus_list));
	nd_region_exit();
	nd_dimm_exit();
	nd_bus_exit();
}
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
module_init(nd_core_init);
module_exit(nd_core_exit);
