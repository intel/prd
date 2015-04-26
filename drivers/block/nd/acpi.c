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
#include <linux/module.h>
#include <linux/list.h>
#include <linux/acpi.h>
#include "acpi_nfit.h"
#include "libnd.h"

static bool warn_checksum;
module_param(warn_checksum, bool, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(warn_checksum, "Turn checksum errors into warnings");

enum {
	NFIT_ACPI_NOTIFY_TABLE = 0x80,
};

static int nd_acpi_ctl(struct nd_bus_descriptor *nd_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len)
{
	return -ENOTTY;
}

static const char *spa_type_name(u16 type)
{
	switch (type) {
	case NFIT_SPA_VOLATILE: return "volatile";
	case NFIT_SPA_PM: return "pmem";
	case NFIT_SPA_DCR: return "dimm-control-region";
	case NFIT_SPA_BDW: return "block-data-window";
	default: return "unknown";
	}
}

static int nfit_spa_type(struct acpi_nfit_spa *spa)
{
	if (memcmp(&nfit_spa_uuid_volatile, spa->type_uuid, 16) == 0)
		return NFIT_SPA_VOLATILE;

	if (memcmp(&nfit_spa_uuid_pm, spa->type_uuid, 16) == 0)
		return NFIT_SPA_PM;

	if (memcmp(&nfit_spa_uuid_dcr, spa->type_uuid, 16) == 0)
		return NFIT_SPA_DCR;

	if (memcmp(&nfit_spa_uuid_bdw, spa->type_uuid, 16) == 0)
		return NFIT_SPA_BDW;

	if (memcmp(&nfit_spa_uuid_vdisk, spa->type_uuid, 16) == 0)
		return NFIT_SPA_VDISK;

	if (memcmp(&nfit_spa_uuid_vcd, spa->type_uuid, 16) == 0)
		return NFIT_SPA_VCD;

	if (memcmp(&nfit_spa_uuid_pdisk, spa->type_uuid, 16) == 0)
		return NFIT_SPA_PDISK;

	if (memcmp(&nfit_spa_uuid_pcd, spa->type_uuid, 16) == 0)
		return NFIT_SPA_PCD;

	return -1;
}

struct nfit_table_header {
	__le16 type;
	__le16 length;
};

static void *add_table(struct acpi_nfit_desc *acpi_desc, void *table, const void *end)
{
	struct device *dev = acpi_desc->dev;
	struct nfit_table_header *hdr;
	void *err = ERR_PTR(-ENOMEM);

	if (table >= end)
		return NULL;

	hdr = (struct nfit_table_header *) table;
	switch (hdr->type) {
	case NFIT_TABLE_SPA: {
		struct nfit_spa *nfit_spa = devm_kzalloc(dev, sizeof(*nfit_spa),
				GFP_KERNEL);
		struct acpi_nfit_spa *spa = table;

		if (!nfit_spa)
			return err;
		INIT_LIST_HEAD(&nfit_spa->list);
		nfit_spa->spa = spa;
		list_add_tail(&nfit_spa->list, &acpi_desc->spas);
		dev_dbg(dev, "%s: spa index: %d type: %s\n", __func__,
				spa->spa_index,
				spa_type_name(nfit_spa_type(spa)));
		break;
	}
	case NFIT_TABLE_MEM: {
		struct nfit_memdev *nfit_memdev = devm_kzalloc(dev,
				sizeof(*nfit_memdev), GFP_KERNEL);
		struct acpi_nfit_memdev *memdev = table;

		if (!nfit_memdev)
			return err;
		INIT_LIST_HEAD(&nfit_memdev->list);
		nfit_memdev->memdev = memdev;
		list_add_tail(&nfit_memdev->list, &acpi_desc->memdevs);
		dev_dbg(dev, "%s: memdev handle: %#x spa: %d dcr: %d\n",
				__func__, memdev->nfit_handle, memdev->spa_index,
				memdev->dcr_index);
		break;
	}
	case NFIT_TABLE_DCR: {
		struct nfit_dcr *nfit_dcr = devm_kzalloc(dev, sizeof(*nfit_dcr),
				GFP_KERNEL);
		struct acpi_nfit_dcr *dcr = table;

		if (!nfit_dcr)
			return err;
		INIT_LIST_HEAD(&nfit_dcr->list);
		nfit_dcr->dcr = dcr;
		list_add_tail(&nfit_dcr->list, &acpi_desc->dcrs);
		dev_dbg(dev, "%s: dcr index: %d num_bcw: %d\n", __func__,
				dcr->dcr_index, dcr->num_bcw);
		break;
	}
	case NFIT_TABLE_BDW: {
		struct nfit_bdw *nfit_bdw = devm_kzalloc(dev, sizeof(*nfit_bdw),
				GFP_KERNEL);
		struct acpi_nfit_bdw *bdw = table;

		if (!nfit_bdw)
			return err;
		INIT_LIST_HEAD(&nfit_bdw->list);
		nfit_bdw->bdw = bdw;
		list_add_tail(&nfit_bdw->list, &acpi_desc->bdws);
		dev_dbg(dev, "%s: bdw dcr: %d num_bdw: %d\n", __func__,
				bdw->dcr_index, bdw->num_bdw);
		break;
	}
	/* TODO */
	case NFIT_TABLE_IDT:
		dev_dbg(dev, "%s: idt\n", __func__);
		break;
	case NFIT_TABLE_FLUSH:
		dev_dbg(dev, "%s: flush\n", __func__);
		break;
	case NFIT_TABLE_SMBIOS:
		dev_dbg(dev, "%s: smbios\n", __func__);
		break;
	default:
		dev_err(dev, "unknown table '%d' parsing nfit\n", hdr->type);
		return ERR_PTR(-ENXIO);
	}

	return table + hdr->length;
}

static void nfit_mem_find_spa_bdw(struct acpi_nfit_desc *acpi_desc,
		struct nfit_mem *nfit_mem)
{
	u32 nfit_handle = __to_nfit_memdev(nfit_mem)->nfit_handle;
	u16 dcr_index = nfit_mem->dcr->dcr_index;
	struct nfit_spa *nfit_spa;

	list_for_each_entry(nfit_spa, &acpi_desc->spas, list) {
		u16 spa_index = nfit_spa->spa->spa_index;
		int type = nfit_spa_type(nfit_spa->spa);
		struct nfit_memdev *nfit_memdev;

		if (type != NFIT_SPA_BDW)
			continue;

		list_for_each_entry(nfit_memdev, &acpi_desc->memdevs, list) {
			if (nfit_memdev->memdev->spa_index != spa_index)
				continue;
			if (nfit_memdev->memdev->nfit_handle != nfit_handle)
				continue;
			if (nfit_memdev->memdev->dcr_index != dcr_index)
				continue;

			nfit_mem->spa_bdw = nfit_spa->spa;
			return;
		}
	}

	dev_dbg(acpi_desc->dev, "SPA-BDW not found for SPA-DCR %d\n",
			nfit_mem->spa_dcr->spa_index);
	nfit_mem->bdw = NULL;
}

static int nfit_mem_add(struct acpi_nfit_desc *acpi_desc,
		struct nfit_mem *nfit_mem, struct acpi_nfit_spa *spa)
{
	u16 dcr_index = __to_nfit_memdev(nfit_mem)->dcr_index;
	struct nfit_dcr *nfit_dcr;
	struct nfit_bdw *nfit_bdw;

	list_for_each_entry(nfit_dcr, &acpi_desc->dcrs, list) {
		if (nfit_dcr->dcr->dcr_index != dcr_index)
			continue;
		nfit_mem->dcr = nfit_dcr->dcr;
		break;
	}

	if (!nfit_mem->dcr) {
		dev_dbg(acpi_desc->dev, "SPA %d missing:%s%s\n", spa->spa_index,
				__to_nfit_memdev(nfit_mem) ? "" : " MEMDEV",
				nfit_mem->dcr ? "" : " DCR");
		return -ENODEV;
	}

	/*
	 * We've found enough to create an nd_dimm, optionally
	 * find an associated BDW
	 */
	list_add(&nfit_mem->list, &acpi_desc->dimms);

	list_for_each_entry(nfit_bdw, &acpi_desc->bdws, list) {
		if (nfit_bdw->bdw->dcr_index != dcr_index)
			continue;
		nfit_mem->bdw = nfit_bdw->bdw;
		break;
	}

	if (!nfit_mem->bdw)
		return 0;

	nfit_mem_find_spa_bdw(acpi_desc, nfit_mem);
	return 0;
}

static int nfit_mem_dcr_init(struct acpi_nfit_desc *acpi_desc,
		struct acpi_nfit_spa *spa)
{
	struct nfit_mem *nfit_mem, *found;
	struct nfit_memdev *nfit_memdev;
	int type = nfit_spa_type(spa);
	u16 dcr_index;

	switch (type) {
	case NFIT_SPA_DCR:
	case NFIT_SPA_PM:
		break;
	default:
		return 0;
	}

	list_for_each_entry(nfit_memdev, &acpi_desc->memdevs, list) {
		int rc;

		if (nfit_memdev->memdev->spa_index != spa->spa_index)
			continue;
		found = NULL;
		dcr_index = nfit_memdev->memdev->dcr_index;
		list_for_each_entry(nfit_mem, &acpi_desc->dimms, list)
			if (__to_nfit_memdev(nfit_mem)->dcr_index == dcr_index) {
				found = nfit_mem;
				break;
			}

		if (found)
			nfit_mem = found;
		else {
			nfit_mem = devm_kzalloc(acpi_desc->dev,
					sizeof(*nfit_mem), GFP_KERNEL);
			if (!nfit_mem)
				return -ENOMEM;
			INIT_LIST_HEAD(&nfit_mem->list);
		}

		if (type == NFIT_SPA_DCR) {
			/* multiple dimms may share a SPA when interleaved */
			nfit_mem->spa_dcr = spa;
			nfit_mem->memdev_dcr = nfit_memdev->memdev;
		} else {
			/*
			 * A single dimm may belong to multiple SPA-PM
			 * ranges, record at least one in addition to
			 * any SPA-DCR range.
			 */
			nfit_mem->memdev_pmem = nfit_memdev->memdev;
		}

		if (found)
			continue;

		rc = nfit_mem_add(acpi_desc, nfit_mem, spa);
		if (rc)
			return rc;
	}

	return 0;
}

static int nfit_mem_cmp(void *priv, struct list_head *__a, struct list_head *__b)
{
	struct nfit_mem *a = container_of(__a, typeof(*a), list);
	struct nfit_mem *b = container_of(__b, typeof(*b), list);
	u32 handleA, handleB;

	handleA = __to_nfit_memdev(a)->nfit_handle;
	handleB = __to_nfit_memdev(b)->nfit_handle;
	if (handleA < handleB)
		return -1;
	else if (handleA > handleB)
		return 1;
	return 0;
}

static int nfit_mem_init(struct acpi_nfit_desc *acpi_desc)
{
	struct nfit_spa *nfit_spa;

	/*
	 * For each SPA-DCR or SPA-PMEM address range find its
	 * corresponding MEMDEV(s).  From each MEMDEV find the
	 * corresponding DCR.  Then, if we're operating on a SPA-DCR,
	 * try to find a SPA-BDW and a corresponding BDW that references
	 * the DCR.  Throw it all into an nfit_mem object.  Note, that
	 * BDWs are optional.
	 */
	list_for_each_entry(nfit_spa, &acpi_desc->spas, list) {
		int rc;

		rc = nfit_mem_dcr_init(acpi_desc, nfit_spa->spa);
		if (rc)
			return rc;
	}

	list_sort(NULL, &acpi_desc->dimms, nfit_mem_cmp);

	return 0;
}

static ssize_t revision_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_bus *nd_bus = to_nd_bus(dev);
	struct nd_bus_descriptor *nd_desc = to_nd_desc(nd_bus);
	struct acpi_nfit_desc *acpi_desc = to_acpi_desc(nd_desc);

	return sprintf(buf, "%d\n", acpi_desc->nfit->revision);
}
static DEVICE_ATTR_RO(revision);

static struct attribute *nd_acpi_attributes[] = {
	&dev_attr_revision.attr,
	NULL,
};

static struct attribute_group nd_acpi_attribute_group = {
	.name = "nfit",
	.attrs = nd_acpi_attributes,
};

const struct attribute_group *nd_acpi_attribute_groups[] = {
	&nd_bus_attribute_group,
	&nd_acpi_attribute_group,
	NULL,
};
EXPORT_SYMBOL_GPL(nd_acpi_attribute_groups);

int nd_acpi_nfit_init(struct acpi_nfit_desc *acpi_desc, acpi_size sz)
{
	struct device *dev = acpi_desc->dev;
	const void *end;
	u8 *data, sum;
	acpi_size i;

	INIT_LIST_HEAD(&acpi_desc->spas);
	INIT_LIST_HEAD(&acpi_desc->dcrs);
	INIT_LIST_HEAD(&acpi_desc->bdws);
	INIT_LIST_HEAD(&acpi_desc->memdevs);
	INIT_LIST_HEAD(&acpi_desc->dimms);

	data = (u8 *) acpi_desc->nfit;
	for (i = 0, sum = 0; i < sz; i++)
		sum += readb(data + i);
	if (sum != 0 && !warn_checksum) {
		dev_dbg(dev, "%s: nfit checksum failure\n", __func__);
		return -ENXIO;
	}
	WARN_TAINT_ONCE(sum != 0, TAINT_FIRMWARE_WORKAROUND,
			"nfit checksum failure, continuing...\n");

	end = data + sz;
	data += sizeof(struct acpi_nfit);
	while (!IS_ERR_OR_NULL(data))
		data = add_table(acpi_desc, data, end);

	if (IS_ERR(data)) {
		dev_dbg(dev, "%s: nfit table parsing error: %ld\n", __func__,
				PTR_ERR(data));
		return PTR_ERR(data);
	}

	if (nfit_mem_init(acpi_desc) != 0)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL_GPL(nd_acpi_nfit_init);

static int nd_acpi_add(struct acpi_device *adev)
{
	struct nd_bus_descriptor *nd_desc;
	struct acpi_nfit_desc *acpi_desc;
	struct device *dev = &adev->dev;
	struct acpi_table_header *tbl;
	acpi_status status = AE_OK;
	acpi_size sz;
	int rc;

	status = acpi_get_table_with_size("NFIT", 0, &tbl, &sz);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "failed to find NFIT\n");
		return -ENXIO;
	}

	acpi_desc = devm_kzalloc(dev, sizeof(*acpi_desc), GFP_KERNEL);
	if (!acpi_desc)
		return -ENOMEM;

	dev_set_drvdata(dev, acpi_desc);
	acpi_desc->dev = dev;
	acpi_desc->nfit = (struct acpi_nfit *) tbl;
	nd_desc = &acpi_desc->nd_desc;
	nd_desc->provider_name = "ACPI.NFIT";
	nd_desc->ndctl = nd_acpi_ctl;
	nd_desc->attr_groups = nd_acpi_attribute_groups;

	acpi_desc->nd_bus = nd_bus_register(dev, nd_desc);
	if (!acpi_desc->nd_bus)
		return -ENXIO;

	rc = nd_acpi_nfit_init(acpi_desc, sz);
	if (rc) {
		nd_bus_unregister(acpi_desc->nd_bus);
		return rc;
	}
	return 0;
}

static int nd_acpi_remove(struct acpi_device *adev)
{
	struct acpi_nfit_desc *acpi_desc = dev_get_drvdata(&adev->dev);

	nd_bus_unregister(acpi_desc->nd_bus);
	return 0;
}

static void nd_acpi_notify(struct acpi_device *adev, u32 event)
{
	/* TODO: handle ACPI_NOTIFY_BUS_CHECK notification */
	dev_dbg(&adev->dev, "%s: event: %d\n", __func__, event);
}

static const struct acpi_device_id nd_acpi_ids[] = {
	{ "ACPI0012", 0 },
	{ "", 0 },
};
MODULE_DEVICE_TABLE(acpi, nd_acpi_ids);

static struct acpi_driver nd_acpi_driver = {
	.name = KBUILD_MODNAME,
	.ids = nd_acpi_ids,
	.flags = ACPI_DRIVER_ALL_NOTIFY_EVENTS,
	.ops = {
		.add = nd_acpi_add,
		.remove = nd_acpi_remove,
		.notify = nd_acpi_notify
	},
};

static __init int nd_acpi_init(void)
{
	BUILD_BUG_ON(sizeof(struct acpi_nfit) != 40);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_spa) != 56);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_memdev) != 48);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_idt) != 16);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_smbios) != 8);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_dcr) != 80);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_bdw) != 40);

	return acpi_bus_register_driver(&nd_acpi_driver);
}

static __exit void nd_acpi_exit(void)
{
	acpi_bus_unregister_driver(&nd_acpi_driver);
}

module_init(nd_acpi_init);
module_exit(nd_acpi_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
