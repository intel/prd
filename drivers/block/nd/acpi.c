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
#include <linux/mutex.h>
#include <linux/ndctl.h>
#include <linux/list.h>
#include <linux/acpi.h>
#include <linux/sort.h>
#include "acpi_nfit.h"
#include "libnd.h"
#include "nd.h"

static bool warn_checksum;
module_param(warn_checksum, bool, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(warn_checksum, "Turn checksum errors into warnings");

static bool force_enable_dimms;
module_param(force_enable_dimms, bool, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(force_enable_dimms, "Ignore _STA (ACPI DIMM device) status");

enum {
	NFIT_ACPI_NOTIFY_TABLE = 0x80,
};

static u8 nd_acpi_uuids[2][16]; /* initialized at nd_acpi_init */

static u8 *nd_acpi_bus_uuid(void)
{
	return nd_acpi_uuids[0];
}

static u8 *nd_acpi_dimm_uuid(void)
{
	return nd_acpi_uuids[1];
}

static struct acpi_nfit_desc *to_acpi_nfit_desc(struct nd_bus_descriptor *nd_desc)
{
	return container_of(nd_desc, struct acpi_nfit_desc, nd_desc);
}

static struct acpi_device *to_acpi_dev(struct acpi_nfit_desc *acpi_desc)
{
	struct nd_bus_descriptor *nd_desc = &acpi_desc->nd_desc;

	/*
	 * If provider == 'ACPI.NFIT' we can assume 'dev' is a struct
	 * acpi_device.
	 */
	if (!nd_desc->provider_name
			|| strcmp(nd_desc->provider_name, "ACPI.NFIT") != 0)
		return NULL;

	return to_acpi_device(acpi_desc->dev);
}

static int nd_acpi_ctl(struct nd_bus_descriptor *nd_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len)
{
	struct acpi_nfit_desc *acpi_desc = to_acpi_nfit_desc(nd_desc);
	const struct nd_cmd_desc const *desc = NULL;
	union acpi_object in_obj, in_buf, *out_obj;
	struct device *dev = acpi_desc->dev;
	const char *cmd_name, *dimm_name;
	unsigned long dsm_mask;
	acpi_handle handle;
	u32 offset;
	int rc, i;
	u8 *uuid;

	if (nd_dimm) {
		struct nfit_mem *nfit_mem = nd_dimm_provider_data(nd_dimm);
		struct acpi_device *adev = nfit_mem->adev;

		if (!adev)
			return -ENOTTY;
		dimm_name = nd_dimm_name(nd_dimm);
		cmd_name = nd_dimm_cmd_name(cmd);
		dsm_mask = nfit_mem->dsm_mask;
		desc = nd_cmd_dimm_desc(cmd);
		uuid = nd_acpi_dimm_uuid();
		handle = adev->handle;
	} else {
		struct acpi_device *adev = to_acpi_dev(acpi_desc);

		cmd_name = nd_bus_cmd_name(cmd);
		dsm_mask = nd_desc->dsm_mask;
		desc = nd_cmd_bus_desc(cmd);
		uuid = nd_acpi_bus_uuid();
		handle = adev->handle;
		dimm_name = "bus";
	}

	if (!desc || (cmd && (desc->out_num + desc->in_num == 0)))
		return -ENOTTY;

	if (!test_bit(cmd, &dsm_mask))
		return -ENOTTY;

	in_obj.type = ACPI_TYPE_PACKAGE;
	in_obj.package.count = 1;
	in_obj.package.elements = &in_buf;
	in_buf.type = ACPI_TYPE_BUFFER;
	in_buf.buffer.pointer = buf;
	in_buf.buffer.length = 0;

	/* libnd has already validated the input envelope */
	for (i = 0; i < desc->in_num; i++)
		in_buf.buffer.length += nd_cmd_in_size(nd_dimm, cmd, desc, i, buf);

	dev_dbg(dev, "%s:%s cmd: %s input length: %d\n", __func__, dimm_name,
			cmd_name, in_buf.buffer.length);
	if (IS_ENABLED(CONFIG_ND_ACPI_DEBUG))
		print_hex_dump_debug(cmd_name, DUMP_PREFIX_OFFSET, 4,
				4, in_buf.buffer.pointer, min_t(u32, 128,
					in_buf.buffer.length), true);

	out_obj = acpi_evaluate_dsm(handle, uuid, 1, cmd, &in_obj);
	if (!out_obj) {
		dev_dbg(dev, "%s:%s _DSM failed cmd: %s\n", __func__, dimm_name,
				cmd_name);
		return -EINVAL;
	}

	if (out_obj->package.type != ACPI_TYPE_BUFFER) {
		dev_dbg(dev, "%s:%s unexpected output object type cmd: %s type: %d\n",
				__func__, dimm_name, cmd_name, out_obj->type);
		rc = -EINVAL;
		goto out;
	}

	dev_dbg(dev, "%s:%s cmd: %s output length: %d\n", __func__, dimm_name,
			cmd_name, out_obj->buffer.length);
	if (IS_ENABLED(CONFIG_ND_ACPI_DEBUG))
		print_hex_dump_debug(cmd_name, DUMP_PREFIX_OFFSET, 4,
				4, out_obj->buffer.pointer, min_t(u32, 128,
					out_obj->buffer.length), true);

	for (i = 0, offset = 0; i < desc->out_num; i++) {
		u32 out_size = nd_cmd_out_size(nd_dimm, cmd, desc, i, buf,
				(u32 *) out_obj->buffer.pointer);

		if (offset + out_size > out_obj->buffer.length) {
			dev_dbg(dev, "%s:%s output object underflow cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			break;
		}

		if (in_buf.buffer.length + offset + out_size > buf_len) {
			dev_dbg(dev, "%s:%s output overrun cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			rc = -ENXIO;
			goto out;
		}
		memcpy(buf + in_buf.buffer.length + offset,
				out_obj->buffer.pointer + offset, out_size);
		offset += out_size;
	}
	if (offset + in_buf.buffer.length < buf_len) {
		if (i >= 1) {
			/*
			 * status valid, return the number of bytes left
			 * unfilled in the output buffer
			 */
			rc = buf_len - offset - in_buf.buffer.length;
		} else {
			dev_err(dev, "%s:%s underrun cmd: %s buf_len: %d out_len: %d\n",
					__func__, dimm_name, cmd_name, buf_len, offset);
			rc = -ENXIO;
		}
	} else
		rc = 0;

 out:
	ACPI_FREE(out_obj);

	return rc;
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
	case NFIT_TABLE_IDT: {
		struct nfit_idt *nfit_idt = devm_kzalloc(dev, sizeof(*nfit_idt),
				GFP_KERNEL);
		struct acpi_nfit_idt *idt = table;

		if (!nfit_idt)
			return err;
		INIT_LIST_HEAD(&nfit_idt->list);
		nfit_idt->idt = idt;
		list_add_tail(&nfit_idt->list, &acpi_desc->idts);
		dev_dbg(dev, "%s: idt index: %d num_lines: %d\n", __func__,
				idt->idt_index, idt->num_lines);
		break;
	}
	/* TODO */
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
	struct nfit_memdev *nfit_memdev;
	struct nfit_dcr *nfit_dcr;
	struct nfit_bdw *nfit_bdw;
	struct nfit_idt *nfit_idt;
	u16 idt_index, spa_index;

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

	if (!nfit_mem->spa_bdw)
		return 0;

	spa_index = nfit_mem->spa_bdw->spa_index;
	list_for_each_entry(nfit_memdev, &acpi_desc->memdevs, list) {
		if (nfit_memdev->memdev->spa_index != spa_index ||
				nfit_memdev->memdev->dcr_index != dcr_index)
			continue;
		nfit_mem->memdev_bdw = nfit_memdev->memdev;
		idt_index = nfit_memdev->memdev->idt_index;
		list_for_each_entry(nfit_idt, &acpi_desc->idts, list) {
			if (nfit_idt->idt->idt_index != idt_index)
				continue;
			nfit_mem->idt_bdw = nfit_idt->idt;
			break;
		}
		break;
	}

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
			struct nfit_idt *nfit_idt;
			u16 idt_index;

			/* multiple dimms may share a SPA when interleaved */
			nfit_mem->spa_dcr = spa;
			nfit_mem->memdev_dcr = nfit_memdev->memdev;
			idt_index = nfit_memdev->memdev->idt_index;
			list_for_each_entry(nfit_idt, &acpi_desc->idts, list) {
				if (nfit_idt->idt->idt_index != idt_index)
					continue;
				nfit_mem->idt_dcr = nfit_idt->idt;
				break;
			}
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

static struct acpi_nfit_memdev *to_nfit_memdev(struct device *dev)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);
	struct nfit_mem *nfit_mem = nd_dimm_provider_data(nd_dimm);

	return __to_nfit_memdev(nfit_mem);
}

static struct acpi_nfit_dcr *to_nfit_dcr(struct device *dev)
{
	struct nd_dimm *nd_dimm = to_nd_dimm(dev);
	struct nfit_mem *nfit_mem = nd_dimm_provider_data(nd_dimm);

	return nfit_mem->dcr;
}

static ssize_t handle_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_memdev *memdev = to_nfit_memdev(dev);

	return sprintf(buf, "%#x\n", memdev->nfit_handle);
}
static DEVICE_ATTR_RO(handle);

static ssize_t phys_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_memdev *memdev = to_nfit_memdev(dev);

	return sprintf(buf, "%#x\n", memdev->phys_id);
}
static DEVICE_ATTR_RO(phys_id);

static ssize_t vendor_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_dcr *dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", dcr->vendor_id);
}
static DEVICE_ATTR_RO(vendor);

static ssize_t rev_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_dcr *dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", dcr->revision_id);
}
static DEVICE_ATTR_RO(rev_id);

static ssize_t device_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_dcr *dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", dcr->device_id);
}
static DEVICE_ATTR_RO(device);

static ssize_t format_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_dcr *dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", dcr->fic);
}
static DEVICE_ATTR_RO(format);

static ssize_t serial_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct acpi_nfit_dcr *dcr = to_nfit_dcr(dev);

	return sprintf(buf, "%#x\n", dcr->serial_number);
}
static DEVICE_ATTR_RO(serial);

static struct attribute *nd_acpi_dimm_attributes[] = {
	&dev_attr_handle.attr,
	&dev_attr_phys_id.attr,
	&dev_attr_vendor.attr,
	&dev_attr_device.attr,
	&dev_attr_format.attr,
	&dev_attr_serial.attr,
	&dev_attr_rev_id.attr,
	NULL,
};

static umode_t nd_acpi_dimm_attr_visible(struct kobject *kobj, struct attribute *a, int n)
{
	struct device *dev = container_of(kobj, struct device, kobj);

	if (to_nfit_dcr(dev))
		return a->mode;
	else
		return 0;
}

static struct attribute_group nd_acpi_dimm_attribute_group = {
	.name = "nfit",
	.attrs = nd_acpi_dimm_attributes,
	.is_visible = nd_acpi_dimm_attr_visible,
};

static const struct attribute_group *nd_acpi_dimm_attribute_groups[] = {
	&nd_dimm_attribute_group,
	&nd_device_attribute_group,
	&nd_acpi_dimm_attribute_group,
	NULL,
};

static struct nd_dimm *nd_acpi_dimm_by_handle(struct acpi_nfit_desc *acpi_desc,
		u32 nfit_handle)
{
	struct nfit_mem *nfit_mem;

	list_for_each_entry(nfit_mem, &acpi_desc->dimms, list)
		if (__to_nfit_memdev(nfit_mem)->nfit_handle == nfit_handle)
			return nfit_mem->nd_dimm;

	return NULL;
}

static int nd_acpi_add_dimm(struct acpi_nfit_desc *acpi_desc,
		struct nfit_mem *nfit_mem, u32 nfit_handle)
{
	struct acpi_device *adev, *adev_dimm;
	struct device *dev = acpi_desc->dev;
	u8 *uuid = nd_acpi_dimm_uuid();
	unsigned long long sta;
	int i, rc = -ENODEV;
	acpi_status status;

	nfit_mem->dsm_mask = acpi_desc->dimm_dsm_force_en;
	adev = to_acpi_dev(acpi_desc);
	if (!adev)
		return 0;

	adev_dimm = acpi_find_child_device(adev, nfit_handle, false);
	nfit_mem->adev = adev_dimm;
	if (!adev_dimm) {
		dev_err(dev, "no ACPI.NFIT device with _ADR %#x, disabling...\n",
				nfit_handle);
		return force_enable_dimms ? 0 : -ENODEV;
	}

	status = acpi_evaluate_integer(adev_dimm->handle, "_STA", NULL, &sta);
	if (status == AE_NOT_FOUND) {
		dev_dbg(dev, "%s missing _STA, assuming enabled...\n",
				dev_name(&adev_dimm->dev));
		rc = 0;
	} else if (ACPI_FAILURE(status))
		dev_err(dev, "%s failed to retrieve_STA, disabling...\n",
				dev_name(&adev_dimm->dev));
	else if ((sta & ACPI_STA_DEVICE_ENABLED) == 0)
		dev_info(dev, "%s disabled by firmware\n",
				dev_name(&adev_dimm->dev));
	else
		rc = 0;

	for (i = ND_CMD_SMART; i <= ND_CMD_VENDOR; i++)
		if (acpi_check_dsm(adev_dimm->handle, uuid, 1, 1ULL << i))
			set_bit(i, &nfit_mem->dsm_mask);

	return force_enable_dimms ? 0 : rc;
}

static int nd_acpi_register_dimms(struct acpi_nfit_desc *acpi_desc)
{
	struct nfit_mem *nfit_mem;
	int dimm_count = 0;

	list_for_each_entry(nfit_mem, &acpi_desc->dimms, list) {
		struct nd_dimm *nd_dimm;
		unsigned long flags = 0;
		u32 nfit_handle;
		int rc;

		nfit_handle = __to_nfit_memdev(nfit_mem)->nfit_handle;
		nd_dimm = nd_acpi_dimm_by_handle(acpi_desc, nfit_handle);
		if (nd_dimm) {
			/*
			 * If for some reason we find multiple DCRs the
			 * first one wins
			 */
			dev_err(acpi_desc->dev, "duplicate DCR detected: %s\n",
					nd_dimm_name(nd_dimm));
			continue;
		}

		if (nfit_mem->bdw && nfit_mem->memdev_pmem)
			flags |= NDD_ALIASING;

		rc = nd_acpi_add_dimm(acpi_desc, nfit_mem, nfit_handle);
		if (rc)
			continue;

		nd_dimm = nd_dimm_create(acpi_desc->nd_bus, nfit_mem,
				nd_acpi_dimm_attribute_groups,
				flags, &nfit_mem->dsm_mask);
		if (!nd_dimm)
			return -ENOMEM;

		nfit_mem->nd_dimm = nd_dimm;
		dimm_count++;
	}

	return nd_bus_validate_dimm_count(acpi_desc->nd_bus, dimm_count);
}

static void nd_acpi_init_dsms(struct acpi_nfit_desc *acpi_desc)
{
	struct nd_bus_descriptor *nd_desc = &acpi_desc->nd_desc;
	u8 *uuid = nd_acpi_bus_uuid();
	struct acpi_device *adev;
	int i;

	adev = to_acpi_dev(acpi_desc);
	if (!adev)
		return;

	for (i = ND_CMD_ARS_CAP; i <= ND_CMD_ARS_QUERY; i++)
		if (acpi_check_dsm(adev->handle, uuid, 1, 1ULL << i))
			set_bit(i, &nd_desc->dsm_mask);
}

static ssize_t spa_index_show(struct device *dev,
                struct device_attribute *attr, char *buf)
{
        struct nd_region *nd_region = to_nd_region(dev);
        struct nfit_spa *nfit_spa = nd_region->provider_data;

        return sprintf(buf, "%d\n", nfit_spa->spa->spa_index);
}
static DEVICE_ATTR_RO(spa_index);

static struct attribute *nd_acpi_region_attributes[] = {
	&dev_attr_spa_index.attr,
	NULL,
};

static struct attribute_group nd_acpi_region_attribute_group = {
	.name = "nfit",
	.attrs = nd_acpi_region_attributes,
};

static const struct attribute_group *nd_acpi_region_attribute_groups[] = {
	&nd_region_attribute_group,
	&nd_mapping_attribute_group,
	&nd_device_attribute_group,
	&nd_acpi_region_attribute_group,
	NULL,
};

/* enough info to uniquely specify an interleave set */
struct nfit_set_info {
	struct nfit_set_info_map {
		u64 region_spa_offset;
		u32 serial_number;
		u32 pad;
	} mapping[0];
};

static size_t sizeof_nfit_set_info(int num_mappings)
{
	return sizeof(struct nfit_set_info)
		+ num_mappings * sizeof(struct nfit_set_info_map);
}

static int cmp_map(const void *m0, const void *m1)
{
	const struct nfit_set_info_map *map0 = m0;
	const struct nfit_set_info_map *map1 = m1;

	return memcmp(&map0->region_spa_offset, &map1->region_spa_offset,
			sizeof(u64));
}

/* Retrieve the nth entry referencing this spa */
static struct acpi_nfit_memdev *memdev_from_spa(
		struct acpi_nfit_desc *acpi_desc, u16 spa_index, int n)
{
        struct nfit_memdev *nfit_memdev;

        list_for_each_entry(nfit_memdev, &acpi_desc->memdevs, list)
                if (nfit_memdev->memdev->spa_index == spa_index)
                        if (n-- == 0)
                                return nfit_memdev->memdev;
        return NULL;
}

static int nd_acpi_init_interleave_set(struct acpi_nfit_desc *acpi_desc,
		struct nd_region_desc *ndr_desc, struct acpi_nfit_spa *spa)
{
	u16 num_mappings = ndr_desc->num_mappings;
	int i, spa_type = nfit_spa_type(spa);
	struct device *dev = acpi_desc->dev;
	struct nd_interleave_set *nd_set;
	struct nfit_set_info *info;

	if (spa_type == NFIT_SPA_PM || spa_type == NFIT_SPA_VOLATILE)
		/* pass */;
	else
		return 0;

	nd_set = devm_kzalloc(dev, sizeof(*nd_set), GFP_KERNEL);
	if (!nd_set)
		return -ENOMEM;

	info = devm_kzalloc(dev, sizeof_nfit_set_info(num_mappings), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	for (i = 0; i < num_mappings; i++) {
		struct nd_mapping *nd_mapping = &ndr_desc->nd_mapping[i];
		struct nfit_set_info_map *map = &info->mapping[i];
		struct nd_dimm *nd_dimm = nd_mapping->nd_dimm;
		struct nfit_mem *nfit_mem = nd_dimm_provider_data(nd_dimm);
		struct acpi_nfit_memdev *memdev = memdev_from_spa(acpi_desc,
				spa->spa_index, i);

		if (!memdev || !nfit_mem->dcr) {
			dev_err(dev, "%s: failed to find DCR\n", __func__);
			return -ENODEV;
		}

		map->region_spa_offset = memdev->region_spa_offset;
		map->serial_number = nfit_mem->dcr->serial_number;
	}

	sort(&info->mapping[0], num_mappings, sizeof(struct nfit_set_info_map),
			cmp_map, NULL);
	nd_set->cookie = nd_fletcher64(info, sizeof_nfit_set_info(num_mappings));
	ndr_desc->nd_set = nd_set;
	devm_kfree(dev, info);

	return 0;
}

static u64 to_interleave_offset(u64 offset, struct nfit_blk_mmio *mmio)
{
	struct acpi_nfit_idt *idt = mmio->idt;
	u32 sub_line_offset, line_index, line_offset;
	u64 line_no, table_skip_count, table_offset;

	line_no = div_u64_rem(offset, mmio->line_size, &sub_line_offset);
	table_skip_count = div_u64_rem(line_no, mmio->num_lines, &line_index);
	line_offset = idt->line_offset[line_index]
		* mmio->line_size;
	table_offset = table_skip_count * mmio->table_size;

	return mmio->base_offset + line_offset + table_offset + sub_line_offset;
}

static u64 read_blk_stat(struct nfit_blk *nfit_blk, unsigned int bw)
{
	struct nfit_blk_mmio *mmio = &nfit_blk->mmio[DCR];
	u64 offset = nfit_blk->stat_offset + mmio->size * bw;

	if (mmio->num_lines)
		offset = to_interleave_offset(offset, mmio);

	return readq(mmio->base + offset);
}

static void write_blk_ctl(struct nfit_blk *nfit_blk, unsigned int bw,
		resource_size_t dpa, unsigned int len, unsigned int write)
{
	u64 cmd, offset;
	struct nfit_blk_mmio *mmio = &nfit_blk->mmio[DCR];

	enum {
		BCW_OFFSET_MASK = (1ULL << 48)-1,
		BCW_LEN_SHIFT = 48,
		BCW_LEN_MASK = (1ULL << 8) - 1,
		BCW_CMD_SHIFT = 56,
	};

	cmd = (dpa >> L1_CACHE_SHIFT) & BCW_OFFSET_MASK;
	len = len >> L1_CACHE_SHIFT;
	cmd |= ((u64) len & BCW_LEN_MASK) << BCW_LEN_SHIFT;
	cmd |= ((u64) write) << BCW_CMD_SHIFT;

	offset = nfit_blk->cmd_offset + mmio->size * bw;
	if (mmio->num_lines)
		offset = to_interleave_offset(offset, mmio);

	writeq(cmd, mmio->base + offset);
	/* FIXME: conditionally perform read-back if mandated by firmware */
}

/* len is <= PAGE_SIZE by this point, so it can be done in a single BW I/O */
static int nd_acpi_blk_region_do_io(struct nd_blk_region *ndbr, void *iobuf,
		unsigned int len, int write, resource_size_t dpa)
{
	struct nfit_blk *nfit_blk = ndbr->blk_provider_data;
	struct nfit_blk_mmio *mmio = &nfit_blk->mmio[BDW];
	struct nd_region *nd_region = &ndbr->nd_region;
	unsigned int bw, copied = 0;
	u64 base_offset;
	int rc;

	bw = nd_region_acquire_lane(nd_region);
	base_offset = nfit_blk->bdw_offset + dpa % L1_CACHE_BYTES + bw * mmio->size;
	/* TODO: non-temporal access, flush hints, cache management etc... */
	write_blk_ctl(nfit_blk, bw, dpa, len, write);
	while (len) {
		unsigned int c;
		u64 offset;

		if (mmio->num_lines) {
			u32 line_offset;

			offset = to_interleave_offset(base_offset + copied,
					mmio);
			div_u64_rem(offset, mmio->line_size, &line_offset);
			c = min(len, mmio->line_size - line_offset);
		} else {
			offset = base_offset + nfit_blk->bdw_offset;
			c = len;
		}

		if (write)
			memcpy(mmio->base + offset, iobuf + copied, c);
		else
			memcpy(iobuf + copied, mmio->base + offset, c);

		len -= c;
		copied += c;
	}
	rc = read_blk_stat(nfit_blk, bw) ? -EIO : 0;
	nd_region_release_lane(nd_region, bw);

	return rc;
}

static void nfit_spa_mapping_release(struct kref *kref)
{
	struct nfit_spa_mapping *spa_map = to_spa_map(kref);
	struct acpi_nfit_spa *spa = spa_map->spa;
	struct acpi_nfit_desc *acpi_desc = spa_map->acpi_desc;

	WARN_ON(!mutex_is_locked(&acpi_desc->spa_map_mutex));
	dev_dbg(acpi_desc->dev, "%s: SPA%d\n", __func__, spa->spa_index);
	iounmap(spa_map->iomem);
	release_mem_region(spa->spa_base, spa->spa_length);
	list_del(&spa_map->list);
	kfree(spa_map);
}

static struct nfit_spa_mapping *find_spa_mapping(struct acpi_nfit_desc *acpi_desc,
		struct acpi_nfit_spa *spa)
{
	struct nfit_spa_mapping *spa_map;

	WARN_ON(!mutex_is_locked(&acpi_desc->spa_map_mutex));
	list_for_each_entry(spa_map, &acpi_desc->spa_maps, list)
		if (spa_map->spa == spa)
			return spa_map;

	return NULL;
}

static void nfit_spa_unmap(struct acpi_nfit_desc *acpi_desc,
		struct acpi_nfit_spa *spa)
{
	struct nfit_spa_mapping *spa_map;

	mutex_lock(&acpi_desc->spa_map_mutex);
	spa_map = find_spa_mapping(acpi_desc, spa);

	if (spa_map)
		kref_put(&spa_map->kref, nfit_spa_mapping_release);
	mutex_unlock(&acpi_desc->spa_map_mutex);
}

static void *__nfit_spa_map(struct acpi_nfit_desc *acpi_desc,
		struct acpi_nfit_spa *spa)
{
	resource_size_t start = spa->spa_base;
	resource_size_t n = spa->spa_length;
	struct nfit_spa_mapping *spa_map;
	struct resource *res;

	WARN_ON(!mutex_is_locked(&acpi_desc->spa_map_mutex));

	spa_map = find_spa_mapping(acpi_desc, spa);
	if (spa_map) {
		kref_get(&spa_map->kref);
		return spa_map->iomem;
	}

	spa_map = kzalloc(sizeof(*spa_map), GFP_KERNEL);
	if (!spa_map)
		return NULL;

	INIT_LIST_HEAD(&spa_map->list);
	spa_map->spa = spa;
	kref_init(&spa_map->kref);
	spa_map->acpi_desc = acpi_desc;

	res = request_mem_region(start, n, dev_name(acpi_desc->dev));
	if (!res)
		goto err_mem;

	/* TODO: cacheability based on the spa type */
	spa_map->iomem = ioremap_nocache(start, n);
	if (!spa_map->iomem)
		goto err_map;

	list_add_tail(&spa_map->list, &acpi_desc->spa_maps);
	return spa_map->iomem;

 err_map:
	release_mem_region(start, n);
 err_mem:
	kfree(spa_map);
	return NULL;
}

/**
 * nfit_spa_map - interleave-aware managed-mappings of acpi_nfit_spa ranges
 * @nd_bus: NFIT-bus that provided the spa table entry
 * @nfit_spa: spa table to map
 *
 * In the case where block-data-window apertures and
 * dimm-control-regions are interleaved they will end up sharing a
 * single request_mem_region() + ioremap() for the address range.  In
 * the style of devm nfit_spa_map() mappings are automatically dropped
 * when all region devices referencing the same mapping are disabled /
 * unbound.
 */
static void *nfit_spa_map(struct acpi_nfit_desc *acpi_desc,
		struct acpi_nfit_spa *spa)
{
	struct nfit_spa_mapping *spa_map;

	mutex_lock(&acpi_desc->spa_map_mutex);
	spa_map = __nfit_spa_map(acpi_desc, spa);
	mutex_unlock(&acpi_desc->spa_map_mutex);

	return spa_map;
}

static int nfit_blk_init_interleave(struct nfit_blk_mmio *mmio,
		struct acpi_nfit_idt *idt, u16 interleave_ways)
{
	if (idt) {
		mmio->num_lines = idt->num_lines;
		mmio->line_size = idt->line_size;
		if (interleave_ways == 0)
			return -ENXIO;
		mmio->table_size = mmio->num_lines * interleave_ways
			* mmio->line_size;
	}

	return 0;
}

int nd_acpi_blk_region_enable(struct nd_bus *nd_bus, struct nd_blk_region *ndbr)
{
	struct nd_bus_descriptor *nd_desc = to_nd_desc(nd_bus);
	struct acpi_nfit_desc *acpi_desc = to_acpi_desc(nd_desc);
	struct nd_region *nd_region = &ndbr->nd_region;
	struct nd_mapping *nd_mapping;
	struct nfit_blk_mmio *mmio;
	struct nfit_blk *nfit_blk;
	struct nfit_mem *nfit_mem;
	struct nd_dimm *nd_dimm;
	int rc;

	nd_mapping = &nd_region->mapping[0];
	nd_dimm = nd_mapping->nd_dimm;
	nfit_mem = nd_dimm_provider_data(nd_dimm);
	if (!nfit_mem || !nfit_mem->dcr || !nfit_mem->bdw) {
		dev_dbg(&nd_region->dev, "%s: missing%s%s%s\n", __func__,
				nfit_mem ? "" : " nfit_mem",
				nfit_mem->dcr ? "" : " dcr",
				nfit_mem->bdw ? "" : " bdw");
		return -ENXIO;
	}

	nfit_blk = devm_kzalloc(&nd_region->dev, sizeof(*nfit_blk), GFP_KERNEL);
	if (!nfit_blk)
		return -ENOMEM;
	ndbr->blk_provider_data = nfit_blk;

	/* map block aperture memory */
	nfit_blk->bdw_offset = nfit_mem->bdw->bdw_offset;
	mmio = &nfit_blk->mmio[BDW];
	mmio->base = nfit_spa_map(acpi_desc, nfit_mem->spa_bdw);
	if (!mmio->base) {
		dev_dbg(&nd_region->dev, "%s: %s failed to map bdw\n", __func__,
				nd_dimm_name(nd_dimm));
		return -ENOMEM;
	}
	mmio->size = nfit_mem->bdw->bdw_size;
	mmio->base_offset = nfit_mem->memdev_bdw->region_spa_offset;
	mmio->idt = nfit_mem->idt_bdw;
	mmio->spa = nfit_mem->spa_bdw;
	rc = nfit_blk_init_interleave(mmio, nfit_mem->idt_bdw,
			nfit_mem->memdev_bdw->interleave_ways);
	if (rc) {
		dev_dbg(&nd_region->dev, "%s: %s failed to init bdw interleave\n",
				__func__, nd_dimm_name(nd_dimm));
		return rc;
	}

	/* map block control memory */
	nfit_blk->cmd_offset = nfit_mem->dcr->cmd_offset;
	nfit_blk->stat_offset = nfit_mem->dcr->status_offset;
	mmio = &nfit_blk->mmio[DCR];
	mmio->base = nfit_spa_map(acpi_desc, nfit_mem->spa_dcr);
	if (!mmio->base) {
		dev_dbg(&nd_region->dev, "%s: %s failed to map dcr\n", __func__,
				nd_dimm_name(nd_dimm));
		return -ENOMEM;
	}
	mmio->size = nfit_mem->dcr->bcw_size;
	mmio->base_offset = nfit_mem->memdev_dcr->region_spa_offset;
	mmio->idt = nfit_mem->idt_dcr;
	mmio->spa = nfit_mem->spa_dcr;
	rc = nfit_blk_init_interleave(mmio, nfit_mem->idt_dcr,
			nfit_mem->memdev_dcr->interleave_ways);
	if (rc) {
		dev_dbg(&nd_region->dev, "%s: %s failed to init dcr interleave\n",
				__func__, nd_dimm_name(nd_dimm));
		return rc;
	}

	if (mmio->line_size == 0)
		return 0;

	if ((u32) nfit_blk->cmd_offset % mmio->line_size + 8 > mmio->line_size) {
		dev_dbg(&nd_region->dev,
				"cmd_offset crosses interleave boundary\n");
		return -ENXIO;
	} else if ((u32) nfit_blk->stat_offset % mmio->line_size + 8 > mmio->line_size) {
		dev_dbg(&nd_region->dev,
				"stat_offset crosses interleave boundary\n");
		return -ENXIO;
	}

	return 0;
}

static void nd_acpi_blk_region_disable(struct nd_bus *nd_bus,
		struct nd_blk_region *ndbr)
{
	struct nd_bus_descriptor *nd_desc = to_nd_desc(nd_bus);
	struct acpi_nfit_desc *acpi_desc = to_acpi_desc(nd_desc);
	struct nfit_blk *nfit_blk = ndbr->blk_provider_data;
	int i;

	if (!nfit_blk)
		return; /* never enabled */

	/* auto-free BLK spa mappings */
	for (i = 0; i < 2; i++) {
		struct nfit_blk_mmio *mmio = &nfit_blk->mmio[i];

		if (mmio->base)
			nfit_spa_unmap(acpi_desc, mmio->spa);
	}
	ndbr->blk_provider_data = NULL;
	/* devm will free nfit_blk */
}

static int nd_acpi_register_region(struct acpi_nfit_desc *acpi_desc,
		struct nfit_spa *nfit_spa)
{
	static struct nd_mapping nd_mappings[ND_MAX_MAPPINGS];
	struct acpi_nfit_spa *spa = nfit_spa->spa;
	struct nd_blk_region_desc ndbr_desc;
	struct nd_region_desc *ndr_desc;
	struct nfit_memdev *nfit_memdev;
	int spa_type, count = 0, rc;
	struct resource res;
	u16 spa_index;

	spa_type = nfit_spa_type(spa);
	spa_index = spa->spa_index;
	if (spa_index == 0) {
		dev_dbg(acpi_desc->dev, "%s: detected invalid spa index\n",
				__func__);
		return 0;
	}

	memset(&res, 0, sizeof(res));
	memset(&nd_mappings, 0, sizeof(nd_mappings));
	memset(&ndbr_desc, 0, sizeof(ndr_desc));
	res.start = spa->spa_base;
	res.end = res.start + spa->spa_length - 1;
	ndr_desc = &ndbr_desc.ndr_desc;
	ndr_desc->res = &res;
	ndr_desc->provider_data = nfit_spa;
	ndr_desc->attr_groups = nd_acpi_region_attribute_groups;
	list_for_each_entry(nfit_memdev, &acpi_desc->memdevs, list) {
		struct acpi_nfit_memdev *memdev = nfit_memdev->memdev;
		struct nd_mapping *nd_mapping;
		struct nd_dimm *nd_dimm;

		if (memdev->spa_index != spa_index)
			continue;
		if (count >= ND_MAX_MAPPINGS) {
			dev_err(acpi_desc->dev, "spa%d exceeds max mappings %d\n",
					spa_index, ND_MAX_MAPPINGS);
			return -ENXIO;
		}
		nd_dimm = nd_acpi_dimm_by_handle(acpi_desc, memdev->nfit_handle);
		if (!nd_dimm) {
			dev_err(acpi_desc->dev, "spa%d dimm: %#x not found\n",
					spa_index, memdev->nfit_handle);
			return -ENODEV;
		}
		nd_mapping = &nd_mappings[count++];
		nd_mapping->nd_dimm = nd_dimm;
		if (spa_type == NFIT_SPA_PM || spa_type == NFIT_SPA_VOLATILE) {
			nd_mapping->start = memdev->region_dpa;
			nd_mapping->size = memdev->region_len;
		} else if (spa_type == NFIT_SPA_DCR) {
			struct nfit_mem *nfit_mem;
			int blk_valid = 1;

			nfit_mem = nd_dimm_provider_data(nd_dimm);
			if (!nfit_mem || !nfit_mem->bdw) {
				dev_dbg(acpi_desc->dev, "%s: spa%d missing bdw\n",
						nd_dimm_name(nd_dimm), spa_index);
				blk_valid = 0;
			} else {
				nd_mapping->size = nfit_mem->bdw->blk_capacity;
				nd_mapping->start = nfit_mem->bdw->blk_offset;
				ndr_desc->num_lanes = nfit_mem->bdw->num_bdw;
			}

			ndr_desc->nd_mapping = nd_mapping;
			ndr_desc->num_mappings = blk_valid;
			ndbr_desc.enable = nd_acpi_blk_region_enable;
			ndbr_desc.disable = nd_acpi_blk_region_disable;
			ndbr_desc.do_io = acpi_desc->blk_do_io;
			if (!nd_blk_region_create(acpi_desc->nd_bus, ndr_desc))
				return -ENOMEM;
		}
	}

	ndr_desc->nd_mapping = nd_mappings;
	ndr_desc->num_mappings = count;
	rc = nd_acpi_init_interleave_set(acpi_desc, ndr_desc, spa);
	if (rc)
		return rc;
	if (spa_type == NFIT_SPA_PM) {
		if (!nd_pmem_region_create(acpi_desc->nd_bus, ndr_desc))
			return -ENOMEM;
	} else if (spa_type == NFIT_SPA_VOLATILE) {
		if (!nd_volatile_region_create(acpi_desc->nd_bus, ndr_desc))
			return -ENOMEM;
	}
	return 0;
}

static int nd_acpi_register_regions(struct acpi_nfit_desc *acpi_desc)
{
	struct nfit_spa *nfit_spa;

	list_for_each_entry(nfit_spa, &acpi_desc->spas, list) {
		int rc = nd_acpi_register_region(acpi_desc, nfit_spa);

		if (rc)
			return rc;
	}
	return 0;
}

int nd_acpi_nfit_init(struct acpi_nfit_desc *acpi_desc, acpi_size sz)
{
	struct device *dev = acpi_desc->dev;
	const void *end;
	u8 *data, sum;
	acpi_size i;
	int rc;

	INIT_LIST_HEAD(&acpi_desc->spa_maps);
	INIT_LIST_HEAD(&acpi_desc->spas);
	INIT_LIST_HEAD(&acpi_desc->dcrs);
	INIT_LIST_HEAD(&acpi_desc->bdws);
	INIT_LIST_HEAD(&acpi_desc->idts);
	INIT_LIST_HEAD(&acpi_desc->memdevs);
	INIT_LIST_HEAD(&acpi_desc->dimms);
	mutex_init(&acpi_desc->spa_map_mutex);

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

	nd_acpi_init_dsms(acpi_desc);

	rc = nd_acpi_register_dimms(acpi_desc);
	if (rc)
		return rc;

	return nd_acpi_register_regions(acpi_desc);
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
	acpi_desc->blk_do_io = nd_acpi_blk_region_do_io;
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
	char *uuids[] = {
		/* bus interface */
		"2f10e7a4-9e91-11e4-89d3-123b93f75cba",
		/* per-dimm interface */
		"4309ac30-0d11-11e4-9191-0800200c9a66",
	};
	int i;

	BUILD_BUG_ON(sizeof(struct acpi_nfit) != 40);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_spa) != 56);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_memdev) != 48);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_idt) != 16);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_smbios) != 8);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_dcr) != 80);
	BUILD_BUG_ON(sizeof(struct acpi_nfit_bdw) != 40);

	for (i = 0; i < ARRAY_SIZE(uuids); i++)
		if (acpi_str_to_uuid(uuids[i], nd_acpi_uuids[i]) != AE_OK) {
			WARN_ON_ONCE(1);
			return -ENXIO;
		}

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
