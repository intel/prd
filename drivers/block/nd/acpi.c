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
#include <linux/list.h>
#include <linux/acpi.h>
#include <linux/mutex.h>
#include <linux/ndctl.h>
#include <linux/module.h>
#include "nfit.h"
#include "nd.h"

enum {
	NFIT_ACPI_NOTIFY_TABLE = 0x80,
};

struct acpi_nfit {
	struct nfit_bus_descriptor nfit_desc;
	struct acpi_device *dev;
	struct nd_bus *nd_bus;
};

static struct acpi_nfit *to_acpi_nfit(struct nfit_bus_descriptor *nfit_desc)
{
	return container_of(nfit_desc, struct acpi_nfit, nfit_desc);
}

#define NFIT_ACPI_MAX_ELEM 4
struct nfit_cmd_desc {
	int in_num;
	int out_num;
	u32 in_sizes[NFIT_ACPI_MAX_ELEM];
	int out_sizes[NFIT_ACPI_MAX_ELEM];
};

static const struct nfit_cmd_desc nfit_dimm_descs[] = {
	[NFIT_CMD_IMPLEMENTED] = { },
	[NFIT_CMD_SMART] = {
		.out_num = 2,
		.out_sizes = { 4, 8, },
	},
	[NFIT_CMD_SMART_THRESHOLD] = {
		.out_num = 2,
		.out_sizes = { 4, 8, },
	},
	[NFIT_CMD_DIMM_FLAGS] = {
		.out_num = 2,
		.out_sizes = { 4, 4 },
	},
	[NFIT_CMD_GET_CONFIG_SIZE] = {
		.out_num = 3,
		.out_sizes = { 4, 4, 4, },
	},
	[NFIT_CMD_GET_CONFIG_DATA] = {
		.in_num = 2,
		.in_sizes = { 4, 4, },
		.out_num = 2,
		.out_sizes = { 4, UINT_MAX, },
	},
	[NFIT_CMD_SET_CONFIG_DATA] = {
		.in_num = 3,
		.in_sizes = { 4, 4, UINT_MAX, },
		.out_num = 1,
		.out_sizes = { 4, },
	},
	[NFIT_CMD_VENDOR] = {
		.in_num = 3,
		.in_sizes = { 4, 4, UINT_MAX, },
		.out_num = 3,
		.out_sizes = { 4, 4, UINT_MAX, },
	},
};

static const struct nfit_cmd_desc nfit_acpi_descs[] = {
	[NFIT_CMD_IMPLEMENTED] = { },
	[NFIT_CMD_ARS_CAP] = {
		.in_num = 2,
		.in_sizes = { 8, 8, },
		.out_num = 2,
		.out_sizes = { 4, 4, },
	},
	[NFIT_CMD_ARS_START] = {
		.in_num = 4,
		.in_sizes = { 8, 8, 2, 6, },
		.out_num = 1,
		.out_sizes = { 4, },
	},
	[NFIT_CMD_ARS_QUERY] = {
		.out_num = 2,
		.out_sizes = { 4, UINT_MAX, },
	},
};

static u32 to_cmd_in_size(struct nd_dimm *nd_dimm, int cmd,
		const struct nfit_cmd_desc *desc, int idx, void *buf)
{
	if (idx >= desc->in_num)
		return UINT_MAX;

	if (desc->in_sizes[idx] < UINT_MAX)
		return desc->in_sizes[idx];

	if (nd_dimm && cmd == NFIT_CMD_SET_CONFIG_DATA && idx == 2) {
		struct nfit_cmd_set_config_hdr *hdr = buf;

		return hdr->in_length;
	} else if (nd_dimm && cmd == NFIT_CMD_VENDOR && idx == 2) {
		struct nfit_cmd_vendor_hdr *hdr = buf;

		return hdr->in_length;
	}

	return UINT_MAX;
}

static u32 to_cmd_out_size(struct nd_dimm *nd_dimm, int cmd,
		const struct nfit_cmd_desc *desc, int idx,
		void *buf, u32 out_length, u32 offset)
{
	if (idx >= desc->out_num)
		return UINT_MAX;

	if (desc->out_sizes[idx] < UINT_MAX)
		return desc->out_sizes[idx];

	if (offset >= out_length)
		return UINT_MAX;

	if (nd_dimm && cmd == NFIT_CMD_GET_CONFIG_DATA && idx == 1)
		return out_length - offset;
	else if (nd_dimm && cmd == NFIT_CMD_VENDOR && idx == 2)
		return out_length - offset;
	else if (!nd_dimm && cmd == NFIT_CMD_ARS_QUERY && idx == 1)
		return out_length - offset;

	return UINT_MAX;
}

static u8 nd_acpi_uuids[2][16]; /* initialized at nd_acpi_init */

static u8 *nd_acpi_bus_uuid(void)
{
	return nd_acpi_uuids[0];
}

static u8 *nd_acpi_dimm_uuid(void)
{
	return nd_acpi_uuids[1];
}

static int nd_acpi_ctl(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len)
{
	struct acpi_nfit *nfit = to_acpi_nfit(nfit_desc);
	union acpi_object in_obj, in_buf, *out_obj;
	const struct nfit_cmd_desc *desc = NULL;
	struct device *dev = &nfit->dev->dev;
	const char *cmd_name, *dimm_name;
	unsigned long dsm_mask;
	acpi_handle handle;
	u32 offset;
	int rc, i;
	u8 *uuid;

	if (nd_dimm) {
		struct acpi_device *adev = nd_dimm_get_pdata(nd_dimm);

		if (cmd < ARRAY_SIZE(nfit_dimm_descs))
			desc = &nfit_dimm_descs[cmd];
		cmd_name = nfit_dimm_cmd_name(cmd);
		dsm_mask = nd_dimm_get_dsm_mask(nd_dimm);
		handle = adev->handle;
		uuid = nd_acpi_dimm_uuid();
		dimm_name = dev_name(&adev->dev);
	} else {
		if (cmd < ARRAY_SIZE(nfit_acpi_descs))
			desc = &nfit_acpi_descs[cmd];
		cmd_name = nfit_bus_cmd_name(cmd);
		dsm_mask = nfit_desc->dsm_mask;
		handle = nfit->dev->handle;
		uuid = nd_acpi_bus_uuid();
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

	/* double check that the nfit_acpi_cmd_descs table is self consistent */
	if (desc->in_num > NFIT_ACPI_MAX_ELEM) {
		WARN_ON_ONCE(1);
		return -ENXIO;
	}

	for (i = 0; i < desc->in_num; i++) {
		u32 in_size;

		in_size = to_cmd_in_size(nd_dimm, cmd, desc, i, buf);
		if (in_size == UINT_MAX) {
			dev_err(dev, "%s:%s unknown input size cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			return -ENXIO;
		}
		in_buf.buffer.length += in_size;
		if (in_buf.buffer.length > buf_len) {
			dev_err(dev, "%s:%s input underrun cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			return -ENXIO;
		}
	}

	dev_dbg(dev, "%s:%s cmd: %s input length: %d\n", __func__, dimm_name,
			cmd_name, in_buf.buffer.length);
	if (IS_ENABLED(CONFIG_NFIT_ACPI_DEBUG))
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
	if (IS_ENABLED(CONFIG_NFIT_ACPI_DEBUG))
		print_hex_dump_debug(cmd_name, DUMP_PREFIX_OFFSET, 4,
				4, out_obj->buffer.pointer, min_t(u32, 128,
					out_obj->buffer.length), true);

	for (i = 0, offset = 0; i < desc->out_num; i++) {
		u32 out_size = to_cmd_out_size(nd_dimm, cmd, desc, i, buf,
				out_obj->buffer.length, offset);

		if (out_size == UINT_MAX) {
			dev_dbg(dev, "%s:%s unknown output size cmd: %s field: %d\n",
					__func__, dimm_name, cmd_name, i);
			break;
		}

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

static int nd_acpi_add_dimm(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm)
{
	struct acpi_nfit *nfit = to_acpi_nfit(nfit_desc);
	u32 nfit_handle = to_nfit_handle(nd_dimm);
	struct device *dev = &nfit->dev->dev;
	struct acpi_device *acpi_dimm;
	unsigned long dsm_mask = 0;
	u8 *uuid = nd_acpi_dimm_uuid();
	unsigned long long sta;
	int i, rc = -ENODEV;
	acpi_status status;

	acpi_dimm = acpi_find_child_device(nfit->dev, nfit_handle, false);
	if (!acpi_dimm) {
		dev_err(dev, "no ACPI.NFIT device with _ADR %#x, disabling...\n",
				nfit_handle);
		return -ENODEV;
	}

	status = acpi_evaluate_integer(acpi_dimm->handle, "_STA", NULL, &sta);
	if (status == AE_NOT_FOUND)
		dev_err(dev, "%s missing _STA, disabling...\n",
				dev_name(&acpi_dimm->dev));
	else if (ACPI_FAILURE(status))
		dev_err(dev, "%s failed to retrieve_STA, disabling...\n",
				dev_name(&acpi_dimm->dev));
	else if ((sta & ACPI_STA_DEVICE_ENABLED) == 0)
		dev_info(dev, "%s disabled by firmware\n",
				dev_name(&acpi_dimm->dev));
	else
		rc = 0;

	for (i = NFIT_CMD_SMART; i <= NFIT_CMD_VENDOR; i++)
		if (acpi_check_dsm(acpi_dimm->handle, uuid, 1, 1ULL << i))
			set_bit(i, &dsm_mask);
	nd_dimm_set_dsm_mask(nd_dimm, dsm_mask);
	nd_dimm_set_pdata(nd_dimm, acpi_dimm);
	return rc;
}

static int nd_acpi_add(struct acpi_device *dev)
{
	struct nfit_bus_descriptor *nfit_desc;
	struct acpi_table_header *tbl;
	u8 *uuid = nd_acpi_bus_uuid();
	acpi_status status = AE_OK;
	struct acpi_nfit *nfit;
	acpi_size sz;
	int i;

	status = acpi_get_table_with_size("NFIT", 0, &tbl, &sz);
	if (ACPI_FAILURE(status)) {
		dev_err(&dev->dev, "failed to find NFIT\n");
		return -ENXIO;
	}

	nfit = devm_kzalloc(&dev->dev, sizeof(*nfit), GFP_KERNEL);
	if (!nfit)
		return -ENOMEM;
	nfit->dev = dev;
	nfit_desc = &nfit->nfit_desc;
	nfit_desc->nfit_base = (void __iomem *) tbl;
	nfit_desc->nfit_size = sz;
	nfit_desc->provider_name = "ACPI.NFIT";
	nfit_desc->nfit_ctl = nd_acpi_ctl;
	nfit_desc->add_dimm = nd_acpi_add_dimm;

	for (i = NFIT_CMD_ARS_CAP; i <= NFIT_CMD_ARS_QUERY; i++)
		if (acpi_check_dsm(dev->handle, uuid, 1, 1ULL << i))
			set_bit(i, &nfit_desc->dsm_mask);

	nfit->nd_bus = nfit_bus_register(&dev->dev, nfit_desc);
	if (!nfit->nd_bus)
		return -ENXIO;

	dev_set_drvdata(&dev->dev, nfit);
	return 0;
}

static int nd_acpi_remove(struct acpi_device *dev)
{
	struct acpi_nfit *nfit = dev_get_drvdata(&dev->dev);

	nfit_bus_unregister(nfit->nd_bus);
	return 0;
}

static void nd_acpi_notify(struct acpi_device *dev, u32 event)
{
	/* TODO: handle ACPI_NOTIFY_BUS_CHECK notification */
	dev_dbg(&dev->dev, "%s: event: %d\n", __func__, event);
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
