/*
 * NVDIMM Firmware Interface Table - NFIT
 *
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
#ifndef __NFIT_H__
#define __NFIT_H__
#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/acpi.h>
#include "libnd.h"

static const uuid_le nfit_spa_uuid_volatile __maybe_unused = UUID_LE(0x7305944f,
		0xfdda, 0x44e3, 0xb1, 0x6c, 0x3f, 0x22, 0xd2, 0x52, 0xe5, 0xd0);

static const uuid_le nfit_spa_uuid_pm __maybe_unused = UUID_LE(0x66f0d379,
		0xb4f3, 0x4074, 0xac, 0x43, 0x0d, 0x33, 0x18, 0xb7, 0x8c, 0xdb);

static const uuid_le nfit_spa_uuid_dcr __maybe_unused = UUID_LE(0x92f701f6,
		0x13b4, 0x405d, 0x91, 0x0b, 0x29, 0x93, 0x67, 0xe8, 0x23, 0x4c);

static const uuid_le nfit_spa_uuid_bdw __maybe_unused = UUID_LE(0x91af0530,
		0x5d86, 0x470e, 0xa6, 0xb0, 0x0a, 0x2d, 0xb9, 0x40, 0x82, 0x49);

static const uuid_le nfit_spa_uuid_vdisk __maybe_unused = UUID_LE(0x77ab535a,
		0x45fc, 0x624b, 0x55, 0x60, 0xf7, 0xb2, 0x81, 0xd1, 0xf9, 0x6e);

static const uuid_le nfit_spa_uuid_vcd __maybe_unused = UUID_LE(0x3d5abd30,
		0x4175, 0x87ce, 0x6d, 0x64, 0xd2, 0xad, 0xe5, 0x23, 0xc4, 0xbb);

static const uuid_le nfit_spa_uuid_pdisk __maybe_unused = UUID_LE(0x5cea02c9,
		0x4d07, 0x69d3, 0x26, 0x9f, 0x44, 0x96, 0xfb, 0xe0, 0x96, 0xf9);

static const uuid_le nfit_spa_uuid_pcd __maybe_unused = UUID_LE(0x08018188,
		0x42cd, 0xbb48, 0x10, 0x0f, 0x53, 0x87, 0xd5, 0x3d, 0xed, 0x3d);

enum {
	NFIT_TABLE_SPA = 0,
	NFIT_TABLE_MEM = 1,
	NFIT_TABLE_IDT = 2,
	NFIT_TABLE_SMBIOS = 3,
	NFIT_TABLE_DCR = 4,
	NFIT_TABLE_BDW = 5,
	NFIT_TABLE_FLUSH = 6,
	NFIT_SPA_VOLATILE = 0,
	NFIT_SPA_PM = 1,
	NFIT_SPA_DCR = 2,
	NFIT_SPA_BDW = 3,
	NFIT_SPA_VDISK = 4,
	NFIT_SPA_VCD = 5,
	NFIT_SPA_PDISK = 6,
	NFIT_SPA_PCD = 7,
	NFIT_SPAF_DCR_HOT_ADD = 1 << 0,
	NFIT_SPAF_PDVALID = 1 << 1,
	NFIT_MEMF_SAVE_FAIL = 1 << 0,
	NFIT_MEMF_RESTORE_FAIL = 1 << 1,
	NFIT_MEMF_FLUSH_FAIL = 1 << 2,
	NFIT_MEMF_UNARMED = 1 << 3,
	NFIT_MEMF_NOTIFY_SMART = 1 << 4,
	NFIT_MEMF_SMART_READY = 1 << 5,
	NFIT_DCRF_BUFFERED = 1 << 0,
};

/**
 * struct acpi_nfit - Nvdimm Firmware Interface Table
 * @signature: "NFIT"
 * @length: sum of size of this table plus all appended subtables
 */
struct acpi_nfit {
	u8 signature[4];
	u32 length;
	u8 revision;
	u8 checksum;
	u8 oemid[6];
	u64 oem_tbl_id;
	u32 oem_revision;
	u32 creator_id;
	u32 creator_revision;
	u32 reserved;
};

/**
 * struct acpi_nfit_spa - System Physical Address Range Descriptor Table
 */
struct acpi_nfit_spa {
	u16 type;
	u16 length;
	u16 spa_index;
	u16 flags;
	u32 reserved;
	u32 proximity_domain;
	u8 type_uuid[16];
	u64 spa_base;
	u64 spa_length;
	u64 mem_attr;
};

/**
 * struct acpi_nfit_mem - Memory Device to SPA Mapping Table
 */
struct acpi_nfit_memdev {
	u16 type;
	u16 length;
	u32 nfit_handle;
	u16 phys_id;
	u16 region_id;
	u16 spa_index;
	u16 dcr_index;
	u64 region_len;
	u64 region_spa_offset;
	u64 region_dpa;
	u16 idt_index;
	u16 interleave_ways;
	u16 flags;
	u16 reserved;
};

#define NFIT_DIMM_HANDLE(node, socket, imc, chan, dimm) \
	(((node & 0xfff) << 16) | ((socket & 0xf) << 12) \
	 | ((imc & 0xf) << 8) | ((chan & 0xf) << 4) | (dimm & 0xf))
#define NFIT_DIMM_NODE(handle) ((handle) >> 16 & 0xfff)
#define NFIT_DIMM_SOCKET(handle) ((handle) >> 12 & 0xf)
#define NFIT_DIMM_CHAN(handle) ((handle) >> 8 & 0xf)
#define NFIT_DIMM_IMC(handle) ((handle) >> 4 & 0xf)
#define NFIT_DIMM_DIMM(handle) ((handle) & 0xf)

/**
 * struct acpi_nfit_idt - Interleave description Table
 */
struct acpi_nfit_idt {
	u16 type;
	u16 length;
	u16 idt_index;
	u16 reserved;
	u32 num_lines;
	u32 line_size;
	u32 line_offset[0];
};

/**
 * struct acpi_nfit_smbios - SMBIOS Management Information Table
 */
struct acpi_nfit_smbios {
	u16 type;
	u16 length;
	u32 reserved;
	u8 data[0];
};

/**
 * struct acpi_nfit_dcr - NVDIMM Control Region Table
 * @fic: Format Interface Code
 * @cmd_offset: command registers relative to block control window
 * @status_offset: status registers relative to block control window
 */
struct acpi_nfit_dcr {
	u16 type;
	u16 length;
	u16 dcr_index;
	u16 vendor_id;
	u16 device_id;
	u16 revision_id;
	u16 sub_vendor_id;
	u16 sub_device_id;
	u16 sub_revision_id;
	u8 reserved[6];
	u32 serial_number;
	u16 fic;
	u16 num_bcw;
	u64 bcw_size;
	u64 cmd_offset;
	u64 cmd_size;
	u64 status_offset;
	u64 status_size;
	u16 flags;
	u8 reserved2[6];
};

/**
 * struct acpi_nfit_bdw - NVDIMM Block Data Window Region Table
 */
struct acpi_nfit_bdw {
	u16 type;
	u16 length;
	u16 dcr_index;
	u16 num_bdw;
	u64 bdw_offset;
	u64 bdw_size;
	u64 blk_capacity;
	u64 blk_offset;
};

/**
 * struct acpi_nfit_flush - Flush Hint Address Structure
 */
struct acpi_nfit_flush {
	u16 type;
	u16 length;
	u32 nfit_handle;
	u16 num_hints;
	u8 reserved[6];
	u64 hint_addr[0];
};

struct nfit_spa {
	struct acpi_nfit_spa *spa;
	struct list_head list;
};

struct nfit_dcr {
	struct acpi_nfit_dcr *dcr;
	struct list_head list;
};

struct nfit_bdw {
	struct acpi_nfit_bdw *bdw;
	struct list_head list;
};

struct nfit_memdev {
	struct acpi_nfit_memdev *memdev;
	struct list_head list;
};

/* assembled tables for a given dimm/memory-device */
struct nfit_mem {
	struct nd_dimm *nd_dimm;
	struct acpi_nfit_memdev *memdev_dcr;
	struct acpi_nfit_memdev *memdev_pmem;
	struct acpi_nfit_dcr *dcr;
	struct acpi_nfit_bdw *bdw;
	struct acpi_nfit_spa *spa_dcr;
	struct acpi_nfit_spa *spa_bdw;
	struct list_head list;
};

struct acpi_nfit_desc {
	struct nd_bus_descriptor nd_desc;
	struct acpi_nfit *nfit;
	struct list_head memdevs;
	struct list_head dimms;
	struct list_head spas;
	struct list_head dcrs;
	struct list_head bdws;
	struct nd_bus *nd_bus;
	struct device *dev;
};

static inline struct acpi_nfit_memdev *__to_nfit_memdev(struct nfit_mem *nfit_mem)
{
	if (nfit_mem->memdev_dcr)
		return nfit_mem->memdev_dcr;
	return nfit_mem->memdev_pmem;
}

static inline struct acpi_nfit_desc *to_acpi_desc(struct nd_bus_descriptor *nd_desc)
{
	return container_of(nd_desc, struct acpi_nfit_desc, nd_desc);
}

int nd_acpi_nfit_init(struct acpi_nfit_desc *nfit, acpi_size sz);
#endif /* __NFIT_H__ */
