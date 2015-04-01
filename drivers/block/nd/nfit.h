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
 * struct nfit - Nvdimm Firmware Interface Table
 * @signature: "NFIT"
 * @length: sum of size of this table plus all appended subtables
 */
struct nfit {
	__u8 signature[4];
	__le32 length;
	__u8 revision;
	__u8 checksum;
	__u8 oemid[6];
	__le64 oem_tbl_id;
	__le32 oem_revision;
	__le32 creator_id;
	__le32 creator_revision;
	__le32 reserved;
} __packed;

/**
 * struct nfit_spa - System Physical Address Range Descriptor Table
 */
struct nfit_spa {
	__le16 type;
	__le16 length;
	__le16 spa_index;
	__le16 flags;
	__le32 reserved;
	__le32 proximity_domain;
	__u8 type_uuid[16];
	__le64 spa_base;
	__le64 spa_length;
	__le64 mem_attr;
} __packed;

/**
 * struct nfit_mem - Memory Device to SPA Mapping Table
 */
struct nfit_mem {
	__le16 type;
	__le16 length;
	__le32 nfit_handle;
	__le16 phys_id;
	__le16 region_id;
	__le16 spa_index;
	__le16 dcr_index;
	__le64 region_len;
	__le64 region_spa_offset;
	__le64 region_dpa;
	__le16 idt_index;
	__le16 interleave_ways;
	__le16 flags;
	__le16 reserved;
} __packed;

/**
 * struct nfit_idt - Interleave description Table
 */
struct nfit_idt {
	__le16 type;
	__le16 length;
	__le16 idt_index;
	__le16 reserved;
	__le32 num_lines;
	__le32 line_size;
	__le32 line_offset[0];
} __packed;

/**
 * struct nfit_smbios - SMBIOS Management Information Table
 */
struct nfit_smbios {
	__le16 type;
	__le16 length;
	__le32 reserved;
	__u8 data[0];
} __packed;

/**
 * struct nfit_dcr - NVDIMM Control Region Table
 * @fic: Format Interface Code
 * @cmd_offset: command registers relative to block control window
 * @status_offset: status registers relative to block control window
 */
struct nfit_dcr {
	__le16 type;
	__le16 length;
	__le16 dcr_index;
	__le16 vendor_id;
	__le16 device_id;
	__le16 revision_id;
	__le16 sub_vendor_id;
	__le16 sub_device_id;
	__le16 sub_revision_id;
	__u8 reserved[6];
	__le32 serial_number;
	__le16 fic;
	__le16 num_bcw;
	__le64 bcw_size;
	__le64 cmd_offset;
	__le64 cmd_size;
	__le64 status_offset;
	__le64 status_size;
	__le16 flags;
	__u8 reserved2[6];
} __packed;

/**
 * struct nfit_bdw - NVDIMM Block Data Window Region Table
 */
struct nfit_bdw {
	__le16 type;
	__le16 length;
	__le16 dcr_index;
	__le16 num_bdw;
	__le64 bdw_offset;
	__le64 bdw_size;
	__le64 blk_capacity;
	__le64 blk_offset;
} __packed;

/**
 * struct nfit_flush - Flush Hint Address Structure
 */
struct nfit_flush {
	__le16 type;
	__le16 length;
	__le32 nfit_handle;
	__le16 num_hints;
	__u8 reserved[6];
	__le64 hint_addr[0];
};

struct nd_dimm;
struct nfit_bus_descriptor;
typedef int (*nfit_ctl_fn)(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len);

typedef int (*nfit_add_dimm_fn)(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm);

struct nfit_bus_descriptor {
	unsigned long dsm_mask;
	void __iomem *nfit_base;
	size_t nfit_size;
	char *provider_name;
	nfit_ctl_fn nfit_ctl;
	nfit_add_dimm_fn add_dimm;
};

struct nd_bus;
struct nd_bus *nfit_bus_register(struct device *parent,
		struct nfit_bus_descriptor *nfit_desc);
void nfit_bus_unregister(struct nd_bus *nd_bus);
#endif /* __NFIT_H__ */
