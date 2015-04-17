/*
 * libnd - Non-volatile-memory Devices Subsystem
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
#ifndef __LIBND_H__
#define __LIBND_H__
#include <linux/sizes.h>

enum {
	/* when a dimm supports both PMEM and BLK access a label is required */
	NDD_ALIASING = 1 << 0,

	/* need to set a limit somewhere, but yes, this is likely overkill */
	ND_IOCTL_MAX_BUFLEN = SZ_4M,
	ND_CMD_MAX_ELEM = 4,
	ND_CMD_MAX_ENVELOPE = 16,
	ND_CMD_ARS_QUERY_MAX = SZ_4K,
	ND_MAX_MAPPINGS = 32,

	/* mark newly adjusted resources as requiring a label update */
	DPA_RESOURCE_ADJUSTED = 1 << 0,
};

extern struct attribute_group nd_bus_attribute_group;
extern struct attribute_group nd_dimm_attribute_group;
extern struct attribute_group nd_device_attribute_group;
extern struct attribute_group nd_region_attribute_group;
extern struct attribute_group nd_mapping_attribute_group;

struct nd_dimm;
struct nd_bus_descriptor;
typedef int (*ndctl_fn)(struct nd_bus_descriptor *nd_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len);

struct nd_namespace_label;
struct nd_mapping {
	struct nd_dimm *nd_dimm;
	struct nd_namespace_label **labels;
	u64 start;
	u64 size;
};

struct nd_bus_descriptor {
	const struct attribute_group **attr_groups;
	unsigned long dsm_mask;
	char *provider_name;
	ndctl_fn ndctl;
};

struct nd_cmd_desc {
	int in_num;
	int out_num;
	u32 in_sizes[ND_CMD_MAX_ELEM];
	int out_sizes[ND_CMD_MAX_ELEM];
};

struct nd_interleave_set {
	u64 cookie;
};

struct nd_region_desc {
	struct resource *res;
	struct nd_mapping *nd_mapping;
	u16 num_mappings;
	const struct attribute_group **attr_groups;
	struct nd_interleave_set *nd_set;
	void *provider_data;
	int num_lanes;
};

struct nd_bus;
struct nd_bus *__nd_bus_register(struct device *parent,
		struct nd_bus_descriptor *nfit_desc, struct module *module);
#define nd_bus_register(parent, desc) \
	__nd_bus_register(parent, desc, THIS_MODULE)
void nd_bus_unregister(struct nd_bus *nd_bus);
struct nd_bus *to_nd_bus(struct device *dev);
struct nd_dimm *to_nd_dimm(struct device *dev);
struct nd_region *to_nd_region(struct device *dev);
struct nd_bus_descriptor *to_nd_desc(struct nd_bus *nd_bus);
const char *nd_dimm_name(struct nd_dimm *nd_dimm);
void *nd_dimm_provider_data(struct nd_dimm *nd_dimm);
void *nd_region_provider_data(struct nd_region *nd_region);
struct nd_dimm *nd_dimm_create(struct nd_bus *nd_bus, void *provider_data,
		const struct attribute_group **groups, unsigned long flags,
		unsigned long *dsm_mask);
const struct nd_cmd_desc const *nd_cmd_dimm_desc(int cmd);
const struct nd_cmd_desc const *nd_cmd_bus_desc(int cmd);
u32 nd_cmd_in_size(struct nd_dimm *nd_dimm, int cmd,
		const struct nd_cmd_desc *desc, int idx, void *buf);
u32 nd_cmd_out_size(struct nd_dimm *nd_dimm, int cmd,
		const struct nd_cmd_desc *desc, int idx, const u32 *in_field,
		const u32 *out_field);
int nd_bus_validate_dimm_count(struct nd_bus *nd_bus, int dimm_count);
struct nd_region *nd_pmem_region_create(struct nd_bus *nd_bus,
		struct nd_region_desc *ndr_desc);
struct nd_region *nd_blk_region_create(struct nd_bus *nd_bus,
		struct nd_region_desc *ndr_desc);
struct nd_region *nd_volatile_region_create(struct nd_bus *nd_bus,
		struct nd_region_desc *ndr_desc);
u64 nd_fletcher64(void __iomem *addr, size_t len);
#endif /* __LIBND_H__ */
