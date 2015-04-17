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
};

extern struct attribute_group nd_bus_attribute_group;
extern struct attribute_group nd_dimm_attribute_group;
extern struct attribute_group nd_device_attribute_group;

struct nd_dimm;
struct nd_bus_descriptor;
typedef int (*ndctl_fn)(struct nd_bus_descriptor *nd_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len);

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

struct nd_bus;
struct nd_bus *nd_bus_register(struct device *parent,
		struct nd_bus_descriptor *nfit_desc);
void nd_bus_unregister(struct nd_bus *nd_bus);
struct nd_bus *to_nd_bus(struct device *dev);
struct nd_dimm *to_nd_dimm(struct device *dev);
struct nd_bus_descriptor *to_nd_desc(struct nd_bus *nd_bus);
const char *nd_dimm_name(struct nd_dimm *nd_dimm);
void *nd_dimm_provider_data(struct nd_dimm *nd_dimm);
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
#endif /* __LIBND_H__ */
