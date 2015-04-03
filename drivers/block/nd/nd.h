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
#ifndef __ND_H__
#define __ND_H__
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/ndctl.h>

struct nd_dimm_drvdata {
	struct device *dev;
	struct nfit_cmd_get_config_size nsarea;
	void *data;
};

struct nd_mapping {
	struct nd_dimm *nd_dimm;
	u64 start;
	u64 size;
};

struct nd_region {
	struct device dev;
	struct nd_spa *nd_spa;
	u16 ndr_mappings;
	u64 ndr_size;
	u64 ndr_start;
	int id;
	struct nd_mapping mapping[0];
};

enum nd_async_mode {
	ND_SYNC,
	ND_ASYNC,
};

void nd_device_register(struct device *dev);
void nd_device_unregister(struct device *dev, enum nd_async_mode mode);
extern struct attribute_group nd_device_attribute_group;
struct nd_dimm;
u32 to_nfit_handle(struct nd_dimm *nd_dimm);
void *nd_dimm_get_pdata(struct nd_dimm *nd_dimm);
void nd_dimm_set_pdata(struct nd_dimm *nd_dimm, void *data);
unsigned long nd_dimm_get_dsm_mask(struct nd_dimm *nd_dimm);
void nd_dimm_set_dsm_mask(struct nd_dimm *nd_dimm, unsigned long dsm_mask);
int nd_dimm_init_nsarea(struct nd_dimm_drvdata *ndd);
int nd_dimm_init_config_data(struct nd_dimm_drvdata *ndd);
int nd_dimm_firmware_status(struct device *dev);
struct nd_region *to_nd_region(struct device *dev);
#endif /* __ND_H__ */
