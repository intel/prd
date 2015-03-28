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
#ifndef __ND_PRIVATE_H__
#define __ND_PRIVATE_H__
#include <linux/device.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include "libnd.h"

extern struct list_head nd_bus_list;
extern struct mutex nd_bus_list_mutex;
extern int nd_dimm_major;

struct nd_bus {
	struct nd_bus_descriptor *nd_desc;
	wait_queue_head_t probe_wait;
	struct module *module;
	struct list_head list;
	struct device dev;
	int id, probe_active;
	struct mutex reconfig_mutex;
};

struct nd_dimm {
	unsigned long flags;
	void *provider_data;
	unsigned long *dsm_mask;
	struct device dev;
	atomic_t busy;
	int id;
};

bool is_nd_dimm(struct device *dev);
bool is_nd_blk(struct device *dev);
bool is_nd_pmem(struct device *dev);
struct nd_bus *walk_to_nd_bus(struct device *nd_dev);
int __init nd_bus_init(void);
void nd_bus_exit(void);
int __init nd_dimm_init(void);
int __init nd_region_init(void);
void nd_dimm_exit(void);
int nd_region_exit(void);
void nd_region_probe_start(struct nd_bus *nd_bus, struct device *dev);
void nd_region_probe_end(struct nd_bus *nd_bus, struct device *dev, int rc);
void nd_region_notify_remove(struct nd_bus *nd_bus, struct device *dev, int rc);
int nd_bus_create_ndctl(struct nd_bus *nd_bus);
void nd_bus_destroy_ndctl(struct nd_bus *nd_bus);
void nd_synchronize(void);
int nd_bus_register_dimms(struct nd_bus *nd_bus);
int nd_bus_register_regions(struct nd_bus *nd_bus);
int nd_bus_init_interleave_sets(struct nd_bus *nd_bus);
int nd_match_dimm(struct device *dev, void *data);
#endif /* __ND_PRIVATE_H__ */
