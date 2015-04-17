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
#include <linux/nd.h>
#include "libnd.h"

extern struct list_head nd_bus_list;
extern struct mutex nd_bus_list_mutex;
extern int nd_dimm_major;

struct block_device;
struct nd_io_claim;
struct nd_btt;
struct nd_io;

struct nd_bus {
	struct nd_bus_descriptor *nd_desc;
	wait_queue_head_t probe_wait;
	struct module *module;
	struct list_head ndios;
	struct list_head list;
	struct device dev;
	int id, probe_active;
	struct mutex reconfig_mutex;
	struct nd_btt *nd_btt;
};

struct nd_dimm {
	unsigned long flags;
	void *provider_data;
	unsigned long *dsm_mask;
	struct device dev;
	atomic_t busy;
	int id;
};

struct nd_io *ndio_lookup(struct nd_bus *nd_bus, const char *diskname);
bool is_nd_dimm(struct device *dev);
bool is_nd_blk(struct device *dev);
bool is_nd_pmem(struct device *dev);
#if IS_ENABLED(CONFIG_ND_BTT_DEVS)
bool is_nd_btt(struct device *dev);
struct nd_btt *nd_btt_create(struct nd_bus *nd_bus);
void nd_btt_notify_ndio(struct nd_bus *nd_bus, struct nd_io *ndio);
#else
static inline bool is_nd_btt(struct device *dev)
{
	return false;
}

static inline struct nd_btt *nd_btt_create(struct nd_bus *nd_bus)
{
	return NULL;
}

static inline void nd_btt_notify_ndio(struct nd_bus *nd_bus, struct nd_io *ndio)
{
}
#endif
struct nd_bus *walk_to_nd_bus(struct device *nd_dev);
int __init nd_bus_init(void);
void nd_bus_exit(void);
int __init nd_dimm_init(void);
int __init nd_region_init(void);
void __init nd_region_init_locks(void);
void nd_dimm_exit(void);
int nd_region_exit(void);
void nd_region_probe_start(struct nd_bus *nd_bus, struct device *dev);
void nd_region_probe_end(struct nd_bus *nd_bus, struct device *dev, int rc);
struct nd_region;
void nd_region_create_blk_seed(struct nd_region *nd_region);
void nd_region_notify_remove(struct nd_bus *nd_bus, struct device *dev, int rc);
int nd_bus_create_ndctl(struct nd_bus *nd_bus);
void nd_bus_destroy_ndctl(struct nd_bus *nd_bus);
void nd_synchronize(void);
int nd_bus_register_dimms(struct nd_bus *nd_bus);
int nd_bus_register_regions(struct nd_bus *nd_bus);
int nd_bus_init_interleave_sets(struct nd_bus *nd_bus);
void __nd_device_register(struct device *dev);
int nd_match_dimm(struct device *dev, void *data);
struct nd_label_id;
char *nd_label_gen_id(struct nd_label_id *label_id, u8 *uuid, u32 flags);
bool nd_is_uuid_unique(struct device *dev, u8 *uuid);
struct nd_region;
struct nd_dimm_drvdata;
struct nd_mapping;
resource_size_t nd_pmem_available_dpa(struct nd_region *nd_region,
		struct nd_mapping *nd_mapping, resource_size_t *overlap);
resource_size_t nd_blk_available_dpa(struct nd_mapping *nd_mapping);
resource_size_t nd_region_available_dpa(struct nd_region *nd_region);
struct resource *nd_dimm_allocate_dpa(struct nd_dimm_drvdata *ndd,
		struct nd_label_id *label_id, resource_size_t start,
		resource_size_t n);
resource_size_t nd_dimm_allocated_dpa(struct nd_dimm_drvdata *ndd,
		struct nd_label_id *label_id);
struct nd_mapping;
struct resource *nsblk_add_resource(struct nd_region *nd_region,
		struct nd_dimm_drvdata *ndd, struct nd_namespace_blk *nsblk,
		resource_size_t start);
int nd_dimm_num_label_slots(struct nd_dimm_drvdata *ndd);
#endif /* __ND_PRIVATE_H__ */
