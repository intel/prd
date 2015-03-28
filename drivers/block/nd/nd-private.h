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
#include <linux/radix-tree.h>
#include <linux/device.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include "nfit.h"

extern struct list_head nd_bus_list;
extern struct mutex nd_bus_list_mutex;
extern int nd_dimm_major;

enum {
	/* need to set a limit somewhere, but yes, this is likely overkill */
	ND_IOCTL_MAX_BUFLEN = SZ_4M,
};

/*
 * List manipulation is protected by nd_bus_list_mutex, except for the
 * deferred probe tracking list which nests under instances where
 * nd_bus_list_mutex is locked
 */
struct nd_bus {
	struct nfit_bus_descriptor *nfit_desc;
	struct radix_tree_root dimm_radix;
	wait_queue_head_t probe_wait;
	struct module *module;
	struct list_head memdevs;
	struct list_head dimms;
	struct list_head spas;
	struct list_head dcrs;
	struct list_head bdws;
	struct list_head list;
	struct device dev;
	int id, probe_active;
	struct mutex reconfig_mutex;
};

struct nd_dimm {
	unsigned long dsm_mask;
	struct nd_mem *nd_mem;
	struct device dev;
	void *provider_data;
	int id, nfit_status;
	atomic_t busy;
	struct nd_dimm_delete {
		struct nd_bus *nd_bus;
		struct nd_mem *nd_mem;
	} *del_info;
};

struct nd_interleave_set {
	u64 cookie;
};

struct nd_spa {
	struct nfit_spa __iomem *nfit_spa;
	struct nd_interleave_set *nd_set;
	struct list_head list;
};

struct nd_dcr {
	struct nfit_dcr __iomem *nfit_dcr;
	struct list_head list;
};

struct nd_bdw {
	struct nfit_bdw __iomem *nfit_bdw;
	struct list_head list;
};

struct nd_memdev {
	struct nfit_mem __iomem *nfit_mem;
	struct list_head list;
};

/* assembled tables for a given dimm */
struct nd_mem {
	struct nfit_mem __iomem *nfit_mem_dcr;
	struct nfit_dcr __iomem *nfit_dcr;
	struct nfit_bdw __iomem *nfit_bdw;
	struct nfit_spa __iomem *nfit_spa_dcr;
	struct nfit_spa __iomem *nfit_spa_bdw;
	struct list_head list;
};

const char *spa_type_name(u16 type);
int nfit_spa_type(struct nfit_spa __iomem *nfit_spa);
struct nd_dimm *nd_dimm_by_handle(struct nd_bus *nd_bus, u32 nfit_handle);
bool is_nd_dimm(struct device *dev);
bool is_nd_blk(struct device *dev);
bool is_nd_pmem(struct device *dev);
struct nd_bus *to_nd_bus(struct device *dev);
struct nd_dimm *to_nd_dimm(struct device *dev);
struct nd_bus *walk_to_nd_bus(struct device *nd_dev);
void nd_synchronize(void);
int __init nd_bus_init(void);
void nd_bus_exit(void);
void nd_dimm_delete(struct nd_dimm *nd_dimm);
int __init nd_dimm_init(void);
int __init nd_region_init(void);
void nd_dimm_exit(void);
int nd_region_exit(void);
void nd_region_probe_start(struct nd_bus *nd_bus, struct device *dev);
void nd_region_probe_end(struct nd_bus *nd_bus, struct device *dev, int rc);
void nd_region_notify_remove(struct nd_bus *nd_bus, struct device *dev, int rc);
int nd_bus_create_ndctl(struct nd_bus *nd_bus);
void nd_bus_destroy_ndctl(struct nd_bus *nd_bus);
int nd_bus_register_dimms(struct nd_bus *nd_bus);
int nd_bus_register_regions(struct nd_bus *nd_bus);
int nd_bus_init_interleave_sets(struct nd_bus *nd_bus);
int nd_match_dimm(struct device *dev, void *data);
#endif /* __ND_PRIVATE_H__ */
