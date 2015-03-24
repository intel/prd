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
extern struct list_head nd_bus_list;
extern struct mutex nd_bus_list_mutex;

struct nd_bus {
	struct nfit_bus_descriptor *nfit_desc;
	struct list_head memdevs;
	struct list_head dimms;
	struct list_head spas;
	struct list_head dcrs;
	struct list_head bdws;
	struct list_head list;
	struct device dev;
	int id;
};

struct nd_spa {
	struct nfit_spa __iomem *nfit_spa;
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

struct nd_bus *to_nd_bus(struct device *dev);
int __init nd_bus_init(void);
void __exit nd_bus_exit(void);
int nd_bus_create_ndctl(struct nd_bus *nd_bus);
void nd_bus_destroy_ndctl(struct nd_bus *nd_bus);
#endif /* __ND_PRIVATE_H__ */
