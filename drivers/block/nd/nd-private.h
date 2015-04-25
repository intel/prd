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
#include "libnd.h"

extern struct list_head nd_bus_list;
extern struct mutex nd_bus_list_mutex;
extern struct bus_type nd_bus_type;

struct nd_bus {
	struct nd_bus_descriptor *nd_desc;
	struct list_head list;
	struct device dev;
	int id;
};

struct nd_dimm {
	unsigned long flags;
	void *provider_data;
	struct device dev;
	int id;
};

struct nd_bus *walk_to_nd_bus(struct device *nd_dev);
int __init nd_bus_init(void);
void __exit nd_bus_exit(void);
int nd_bus_create_ndctl(struct nd_bus *nd_bus);
void nd_bus_destroy_ndctl(struct nd_bus *nd_bus);
#endif /* __ND_PRIVATE_H__ */
