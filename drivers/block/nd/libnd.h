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
struct nd_dimm;
struct nd_bus_descriptor;
typedef int (*ndctl_fn)(struct nd_bus_descriptor *nd_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len);

struct nd_bus_descriptor {
	unsigned long dsm_mask;
	char *provider_name;
	ndctl_fn ndctl;
};

struct nd_bus;
struct nd_bus *nd_bus_register(struct device *parent,
		struct nd_bus_descriptor *nfit_desc);
void nd_bus_unregister(struct nd_bus *nd_bus);
#endif /* __LIBND_H__ */
