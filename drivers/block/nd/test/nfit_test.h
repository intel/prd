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
#ifndef __NFIT_TEST_H__
#define __NFIT_TEST_H__
#include <linux/types.h>

struct nfit_test_resource {
	struct list_head list;
	struct resource *res;
	void *buf;
};

typedef struct nfit_test_resource *(*nfit_test_lookup_fn)(resource_size_t);
struct nd_region;
typedef unsigned int (*nfit_test_acquire_lane_fn)(struct nd_region *nd_region);
typedef void (*nfit_test_release_lane_fn)(struct nd_region *nd_region,
		unsigned int lane);
struct nd_blk_window;
struct page;
typedef int (*nfit_test_blk_do_io_fn)(struct nd_blk_window *ndbw, void *iobuf,
		unsigned int len, int rw, resource_size_t dpa);
void nfit_test_setup(nfit_test_lookup_fn lookup,
		nfit_test_acquire_lane_fn acquire_lane,
		nfit_test_release_lane_fn release_lane,
		nfit_test_blk_do_io_fn blk_do_io);
void nfit_test_teardown(void);
#endif
