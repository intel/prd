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
struct nd_dimm;
u32 to_nfit_handle(struct nd_dimm *nd_dimm);
void *nd_dimm_get_pdata(struct nd_dimm *nd_dimm);
void nd_dimm_set_pdata(struct nd_dimm *nd_dimm, void *data);
unsigned long nd_dimm_get_dsm_mask(struct nd_dimm *nd_dimm);
void nd_dimm_set_dsm_mask(struct nd_dimm *nd_dimm, unsigned long dsm_mask);
#endif /* __ND_H__ */
