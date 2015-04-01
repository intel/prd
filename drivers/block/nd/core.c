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
#include <linux/export.h>
#include <linux/module.h>
#include "nfit.h"

struct nd_bus *nfit_bus_register(struct device *parent,
		struct nfit_bus_descriptor *nfit_desc)
{
	return NULL;
}
EXPORT_SYMBOL(nfit_bus_register);

void nfit_bus_unregister(struct nd_bus *nd_bus)
{
}
EXPORT_SYMBOL(nfit_bus_unregister);

static __init int nd_core_init(void)
{
	BUILD_BUG_ON(sizeof(struct nfit) != 40);
	BUILD_BUG_ON(sizeof(struct nfit_spa) != 56);
	BUILD_BUG_ON(sizeof(struct nfit_mem) != 48);
	BUILD_BUG_ON(sizeof(struct nfit_idt) != 16);
	BUILD_BUG_ON(sizeof(struct nfit_smbios) != 8);
	BUILD_BUG_ON(sizeof(struct nfit_dcr) != 80);
	BUILD_BUG_ON(sizeof(struct nfit_bdw) != 40);

	return 0;
}

static __exit void nd_core_exit(void)
{
}
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
module_init(nd_core_init);
module_exit(nd_core_exit);
