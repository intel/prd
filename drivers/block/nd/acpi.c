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
#include <linux/list.h>
#include <linux/acpi.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include "nfit.h"

enum {
	NFIT_ACPI_NOTIFY_TABLE = 0x80,
};

struct acpi_nfit {
	struct nfit_bus_descriptor nfit_desc;
	struct acpi_device *dev;
	struct nd_bus *nd_bus;
};

static int nd_acpi_ctl(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len)
{
	return -ENOTTY;
}

static int nd_acpi_add(struct acpi_device *dev)
{
	struct nfit_bus_descriptor *nfit_desc;
	struct acpi_table_header *tbl;
	acpi_status status = AE_OK;
	struct acpi_nfit *nfit;
	acpi_size sz;

	status = acpi_get_table_with_size("NFIT", 0, &tbl, &sz);
	if (ACPI_FAILURE(status)) {
		dev_err(&dev->dev, "failed to find NFIT\n");
		return -ENXIO;
	}

	nfit = devm_kzalloc(&dev->dev, sizeof(*nfit), GFP_KERNEL);
	if (!nfit)
		return -ENOMEM;
	nfit->dev = dev;
	nfit_desc = &nfit->nfit_desc;
	nfit_desc->nfit_base = (void __iomem *) tbl;
	nfit_desc->nfit_size = sz;
	nfit_desc->provider_name = "ACPI.NFIT";
	nfit_desc->nfit_ctl = nd_acpi_ctl;

	nfit->nd_bus = nfit_bus_register(&dev->dev, nfit_desc);
	if (!nfit->nd_bus)
		return -ENXIO;

	dev_set_drvdata(&dev->dev, nfit);
	return 0;
}

static int nd_acpi_remove(struct acpi_device *dev)
{
	struct acpi_nfit *nfit = dev_get_drvdata(&dev->dev);

	nfit_bus_unregister(nfit->nd_bus);
	return 0;
}

static void nd_acpi_notify(struct acpi_device *dev, u32 event)
{
	/* TODO: handle ACPI_NOTIFY_BUS_CHECK notification */
	dev_dbg(&dev->dev, "%s: event: %d\n", __func__, event);
}

static const struct acpi_device_id nd_acpi_ids[] = {
	{ "ACPI0012", 0 },
	{ "", 0 },
};
MODULE_DEVICE_TABLE(acpi, nd_acpi_ids);

static struct acpi_driver nd_acpi_driver = {
	.name = KBUILD_MODNAME,
	.ids = nd_acpi_ids,
	.flags = ACPI_DRIVER_ALL_NOTIFY_EVENTS,
	.ops = {
		.add = nd_acpi_add,
		.remove = nd_acpi_remove,
		.notify = nd_acpi_notify
	},
};

static __init int nd_acpi_init(void)
{
	return acpi_bus_register_driver(&nd_acpi_driver);
}

static __exit void nd_acpi_exit(void)
{
	acpi_bus_unregister_driver(&nd_acpi_driver);
}

module_init(nd_acpi_init);
module_exit(nd_acpi_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
