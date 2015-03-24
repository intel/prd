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
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/sizes.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/nd.h>
#include "nd.h"

static void free_data(struct nd_dimm_drvdata *ndd)
{
	if (!ndd)
		return;

	if (ndd->data && is_vmalloc_addr(ndd->data))
		vfree(ndd->data);
	else
		kfree(ndd->data);
	kfree(ndd);
}

static int nd_dimm_probe(struct device *dev)
{
	struct nd_dimm_drvdata *ndd;
	int rc;

	ndd = kzalloc(sizeof(*ndd), GFP_KERNEL);
	if (!ndd)
		return -ENOMEM;

	dev_set_drvdata(dev, ndd);
        ndd->dev = dev;

	rc = nd_dimm_init_nsarea(ndd);
	if (rc)
		goto err;

	rc = nd_dimm_init_config_data(ndd);
	if (rc)
		goto err;

	dev_dbg(dev, "config data size: %d\n", ndd->nsarea.config_size);

	return 0;

 err:
	free_data(ndd);
	return rc;

}

static int nd_dimm_remove(struct device *dev)
{
	struct nd_dimm_drvdata *ndd = dev_get_drvdata(dev);

	free_data(ndd);

	return 0;
}

static struct nd_device_driver nd_dimm_driver = {
	.probe = nd_dimm_probe,
	.remove = nd_dimm_remove,
	.drv = {
		.name = "nd_dimm",
	},
	.type = ND_DRIVER_DIMM,
};

int __init nd_dimm_init(void)
{
	return nd_driver_register(&nd_dimm_driver);
}

void nd_dimm_exit(void)
{
	driver_unregister(&nd_dimm_driver.drv);
}

MODULE_ALIAS_ND_DEVICE(ND_DEVICE_DIMM);
