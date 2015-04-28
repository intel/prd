/*
 * NVDIMM Block Window Driver
 * Copyright (c) 2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/nd.h>
#include <linux/sizes.h>
#include "nd.h"

struct nd_blk_device {
	struct request_queue *queue;
	struct gendisk *disk;
	struct nd_namespace_blk *nsblk;
	struct nd_blk_region *ndbr;
	struct nd_io ndio;
	size_t disk_size;
	int id;
};

static int nd_blk_major;
static DEFINE_IDA(nd_blk_ida);

static resource_size_t to_dev_offset(struct nd_namespace_blk *nsblk,
				resource_size_t ns_offset, unsigned int len)
{
	int i;

	for (i = 0; i < nsblk->num_resources; i++) {
		if (ns_offset < resource_size(nsblk->res[i])) {
			if (ns_offset + len > resource_size(nsblk->res[i])) {
				dev_WARN_ONCE(&nsblk->dev, 1,
					"%s: illegal request\n", __func__);
				return SIZE_MAX;
			}
			return nsblk->res[i]->start + ns_offset;
		}
		ns_offset -= resource_size(nsblk->res[i]);
	}

	dev_WARN_ONCE(&nsblk->dev, 1, "%s: request out of range\n", __func__);
	return SIZE_MAX;
}

static void nd_blk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct gendisk *disk = bdev->bd_disk;
	struct nd_namespace_blk *nsblk;
	struct nd_blk_device *blk_dev;
	struct nd_blk_region *ndbr;
	struct bvec_iter iter;
	struct bio_vec bvec;
	int err = 0, rw;
	sector_t sector;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(disk)) {
		err = -EIO;
		goto out;
	}

	BUG_ON(bio->bi_rw & REQ_DISCARD);

	rw = bio_data_dir(bio);

	blk_dev = disk->private_data;
	nsblk = blk_dev->nsblk;
	ndbr = blk_dev->ndbr;
	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		resource_size_t	dev_offset;
		void *iobuf;

		BUG_ON(len > PAGE_SIZE);

		dev_offset = to_dev_offset(nsblk, sector << SECTOR_SHIFT, len);
		if (dev_offset == SIZE_MAX) {
			err = -EIO;
			goto out;
		}

		iobuf = kmap_atomic(bvec.bv_page);
		err = ndbr->do_io(ndbr, iobuf + bvec.bv_offset, len, rw, dev_offset);
		kunmap_atomic(iobuf);
		if (err)
			goto out;

		sector += len >> SECTOR_SHIFT;
	}

 out:
	bio_endio(bio, err);
}

static int nd_blk_rw_bytes(struct nd_io *ndio, void *iobuf, size_t offset,
		size_t n, unsigned long flags)
{
	struct nd_namespace_blk *nsblk;
	struct nd_blk_device *blk_dev;
	int rw = nd_data_dir(flags);
	struct nd_blk_region *ndbr;
	resource_size_t	dev_offset;

	blk_dev = container_of(ndio, typeof(*blk_dev), ndio);
	ndbr = blk_dev->ndbr;
	nsblk = blk_dev->nsblk;
	dev_offset = to_dev_offset(nsblk, offset, n);

	if (unlikely(offset + n > blk_dev->disk_size)) {
		dev_WARN_ONCE(ndio->dev, 1, "%s: request out of range\n",
				__func__);
		return -EFAULT;
	}

	if (dev_offset == SIZE_MAX)
		return -EIO;

	return ndbr->do_io(ndbr, iobuf, n, rw, dev_offset);
}

static const struct block_device_operations nd_blk_fops = {
	.owner =		THIS_MODULE,
};

static int nd_blk_probe(struct device *dev)
{
	struct nd_namespace_blk *nsblk = to_nd_namespace_blk(dev);
	struct nd_blk_device *blk_dev;
	resource_size_t disk_size;
	struct gendisk *disk;
	int err;

	disk_size = nd_namespace_blk_validate(nsblk);
	if (disk_size < ND_MIN_NAMESPACE_SIZE)
		return -ENXIO;

	blk_dev = kzalloc(sizeof(*blk_dev), GFP_KERNEL);
	if (!blk_dev)
		return -ENOMEM;

	blk_dev->id = ida_simple_get(&nd_blk_ida, 0, 0, GFP_KERNEL);
	if (blk_dev->id < 0) {
		err = blk_dev->id;
		goto err_ida;
	}

	blk_dev->disk_size	= disk_size;

	blk_dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!blk_dev->queue) {
		err = -ENOMEM;
		goto err_alloc_queue;
	}

	blk_queue_make_request(blk_dev->queue, nd_blk_make_request);
	blk_queue_max_hw_sectors(blk_dev->queue, 1024);
	blk_queue_bounce_limit(blk_dev->queue, BLK_BOUNCE_ANY);

	disk = blk_dev->disk = alloc_disk(0);
	if (!disk) {
		err = -ENOMEM;
		goto err_alloc_disk;
	}

	blk_dev->ndbr = to_blk_region(to_nd_region(nsblk->dev.parent));
	blk_dev->nsblk = nsblk;

	disk->driverfs_dev	= dev;
	disk->major		= nd_blk_major;
	disk->first_minor	= 0;
	disk->fops		= &nd_blk_fops;
	disk->private_data	= blk_dev;
	disk->queue		= blk_dev->queue;
	disk->flags		= GENHD_FL_EXT_DEVT;
	sprintf(disk->disk_name, "ndblk%d", blk_dev->id);
	set_capacity(disk, disk_size >> SECTOR_SHIFT);

	nd_bus_lock(dev);
	dev_set_drvdata(dev, blk_dev);

	add_disk(disk);
	nd_init_ndio(&blk_dev->ndio, nd_blk_rw_bytes, dev, disk, 0);
	nd_register_ndio(&blk_dev->ndio);
	nd_bus_unlock(dev);

	return 0;

 err_alloc_disk:
	blk_cleanup_queue(blk_dev->queue);
 err_alloc_queue:
	ida_simple_remove(&nd_blk_ida, blk_dev->id);
 err_ida:
	kfree(blk_dev);
	return err;
}

static int nd_blk_remove(struct device *dev)
{
	/* FIXME: eventually need to get to nd_blk_device from struct device.
	struct nd_namespace_io *nsio = to_nd_namespace_io(dev); */

	struct nd_blk_device *blk_dev = dev_get_drvdata(dev);

	nd_unregister_ndio(&blk_dev->ndio);
	del_gendisk(blk_dev->disk);
	put_disk(blk_dev->disk);
	blk_cleanup_queue(blk_dev->queue);
	ida_simple_remove(&nd_blk_ida, blk_dev->id);
	kfree(blk_dev);

	return 0;
}

static struct nd_device_driver nd_blk_driver = {
	.probe = nd_blk_probe,
	.remove = nd_blk_remove,
	.drv = {
		.name = "nd_blk",
	},
	.type = ND_DRIVER_NAMESPACE_BLK,
};

static int __init nd_blk_init(void)
{
	int rc;

	rc = register_blkdev(0, "nd_blk");
	if (rc < 0)
		return rc;

	nd_blk_major = rc;
	rc = nd_driver_register(&nd_blk_driver);

	if (rc < 0)
		unregister_blkdev(nd_blk_major, "nd_blk");

	return rc;
}

static void __exit nd_blk_exit(void)
{
	driver_unregister(&nd_blk_driver.drv);
	unregister_blkdev(nd_blk_major, "nd_blk");
}

MODULE_AUTHOR("Ross Zwisler <ross.zwisler@linux.intel.com>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_ND_DEVICE(ND_DEVICE_NAMESPACE_BLK);
module_init(nd_blk_init);
module_exit(nd_blk_exit);
