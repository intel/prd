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
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include "nd-private.h"
#include "btt.h"
#include "nd.h"

static DEFINE_IDA(btt_ida);

static void nd_btt_release(struct device *dev)
{
	struct nd_btt *nd_btt = to_nd_btt(dev);

	dev_dbg(dev, "%s\n", __func__);
	WARN_ON(nd_btt->backing_dev);
	ndio_del_claim(nd_btt->ndio_claim);
	ida_simple_remove(&btt_ida, nd_btt->id);
	kfree(nd_btt->uuid);
	kfree(nd_btt);
}

static struct device_type nd_btt_device_type = {
	.name = "nd_btt",
	.release = nd_btt_release,
};

bool is_nd_btt(struct device *dev)
{
	return dev->type == &nd_btt_device_type;
}

struct nd_btt *to_nd_btt(struct device *dev)
{
	struct nd_btt *nd_btt = container_of(dev, struct nd_btt, dev);

	WARN_ON(!is_nd_btt(dev));
	return nd_btt;
}
EXPORT_SYMBOL(to_nd_btt);

static const unsigned long btt_lbasize_supported[] = { 512, 4096, 0 };

static ssize_t sector_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_btt *nd_btt = to_nd_btt(dev);

	return nd_sector_size_show(nd_btt->lbasize, btt_lbasize_supported, buf);
}

static ssize_t sector_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct nd_btt *nd_btt = to_nd_btt(dev);
	ssize_t rc;

	device_lock(dev);
	nd_bus_lock(dev);
	rc = nd_sector_size_store(dev, buf, &nd_btt->lbasize,
			btt_lbasize_supported);
	dev_dbg(dev, "%s: result: %zd wrote: %s%s", __func__,
			rc, buf, buf[len - 1] == '\n' ? "" : "\n");
	nd_bus_unlock(dev);
	device_unlock(dev);

	return rc ? rc : len;
}
static DEVICE_ATTR_RW(sector_size);

static ssize_t uuid_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_btt *nd_btt = to_nd_btt(dev);

	if (nd_btt->uuid)
		return sprintf(buf, "%pUb\n", nd_btt->uuid);
	return sprintf(buf, "\n");
}

static ssize_t uuid_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct nd_btt *nd_btt = to_nd_btt(dev);
	ssize_t rc;

	device_lock(dev);
	rc = nd_uuid_store(dev, &nd_btt->uuid, buf, len);
	dev_dbg(dev, "%s: result: %zd wrote: %s%s", __func__,
			rc, buf, buf[len - 1] == '\n' ? "" : "\n");
	device_unlock(dev);

	return rc ? rc : len;
}
static DEVICE_ATTR_RW(uuid);

static ssize_t backing_dev_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nd_btt *nd_btt = to_nd_btt(dev);
	char name[BDEVNAME_SIZE];

	if (nd_btt->backing_dev)
		return sprintf(buf, "/dev/%s\n",
				bdevname(nd_btt->backing_dev, name));
	else
		return sprintf(buf, "\n");
}

static const fmode_t nd_btt_devs_mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

static void nd_btt_ndio_notify_remove(struct nd_io_claim *ndio_claim)
{
	char bdev_name[BDEVNAME_SIZE];
	struct nd_btt *nd_btt;

	if (!ndio_claim || !ndio_claim->holder)
		return;

	nd_btt = to_nd_btt(ndio_claim->holder);
	WARN_ON_ONCE(!is_nd_bus_locked(&nd_btt->dev));
	dev_dbg(&nd_btt->dev, "%pf: %s: release /dev/%s\n",
			__builtin_return_address(0), __func__,
			bdevname(nd_btt->backing_dev, bdev_name));
	blkdev_put(nd_btt->backing_dev, nd_btt_devs_mode);
	nd_btt->backing_dev = NULL;

	/*
	 * Once we've had our backing device removed we need to be fully
	 * reconfigured.  The bus will have already created a new seed
	 * for this purpose, so now is a good time to clean up this
	 * stale nd_btt instance.
	 */
	if (nd_btt->dev.driver)
		nd_device_unregister(&nd_btt->dev, ND_ASYNC);
	else {
		ndio_del_claim(ndio_claim);
		nd_btt->ndio_claim = NULL;
	}
}

static ssize_t __backing_dev_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);
	struct nd_btt *nd_btt = to_nd_btt(dev);
	char bdev_name[BDEVNAME_SIZE];
	struct block_device *bdev;
	struct nd_io *ndio;
	char *path;

	if (dev->driver) {
		dev_dbg(dev, "%s: -EBUSY\n", __func__);
		return -EBUSY;
	}

	path = kstrndup(buf, len, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	/* detach the backing device */
	if (strcmp(strim(path), "") == 0) {
		if (!nd_btt->backing_dev)
			goto out;
		nd_btt_ndio_notify_remove(nd_btt->ndio_claim);
		goto out;
	} else if (nd_btt->backing_dev) {
		dev_dbg(dev, "backing_dev already set\n");
		len = -EBUSY;
		goto out;
	}

	bdev = blkdev_get_by_path(strim(path), nd_btt_devs_mode, nd_btt);
	if (IS_ERR(bdev)) {
		dev_dbg(dev, "open '%s' failed: %ld\n", strim(path),
				PTR_ERR(bdev));
		len = PTR_ERR(bdev);
		goto out;
	}

	if (get_capacity(bdev->bd_disk) < SZ_16M / 512) {
		blkdev_put(bdev, nd_btt_devs_mode);
		len = -ENXIO;
		goto out;
	}

	ndio = ndio_lookup(nd_bus, bdevname(bdev->bd_contains, bdev_name));
	if (!ndio) {
		dev_dbg(dev, "%s does not have an ndio interface\n",
				strim(path));
		blkdev_put(bdev, nd_btt_devs_mode);
		len = -ENXIO;
		goto out;
	}

	nd_btt->ndio_claim = ndio_add_claim(ndio, &nd_btt->dev,
			nd_btt_ndio_notify_remove);
	if (!nd_btt->ndio_claim) {
		blkdev_put(bdev, nd_btt_devs_mode);
		len = -ENOMEM;
		goto out;
	}

	WARN_ON_ONCE(!is_nd_bus_locked(&nd_btt->dev));
	nd_btt->backing_dev = bdev;

 out:
	kfree(path);
	return len;
}

static ssize_t backing_dev_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	ssize_t rc;

	nd_bus_lock(dev);
	device_lock(dev);
	rc = __backing_dev_store(dev, attr, buf, len);
	dev_dbg(dev, "%s: result: %zd wrote: %s%s", __func__,
			rc, buf, buf[len - 1] == '\n' ? "" : "\n");
	device_unlock(dev);
	nd_bus_unlock(dev);

	return rc;
}
static DEVICE_ATTR_RW(backing_dev);

static bool is_nd_btt_idle(struct device *dev)
{
	struct nd_bus *nd_bus = walk_to_nd_bus(dev);
	struct nd_btt *nd_btt = to_nd_btt(dev);

	if (nd_bus->nd_btt == nd_btt || dev->driver || nd_btt->backing_dev)
		return false;
	return true;
}

static ssize_t delete_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	/* return 1 if can be deleted */
	return sprintf(buf, "%d\n", is_nd_btt_idle(dev));
}

static ssize_t delete_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	unsigned long val;

	/* write 1 to delete */
	if (kstrtoul(buf, 0, &val) != 0 || val != 1)
		return -EINVAL;

	/* prevent deletion while this btt is active, or is the current seed */
	if (!is_nd_btt_idle(dev))
		return -EBUSY;

	/*
	 * userspace raced itself if device goes active here and it gets
	 * to keep the pieces
	 */
	nd_device_unregister(dev, ND_ASYNC);

	return len;
}
static DEVICE_ATTR_RW(delete);

static struct attribute *nd_btt_attributes[] = {
	&dev_attr_sector_size.attr,
	&dev_attr_backing_dev.attr,
	&dev_attr_delete.attr,
	&dev_attr_uuid.attr,
	NULL,
};

static struct attribute_group nd_btt_attribute_group = {
	.attrs = nd_btt_attributes,
};

static const struct attribute_group *nd_btt_attribute_groups[] = {
	&nd_btt_attribute_group,
	&nd_device_attribute_group,
	NULL,
};

static struct nd_btt *__nd_btt_create(struct nd_bus *nd_bus,
		unsigned long lbasize, u8 *uuid)
{
	struct nd_btt *nd_btt = kzalloc(sizeof(*nd_btt), GFP_KERNEL);
	struct device *dev;

	if (!nd_btt)
		return NULL;
	nd_btt->id = ida_simple_get(&btt_ida, 0, 0, GFP_KERNEL);
	if (nd_btt->id < 0) {
		kfree(nd_btt);
		return NULL;
	}

	nd_btt->lbasize = lbasize;
	if (uuid)
		uuid = kmemdup(uuid, 16, GFP_KERNEL);
	nd_btt->uuid = uuid;
	dev = &nd_btt->dev;
	dev_set_name(dev, "btt%d", nd_btt->id);
	dev->parent = &nd_bus->dev;
	dev->type = &nd_btt_device_type;
	dev->groups = nd_btt_attribute_groups;
	return nd_btt;
}

struct nd_btt *nd_btt_create(struct nd_bus *nd_bus)
{
	struct nd_btt *nd_btt = __nd_btt_create(nd_bus, 0, NULL);

	if (!nd_btt)
		return NULL;
	nd_device_register(&nd_btt->dev);
	return nd_btt;
}

/*
 * nd_btt_sb_checksum: compute checksum for btt info block
 *
 * Returns a fletcher64 checksum of everything in the given info block
 * except the last field (since that's where the checksum lives).
 */
u64 nd_btt_sb_checksum(struct btt_sb *btt_sb)
{
	u64 sum, sum_save;

	sum_save = btt_sb->checksum;
	btt_sb->checksum = 0;
	sum = nd_fletcher64(btt_sb, sizeof(*btt_sb));
	btt_sb->checksum = sum_save;
	return sum;
}
EXPORT_SYMBOL(nd_btt_sb_checksum);

static int nd_btt_autodetect(struct nd_bus *nd_bus, struct nd_io *ndio,
		struct block_device *bdev)
{
	char name[BDEVNAME_SIZE];
	struct nd_btt *nd_btt;
	struct btt_sb *btt_sb;
	u64 offset, checksum;
	u32 lbasize;
	u8 *uuid;
	int rc;

	btt_sb = kzalloc(sizeof(*btt_sb), GFP_KERNEL);
	if (!btt_sb)
		return -ENODEV;

	offset = nd_partition_offset(bdev);
	rc = ndio->rw_bytes(ndio, btt_sb, offset + SZ_4K, sizeof(*btt_sb), READ);
	if (rc)
		goto out_free_sb;

	if (get_capacity(bdev->bd_disk) < SZ_16M / 512)
		goto out_free_sb;

	if (memcmp(btt_sb->signature, BTT_SIG, BTT_SIG_LEN) != 0)
		goto out_free_sb;

	checksum = le64_to_cpu(btt_sb->checksum);
	btt_sb->checksum = 0;
	if (checksum != nd_btt_sb_checksum(btt_sb))
		goto out_free_sb;
	btt_sb->checksum = cpu_to_le64(checksum);

	uuid = kmemdup(btt_sb->uuid, 16, GFP_KERNEL);
	if (!uuid)
		goto out_free_sb;

	lbasize = le32_to_cpu(btt_sb->external_lbasize);
	nd_btt = __nd_btt_create(nd_bus, lbasize, uuid);
	if (!nd_btt)
		goto out_free_uuid;

	device_initialize(&nd_btt->dev);
	nd_btt->ndio_claim = ndio_add_claim(ndio, &nd_btt->dev,
			nd_btt_ndio_notify_remove);
	if (!nd_btt->ndio_claim)
		goto out_free_btt;

	nd_btt->backing_dev = bdev;
	dev_dbg(&nd_btt->dev, "%s: activate %s\n", __func__,
			bdevname(bdev, name));
	__nd_device_register(&nd_btt->dev);
	kfree(btt_sb);
	return 0;

 out_free_btt:
	kfree(nd_btt);
 out_free_uuid:
	kfree(uuid);
 out_free_sb:
	kfree(btt_sb);

	return -ENODEV;
}

void nd_btt_notify_ndio(struct nd_bus *nd_bus, struct nd_io *ndio)
{
	struct disk_part_iter piter;
	struct hd_struct *part;

	disk_part_iter_init(&piter, ndio->disk, DISK_PITER_INCL_PART0);
	while ((part = disk_part_iter_next(&piter))) {
		struct block_device *bdev;
		int rc;

		bdev = bdget_disk(ndio->disk, part->partno);
		if (!bdev)
			continue;
		if (blkdev_get(bdev, nd_btt_devs_mode, nd_bus) != 0)
			continue;
		rc = nd_btt_autodetect(nd_bus, ndio, bdev);
		if (rc)
			blkdev_put(bdev, nd_btt_devs_mode);
		/* no need to scan further in the case of whole disk btt */
		if (rc == 0 && part->partno == 0)
			break;
	}
	disk_part_iter_exit(&piter);
}
