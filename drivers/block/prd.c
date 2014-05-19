/*
 * Persistent RAM Driver
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
 *
 * This driver is heavily based on block/brd.c.
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 */

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)

/*
 * driver-wide physical address and total_size - one single, contiguous memory
 * region that we divide up in to same-sized devices
 */
phys_addr_t	phys_addr;
void		*virt_addr;
size_t		total_size;

struct prd_device {
	int			prd_number;

	struct request_queue	*prd_queue;
	struct gendisk		*prd_disk;
	struct list_head	prd_list;

	phys_addr_t		phys_addr;
	void			*virt_addr;
	size_t			size;
};

static int prd_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
	/* some standard values */
	geo->heads = 1 << 6;
	geo->sectors = 1 << 5;
	geo->cylinders = get_capacity(bd->bd_disk) >> 11;
	return 0;
}

/*
 * direct translation from (prd,sector) => void*
 * We do not require that sector be page aligned.
 * The return value will point to the beginning of the page containing the
 * given sector, not to the sector itself.
 */
static void *prd_lookup_pg_addr(struct prd_device *prd, sector_t sector)
{
	size_t page_offset = sector >> PAGE_SECTORS_SHIFT;
	size_t offset = page_offset << PAGE_SHIFT;
	BUG_ON(offset >= prd->size);
	return prd->virt_addr + offset;
}

/* sector must be page aligned */
static unsigned long prd_lookup_pfn(struct prd_device *prd, sector_t sector)
{
	size_t page_offset = sector >> PAGE_SECTORS_SHIFT;
	BUG_ON(sector & (PAGE_SECTORS - 1));
	return (prd->phys_addr >> PAGE_SHIFT) + page_offset;
}

/* sector must be page aligned */
static void prd_zero_page(struct prd_device *prd, sector_t sector)
{
	void *page_addr = prd_lookup_pg_addr(prd, sector);
	BUG_ON(sector & (PAGE_SECTORS - 1));
	memset(page_addr, 0, PAGE_SIZE);
}

/* sector must be page aligned and n must be a multiple of PAGE_SIZE */
static void discard_from_prd(struct prd_device *prd,
			sector_t sector, size_t n)
{
	BUG_ON(sector & (PAGE_SECTORS - 1));
	BUG_ON(n      & (PAGE_SIZE    - 1));

	while (n >= PAGE_SIZE) {
		prd_zero_page(prd, sector);
		sector += PAGE_SIZE >> SECTOR_SHIFT;
		n -= PAGE_SIZE;
	}
}

/*
 * sector is not required to be page aligned.
 * n is at most a single page, but could be less.
 */
static void copy_to_prd(struct prd_device *prd, const void *src,
			sector_t sector, size_t n)
{
	void *dst;
	unsigned int offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t copy;

	BUG_ON(n > PAGE_SIZE);

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	dst = prd_lookup_pg_addr(prd, sector);
	memcpy(dst + offset, src, copy);

	if (copy < n) {
		src += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		dst = prd_lookup_pg_addr(prd, sector);
		memcpy(dst, src, copy);
	}
}

/*
 * sector is not required to be page aligned.
 * n is at most a single page, but could be less.
 */
static void copy_from_prd(void *dst, struct prd_device *prd,
			  sector_t sector, size_t n)
{
	void *src;
	unsigned int offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;
	size_t copy;

	BUG_ON(n > PAGE_SIZE);

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	src = prd_lookup_pg_addr(prd, sector);

	memcpy(dst, src + offset, copy);

	if (copy < n) {
		dst += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		src = prd_lookup_pg_addr(prd, sector);
		memcpy(dst, src, copy);
	}
}

static void prd_do_bvec(struct prd_device *prd, struct page *page,
			unsigned int len, unsigned int off, int rw,
			sector_t sector)
{
	void *mem = kmap_atomic(page);

	if (rw == READ) {
		copy_from_prd(mem + off, prd, sector, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		copy_to_prd(prd, mem + off, sector, len);
	}

	kunmap_atomic(mem);
}

static void prd_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct prd_device *prd = bdev->bd_disk->private_data;
	int rw;
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;
	int err = 0;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bdev->bd_disk)) {
		err = -EIO;
		goto out;
	}

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		discard_from_prd(prd, sector, bio->bi_iter.bi_size);
		goto out;
	}

	rw = bio_rw(bio);
	if (rw == READA)
		rw = READ;

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		BUG_ON(len > PAGE_SIZE);
		prd_do_bvec(prd, bvec.bv_page, len,
			    bvec.bv_offset, rw, sector);
		sector += len >> SECTOR_SHIFT;
	}

out:
	bio_endio(bio, err);
}

/* sector must be page aligned and size must be a multiple of PAGE_SIZE */
static long prd_direct_access(struct block_device *bdev, sector_t sector,
			      void **kaddr, unsigned long *pfn, long size)
{
	struct prd_device *prd = bdev->bd_disk->private_data;

	if (!prd)
		return -ENODEV;
	if (sector & (PAGE_SECTORS - 1) ||
	    size   & (PAGE_SIZE    - 1))
		return -EINVAL;
	if (sector + (size >> SECTOR_SHIFT) > get_capacity(bdev->bd_disk))
		return -ERANGE;

	*kaddr = prd_lookup_pg_addr(prd, sector);
	*pfn = prd_lookup_pfn(prd, sector);

	return size;
}

static const struct block_device_operations prd_fops = {
	.owner =		THIS_MODULE,
	.direct_access =	prd_direct_access,
	.getgeo =		prd_getgeo,
};

/* Kernel module stuff */
static int prd_start_gb = CONFIG_BLK_DEV_PMEM_START;
module_param(prd_start_gb, int, S_IRUGO);
MODULE_PARM_DESC(prd_start_gb, "Offset in GB of where to start claiming space");

static int prd_size_gb = CONFIG_BLK_DEV_PMEM_SIZE;
module_param(prd_size_gb,  int, S_IRUGO);
MODULE_PARM_DESC(prd_size_gb,  "Total size in GB of space to claim for all disks");

static int prd_major;
module_param(prd_major, int, 0);
MODULE_PARM_DESC(prd_major,  "Major number to request for this driver");

static int prd_count = CONFIG_BLK_DEV_PMEM_COUNT;
module_param(prd_count, int, S_IRUGO);
MODULE_PARM_DESC(prd_count, "Number of prd devices to evenly split allocated space");

static int max_part = 15;
module_param(max_part, int, S_IRUGO);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per PRAM disk");

static int part_shift;

static LIST_HEAD(prd_devices);
static DEFINE_MUTEX(prd_devices_mutex);

/* FIXME: move phys_addr, virt_addr, size calls up to caller */
static struct prd_device *prd_alloc(int i)
{
	struct prd_device *prd;
	struct gendisk *disk;
	size_t disk_size = total_size / prd_count;
	size_t disk_sectors =  disk_size / 512;

	prd = kzalloc(sizeof(*prd), GFP_KERNEL);
	if (!prd)
		goto out;

	prd->prd_number	= i;
	prd->phys_addr = phys_addr + i * disk_size;
	prd->virt_addr = virt_addr + i * disk_size;
	prd->size = disk_size;

	prd->prd_queue = blk_alloc_queue(GFP_KERNEL);
	if (!prd->prd_queue)
		goto out_free_dev;

	blk_queue_make_request(prd->prd_queue, prd_make_request);
	blk_queue_max_hw_sectors(prd->prd_queue, 1024);
	blk_queue_bounce_limit(prd->prd_queue, BLK_BOUNCE_ANY);

	prd->prd_queue->limits.discard_granularity = PAGE_SIZE;
	prd->prd_queue->limits.max_discard_sectors = UINT_MAX;
	prd->prd_queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, prd->prd_queue);

	disk = prd->prd_disk = alloc_disk(1 << part_shift);
	if (!disk)
		goto out_free_queue;
	disk->major		= prd_major;
	disk->first_minor	= i << part_shift;
	disk->fops		= &prd_fops;
	disk->private_data	= prd;
	disk->queue		= prd->prd_queue;
	sprintf(disk->disk_name, "pmem%d", i);
	set_capacity(disk, disk_sectors);

	return prd;

out_free_queue:
	blk_cleanup_queue(prd->prd_queue);
out_free_dev:
	kfree(prd);
out:
	return NULL;
}

static void prd_free(struct prd_device *prd)
{
	put_disk(prd->prd_disk);
	blk_cleanup_queue(prd->prd_queue);
	kfree(prd);
}

static struct prd_device *prd_init_one(int i)
{
	struct prd_device *prd;

	list_for_each_entry(prd, &prd_devices, prd_list) {
		if (prd->prd_number == i)
			goto out;
	}

	prd = prd_alloc(i);
	if (prd) {
		add_disk(prd->prd_disk);
		list_add_tail(&prd->prd_list, &prd_devices);
	}
out:
	return prd;
}

static void prd_del_one(struct prd_device *prd)
{
	list_del(&prd->prd_list);
	del_gendisk(prd->prd_disk);
	prd_free(prd);
}

static struct kobject *prd_probe(dev_t dev, int *part, void *data)
{
	struct prd_device *prd;
	struct kobject *kobj;

	mutex_lock(&prd_devices_mutex);
	prd = prd_init_one(MINOR(dev) >> part_shift);
	kobj = prd ? get_disk(prd->prd_disk) : NULL;
	mutex_unlock(&prd_devices_mutex);

	*part = 0;
	return kobj;
}

static int __init prd_init(void)
{
	int result, i;
	struct resource *res_mem;
	unsigned long range;
	struct prd_device *prd, *next;

	phys_addr  = (phys_addr_t) prd_start_gb * 1024 * 1024 * 1024;
	total_size = (size_t)	   prd_size_gb  * 1024 * 1024 * 1024;

	res_mem = request_mem_region_exclusive(phys_addr, total_size, "prd");
	if (!res_mem)
		return -ENOMEM;

	virt_addr = ioremap_cache(phys_addr, total_size);

	if (!virt_addr) {
		result = -ENOMEM;
		goto out_release;
	}

	part_shift = 0;
	if (max_part > 0) {
		part_shift = fls(max_part);

		/*
		 * Adjust max_part according to part_shift as it is exported
		 * to user space so that user can decide correct minor number
		 * if [s]he want to create more devices.
		 *
		 * Note that -1 is required because partition 0 is reserved
		 * for the whole disk.
		 */
		max_part = (1UL << part_shift) - 1;
	}

	if ((1UL << part_shift) > DISK_MAX_PARTS ||
	    prd_count > 1UL << (MINORBITS - part_shift)) {
		result = -EINVAL;
		goto out_unmap;
	}

	/* FIXME: this is just a workaround for [bp]rd_probe being broken */
	range = 1UL << MINORBITS;

	result = register_blkdev(prd_major, "prd");
	if (result < 0) {
		result = -EIO;
		goto out_unmap;
	} else if (result > 0)
		prd_major = result;

	for (i = 0; i < prd_count; i++) {
		prd = prd_alloc(i);
		if (!prd) {
			result = -ENOMEM;
			goto out_free;
		}
		list_add_tail(&prd->prd_list, &prd_devices);
	}

	/* point of no return */

	list_for_each_entry(prd, &prd_devices, prd_list)
		add_disk(prd->prd_disk);

	blk_register_region(MKDEV(prd_major, 0), range,
				  THIS_MODULE, prd_probe, NULL, NULL);

	pr_info("prd: module loaded\n");
	return 0;

out_free:
	list_for_each_entry_safe(prd, next, &prd_devices, prd_list) {
		list_del(&prd->prd_list);
		prd_free(prd);
	}
	unregister_blkdev(prd_major, "prd");

out_unmap:
	iounmap(virt_addr);

out_release:
	release_mem_region(phys_addr, total_size);
	return result;
}

static void __exit prd_exit(void)
{
	unsigned long range;
	struct prd_device *prd, *next;

	range = prd_count << part_shift;

	blk_unregister_region(MKDEV(prd_major, 0), range);

	list_for_each_entry_safe(prd, next, &prd_devices, prd_list)
		prd_del_one(prd);

	unregister_blkdev(prd_major, "prd");
	iounmap(virt_addr);
	release_mem_region(phys_addr, total_size);

	pr_info("prd: module unloaded\n");
}

MODULE_AUTHOR("Ross Zwisler <ross.zwisler@linux.intel.com>");
MODULE_LICENSE("GPL");
module_init(prd_init);
module_exit(prd_exit);
