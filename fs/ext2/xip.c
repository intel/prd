/*
 *  linux/fs/ext2/xip.c
 *
 * Copyright (C) 2005 IBM Corporation
 * Author: Carsten Otte (cotte@de.ibm.com)
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include "ext2.h"
#include "xip.h"

static inline long __inode_direct_access(struct inode *inode, sector_t block,
				void **kaddr, unsigned long *pfn, long size)
{
	struct block_device *bdev = inode->i_sb->s_bdev;
	const struct block_device_operations *ops = bdev->bd_disk->fops;
	sector_t sector = block * (PAGE_SIZE / 512);
	return ops->direct_access(bdev, sector, kaddr, pfn, size);
}

int
ext2_clear_xip_target(struct inode *inode, sector_t block)
{
	void *kaddr;
	unsigned long pfn;
	long size;

	size = __inode_direct_access(inode, block, &kaddr, &pfn, PAGE_SIZE);
	if (size < 0)
		return size;
	clear_page(kaddr);
	return 0;
}

void ext2_xip_verify_sb(struct super_block *sb)
{
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	if ((sbi->s_mount_opt & EXT2_MOUNT_XIP) &&
	    !sb->s_bdev->bd_disk->fops->direct_access) {
		sbi->s_mount_opt &= (~EXT2_MOUNT_XIP);
		ext2_msg(sb, KERN_WARNING,
			     "warning: ignoring xip option - "
			     "not supported by bdev");
	}
}
