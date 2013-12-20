/*
 * fs/dax.c - Direct Access filesystem code
 * Copyright (c) 2013-2014 Intel Corporation
 * Author: Matthew Wilcox <matthew.r.wilcox@intel.com>
 * Author: Ross Zwisler <ross.zwisler@linux.intel.com>
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

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/uio.h>
#include <linux/vmstat.h>

static long dax_get_addr(struct inode *inode, struct buffer_head *bh,
								void **addr)
{
	struct block_device *bdev = bh->b_bdev;
	const struct block_device_operations *ops = bdev->bd_disk->fops;
	unsigned long pfn;
	sector_t sector = bh->b_blocknr << (inode->i_blkbits - 9);
	return ops->direct_access(bdev, sector, addr, &pfn, bh->b_size);
}

static long dax_get_pfn(struct inode *inode, struct buffer_head *bh,
							unsigned long *pfn)
{
	struct block_device *bdev = bh->b_bdev;
	const struct block_device_operations *ops = bdev->bd_disk->fops;
	void *addr;
	sector_t sector = bh->b_blocknr << (inode->i_blkbits - 9);
	return ops->direct_access(bdev, sector, &addr, pfn, bh->b_size);
}

static void dax_new_buf(void *addr, unsigned size, unsigned first,
					loff_t offset, loff_t end, int rw)
{
	loff_t final = end - offset + first; /* The final byte of the buffer */
	if (rw != WRITE) {
		memset(addr, 0, size);
		return;
	}

	if (first > 0)
		memset(addr, 0, first);
	if (final < size)
		memset(addr + final, 0, size - final);
}

static bool buffer_written(struct buffer_head *bh)
{
	return buffer_mapped(bh) && !buffer_unwritten(bh);
}

/*
 * When ext4 encounters a hole, it likes to return without modifying the
 * buffer_head which means that we can't trust b_size.  To cope with this,
 * we set b_state to 0 before calling get_block and, if any bit is set, we
 * know we can trust b_size.  Unfortunate, really, since ext4 does know
 * precisely how long a hole is and would save us time calling get_block
 * repeatedly.
 */
static bool buffer_size_valid(struct buffer_head *bh)
{
	return bh->b_state != 0;
}

static ssize_t dax_io(int rw, struct inode *inode, const struct iovec *iov,
			loff_t start, loff_t end, get_block_t get_block,
			struct buffer_head *bh)
{
	ssize_t retval = 0;
	unsigned seg = 0;
	unsigned len;
	unsigned copied = 0;
	loff_t offset = start;
	loff_t max = start;
	loff_t bh_max = start;
	void *addr;
	bool hole = false;

	if (rw != WRITE)
		end = min(end, i_size_read(inode));

	while (offset < end) {
		void __user *buf = iov[seg].iov_base + copied;

		if (offset == max) {
			sector_t block = offset >> inode->i_blkbits;
			unsigned first = offset - (block << inode->i_blkbits);
			long size;

			if (offset == bh_max) {
				bh->b_size = PAGE_ALIGN(end - offset);
				bh->b_state = 0;
				retval = get_block(inode, block, bh,
								rw == WRITE);
				if (retval)
					break;
				if (!buffer_size_valid(bh))
					bh->b_size = 1 << inode->i_blkbits;
				bh_max = offset - first + bh->b_size;
			} else {
				unsigned done = bh->b_size - (bh_max -
							(offset - first));
				bh->b_blocknr += done >> inode->i_blkbits;
				bh->b_size -= done;
			}
			if (rw == WRITE) {
				if (!buffer_mapped(bh)) {
					retval = -EIO;
					break;
				}
				hole = false;
			} else {
				hole = !buffer_written(bh);
			}

			if (hole) {
				addr = NULL;
				size = bh->b_size - first;
			} else {
				retval = dax_get_addr(inode, bh, &addr);
				if (retval < 0)
					break;
				if (buffer_unwritten(bh) || buffer_new(bh))
					dax_new_buf(addr, retval, first,
						   offset, end, rw);
				addr += first;
				size = retval - first;
			}
			max = min(offset + size, end);
		}

		len = min_t(unsigned, iov[seg].iov_len - copied, max - offset);

		if (rw == WRITE)
			len -= __copy_from_user_nocache(addr, buf, len);
		else if (!hole)
			len -= __copy_to_user(buf, addr, len);
		else
			len -= __clear_user(buf, len);

		if (!len)
			break;

		offset += len;
		copied += len;
		addr += len;
		if (copied == iov[seg].iov_len) {
			seg++;
			copied = 0;
		}
	}

	return (offset == start) ? retval : offset - start;
}

/**
 * dax_do_io - Perform I/O to a DAX file
 * @rw: READ to read or WRITE to write
 * @iocb: The control block for this I/O
 * @inode: The file which the I/O is directed at
 * @iov: The user addresses to do I/O from or to
 * @offset: The file offset where the I/O starts
 * @nr_segs: The length of the iov array
 * @get_block: The filesystem method used to translate file offsets to blocks
 * @end_io: A filesystem callback for I/O completion
 * @flags: See below
 *
 * This function uses the same locking scheme as do_blockdev_direct_IO:
 * If @flags has DIO_LOCKING set, we assume that the i_mutex is held by the
 * caller for writes.  For reads, we take and release the i_mutex ourselves.
 * If DIO_LOCKING is not set, the filesystem takes care of its own locking.
 * As with do_blockdev_direct_IO(), we increment i_dio_count while the I/O
 * is in progress.
 */
ssize_t dax_do_io(int rw, struct kiocb *iocb, struct inode *inode,
		const struct iovec *iov, loff_t offset, unsigned nr_segs,
		get_block_t get_block, dio_iodone_t end_io, int flags)
{
	struct buffer_head bh;
	unsigned seg;
	ssize_t retval = -EINVAL;
	loff_t end = offset;

	memset(&bh, 0, sizeof(bh));
	for (seg = 0; seg < nr_segs; seg++)
		end += iov[seg].iov_len;

	if ((flags & DIO_LOCKING) && (rw == READ)) {
		struct address_space *mapping = inode->i_mapping;
		mutex_lock(&inode->i_mutex);
		retval = filemap_write_and_wait_range(mapping, offset, end - 1);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			goto out;
		}
	}

	/* Protects against truncate */
	atomic_inc(&inode->i_dio_count);

	retval = dax_io(rw, inode, iov, offset, end, get_block, &bh);

	if ((flags & DIO_LOCKING) && (rw == READ))
		mutex_unlock(&inode->i_mutex);

	inode_dio_done(inode);

	if ((retval > 0) && end_io)
		end_io(iocb, offset, retval, bh.b_private);
 out:
	return retval;
}
EXPORT_SYMBOL_GPL(dax_do_io);

/*
 * The user has performed a load from a hole in the file.  Allocating
 * a new page in the file would cause excessive storage usage for
 * workloads with sparse files.  We allocate a page cache page instead.
 * We'll kick it out of the page cache if it's ever written to,
 * otherwise it will simply fall out of the page cache under memory
 * pressure without ever having been dirtied.
 */
static int dax_load_hole(struct address_space *mapping, struct page *page,
							struct vm_fault *vmf)
{
	unsigned long size;
	struct inode *inode = mapping->host;
	if (!page)
		page = find_or_create_page(mapping, vmf->pgoff,
						GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return VM_FAULT_OOM;
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		unlock_page(page);
		page_cache_release(page);
		return VM_FAULT_SIGBUS;
	}

	vmf->page = page;
	return VM_FAULT_LOCKED;
}

static void copy_user_bh(struct page *to, struct inode *inode,
				struct buffer_head *bh, unsigned long vaddr)
{
	void *vfrom, *vto;
	dax_get_addr(inode, bh, &vfrom);	/* XXX: error handling */
	vto = kmap_atomic(to);
	copy_user_page(vto, vfrom, vaddr, to);
	kunmap_atomic(vto);
}

static int do_dax_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
			get_block_t get_block)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = file->f_mapping;
	struct page *page;
	struct buffer_head bh;
	unsigned long vaddr = (unsigned long)vmf->virtual_address;
	sector_t block;
	pgoff_t size;
	unsigned long pfn;
	int error;
	int major = 0;

	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size)
		return VM_FAULT_SIGBUS;

	memset(&bh, 0, sizeof(bh));
	block = (sector_t)vmf->pgoff << (PAGE_SHIFT - inode->i_blkbits);
	bh.b_size = PAGE_SIZE;

 repeat:
	page = find_get_page(mapping, vmf->pgoff);
	if (page) {
		if (!lock_page_or_retry(page, vma->vm_mm, vmf->flags)) {
			page_cache_release(page);
			return VM_FAULT_RETRY;
		}
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			page_cache_release(page);
			goto repeat;
		}
	}

	error = get_block(inode, block, &bh, 0);
	if (error || bh.b_size < PAGE_SIZE)
		goto sigbus;

	if (!buffer_written(&bh) && !vmf->cow_page) {
		if (vmf->flags & FAULT_FLAG_WRITE) {
			error = get_block(inode, block, &bh, 1);
			count_vm_event(PGMAJFAULT);
			mem_cgroup_count_vm_event(vma->vm_mm, PGMAJFAULT);
			major = VM_FAULT_MAJOR;
			if (error || bh.b_size < PAGE_SIZE)
				goto sigbus;
		} else {
			return dax_load_hole(mapping, page, vmf);
		}
	}

	/* Recheck i_size under i_mmap_mutex */
	mutex_lock(&mapping->i_mmap_mutex);
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (unlikely(vmf->pgoff >= size)) {
		mutex_unlock(&mapping->i_mmap_mutex);
		goto sigbus;
	}
	if (vmf->cow_page) {
		if (buffer_written(&bh))
			copy_user_bh(vmf->cow_page, inode, &bh, vaddr);
		else
			clear_user_highpage(vmf->cow_page, vaddr);
		if (page) {
			unlock_page(page);
			page_cache_release(page);
		}
		/* do_cow_fault() will release the i_mmap_mutex */
		return VM_FAULT_COWED;
	}

	if (buffer_unwritten(&bh) || buffer_new(&bh))
		dax_clear_blocks(inode, bh.b_blocknr, bh.b_size);

	error = dax_get_pfn(inode, &bh, &pfn);
	if (error > 0)
		error = vm_insert_mixed(vma, vaddr, pfn);
	mutex_unlock(&mapping->i_mmap_mutex);

	if (page) {
		delete_from_page_cache(page);
		unmap_mapping_range(mapping, vmf->pgoff << PAGE_SHIFT,
							PAGE_CACHE_SIZE, 0);
		unlock_page(page);
		page_cache_release(page);
	}

	if (error == -ENOMEM)
		return VM_FAULT_OOM;
	/* -EBUSY is fine, somebody else faulted on the same PTE */
	if (error != -EBUSY)
		BUG_ON(error);
	return VM_FAULT_NOPAGE | major;

 sigbus:
	if (page) {
		unlock_page(page);
		page_cache_release(page);
	}
	return VM_FAULT_SIGBUS;
}

/**
 * dax_fault - handle a page fault on an XIP file
 * @vma: The virtual memory area where the fault occurred
 * @vmf: The description of the fault
 * @get_block: The filesystem method used to translate file offsets to blocks
 *
 * When a page fault occurs, filesystems may call this helper in their
 * fault handler for XIP files.
 */
int dax_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
			get_block_t get_block)
{
	int result;
	struct super_block *sb = file_inode(vma->vm_file)->i_sb;

	sb_start_pagefault(sb);
	file_update_time(vma->vm_file);
	result = do_dax_fault(vma, vmf, get_block);
	sb_end_pagefault(sb);

	return result;
}
EXPORT_SYMBOL_GPL(dax_fault);

/**
 * dax_mkwrite - convert a read-only page to read-write in an XIP file
 * @vma: The virtual memory area where the fault occurred
 * @vmf: The description of the fault
 * @get_block: The filesystem method used to translate file offsets to blocks
 *
 * XIP handles reads of holes by adding pages full of zeroes into the
 * mapping.  If the page is subsequenty written to, we have to allocate
 * the page on media and free the page that was in the cache.
 */
int dax_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
			get_block_t get_block)
{
	int result;
	struct super_block *sb = file_inode(vma->vm_file)->i_sb;

	sb_start_pagefault(sb);
	file_update_time(vma->vm_file);
	result = do_dax_fault(vma, vmf, get_block);
	sb_end_pagefault(sb);

	return result;
}
EXPORT_SYMBOL_GPL(dax_mkwrite);
