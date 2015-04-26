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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include "nfit_test.h"

#include "../acpi_nfit.h"
#include "../libnd.h"

/*
 * Generate an NFIT table to describe the following topology:
 *
 * BUS0: Interleaved PMEM regions, and aliasing with BLK regions
 *
 *                     (a)                       (b)            DIMM   BLK-REGION
 *           +----------+--------------+----------+---------+
 * +------+  |  blk2.0  |     pm0.0    |  blk2.1  |  pm1.0  |    0      region2
 * | imc0 +--+- - - - - region0 - - - -+----------+         +
 * +--+---+  |  blk3.0  |     pm0.0    |  blk3.1  |  pm1.0  |    1      region3
 *    |      +----------+--------------v----------v         v
 * +--+---+                            |                    |
 * | cpu0 |                                    region1
 * +--+---+                            |                    |
 *    |      +-------------------------^----------^         ^
 * +--+---+  |                 blk4.0             |  pm1.0  |    2      region4
 * | imc1 +--+-------------------------+----------+         +
 * +------+  |                 blk5.0             |  pm1.0  |    3      region5
 *           +-------------------------+----------+-+-------+
 *
 * *) In this layout we have four dimms and two memory controllers in one
 *    socket.  Each unique interface (BLK or PMEM) to DPA space
 *    is identified by a region device with a dynamically assigned id.
 *
 * *) The first portion of dimm0 and dimm1 are interleaved as REGION0.
 *    A single PMEM namespace "pm0.0" is created using half of the
 *    REGION0 SPA-range.  REGION0 spans dimm0 and dimm1.  PMEM namespace
 *    allocate from from the bottom of a region.  The unallocated
 *    portion of REGION0 aliases with REGION2 and REGION3.  That
 *    unallacted capacity is reclaimed as BLK namespaces ("blk2.0" and
 *    "blk3.0") starting at the base of each DIMM to offset (a) in those
 *    DIMMs.  "pm0.0", "blk2.0" and "blk3.0" are free-form readable
 *    names that can be assigned to a namespace.
 *
 * *) In the last portion of dimm0 and dimm1 we have an interleaved
 *    SPA range, REGION1, that spans those two dimms as well as dimm2
 *    and dimm3.  Some of REGION1 allocated to a PMEM namespace named
 *    "pm1.0" the rest is reclaimed in 4 BLK namespaces (for each
 *    dimm in the interleave set), "blk2.1", "blk3.1", "blk4.0", and
 *    "blk5.0".
 *
 * *) The portion of dimm2 and dimm3 that do not participate in the
 *    REGION1 interleaved SPA range (i.e. the DPA address below offset
 *    (b) are also included in the "blk4.0" and "blk5.0" namespaces.
 *    Note, that BLK namespaces need not be contiguous in DPA-space, and
 *    can consume aliased capacity from multiple interleave sets.
 *
 * BUS1: Legacy NVDIMM (single contiguous range)
 *
 *  region2
 * +---------------------+
 * |---------------------|
 * ||       pm2.0       ||
 * |---------------------|
 * +---------------------+
 *
 * *) A NFIT-table may describe a simple system-physical-address range
 *    with no BLK aliasing.  This type of region may optionally
 *    reference an NVDIMM.
 */
enum {
	NUM_PM  = 2,
	NUM_DCR = 4,
	NUM_BDW = NUM_DCR,
	NUM_SPA = NUM_PM + NUM_DCR + NUM_BDW,
	NUM_MEM = NUM_DCR + NUM_BDW + 2 /* spa0 iset */ + 4 /* spa1 iset */,
	DIMM_SIZE = SZ_32M,
	LABEL_SIZE = SZ_128K,
	SPA0_SIZE = DIMM_SIZE,
	SPA1_SIZE = DIMM_SIZE*2,
	SPA2_SIZE = DIMM_SIZE,
	BDW_SIZE = 64 << 8,
	DCR_SIZE = 12,
	NUM_NFITS = 2, /* permit testing multiple NFITs per system */
};

struct nfit_test_dcr {
	__le64 bdw_addr;
	__le32 bdw_status;
	__u8 aperature[BDW_SIZE];
};

static u32 handle[NUM_DCR] = {
	[0] = NFIT_DIMM_HANDLE(0, 0, 0, 0, 0),
	[1] = NFIT_DIMM_HANDLE(0, 0, 0, 0, 1),
	[2] = NFIT_DIMM_HANDLE(0, 0, 1, 0, 0),
	[3] = NFIT_DIMM_HANDLE(0, 0, 1, 0, 1),
};

struct nfit_test {
	struct acpi_nfit_desc acpi_desc;
	struct platform_device pdev;
	struct list_head resources;
	void *nfit_buf;
	dma_addr_t nfit_dma;
	size_t nfit_size;
	int num_dcr;
	int num_pm;
	void **dimm;
	dma_addr_t *dimm_dma;
	void **label;
	dma_addr_t *label_dma;
	void **spa_set;
	dma_addr_t *spa_set_dma;
	struct nfit_test_dcr **dcr;
	dma_addr_t *dcr_dma;
	int (*alloc)(struct nfit_test *t);
	void (*setup)(struct nfit_test *t);
};

static struct nfit_test *to_nfit_test(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);

	return container_of(pdev, struct nfit_test, pdev);
}

static int nfit_test_ctl(struct nd_bus_descriptor *nd_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len)
{
	return -ENOTTY;
}

static DEFINE_SPINLOCK(nfit_test_lock);
static struct nfit_test *instances[NUM_NFITS];

static void release_nfit_res(void *data)
{
	struct nfit_test_resource *nfit_res = data;
	struct resource *res = nfit_res->res;

	spin_lock(&nfit_test_lock);
	list_del(&nfit_res->list);
	spin_unlock(&nfit_test_lock);

	if (is_vmalloc_addr(nfit_res->buf))
		vfree(nfit_res->buf);
	else
		dma_free_coherent(nfit_res->dev, resource_size(res),
				nfit_res->buf, res->start);
	kfree(res);
	kfree(nfit_res);
}

static void *__test_alloc(struct nfit_test *t, size_t size, dma_addr_t *dma,
		void *buf)
{
	struct device *dev = &t->pdev.dev;
	struct resource *res = kzalloc(sizeof(*res) * 2, GFP_KERNEL);
	struct nfit_test_resource *nfit_res = kzalloc(sizeof(*nfit_res),
			GFP_KERNEL);
	int rc;

	if (!res || !buf || !nfit_res)
		goto err;
	rc = devm_add_action(dev, release_nfit_res, nfit_res);
	if (rc)
		goto err;
	INIT_LIST_HEAD(&nfit_res->list);
	memset(buf, 0, size);
	nfit_res->dev = dev;
	nfit_res->buf = buf;
	nfit_res->res = res;
	res->start = *dma;
	res->end = *dma + size - 1;
	res->name = "NFIT";
	spin_lock(&nfit_test_lock);
	list_add(&nfit_res->list, &t->resources);
	spin_unlock(&nfit_test_lock);

	return nfit_res->buf;
 err:
	if (buf && !is_vmalloc_addr(buf))
		dma_free_coherent(dev, size, buf, *dma);
	else if (buf)
		vfree(buf);
	kfree(res);
	kfree(nfit_res);
	return NULL;
}

static void *test_alloc(struct nfit_test *t, size_t size, dma_addr_t *dma)
{
	void *buf = vmalloc(size);

	*dma = (unsigned long) buf;
	return __test_alloc(t, size, dma, buf);
}

static void *test_alloc_coherent(struct nfit_test *t, size_t size, dma_addr_t *dma)
{
	struct device *dev = &t->pdev.dev;
	void *buf = dma_alloc_coherent(dev, size, dma, GFP_KERNEL);

	return __test_alloc(t, size, dma, buf);
}

static struct nfit_test_resource *nfit_test_lookup(resource_size_t addr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(instances); i++) {
		struct nfit_test_resource *n, *nfit_res = NULL;
		struct nfit_test *t = instances[i];

		if (!t)
			continue;
		spin_lock(&nfit_test_lock);
		list_for_each_entry(n, &t->resources, list) {
			if (addr >= n->res->start && (addr < n->res->start
						+ resource_size(n->res))) {
				nfit_res = n;
				break;
			} else if (addr >= (unsigned long) n->buf
					&& (addr < (unsigned long) n->buf
						+ resource_size(n->res))) {
				nfit_res = n;
				break;
			}
		}
		spin_unlock(&nfit_test_lock);
		if (nfit_res)
			return nfit_res;
	}

	return NULL;
}

static int nfit_test0_alloc(struct nfit_test *t)
{
	size_t nfit_size = sizeof(struct acpi_nfit)
			+ sizeof(struct acpi_nfit_spa) * NUM_SPA
			+ sizeof(struct acpi_nfit_memdev) * NUM_MEM
			+ sizeof(struct acpi_nfit_dcr) * NUM_DCR
			+ sizeof(struct acpi_nfit_bdw) * NUM_BDW;
	int i;

	t->nfit_buf = test_alloc(t, nfit_size, &t->nfit_dma);
	if (!t->nfit_buf)
		return -ENOMEM;
	t->nfit_size = nfit_size;

	t->spa_set[0] = test_alloc_coherent(t, SPA0_SIZE, &t->spa_set_dma[0]);
	if (!t->spa_set[0])
		return -ENOMEM;

	t->spa_set[1] = test_alloc_coherent(t, SPA1_SIZE, &t->spa_set_dma[1]);
	if (!t->spa_set[1])
		return -ENOMEM;

	for (i = 0; i < NUM_DCR; i++) {
		t->dimm[i] = test_alloc(t, DIMM_SIZE, &t->dimm_dma[i]);
		if (!t->dimm[i])
			return -ENOMEM;

		t->label[i] = test_alloc(t, LABEL_SIZE, &t->label_dma[i]);
		if (!t->label[i])
			return -ENOMEM;
	}

	for (i = 0; i < NUM_DCR; i++) {
		t->dcr[i] = test_alloc(t, LABEL_SIZE, &t->dcr_dma[i]);
		if (!t->dcr[i])
			return -ENOMEM;
	}

	return 0;
}

static u8 nfit_checksum(void *buf, size_t size)
{
	u8 sum, *data = buf;
	size_t i;

	for (sum = 0, i = 0; i < size; i++)
		sum += data[i];
	return 0 - sum;
}

static int nfit_test1_alloc(struct nfit_test *t)
{
	size_t nfit_size = sizeof(struct acpi_nfit)
		+ sizeof(struct acpi_nfit_spa) + sizeof(struct acpi_nfit_memdev)
		+ sizeof(struct acpi_nfit_dcr);

	t->nfit_buf = test_alloc(t, nfit_size, &t->nfit_dma);
	if (!t->nfit_buf)
		return -ENOMEM;
	t->nfit_size = nfit_size;

	t->spa_set[0] = test_alloc_coherent(t, SPA2_SIZE, &t->spa_set_dma[0]);
	if (!t->spa_set[0])
		return -ENOMEM;

	return 0;
}

static void nfit_test0_setup(struct nfit_test *t)
{
	struct nd_bus_descriptor *nd_desc;
	struct acpi_nfit_memdev *memdev;
	void *nfit_buf = t->nfit_buf;
	size_t size = t->nfit_size;
	struct acpi_nfit_spa *spa;
	struct acpi_nfit_dcr *dcr;
	struct acpi_nfit_bdw *bdw;
	struct acpi_nfit *nfit;
	unsigned int offset;

	/* nfit header */
	nfit = nfit_buf;
	memcpy(nfit->signature, "NFIT", 4);
	nfit->length = size;
	nfit->revision = 1;
	memcpy(nfit->oemid, "NDTEST", 6);
	nfit->oem_tbl_id = 0x1234;
	nfit->oem_revision = 1;
	nfit->creator_id = 0xabcd0000;
	nfit->creator_revision = 1;

	/*
	 * spa0 (interleave first half of dimm0 and dimm1, note storage
	 * does not actually alias the related block-data-window
	 * regions)
	 */
	spa = nfit_buf + sizeof(*nfit);
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_pm, 16);
	spa->spa_index = 0+1;
	spa->spa_base = t->spa_set_dma[0];
	spa->spa_length = SPA0_SIZE;

	/*
	 * spa1 (interleave last half of the 4 DIMMS, note storage
	 * does not actually alias the related block-data-window
	 * regions)
	 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa);
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_pm, 16);
	spa->spa_index = 1+1;
	spa->spa_base = t->spa_set_dma[1];
	spa->spa_length = SPA1_SIZE;

	/* spa2 (dcr0) dimm0 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 2;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	spa->spa_index = 2+1;
	spa->spa_base = t->dcr_dma[0];
	spa->spa_length = DCR_SIZE;

	/* spa3 (dcr1) dimm1 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 3;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	spa->spa_index = 3+1;
	spa->spa_base = t->dcr_dma[1];
	spa->spa_length = DCR_SIZE;

	/* spa4 (dcr2) dimm2 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 4;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	spa->spa_index = 4+1;
	spa->spa_base = t->dcr_dma[2];
	spa->spa_length = DCR_SIZE;

	/* spa5 (dcr3) dimm3 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 5;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	spa->spa_index = 5+1;
	spa->spa_base = t->dcr_dma[3];
	spa->spa_length = DCR_SIZE;

	/* spa6 (bdw for dcr0) dimm0 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 6;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	spa->spa_index = 6+1;
	spa->spa_base = t->dimm_dma[0];
	spa->spa_length = DIMM_SIZE;

	/* spa7 (bdw for dcr1) dimm1 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 7;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	spa->spa_index = 7+1;
	spa->spa_base = t->dimm_dma[1];
	spa->spa_length = DIMM_SIZE;

	/* spa8 (bdw for dcr2) dimm2 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 8;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	spa->spa_index = 8+1;
	spa->spa_base = t->dimm_dma[2];
	spa->spa_length = DIMM_SIZE;

	/* spa9 (bdw for dcr3) dimm3 */
	spa = nfit_buf + sizeof(*nfit) + sizeof(*spa) * 9;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	spa->spa_index = 9+1;
	spa->spa_base = t->dimm_dma[3];
	spa->spa_length = DIMM_SIZE;

	offset = sizeof(*nfit) + sizeof(*spa) * 10;
	/* mem-region0 (spa0, dimm0) */
	memdev = nfit_buf + offset;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[0];
	memdev->phys_id = 0;
	memdev->region_id = 0;
	memdev->spa_index = 0+1;
	memdev->dcr_index = 0+1;
	memdev->region_len = SPA0_SIZE/2;
	memdev->region_spa_offset = t->spa_set_dma[0];
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 2;

	/* mem-region1 (spa0, dimm1) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev);
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[1];
	memdev->phys_id = 1;
	memdev->region_id = 0;
	memdev->spa_index = 0+1;
	memdev->dcr_index = 1+1;
	memdev->region_len = SPA0_SIZE/2;
	memdev->region_spa_offset = t->spa_set_dma[0] + SPA0_SIZE/2;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 2;

	/* mem-region2 (spa1, dimm0) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 2;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[0];
	memdev->phys_id = 0;
	memdev->region_id = 1;
	memdev->spa_index = 1+1;
	memdev->dcr_index = 0+1;
	memdev->region_len = SPA1_SIZE/4;
	memdev->region_spa_offset = t->spa_set_dma[1];
	memdev->region_dpa = SPA0_SIZE/2;
	memdev->idt_index = 0;
	memdev->interleave_ways = 4;

	/* mem-region3 (spa1, dimm1) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 3;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[1];
	memdev->phys_id = 1;
	memdev->region_id = 1;
	memdev->spa_index = 1+1;
	memdev->dcr_index = 1+1;
	memdev->region_len = SPA1_SIZE/4;
	memdev->region_spa_offset = t->spa_set_dma[1] + SPA1_SIZE/4;
	memdev->region_dpa = SPA0_SIZE/2;
	memdev->idt_index = 0;
	memdev->interleave_ways = 4;

	/* mem-region4 (spa1, dimm2) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 4;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[2];
	memdev->phys_id = 2;
	memdev->region_id = 0;
	memdev->spa_index = 1+1;
	memdev->dcr_index = 2+1;
	memdev->region_len = SPA1_SIZE/4;
	memdev->region_spa_offset = t->spa_set_dma[1] + 2*SPA1_SIZE/4;
	memdev->region_dpa = SPA0_SIZE/2;
	memdev->idt_index = 0;
	memdev->interleave_ways = 4;

	/* mem-region5 (spa1, dimm3) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 5;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[3];
	memdev->phys_id = 3;
	memdev->region_id = 0;
	memdev->spa_index = 1+1;
	memdev->dcr_index = 3+1;
	memdev->region_len = SPA1_SIZE/4;
	memdev->region_spa_offset = t->spa_set_dma[1] + 3*SPA1_SIZE/4;
	memdev->region_dpa = SPA0_SIZE/2;
	memdev->idt_index = 0;
	memdev->interleave_ways = 4;

	/* mem-region6 (spa/dcr0, dimm0) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 6;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[0];
	memdev->phys_id = 0;
	memdev->region_id = 0;
	memdev->spa_index = 2+1;
	memdev->dcr_index = 0+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region7 (spa/dcr1, dimm1) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 7;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[1];
	memdev->phys_id = 1;
	memdev->region_id = 0;
	memdev->spa_index = 3+1;
	memdev->dcr_index = 1+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region8 (spa/dcr2, dimm2) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 8;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[2];
	memdev->phys_id = 2;
	memdev->region_id = 0;
	memdev->spa_index = 4+1;
	memdev->dcr_index = 2+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region9 (spa/dcr3, dimm3) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 9;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[3];
	memdev->phys_id = 3;
	memdev->region_id = 0;
	memdev->spa_index = 5+1;
	memdev->dcr_index = 3+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region10 (spa/bdw0, dimm0) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 10;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[0];
	memdev->phys_id = 0;
	memdev->region_id = 0;
	memdev->spa_index = 6+1;
	memdev->dcr_index = 0+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region11 (spa/bdw1, dimm1) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 11;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[1];
	memdev->phys_id = 1;
	memdev->region_id = 0;
	memdev->spa_index = 7+1;
	memdev->dcr_index = 1+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region12 (spa/bdw2, dimm2) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 12;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[2];
	memdev->phys_id = 2;
	memdev->region_id = 0;
	memdev->spa_index = 8+1;
	memdev->dcr_index = 2+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	/* mem-region13 (spa/dcr3, dimm3) */
	memdev = nfit_buf + offset + sizeof(struct acpi_nfit_memdev) * 13;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = handle[3];
	memdev->phys_id = 3;
	memdev->region_id = 0;
	memdev->spa_index = 9+1;
	memdev->dcr_index = 3+1;
	memdev->region_len = 0;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	offset = offset + sizeof(struct acpi_nfit_memdev) * 14;
	/* dcr-descriptor0 */
	dcr = nfit_buf + offset;
	dcr->type = NFIT_TABLE_DCR;
	dcr->length = sizeof(struct acpi_nfit_dcr);
	dcr->dcr_index = 0+1;
	dcr->vendor_id = 0xabcd;
	dcr->device_id = 0;
	dcr->revision_id = 1;
	dcr->serial_number = ~handle[0];
	dcr->num_bcw = 1;
	dcr->bcw_size = DCR_SIZE;
	dcr->cmd_offset = 0;
	dcr->cmd_size = 8;
	dcr->status_offset = 8;
	dcr->status_size = 4;

	/* dcr-descriptor1 */
	dcr = nfit_buf + offset + sizeof(struct acpi_nfit_dcr);
	dcr->type = NFIT_TABLE_DCR;
	dcr->length = sizeof(struct acpi_nfit_dcr);
	dcr->dcr_index = 1+1;
	dcr->vendor_id = 0xabcd;
	dcr->device_id = 0;
	dcr->revision_id = 1;
	dcr->serial_number = ~handle[1];
	dcr->num_bcw = 1;
	dcr->bcw_size = DCR_SIZE;
	dcr->cmd_offset = 0;
	dcr->cmd_size = 8;
	dcr->status_offset = 8;
	dcr->status_size = 4;

	/* dcr-descriptor2 */
	dcr = nfit_buf + offset + sizeof(struct acpi_nfit_dcr) * 2;
	dcr->type = NFIT_TABLE_DCR;
	dcr->length = sizeof(struct acpi_nfit_dcr);
	dcr->dcr_index = 2+1;
	dcr->vendor_id = 0xabcd;
	dcr->device_id = 0;
	dcr->revision_id = 1;
	dcr->serial_number = ~handle[2];
	dcr->num_bcw = 1;
	dcr->bcw_size = DCR_SIZE;
	dcr->cmd_offset = 0;
	dcr->cmd_size = 8;
	dcr->status_offset = 8;
	dcr->status_size = 4;

	/* dcr-descriptor3 */
	dcr = nfit_buf + offset + sizeof(struct acpi_nfit_dcr) * 3;
	dcr->type = NFIT_TABLE_DCR;
	dcr->length = sizeof(struct acpi_nfit_dcr);
	dcr->dcr_index = 3+1;
	dcr->vendor_id = 0xabcd;
	dcr->device_id = 0;
	dcr->revision_id = 1;
	dcr->serial_number = ~handle[3];
	dcr->num_bcw = 1;
	dcr->bcw_size = DCR_SIZE;
	dcr->cmd_offset = 0;
	dcr->cmd_size = 8;
	dcr->status_offset = 8;
	dcr->status_size = 4;

	offset = offset + sizeof(struct acpi_nfit_dcr) * 4;
	/* bdw0 (spa/dcr0, dimm0) */
	bdw = nfit_buf + offset;
	bdw->type = NFIT_TABLE_BDW;
	bdw->length = sizeof(struct acpi_nfit_bdw);
	bdw->dcr_index = 0+1;
	bdw->num_bdw = 1;
	bdw->bdw_offset = 0;
	bdw->bdw_size = BDW_SIZE;
	bdw->blk_capacity = DIMM_SIZE;
	bdw->blk_offset = 0;

	/* bdw1 (spa/dcr1, dimm1) */
	bdw = nfit_buf + offset + sizeof(struct acpi_nfit_bdw);
	bdw->type = NFIT_TABLE_BDW;
	bdw->length = sizeof(struct acpi_nfit_bdw);
	bdw->dcr_index = 1+1;
	bdw->num_bdw = 1;
	bdw->bdw_offset = 0;
	bdw->bdw_size = BDW_SIZE;
	bdw->blk_capacity = DIMM_SIZE;
	bdw->blk_offset = 0;

	/* bdw2 (spa/dcr2, dimm2) */
	bdw = nfit_buf + offset + sizeof(struct acpi_nfit_bdw) * 2;
	bdw->type = NFIT_TABLE_BDW;
	bdw->length = sizeof(struct acpi_nfit_bdw);
	bdw->dcr_index = 2+1;
	bdw->num_bdw = 1;
	bdw->bdw_offset = 0;
	bdw->bdw_size = BDW_SIZE;
	bdw->blk_capacity = DIMM_SIZE;
	bdw->blk_offset = 0;

	/* bdw3 (spa/dcr3, dimm3) */
	bdw = nfit_buf + offset + sizeof(struct acpi_nfit_bdw) * 3;
	bdw->type = NFIT_TABLE_BDW;
	bdw->length = sizeof(struct acpi_nfit_bdw);
	bdw->dcr_index = 3+1;
	bdw->num_bdw = 1;
	bdw->bdw_offset = 0;
	bdw->bdw_size = BDW_SIZE;
	bdw->blk_capacity = DIMM_SIZE;
	bdw->blk_offset = 0;

	nfit->checksum = nfit_checksum(nfit_buf, size);

	nd_desc = &t->acpi_desc.nd_desc;
	nd_desc->ndctl = nfit_test_ctl;
}

static void nfit_test1_setup(struct nfit_test *t)
{
	size_t size = t->nfit_size, offset;
	void *nfit_buf = t->nfit_buf;
	struct acpi_nfit_memdev *memdev;
	struct acpi_nfit_dcr *dcr;
	struct acpi_nfit_spa *spa;
	struct acpi_nfit *nfit;

	/* nfit header */
	nfit = nfit_buf;
	memcpy(nfit->signature, "NFIT", 4);
	nfit->length = size;
	nfit->revision = 1;
	memcpy(nfit->oemid, "NDTEST", 6);
	nfit->oem_tbl_id = 0x1234;
	nfit->oem_revision = 1;
	nfit->creator_id = 0xabcd0000;
	nfit->creator_revision = 1;

	offset = sizeof(*nfit);
	/* spa0 (flat range with no bdw aliasing) */
	spa = nfit_buf + offset;
	spa->type = NFIT_TABLE_SPA;
	spa->length = sizeof(*spa);
	memcpy(spa->type_uuid, &nfit_spa_uuid_pm, 16);
	spa->spa_index = 0+1;
	spa->spa_base = t->spa_set_dma[0];
	spa->spa_length = SPA2_SIZE;

	offset += sizeof(*spa);
	/* mem-region0 (spa0, dimm0) */
	memdev = nfit_buf + offset;
	memdev->type = NFIT_TABLE_MEM;
	memdev->length = sizeof(*memdev);
	memdev->nfit_handle = 0;
	memdev->phys_id = 0;
	memdev->region_id = 0;
	memdev->spa_index = 0+1;
	memdev->dcr_index = 0+1;
	memdev->region_len = SPA2_SIZE;
	memdev->region_spa_offset = 0;
	memdev->region_dpa = 0;
	memdev->idt_index = 0;
	memdev->interleave_ways = 1;

	offset += sizeof(*memdev);
	/* dcr-descriptor0 */
	dcr = nfit_buf + offset;
	dcr->type = NFIT_TABLE_DCR;
	dcr->length = sizeof(struct acpi_nfit_dcr);
	dcr->dcr_index = 0+1;
	dcr->vendor_id = 0xabcd;
	dcr->device_id = 0;
	dcr->revision_id = 1;
	dcr->serial_number = ~0;
	dcr->num_bcw = 0;
	dcr->bcw_size = 0;
	dcr->cmd_offset = 0;
	dcr->cmd_size = 0;
	dcr->status_offset = 0;
	dcr->status_size = 0;

	nfit->checksum = nfit_checksum(nfit_buf, size);
}

extern const struct attribute_group *nd_acpi_attribute_groups[];

static int nfit_test_probe(struct platform_device *pdev)
{
	struct nd_bus_descriptor *nd_desc;
	struct acpi_nfit_desc *acpi_desc;
	struct device *dev = &pdev->dev;
	struct nfit_test *nfit_test;
	int rc;

	nfit_test = to_nfit_test(&pdev->dev);

	/* common alloc */
	if (nfit_test->num_dcr) {
		int num = nfit_test->num_dcr;

		nfit_test->dimm = devm_kcalloc(dev, num, sizeof(void *), GFP_KERNEL);
		nfit_test->dimm_dma = devm_kcalloc(dev, num, sizeof(dma_addr_t), GFP_KERNEL);
		nfit_test->label = devm_kcalloc(dev, num, sizeof(void *), GFP_KERNEL);
		nfit_test->label_dma = devm_kcalloc(dev, num, sizeof(dma_addr_t), GFP_KERNEL);
		nfit_test->dcr = devm_kcalloc(dev, num, sizeof(struct nfit_test_dcr *), GFP_KERNEL);
		nfit_test->dcr_dma = devm_kcalloc(dev, num, sizeof(dma_addr_t), GFP_KERNEL);
		if (nfit_test->dimm && nfit_test->dimm_dma && nfit_test->label
				&& nfit_test->label_dma && nfit_test->dcr
				&& nfit_test->dcr_dma)
			/* pass */;
		else
			return -ENOMEM;
	}

	if (nfit_test->num_pm) {
		int num = nfit_test->num_pm;

		nfit_test->spa_set = devm_kcalloc(dev, num, sizeof(void *), GFP_KERNEL);
		nfit_test->spa_set_dma = devm_kcalloc(dev, num,
				sizeof(dma_addr_t), GFP_KERNEL);
		if (nfit_test->spa_set && nfit_test->spa_set_dma)
			/* pass */;
		else
			return -ENOMEM;
	}

	/* per-nfit specific alloc */
	if (nfit_test->alloc(nfit_test))
		return -ENOMEM;

	nfit_test->setup(nfit_test);
	acpi_desc = &nfit_test->acpi_desc;
	acpi_desc->dev = &pdev->dev;
	acpi_desc->nfit = nfit_test->nfit_buf;
	nd_desc = &acpi_desc->nd_desc;
	nd_desc->attr_groups = nd_acpi_attribute_groups;
	acpi_desc->nd_bus = nd_bus_register(&pdev->dev, nd_desc);
	if (!acpi_desc->nd_bus)
		return -ENXIO;

	rc = nd_acpi_nfit_init(acpi_desc, nfit_test->nfit_size);
	if (rc) {
		nd_bus_unregister(acpi_desc->nd_bus);
		return rc;
	}

	return 0;
}

static int nfit_test_remove(struct platform_device *pdev)
{
	struct nfit_test *nfit_test = to_nfit_test(&pdev->dev);
	struct acpi_nfit_desc *acpi_desc = &nfit_test->acpi_desc;

	nd_bus_unregister(acpi_desc->nd_bus);

	return 0;
}

static void nfit_test_release(struct device *dev)
{
	struct nfit_test *nfit_test = to_nfit_test(dev);

	kfree(nfit_test);
}

static const struct platform_device_id nfit_test_id[] = {
	{ KBUILD_MODNAME },
	{ },
};

static struct platform_driver nfit_test_driver = {
	.probe = nfit_test_probe,
	.remove = nfit_test_remove,
	.driver = {
		.name = KBUILD_MODNAME,
	},
	.id_table = nfit_test_id,
};

#ifdef CONFIG_CMA_SIZE_MBYTES
#define CMA_SIZE_MBYTES CONFIG_CMA_SIZE_MBYTES
#else
#define CMA_SIZE_MBYTES 0
#endif

static __init int nfit_test_init(void)
{
	int rc, i;

	nfit_test_setup(nfit_test_lookup);

	for (i = 0; i < NUM_NFITS; i++) {
		struct nfit_test *nfit_test;
		struct platform_device *pdev;
		static int once;

		nfit_test = kzalloc(sizeof(*nfit_test), GFP_KERNEL);
		if (!nfit_test) {
			rc = -ENOMEM;
			goto err_register;
		}
		INIT_LIST_HEAD(&nfit_test->resources);
		switch (i) {
		case 0:
			nfit_test->num_pm = NUM_PM;
			nfit_test->num_dcr = NUM_DCR;
			nfit_test->alloc = nfit_test0_alloc;
			nfit_test->setup = nfit_test0_setup;
			break;
		case 1:
			nfit_test->num_pm = 1;
			nfit_test->alloc = nfit_test1_alloc;
			nfit_test->setup = nfit_test1_setup;
			break;
		default:
			rc = -EINVAL;
			goto err_register;
		}
		pdev = &nfit_test->pdev;
		pdev->name = KBUILD_MODNAME;
		pdev->id = i;
		pdev->dev.release = nfit_test_release;
		rc = platform_device_register(pdev);
		if (rc) {
			put_device(&pdev->dev);
			goto err_register;
		}

		rc = dma_coerce_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
		if (rc)
			goto err_register;

		instances[i] = nfit_test;

		if (!once++) {
			dma_addr_t dma;
			void *buf;

			buf = dma_alloc_coherent(&pdev->dev, SZ_128M, &dma,
					GFP_KERNEL);
			if (!buf) {
				rc = -ENOMEM;
				dev_warn(&pdev->dev, "need 128M of free cma\n");
				goto err_register;
			}
			dma_free_coherent(&pdev->dev, SZ_128M, buf, dma);
		}
	}

	rc = platform_driver_register(&nfit_test_driver);
	if (rc)
		goto err_register;
	return 0;

 err_register:
	for (i = 0; i < NUM_NFITS; i++)
		if (instances[i])
			platform_device_unregister(&instances[i]->pdev);
	nfit_test_teardown();
	return rc;
}

static __exit void nfit_test_exit(void)
{
	int i;

	platform_driver_unregister(&nfit_test_driver);
	for (i = 0; i < NUM_NFITS; i++)
		platform_device_unregister(&instances[i]->pdev);
	nfit_test_teardown();
}

module_init(nfit_test_init);
module_exit(nfit_test_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
