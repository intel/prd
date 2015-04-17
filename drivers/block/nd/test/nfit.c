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
#include <linux/ndctl.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include "nfit_test.h"
#include "../nfit.h"
#include "../nd.h"

#include <asm-generic/io-64-nonatomic-lo-hi.h>

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
 *    with no backing dimm or interleave description.
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
	struct nfit_bus_descriptor nfit_desc;
	struct platform_device pdev;
	struct list_head resources;
	void __iomem *nfit_buf;
	struct nd_bus *nd_bus;
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

static int nfit_test_add_dimm(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm)
{
	u32 nfit_handle = to_nfit_handle(nd_dimm);
	unsigned long dsm_mask = 0;
	long i;

	for (i = 0; i < ARRAY_SIZE(handle); i++)
		if (nfit_handle == handle[i])
			break;
	if (i >= ARRAY_SIZE(handle))
		return -EINVAL;

	set_bit(NFIT_CMD_GET_CONFIG_SIZE, &dsm_mask);
	set_bit(NFIT_CMD_GET_CONFIG_DATA, &dsm_mask);
	set_bit(NFIT_CMD_SET_CONFIG_DATA, &dsm_mask);
	nd_dimm_set_dsm_mask(nd_dimm, dsm_mask);
	nd_dimm_set_pdata(nd_dimm, (void *) i);
	return 0;
}

static int nfit_test_ctl(struct nfit_bus_descriptor *nfit_desc,
		struct nd_dimm *nd_dimm, unsigned int cmd, void *buf,
		unsigned int buf_len)
{
	struct nfit_test *t = container_of(nfit_desc, typeof(*t), nfit_desc);
	unsigned long dsm_mask = nd_dimm_get_dsm_mask(nd_dimm);
	int i, rc;

	if (!nd_dimm || !test_bit(cmd, &dsm_mask))
		return -ENXIO;

	/* lookup label space for the given dimm */
	i = (long) nd_dimm_get_pdata(nd_dimm);

	switch (cmd) {
	case NFIT_CMD_GET_CONFIG_SIZE: {
		struct nfit_cmd_get_config_size *nfit_cmd = buf;

		if (buf_len < sizeof(*nfit_cmd))
			return -EINVAL;
		nfit_cmd->status = 0;
		nfit_cmd->config_size = LABEL_SIZE;
		nfit_cmd->max_xfer = SZ_4K;
		rc = 0;
		break;
	}
	case NFIT_CMD_GET_CONFIG_DATA: {
		struct nfit_cmd_get_config_data_hdr *nfit_cmd = buf;
		unsigned int len, offset = nfit_cmd->in_offset;

		if (buf_len < sizeof(*nfit_cmd))
			return -EINVAL;
		if (offset >= LABEL_SIZE)
			return -EINVAL;
		if (nfit_cmd->in_length + sizeof(*nfit_cmd) > buf_len)
			return -EINVAL;

		nfit_cmd->status = 0;
		len = min(nfit_cmd->in_length, LABEL_SIZE - offset);
		memcpy(nfit_cmd->out_buf, t->label[i] + offset, len);
		rc = buf_len - sizeof(*nfit_cmd) - len;
		break;
	}
	case NFIT_CMD_SET_CONFIG_DATA: {
		struct nfit_cmd_set_config_hdr *nfit_cmd = buf;
		unsigned int len, offset = nfit_cmd->in_offset;
		u32 *status;

		if (buf_len < sizeof(*nfit_cmd))
			return -EINVAL;
		if (offset >= LABEL_SIZE)
			return -EINVAL;
		if (nfit_cmd->in_length + sizeof(*nfit_cmd) + 4 > buf_len)
			return -EINVAL;

		status = buf + nfit_cmd->in_length + sizeof(*nfit_cmd);
		*status = 0;
		len = min(nfit_cmd->in_length, LABEL_SIZE - offset);
		memcpy(t->label[i] + offset, nfit_cmd->in_buf, len);
		rc = buf_len - sizeof(*nfit_cmd) - (len + 4);
		break;
	}
	default:
		return -ENOTTY;
	}

	return rc;
}

static DEFINE_SPINLOCK(nfit_test_lock);
static struct nfit_test *instances[NUM_NFITS];

static void *alloc_coherent(struct nfit_test *t, size_t size, dma_addr_t *dma)
{
	struct device *dev = &t->pdev.dev;
	struct resource *res = devm_kzalloc(dev, sizeof(*res) * 2, GFP_KERNEL);
	void *buf = dmam_alloc_coherent(dev, size, dma, GFP_KERNEL);
	struct nfit_test_resource *nfit_res = devm_kzalloc(dev,
			sizeof(*nfit_res), GFP_KERNEL);

	if (!res || !buf || !nfit_res)
		return NULL;
	INIT_LIST_HEAD(&nfit_res->list);
	memset(buf, 0, size);
	nfit_res->buf = buf;
	nfit_res->res = res;
	res->start = *dma;
	res->end = *dma + size - 1;
	res->name = "NFIT";
	spin_lock(&nfit_test_lock);
	list_add(&nfit_res->list, &t->resources);
	spin_unlock(&nfit_test_lock);

	return nfit_res->buf;
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
	size_t nfit_size = sizeof(struct nfit)
			+ sizeof(struct nfit_spa) * NUM_SPA
			+ sizeof(struct nfit_mem) * NUM_MEM
			+ sizeof(struct nfit_dcr) * NUM_DCR
			+ sizeof(struct nfit_bdw) * NUM_BDW;
	int i;

	t->nfit_buf = (void __iomem *) alloc_coherent(t, nfit_size,
			&t->nfit_dma);
	if (!t->nfit_buf)
		return -ENOMEM;
	t->nfit_size = nfit_size;

	t->spa_set[0] = alloc_coherent(t, SPA0_SIZE, &t->spa_set_dma[0]);
	if (!t->spa_set[0])
		return -ENOMEM;

	t->spa_set[1] = alloc_coherent(t, SPA1_SIZE, &t->spa_set_dma[1]);
	if (!t->spa_set[1])
		return -ENOMEM;

	for (i = 0; i < NUM_DCR; i++) {
		t->dimm[i] = alloc_coherent(t, DIMM_SIZE, &t->dimm_dma[i]);
		if (!t->dimm[i])
			return -ENOMEM;

		t->label[i] = alloc_coherent(t, LABEL_SIZE, &t->label_dma[i]);
		if (!t->label[i])
			return -ENOMEM;
		sprintf(t->label[i], "label%d", i);
	}

	for (i = 0; i < NUM_DCR; i++) {
		t->dcr[i] = alloc_coherent(t, LABEL_SIZE, &t->dcr_dma[i]);
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
	size_t nfit_size = sizeof(struct nfit) + sizeof(struct nfit_spa);

	t->nfit_buf = (void __iomem *) alloc_coherent(t, nfit_size,
			&t->nfit_dma);
	if (!t->nfit_buf)
		return -ENOMEM;
	t->nfit_size = nfit_size;

	t->spa_set[0] = alloc_coherent(t, SPA2_SIZE, &t->spa_set_dma[0]);
	if (!t->spa_set[0])
		return -ENOMEM;

	return 0;
}

static void nfit_test0_setup(struct nfit_test *t)
{
	struct nfit_bus_descriptor *nfit_desc;
	void __iomem *nfit_buf = t->nfit_buf;
	struct nfit_spa __iomem *nfit_spa;
	struct nfit_dcr __iomem *nfit_dcr;
	struct nfit_bdw __iomem *nfit_bdw;
	struct nfit_mem __iomem *nfit_mem;
	size_t size = t->nfit_size;
	struct nfit __iomem *nfit;
	unsigned int offset;

	/* nfit header */
	nfit = nfit_buf;
	memcpy_toio(nfit->signature, "NFIT", 4);
	writel(size, &nfit->length);
	writeb(1, &nfit->revision);
	memcpy_toio(nfit->oemid, "NDTEST", 6);
	writew(0x1234, &nfit->oem_tbl_id);
	writel(1, &nfit->oem_revision);
	writel(0xabcd0000, &nfit->creator_id);
	writel(1, &nfit->creator_revision);

	/*
	 * spa0 (interleave first half of dimm0 and dimm1, note storage
	 * does not actually alias the related block-data-window
	 * regions)
	 */
	nfit_spa = nfit_buf + sizeof(*nfit);
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_pm, 16);
	writew(0+1, &nfit_spa->spa_index);
	writeq(t->spa_set_dma[0], &nfit_spa->spa_base);
	writeq(SPA0_SIZE, &nfit_spa->spa_length);

	/*
	 * spa1 (interleave last half of the 4 DIMMS, note storage
	 * does not actually alias the related block-data-window
	 * regions)
	 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa);
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_pm, 16);
	writew(1+1, &nfit_spa->spa_index);
	writeq(t->spa_set_dma[1], &nfit_spa->spa_base);
	writeq(SPA1_SIZE, &nfit_spa->spa_length);

	/* spa2 (dcr0) dimm0 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 2;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	writew(2+1, &nfit_spa->spa_index);
	writeq(t->dcr_dma[0], &nfit_spa->spa_base);
	writeq(DCR_SIZE, &nfit_spa->spa_length);

	/* spa3 (dcr1) dimm1 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 3;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	writew(3+1, &nfit_spa->spa_index);
	writeq(t->dcr_dma[1], &nfit_spa->spa_base);
	writeq(DCR_SIZE, &nfit_spa->spa_length);

	/* spa4 (dcr2) dimm2 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 4;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	writew(4+1, &nfit_spa->spa_index);
	writeq(t->dcr_dma[2], &nfit_spa->spa_base);
	writeq(DCR_SIZE, &nfit_spa->spa_length);

	/* spa5 (dcr3) dimm3 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 5;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_dcr, 16);
	writew(5+1, &nfit_spa->spa_index);
	writeq(t->dcr_dma[3], &nfit_spa->spa_base);
	writeq(DCR_SIZE, &nfit_spa->spa_length);

	/* spa6 (bdw for dcr0) dimm0 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 6;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	writew(6+1, &nfit_spa->spa_index);
	writeq(t->dimm_dma[0], &nfit_spa->spa_base);
	writeq(DIMM_SIZE, &nfit_spa->spa_length);
	dev_dbg(&t->pdev.dev, "%s: BDW0: %#llx:%#x\n", __func__,
			(unsigned long long) t->dimm_dma[0], DIMM_SIZE);

	/* spa7 (bdw for dcr1) dimm1 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 7;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	writew(7+1, &nfit_spa->spa_index);
	writeq(t->dimm_dma[1], &nfit_spa->spa_base);
	writeq(DIMM_SIZE, &nfit_spa->spa_length);
	dev_dbg(&t->pdev.dev, "%s: BDW1: %#llx:%#x\n", __func__,
			(unsigned long long) t->dimm_dma[1], DIMM_SIZE);

	/* spa8 (bdw for dcr2) dimm2 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 8;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	writew(8+1, &nfit_spa->spa_index);
	writeq(t->dimm_dma[2], &nfit_spa->spa_base);
	writeq(DIMM_SIZE, &nfit_spa->spa_length);
	dev_dbg(&t->pdev.dev, "%s: BDW2: %#llx:%#x\n", __func__,
			(unsigned long long) t->dimm_dma[2], DIMM_SIZE);

	/* spa9 (bdw for dcr3) dimm3 */
	nfit_spa = nfit_buf + sizeof(*nfit) + sizeof(*nfit_spa) * 9;
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_bdw, 16);
	writew(9+1, &nfit_spa->spa_index);
	writeq(t->dimm_dma[3], &nfit_spa->spa_base);
	writeq(DIMM_SIZE, &nfit_spa->spa_length);
	dev_dbg(&t->pdev.dev, "%s: BDW3: %#llx:%#x\n", __func__,
			(unsigned long long) t->dimm_dma[3], DIMM_SIZE);

	offset = sizeof(*nfit) + sizeof(*nfit_spa) * 10;
	/* mem-region0 (spa0, dimm0) */
	nfit_mem = nfit_buf + offset;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[0], &nfit_mem->nfit_handle);
	writew(0, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(0+1, &nfit_mem->spa_index);
	writew(0+1, &nfit_mem->dcr_index);
	writeq(SPA0_SIZE/2, &nfit_mem->region_len);
	writeq(t->spa_set_dma[0], &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(2, &nfit_mem->interleave_ways);

	/* mem-region1 (spa0, dimm1) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem);
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[1], &nfit_mem->nfit_handle);
	writew(1, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(0+1, &nfit_mem->spa_index);
	writew(1+1, &nfit_mem->dcr_index);
	writeq(SPA0_SIZE/2, &nfit_mem->region_len);
	writeq(t->spa_set_dma[0] + SPA0_SIZE/2, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(2, &nfit_mem->interleave_ways);

	/* mem-region2 (spa1, dimm0) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 2;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[0], &nfit_mem->nfit_handle);
	writew(0, &nfit_mem->phys_id);
	writew(1, &nfit_mem->region_id);
	writew(1+1, &nfit_mem->spa_index);
	writew(0+1, &nfit_mem->dcr_index);
	writeq(SPA1_SIZE/4, &nfit_mem->region_len);
	writeq(t->spa_set_dma[1], &nfit_mem->region_spa_offset);
	writeq(SPA0_SIZE/2, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(4, &nfit_mem->interleave_ways);

	/* mem-region3 (spa1, dimm1) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 3;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[1], &nfit_mem->nfit_handle);
	writew(1, &nfit_mem->phys_id);
	writew(1, &nfit_mem->region_id);
	writew(1+1, &nfit_mem->spa_index);
	writew(1+1, &nfit_mem->dcr_index);
	writeq(SPA1_SIZE/4, &nfit_mem->region_len);
	writeq(t->spa_set_dma[1] + SPA1_SIZE/4, &nfit_mem->region_spa_offset);
	writeq(SPA0_SIZE/2, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(4, &nfit_mem->interleave_ways);

	/* mem-region4 (spa1, dimm2) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 4;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[2], &nfit_mem->nfit_handle);
	writew(2, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(1+1, &nfit_mem->spa_index);
	writew(2+1, &nfit_mem->dcr_index);
	writeq(SPA1_SIZE/4, &nfit_mem->region_len);
	writeq(t->spa_set_dma[1] + 2*SPA1_SIZE/4, &nfit_mem->region_spa_offset);
	writeq(SPA0_SIZE/2, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(4, &nfit_mem->interleave_ways);

	/* mem-region5 (spa1, dimm3) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 5;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[3], &nfit_mem->nfit_handle);
	writew(3, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(1+1, &nfit_mem->spa_index);
	writew(3+1, &nfit_mem->dcr_index);
	writeq(SPA1_SIZE/4, &nfit_mem->region_len);
	writeq(t->spa_set_dma[1] + 3*SPA1_SIZE/4, &nfit_mem->region_spa_offset);
	writeq(SPA0_SIZE/2, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(4, &nfit_mem->interleave_ways);

	/* mem-region6 (spa/dcr0, dimm0) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 6;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[0], &nfit_mem->nfit_handle);
	writew(0, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(2+1, &nfit_mem->spa_index);
	writew(0+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region7 (spa/dcr1, dimm1) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 7;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[1], &nfit_mem->nfit_handle);
	writew(1, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(3+1, &nfit_mem->spa_index);
	writew(1+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region8 (spa/dcr2, dimm2) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 8;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[2], &nfit_mem->nfit_handle);
	writew(2, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(4+1, &nfit_mem->spa_index);
	writew(2+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region9 (spa/dcr3, dimm3) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 9;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[3], &nfit_mem->nfit_handle);
	writew(3, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(5+1, &nfit_mem->spa_index);
	writew(3+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region10 (spa/bdw0, dimm0) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 10;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[0], &nfit_mem->nfit_handle);
	writew(0, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(6+1, &nfit_mem->spa_index);
	writew(0+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region11 (spa/bdw1, dimm1) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 11;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[1], &nfit_mem->nfit_handle);
	writew(1, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(7+1, &nfit_mem->spa_index);
	writew(1+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region12 (spa/bdw2, dimm2) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 12;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[2], &nfit_mem->nfit_handle);
	writew(2, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(8+1, &nfit_mem->spa_index);
	writew(2+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	/* mem-region13 (spa/dcr3, dimm3) */
	nfit_mem = nfit_buf + offset + sizeof(struct nfit_mem) * 13;
	writew(NFIT_TABLE_MEM, &nfit_mem->type);
	writew(sizeof(*nfit_mem), &nfit_mem->length);
	writel(handle[3], &nfit_mem->nfit_handle);
	writew(3, &nfit_mem->phys_id);
	writew(0, &nfit_mem->region_id);
	writew(9+1, &nfit_mem->spa_index);
	writew(3+1, &nfit_mem->dcr_index);
	writeq(0, &nfit_mem->region_len);
	writeq(0, &nfit_mem->region_spa_offset);
	writeq(0, &nfit_mem->region_dpa);
	writew(0, &nfit_mem->idt_index);
	writew(1, &nfit_mem->interleave_ways);

	offset = offset + sizeof(struct nfit_mem) * 14;
	/* dcr-descriptor0 */
	nfit_dcr = nfit_buf + offset;
	writew(NFIT_TABLE_DCR, &nfit_dcr->type);
	writew(sizeof(struct nfit_dcr), &nfit_dcr->length);
	writew(0+1, &nfit_dcr->dcr_index);
	writew(0xabcd, &nfit_dcr->vendor_id);
	writew(0, &nfit_dcr->device_id);
	writew(1, &nfit_dcr->revision_id);
	writel(~handle[0], &nfit_dcr->serial_number);
	writew(1, &nfit_dcr->num_bcw);
	writeq(DCR_SIZE, &nfit_dcr->bcw_size);
	writeq(0, &nfit_dcr->cmd_offset);
	writeq(8, &nfit_dcr->cmd_size);
	writeq(8, &nfit_dcr->status_offset);
	writeq(4, &nfit_dcr->status_size);

	/* dcr-descriptor1 */
	nfit_dcr = nfit_buf + offset + sizeof(struct nfit_dcr);
	writew(NFIT_TABLE_DCR, &nfit_dcr->type);
	writew(sizeof(struct nfit_dcr), &nfit_dcr->length);
	writew(1+1, &nfit_dcr->dcr_index);
	writew(0xabcd, &nfit_dcr->vendor_id);
	writew(0, &nfit_dcr->device_id);
	writew(1, &nfit_dcr->revision_id);
	writel(~handle[1], &nfit_dcr->serial_number);
	writew(1, &nfit_dcr->num_bcw);
	writeq(DCR_SIZE, &nfit_dcr->bcw_size);
	writeq(0, &nfit_dcr->cmd_offset);
	writeq(8, &nfit_dcr->cmd_size);
	writeq(8, &nfit_dcr->status_offset);
	writeq(4, &nfit_dcr->status_size);

	/* dcr-descriptor2 */
	nfit_dcr = nfit_buf + offset + sizeof(struct nfit_dcr) * 2;
	writew(NFIT_TABLE_DCR, &nfit_dcr->type);
	writew(sizeof(struct nfit_dcr), &nfit_dcr->length);
	writew(2+1, &nfit_dcr->dcr_index);
	writew(0xabcd, &nfit_dcr->vendor_id);
	writew(0, &nfit_dcr->device_id);
	writew(1, &nfit_dcr->revision_id);
	writel(~handle[2], &nfit_dcr->serial_number);
	writew(1, &nfit_dcr->num_bcw);
	writeq(DCR_SIZE, &nfit_dcr->bcw_size);
	writeq(0, &nfit_dcr->cmd_offset);
	writeq(8, &nfit_dcr->cmd_size);
	writeq(8, &nfit_dcr->status_offset);
	writeq(4, &nfit_dcr->status_size);

	/* dcr-descriptor3 */
	nfit_dcr = nfit_buf + offset + sizeof(struct nfit_dcr) * 3;
	writew(NFIT_TABLE_DCR, &nfit_dcr->type);
	writew(sizeof(struct nfit_dcr), &nfit_dcr->length);
	writew(3+1, &nfit_dcr->dcr_index);
	writew(0xabcd, &nfit_dcr->vendor_id);
	writew(0, &nfit_dcr->device_id);
	writew(1, &nfit_dcr->revision_id);
	writel(~handle[3], &nfit_dcr->serial_number);
	writew(1, &nfit_dcr->num_bcw);
	writeq(DCR_SIZE, &nfit_dcr->bcw_size);
	writeq(0, &nfit_dcr->cmd_offset);
	writeq(8, &nfit_dcr->cmd_size);
	writeq(8, &nfit_dcr->status_offset);
	writeq(4, &nfit_dcr->status_size);

	offset = offset + sizeof(struct nfit_dcr) * 4;
	/* bdw0 (spa/dcr0, dimm0) */
	nfit_bdw = nfit_buf + offset;
	writew(NFIT_TABLE_BDW, &nfit_bdw->type);
	writew(sizeof(struct nfit_bdw), &nfit_bdw->length);
	writew(0+1, &nfit_bdw->dcr_index);
	writew(1, &nfit_bdw->num_bdw);
	writeq(0, &nfit_bdw->bdw_offset);
	writeq(BDW_SIZE, &nfit_bdw->bdw_size);
	writeq(DIMM_SIZE, &nfit_bdw->blk_capacity);
	writeq(0, &nfit_bdw->blk_offset);

	/* bdw1 (spa/dcr1, dimm1) */
	nfit_bdw = nfit_buf + offset + sizeof(struct nfit_bdw);
	writew(NFIT_TABLE_BDW, &nfit_bdw->type);
	writew(sizeof(struct nfit_bdw), &nfit_bdw->length);
	writew(1+1, &nfit_bdw->dcr_index);
	writew(1, &nfit_bdw->num_bdw);
	writeq(0, &nfit_bdw->bdw_offset);
	writeq(BDW_SIZE, &nfit_bdw->bdw_size);
	writeq(DIMM_SIZE, &nfit_bdw->blk_capacity);
	writeq(0, &nfit_bdw->blk_offset);

	/* bdw2 (spa/dcr2, dimm2) */
	nfit_bdw = nfit_buf + offset + sizeof(struct nfit_bdw) * 2;
	writew(NFIT_TABLE_BDW, &nfit_bdw->type);
	writew(sizeof(struct nfit_bdw), &nfit_bdw->length);
	writew(2+1, &nfit_bdw->dcr_index);
	writew(1, &nfit_bdw->num_bdw);
	writeq(0, &nfit_bdw->bdw_offset);
	writeq(BDW_SIZE, &nfit_bdw->bdw_size);
	writeq(DIMM_SIZE, &nfit_bdw->blk_capacity);
	writeq(0, &nfit_bdw->blk_offset);

	/* bdw3 (spa/dcr3, dimm3) */
	nfit_bdw = nfit_buf + offset + sizeof(struct nfit_bdw) * 3;
	writew(NFIT_TABLE_BDW, &nfit_bdw->type);
	writew(sizeof(struct nfit_bdw), &nfit_bdw->length);
	writew(3+1, &nfit_bdw->dcr_index);
	writew(1, &nfit_bdw->num_bdw);
	writeq(0, &nfit_bdw->bdw_offset);
	writeq(BDW_SIZE, &nfit_bdw->bdw_size);
	writeq(DIMM_SIZE, &nfit_bdw->blk_capacity);
	writeq(0, &nfit_bdw->blk_offset);

	writeb(nfit_checksum(nfit_buf, size), &nfit->checksum);

	nfit_desc = &t->nfit_desc;
	nfit_desc->nfit_ctl = nfit_test_ctl;
	nfit_desc->add_dimm = nfit_test_add_dimm;
}

static void nfit_test1_setup(struct nfit_test *t)
{
	void __iomem *nfit_buf = t->nfit_buf;
	struct nfit_spa __iomem *nfit_spa;
	size_t size = t->nfit_size;
	struct nfit __iomem *nfit;

	/* nfit header */
	nfit = nfit_buf;
	memcpy_toio(nfit->signature, "NFIT", 4);
	writel(size, &nfit->length);
	writeb(1, &nfit->revision);
	memcpy_toio(nfit->oemid, "NDTEST", 6);
	writew(0x1234, &nfit->oem_tbl_id);
	writel(1, &nfit->oem_revision);
	writel(0xabcd0000, &nfit->creator_id);
	writel(1, &nfit->creator_revision);

	/* spa0 (flat range with no bdw aliasing) */
	nfit_spa = nfit_buf + sizeof(*nfit);
	writew(NFIT_TABLE_SPA, &nfit_spa->type);
	writew(sizeof(*nfit_spa), &nfit_spa->length);
	memcpy_toio(&nfit_spa->type_uuid, &nfit_spa_uuid_pm, 16);
	writew(0+1, &nfit_spa->spa_index);
	writeq(t->spa_set_dma[0], &nfit_spa->spa_base);
	writeq(SPA2_SIZE, &nfit_spa->spa_length);

	writeb(nfit_checksum(nfit_buf, size), &nfit->checksum);
}

static int nfit_test_probe(struct platform_device *pdev)
{
	struct nfit_bus_descriptor *nfit_desc;
	struct device *dev = &pdev->dev;
	struct nfit_test *nfit_test;
	int rc;

	nfit_test = to_nfit_test(&pdev->dev);
	rc = dma_coerce_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (rc)
		return rc;

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

	nfit_desc = &nfit_test->nfit_desc;
	nfit_desc->nfit_base = nfit_test->nfit_buf;
	nfit_desc->nfit_size = nfit_test->nfit_size;

	nfit_test->nd_bus = nfit_bus_register(&pdev->dev, nfit_desc);
	if (!nfit_test->nd_bus)
		return -EINVAL;

	return 0;
}

static int nfit_test_remove(struct platform_device *pdev)
{
	struct nfit_test *nfit_test = to_nfit_test(&pdev->dev);

	nfit_bus_unregister(nfit_test->nd_bus);

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

	if (CMA_SIZE_MBYTES < 584) {
		pr_err("need CONFIG_CMA_SIZE_MBYTES >= 584 to load\n");
		return -EINVAL;
	}

	nfit_test_setup(nfit_test_lookup);

	for (i = 0; i < NUM_NFITS; i++) {
		struct nfit_test *nfit_test;
		struct platform_device *pdev;

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
		instances[i] = nfit_test;
	}

	rc = platform_driver_register(&nfit_test_driver);
	if (rc)
		goto err_register;
	return 0;

 err_register:
	for (i = 0; i < NUM_NFITS; i++)
		if (instances[i])
			platform_device_unregister(&instances[i]->pdev);
	return rc;
}

static __exit void nfit_test_exit(void)
{
	int i;

	nfit_test_teardown();
	for (i = 0; i < NUM_NFITS; i++)
		platform_device_unregister(&instances[i]->pdev);
	platform_driver_unregister(&nfit_test_driver);
}

module_init(nfit_test_init);
module_exit(nfit_test_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
