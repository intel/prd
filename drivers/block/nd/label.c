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
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/nd.h>
#include "nd-private.h"
#include "label.h"
#include "nd.h"

#include <asm-generic/io-64-nonatomic-lo-hi.h>

static u32 best_seq(u32 a, u32 b)
{
	a &= NSINDEX_SEQ_MASK;
	b &= NSINDEX_SEQ_MASK;

	if (a == 0 || a == b)
		return b;
	else if (b == 0)
		return a;
	else if (nd_inc_seq(a) == b)
		return b;
	else
		return a;
}

size_t sizeof_namespace_index(struct nd_dimm_drvdata *ndd)
{
	u32 index_span;

	if (ndd->nsindex_size)
		return ndd->nsindex_size;

	/*
	 * The minimum index space is 512 bytes, with that amount of
	 * index we can describe ~1400 labels which is less than a byte
	 * of overhead per label.  Round up to a byte of overhead per
	 * label and determine the size of the index region.  Yes, this
	 * starts to waste space at larger config_sizes, but it's
	 * unlikely we'll ever see anything but 128K.
	 */
	index_span = ndd->nsarea.config_size / 129;
	index_span /= NSINDEX_ALIGN * 2;
	ndd->nsindex_size = index_span * NSINDEX_ALIGN;

	return ndd->nsindex_size;
}

int nd_dimm_num_label_slots(struct nd_dimm_drvdata *ndd)
{
	return ndd->nsarea.config_size / 129;
}

int nd_label_validate(struct nd_dimm_drvdata *ndd)
{
	/*
	 * On media label format consists of two index blocks followed
	 * by an array of labels.  None of these structures are ever
	 * updated in place.  A sequence number tracks the current
	 * active index and the next one to write, while labels are
	 * written to free slots.
	 *
	 *     +------------+
	 *     |            |
	 *     |  nsindex0  |
	 *     |            |
	 *     +------------+
	 *     |            |
	 *     |  nsindex1  |
	 *     |            |
	 *     +------------+
	 *     |   label0   |
	 *     +------------+
	 *     |   label1   |
	 *     +------------+
	 *     |            |
	 *      ....nslot...
	 *     |            |
	 *     +------------+
	 *     |   labelN   |
	 *     +------------+
	 */
	struct nd_namespace_index __iomem *nsindex[] = {
		to_namespace_index(ndd, 0),
		to_namespace_index(ndd, 1),
	};
	const int num_index = ARRAY_SIZE(nsindex);
	struct device *dev = ndd->dev;
	bool valid[] = { false, false };
	int i, num_valid = 0;
	u32 seq;

	for (i = 0; i < num_index; i++) {
		u64 sum_save, sum;
		u8 sig[NSINDEX_SIG_LEN];

		memcpy_fromio(sig, nsindex[i]->sig, NSINDEX_SIG_LEN);
		if (memcmp(sig, NSINDEX_SIGNATURE, NSINDEX_SIG_LEN) != 0) {
			dev_dbg(dev, "%s: nsindex%d signature invalid\n",
					__func__, i);
			continue;
		}
		sum_save = readq(&nsindex[i]->checksum);
		writeq(0, &nsindex[i]->checksum);
		sum = nd_fletcher64(nsindex[i], sizeof_namespace_index(ndd));
		writeq(sum_save, &nsindex[i]->checksum);
		if (sum != sum_save) {
			dev_dbg(dev, "%s: nsindex%d checksum invalid\n",
					__func__, i);
			continue;
		}
		if ((readl(&nsindex[i]->seq) & NSINDEX_SEQ_MASK) == 0) {
			dev_dbg(dev, "%s: nsindex%d sequence: %#x invalid\n",
					__func__, i, readl(&nsindex[i]->seq));
			continue;
		}

		/* sanity check the index against expected values */
		if (readq(&nsindex[i]->myoff)
				!= i * sizeof_namespace_index(ndd)) {
			dev_dbg(dev, "%s: nsindex%d myoff: %#llx invalid\n",
					__func__, i, (unsigned long long)
					readq(&nsindex[i]->myoff));
			continue;
		}
		if (readq(&nsindex[i]->otheroff)
				!= (!i) * sizeof_namespace_index(ndd)) {
			dev_dbg(dev, "%s: nsindex%d otheroff: %#llx invalid\n",
					__func__, i, (unsigned long long)
					readq(&nsindex[i]->otheroff));
			continue;
		}
		if (readq(&nsindex[i]->mysize) > sizeof_namespace_index(ndd)
				|| readq(&nsindex[i]->mysize)
				< sizeof(struct nd_namespace_index)) {
			dev_dbg(dev, "%s: nsindex%d mysize: %#llx invalid\n",
					__func__, i, (unsigned long long)
					readq(&nsindex[i]->mysize));
			continue;
		}
		if (readl(&nsindex[i]->nslot) * sizeof(struct nd_namespace_label)
				+ 2 * sizeof_namespace_index(ndd)
				> ndd->nsarea.config_size) {
			dev_dbg(dev, "%s: nsindex%d nslot: %u invalid, config_size: %#x\n",
					__func__, i, readl(&nsindex[i]->nslot),
					ndd->nsarea.config_size);
			continue;
		}
		valid[i] = true;
		num_valid++;
	}

	switch (num_valid) {
	case 0:
		break;
	case 1:
		for (i = 0; i < num_index; i++)
			if (valid[i])
				return i;
		/* can't have num_valid > 0 but valid[] = { false, false } */
		WARN_ON(1);
		break;
	default:
		/* pick the best index... */
		seq = best_seq(readl(&nsindex[0]->seq), readl(&nsindex[1]->seq));
		if (seq == (readl(&nsindex[1]->seq) & NSINDEX_SEQ_MASK))
			return 1;
		else
			return 0;
		break;
	}

	return -1;
}

void nd_label_copy(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_index __iomem *dst,
		struct nd_namespace_index __iomem *src)
{
	void *s, *d;

	if (dst && src)
		/* pass */;
	else
		return;

	d = (void * __force) dst;
	s = (void * __force) src;
	memcpy(d, s, sizeof_namespace_index(ndd));
}

static struct nd_namespace_label __iomem *nd_label_base(struct nd_dimm_drvdata *ndd)
{
	void *base = to_namespace_index(ndd, 0);

	return base + 2 * sizeof_namespace_index(ndd);
}

static int to_slot(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_label __iomem *nd_label)
{
	return nd_label - nd_label_base(ndd);
}

#define for_each_clear_bit_le(bit, addr, size) \
	for ((bit) = find_next_zero_bit_le((addr), (size), 0);  \
	     (bit) < (size);                                    \
	     (bit) = find_next_zero_bit_le((addr), (size), (bit) + 1))

/**
 * preamble_index - common variable initialization for nd_label_* routines
 * @nd_dimm: dimm container for the relevant label set
 * @idx: namespace_index index
 * @nsindex: on return set to the currently active namespace index
 * @free: on return set to the free label bitmap in the index
 * @nslot: on return set to the number of slots in the label space
 */
static bool preamble_index(struct nd_dimm_drvdata *ndd, int idx,
		struct nd_namespace_index **nsindex,
		unsigned long **free, u32 *nslot)
{
	*nsindex = to_namespace_index(ndd, idx);
	if (*nsindex == NULL)
		return false;

	*free = (unsigned long __force *) (*nsindex)->free;
	*nslot = readl(&(*nsindex)->nslot);

	return true;
}

char *nd_label_gen_id(struct nd_label_id *label_id, u8 *uuid, u32 flags)
{
	if (!label_id || !uuid)
		return NULL;
	snprintf(label_id->id, ND_LABEL_ID_SIZE, "%s-%pUb",
			flags & NSLABEL_FLAG_LOCAL ? "blk" : "pmem", uuid);
	return label_id->id;
}

static bool preamble_current(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_index **nsindex,
		unsigned long **free, u32 *nslot)
{
	return preamble_index(ndd, ndd->ns_current, nsindex,
			free, nslot);
}

static bool preamble_next(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_index **nsindex,
		unsigned long **free, u32 *nslot)
{
	return preamble_index(ndd, ndd->ns_next, nsindex,
			free, nslot);
}

static bool slot_valid(struct nd_namespace_label __iomem *nd_label, u32 slot)
{
	/* check that we are written where we expect to be written */
	if (slot != readl(&nd_label->slot))
		return false;

	/* check that DPA allocations are page aligned */
	if ((readq(&nd_label->dpa) | readq(&nd_label->rawsize)) % SZ_4K)
		return false;

	return true;
}

int nd_label_reserve_dpa(struct nd_dimm_drvdata *ndd)
{
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot, slot;

	if (!preamble_current(ndd, &nsindex, &free, &nslot))
		return 0; /* no label, nothing to reserve */

	for_each_clear_bit_le(slot, free, nslot) {
		struct nd_namespace_label __iomem *nd_label;
		struct nd_region *nd_region = NULL;
		u8 label_uuid[NSLABEL_UUID_LEN];
		struct nd_label_id *label_id;
		struct resource *res;
		u32 flags;

		nd_label = nd_label_base(ndd) + slot;

		if (!slot_valid(nd_label, slot))
			continue;

		label_id = devm_kzalloc(ndd->dev, sizeof(*label_id),
				GFP_KERNEL);
		if (!label_id)
			return -ENOMEM;
		memcpy_fromio(label_uuid, nd_label->uuid,
				NSLABEL_UUID_LEN);
		flags = readl(&nd_label->flags);
		res = __request_region(&ndd->dpa, readq(&nd_label->dpa),
				readq(&nd_label->rawsize),
				nd_label_gen_id(label_id, label_uuid, flags), 0);
		nd_dbg_dpa(nd_region, ndd, res, "reserve\n");
		if (!res)
			return -EBUSY;
	}

	return 0;
}

int nd_label_active_count(struct nd_dimm_drvdata *ndd)
{
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot, slot;
	int count = 0;

	if (!preamble_current(ndd, &nsindex, &free, &nslot))
		return 0;

	for_each_clear_bit_le(slot, free, nslot) {
		struct nd_namespace_label __iomem *nd_label;

		nd_label = nd_label_base(ndd) + slot;

		if (!slot_valid(nd_label, slot)) {
			dev_dbg(ndd->dev,
				"%s: slot%d invalid slot: %d dpa: %lx rawsize: %lx\n",
					__func__, slot, readl(&nd_label->slot),
					(unsigned long) readq(&nd_label->dpa),
					(unsigned long) readq(&nd_label->rawsize));
			continue;
		}
		count++;
	}
	return count;
}

struct nd_namespace_label __iomem *nd_label_active(
		struct nd_dimm_drvdata *ndd, int n)
{
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot, slot;

	if (!preamble_current(ndd, &nsindex, &free, &nslot))
		return NULL;

	for_each_clear_bit_le(slot, free, nslot) {
		struct nd_namespace_label __iomem *nd_label;

		nd_label = nd_label_base(ndd) + slot;
		if (slot != readl(&nd_label->slot))
			continue;

		if (n-- == 0)
			return nd_label_base(ndd) + slot;
	}

	return NULL;
}

u32 nd_label_alloc_slot(struct nd_dimm_drvdata *ndd)
{
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot, slot;

	if (!preamble_next(ndd, &nsindex, &free, &nslot))
		return UINT_MAX;

	WARN_ON(!is_nd_bus_locked(ndd->dev));

	slot = find_next_bit_le(free, nslot, 0);
	if (slot == nslot)
		return UINT_MAX;

	clear_bit_le(slot, free);

	return slot;
}

bool nd_label_free_slot(struct nd_dimm_drvdata *ndd, u32 slot)
{
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot;

	if (!preamble_next(ndd, &nsindex, &free, &nslot))
		return false;

	WARN_ON(!is_nd_bus_locked(ndd->dev));

	if (slot < nslot)
		return !test_and_set_bit_le(slot, free);
	return false;
}

u32 nd_label_nfree(struct nd_dimm_drvdata *ndd)
{
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot;

	WARN_ON(!is_nd_bus_locked(ndd->dev));

	if (!preamble_next(ndd, &nsindex, &free, &nslot))
		return nd_dimm_num_label_slots(ndd);

	return bitmap_weight(free, nslot);
}

static int nd_label_write_index(struct nd_dimm_drvdata *ndd, int index, u32 seq,
		unsigned long flags)
{
	struct nd_namespace_index *nsindex = to_namespace_index(ndd, index);
	unsigned long offset;
	u64 checksum;
	u32 nslot;
	int rc;

	if (flags & ND_NSINDEX_INIT)
		nslot = nd_dimm_num_label_slots(ndd);
	else
		nslot = readl(&nsindex->nslot);

	memcpy_toio(nsindex->sig, NSINDEX_SIGNATURE, NSINDEX_SIG_LEN);
	writel(0, &nsindex->flags);
	writel(seq, &nsindex->seq);
	offset = (unsigned long) nsindex
		- (unsigned long) to_namespace_index(ndd, 0);
	writeq(offset, &nsindex->myoff);
	writeq(sizeof_namespace_index(ndd), &nsindex->mysize);
	offset = (unsigned long) to_namespace_index(ndd,
			nd_label_next_nsindex(index))
		- (unsigned long) to_namespace_index(ndd, 0);
	writeq(offset, &nsindex->otheroff);
	offset = (unsigned long) nd_label_base(ndd)
		- (unsigned long) to_namespace_index(ndd, 0);
	writeq(offset, &nsindex->labeloff);
	writel(nslot, &nsindex->nslot);
	writew(1, &nsindex->major);
	writew(1, &nsindex->minor);
	writeq(0, &nsindex->checksum);
	if (flags & ND_NSINDEX_INIT) {
		unsigned long *free = (unsigned long __force *) nsindex->free;
		u32 nfree = ALIGN(nslot, BITS_PER_LONG);
		int last_bits, i;

		memset_io(nsindex->free, 0xff, nfree / 8);
		for (i = 0, last_bits = nfree - nslot; i < last_bits; i++)
			clear_bit_le(nslot + i, free);
	}
	checksum = nd_fletcher64(nsindex, sizeof_namespace_index(ndd));
	writeq(checksum, &nsindex->checksum);
	rc = nd_dimm_set_config_data(ndd, readq(&nsindex->myoff),
			nsindex, sizeof_namespace_index(ndd));
	if (rc < 0)
		return rc;

	if (flags & ND_NSINDEX_INIT)
		return 0;

	/* copy the index we just wrote to the new 'next' */
	WARN_ON(index != ndd->ns_next);
	nd_label_copy(ndd, to_current_namespace_index(ndd), nsindex);
	ndd->ns_current = nd_label_next_nsindex(ndd->ns_current);
	ndd->ns_next = nd_label_next_nsindex(ndd->ns_next);
	WARN_ON(ndd->ns_current == ndd->ns_next);

	return 0;
}

static unsigned long nd_label_offset(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_label __iomem *nd_label)
{
	return (unsigned long) nd_label
		- (unsigned long) to_namespace_index(ndd, 0);
}

static int __pmem_label_update(struct nd_region *nd_region,
		struct nd_mapping *nd_mapping, struct nd_namespace_pmem *nspm,
		int pos)
{
	u64 cookie = nd_region_interleave_set_cookie(nd_region), rawsize;
	struct nd_dimm_drvdata *ndd = to_ndd(nd_mapping);
	struct nd_namespace_label __iomem *victim_label;
	struct nd_namespace_label __iomem *nd_label;
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free;
	u32 nslot, slot;
	size_t offset;
	int rc;

	if (!preamble_next(ndd, &nsindex, &free, &nslot))
		return -ENXIO;

	/* allocate and write the label to the staging (next) index */
	slot = nd_label_alloc_slot(ndd);
	if (slot == UINT_MAX)
		return -ENXIO;
	dev_dbg(ndd->dev, "%s: allocated: %d\n", __func__, slot);

	nd_label = nd_label_base(ndd) + slot;
	memset_io(nd_label, 0, sizeof(struct nd_namespace_label));
	memcpy_toio(nd_label->uuid, nspm->uuid, NSLABEL_UUID_LEN);
	if (nspm->alt_name)
		memcpy_toio(nd_label->name, nspm->alt_name, NSLABEL_NAME_LEN);
	writel(NSLABEL_FLAG_UPDATING, &nd_label->flags);
	writew(nd_region->ndr_mappings, &nd_label->nlabel);
	writew(pos, &nd_label->position);
	writeq(cookie, &nd_label->isetcookie);
	rawsize = div_u64(resource_size(&nspm->nsio.res),
			nd_region->ndr_mappings);
	writeq(rawsize, &nd_label->rawsize);
	writeq(nd_mapping->start, &nd_label->dpa);
	writel(slot, &nd_label->slot);

	/* update label */
	offset = nd_label_offset(ndd, nd_label);
	rc = nd_dimm_set_config_data(ndd, offset, nd_label,
			sizeof(struct nd_namespace_label));
	if (rc < 0)
		return rc;

	/* Garbage collect the previous label */
	victim_label = nd_get_label(nd_mapping->labels, 0);
	if (victim_label) {
		slot = to_slot(ndd, victim_label);
		nd_label_free_slot(ndd, slot);
		dev_dbg(ndd->dev, "%s: free: %d\n", __func__, slot);
	}

	/* update index */
	rc = nd_label_write_index(ndd, ndd->ns_next,
			nd_inc_seq(readl(&nsindex->seq)), 0);
	if (rc < 0)
		return rc;

	nd_set_label(nd_mapping->labels, nd_label, 0);

	return 0;
}

static void del_label(struct nd_mapping *nd_mapping, int l)
{
	struct nd_namespace_label __iomem *next_label, __iomem *nd_label;
	struct nd_dimm_drvdata *ndd = to_ndd(nd_mapping);
	unsigned int slot;
	int j;

	nd_label = nd_get_label(nd_mapping->labels, l);
	slot = to_slot(ndd, nd_label);
	dev_vdbg(ndd->dev, "%s: clear: %d\n", __func__, slot);

	for (j = l; (next_label = nd_get_label(nd_mapping->labels, j + 1)); j++)
		nd_set_label(nd_mapping->labels, next_label, j);
	nd_set_label(nd_mapping->labels, NULL, j);
}

static bool is_old_resource(struct resource *res, struct resource **list, int n)
{
	int i;

	if (res->flags & DPA_RESOURCE_ADJUSTED)
		return false;
	for (i = 0; i < n; i++)
		if (res == list[i])
			return true;
	return false;
}

static struct resource *to_resource(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_label __iomem *nd_label)
{
	struct resource *res;

	for_each_dpa_resource(ndd, res) {
		if (res->start != readq(&nd_label->dpa))
			continue;
		if (resource_size(res) != readq(&nd_label->rawsize))
			continue;
		return res;
	}

	return NULL;
}

/*
 * 1/ Account all the labels that can be freed after this update
 * 2/ Allocate and write the label to the staging (next) index
 * 3/ Record the resources in the namespace device
 */
static int __blk_label_update(struct nd_region *nd_region,
		struct nd_mapping *nd_mapping, struct nd_namespace_blk *nsblk,
		int num_labels)
{
	int i, l, alloc, victims, nfree, old_num_resources, nlabel, rc = -ENXIO;
	struct nd_dimm_drvdata *ndd = to_ndd(nd_mapping);
	struct nd_namespace_label __iomem *nd_label;
	struct nd_namespace_index __iomem *nsindex;
	unsigned long *free, *victim_map = NULL;
	struct resource *res, **old_res_list;
	struct nd_label_id label_id;
	u8 uuid[NSLABEL_UUID_LEN];
	u32 nslot, slot;

	if (!preamble_next(ndd, &nsindex, &free, &nslot))
		return -ENXIO;

	old_res_list = nsblk->res;
	nfree = nd_label_nfree(ndd);
	old_num_resources = nsblk->num_resources;
	nd_label_gen_id(&label_id, nsblk->uuid, NSLABEL_FLAG_LOCAL);

	/*
	 * We need to loop over the old resources a few times, which seems a
	 * bit inefficient, but we need to know that we have the label
	 * space before we start mutating the tracking structures.
	 * Otherwise the recovery method of last resort for userspace is
	 * disable and re-enable the parent region.
	 */
	alloc = 0;
	for_each_dpa_resource(ndd, res) {
		if (strcmp(res->name, label_id.id) != 0)
			continue;
		if (!is_old_resource(res, old_res_list, old_num_resources))
			alloc++;
	}

	victims = 0;
	if (old_num_resources) {
		/* convert old local-label-map to dimm-slot victim-map */
		victim_map = kcalloc(BITS_TO_LONGS(nslot), sizeof(long),
				GFP_KERNEL);
		if (!victim_map)
			return -ENOMEM;

		/* mark unused labels for garbage collection */
		for_each_clear_bit_le(slot, free, nslot) {
			nd_label = nd_label_base(ndd) + slot;
			memcpy_fromio(uuid, nd_label->uuid, NSLABEL_UUID_LEN);
			if (memcmp(uuid, nsblk->uuid, NSLABEL_UUID_LEN) != 0)
				continue;
			res = to_resource(ndd, nd_label);
			if (res && is_old_resource(res, old_res_list,
						old_num_resources))
				continue;
			slot = to_slot(ndd, nd_label);
			set_bit(slot, victim_map);
			victims++;
		}
	}

	/* don't allow updates that consume the last label */
	if (nfree - alloc < 0 || nfree - alloc + victims < 1) {
		dev_info(&nsblk->dev, "insufficient label space\n");
		kfree(victim_map);
		return -ENOSPC;
	}
	/* from here on we need to abort on error */


	/* assign all resources to the namespace before writing the labels */
	nsblk->res = NULL;
	nsblk->num_resources = 0;
	for_each_dpa_resource(ndd, res) {
		if (strcmp(res->name, label_id.id) != 0)
			continue;
		if (!nsblk_add_resource(nd_region, ndd, nsblk, res->start)) {
			rc = -ENOMEM;
			goto abort;
		}
	}

	for (i = 0; i < nsblk->num_resources; i++) {
		size_t offset;

		res = nsblk->res[i];
		if (is_old_resource(res, old_res_list, old_num_resources))
			continue; /* carry-over */
		slot = nd_label_alloc_slot(ndd);
		if (slot == UINT_MAX)
			goto abort;
		dev_dbg(ndd->dev, "%s: allocated: %d\n", __func__, slot);

		nd_label = nd_label_base(ndd) + slot;
		memset_io(nd_label, 0, sizeof(struct nd_namespace_label));
		memcpy_toio(nd_label->uuid, nsblk->uuid, NSLABEL_UUID_LEN);
		if (nsblk->alt_name)
			memcpy_toio(nd_label->name, nsblk->alt_name,
					NSLABEL_NAME_LEN);
		writel(NSLABEL_FLAG_LOCAL, &nd_label->flags);
		writew(0, &nd_label->nlabel); /* N/A */
		writew(0, &nd_label->position); /* N/A */
		writeq(0, &nd_label->isetcookie); /* N/A */
		writeq(res->start, &nd_label->dpa);
		writeq(resource_size(res), &nd_label->rawsize);
		writeq(nsblk->lbasize, &nd_label->lbasize);
		writel(slot, &nd_label->slot);

		/* update label */
		offset = nd_label_offset(ndd, nd_label);
		rc = nd_dimm_set_config_data(ndd, offset, nd_label,
				sizeof(struct nd_namespace_label));
		if (rc < 0)
			goto abort;
	}

	/* free up now unused slots in the new index */
	for_each_set_bit(slot, victim_map, victim_map ? nslot : 0) {
		dev_dbg(ndd->dev, "%s: free: %d\n", __func__, slot);
		nd_label_free_slot(ndd, slot);
	}

	/* update index */
	rc = nd_label_write_index(ndd, ndd->ns_next,
			nd_inc_seq(readl(&nsindex->seq)), 0);
	if (rc)
		goto abort;

	/*
	 * Now that the on-dimm labels are up to date, fix up the tracking
	 * entries in nd_mapping->labels
	 */
	nlabel = 0;
	for_each_label(l, nd_label, nd_mapping->labels) {
		nlabel++;
		memcpy_fromio(uuid, nd_label->uuid, NSLABEL_UUID_LEN);
		if (memcmp(uuid, nsblk->uuid, NSLABEL_UUID_LEN) != 0)
			continue;
		nlabel--;
		del_label(nd_mapping, l);
		l--; /* retry with the new label at this index */
	}
	if (nlabel + nsblk->num_resources > num_labels) {
		/*
		 * Bug, we can't end up with more resources than
		 * available labels
		 */
		WARN_ON_ONCE(1);
		rc = -ENXIO;
		goto out;
	}

	for_each_clear_bit_le(slot, free, nslot) {
		nd_label = nd_label_base(ndd) + slot;
		memcpy_fromio(uuid, nd_label->uuid, NSLABEL_UUID_LEN);
		if (memcmp(uuid, nsblk->uuid, NSLABEL_UUID_LEN) != 0)
			continue;
		res = to_resource(ndd, nd_label);
		res->flags &= ~DPA_RESOURCE_ADJUSTED;
		dev_vdbg(&nsblk->dev, "assign label[%d] slot: %d\n", l, slot);
		nd_set_label(nd_mapping->labels, nd_label, l++);
	}
	nd_set_label(nd_mapping->labels, NULL, l);

 out:
	kfree(old_res_list);
	kfree(victim_map);
	return rc;

 abort:
	/*
	 * 1/ repair the allocated label bitmap in the index
	 * 2/ restore the resource list
	 */
	nd_label_copy(ndd, nsindex, to_current_namespace_index(ndd));
	kfree(nsblk->res);
	nsblk->res = old_res_list;
	nsblk->num_resources = old_num_resources;
	old_res_list = NULL;
	goto out;
}

static int init_labels(struct nd_mapping *nd_mapping, int num_labels)
{
	int i, l, old_num_labels = 0;
	struct nd_namespace_index __iomem *nsindex;
	struct nd_namespace_label __iomem *nd_label;
	struct nd_dimm_drvdata *ndd = to_ndd(nd_mapping);
	size_t size = (num_labels + 1) * sizeof(struct nd_namespace_label *);

	for_each_label(l, nd_label, nd_mapping->labels)
		old_num_labels++;

	/*
	 * We need to preserve all the old labels for the mapping so
	 * they can be garbage collected after writing the new labels.
	 */
	if (num_labels > old_num_labels) {
		struct nd_namespace_label **labels;

		labels = krealloc(nd_mapping->labels, size, GFP_KERNEL);
		if (!labels)
			return -ENOMEM;
		nd_mapping->labels = labels;
	}
	if (!nd_mapping->labels)
		return -ENOMEM;

	for (i = old_num_labels; i <= num_labels; i++)
		nd_set_label(nd_mapping->labels, NULL, i);

	if (ndd->ns_current == -1 || ndd->ns_next == -1)
		/* pass */;
	else
		return max(num_labels, old_num_labels);

	nsindex = to_namespace_index(ndd, 0);
	memset_io(nsindex, 0, ndd->nsarea.config_size);
	for (i = 0; i < 2; i++) {
		int rc = nd_label_write_index(ndd, i, i*2, ND_NSINDEX_INIT);

		if (rc)
			return rc;
	}
	ndd->ns_next = 1;
	ndd->ns_current = 0;

	return max(num_labels, old_num_labels);
}

static int del_labels(struct nd_mapping *nd_mapping, u8 *uuid)
{
	struct nd_dimm_drvdata *ndd = to_ndd(nd_mapping);
	struct nd_namespace_label __iomem *nd_label;
	struct nd_namespace_index __iomem *nsindex;
	u8 label_uuid[NSLABEL_UUID_LEN];
	int l, num_freed = 0;
	unsigned long *free;
	u32 nslot, slot;

	if (!uuid)
		return 0;

	/* no index || no labels == nothing to delete */
	if (!preamble_next(ndd, &nsindex, &free, &nslot)
			|| !nd_mapping->labels)
		return 0;

	for_each_label(l, nd_label, nd_mapping->labels) {
		memcpy_fromio(label_uuid, nd_label->uuid, NSLABEL_UUID_LEN);
		if (memcmp(label_uuid, uuid, NSLABEL_UUID_LEN) != 0)
			continue;
		slot = to_slot(ndd, nd_label);
		nd_label_free_slot(ndd, slot);
		dev_dbg(ndd->dev, "%s: free: %d\n", __func__, slot);
		del_label(nd_mapping, l);
		num_freed++;
		l--; /* retry with new label at this index */
	}

	if (num_freed > l) {
		/*
		 * num_freed will only ever be > l when we delete the last
		 * label
		 */
		kfree(nd_mapping->labels);
		nd_mapping->labels = NULL;
		dev_dbg(ndd->dev, "%s: no more labels\n", __func__);
	}

	return nd_label_write_index(ndd, ndd->ns_next,
			nd_inc_seq(readl(&nsindex->seq)), 0);
}

int nd_pmem_namespace_label_update(struct nd_region *nd_region,
		struct nd_namespace_pmem *nspm, resource_size_t size)
{
	int i;

	for (i = 0; i < nd_region->ndr_mappings; i++) {
		struct nd_mapping *nd_mapping = &nd_region->mapping[i];
		int rc;

		if (size == 0) {
			rc = del_labels(nd_mapping, nspm->uuid);
			if (rc)
				return rc;
			continue;
		}

		rc = init_labels(nd_mapping, 1);
		if (rc < 0)
			return rc;

		rc = __pmem_label_update(nd_region, nd_mapping, nspm, i);
		if (rc)
			return rc;
	}

	return 0;
}

int nd_blk_namespace_label_update(struct nd_region *nd_region,
		struct nd_namespace_blk *nsblk, resource_size_t size)
{
	struct nd_mapping *nd_mapping = &nd_region->mapping[0];
	struct resource *res;
	int count = 0;

	if (size == 0)
		return del_labels(nd_mapping, nsblk->uuid);

	for_each_dpa_resource(to_ndd(nd_mapping), res)
		count++;

	count = init_labels(nd_mapping, count);
	if (count < 0)
		return count;

	return __blk_label_update(nd_region, nd_mapping, nsblk, count);
}
