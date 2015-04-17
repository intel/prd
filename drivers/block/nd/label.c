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

#define for_each_clear_bit_le(bit, addr, size) \
	for ((bit) = find_next_zero_bit_le((addr), (size), 0);  \
	     (bit) < (size);                                    \
	     (bit) = find_next_zero_bit_le((addr), (size), (bit) + 1))

/**
 * preamble_current - common variable initialization for nd_label_* routines
 * @nd_dimm: dimm container for the relevant label set
 * @nsindex: on return set to the currently active namespace index
 * @free: on return set to the free label bitmap in the index
 * @nslot: on return set to the number of slots in the label space
 */
static bool preamble_current(struct nd_dimm_drvdata *ndd,
		struct nd_namespace_index **nsindex,
		unsigned long **free, u32 *nslot)
{
	*nsindex = to_current_namespace_index(ndd);
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
