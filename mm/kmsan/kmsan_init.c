// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN initialization routines.
 *
 * Copyright (C) 2017-2020 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#include "kmsan.h"

#include <asm/cpu_entry_area.h>
#include <asm/sections.h>
#include <linux/mm.h>
#include <linux/memblock.h>

#define NUM_FUTURE_RANGES 128
struct start_end_pair {
	u64 start, end;
};

static struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES] __initdata;
static int future_index __initdata;

/*
 * Record a range of memory for which the metadata pages will be created once
 * the page allocator becomes available.
 */
static void __init kmsan_record_future_shadow_range(void *start, void *end)
{
	int i;
	u64 nstart = (u64)start, nend = (u64)end, cstart, cend;
	bool merged = false;

	BUG_ON(future_index == NUM_FUTURE_RANGES);
	BUG_ON((nstart >= nend) || !nstart || !nend);
	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
	nend = ALIGN(nend, PAGE_SIZE);

	/*
	 * Scan the existing ranges to see if any of them overlaps with
	 * [start, end). In that case, merge the two ranges instead of
	 * creating a new one.
	 * The number of ranges is less than 20, so there is no need to organize
	 * them into a more intelligent data structure.
	 */
	for (i = 0; i < future_index; i++) {
		cstart = start_end_pairs[i].start;
		cend = start_end_pairs[i].end;
		if ((cstart < nstart && cend < nstart) ||
		    (cstart > nend && cend > nend))
			/* ranges are disjoint - do not merge */
			continue;
		start_end_pairs[i].start = min(nstart, cstart);
		start_end_pairs[i].end = max(nend, cend);
		merged = true;
		break;
	}
	if (merged)
		return;
	start_end_pairs[future_index].start = nstart;
	start_end_pairs[future_index].end = nend;
	future_index++;
}

/*
 * Initialize the shadow for existing mappings during kernel initialization.
 * These include kernel text/data sections, NODE_DATA and future ranges
 * registered while creating other data (e.g. percpu).
 *
 * Allocations via memblock can be only done before slab is initialized.
 */
void __init kmsan_initialize_shadow(void)
{
	int nid;
	u64 i;
	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
	phys_addr_t p_start, p_end;

	for_each_reserved_mem_range(i, &p_start, &p_end)
		kmsan_record_future_shadow_range(phys_to_virt(p_start),
						 phys_to_virt(p_end));
	/* Allocate shadow for .data */
	kmsan_record_future_shadow_range(_sdata, _edata);

	for_each_online_node (nid)
		kmsan_record_future_shadow_range(
			NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);

	for (i = 0; i < future_index; i++)
		kmsan_init_alloc_meta_for_range((void *)start_end_pairs[i].start,
						(void *)start_end_pairs[i].end);
}
EXPORT_SYMBOL(kmsan_initialize_shadow);

void __init kmsan_initialize(void)
{
	/* Assuming current is init_task */
	kmsan_internal_task_create(current);
	pr_info("vmalloc area at: %px\n", VMALLOC_START);
	pr_info("vmalloc shadow at: %px\n",
		VMALLOC_START + KMSAN_VMALLOC_SHADOW_OFFSET);
	pr_info("Starting KernelMemorySanitizer\n");
	kmsan_ready = true;
}
EXPORT_SYMBOL(kmsan_initialize);
