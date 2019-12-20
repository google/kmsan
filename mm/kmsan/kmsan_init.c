// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN initialization routines.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "kmsan.h"

#include <asm/cpu_entry_area.h>
#include <asm/sections.h>
#include <linux/mm.h>
#include <linux/memblock.h>

#define NUM_FUTURE_RANGES 128
struct start_end_pair {
	void *start, *end;
};

static struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES] __initdata;
static int future_index __initdata;

/*
 * Record a range of memory for which the metadata pages will be created once
 * the page allocator becomes available.
 */
static void __init kmsan_record_future_shadow_range(void *start, void *end)
{
	BUG_ON(future_index == NUM_FUTURE_RANGES);
	BUG_ON((start >= end) || !start || !end);
	start_end_pairs[future_index].start = start;
	start_end_pairs[future_index].end = end;
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

	for_each_reserved_mem_region(i, &p_start, &p_end)
		kmsan_record_future_shadow_range(phys_to_virt(p_start),
						 phys_to_virt(p_end+1));
	/* Allocate shadow for .data */
	kmsan_record_future_shadow_range(_sdata, _edata);

	for_each_online_node(nid)
		kmsan_record_future_shadow_range(
			NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);

	for (i = 0; i < future_index; i++)
		kmsan_init_alloc_meta_for_range(start_end_pairs[i].start,
						start_end_pairs[i].end);
}
EXPORT_SYMBOL(kmsan_initialize_shadow);

void __init kmsan_initialize(void)
{
	/* Assuming current is init_task */
	kmsan_internal_task_create(current);
	pr_info("Starting KernelMemorySanitizer\n");
	kmsan_ready = true;
}
EXPORT_SYMBOL(kmsan_initialize);
