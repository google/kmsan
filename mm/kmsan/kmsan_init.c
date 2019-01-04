/*
 * KMSAN initialization routines.
 *
 * Copyright (C) 2017 Google, Inc
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "kmsan.h"

#include <asm/cpu_entry_area.h>
#include <linux/mm.h>
#include <linux/memblock.h>

#define NUM_FUTURE_RANGES 128
struct start_end_pair {
	u64 start, end;
};

static __initdata struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES];
static __initdata int future_index = 0;
static __initdata bool ranges_processed = false;

/*
 * Record a range of memory for which the metadata pages will be created once
 * the page allocator becomes available.
 * TODO(glider): squash together ranges belonging to the same page.
 */
static void __init kmsan_record_future_shadow_range(u64 start, u64 end)
{
	BUG_ON(future_index == NUM_FUTURE_RANGES);
	BUG_ON(ranges_processed);
	BUG_ON((start >= end) || !start || !end);
	start_end_pairs[future_index].start = start;
	start_end_pairs[future_index].end = end;
	future_index++;
}

extern char _sdata[], _edata[];

void __init kmsan_alloc_meta_for_range(u64 start, u64 end)
{
	u64 addr;
	struct page *page;
	pr_err("kmsan_alloc_meta_for_range(%px, %px)\n", start, end);
	start = ALIGN_DOWN(start, PAGE_SIZE);
	u64 size = ALIGN(end - start, PAGE_SIZE);
	void *shadow, *origin;
	struct page *shadow_p, *origin_p;

	shadow = memblock_alloc(size, PAGE_SIZE);
	origin = memblock_alloc(size, PAGE_SIZE);
	for (addr = 0; addr < size; addr += PAGE_SIZE) {
		page = virt_to_page_or_null((char*)start + addr);
		shadow_p = virt_to_page_or_null((char*)shadow + addr);
		shadow_p->shadow = NULL;
		shadow_p->origin = NULL;
		page->shadow = shadow_p;
		origin_p = virt_to_page_or_null((char*)origin + addr);
		origin_p->shadow = NULL;
		origin_p->origin = NULL;
		page->origin = origin_p;
	}
}

/* Was intended to be called several times, but better not do that. */
void __init process_future_ranges(void)
{
	int i = 0;

	for (; i < future_index; i++)
		kmsan_alloc_meta_for_range(start_end_pairs[i].start,
						start_end_pairs[i].end);
	ranges_processed = true;
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

	for_each_reserved_mem_region(i, &p_start, &p_end) {
		kmsan_record_future_shadow_range(phys_to_virt(p_start), phys_to_virt(p_end+1));
	}
	/* Allocate shadow for .data */
	kmsan_record_future_shadow_range(_sdata, _edata);

	/*
	 * TODO(glider): alloc_node_data() in arch/x86/mm/numa.c uses
	 * sizeof(pg_data_t).
	 */
	for_each_online_node(nid)
		kmsan_record_future_shadow_range((u64)NODE_DATA(nid),
						(u64)NODE_DATA(nid) + nd_size);
	process_future_ranges();
}
EXPORT_SYMBOL(kmsan_initialize_shadow);

void __init kmsan_initialize(void)
{
	/* Assuming current is init_task */
	do_kmsan_task_create(current);
	kmsan_pr_err("Starting KernelMemorySanitizer\n");
	kmsan_ready = true;
}
EXPORT_SYMBOL(kmsan_initialize);
