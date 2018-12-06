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
	///pr_err("kmsan_record_future_shadow_range(%px, %px)\n", start, end);
	///dump_stack();
	BUG_ON(future_index == NUM_FUTURE_RANGES);
	BUG_ON(ranges_processed);
	BUG_ON((start >= end) || !start || !end);
	start_end_pairs[future_index].start = start;
	start_end_pairs[future_index].end = end;
	future_index++;
}

extern char __bss_stop[];

/*
 * Allocate metadata pages for kernel sections from __START_KERNEL_map to
 * __bss_stop.
 * TODO(glider): try to use memblock_alloc() to reserve some phys space for the
 * addresses.
 * Problem: need to allocate contiguous shadow/origin ranges to avoid
 * situations when an access crosses an allocation boundary.
 */
void kmsan_initialize_shadow_for_text()
{
	u64 addr;
	struct page *page, *upper;
	u64 start = __START_KERNEL_map;
	u64 size = (u64)__bss_stop - start;
	u64 order = MAX_ORDER - 1;
	int np;

	/*
	 * Allocate chunks of (PAGE_SIZE << order) bytes to decrease the number
	 * of stitches.
	 * TODO(glider): Ideally, every single section should have consequent
	 * shadow memory range.
	 * This is quite hard, because page_alloc can allocate at most
	 * 1 << (MAX_ORDER-1) pages.
	 */
	for (addr = 0; addr < size; addr += (PAGE_SIZE << order)) {
		page = virt_to_page_or_null((char*)addr + __START_KERNEL_map);
		/* TODO(glider): use proper actual_size? */
		BUG_ON(kmsan_internal_alloc_meta_for_pages(
			page, order, /*actual_size*/ 0, GFP_ATOMIC | __GFP_ZERO,
			NUMA_NO_NODE));
		upper = virt_to_page_or_null((char*)addr + __PAGE_OFFSET);
		BUG_ON(page != upper);
		for (np = 0; np < 1 << order; np++) {
			/*
			 * TODO(glider): may we use a single page for both
			 * upper and lower mappings?
			 * Depends on whether ffff880000000000 and
			 * ffffffff80000000 are the same.
			 */
			upper[np].shadow = page[np].shadow;
			upper[np].origin = page[np].origin;
		}
	}
}

void __init kmsan_alloc_meta_for_range(u64 start, u64 end)
{
	u64 addr;
	struct page *page;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		page = virt_to_page_or_null((void *)addr);
		if (!page) {
			pr_err("virt_to_page_or_null(%px)=NULL!\n",
				addr, page);
			BUG();
		}
		if (!page->shadow)
			BUG_ON(kmsan_internal_alloc_meta_for_pages(page,
				/*order*/ 0, /*actual_size*/ 0,
				GFP_ATOMIC | __GFP_ZERO,
				NUMA_NO_NODE));
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
 */
void __init kmsan_initialize_shadow(void)
{
	int nid;
	u64 i;
	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
	phys_addr_t p_start, p_end;

	for_each_reserved_mem_region(i, &p_start, &p_end) {
		///pr_err("reserved region: %px--%px\n", phys_to_virt(p_start), phys_to_virt(p_end+1));
		kmsan_record_future_shadow_range(phys_to_virt(p_start), phys_to_virt(p_end+1));
	}

	kmsan_initialize_shadow_for_text();
	/*
	 * TODO(glider): alloc_node_data() in arch/x86/mm/numa.c uses
	 * sizeof(pg_data_t).
	 */
	for_each_online_node(nid)
		kmsan_record_future_shadow_range((u64)NODE_DATA(nid),
						(u64)NODE_DATA(nid) + nd_size);
	process_future_ranges();
	/* Assuming current is init_task */
	do_kmsan_task_create(current);
	kmsan_pr_err("Starting KernelMemorySanitizer\n");
	kmsan_ready = true;
}
EXPORT_SYMBOL(kmsan_initialize_shadow);
