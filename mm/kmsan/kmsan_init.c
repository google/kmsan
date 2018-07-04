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

#define NUM_FUTURE_RANGES 128
struct start_end_pair {
	u64 start, end;
};

__initdata struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES];
__initdata int future_index = 0;	// next available index
__initdata int future_processed = 0;

/* For percpu allocations it may be too early to allocate memory using
 * alloc_pages().
 * */
void kmsan_init_percpu_metadata(void *mem, void *shadow, void *origin, size_t size)
{
	int i;
	u64 addr = (u64)mem;
	struct page *page;

	BUG_ON(size % PAGE_SIZE);
	for (i = 0; i < size / PAGE_SIZE; i++, addr += PAGE_SIZE) {
		page = virt_to_page_or_null((void*)addr);
		page->shadow = virt_to_page_or_null(shadow) + i;
		page->origin = virt_to_page_or_null(origin) + i;
	}
}

// TODO(glider): this is thread-unsafe.
void __initdata kmsan_record_future_shadow_range(u64 start, u64 end)
{
	if (future_index == NUM_FUTURE_RANGES) {
		BUG();
		return;
	}
	start_end_pairs[future_index].start = start;
	start_end_pairs[future_index].end = end;
	future_index++;
	///pr_err("future_index: %d\n", future_index);
	///dump_stack();
}
EXPORT_SYMBOL(kmsan_record_future_shadow_range);

extern char __bss_start[];
extern char __bss_stop[];
extern char _sdata[];
extern char _edata[];

void kmsan_initialize_shadow_for_text()
{
	u64 addr;
	struct page *page, *upper;
	///u64 size = 128 * 1024 * 1024;
	u64 start = __START_KERNEL_map;
	///u64 start = 0xffffffff81000000;
	// From arch/x86/boot/voffset.h
	///u64 size = 0xffffffff85b94000-0xffffffff81000000;
	///u64 size = 0xffffffff85b94000-__START_KERNEL_map;
	///u64 size = 0xffffffff85d86000-__START_KERNEL_map;
	u64 size = __bss_stop-__START_KERNEL_map;
	u64 order = MAX_ORDER - 1;

	// TODO(glider): try to use memblock_alloc() to reserve some phys space
	// for the addresses.
	// Problem: need to allocate contiguous shadow range to avoid reports

	kmsan_pr_err("__START_KERNEL_map: %px, end (__bss_stop): %px\n", __START_KERNEL_map, __bss_stop);
	kmsan_pr_err("__bss: %px-%px, __data: %px-%px\n", __bss_start, __bss_stop, _sdata, _edata);
	kmsan_pr_err("upper start: %px, end: %px\n", __PAGE_OFFSET, size + __PAGE_OFFSET);

	// Allocate PAGE_SIZE<<order to decrease the number of stitches.
	// Ideally, every single section should have consequent shadow memory range.
	// Which is quite hard, because page_alloc can allocate at most 1 << (MAX_ORDER-1) pages.
	for (addr = 0; addr < size; addr += (PAGE_SIZE << order)) {
		page = virt_to_page_or_null((char*)addr + __START_KERNEL_map);
		// TODO(glider): use proper actual_size?
		BUG_ON(kmsan_internal_alloc_meta_for_pages(page, order, /*actual_size*/0, GFP_ATOMIC | __GFP_ZERO,
							NUMA_NO_NODE));
		upper = virt_to_page_or_null((char*)addr + __PAGE_OFFSET);
		BUG_ON(page != upper);
		for (int np = 0; np < 1 << order; np++) {
			// TODO(glider): may we use a single page for both upper and lower mappings?
			// Depends on whether ffff880000000000 and ffffffff80000000 are the same.
			upper[np].shadow = page[np].shadow;
			upper[np].origin = page[np].origin;
		}
	}
}

void __initdata kmsan_initialize_shadow_range(u64 start, u64 end)
{
	u64 addr;
	struct page *page;
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		page = virt_to_page_or_null((void*)addr);
		if (!virt_addr_valid(addr)) {
			pr_err("addr: %px, page: %px\n", addr, page);
			BUG();
		}
		if (page->shadow) {
			///kmsan_pr_err("skipping %px (page %px)\n", addr, page);
		} else {
			BUG_ON(kmsan_internal_alloc_meta_for_pages(page, /*order*/0, /*actual_size*/0, GFP_ATOMIC | __GFP_ZERO,
							NUMA_NO_NODE));
		}
	}
}

void __initdata process_future_ranges(void)
{
	int i;

	for (i = future_processed; i < future_index; i++) {
		kmsan_initialize_shadow_range(start_end_pairs[i].start, start_end_pairs[i].end);
	}
	future_processed = future_index;
}

void __initdata kmsan_initialize_shadow(void)
{
	struct page *page;
	unsigned long i;
	u64 addr;
	int nid;
	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);

	kmsan_initialize_shadow_for_text();
	// Allocate shadow for init stack.
	///kmsan_initialize_shadow_range(init_task.stack, init_task.stack + THREAD_SIZE);
	////kmsan_record_future_shadow_range((u64)NODE_DATA(0), (u64)NODE_DATA(0) + roundup(sizeof(struct pglist_data), PAGE_SIZE) * num_online_cpus());
	//
	// TODO(glider): alloc_node_data() in arch/x86/mm/numa.c uses sizeof(pg_data_t).
	for_each_online_node(nid) {
		kmsan_record_future_shadow_range((u64)NODE_DATA(nid), (u64)NODE_DATA(nid) + nd_size);
		///pr_err("nid: %d, stack: %px, size: %d\n", nid, get_cpu_entry_area(nid)->exception_stacks, CPU_ENTRY_AREA_SIZE);
		///kmsan_record_future_shadow_range((u64)get_cpu_entry_area(nid)->exception_stacks, CPU_ENTRY_AREA_SIZE);
	}
	///kmsan_pr_err("future_index: %d\n", future_index);
	process_future_ranges();
	// TODO(glider): should be init_task.
	do_kmsan_thread_create(current);
	kmsan_pr_err("Starting KernelMemorySanitizer\n");
	kmsan_ready = true;
	kmsan_threads_ready = true;
}
EXPORT_SYMBOL(kmsan_initialize_shadow);

