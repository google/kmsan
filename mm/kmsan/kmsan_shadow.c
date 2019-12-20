// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN shadow implementation.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <asm/cpu_entry_area.h>
#include <asm/page.h>
#include <asm/pgtable_64_types.h>
#include <asm/tlbflush.h>
#include <linux/memblock.h>
#include <linux/mm_types.h>
#include <linux/percpu-defs.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/stddef.h>

#include "kmsan.h"
#include "kmsan_shadow.h"

#define shadow_page_for(page) ((page)->shadow)

#define origin_page_for(page) ((page)->origin)

#define shadow_ptr_for(page) (page_address((page)->shadow))

#define origin_ptr_for(page) (page_address((page)->origin))

#define has_shadow_page(page) (!!((page)->shadow))

#define has_origin_page(page) (!!((page)->origin))

#define set_no_shadow_origin_page(page)	\
	do {				\
		(page)->shadow = NULL;	\
		(page)->origin = NULL;	\
	} while (0) /**/

#define is_ignored_page(page) (!!(((u64)((page)->shadow)) % 2))

#define ignore_page(pg)	\
	((pg)->shadow = (struct page *)((u64)((pg)->shadow) | 1))

DEFINE_PER_CPU(char[CPU_ENTRY_AREA_SIZE], cpu_entry_area_shadow);
DEFINE_PER_CPU(char[CPU_ENTRY_AREA_SIZE], cpu_entry_area_origin);

/*
 * Dummy load and store pages to be used when the real metadata is unavailable.
 * There are separate pages for loads and stores, so that every load returns a
 * zero, and every store doesn't affect other loads.
 */
char dummy_load_page[PAGE_SIZE] __aligned(PAGE_SIZE);
char dummy_store_page[PAGE_SIZE] __aligned(PAGE_SIZE);

/*
 * Taken from arch/x86/mm/physaddr.h to avoid using an instrumented version.
 */
static int kmsan_phys_addr_valid(unsigned long addr)
{
#ifdef CONFIG_PHYS_ADDR_T_64BIT
	return !(addr >> boot_cpu_data.x86_phys_bits);
#else
	return 1;
#endif
}

/*
 * Taken from arch/x86/mm/physaddr.c to avoid using an instrumented version.
 */
static bool kmsan_virt_addr_valid(void *addr)
{
	unsigned long x = (unsigned long)addr;
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	if (unlikely(x > y)) {
		x = y + phys_base;

		if (y >= KERNEL_IMAGE_SIZE)
			return false;
	} else {
		x = y + (__START_KERNEL_map - PAGE_OFFSET);

		/* carry flag will be set if starting x was >= PAGE_OFFSET */
		if ((x > y) || !kmsan_phys_addr_valid(x))
			return false;
	}

	return pfn_valid(x >> PAGE_SHIFT);
}

static unsigned long vmalloc_meta(void *addr, bool is_origin)
{
	unsigned long addr64 = (unsigned long)addr, off;

	BUG_ON(is_origin && !IS_ALIGNED(addr64, ORIGIN_SIZE));
	if (kmsan_internal_is_vmalloc_addr(addr))
		return addr64 + (is_origin ? VMALLOC_ORIGIN_OFFSET
					   : VMALLOC_SHADOW_OFFSET);
	if (kmsan_internal_is_module_addr(addr)) {
		off = addr64 - MODULES_VADDR;
		return off + (is_origin ? MODULES_ORIGIN_START
					: MODULES_SHADOW_START);
	}
	return 0;
}

static void *get_cea_meta_or_null(void *addr, bool is_origin)
{
	int cpu = smp_processor_id();
	int off;
	char *metadata_array;

	if (((u64)addr < CPU_ENTRY_AREA_BASE) ||
	    ((u64)addr >= (CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE)))
		return NULL;
	off = (char *)addr - (char *)get_cpu_entry_area(cpu);
	if ((off < 0) || (off >= CPU_ENTRY_AREA_SIZE))
		return NULL;
	metadata_array = is_origin ? cpu_entry_area_origin :
				     cpu_entry_area_shadow;
	return &per_cpu(metadata_array[off], cpu);
}

static struct page *virt_to_page_or_null(void *vaddr)
{
	if (kmsan_virt_addr_valid(vaddr))
		return virt_to_page(vaddr);
	else
		return NULL;
}

struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *address, u64 size,
						     bool store)
{
	struct shadow_origin_ptr ret;
	void *shadow;

	if (size > PAGE_SIZE)
		panic("size too big in %s(%px, %d, %d)\n",
		     __func__, address, size, store);

	if (!kmsan_ready || kmsan_in_runtime())
		goto return_dummy;

	BUG_ON(!metadata_is_contiguous(address, size, META_SHADOW));
	shadow = kmsan_get_metadata(address, size, META_SHADOW);
	if (!shadow)
		goto return_dummy;

	ret.s = shadow;
	ret.o = kmsan_get_metadata(address, size, META_ORIGIN);
	return ret;

return_dummy:
	if (store) {
		ret.s = dummy_store_page;
		ret.o = dummy_store_page;
	} else {
		ret.s = dummy_load_page;
		ret.o = dummy_load_page;
	}
	return ret;
}

/*
 * Obtain the shadow or origin pointer for the given address, or NULL if there's
 * none. The caller must check the return value for being non-NULL if needed.
 * The return value of this function should not depend on whether we're in the
 * runtime or not.
 */
void *kmsan_get_metadata(void *address, size_t size, bool is_origin)
{
	struct page *page;
	void *ret;
	u64 addr = (u64)address, pad, off;

	if (is_origin && !IS_ALIGNED(addr, ORIGIN_SIZE)) {
		pad = addr % ORIGIN_SIZE;
		addr -= pad;
		size += pad;
	}
	address = (void *)addr;
	if (kmsan_internal_is_vmalloc_addr(address) ||
	    kmsan_internal_is_module_addr(address))
		return (void *)vmalloc_meta(address, is_origin);

	ret = get_cea_meta_or_null(address, is_origin);
	if (ret)
		return ret;

	page = virt_to_page_or_null(address);
	if (!page)
		return NULL;
	if (is_ignored_page(page))
		return NULL;
	if (!has_shadow_page(page) || !has_origin_page(page))
		return NULL;
	off = addr % PAGE_SIZE;

	ret = (is_origin ? origin_ptr_for(page) : shadow_ptr_for(page)) + off;
	return ret;
}

void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
{
	u64 addr, size;
	struct page *page;
	void *shadow, *origin;
	struct page *shadow_p, *origin_p;

	start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
	size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
	shadow = memblock_alloc(size, PAGE_SIZE);
	origin = memblock_alloc(size, PAGE_SIZE);
	for (addr = 0; addr < size; addr += PAGE_SIZE) {
		page = virt_to_page_or_null((char *)start + addr);
		shadow_p = virt_to_page_or_null((char *)shadow + addr);
		set_no_shadow_origin_page(shadow_p);
		shadow_page_for(page) = shadow_p;
		origin_p = virt_to_page_or_null((char *)origin + addr);
		set_no_shadow_origin_page(origin_p);
		origin_page_for(page) = origin_p;
	}
}

/* Called from mm/memory.c */
void kmsan_copy_page_meta(struct page *dst, struct page *src)
{
	unsigned long irq_flags;

	if (!kmsan_ready || kmsan_in_runtime())
		return;
	if (!has_shadow_page(src)) {
		kmsan_internal_unpoison_shadow(page_address(dst), PAGE_SIZE,
					       /*checked*/false);
		return;
	}
	if (!has_shadow_page(dst))
		return;
	if (is_ignored_page(src)) {
		ignore_page(dst);
		return;
	}

	irq_flags = kmsan_enter_runtime();
	__memcpy(shadow_ptr_for(dst), shadow_ptr_for(src),
		PAGE_SIZE);
	BUG_ON(!has_origin_page(src) || !has_origin_page(dst));
	__memcpy(origin_ptr_for(dst), origin_ptr_for(src),
		PAGE_SIZE);
	kmsan_leave_runtime(irq_flags);
}
EXPORT_SYMBOL(kmsan_copy_page_meta);

/* Helper function to allocate page metadata. */
static int kmsan_internal_alloc_meta_for_pages(struct page *page,
					       unsigned int order,
					       gfp_t flags, int node)
{
	struct page *shadow, *origin;
	int pages = 1 << order;
	int i;
	bool initialized = (flags & __GFP_ZERO) || !kmsan_ready;
	depot_stack_handle_t handle;

	if (flags & __GFP_NO_KMSAN_SHADOW) {
		for (i = 0; i < pages; i++)
			set_no_shadow_origin_page(&page[i]);
		return 0;
	}

	/*
	 * We always want metadata allocations to succeed and to finish fast.
	 */
	flags = GFP_ATOMIC;
	if (initialized)
		flags |= __GFP_ZERO;
	shadow = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	if (!shadow) {
		for (i = 0; i < pages; i++) {
			set_no_shadow_origin_page(&page[i]);
			set_no_shadow_origin_page(&page[i]);
		}
		return -ENOMEM;
	}
	if (!initialized)
		__memset(page_address(shadow), -1, PAGE_SIZE * pages);

	origin = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	/* Assume we've allocated the origin. */
	if (!origin) {
		__free_pages(shadow, order);
		for (i = 0; i < pages; i++)
			set_no_shadow_origin_page(&page[i]);
		return -ENOMEM;
	}

	if (!initialized) {
		handle = kmsan_save_stack_with_flags(flags, /*extra_bits*/0);
		/*
		 * Addresses are page-aligned, pages are contiguous, so it's ok
		 * to just fill the origin pages with |handle|.
		 */
		for (i = 0; i < PAGE_SIZE * pages / sizeof(handle); i++) {
			((depot_stack_handle_t *)page_address(origin))[i] =
						handle;
		}
	}

	for (i = 0; i < pages; i++) {
		shadow_page_for(&page[i]) = &shadow[i];
		set_no_shadow_origin_page(shadow_page_for(&page[i]));
		origin_page_for(&page[i]) = &origin[i];
		set_no_shadow_origin_page(origin_page_for(&page[i]));
	}
	return 0;
}

/* Called from mm/page_alloc.c */
int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags)
{
	unsigned long irq_flags;
	int ret;

	if (kmsan_in_runtime())
		return 0;
	irq_flags = kmsan_enter_runtime();
	ret = kmsan_internal_alloc_meta_for_pages(page, order, flags, -1);
	kmsan_leave_runtime(irq_flags);
	return ret;
}

/* Called from mm/page_alloc.c */
void kmsan_free_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin, *cur_page;
	int pages = 1 << order;
	int i;
	unsigned long irq_flags;

	if (!shadow_page_for(page)) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			BUG_ON(shadow_page_for(cur_page));
		}
		return;
	}

	if (!kmsan_ready) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			set_no_shadow_origin_page(cur_page);
		}
		return;
	}

	irq_flags = kmsan_enter_runtime();
	shadow = shadow_page_for(&page[0]);
	origin = origin_page_for(&page[0]);

	for (i = 0; i < pages; i++) {
		BUG_ON(has_shadow_page(shadow_page_for(&page[i])));
		BUG_ON(has_shadow_page(origin_page_for(&page[i])));
		set_no_shadow_origin_page(&page[i]);
	}
	BUG_ON(has_shadow_page(shadow));
	__free_pages(shadow, order);

	BUG_ON(has_shadow_page(origin));
	__free_pages(origin, order);
	kmsan_leave_runtime(irq_flags);
}
EXPORT_SYMBOL(kmsan_free_page);

/* Called from mm/page_alloc.c */
void kmsan_split_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin;
	unsigned long irq_flags;

	if (!kmsan_ready || kmsan_in_runtime())
		return;

	irq_flags = kmsan_enter_runtime();
	if (!has_shadow_page(&page[0])) {
		BUG_ON(has_origin_page(&page[0]));
		kmsan_leave_runtime(irq_flags);
		return;
	}
	shadow = shadow_page_for(&page[0]);
	split_page(shadow, order);

	origin = origin_page_for(&page[0]);
	split_page(origin, order);
	kmsan_leave_runtime(irq_flags);
}
EXPORT_SYMBOL(kmsan_split_page);

/* Called from mm/vmalloc.c */
void kmsan_vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages)
{
	int nr, i, mapped;
	struct page **s_pages, **o_pages;
	unsigned long shadow_start, shadow_end, origin_start, origin_end;

	if (!kmsan_ready || kmsan_in_runtime())
		return;
	shadow_start = vmalloc_meta((void *)start, META_SHADOW);
	if (!shadow_start)
		return;

	BUG_ON(start >= end);
	nr = (end - start) / PAGE_SIZE;
	s_pages = kcalloc(nr, sizeof(struct page *), GFP_KERNEL);
	o_pages = kcalloc(nr, sizeof(struct page *), GFP_KERNEL);
	if (!s_pages || !o_pages)
		goto ret;
	for (i = 0; i < nr; i++) {
		s_pages[i] = shadow_page_for(pages[i]);
		o_pages[i] = origin_page_for(pages[i]);
	}
	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
	prot = PAGE_KERNEL;

	shadow_end = vmalloc_meta((void *)end, META_SHADOW);
	origin_start = vmalloc_meta((void *)start, META_ORIGIN);
	origin_end = vmalloc_meta((void *)end, META_ORIGIN);
	mapped = __vmap_page_range_noflush(shadow_start, shadow_end,
					   prot, s_pages);
	BUG_ON(mapped != nr);
	flush_tlb_kernel_range(shadow_start, shadow_end);
	mapped = __vmap_page_range_noflush(origin_start, origin_end,
					   prot, o_pages);
	BUG_ON(mapped != nr);
	flush_tlb_kernel_range(origin_start, origin_end);
ret:
	kfree(s_pages);
	kfree(o_pages);
}

void kmsan_ignore_page(struct page *page, int order)
{
	int i;

	for (i = 0; i < 1 << order; i++)
		ignore_page(&page[i]);
}
