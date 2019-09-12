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
#include <linux/percpu-defs.h>
#include <linux/stddef.h>
#include <linux/smp.h>

#include "kmsan.h"

DEFINE_PER_CPU(char[CPU_ENTRY_AREA_SIZE], cpu_entry_area_shadow);
DEFINE_PER_CPU(char[CPU_ENTRY_AREA_SIZE], cpu_entry_area_origin);

/*
 * Dummy load and store pages to be used when the real metadata is unavailable.
 * There are separate pages for loads and stores, so that every load returns a
 * zero, and every store doesn't affect other stores.
 */
char dummy_load_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
char dummy_store_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

/*
 * Taken from arch/x86/mm/physaddr.h
 * TODO(glider): do we need it?
 */
static inline int my_phys_addr_valid(unsigned long addr)
{
#ifdef CONFIG_PHYS_ADDR_T_64BIT
	return !(addr >> boot_cpu_data.x86_phys_bits);
#else
	return 1;
#endif
}

/*
 * Taken from arch/x86/mm/physaddr.c
 * TODO(glider): do we need it?
 */
static bool my_virt_addr_valid(void *addr)
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
		if ((x > y) || !my_phys_addr_valid(x))
			return false;
	}

	return pfn_valid(x >> PAGE_SHIFT);
}

static inline bool is_cpu_entry_area_addr(void *addr)
{
        return ((u64)addr >= CPU_ENTRY_AREA_BASE) && ((u64)addr < (CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE));
}

static void *get_cea_shadow_or_null(void *addr)
{
	int cpu = smp_processor_id();
	int off;

	if (!is_cpu_entry_area_addr(addr))
		return NULL;
	off = (char*)addr - (char*)get_cpu_entry_area(cpu);
	if ((off < 0) || (off >= CPU_ENTRY_AREA_SIZE))
		return NULL;
	return &per_cpu(cpu_entry_area_shadow[off], cpu);
}

void *vmalloc_meta(void *addr, bool is_origin)
{
	u64 addr64 = (u64)addr, off;

	BUG_ON(is_origin && !IS_ALIGNED(addr64, ORIGIN_SIZE));
	if (_is_vmalloc_addr(addr)) {
		return (void *)(addr64 + (is_origin ? VMALLOC_ORIGIN_OFFSET
						: VMALLOC_SHADOW_OFFSET));
	}
	if (is_module_addr(addr)) {
		off = addr64 - MODULES_VADDR;
		return (void *)(off + (is_origin ? MODULES_ORIGIN_START
						: MODULES_SHADOW_START));
	}
	return NULL;
}

static void *get_cea_origin_or_null(void *addr)
{
	int cpu = smp_processor_id();
	int off;

	if (!is_cpu_entry_area_addr(addr))
		return NULL;
	off = (char*)addr - (char*)get_cpu_entry_area(cpu);
	if ((off < 0) || (off >= CPU_ENTRY_AREA_SIZE))
		return NULL;
	return &per_cpu(cpu_entry_area_origin[off], cpu);
}

struct page *virt_to_page_or_null(void *vaddr)
{
	if (my_virt_addr_valid(vaddr))
		return virt_to_page(vaddr);
	else
		return NULL;
}

shadow_origin_ptr_t kmsan_get_shadow_origin_ptr(void *address, u64 size, bool store)
{
	shadow_origin_ptr_t ret;
	struct page *page;
	u64 pad, offset, o_offset;
	const u64 addr64 = (u64)address;
	u64 o_addr64 = (u64)address;
	void *shadow;

	if (size > PAGE_SIZE) {
		WARN(1, "size too big in kmsan_get_shadow_origin_ptr("
			"%px, %d, %d)\n", address, size, store);
		BUG();
	}
	if (store) {
		ret.s = dummy_store_page;
		ret.o = dummy_store_page;
	} else {
		ret.s = dummy_load_page;
		ret.o = dummy_load_page;
	}
	if (!kmsan_ready || IN_RUNTIME())
		return ret;
	BUG_ON(!metadata_is_contiguous(address, size, /*is_origin*/false));

	if (!IS_ALIGNED(addr64, ORIGIN_SIZE)) {
		pad = addr64 % ORIGIN_SIZE;
		o_addr64 -= pad;
	}

	if (_is_vmalloc_addr(address) || is_module_addr(address)) {
		ret.s = vmalloc_shadow(address);
		ret.o = vmalloc_origin((void *)o_addr64);
		return ret;
	}

	if (!my_virt_addr_valid(address)) {
		page = vmalloc_to_page_or_null(address);
		if (page)
			goto next;
		shadow = get_cea_shadow_or_null(address);
		if (shadow) {
			ret.s = shadow;
			ret.o = get_cea_origin_or_null((void *)o_addr64);
			return ret;
		}
	}
	page = virt_to_page_or_null(address);
	if (!page)
		return ret;
next:
        if (!has_shadow_page(page) || !has_origin_page(page))
		return ret;
	offset = addr64 % PAGE_SIZE;
	o_offset = o_addr64 % PAGE_SIZE;

	if (offset + size - 1 > PAGE_SIZE) {
		/*
		 * The access overflows the current page and touches the
		 * subsequent ones. Make sure the shadow/origin pages are also
		 * consequent.
		 */
		BUG_ON(!metadata_is_contiguous(address, size, /*is_origin*/false));
	}

	ret.s = shadow_ptr_for(page) + offset;
	ret.o = origin_ptr_for(page) + o_offset;
	return ret;
}

/*
 * TODO(glider): all other shadow getters are broken, so let's write another
 * one. The semantic is pretty straightforward: either return a valid shadow
 * pointer or NULL. The caller must BUG_ON on NULL if he wants to.
 * The return value of this function should not depend on whether we're in the
 * runtime or not.
 */
__always_inline
void *kmsan_get_metadata_or_null(void *address, size_t size, bool is_origin)
{
	struct page *page;
	void *ret;
	u64 addr = (u64)address, pad, offset;

	if (is_origin && !IS_ALIGNED(addr, ORIGIN_SIZE)) {
		pad = addr % ORIGIN_SIZE;
		addr -= pad;
		size += pad;
	}
	address = (void *)addr;
	if (_is_vmalloc_addr(address) || is_module_addr(address)) {
		return vmalloc_meta(address, is_origin);
	}

	if (!my_virt_addr_valid(address)) {
		page = vmalloc_to_page_or_null(address);
		if (page)
			goto next;
		ret = is_origin ? get_cea_origin_or_null(address) : get_cea_shadow_or_null(address);
		if (ret)
			return ret;
	}
	page = virt_to_page_or_null(address);
	if (!page)
		return NULL;
next:
        if (!has_shadow_page(page) || !has_origin_page(page))
		return NULL;
	offset = addr % PAGE_SIZE;

	ret = (is_origin ? origin_ptr_for(page) : shadow_ptr_for(page)) + offset;
	return ret;
}
