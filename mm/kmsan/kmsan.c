// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN runtime library.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/page.h>
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kmsan.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mmzone.h>
#include <linux/percpu-defs.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "../slab.h"
#include "kmsan.h"

#define KMSAN_STACK_DEPTH 64
#define MAX_CHAIN_DEPTH 7

/*
 * Some kernel asm() calls mention the non-existing |__force_order| variable
 * in the asm constraints to preserve the order of accesses to control
 * registers. KMSAN turns those mentions into actual memory accesses, therefore
 * the variable is now required to link the kernel.
 */
unsigned long __force_order;
EXPORT_SYMBOL(__force_order);

bool kmsan_ready;
/*
 * According to Documentation/x86/kernel-stacks, kernel code can run on the
 * following stacks:
 * - regular task stack - when executing the task code
 *  - interrupt stack - when handling external hardware interrupts and softirqs
 *  - NMI stack
 * 0 is for regular interrupts, 1 for softirqs, 2 for NMI.
 * Because interrupts may nest, trying to use a new context for every new
 * interrupt.
 */
DEFINE_PER_CPU(struct kmsan_task_state, kmsan_percpu_tstate);

struct kmsan_task_state *kmsan_get_task_state(void)
{
	return in_task() ? &current->kmsan : raw_cpu_ptr(&kmsan_percpu_tstate);
}

void kmsan_internal_task_create(struct task_struct *task)
{
	struct kmsan_task_state *state = &task->kmsan;

	__memset(state, 0, sizeof(struct kmsan_task_state));
	state->allow_reporting = true;
}

void kmsan_internal_memset_shadow(void *addr, int b, size_t size, bool checked)
{
	void *shadow_start;
	u64 page_offset, address = (u64)addr;
	size_t to_fill;

	BUG_ON(!metadata_is_contiguous(addr, size, META_SHADOW));
	while (size) {
		page_offset = address % PAGE_SIZE;
		to_fill = min(PAGE_SIZE - page_offset, (u64)size);
		shadow_start = kmsan_get_metadata((void *)address, to_fill,
						  META_SHADOW);
		if (!shadow_start) {
			if (checked)
				panic("%s: not memsetting %d bytes starting at %px, because the shadow is NULL\n",
				      __func__, to_fill, address);
			/* Otherwise just move on. */
		} else {
			__memset(shadow_start, b, to_fill);
		}
		address += to_fill;
		size -= to_fill;
	}
}

void kmsan_internal_poison_shadow(void *address, size_t size, gfp_t flags,
				  unsigned int poison_flags)
{
	bool checked = poison_flags & KMSAN_POISON_CHECK;
	depot_stack_handle_t handle;
	u32 extra_bits =
		kmsan_extra_bits(/*depth*/ 0, poison_flags & KMSAN_POISON_FREE);

	kmsan_internal_memset_shadow(address, -1, size, checked);
	handle = kmsan_save_stack_with_flags(flags, extra_bits);
	kmsan_set_origin_checked(address, size, handle, checked);
}

void kmsan_internal_unpoison_shadow(void *address, size_t size, bool checked)
{
	kmsan_internal_memset_shadow(address, 0, size, checked);
	kmsan_set_origin_checked(address, size, 0, checked);
}

depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
						 unsigned int reserved)
{
	depot_stack_handle_t handle;
	unsigned long entries[KMSAN_STACK_DEPTH];
	unsigned int nr_entries;

	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
	nr_entries = filter_irq_stacks(entries, nr_entries);

	/* Don't sleep (see might_sleep_if() in __alloc_pages_nodemask()). */
	flags &= ~__GFP_DIRECT_RECLAIM;

	handle = stack_depot_save(entries, nr_entries, flags);
	return set_dsh_extra_bits(handle, reserved);
}

/*
 * Depending on the value of is_memmove, this serves as both a memcpy and a
 * memmove implementation.
 *
 * As with the regular memmove, do the following:
 * - if src and dst don't overlap, use memcpy();
 * - if src and dst overlap:
 *   - if src > dst, use memcpy();
 *   - if src < dst, use reverse-memcpy.
 * Why this is correct:
 * - problems may arise if for some part of the overlapping region we
 *   overwrite its shadow with a new value before copying it somewhere.
 *   But there's a 1:1 mapping between the kernel memory and its shadow,
 *   therefore if this doesn't happen with the kernel memory it can't happen
 *   with the shadow.
 */
static void kmsan_memcpy_memmove_metadata(void *dst, void *src, size_t n,
					  bool is_memmove)
{
	void *shadow_src, *shadow_dst;
	depot_stack_handle_t *origin_src, *origin_dst;
	int src_slots, dst_slots, i, iter, step, skip_bits;
	depot_stack_handle_t old_origin = 0, chain_origin, new_origin = 0;
	u32 *align_shadow_src, shadow;
	bool backwards;

	shadow_dst = kmsan_get_metadata(dst, n, META_SHADOW);
	if (!shadow_dst)
		return;
	BUG_ON(!metadata_is_contiguous(dst, n, META_SHADOW));

	shadow_src = kmsan_get_metadata(src, n, META_SHADOW);
	if (!shadow_src) {
		/*
		 * |src| is untracked: zero out destination shadow, ignore the
		 * origins, we're done.
		 */
		__memset(shadow_dst, 0, n);
		return;
	}
	BUG_ON(!metadata_is_contiguous(src, n, META_SHADOW));

	if (is_memmove)
		__memmove(shadow_dst, shadow_src, n);
	else
		__memcpy(shadow_dst, shadow_src, n);

	origin_dst = kmsan_get_metadata(dst, n, META_ORIGIN);
	origin_src = kmsan_get_metadata(src, n, META_ORIGIN);
	BUG_ON(!origin_dst || !origin_src);
	BUG_ON(!metadata_is_contiguous(dst, n, META_ORIGIN));
	BUG_ON(!metadata_is_contiguous(src, n, META_ORIGIN));
	src_slots = (ALIGN((u64)src + n, ORIGIN_SIZE) -
		     ALIGN_DOWN((u64)src, ORIGIN_SIZE)) /
		    ORIGIN_SIZE;
	dst_slots = (ALIGN((u64)dst + n, ORIGIN_SIZE) -
		     ALIGN_DOWN((u64)dst, ORIGIN_SIZE)) /
		    ORIGIN_SIZE;
	BUG_ON(!src_slots || !dst_slots);
	BUG_ON((src_slots < 1) || (dst_slots < 1));
	BUG_ON((src_slots - dst_slots > 1) || (dst_slots - src_slots < -1));

	backwards = is_memmove && (dst > src);
	i = backwards ? min(src_slots, dst_slots) - 1 : 0;
	iter = backwards ? -1 : 1;

	align_shadow_src = (u32 *)ALIGN_DOWN((u64)shadow_src, ORIGIN_SIZE);
	for (step = 0; step < min(src_slots, dst_slots); step++, i += iter) {
		BUG_ON(i < 0);
		shadow = align_shadow_src[i];
		if (i == 0) {
			/*
			 * If |src| isn't aligned on ORIGIN_SIZE, don't
			 * look at the first |src % ORIGIN_SIZE| bytes
			 * of the first shadow slot.
			 */
			skip_bits = ((u64)src % ORIGIN_SIZE) * 8;
			shadow = (shadow << skip_bits) >> skip_bits;
		}
		if (i == src_slots - 1) {
			/*
			 * If |src + n| isn't aligned on
			 * ORIGIN_SIZE, don't look at the last
			 * |(src + n) % ORIGIN_SIZE| bytes of the
			 * last shadow slot.
			 */
			skip_bits = (((u64)src + n) % ORIGIN_SIZE) * 8;
			shadow = (shadow >> skip_bits) << skip_bits;
		}
		/*
		 * Overwrite the origin only if the corresponding
		 * shadow is nonempty.
		 */
		if (origin_src[i] && (origin_src[i] != old_origin) && shadow) {
			old_origin = origin_src[i];
			chain_origin = kmsan_internal_chain_origin(old_origin);
			/*
			 * kmsan_internal_chain_origin() may return
			 * NULL, but we don't want to lose the previous
			 * origin value.
			 */
			if (chain_origin)
				new_origin = chain_origin;
			else
				new_origin = old_origin;
		}
		if (shadow)
			origin_dst[i] = new_origin;
		else
			origin_dst[i] = 0;
	}
}

void kmsan_memcpy_metadata(void *dst, void *src, size_t n)
{
	kmsan_memcpy_memmove_metadata(dst, src, n, /*is_memmove*/ false);
}

void kmsan_memmove_metadata(void *dst, void *src, size_t n)
{
	kmsan_memcpy_memmove_metadata(dst, src, n, /*is_memmove*/ true);
}

depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
{
	depot_stack_handle_t handle;
	unsigned long entries[3];
	u64 magic = KMSAN_CHAIN_MAGIC_ORIGIN_FULL;
	int depth = 0;
	static int skipped;
	u32 extra_bits;
	bool uaf;

	if (!id)
		return id;
	/*
	 * Make sure we have enough spare bits in |id| to hold the UAF bit and
	 * the chain depth.
	 */
	BUILD_BUG_ON((1 << STACK_DEPOT_EXTRA_BITS) <= (MAX_CHAIN_DEPTH << 1));

	extra_bits = get_dsh_extra_bits(id);
	depth = kmsan_depth_from_eb(extra_bits);
	uaf = kmsan_uaf_from_eb(extra_bits);

	if (depth >= MAX_CHAIN_DEPTH) {
		skipped++;
		if (skipped % 10000 == 0) {
			pr_warn("not chained %d origins\n", skipped);
			dump_stack();
			kmsan_print_origin(id);
		}
		return id;
	}
	depth++;
	extra_bits = kmsan_extra_bits(depth, uaf);

	entries[0] = magic + depth;
	entries[1] = kmsan_save_stack_with_flags(GFP_ATOMIC, extra_bits);
	entries[2] = id;
	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC);
	return set_dsh_extra_bits(handle, extra_bits);
}

void kmsan_write_aligned_origin(void *var, size_t size, u32 origin)
{
	u32 *var_cast = (u32 *)var;
	int i;

	BUG_ON((u64)var_cast % ORIGIN_SIZE);
	BUG_ON(size % ORIGIN_SIZE);
	for (i = 0; i < size / ORIGIN_SIZE; i++)
		var_cast[i] = origin;
}

void kmsan_internal_set_origin(void *addr, int size, u32 origin)
{
	void *origin_start;
	u64 address = (u64)addr, page_offset;
	size_t to_fill, pad = 0;

	if (!IS_ALIGNED(address, ORIGIN_SIZE)) {
		pad = address % ORIGIN_SIZE;
		address -= pad;
		size += pad;
	}

	while (size > 0) {
		page_offset = address % PAGE_SIZE;
		to_fill = min(PAGE_SIZE - page_offset, (u64)size);
		/* write at least ORIGIN_SIZE bytes */
		to_fill = ALIGN(to_fill, ORIGIN_SIZE);
		BUG_ON(!to_fill);
		origin_start = kmsan_get_metadata((void *)address, to_fill,
						  META_ORIGIN);
		address += to_fill;
		size -= to_fill;
		if (!origin_start)
			/* Can happen e.g. if the memory is untracked. */
			continue;
		kmsan_write_aligned_origin(origin_start, to_fill, origin);
	}
}

void kmsan_set_origin_checked(void *addr, int size, u32 origin, bool checked)
{
	if (checked && !metadata_is_contiguous(addr, size, META_ORIGIN))
		panic("%s: WARNING: not setting origin for %d bytes starting at %px, because the metadata is incontiguous\n",
		      __func__, size, addr);
	kmsan_internal_set_origin(addr, size, origin);
}

struct page *vmalloc_to_page_or_null(void *vaddr)
{
	struct page *page;

	if (!kmsan_internal_is_vmalloc_addr(vaddr) &&
	    !kmsan_internal_is_module_addr(vaddr))
		return NULL;
	page = vmalloc_to_page(vaddr);
	if (pfn_valid(page_to_pfn(page)))
		return page;
	else
		return NULL;
}

void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
				 int reason)
{
	unsigned long irq_flags;
	unsigned long addr64 = (unsigned long)addr;
	unsigned char *shadow = NULL;
	depot_stack_handle_t *origin = NULL;
	depot_stack_handle_t cur_origin = 0, new_origin = 0;
	int cur_off_start = -1;
	int i, chunk_size;
	size_t pos = 0;

	BUG_ON(!metadata_is_contiguous(addr, size, META_SHADOW));
	if (size <= 0)
		return;
	while (pos < size) {
		chunk_size = min(size - pos,
				 PAGE_SIZE - ((addr64 + pos) % PAGE_SIZE));
		shadow = kmsan_get_metadata((void *)(addr64 + pos), chunk_size,
					    META_SHADOW);
		if (!shadow) {
			/*
			 * This page is untracked. If there were uninitialized
			 * bytes before, report them.
			 */
			if (cur_origin) {
				irq_flags = kmsan_enter_runtime();
				kmsan_report(cur_origin, addr, size,
					     cur_off_start, pos - 1, user_addr,
					     reason);
				kmsan_leave_runtime(irq_flags);
			}
			cur_origin = 0;
			cur_off_start = -1;
			pos += chunk_size;
			continue;
		}
		for (i = 0; i < chunk_size; i++) {
			if (!shadow[i]) {
				/*
				 * This byte is unpoisoned. If there were
				 * poisoned bytes before, report them.
				 */
				if (cur_origin) {
					irq_flags = kmsan_enter_runtime();
					kmsan_report(cur_origin, addr, size,
						     cur_off_start, pos + i - 1,
						     user_addr, reason);
					kmsan_leave_runtime(irq_flags);
				}
				cur_origin = 0;
				cur_off_start = -1;
				continue;
			}
			origin =
				kmsan_get_metadata((void *)(addr64 + pos + i),
						   chunk_size - i, META_ORIGIN);
			BUG_ON(!origin);
			new_origin = *origin;
			/*
			 * Encountered new origin - report the previous
			 * uninitialized range.
			 */
			if (cur_origin != new_origin) {
				if (cur_origin) {
					irq_flags = kmsan_enter_runtime();
					kmsan_report(cur_origin, addr, size,
						     cur_off_start, pos + i - 1,
						     user_addr, reason);
					kmsan_leave_runtime(irq_flags);
				}
				cur_origin = new_origin;
				cur_off_start = pos + i;
			}
		}
		pos += chunk_size;
	}
	BUG_ON(pos != size);
	if (cur_origin) {
		irq_flags = kmsan_enter_runtime();
		kmsan_report(cur_origin, addr, size, cur_off_start, pos - 1,
			     user_addr, reason);
		kmsan_leave_runtime(irq_flags);
	}
}

bool metadata_is_contiguous(void *addr, size_t size, bool is_origin)
{
	u64 cur_addr = (u64)addr, next_addr;
	char *cur_meta = NULL, *next_meta = NULL;
	depot_stack_handle_t *origin_p;
	bool all_untracked = false;
	const char *fname = is_origin ? "origin" : "shadow";

	if (!size)
		return true;

	/* The whole range belongs to the same page. */
	if (ALIGN_DOWN(cur_addr + size - 1, PAGE_SIZE) ==
	    ALIGN_DOWN(cur_addr, PAGE_SIZE))
		return true;
	cur_meta = kmsan_get_metadata((void *)cur_addr, 1, is_origin);
	if (!cur_meta)
		all_untracked = true;
	for (next_addr = cur_addr + PAGE_SIZE; next_addr < (u64)addr + size;
	     cur_addr = next_addr, cur_meta = next_meta,
	    next_addr += PAGE_SIZE) {
		next_meta = kmsan_get_metadata((void *)next_addr, 1, is_origin);
		if (!next_meta) {
			if (!all_untracked)
				goto report;
			continue;
		}
		if ((u64)cur_meta == ((u64)next_meta - PAGE_SIZE))
			continue;
		goto report;
	}
	return true;

report:
	pr_err("BUG: attempting to access two shadow page ranges.\n");
	dump_stack();
	pr_err("\n");
	pr_err("Access of size %d at %px.\n", size, addr);
	pr_err("Addresses belonging to different ranges: %px and %px\n",
	       cur_addr, next_addr);
	pr_err("page[0].%s: %px, page[1].%s: %px\n", fname, cur_meta, fname,
	       next_meta);
	origin_p = kmsan_get_metadata(addr, 1, META_ORIGIN);
	if (origin_p) {
		pr_err("Origin: %08x\n", *origin_p);
		kmsan_print_origin(*origin_p);
	} else {
		pr_err("Origin: unavailable\n");
	}
	return false;
}

/*
 * Dummy replacement for __builtin_return_address() which may crash without
 * frame pointers.
 */
void *kmsan_internal_return_address(int arg)
{
#ifdef CONFIG_UNWINDER_FRAME_POINTER
	switch (arg) {
	case 1:
		return __builtin_return_address(1);
	case 2:
		return __builtin_return_address(2);
	default:
		BUG();
	}
#else
	unsigned long entries[1];

	stack_trace_save(entries, 1, arg);
	return (void *)entries[0];
#endif
}

bool kmsan_internal_is_module_addr(void *vaddr)
{
	return ((u64)vaddr >= MODULES_VADDR) && ((u64)vaddr < MODULES_END);
}

bool kmsan_internal_is_vmalloc_addr(void *addr)
{
	return ((u64)addr >= VMALLOC_START) && ((u64)addr < VMALLOC_END);
}
