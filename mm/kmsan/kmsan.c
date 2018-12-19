/*
 * KMSAN runtime library.
 *
 * Copyright (C) 2017 Google, Inc
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/compiler.h>
#include <linux/console.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kmsan.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/percpu-defs.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/types.h>
#include <asm/page.h>	// for clear_page()
#include <linux/vmalloc.h>

#include <linux/mmzone.h>

#include "../slab.h"
#include "kmsan.h"

/* Some kernel asm() calls mention the non-existing |__force_order| variable
 * in the asm constraints to preserve the order of accesses to control
 * registers. KMSAN turns those mentions into actual memory accesses, therefore
 * the variable is now required to link the kernel.
 */
unsigned long __force_order;

extern char __irqentry_text_end[];
extern char __irqentry_text_start[];
extern char __softirqentry_text_end[];
extern char __softirqentry_text_start[];

// Dummy load and store pages to be used when the real metadata is unavailable.
// There are separate pages for loads and stores, so that every load returns a
// zero, and every store doesn't affect other stores.
char dummy_load_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
char dummy_store_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

bool kmsan_ready = false;
#define KMSAN_STACK_DEPTH 64
#define MAX_CHAIN_DEPTH 7

// According to Documentation/x86/kernel-stacks, kernel code can run on the
// following stacks:
//  - regular task stack - when executing the task code
//  - interrupt stack - when handling external hardware interrupts and softirqs
//  - TODO
// 0 is for regular interrupts, 1 for softirqs, 2 for NMI.
// Because interrupts may nest, trying to use a new context for every new interrupt.
DEFINE_PER_CPU(kmsan_context_state[KMSAN_NESTED_CONTEXT_MAX], kmsan_percpu_cstate);  // [0] for dummy per-CPU context
DEFINE_PER_CPU(int, kmsan_context_level);  // 0 for task context, |i>0| for kmsan_context_state[i]
DEFINE_PER_CPU(int, kmsan_in_interrupt);
DEFINE_PER_CPU(bool, kmsan_in_softirq);
DEFINE_PER_CPU(bool, kmsan_in_nmi);

DEFINE_PER_CPU(char[CPU_ENTRY_AREA_SIZE], cpu_entry_area_shadow);
DEFINE_PER_CPU(char[CPU_ENTRY_AREA_SIZE], cpu_entry_area_origin);

extern int oops_in_progress;

extern bool logbuf_lock_is_locked;
bool is_logbuf_locked(void)
{
	return logbuf_lock_is_locked;
}
EXPORT_SYMBOL(is_logbuf_locked);

kmsan_context_state *task_kmsan_context_state(void)
{
	int cpu = smp_processor_id();
	int level = this_cpu_read(kmsan_context_level);
	kmsan_context_state *ret;

	if (!kmsan_ready || IN_RUNTIME()) {
		ret = &per_cpu(kmsan_percpu_cstate[0], cpu);
		__memset(ret, 0, sizeof(kmsan_context_state));
		return ret;
	}

	if (!level)
		ret = &current->kmsan.cstate;
	else
		ret = &per_cpu(kmsan_percpu_cstate[level], cpu);
	return ret;
}

/* For KMSAN_ENABLE and KMSAN_DISABLE */
void kmsan_enter_runtime(unsigned long *flags)
{
	ENTER_RUNTIME(*flags);
}
EXPORT_SYMBOL(kmsan_enter_runtime);

void kmsan_leave_runtime(unsigned long *flags)
{
	LEAVE_RUNTIME(*flags);
}
EXPORT_SYMBOL(kmsan_leave_runtime);

// TODO(glider): switch to page_ext?
void inline do_kmsan_task_create(struct task_struct *task)
{
	kmsan_task_state *state = &task->kmsan;

	__memset(&state->cstate, 0, sizeof(kmsan_context_state));
	state->enabled = true;
	state->allow_reporting = true;
	state->is_reporting = false;
}

inline void kmsan_internal_memset_shadow(u64 address, int b, size_t size, bool checked)
{
	void *shadow_start;
	u64 page_offset;
	size_t to_fill;

	while (size) {
		page_offset = address % PAGE_SIZE;
		to_fill = min(PAGE_SIZE - page_offset, size);
		shadow_start = kmsan_get_metadata_or_null(address, to_fill, /*is_origin*/false);
		if (!shadow_start) {
			if (checked) {
				current->kmsan.is_reporting = true;
				kmsan_pr_err("WARNING: not memsetting %d bytes starting at %px, because the shadow is NULL\n", to_fill, address);
				current->kmsan.is_reporting = false;
				BUG();
			}
			// Otherwise just move on.
		} else {
			__memset(shadow_start, b, to_fill);
		}
		address += to_fill;
		size -= to_fill;
	}
}

void kmsan_internal_poison_shadow(const volatile void *address, size_t size,
				gfp_t flags, bool checked)
{
	depot_stack_handle_t handle;
	kmsan_internal_memset_shadow((u64)address, -1, size, checked);
	handle = kmsan_save_stack_with_flags(flags);
	kmsan_set_origin((u64)address, size, handle, checked);
}


void kmsan_internal_unpoison_shadow(const volatile void *address, size_t size, bool checked)
{
	kmsan_internal_memset_shadow((u64)address, 0, size, checked);
	kmsan_set_origin((u64)address, size, 0, checked);
}

// TODO(glider): move to lib/
static inline int in_irqentry_text(unsigned long ptr)
{
	return (ptr >= (unsigned long)&__irqentry_text_start &&
		ptr < (unsigned long)&__irqentry_text_end) ||
		(ptr >= (unsigned long)&__softirqentry_text_start &&
		 ptr < (unsigned long)&__softirqentry_text_end);
}

static inline void filter_irq_stacks(struct stack_trace *trace)
{
	int i;

	if (!trace->nr_entries)
		return;
	for (i = 0; i < trace->nr_entries; i++)
		if (in_irqentry_text(trace->entries[i])) {
			/* Include the irqentry function into the stack. */
			trace->nr_entries = i + 1;
			break;
		}
}

/* static */
inline depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags)
{
	depot_stack_handle_t handle;
	unsigned long entries[KMSAN_STACK_DEPTH];
	struct stack_trace trace = {
		.nr_entries = 0,
		.entries = entries,
		.max_entries = KMSAN_STACK_DEPTH,
		.skip = 0
	};

	kmsan_internal_unpoison_shadow(&trace, sizeof(trace), /*checked*/false);
	save_stack_trace(&trace);
	filter_irq_stacks(&trace);
	if (trace.nr_entries != 0 &&
	    trace.entries[trace.nr_entries-1] == ULONG_MAX)
		trace.nr_entries--;

	// Don't sleep. (see might_sleep_if() in __alloc_pages_nodemask())
	flags &= ~__GFP_DIRECT_RECLAIM;

	handle = depot_save_stack(&trace, flags);
	return handle;
}

inline depot_stack_handle_t kmsan_save_stack()
{
	return kmsan_save_stack_with_flags(GFP_ATOMIC);
}

/* As with the regular memmove, do the following:
 * - if src and dst don't overlap, use memcpy;
 * - if src and dst overlap:
 *   - if src > dst, use memcpy;
 *   - if src < dst, use reverse-memcpy.
 * Why this is correct:
 * - problems may arise if for some part of the overlapping region we
 *   overwrite its shadow with a new value before copying it somewhere.
 *   But there's a 1:1 mapping between the kernel memory and its shadow,
 *   therefore if this doesn't happen with the kernel memory it can't happen
 *   with the shadow.
 */
inline
void kmsan_memcpy_memmove_metadata(u64 dst, u64 src, size_t n, bool is_memmove)
{
	void *shadow_src, *shadow_dst;
	depot_stack_handle_t *origin_src, *origin_dst, *align_shadow_src;
	depot_stack_handle_t prev_origin, chained_origin, new_origin;
	int i, iter, step, src_slots, dst_slots;
	int rem_src, rem_dst, to_copy;
	u32 shadow;

	if (is_memmove && (src > dst)) {
		kmsan_memcpy_memmove_metadata(dst, src, n, /*is_memmove*/false);
		return;
	}

	if (!n || dst == src)
		return;
	BUG_ON(dst + n < dst);
	BUG_ON(src + n < src);
	while (n) {
		rem_src = PAGE_SIZE - (src % PAGE_SIZE);
		rem_dst = PAGE_SIZE - (dst % PAGE_SIZE);
		to_copy = min(n, min(rem_src, rem_dst));
		shadow_dst = kmsan_get_metadata_or_null(dst, to_copy, /*is_origin*/false);
		shadow_src = kmsan_get_metadata_or_null(src, to_copy, /*is_origin*/false);
		origin_dst = kmsan_get_metadata_or_null(dst, to_copy, /*is_origin*/true);
		origin_src = kmsan_get_metadata_or_null(src, to_copy, /*is_origin*/true);

		src_slots = (ALIGN(src + to_copy, ORIGIN_SIZE) - ALIGN_DOWN(src, ORIGIN_SIZE)) / ORIGIN_SIZE;
		dst_slots = (ALIGN(dst + to_copy, ORIGIN_SIZE) - ALIGN_DOWN(dst, ORIGIN_SIZE)) / ORIGIN_SIZE;
		BUG_ON((src_slots < 1) || (dst_slots < 1));
		BUG_ON((src_slots - dst_slots > 1) || (dst_slots - src_slots < -1));

		src += to_copy;
		dst += to_copy;
		BUG_ON(n < to_copy);
		n -= to_copy;
		if (!shadow_dst)
			continue;
		if (!shadow_src) {
			// |src| is untracked: zero out destination shadow, ignore the origins.
			__memset(shadow_dst, 0, to_copy);
			continue;
		} else {
			if (is_memmove)
				__memmove(shadow_dst, shadow_src, to_copy);
			else
				__memcpy(shadow_dst, shadow_src, to_copy);
		}
		BUG_ON(!origin_dst || !origin_src);

		i = is_memmove ? min(src_slots, dst_slots) - 1 : 0;
		iter = is_memmove ? -1 : 1;

		align_shadow_src = ALIGN_DOWN((u64)shadow_src, ORIGIN_SIZE);
		for (step = 0; step < min(src_slots, dst_slots); step++,i+=iter) {
			shadow = align_shadow_src[i];
			if (i == 0)
				// If |src| isn't aligned on ORIGIN_SIZE, don't look at the first |src % ORIGIN_SIZE| bytes of the first shadow slot.
				shadow = (shadow << (src % ORIGIN_SIZE)) >> (src % ORIGIN_SIZE);
			if (i == src_slots - 1)
				// If |src + to_copy| isn't aligned on ORIGIN_SIZE, don't look
				// at the last |(src + to_copy) % ORIGIN_SIZE| bytes of
				// the last shadow slot.
				shadow = (shadow >> ((src + to_copy) % ORIGIN_SIZE)) >> ((src + to_copy) % ORIGIN_SIZE);
			// Overwrite the origin only if the corresponding shadow is nonempty.
			if (origin_src[i] && (origin_src[i] != prev_origin) && shadow) {
				prev_origin = origin_src[i];
				chained_origin = kmsan_internal_chain_origin(prev_origin);
				// kmsan_internal_chain_origin() may return NULL, but we don't want to lose the previous origin value.
				if (chained_origin)
					new_origin = chained_origin;
				else
					new_origin = prev_origin;
			}
			if (shadow) {
				origin_dst[i] = new_origin;
			} else {
				origin_dst[i] = 0;
			}
		}
	}
}

void kmsan_memcpy_metadata(u64 dst, u64 src, size_t n)
{
	kmsan_memcpy_memmove_metadata(dst, src, n, /*is_memmove*/false);
}

void kmsan_memmove_metadata(u64 dst, u64 src, size_t n)
{
	kmsan_memcpy_memmove_metadata(dst, src, n, /*is_memmove*/true);
}

static inline void kmsan_print_origin(depot_stack_handle_t origin)
{
	struct stack_trace trace, chained_trace;
	char *descr = NULL;
	void *pc1 = NULL, *pc2 = NULL;
	depot_stack_handle_t head;

	if (!origin) {
		kmsan_pr_err("Origin not found, presumably a false report.\n");
		return;
	}

	while (true) {
		depot_fetch_stack(origin, &trace);
		if ((trace.nr_entries == 4) &&
		    ((trace.entries[0] & KMSAN_MAGIC_MASK) == KMSAN_ALLOCA_MAGIC_ORIGIN)) {
			descr = (char*)trace.entries[1];
			pc1 = (void*)trace.entries[2];
			pc2 = (void*)trace.entries[3];
			kmsan_pr_err("Local variable description: %s\n", descr);
			kmsan_pr_err("Variable was created at:\n");
			kmsan_pr_err(" %pS\n", pc1);
			kmsan_pr_err(" %pS\n", pc2);
			break;
		}
		if (trace.nr_entries == 3) {
			if ((trace.entries[0] & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FULL) {
				head = trace.entries[1];
				origin = trace.entries[2];
				kmsan_pr_err("Uninit was stored to memory at:\n");
				depot_fetch_stack(head, &chained_trace);
				print_stack_trace(&chained_trace, 0);
				kmsan_pr_err("\n");
				continue;
			}
		}
		kmsan_pr_err("Uninit was created at:\n");
		if (trace.entries)
			print_stack_trace(&trace, 0);
		else
			kmsan_pr_err("No stack\n");
		break;
	}
}

depot_stack_handle_t inline kmsan_internal_chain_origin(depot_stack_handle_t id)
{
	depot_stack_handle_t handle;
	unsigned long entries[3];
	struct stack_trace trace = {
		.nr_entries = 3,
		.entries = entries,
		.max_entries = 3,
		.skip = 0
	};
	u64 magic = KMSAN_CHAIN_MAGIC_ORIGIN_FULL;
	struct stack_trace old_trace;
	int depth = 0;
	u64 old_magic;
	static int skipped = 0;

	if (!kmsan_ready)
		return 0;

	// TODO(glider): invalid id may denote we've hit the stack depot
	// capacity. We can either return the same id or generate a new one.
	if (!id) return id;

	// TODO(glider): this is slower, but will save us a lot of memory.
	// Let us store the chain length in the lowest byte of the magic.
	// Maybe we can cache the ids somehow to avoid fetching them?
	depot_fetch_stack(id, &old_trace);
	if (!old_trace.nr_entries)
		return id;
	old_magic = old_trace.entries[0];
	// TODO(glider): just make the chain magics more similar.
	if ((old_magic & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FULL) {
		depth = old_magic & 0xff;
	}
	if (depth >= MAX_CHAIN_DEPTH) {
		skipped++;
		if (skipped % 10000 == 0) {
			kmsan_pr_err("not chained %d origins\n", skipped);
			dump_stack();
			kmsan_print_origin(id);
		}
		return id;
	}
	depth++;
	// TODO(glider): how do we figure out we've dropped some frames?
	entries[0] = magic + depth;
	entries[1] = kmsan_save_stack();
	entries[2] = id;
	handle = depot_save_stack(&trace, GFP_ATOMIC);
	return handle;
}

inline
void kmsan_write_aligned_origin(const void *var, size_t size, u32 origin)
{
	u32 *var_cast = (u32 *)var;
	int i;

	BUG_ON((u64)var_cast % ORIGIN_SIZE);
	BUG_ON(size % ORIGIN_SIZE);
	for (i = 0; i < size / ORIGIN_SIZE; i++)
		var_cast[i] = origin;
}

// TODO(glider): writing an initialized byte shouldn't zero out the origin, if
// the remaining three bytes are uninitialized.
void kmsan_set_origin(u64 address, int size, u32 origin, bool checked)
{
	void *origin_start;
	u64 page_offset;
	size_t to_fill, pad = 0;

	if (!IS_ALIGNED(address, ORIGIN_SIZE)) {
		pad = address % ORIGIN_SIZE;
		address -= pad;
		size += pad;
	}

	while (size > 0) {
		page_offset = address % PAGE_SIZE;
		to_fill = min(PAGE_SIZE - page_offset, size);
		to_fill = ALIGN(to_fill, ORIGIN_SIZE);
		BUG_ON(!to_fill);
		origin_start = kmsan_get_metadata_or_null(address, to_fill, /*origin*/true);
		if (!origin_start) {
			if (checked) {
				current->kmsan.is_reporting = true;
				kmsan_pr_err("WARNING: not setting origing for %d bytes starting at %px, because the origin is NULL\n", to_fill, address);
				current->kmsan.is_reporting = false;
				BUG();
			}
		} else {
			kmsan_write_aligned_origin(origin_start, to_fill, origin);
		}
		address += to_fill;
		size -= to_fill;
	}
}

static bool is_module_addr(const void *vaddr)
{
	return (vaddr >= MODULES_VADDR) && (vaddr < MODULES_END);
}

void *get_cea_shadow_or_null(const void *addr)
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

void *get_cea_origin_or_null(const void *addr)
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

struct page *vmalloc_to_page_or_null(const void *vaddr)
{
	struct page *page;

	if (!is_vmalloc_addr(vaddr) && !is_module_addr(vaddr))
		return NULL;
	page = vmalloc_to_page(vaddr);
	if (pfn_valid(page_to_pfn(page)))
		return page;
	else
		return NULL;
}

struct page *virt_to_page_or_null(const void *vaddr)
{
	if (my_virt_addr_valid(vaddr))
		return virt_to_page(vaddr);
	else
		return NULL;
}

// TODO(glider): unite with kmsan_alloc_page()?
void kmsan_prep_pages(struct page *page, unsigned int order)
{
	int i;

	for (i = 0; i < 1 << order; i++) {
		page->shadow = 0;
		page->origin = 0;
	}
}
EXPORT_SYMBOL(kmsan_prep_pages);

int order_from_size(unsigned long size)
{
	unsigned long pages = size >> PAGE_SHIFT;

	if (!pages)
		pages = 1;
	if (hweight64(pages) > 1)
		// TODO(glider): round up to the next power of 2.
		// This is a bit excessive.
		return fls(pages);
	else
		return fls(pages) - 1;
}

DEFINE_SPINLOCK(report_lock);

// |deep| is a dirty hack to skip an additional frame when calling
// kmsan_report() from kmsan_copy_to_user().
inline void kmsan_report(void *caller, depot_stack_handle_t origin,
			u64 address, int size, int off_first, int off_last, u64 user_addr, bool deep, int reason)
{
	unsigned long flags;
	struct stack_trace trace;

	if (!kmsan_ready)
		return;
	if (!current->kmsan.allow_reporting)
		return;
	if (is_console_locked() || is_logbuf_locked())
		return;

	// TODO(glider): temporarily disabling reports without origins.
	if (!origin)
		return;

	depot_fetch_stack(origin, &trace);

	current->kmsan.allow_reporting = false; // TODO(glider)
	current->kmsan.is_reporting = true;
	spin_lock_irqsave(&report_lock, flags);
	kmsan_pr_err("==================================================================\n");
	// TODO(glider): inline this properly
	switch (reason) {
		case REASON_ANY:
			kmsan_pr_err("BUG: KMSAN: uninit-value in %pS\n", deep ? kmsan_internal_return_address(2) : kmsan_internal_return_address(1));
			break;
		case REASON_COPY_TO_USER:
			kmsan_pr_err("BUG: KMSAN: kernel-infoleak in %pS\n", deep ? kmsan_internal_return_address(2) : kmsan_internal_return_address(1));
			break;
	}
	dump_stack();
	kmsan_pr_err("\n");

	kmsan_print_origin(origin);

	if (size) {
		kmsan_pr_err("\n");
		if (off_first == off_last)
			kmsan_pr_err("Byte %d of %d is uninitialized\n", off_first, size);
		else
			kmsan_pr_err("Bytes %d-%d of %d are uninitialized\n", off_first, off_last, size);
	}
	if (address)
		kmsan_pr_err("Memory access of size %d starts at %px\n", size, address);
	if (user_addr && reason == REASON_COPY_TO_USER)
		kmsan_pr_err("Data copied to user address %px\n", user_addr);
	kmsan_pr_err("==================================================================\n");
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&report_lock, flags);
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");
	current->kmsan.is_reporting = false;
	current->kmsan.allow_reporting = true;
}

void kmsan_internal_check_memory(const volatile void *addr, size_t size, const void *user_addr, int reason)
{
	unsigned long irq_flags;
	u64 addr64 = (u64)addr;
	unsigned char *shadow = NULL;
	depot_stack_handle_t *origin = NULL;
	depot_stack_handle_t cur_origin = 0, new_origin = 0;
	int cur_off_start = -1;
	int i, chunk_size, pos;

	pos = 0;
	while (pos < size) {
		chunk_size = min(size - pos, PAGE_SIZE - ((addr64 + pos) % PAGE_SIZE));
		shadow = kmsan_get_metadata_or_null(addr64 + pos, chunk_size, /*is_origin*/false);
		if (!shadow) {
			/* This page is untracked. TODO(glider): assert.
			 * If there were uninitialized bytes before, report them.
			 */
			if (cur_origin) {
				ENTER_RUNTIME(irq_flags);
				kmsan_report(_THIS_IP_, cur_origin, addr, size, cur_off_start, pos - 1, user_addr, /*deep*/true, reason);
				LEAVE_RUNTIME(irq_flags);
			}
			cur_origin = 0;
			cur_off_start = -1;
			pos += chunk_size;
			continue;
		}
		for (i = 0; i < chunk_size; i++) {
			if (!shadow[i]) {
				/* This byte is unpoisoned. If there were poisoned bytes before, report them. */
				if (cur_origin) {
					ENTER_RUNTIME(irq_flags);
					kmsan_report(_THIS_IP_, cur_origin, addr, size, cur_off_start, pos + i - 1, user_addr, /*deep*/true, reason);
					LEAVE_RUNTIME(irq_flags);
				}
				cur_origin = 0;
				cur_off_start = -1;
				continue;
			}
			origin = kmsan_get_metadata_or_null(addr64 + pos + i, chunk_size - i, /*is_origin*/true);
			BUG_ON(!origin);
			new_origin = *origin;
			// Encountered new origin - report the previous uninitialized range.
			if (cur_origin != new_origin) {
				if (cur_origin) {
					ENTER_RUNTIME(irq_flags);
					kmsan_report(_THIS_IP_, cur_origin, addr, size, cur_off_start, pos + i - 1, user_addr, /*deep*/true, reason);
					LEAVE_RUNTIME(irq_flags);
				}
				cur_origin = new_origin;
				cur_off_start = pos + i;
			}
		}
		pos += chunk_size;
	}
	BUG_ON(pos != size);
	if (cur_origin) {
		ENTER_RUNTIME(irq_flags);
		kmsan_report(_THIS_IP_, cur_origin, addr, size, cur_off_start, pos - 1, user_addr, /*deep*/true, reason);
		LEAVE_RUNTIME(irq_flags);
	}
}

void kmsan_check_memory(const volatile void *addr, size_t size)
{
	return kmsan_internal_check_memory(addr, size, /*user_addr*/ 0, REASON_ANY);
}
EXPORT_SYMBOL(kmsan_check_memory);

// TODO(glider): this check shouldn't be performed for origin pages, because
// they're always accessed after the shadow pages.
bool metadata_is_contiguous(u64 addr, size_t size, bool is_origin) {
	u64 cur_addr, next_addr, cur_meta_addr, next_meta_addr;
	struct page *cur_page, *next_page;
	depot_stack_handle_t *origin_p;
	for (cur_addr = addr; next_addr < addr + size;
			cur_addr = next_addr, next_addr += PAGE_SIZE) {
		next_addr = cur_addr + PAGE_SIZE;
		cur_page = virt_to_page_or_null(cur_addr);
		next_page = virt_to_page_or_null(next_addr);
		cur_meta_addr = page_address(is_origin ? cur_page->shadow : cur_page->origin);
		next_meta_addr = page_address(is_origin ? next_page->shadow : next_page->origin);
		if (cur_meta_addr != next_meta_addr - PAGE_SIZE) {
			if ((addr < _sdata) || (addr >= _edata)) {
				const char *fname = is_origin ? "shadow" : "origin";
				// Skip reports on __data.
				// TODO(glider): allocate contiguous shadow for __data instead.
				current->kmsan.is_reporting = true;
				kmsan_pr_err("BUG: attempting to access two shadow page ranges.\n");
				dump_stack();

				kmsan_pr_err("\n");
				kmsan_pr_err("Access of size %d at %px.\n", size, addr);
				kmsan_pr_err("Addresses belonging to different ranges are: %px and %px\n", cur_addr, next_addr);
				kmsan_pr_err("page[0].%s: %px, page[1].%s: %px\n", fname, cur_meta_addr, fname, next_meta_addr);
				origin_p = kmsan_get_metadata_or_null(addr, 1, /*is_origin*/true);
				if (origin_p) {
					kmsan_pr_err("Origin: %px\n", *origin_p);
					kmsan_print_origin(*origin_p);
				} else {
					kmsan_pr_err("Origin: unavailable\n");
				}
				current->kmsan.is_reporting = false;
				return false;
			}
		}
	}
	return true;
}

/* TODO(glider): all other shadow getters are broken, so let's write another
 * one. The semantic is pretty straightforward: either return a valid shadow
 * pointer or NULL. The caller must BUG_ON on NULL if he wants to.
 * The return value of this function should not depend on whether we're in the
 * runtime or not.
 */
__always_inline
void *kmsan_get_metadata_or_null(u64 addr, size_t size, bool is_origin)
{
	struct page *page;
	void *ret;
	u64 pad, offset;

	if (is_origin && !IS_ALIGNED(addr, ORIGIN_SIZE)) {
		pad = addr % ORIGIN_SIZE;
		addr -= pad;
		size += pad;
	}

	if (!my_virt_addr_valid(addr)) {
		page = vmalloc_to_page_or_null(addr);
		if (page)
			goto next;
		ret = is_origin ? get_cea_origin_or_null(addr) : get_cea_shadow_or_null(addr);
		if (ret)
			return ret;
	}
	page = virt_to_page_or_null(addr);
	if (!page)
		return NULL;
next:
        if (!page->shadow || !page->origin)
		return NULL;
	offset = addr % PAGE_SIZE;

	if (offset + size - 1 > PAGE_SIZE) {
		/* The access overflows the current page and touches the
		 * subsequent ones. Make sure the shadow/origin pages are also
		 * consequent.
		 */
		if (!metadata_is_contiguous(addr, size, is_origin))
			return NULL;
	}
	ret = page_address(is_origin ? page->origin : page->shadow) + offset;
	return ret;
}

noinline
shadow_origin_ptr_t kmsan_get_shadow_origin_ptr(u64 addr, u64 size, bool store)
{
	shadow_origin_ptr_t ret;
	struct page *page;
	u64 pad, offset, o_offset;
	u64 o_addr = addr;
	void *shadow, *origin;

	if (size > PAGE_SIZE) {
		WARN(1, "size too big in kmsan_get_shadow_origin_ptr(%px, %d, %d)\n", addr, size, store);
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

	if (!IS_ALIGNED(addr, ORIGIN_SIZE)) {
		pad = addr % ORIGIN_SIZE;
		o_addr -= pad;
	}

	if (!my_virt_addr_valid(addr)) {
		page = vmalloc_to_page_or_null(addr);
		if (page)
			goto next;
		if (shadow = get_cea_shadow_or_null(addr)) {
			ret.s = shadow;
			ret.o = get_cea_origin_or_null(o_addr);
			return ret;
		}
	}
	page = virt_to_page_or_null(addr);
	if (!page)
		return ret;
next:
        if (!page->shadow || !page->origin)
		return ret;
	offset = addr % PAGE_SIZE;
	o_offset = o_addr % PAGE_SIZE;

	if (offset + size - 1 > PAGE_SIZE) {
		/* The access overflows the current page and touches the
		 * subsequent ones. Make sure the shadow/origin pages are also
		 * consequent.
		 */
		if (!metadata_is_contiguous(addr, size, /*is_origin*/false))
			return ret;
	}

	shadow = page_address(page->shadow) + offset;
	ret.s = shadow;

	origin = page_address(page->origin) + o_offset;
	ret.o = origin;
	return ret;
}
