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
#include <asm/cpu_entry_area.h>  // for CPU_ENTRY_AREA_MAP_SIZE
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

// Dummy shadow and origin pages to be used when the real metadata is
// unavailable.
// There are separate pages for loads and stores, so that every load returns a
// zero, and every store doesn't affect other stores.
char dummy_shadow_load_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
char dummy_origin_load_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
char dummy_shadow_store_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
char dummy_origin_store_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

bool kmsan_ready = false;
#define KMSAN_STACK_DEPTH 64

#define DUMMY_SHADOW_SIZE (PAGE_SIZE * 2)
static inline char *kmsan_dummy_shadow(bool is_store)
{
	return is_store ? dummy_shadow_store_page : dummy_shadow_load_page;
}

static inline char *kmsan_dummy_origin(bool is_store)
{
	return is_store ? dummy_origin_store_page : dummy_origin_load_page;
}

// According to Documentation/x86/kernel-stacks, kernel code can run on the
// following stacks:
//  - regular task stack - when executing the task code
//  - interrupt stack - when handling external hardware interrupts and softirqs
//  - 
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

// TODO(glider): inline?
kmsan_context_state *task_kmsan_context_state(void)
{
	unsigned long irq_flags;
	int cpu = smp_processor_id();
	int level = this_cpu_read(kmsan_context_level);
	kmsan_context_state *ret;

	if (!kmsan_ready || IN_RUNTIME()) {
		ret = &per_cpu(kmsan_percpu_cstate[0], cpu);
		__memset(ret, 0, sizeof(kmsan_context_state));
		return ret;
	}

	// TODO(glider): no need to enter/leave runtime?
	ENTER_RUNTIME(irq_flags);
	if (!level)
		ret = &current->kmsan.cstate;
	else
		ret = &per_cpu(kmsan_percpu_cstate[level], cpu);
	LEAVE_RUNTIME(irq_flags);
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

// TODO(glider): switch to page_ext. We need to update the kernel version for that.
void inline do_kmsan_thread_create(struct task_struct *task)
{
	kmsan_thread_state *state = &task->kmsan;

#ifdef CONFIG_VMAP_STACK
	// TODO(glider): KMSAN isn't currently compatible with CONFIG_VMAP_STACK.
	// BUG_ON(!virt_addr_valid(task->stack));
#error TODO(glider): KMSAN isn't currently compatible with CONFIG_VMAP_STACK
#endif
	__memset(&state->cstate, 0, sizeof(kmsan_context_state));
	state->enabled = true;
	state->allow_reporting = true;
	state->is_reporting = false;
}
EXPORT_SYMBOL(do_kmsan_thread_create);

inline void kmsan_internal_memset_shadow(u64 address, int b, size_t size)
{
	void *shadow_start;
	u64 page_offset;
	size_t to_fill;

	if (!kmsan_ready)
		/* No need to fill the dummy shadow. */
		return;

	while (size) {
		page_offset = address % PAGE_SIZE;
		to_fill = min_num(PAGE_SIZE - page_offset, size);
		shadow_start = kmsan_get_shadow_address(address, to_fill, /*checked*/true, /*is_store*/true);
		if (!shadow_start) {
			current->kmsan.is_reporting = true;
			kmsan_pr_err("WARNING: not poisoning %d bytes starting at %px, because the shadow is NULL\n", to_fill, address);
			current->kmsan.is_reporting = false;
			BUG();
		}
		__memset(shadow_start, b, to_fill);
		address += to_fill;
		size -= to_fill;
	}
}

void kmsan_internal_poison_shadow(void *address, size_t size, gfp_t flags)
{
	depot_stack_handle_t handle;
	kmsan_internal_memset_shadow((u64)address, -1, size);
	handle = kmsan_save_stack_with_flags(flags);
	kmsan_set_origin((u64)address, size, handle);
}

void kmsan_poison_shadow(void *address, size_t size, gfp_t flags)
{
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_internal_poison_shadow(address, size, flags);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_poison_shadow);

void kmsan_internal_unpoison_shadow(void *address, size_t size)
{
	kmsan_internal_memset_shadow((u64)address, 0, size);
	kmsan_set_origin((u64)address, size, 0);
}

void kmsan_unpoison_shadow(void *address, size_t size)
{
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	kmsan_internal_unpoison_shadow(address, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_unpoison_shadow);


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


void kmsan_memcpy_shadow(u64 dst, u64 src, size_t n)
{
	void *shadow_src, *shadow_dst;
	size_t to_copy, rem_src, rem_dst;
	if (!n || dst == src)
		return;
	BUG_ON(dst + n < dst);
	BUG_ON(src + n < src);
	while (n) {
		rem_src = PAGE_SIZE - (src % PAGE_SIZE);
		rem_dst = PAGE_SIZE - (dst % PAGE_SIZE);
		to_copy = min_num(n, min_num(rem_src, rem_dst));
		shadow_dst = kmsan_get_shadow_address(dst, to_copy, /*checked*/true, /*is_store*/true);
		shadow_src = kmsan_get_shadow_address(src, to_copy, /*checked*/true, /*is_store*/false);
		__memcpy(shadow_dst, shadow_src, to_copy);
		dst += to_copy;
		src += to_copy;
		n -= to_copy;
	}
}

/* TODO(glider): this is crazy. We need to split utility functions into a
 * different file and test them.
 */

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
void kmsan_memmove_shadow(u64 dst, u64 src, size_t n)
{
	// TODO(glider): must be real memmove.
	void *shadow_src, *shadow_dst;
	size_t to_copy, rem_src, rem_dst;
	if (!n || src == dst)
		return;
	if (src > dst) {
		kmsan_memcpy_shadow(dst, src, n);
		return;
	}
	BUG_ON(dst + n < dst);
	BUG_ON(src + n < src);
	/* start with dst+n and src+n, move backwards */
	dst += n;
	src += n;
	while (n) {
		rem_src = src % PAGE_SIZE;
		rem_dst = dst % PAGE_SIZE;
		to_copy = min_num(n, min_num(rem_src, rem_dst));
		shadow_dst = kmsan_get_shadow_address(dst - to_copy, to_copy, /*checked*/true, /*is_store*/true);
		shadow_src = kmsan_get_shadow_address(src - to_copy, to_copy, /*checked*/true, /*is_store*/false);
		__memmove(shadow_dst, shadow_src, to_copy);
		dst -= to_copy;
		src -= to_copy;
		n -= to_copy;
	}
}

/* TODO(glider): overthink this.
 * Ideally, we want a chained origin for each distinct 4-byte slot.
 * Origins are aligned on 4.
 * When copying 1 <= n <= 3 initialized bytes, we need to check that the
 * remaining 4-n bytes are initialized before overwriting the origin (if they
 * are not, no need to overwrite).
 * 3 cases:
 * 1. |dst| and |src| are 4-aligned. Just copy ALIGN(n, 4) origin bytes from
 *    the corresponding origin pages.
 * 2. |dst| is 4-aligned, |src| is not. We can write to at most
 *    [o(dst), (o(dst+ALIGN(n, 4))) bytes, while the interesting source origins
 *    reside at [o(ALIGN_DOWN(src, 4), o(ALIGN(src + n, 4)) ), which is 4 bytes
 *    longer.
 * ... (TODO)
 * The major problem is that there are cases in which N+1 origin slots
 * correspond to N*4 bytes of the kernel memory, so we need to evict one of the
 * origins.
 */
void kmsan_memcpy_origins(u64 dst, u64 src, size_t n)
{
	size_t off, rem_src, rem_dst, to_copy;
	depot_stack_handle_t handle = 0, new_handle = 0;
	depot_stack_handle_t *h_src, *h_dst;
	u32 shadow;
	u32 *shadow_ptr;

	if (!n || dst == src)
		return;
	BUG_ON(dst + n < dst);
	BUG_ON(src + n < src);

	off = src % 4;
	dst = (dst >> 2) << 2;
	src = src - off;
	// In the case |src| isn't aligned on 4, it touches the extra 4 origin bytes.
	// Unfortunately we can't copy more than n bytes.
	n = ALIGN(src + n, 4) - src;
	while (n) {
		rem_src = PAGE_SIZE - (src % PAGE_SIZE);
		rem_dst = PAGE_SIZE - (dst % PAGE_SIZE);
		to_copy = min_num(n, min_num(rem_src, rem_dst));
		h_dst = kmsan_get_origin_address(dst, to_copy, /*checked*/true, /*is_store*/true);
		h_src = kmsan_get_origin_address(src, to_copy, /*checked*/true, /*is_store*/false);

		for (int i = 0; i < to_copy/4; i++) {
			// Make sure we don't copy origins for zero shadow.
			shadow = (u32)-1;
			if (to_copy >= 4) {
				shadow_ptr = kmsan_get_shadow_address(ALIGN(src, 4), 4, /*checked*/true, /*is_store*/false);
				if (shadow_ptr) {
					shadow = *shadow_ptr;
				}
			}
			// TODO(glider): need to check that current origin != previous origin.
			if (*h_src && (*h_src != handle) && shadow) {
				handle = *h_src;
				new_handle = kmsan_internal_chain_origin(handle, /*full*/true);
				if (new_handle) handle = new_handle;
			}
			if (!shadow) {
				*h_dst = 0;
			} else {
				*h_dst = handle;
			}
			h_src++;
			h_dst++;
		}
		dst += to_copy;
		src += to_copy;
		n -= to_copy;
	}
}

void kmsan_memmove_origins(u64 dst, u64 src, size_t n)
{
	size_t off, rem_src, rem_dst, to_copy;
	depot_stack_handle_t handle = 0, new_handle = 0;
	depot_stack_handle_t *h_src, *h_dst;
	u32 shadow;
	u32 *shadow_ptr;

	if (!n || dst == src)
		return;
 	if (src > dst) {
		kmsan_memcpy_origins(dst, src, n);
		return;
	}
	BUG_ON(dst + n < dst);
	BUG_ON(src + n < src);

	off = src % 4;
	dst = (dst >> 2) << 2;
	src = src - off;
	// In the case |src| isn't aligned on 4, it touches the extra 4 origin bytes.
	// Unfortunately we can't copy more than n bytes.
	n = ALIGN(src + n, 4) - src;
	dst += n;
	src += n;
	while (n) {
		rem_src = src % PAGE_SIZE;
		rem_dst = dst % PAGE_SIZE;
		to_copy = min_num(n, min_num(rem_src, rem_dst));
		h_dst = kmsan_get_origin_address(dst - to_copy, to_copy, /*checked*/true, /*is_store*/true);
		h_src = kmsan_get_origin_address(src - to_copy, to_copy, /*checked*/true, /*is_store*/false);

		for (int i = 0; i < to_copy/4; i++) {
			// Make sure we don't copy origins for zero shadow.
			shadow = (u32)-1;
			if (to_copy >= 4) {
				shadow_ptr = kmsan_get_shadow_address(ALIGN(src, 4), 4, /*checked*/true, /*is_store*/false);
				if (shadow_ptr) {
					shadow = *shadow_ptr;
				}
			}
			// TODO(glider): need to check that current origin != previous origin.
			if (*h_src && (*h_src != handle) && shadow) {
				handle = *h_src;
				new_handle = kmsan_internal_chain_origin(handle, /*full*/true);
				if (new_handle) handle = new_handle;
			}
			if (!shadow) {
				*h_dst = 0;
			} else {
				*h_dst = handle;
			}
			h_src--;
			h_dst--;
		}
		dst -= to_copy;
		src -= to_copy;
		n -= to_copy;
	}
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
			} else
			if ((trace.entries[0] & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FRAME) {
				origin = trace.entries[2];
				kmsan_pr_err("Uninit was stored to memory at:\n");
				kmsan_pr_err("%px - %pSR\n", trace.entries[1], trace.entries[1]);
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

#define MAX_CHAIN_DEPTH 7
depot_stack_handle_t inline kmsan_internal_chain_origin(depot_stack_handle_t id, bool full)
{
	depot_stack_handle_t handle;
	unsigned long entries[3];
	struct stack_trace trace = {
		.nr_entries = 3,
		.entries = entries,
		.max_entries = 3,
		.skip = 0
	};
	u64 magic = full ? KMSAN_CHAIN_MAGIC_ORIGIN_FULL : KMSAN_CHAIN_MAGIC_ORIGIN_FRAME;
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
	old_magic = old_trace.entries[0];
	// TODO(glider): just make the chain magics more similar.
	if (((old_magic & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FULL) ||
		((old_magic & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FRAME)) {
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
	if (full) {
		entries[1] = kmsan_save_stack();
	} else {
		entries[1] = (unsigned long)kmsan_internal_return_address(1);
	}
	entries[2] = id;
	handle = depot_save_stack(&trace, GFP_ATOMIC);
	return handle;
}


inline
void kmsan_write_aligned_origin(const void *var, size_t size, u32 origin)
{
	u32 *var_cast = (u32 *)var;
	int i;

	BUG_ON((u64)var_cast % 4);
	BUG_ON(size % 4);
	for (i = 0; i < size / 4; i++)
		var_cast[i] = origin;
}

// TODO(glider): writing an initialized byte shouldn't zero out the origin, if
// the remaining three bytes are uninitialized.
void kmsan_set_origin(u64 address, int size, u32 origin)
{
	void *origin_start;
	u64 page_offset;
	size_t to_fill, pad = 0;

	if (!kmsan_ready) {
		// No need to fill the dummy origin.
		return;
	}
	if (!IS_ALIGNED(address, 4)) {
		pad = address % 4;
		address -= pad;
		size += pad;
	}
	BUG_ON(!IS_ALIGNED(address, 4));
	while (size > 0) {
		page_offset = address % PAGE_SIZE;
		to_fill = (PAGE_SIZE - page_offset > size) ? size : PAGE_SIZE - page_offset;
		to_fill = ALIGN(to_fill, 4);
		BUG_ON(!to_fill);
		origin_start = kmsan_get_origin_address(address, to_fill, /*checked*/true, /*is_store*/true);
		if (!origin_start) {
			current->kmsan.is_reporting = true;
			kmsan_pr_err("WARNING: not setting origing for %d bytes starting at %px, because the origin is NULL\n", to_fill, address);
			current->kmsan.is_reporting = false;
			BUG();
		}
		kmsan_write_aligned_origin(origin_start, to_fill, origin);
		address += to_fill;
		size -= to_fill;
	}
}
EXPORT_SYMBOL(kmsan_set_origin);

void enable_reporting()
{
	current->kmsan.allow_reporting = true;
}
EXPORT_SYMBOL(enable_reporting);


int kmsan_internal_alloc_meta_for_pages(struct page *page, unsigned int order,
		     		unsigned int actual_size, gfp_t flags, int node)
{
	struct page *shadow, *origin;
	int pages = 1 << order;
	int i;
	bool initialized = (flags & __GFP_ZERO) || !kmsan_ready;
	depot_stack_handle_t handle;

	// If |actual_size| is non-zero, we allocate |1 << order| metadata pages
	// for |actual_size| bytes of memory. We can't set shadow for more than
	// |actual_size >> PAGE_SHIFT| pages in that case.
	if (actual_size)
		pages = ALIGN(actual_size, PAGE_SIZE) >> PAGE_SHIFT;

	if (flags & __GFP_NO_KMSAN_SHADOW) {
		for (i = 0; i < pages; i++) {
			page[i].is_kmsan_tracked_page = false;
			// TODO(glider): this is redundant.
			page[i].shadow = NULL;
			page[i].origin = NULL;
		}
		return 0;
	}

	flags = GFP_ATOMIC;  // TODO(glider)
	if (initialized)
		flags |= __GFP_ZERO;
	shadow = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	if (!shadow) {
		for (i = 0; i < pages; i++) {
			page[i].is_kmsan_tracked_page = false;
			// TODO(glider): this is redundant.
			page[i].shadow = NULL;
			page[i].origin = NULL;
		}
		return -ENOMEM;
	}
	if (!initialized)
		__memset(page_address(shadow), -1, PAGE_SIZE * pages);

	origin = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	// Assume we've allocated the origin.
	if (!origin) {
		__free_pages(shadow, order);
		for (i = 0; i < pages; i++) {
			page[i].is_kmsan_tracked_page = false;
			// TODO(glider): this is redundant.
			page[i].shadow = NULL;
			page[i].origin = NULL;
		}
		return -ENOMEM;
	}

	if (!initialized) {
		handle = kmsan_save_stack_with_flags(flags);
		// Addresses are page-aligned, pages are contiguous, so it's ok
		// to just fill the origin pages with |handle|.
		for (i = 0; i < PAGE_SIZE * pages / sizeof(handle); i++) {
			((depot_stack_handle_t*)page_address(origin))[i] = handle;
		}
	}

	for (i = 0; i < pages; i++) {
		// TODO(glider): sometimes page[i].shadow is initialized. Let's skip the check for now.
		///if (page[i].shadow) continue;
		page[i].shadow = &shadow[i];
		page[i].shadow->is_kmsan_tracked_page = false;
		page[i].shadow->shadow = NULL;
		page[i].shadow->origin = NULL;
		// TODO(glider): sometimes page[i].origin is initialized. Let's skip the check for now.
		BUG_ON(page[i].origin && 0);
		// page.origin is struct page.
		page[i].origin = &origin[i];
		page[i].origin->is_kmsan_tracked_page = false;
		page[i].origin->shadow = NULL;
		page[i].origin->origin = NULL;
		page[i].is_kmsan_tracked_page = true;
	}
	return 0;
}


static bool is_module_addr(const void *vaddr)
{
	if (vaddr < MODULES_VADDR)
		return false;
	if (vaddr >= MODULES_END)
		return false;
	return true;
}

// Taken from arch/x86/mm/physaddr.h
// TODO(glider): do we need it?
static inline int my_phys_addr_valid(resource_size_t addr)
{
#ifdef CONFIG_PHYS_ADDR_T_64BIT
	return !(addr >> boot_cpu_data.x86_phys_bits);
#else
	return 1;
#endif
}

// Taken from arch/x86/mm/physaddr.c
// TODO(glider): do we need it?
static bool my_virt_addr_valid(unsigned long x)
{
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

bool is_cpu_entry_area_addr(u64 addr)
{
	return (addr >= CPU_ENTRY_AREA_BASE) && (addr < CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE);
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



// TODO(glider): this is similar to kmsan_clear_user_page().
void kmsan_clear_page(void *page_addr)
{
	struct page *page;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	BUG_ON(!IS_ALIGNED((u64)page_addr, PAGE_SIZE));
	page = vmalloc_to_page_or_null(page_addr);
	if (!page)
		page = virt_to_page_or_null(page_addr);
	if (!page || !page->is_kmsan_tracked_page)
		return;
	if (!page->shadow)
		return;
	__memset(page_address(page->shadow), 0, PAGE_SIZE);
	BUG_ON(!page->origin);
	__memset(page_address(page->origin), 0, PAGE_SIZE);
}
EXPORT_SYMBOL(kmsan_clear_page);

// Clear shadow and origin for a given struct page.
void kmsan_clear_user_page(struct page *page)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	if (!page->is_kmsan_tracked_page)
		return;

	ENTER_RUNTIME(irq_flags);
	__memset(page_address(page->shadow), 0, PAGE_SIZE);
	__memset(page_address(page->origin), 0, PAGE_SIZE);
	LEAVE_RUNTIME(irq_flags);
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
#define MAX_REPORTS 12800
static void *reporters_tbl[MAX_REPORTS];
static int reporters_index = 0;
static void *locals_tbl[MAX_REPORTS];
static int locals_index = 0;

// TODO(glider): thread-unsafe, need a hashmap
bool reported_already(void *caller, void **table)
{
	return false;
	for (int i = 0; i < MAX_REPORTS; i++)
		if (table[i] == caller) {
			return true;
		}
	return false;
}

// Works under report_lock, but thread-unsafe because of reported_already().
void save_reporter(void *caller, void **table, int *index)
{
	if (*index >= MAX_REPORTS)
		return;
	table[(*index)++] = caller;
}

// |deep| is a dirty hack to skip an additional frame when calling
// kmsan_report() from kmsan_copy_to_user().
inline void kmsan_report(void *caller, depot_stack_handle_t origin,
			u64 address, int size, int off_first, int off_last, bool deep, int reason)
{
	unsigned long flags;
	struct stack_trace trace;
	char *descr = NULL;

	if (!kmsan_ready)
		return;
	if (!current->kmsan.allow_reporting)
		return;
	if (reported_already(caller, reporters_tbl))
		return;
	if (is_console_locked() || is_logbuf_locked())
		return;

	// TODO(glider): temporarily disabling reports without origins.
	if (!origin)
		return;

	depot_fetch_stack(origin, &trace);
	if ((trace.nr_entries == 4) && trace.entries[0] == KMSAN_ALLOCA_MAGIC_ORIGIN) {
		// TODO(glider): this is just to skip uniniteresting reports at the prototype stage.
		// There can be actual bugs with duplicate descriptions.
		descr = (char*)trace.entries[1];
		if (descr) {
			if (reported_already(descr, locals_tbl))
				return;
			save_reporter(descr, locals_tbl, &locals_index);
		}
	}

	current->kmsan.allow_reporting = false; // TODO(glider)
	current->kmsan.is_reporting = true;
	spin_lock_irqsave(&report_lock, flags);
	save_reporter(caller, reporters_tbl, &reporters_index);
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
	if (address) {
		kmsan_pr_err("Memory access starts at %px\n", address);
	}
	kmsan_pr_err("==================================================================\n");
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&report_lock, flags);
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");
	current->kmsan.is_reporting = false;
	current->kmsan.allow_reporting = true;
}


inline
void kmsan_internal_check_memory(const void *addr, size_t size, int reason)
{
	unsigned long irq_flags;
	char *shadow;
	depot_stack_handle_t origin = 0, prev_origin = 0;
	size_t i, prev_start = -1;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	shadow = kmsan_get_shadow_address(addr, size, /*checked*/true, /*is_store*/false);
	if (!shadow) {
		// TODO(glider): do we need to report an error here?
		LEAVE_RUNTIME(irq_flags);
		return;
	}
	for (i = 0; i < size; i++) {
		if (!shadow[i]) {
			if (prev_start != -1)
				kmsan_report(_THIS_IP_, prev_origin, addr, size, prev_start, i - 1, /*deep*/true, reason);
			prev_origin = 0;
			prev_start = -1;
			continue;
		}
		// Not checking for the second time.
		origin = *(depot_stack_handle_t*)kmsan_get_origin_address(addr + i, size, /*checked*/false, /*is_store*/false);
		if (prev_start == -1) {
			prev_start = i;
			prev_origin = origin;
			continue;
		}
		if (origin != prev_origin) {
			kmsan_report(_THIS_IP_, prev_origin, addr, size, prev_start, i - 1, /*deep*/true, reason);
			prev_origin = origin;
			prev_start = i;
		}
	}
	if (prev_origin) {
		kmsan_report(_THIS_IP_, prev_origin, addr, size, prev_start, size - 1, /*deep*/true, reason);
	}
	LEAVE_RUNTIME(irq_flags);
}

void kmsan_check_memory(const void *addr, size_t size)
{
	return kmsan_internal_check_memory(addr, size, REASON_ANY);
}
EXPORT_SYMBOL(kmsan_check_memory);



// TODO(glider): this check shouldn't be performed for origin pages, because
// they're always accessed after the shadow pages.
bool metadata_is_contiguous(u64 addr, size_t size, bool is_origin) {
	u64 cur_addr, next_addr, cur_meta_addr, next_meta_addr;
	struct page *cur_page, *next_page;
	depot_stack_handle_t origin;
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
				origin = *(depot_stack_handle_t*)kmsan_get_origin_address(addr, 1, /*checked*/false, /*is_store*/false);
				kmsan_pr_err("Origin: %px\n", origin);
				kmsan_print_origin(origin);
				current->kmsan.is_reporting = false;
				return false;
			}
		}
	}
	return true;
}

// TODO(glider): do we want to inline this into kmsan_instr.c?
inline
void *kmsan_get_shadow_address(u64 addr, size_t size, bool checked, bool is_store)
{
	struct page *page;
	unsigned long offset;
	void *ret;

	// TODO(glider): refactor this code.
	if (!my_virt_addr_valid(addr)) {
		///kmsan_pr_err("not a valid virtual address: %px\n", addr);
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy shadow size further.
		page = vmalloc_to_page_or_null(addr);
		if (page)
			goto next;
		ret = get_cea_shadow_or_null(addr);
		if (ret)
			return ret;
		if (size > PAGE_SIZE) {
			WARN(1, "kmsan_get_shadow_address(%px, %d, %d)\n", addr, size, checked);
			if (checked)
				BUG();
			else
				return NULL;
		}
		return kmsan_dummy_shadow(is_store);
	}

 	page = virt_to_page_or_null(addr);
	if (!page) {
		current->kmsan.is_reporting = true;
		kmsan_pr_err("No page for address %px\n", addr);
		current->kmsan.is_reporting = false;
		return kmsan_dummy_shadow(is_store);
	}
next:
	if (!page->is_kmsan_tracked_page)
		return kmsan_dummy_shadow(is_store);
	if (!page->shadow) {
		oops_in_progress = 1;
		current->kmsan.is_reporting = true;
		kmsan_pr_err("Not allocated shadow for addr %px (page %px)\n", addr, page);
		kmsan_pr_err("Attempted to access %d bytes\n", size);
		BUG();
		current->kmsan.is_reporting = false;
	}
	offset = addr % PAGE_SIZE;

	if (checked && (offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the
		 * subsequent ones. Make sure the shadow pages are also
		 * consequent.
		 */
		if (!metadata_is_contiguous(addr, size, /*is_origin*/false)) {
			return kmsan_dummy_shadow(is_store);
		}

	}
	ret = page_address(page->shadow) + offset;
	return ret;
}


// TODO(glider): do we want to inline this into kmsan_instr.c?
// TODO(glider): either delete kmsan_get_shadow_address() or refactor.
/* kmsan_get_shadow_address_noruntime() must not be called from within runtime. */
inline
void *kmsan_get_shadow_address_noruntime(u64 addr, size_t size, bool checked)
{
	struct page *page;
	unsigned long offset;
	void *ret;
	unsigned long irq_flags;

	// TODO(glider): refactor this code.
	if (!my_virt_addr_valid(addr)) {
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy shadow size further.
		page = vmalloc_to_page_or_null(addr);
		if (page)
			goto next;
		ret = get_cea_shadow_or_null(addr);
		if (ret)
			return ret;
		if (size > PAGE_SIZE) {
			WARN(1, "kmsan_get_shadow_address_noruntime(%px, %d, %d)\n", addr, size, checked);
			if (checked)
				BUG();
			else
				return NULL;
		}
		return NULL;
	}


	page = virt_to_page_or_null(addr);
	if (!page) {
		return NULL;
		ENTER_RUNTIME(irq_flags);
		current->kmsan.is_reporting = true;
		kmsan_pr_err("No page for address %px\n", addr);
		current->kmsan.is_reporting = false;
		LEAVE_RUNTIME(irq_flags);
		return NULL;
	}
next:
	if (!(page->shadow)) {
		ENTER_RUNTIME(irq_flags);
		oops_in_progress = 1;
		kmsan_pr_err("Not allocated shadow for addr %px (page %px)\n", addr, page);
		BUG();
		LEAVE_RUNTIME(irq_flags);
	}
	offset = addr % PAGE_SIZE;

	if (checked && (offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the next
		 * one. Make sure the shadow pages are also consequent.
		 */
		if (!metadata_is_contiguous(addr, size, /*is_origin*/false)) {
			return NULL;
		}
	}
	ret = page_address(page->shadow) + offset;
	return ret;
}

/* kmsan_get_origin_address_noruntime() must not be called from within runtime. */
inline
void *kmsan_get_origin_address_noruntime(u64 addr, size_t size, bool checked)
{
	struct page *page;
	unsigned long offset;
	void *ret;
	unsigned long irq_flags;
	size_t pad;

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
		addr -= pad;
		size += pad;
	}

	// TODO(glider): refactor this code.
	if (!my_virt_addr_valid(addr)) {
		///kmsan_pr_err("not a valid virtual address: %px\n", addr);
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy origin size further.
		page = vmalloc_to_page_or_null(addr);
		if (page)
			goto next;
		ret = get_cea_origin_or_null(addr);
		if (ret)
			return ret;
		if (size > PAGE_SIZE) {
			WARN(1, "kmsan_get_origin_address_noruntime(%px, %d, %d)\n", addr, size, checked);
			if (checked)
				BUG();
			else
				return NULL;
		}
		return NULL;
	}

	page = virt_to_page_or_null(addr);
	if (!page) {
		return NULL;
		ENTER_RUNTIME(irq_flags);
		current->kmsan.is_reporting = true;
		kmsan_pr_err("No page for address %px\n", addr);
		current->kmsan.is_reporting = false;
		LEAVE_RUNTIME(irq_flags);
		return NULL;
	}
next:
	if (!(page->origin)) {
		ENTER_RUNTIME(irq_flags);
		oops_in_progress = 1;
		kmsan_pr_err("Not allocated origin for addr %px (page %px)\n", addr, page);
		BUG();
		LEAVE_RUNTIME(irq_flags);
	}
	offset = addr % PAGE_SIZE;

	if (checked && (offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the next
		 * one. Make sure the origin pages are also consequent.
		 */
		if (!metadata_is_contiguous(addr, size, /*is_origin*/true)) {
			return NULL;
		}
	}
	ret = page_address(page->origin) + offset;
	return ret;
}


inline
void *kmsan_get_origin_address(u64 addr, size_t size, bool checked, bool is_store)
{
	struct page *page;
	u64 offset;
	int pad = 0;
	void *ret;

	// TODO(glider): refactor this code.
	if (!my_virt_addr_valid(addr)) {
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy origin size further.
		page = vmalloc_to_page_or_null(addr);
		if (page)
			goto next;
		ret = get_cea_origin_or_null(addr);
		if (ret)
			return ret;
		if (size > PAGE_SIZE) {
			WARN(1, "kmsan_get_origin_address(%px, %d, %d)\n", addr, size, checked);
			if (checked)
				BUG();
			else
				return NULL;
		}
		return kmsan_dummy_origin(is_store);
	}


 	page = virt_to_page_or_null(addr);
	if (!page) {
		current->kmsan.is_reporting = true;
		kmsan_pr_err("No page for address %px\n", addr);
		current->kmsan.is_reporting = false;
	}
next:
	if (!page->is_kmsan_tracked_page)
		return kmsan_dummy_origin(is_store);
	if (!IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
		addr -= pad;
		size += pad;
	}
	offset = (addr % PAGE_SIZE);
	if (!page->origin) {
		kmsan_pr_err("No origin for address %px (page %px), size=%d\n", addr, page, size);
		BUG_ON(page->shadow);
		BUG_ON(!page->origin);
	}
	if (!page->origin) {
		oops_in_progress = 1;
		kmsan_pr_err("No origin for address %px (page %px)\n", addr, page);
		BUG_ON(!page->origin);
	}
	/* TODO(glider): this is conservative. */
	if (checked && (offset + size - 1 > PAGE_SIZE)) {
		if (!metadata_is_contiguous(addr, size, /*is_origin*/true)) {
			return kmsan_dummy_origin(is_store);
		}
	}
	ret = page_address(page->origin) + offset;
	BUG_ON(!IS_ALIGNED((u64)ret, 4));
	return ret;
}
