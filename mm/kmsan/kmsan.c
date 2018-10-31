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

	if (!kmsan_ready)
		// No need to fill the dummy origin.
		return;
	if (!IS_ALIGNED(address, 4)) {
		pad = address % 4;
		address -= pad;
		size += pad;
	}

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

	__memset(page_address(page->shadow), 0, PAGE_SIZE);
	__memset(page_address(page->origin), 0, PAGE_SIZE);
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
	if (address)
		kmsan_pr_err("Memory access of size %d starts at %px\n", size, address);
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
	unsigned char *shadow_page = (unsigned char *)-1;
	depot_stack_handle_t origin = 0, prev_origin = 0;
	size_t i, prev_start = -1, tail_size;
	u64 addr64 = (u64)addr;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	for (i = 0; i < size; i++) {
		/* Shadow pages aren't necessarily contiguous, e.g. for a vmalloc()'ed region. */
		if ((shadow_page == (unsigned char *)-1) || ((addr64 + i) % PAGE_SIZE == 0)) {
			if (shadow_page == (unsigned char *)-1) {
				tail_size = min_num(size, PAGE_SIZE - (addr64 % PAGE_SIZE));
			} else {
				tail_size = min_num(size - i, PAGE_SIZE);
			}
			ENTER_RUNTIME(irq_flags);
			shadow_page = kmsan_get_shadow_address(addr64 + i, tail_size, /*checked*/true, /*is_store*/false);
			shadow_page = ALIGN_DOWN((u64)shadow_page, PAGE_SIZE);
			LEAVE_RUNTIME(irq_flags);
		}
		if (!shadow_page)
			/* TODO(glider): make sure the page is untracked. */
			continue;
		if (!shadow_page[(addr64 + i) % PAGE_SIZE]) {
			if (prev_start != -1) {
				ENTER_RUNTIME(irq_flags);
				kmsan_report(_THIS_IP_, prev_origin, addr, size, prev_start, i - 1, /*deep*/true, reason);
				LEAVE_RUNTIME(irq_flags);
			}
			prev_origin = 0;
			prev_start = -1;
			continue;
		}
		// Not checking for the second time.
		ENTER_RUNTIME(irq_flags);
		origin = *(depot_stack_handle_t*)kmsan_get_origin_address(addr64 + i, min_num(sizeof(depot_stack_handle_t), size - i), /*checked*/false, /*is_store*/false);
		LEAVE_RUNTIME(irq_flags);
		if (prev_start == -1) {
			prev_start = i;
			prev_origin = origin;
			continue;
		}
		if (origin != prev_origin) {
			ENTER_RUNTIME(irq_flags);
			kmsan_report(_THIS_IP_, prev_origin, addr, size, prev_start, i - 1, /*deep*/true, reason);
			LEAVE_RUNTIME(irq_flags);
			prev_origin = origin;
			prev_start = i;
		}
	}
	if (prev_origin) {
		ENTER_RUNTIME(irq_flags);
		kmsan_report(_THIS_IP_, prev_origin, addr, size, prev_start, size - 1, /*deep*/true, reason);
		LEAVE_RUNTIME(irq_flags);
	}
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

	if (is_origin && !IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
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
	if (!page->is_kmsan_tracked_page)
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
	u64 o_size = size;
	void *shadow, *origin;

	if (size > PAGE_SIZE) {
		WARN(1, "size too big in kmsan_get_shadow_origin_ptr(%px, %d, %d)\n", addr, size, store);
		//BUG();
		ret.s = NULL;
		ret.o = NULL;
		return ret;
	}
	if (store) {
		ret.s = dummy_shadow_store_page;
		ret.o = dummy_origin_store_page;
	} else {
		ret.s = dummy_shadow_load_page;
		ret.o = dummy_origin_load_page;
	}
	if (!kmsan_ready || IN_RUNTIME()) {
		return ret;
	}

	if (!IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
		o_addr -= pad;
		o_size += pad;
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
	if (!page->is_kmsan_tracked_page)
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
	if (!shadow)
		return ret;
	ret.s = shadow;

	origin = page_address(page->origin) + o_offset;
	// origin cannot be NULL, because shadow is already non-NULL.
	BUG_ON(!origin);
	ret.o = origin;
	return ret;
}
EXPORT_SYMBOL(kmsan_get_shadow_origin_ptr);


inline
void *kmsan_get_shadow_address(u64 addr, size_t size, bool checked, bool is_store)
{
	void *shadow = kmsan_get_metadata_or_null(addr, size, /*is_origin*/false);

	if (shadow)
		return shadow;
	if (size <= PAGE_SIZE) {
		// TODO(glider): shall we report a bug on |checked| here?
		return kmsan_dummy_shadow(is_store);
	} else {
		BUG_ON(checked);
		return NULL;
	}
}

inline
void *kmsan_get_origin_address(u64 addr, size_t size, bool checked, bool is_store)
{
	void *origin;
	u64 offset, pad;

	origin = kmsan_get_metadata_or_null(addr, size, /*is_origin*/true);

	if (origin)
		return origin;
	if (size <= PAGE_SIZE) {
		// TODO(glider): shall we report a bug on |checked| here?
		return kmsan_dummy_origin(is_store);
	} else {
		BUG_ON(checked);
		return NULL;
	}
}
