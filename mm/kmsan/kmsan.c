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
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/types.h>

#include <linux/mmzone.h>

#include "../slab.h"
#include "kmsan.h"

// shadow page stats
atomic_t alloc_calls = ATOMIC_INIT(0), free_calls = ATOMIC_INIT(0);
atomic_t meta_alloc_calls = ATOMIC_INIT(0), meta_free_calls = ATOMIC_INIT(0);

extern char __irqentry_text_end[];
extern char __irqentry_text_start[];
extern char __softirqentry_text_end[];
extern char __softirqentry_text_start[];

bool kmsan_ready = false;
bool kmsan_threads_ready = false;
bool use_chained_origins = true;  // TODO(glider)
#define KMSAN_STACK_DEPTH 64

#define DUMMY_SHADOW_SIZE (PAGE_SIZE * 2)
char kmsan_dummy_shadow[DUMMY_SHADOW_SIZE];
char kmsan_dummy_origin[DUMMY_SHADOW_SIZE];

void *kmsan_dummy_retval_tls[RETVAL_SIZE/sizeof(void*)];
u64 kmsan_dummy_va_arg_overflow_size_tls;
void *kmsan_dummy_va_arg_tls[PARAM_SIZE/sizeof(void*)];
void *kmsan_dummy_param_tls[PARAM_SIZE/sizeof(void*)];
depot_stack_handle_t kmsan_dummy_origin_tls;
depot_stack_handle_t kmsan_dummy_param_origin_tls[PARAM_SIZE/sizeof(depot_stack_handle_t)];
depot_stack_handle_t kmsan_dummy_retval_origin_tls;

extern int oops_in_progress;

extern bool logbuf_lock_is_locked;
bool is_logbuf_locked(void)
{
	return logbuf_lock_is_locked;
}
EXPORT_SYMBOL(is_logbuf_locked);

int task_tls_index()
{
	// TODO(glider): more than two indices.
	int preempt = preempt_count();
	if (preempt & HARDIRQ_MASK) {
		return 1;
	} else if (preempt & SOFTIRQ_OFFSET) {  // Sic!
		return 2;
	} else if (preempt & NMI_MASK) {
		return 3;
	}
	return 0;
}
EXPORT_SYMBOL(task_tls_index);

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
// |size| in bytes, always less than one page.
void *kmsan_alloc_internal(size_t size, gfp_t flags)
{
	size_t order = 0;
	void *ret;
	struct page *page;
	if (size > (1 << order) * PAGE_SIZE) {
		current->kmsan.is_reporting = true;
		kmsan_pr_err("size: %d, order: %d\n", size, order);
		current->kmsan.is_reporting = false;
		BUG();
	}
	flags = GFP_ATOMIC;
	page = alloc_pages(flags | __GFP_ZERO | __GFP_NO_KMSAN_SHADOW, order);
	BUG_ON(!page);
	BUG_ON(!page_address(page));
	return page_address(page);
}

void kmsan_free_internal(void *ptr)
{
	size_t order = 0;  // TODO(glider): we're only allocating buffers <= PAGE_SIZE
	free_pages(ptr, order);
}

void inline do_kmsan_thread_create(struct task_struct *task)
{
	int i;
	kmsan_thread_state *state = &task->kmsan;

	///kmsan_pr_err("in do_kmsan_thread_create(%p), pid=%d, current: %p, pid=%d task.stack: %p\n", task, task->pid, current, current->pid, task->stack);
#ifdef CONFIG_VMAP_STACK
	// TODO(glider): KMSAN isn't currently compatible with CONFIG_VMAP_STACK.
	// BUG_ON(!virt_addr_valid(task->stack));
#error TODO(glider): KMSAN isn't currently compatible with CONFIG_VMAP_STACK
#endif
	for (i = 0; i < KMSAN_NUM_SHADOW_STACKS; i++) {
		state->retval_tls[i] = kmsan_alloc_internal(RETVAL_SIZE, GFP_KERNEL);
		state->va_arg_overflow_size_tls[i] = 0;
		state->va_arg_tls[i] = kmsan_alloc_internal(PARAM_SIZE, GFP_KERNEL);
		state->param_tls[i] = kmsan_alloc_internal(PARAM_SIZE, GFP_KERNEL);
		state->origin_tls[i] = 0;
		state->param_origin_tls[i] = kmsan_alloc_internal(PARAM_SIZE, GFP_KERNEL);
		state->retval_origin_tls[i] = 0;
	}
	state->enabled = true;
	state->allow_reporting = true;
	state->is_reporting = false;
}
EXPORT_SYMBOL(do_kmsan_thread_create);

void kmsan_task_exit(struct task_struct *task)
{
	unsigned long irq_flags;
	int i;
	kmsan_thread_state *state = &task->kmsan;
	///kmsan_pr_err("in kmsan_task_exit(%p), pid=%d, current: %p, pid=%d\n", task, task->pid, current, current->pid);
	if (!kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	///for (i = 0; i < KMSAN_NUM_SHADOW_STACKS; i++) {
	// TODO(glider): not deleting IRQ arrays here.
	// We must allocate one per-CPU array for IRQs and softirqs instead of per-task ones.
	for (i = 0; i < 1; i++) {
		break;  // TODO(glider);
		kmsan_free_internal(state->retval_tls[i]);
		state->va_arg_overflow_size_tls[i] = 0;
		kmsan_free_internal(state->va_arg_tls[i]);
		kmsan_free_internal(state->param_tls[i]);
		state->origin_tls[i] = 0;
		kmsan_free_internal(state->param_origin_tls[i]);
		state->retval_origin_tls[i] = 0;
	}
	state->enabled = false;
	state->allow_reporting = false;
	state->is_reporting = false;

	LEAVE_RUNTIME(irq_flags);
}

// TODO(glider): rename (underscores, kmsan).
void __msan_init(void) {
	return;
}
EXPORT_SYMBOL(__msan_init);

bool unused_msan_check_range(void *addr, size_t size, int from)
{
	int i;
	char *shadow;
	unsigned long irq_flags;
	bool ret = false;

	if (!addr || !kmsan_ready || IN_RUNTIME())
		return ret;
	ENTER_RUNTIME(irq_flags);
	shadow = (char*)kmsan_get_shadow_address((u64)addr, size, /*checked*/true); // TODO(glider)
	current->kmsan.is_reporting = true;

	for (i = 0; i < size; i++) {
		if (shadow[i]) {
			kmsan_pr_err("msan_check_range(%p, %d) starting from %p @ %d\n", addr, size, shadow, from);
			ret = true;
			break;
		}
	}
	for (i = 0; i < size; i++) {
		if (shadow[i])
			kmsan_pr_err("shadow of %p = %d @ %d\n", ((char*)addr) + i, shadow[i], from);
	}
	current->kmsan.is_reporting = false;
	LEAVE_RUNTIME(irq_flags);
	return ret;
}
EXPORT_SYMBOL(unused_msan_check_range);

#define min_num(x,y) ((x) < (y) ? x : y)
inline void kmsan_internal_memset_shadow(u64 address, int b, size_t size)
{
	void *shadow_start;
	u64 page_offset;
	size_t to_fill;

	if (!kmsan_ready) {
		// No need to fill the dummy shadow.
		return;
	}

	while (size) {
		page_offset = address % PAGE_SIZE;
		to_fill = min_num(PAGE_SIZE - page_offset, size);
		shadow_start = kmsan_get_shadow_address(address, to_fill, true);
		if (!shadow_start) {
			current->kmsan.is_reporting = true;
			kmsan_pr_err("WARNING: not poisoning %d bytes starting at %p, because the shadow is NULL\n", to_fill, address);
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

void kmsan_poison_slab(struct page *page, gfp_t flags)
{
	unsigned long irq_flags;
	depot_stack_handle_t handle;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	///kmsan_pr_err("kmsan_poison_slab(%p[%p])\n", page_address(page), page);
	if (flags & __GFP_ZERO) {
		kmsan_internal_unpoison_shadow(page_address(page), PAGE_SIZE << compound_order(page));
	} else {
		kmsan_internal_poison_shadow(page_address(page), PAGE_SIZE << compound_order(page), flags);
	}
	LEAVE_RUNTIME(irq_flags);
}

void kmsan_slab_setup_object(struct kmem_cache *s, void *object)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	/* We are about to call the object constructor. Prior to that the
	 * object is supposed to be uninitialized.
	 */
	kmsan_internal_unpoison_shadow(object, s->object_size);
	LEAVE_RUNTIME(irq_flags);
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

void kmsan_kmalloc(struct kmem_cache *cache, const void *object, size_t size,
		   gfp_t flags)
{
	depot_stack_handle_t handle;
	unsigned long irq_flags;

	if (unlikely(object == NULL))
		return;
	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	if (flags & __GFP_ZERO) {
		// TODO(glider) do we poison by default?
		kmsan_internal_unpoison_shadow((void *)object, size);
	} else {
		kmsan_internal_poison_shadow((void *)object, size, flags);
	}
	LEAVE_RUNTIME(irq_flags);
}

void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
{
	kmsan_kmalloc(s, object, s->object_size, flags);
}

void kmsan_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
			size_t size, void *object)
{
	kmsan_kmalloc(s, object, size, flags);
}

bool kmsan_slab_free(struct kmem_cache *s, void *object)
{
	/* RCU slabs could be legally used after free within the RCU period */
	if (unlikely(s->flags & SLAB_DESTROY_BY_RCU))
		return false;
	kmsan_internal_poison_shadow((void *)object, s->object_size, GFP_KERNEL);
	return true;
}

void kmsan_kfree_large(const void *ptr)
{
	depot_stack_handle_t handle;
	struct page *page;
	unsigned long irq_flags;

	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	page = virt_to_page(ptr);
	kmsan_internal_poison_shadow((void*)ptr, PAGE_SIZE << compound_order(page), GFP_KERNEL);
	// TODO(glider): delete?
	handle = kmsan_save_stack();
	kmsan_set_origin((u64)ptr, PAGE_SIZE << compound_order(page), handle);
	LEAVE_RUNTIME(irq_flags);
}

void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
{
	depot_stack_handle_t handle;
	unsigned long irq_flags;

	if (unlikely(ptr == NULL))
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_internal_poison_shadow((void*)ptr, size, flags);
	// TODO(glider): delete?
	handle = kmsan_save_stack_with_flags(flags);
	kmsan_set_origin((u64)ptr, size, handle);
	LEAVE_RUNTIME(irq_flags);
}

void kmsan_memcpy_shadow(u64 dst, u64 src, size_t n)
{
	void *shadow_src, *shadow_dst;
	size_t to_copy, rem_src, rem_dst;
	if (!n)
		return;
	while (n) {
		rem_src = PAGE_SIZE - (src % PAGE_SIZE);
		rem_dst = PAGE_SIZE - (dst % PAGE_SIZE);
		to_copy = min_num(n, min_num(rem_src, rem_dst));
		shadow_dst = kmsan_get_shadow_address(dst, to_copy, true);
		shadow_src = kmsan_get_shadow_address(src, to_copy, true);
		__memcpy(shadow_dst, shadow_src, to_copy);
		dst += to_copy;
		src += to_copy;
		n -= to_copy;
	}
}

// memcpy(shadow(dst), src, n). The destination may not be contiguous.
void kmsan_memcpy_mem_to_shadow(u64 dst, u64 src, size_t n)
{
	void *shadow_dst;
	size_t to_copy, rem_dst;
	if (!n)
		return;
	while (n) {
		rem_dst = PAGE_SIZE - (dst % PAGE_SIZE);
		to_copy = min_num(n, rem_dst);
		shadow_dst = kmsan_get_shadow_address(dst, to_copy, true);
		__memcpy(shadow_dst, src, to_copy);
		dst += to_copy;
		src += to_copy;
		n -= to_copy;
	}
}

// memcpy(dst, shadow(src), n). The source may not be contiguous.
void kmsan_memcpy_shadow_to_mem(u64 dst, u64 src, size_t n)
{
	void *shadow_src;
	size_t to_copy, rem_src;
	if (!n)
		return;
	while (n) {
		rem_src = PAGE_SIZE - (src % PAGE_SIZE);
		to_copy = min_num(n, rem_src);
		shadow_src = kmsan_get_shadow_address(src, to_copy, true);
		__memcpy(dst, shadow_src, to_copy);
		dst += to_copy;
		src += to_copy;
		n -= to_copy;
	}
}

// TODO(glider): overthink this.
// Ideally, we want a chained origin for each distinct 4-byte slot.
// Origins are aligned on 4
void kmsan_memcpy_origins(u64 dst, u64 src, size_t n)
{
	void *origin_src, *origin_dst;
	size_t off, rem_src, rem_dst, to_copy;
	bool printed = false;
	depot_stack_handle_t handle = 0, new_handle = 0;
	depot_stack_handle_t *h_src, *h_dst;
	u64 old_dst = dst, old_src = src;
	size_t old_n = n;

	if (!n)
		return;

	off = src % 4;
	dst = (dst >> 2) << 2;
	src = src - off;
	n = ALIGN(n + off, 4);
	while (n) {
		rem_src = PAGE_SIZE - (src % PAGE_SIZE);
		rem_dst = PAGE_SIZE - (dst % PAGE_SIZE);
		to_copy = min_num(n, min_num(rem_src, rem_dst));
		h_dst = kmsan_get_origin_address(dst, to_copy, true);
		h_src = kmsan_get_origin_address(src, to_copy, true);

		for (int i = 0; i < to_copy/4; i++) {
			if (*h_src && (*h_src != handle)) {
				handle = *h_src;
				new_handle = kmsan_internal_chain_origin(handle, /*full*/true);
				if (new_handle) handle = new_handle;
			}
			*h_dst = handle;
			h_src++;
			h_dst++;
		}
		dst += to_copy;
		src += to_copy;
		n -= to_copy;
	}
}

void kmsan_memmove_shadow(u64 dst, u64 src, size_t n)
{
	// TODO(glider): must be real memmove.
	kmsan_memcpy_shadow(dst, src, n);
}

void kmsan_memmove_origins(u64 dst, u64 src, size_t n)
{
	// TODO(glider): must be real memmove.
	kmsan_memcpy_origins(dst, src, n);
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
	static int skipped;

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
		if (skipped % 10000 == 0)
		kmsan_pr_err("not chained %d origins\n", skipped);
		return id;
	}
	depth++;
	// TODO(glider): how do we figure out we've dropped some frames?
	entries[0] = magic + depth;
	if (full) {
		entries[1] = kmsan_save_stack();
	} else {
		entries[1] = (unsigned long)__builtin_return_address(1);
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
#if 1
		origin_start = kmsan_get_origin_address(address, to_fill, true);
		if (!origin_start) {
			current->kmsan.is_reporting = true;
			kmsan_pr_err("WARNING: not setting origing for %d bytes starting at %p, because the origin is NULL\n", to_fill, address);
			current->kmsan.is_reporting = false;
			BUG();
		}
		kmsan_write_aligned_origin(origin_start, to_fill, origin);
#endif
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


void kmsan_thread_create(struct task_struct *task)
{
	unsigned long irq_flags;

	ENTER_RUNTIME(irq_flags);
	do_kmsan_thread_create(task);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_thread_create);

extern char __bss_stop[];
int kmsan_alloc_meta_for_pages(struct page *page, unsigned int order,
		     		gfp_t flags, int node)
{
	struct page *shadow, *origin;
	int pages = 1 << order;
	int i;

	if (flags & __GFP_NO_KMSAN_SHADOW) {
		for (i = 0; i < pages; i++)
			page->is_kmsan_untracked_page = true;
		return 0;
	}

	if (page->is_kmsan_untracked_page)
		return 0;

	flags = GFP_ATOMIC;  // TODO(glider)
	shadow = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	if (!shadow) {
		page->is_kmsan_untracked_page = true;
		return -ENOMEM;
	}
	atomic_add(pages, &meta_alloc_calls);
	__memset(page_address(shadow), 0, PAGE_SIZE * pages);

	//if (kmsan_ready)
	//	kmsan_pr_err("allocated shadow for %p-%p\n", (char*)page_address(page), page_address(page) + pages * PAGE_SIZE);

	origin = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	atomic_add(pages, &meta_alloc_calls);
	///kmsan_pr_err("allocated origin %p-%p\n", (char*)page_address(origin), page_address(origin) + pages * PAGE_SIZE);
	// Assume we've allocated the origin.
	if (!origin) {
		__free_pages(shadow, order);
		page->is_kmsan_untracked_page = true;
		return -ENOMEM;
	}
	__memset(page_address(origin), 0, PAGE_SIZE * pages);
	// TODO(glider): this is racy, need to set shadow & origin atomically
	// for a page.
	// Or not? Nobody's using this page.
	for (i = 0; i < pages; i++) {
		// TODO(glider): sometimes page[i].shadow is initialized. Let's skip the check for now.
		if (page[i].shadow && 0) {
			kmsan_pr_err("page[%d].shadow=%p (should be 0), page[%d] points to %p\n", i, page[i].shadow, i, page_address(&page[i]));
			BUG();
		}
		///if (page[i].shadow) continue;
		page[i].shadow = &shadow[i];
		page[i].shadow->is_kmsan_untracked_page = true;
		page[i].shadow->shadow = NULL;
		page[i].shadow->origin = NULL;
		// TODO(glider): sometimes page[i].origin is initialized. Let's skip the check for now.
		BUG_ON(page[i].origin && 0);
		// page.origin is struct page.
		page[i].origin = &origin[i];
		page[i].origin->is_kmsan_untracked_page = true;
		page[i].origin->shadow = NULL;
		page[i].origin->origin = NULL;
		page[i].is_kmsan_untracked_page = false;
	}
	return 0;
}


void maybe_report_stats(void)
{
	return;
	if (atomic_read(&alloc_calls) % 10000 == 0) {
		kmsan_pr_err("alloc_calls: %d, free_calls: %d\n"
			"meta_alloc_calls: %d, meta_free_calls: %d\n",
			atomic_read(&alloc_calls), atomic_read(&free_calls), atomic_read(&meta_alloc_calls), atomic_read(&meta_free_calls));
	}
}

int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags)
{
	unsigned long irq_flags;
	int pages = 1 << order;  // TODO(glider): remove
	int ret;

	atomic_add(pages, &alloc_calls);

	if (IN_RUNTIME())
		return 0;
	maybe_report_stats();
	ENTER_RUNTIME(irq_flags);
	ret = kmsan_alloc_meta_for_pages(page, order, flags, -1);
	LEAVE_RUNTIME(irq_flags);
	return ret;
}


void kmsan_free_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin, *cur_page;
	int pages = 1 << order;
	int i;
	unsigned long irq_flags;

	atomic_add(pages, &free_calls);
	maybe_report_stats();

	if (page->is_kmsan_untracked_page) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			cur_page->is_kmsan_untracked_page = false;
			BUG_ON(cur_page->shadow);
		}
		return;
	}

	// TODO(glider): order?
	// We want is_kmsan_untracked_page be false for all deallocated pages.
	if (!kmsan_ready) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			cur_page->is_kmsan_untracked_page = false;
			cur_page->shadow = NULL;
			cur_page->origin = NULL;
		}
		return;
	}

	if (IN_RUNTIME()) {
		return;
		// TODO(glider): looks legit. depot_save_stack() may call free_pages().
		///BUG();
	}

	ENTER_RUNTIME(irq_flags);
	if (!page[0].shadow) {
		/// TODO(glider): can we free a page without a shadow?
		// Maybe if it was allocated at boot time?
		// Anyway, all shadow pages must be NULL then.
		for (i = 0; i < pages; i++)
			if (page[i].shadow) {
				current->kmsan.is_reporting = true;
				for (i = 0; i < pages; i++)
					kmsan_pr_err("page[%d].shadow=%p\n", i, page[i].shadow);
				current->kmsan.is_reporting = false;
				break;
			}
		///kmsan_pr_err("trying to deallocate missing shadow for page %p\n", page);
		LEAVE_RUNTIME(irq_flags);
		return;
	}

	shadow = page[0].shadow;
	origin = page[0].origin;

	// TODO(glider): this is racy.
	for (i = 0; i < pages; i++) {
		BUG_ON(!(page[i].shadow->is_kmsan_untracked_page));
		page[i].shadow = NULL;
		///kmsan_pr_err("Nullified shadow of %p\n", page_address(&page[i]));
		BUG_ON(!page[i].origin->is_kmsan_untracked_page);
		page[i].origin = NULL;
	}
	///kmsan_pr_err("freeing shadow: %p\n", shadow);
	BUG_ON(!shadow->is_kmsan_untracked_page);
	__free_pages(shadow, order);
	atomic_add(pages, &meta_free_calls);

	///kmsan_pr_err("freeing origin: %p\n", origin);
	BUG_ON(!origin->is_kmsan_untracked_page);
	__free_pages(origin, order);
	atomic_add(pages, &meta_free_calls);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_free_page);

void kmsan_split_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin;
	int i;
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	if (page->is_kmsan_untracked_page)
		return;

	ENTER_RUNTIME(irq_flags);
	if (!page[0].shadow) {
		BUG_ON(page[0].origin);
		LEAVE_RUNTIME(irq_flags);
		return;
	}
	shadow = page[0].shadow;
	///kmsan_pr_err("kmsan_split_page(%p, %d), shadow is %p\n", page, order, shadow);
	split_page(shadow, order);

	origin = page[0].origin;
	split_page(origin, order);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_split_page);

DEFINE_SPINLOCK(report_lock);
//static DEFINE_HASHTABLE(reporters_tbl, );
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
	///kmsan_pr_err("saved pointer: %p in table %p\n", caller, table);
}

// TODO(glider): drop this fn?
void kmsan_fetch_stack(depot_stack_handle_t origin, struct stack_trace *trace)
{
	depot_fetch_stack(origin, trace);
}

static inline void kmsan_print_origin(depot_stack_handle_t origin)
{
	struct stack_trace trace, chained_trace;
	char *descr = NULL;
	void *pc1 = NULL, *pc2 = NULL;
	depot_stack_handle_t head;

	if (!origin)
		return;

	while (true) {
		kmsan_fetch_stack(origin, &trace);
		if ((trace.nr_entries == 4) &&
		    ((trace.entries[0] & KMSAN_MAGIC_MASK) == KMSAN_ALLOCA_MAGIC_ORIGIN)) {
			descr = (char*)trace.entries[1];
			pc1 = (void*)trace.entries[2];
			pc2 = (void*)trace.entries[3];
			//kmsan_pr_err("origin description: %s\n", descr);
			// TODO(glider): don't print origin here.
			kmsan_pr_err("origin description: %s (origin=%p)\n", descr, origin);
			kmsan_pr_err("local variable created at:\n");
			kmsan_pr_err(" %pS\n", pc1);
			kmsan_pr_err(" %pS\n", pc2);
			break;
		}
		if (trace.nr_entries == 3) {
			if ((trace.entries[0] & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FULL) {
				head = trace.entries[1];
				origin = trace.entries[2];
				///kmsan_pr_err("chained origin:\n");
				kmsan_pr_err("chained origin: %p\n", head);  // TODO(glider)
				kmsan_fetch_stack(head, &chained_trace);
				print_stack_trace(&chained_trace, 0);
				continue;
			} else
			if ((trace.entries[0] & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FRAME) {
				origin = trace.entries[2];
				///kmsan_pr_err("chained origin:\n");
				kmsan_pr_err("chained origin:\n");  // TODO(glider)
				kmsan_pr_err("%p - %pSR\n", trace.entries[1], trace.entries[1]);
				continue;
			}
		}
		///kmsan_pr_err("origin:\n");
		kmsan_pr_err("origin: %p\n", origin);  // TODO(glider): remove the origin id.
		if (trace.entries)
			print_stack_trace(&trace, 0);
		else
			kmsan_pr_err("No entries\n");
		break;
	}
}

#define STACK_TOP_MARGIN        128
bool in_exception()
{
	struct orig_ist *oist;
	u64 estack_top, estack_bottom;
	oist = this_cpu_ptr(&orig_ist);
	estack_top = (u64)oist->ist[0] - EXCEPTION_STKSZ + STACK_TOP_MARGIN;
	estack_bottom = (u64)oist->ist[N_EXCEPTION_STACKS - 1];
	if (&oist >= estack_top && &oist <= estack_bottom)
		return true;
	return false;
}

/*static*/
inline void kmsan_report(void *caller, depot_stack_handle_t origin)
{
	unsigned long flags;
	struct stack_trace trace;
	char *descr = NULL;
	int i; // TODO(glider)
	depot_stack_handle_t tmp_origin;
	int inter = task_tls_index();

	if (!kmsan_ready)
		return;
	if (!current->kmsan.allow_reporting)
		return;
	if (reported_already(caller, reporters_tbl))
		return;
	if (is_console_locked() || is_logbuf_locked())
		return;

	if (!origin)
		return;

	kmsan_fetch_stack(origin, &trace);
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
	// TODO(glider): inline this properly, avoid __builtin_return_address(1).
	kmsan_pr_err("BUG: KMSAN: use of unitialized memory in %pS\n", __builtin_return_address(1));
	dump_stack();
	kmsan_print_origin(origin);
	kmsan_pr_err("==================================================================\n");
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&report_lock, flags);
	current->kmsan.is_reporting = false;
	current->kmsan.allow_reporting = true;
}

void kmsan_vprintk_func(const char *fmt, va_list args)
{
	const char *cur_p = fmt;
	char cur;
	size_t size = 8;  // TODO(glider)

	while ((cur = *cur_p)) {
		if (cur == '%') {
			// TODO(glider): this is inaccurate.
			// Okay, this is actually doing nothing.
		}
		cur_p++;
	}
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
bool my_virt_addr_valid(unsigned long x)
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

void kmsan_check_memory(const void *addr, size_t size)
{
	unsigned long irq_flags;
	char *shadow;
	depot_stack_handle_t *origin;
	size_t i;

	// copy_to_user() may copy zero bytes. No need to check.
	if (!kmsan_ready || IN_RUNTIME() || !size)
		return;
	ENTER_RUNTIME(irq_flags);
	shadow = kmsan_get_shadow_address(addr, size, /*checked*/true);
	if (!shadow) {
		// TODO(glider): do we need to report an error here?
		LEAVE_RUNTIME(irq_flags);
		return;
	}
	for (i = 0; i < size; i++) {
		if (!shadow[i]) continue;
		// Not checking for the second time.
		origin = kmsan_get_origin_address(addr, size, /*checked*/false);
		kmsan_report(_THIS_IP_, *origin);
	}
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_check_memory);

// TODO(glider): do we want to inline this into kmsan_instr.c?
inline
void *kmsan_get_shadow_address(u64 addr, size_t size, bool checked)
{
	struct page *page, *next_page;
	unsigned long page_offset, shadow_size;
	void *ret;
	depot_stack_handle_t origin;

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!my_virt_addr_valid(addr)) {
		///kmsan_pr_err("not a valid virtual address: %p\n", addr);
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy shadow size further.
		if (size > PAGE_SIZE) {
			WARN("kmsan_get_shadow_address(%p, %d, %d)\n", addr, size, checked);
			///BUG();
			if (checked)
				BUG();
			else
				return NULL;
		}
		__memset(kmsan_dummy_shadow, 0, DUMMY_SHADOW_SIZE); // TODO(glider)
		return kmsan_dummy_shadow;
	}

 	page = virt_to_page(addr);
	if (!page) {
		current->kmsan.is_reporting = true;
		kmsan_pr_err("no page for address %p\n", addr);
		current->kmsan.is_reporting = false;
		__memset(kmsan_dummy_shadow, 0, DUMMY_SHADOW_SIZE); // TODO(glider)
		return kmsan_dummy_shadow;
	}
	if (!page->shadow) {
		oops_in_progress = 1;
		kmsan_pr_err("not allocated shadow for addr %p (page %p)\n", addr, page);
		BUG();
	}
	page_offset = addr % PAGE_SIZE;

	if (checked && (page_offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the next
		 * one. Make sure the shadow pages are also consequent.
		 */
		next_page = virt_to_page(addr + size - 1);
		if (page_address(page->shadow) != page_address(next_page->shadow) - PAGE_SIZE) {
			if ((addr < _sdata) || (addr >= _edata)) {
				// Skip reports on __data.
				// TODO(glider): allocate contiguous shadow for __data instead.
				current->kmsan.is_reporting = true;
				kmsan_pr_err("BUG: attempting to access two shadow page ranges.\n");
				dump_stack();
				kmsan_pr_err("Access of size %d at %p.\n", size, addr);
				kmsan_pr_err("page[0].shadow: %p, page[1].shadow: %p\n", page_address(page->shadow), page_address(virt_to_page(addr + size - 1)));
				origin = *(depot_stack_handle_t*)kmsan_get_origin_address(addr, 1, false);
				kmsan_pr_err("origin: %p\n", origin);
				kmsan_print_origin(origin);
				current->kmsan.is_reporting = false;
			}
			__memset(kmsan_dummy_shadow, 0, DUMMY_SHADOW_SIZE); // TODO(glider)
			return kmsan_dummy_shadow;
		}
	}
	ret = page_address(page->shadow) + page_offset;
	return ret;
}


// TODO(glider): do we want to inline this into kmsan_instr.c?
// TODO(glider): either delete kmsan_get_shadow_address() or refactor.
/* kmsan_get_shadow_address_noruntime() must not be called from within runtime. */
inline
void *kmsan_get_shadow_address_noruntime(u64 addr, size_t size, bool checked)
{
	struct page *page, *next_page;
	unsigned long page_offset, shadow_size;
	void *ret;
	depot_stack_handle_t origin;
	unsigned long irq_flags;

	u64 caller = __builtin_return_address(1);

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!my_virt_addr_valid(addr)) {
		ENTER_RUNTIME(irq_flags);
		///kmsan_pr_err("not a valid virtual address: %p\n", addr);
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy shadow size further.
		if (size > PAGE_SIZE) {
			WARN("kmsan_get_shadow_address_noruntime(%p, %d, %d)\n", addr, size, checked);
			if (checked)
				BUG();
			else
				return NULL;
		}
		LEAVE_RUNTIME(irq_flags);
		return NULL;
	}

	page = virt_to_page(addr);
	if (!page) {
		return NULL;
		ENTER_RUNTIME(irq_flags);
		current->kmsan.is_reporting = true;
		kmsan_pr_err("no page for address %p\n", addr);
		current->kmsan.is_reporting = false;
		LEAVE_RUNTIME(irq_flags);
		return NULL;
	}
	if (!(page->shadow)) {
		ENTER_RUNTIME(irq_flags);
		oops_in_progress = 1;
		kmsan_pr_err("not allocated shadow for addr %p (page %p)\n", addr, page);
		BUG();
		LEAVE_RUNTIME(irq_flags);
	}
	page_offset = addr % PAGE_SIZE;

	if (checked && (page_offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the next
		 * one. Make sure the shadow pages are also consequent.
		 */
		next_page = virt_to_page(addr + size - 1);
		if (page_address(page->shadow) != page_address(next_page->shadow) - PAGE_SIZE) {
			if ((addr < _sdata) || (addr >= _edata)) {
				ENTER_RUNTIME(irq_flags);
				// Skip reports on __data.
				// TODO(glider): allocate contiguous shadow for __data instead.
				current->kmsan.is_reporting = true;
				kmsan_pr_err("BUG: attempting to access two shadow page ranges.\n");
				dump_stack();
				kmsan_pr_err("Access of size %d at %p.\n", size, addr);
				kmsan_pr_err("page[0].shadow: %p, page[1].shadow: %p\n", page_address(page->shadow), page_address(virt_to_page(addr + size - 1)));
				origin = *(depot_stack_handle_t*)kmsan_get_origin_address(addr, 1, false);
				kmsan_pr_err("origin: %p\n", origin);
				kmsan_print_origin(origin);
				current->kmsan.is_reporting = false;
				LEAVE_RUNTIME(irq_flags);
			}
			return NULL;
		}
	}
	ret = page_address(page->shadow) + page_offset;
	return ret;
}

inline
void *kmsan_get_origin_address(u64 addr, size_t size, bool checked)
{
	struct page *page;
	u64 page_offset;
	int pad = 0;
	void *ret;

	if (!my_virt_addr_valid(addr)) {
		///kmsan_pr_err("not a valid virtual address: %p\n", addr);
		BUG_ON(size > PAGE_SIZE);
		__memset(kmsan_dummy_origin, 0, DUMMY_SHADOW_SIZE); // TODO(glider)
		return kmsan_dummy_origin;
	}

 	page = virt_to_page(addr);
	if (!page) {
		current->kmsan.is_reporting = true;
		kmsan_pr_err("no page for address %p\n", addr);
		current->kmsan.is_reporting = false;
	}
	if (!IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
		addr -= pad;
		size += pad;
	}
	page_offset = (addr % PAGE_SIZE);
	// TODO(glider): no lazy allocation!
	if (!page->origin) {
		kmsan_pr_err("No origin for address %p (page %p)\n", addr, page);
		BUG_ON(page->shadow);
		BUG_ON(!page->origin);
	}
	if (!page->origin) {
		oops_in_progress = 1;
		kmsan_pr_err("No origin for address %p (page %p)\n", addr, page);
		BUG_ON(!page->origin);
	}
	/* TODO(glider): this is conservative. */
	if (checked && (page_offset + size - 1 > PAGE_SIZE)) {
		current->kmsan.is_reporting = true;
		kmsan_pr_err("BUG: attempting to access two origin page ranges.\n");
		kmsan_pr_err("Access of size %d at %p.\n", size - pad, addr + pad);
		kmsan_pr_err("page[0].origin: %p, page[1].origin: %p\n", page_address(page->origin), page_address(virt_to_page(addr + size - 1)));
		current->kmsan.is_reporting = false;
		__memset(kmsan_dummy_origin, 0, DUMMY_SHADOW_SIZE); // TODO(glider)
		return kmsan_dummy_origin;
	}
	ret = page_address(page->origin) + page_offset;
	return ret;
}
