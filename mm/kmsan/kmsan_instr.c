/*
 * KMSAN compiler API.
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
#include <linux/gfp.h>
#include <linux/mm.h>

// TODO(glider): dummy shadow should be per-task.
// TODO(glider): ideally, there should be no dummy shadow once we're initialized.
// I.e. we need to remove IN_RUNTIME checks from the fast path.

void check_param_origin_tls(void)
{
	kmsan_context_state *cstate = task_kmsan_context_state();
	int i;
	unsigned long flags;
	return;
	if (!kmsan_ready)
		return;

	for (i = 0; i < KMSAN_PARAM_SIZE / sizeof(depot_stack_handle_t); i++) {
		if (cstate->param_origin_tls[i]) {
			spin_lock_irqsave(&report_lock, flags);
			dump_stack();
			spin_unlock_irqrestore(&report_lock, flags);
		}
		cstate->param_origin_tls[i] = 0;
	}
	for (i = 0; i < KMSAN_PARAM_SIZE; i++) {
		cstate->param_tls[i] = 0;
	}
}

void check_vararg_meta(void)
{
	kmsan_context_state *cstate = task_kmsan_context_state();
	int i;
	unsigned long irq_flags, flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME() || !current->kmsan.enabled)
		return;
	ENTER_RUNTIME(irq_flags);

	for (i = 0; i < KMSAN_PARAM_SIZE; i++) {
		if (cstate->va_arg_tls[i]) {
			spin_lock_irqsave(&report_lock, flags);
			dump_stack();
			spin_unlock_irqrestore(&report_lock, flags);
			break;
		}
	}
	LEAVE_RUNTIME(irq_flags);
}

// TODO(glider): remove this fn?
// Looks like it's enough to mark syscall entries non-instrumented.
void kmsan_wipe_params_shadow_origin()
{
	int ind, num;
	unsigned long irq_flags;
	kmsan_context_state *cstate = task_kmsan_context_state();

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME() || !current->kmsan.enabled)
		return;
	ENTER_RUNTIME(irq_flags);
	__memset(cstate->param_origin_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->param_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->va_arg_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->va_arg_origin_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->retval_tls, 0, RETVAL_SIZE);
	cstate->retval_origin_tls = 0;
	cstate->origin_tls = 0;
	cstate->va_arg_overflow_size_tls = 0;
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_wipe_params_shadow_origin);

typedef struct {
	void* s;
	void* o;
} shadow_origin_ptr_t;


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

// TODO(glider): do we want to inline this into kmsan_instr.c?
// TODO(glider): either delete kmsan_get_shadow_address() or refactor.
/* kmsan_get_shadow_address_noruntime() must not be called from within runtime. */
inline
void *kmsan_get_shadow_address_inline(u64 addr, size_t size, bool checked)
{
	struct page *page, *next_page;
	unsigned long page_offset, shadow_size;
	void *ret;
	depot_stack_handle_t origin;
	unsigned long irq_flags;

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!my_virt_addr_valid(addr)) {
		ENTER_RUNTIME(irq_flags);
		///kmsan_pr_err("not a valid virtual address: %p\n", addr);
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy shadow size further.
		if (size > PAGE_SIZE) {
			WARN("kmsan_get_shadow_address_inline(%p, %d, %d)\n", addr, size, checked);
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
	}
	if (!(page->shadow)) {
		ENTER_RUNTIME(irq_flags);
		oops_in_progress = 1;
		kmsan_pr_err("not allocated shadow for addr %p (page %p)\n", addr, page);
		BUG();
		LEAVE_RUNTIME(irq_flags);
	}
	page_offset = addr % PAGE_SIZE;

	if ((page_offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the next
		 * one. Make sure the shadow pages are also consequent.
		 */
		if (!metadata_is_contiguous(addr, size, /*is_origin*/false)) {
			return NULL;
		}
	}
	ret = page_address(page->shadow) + page_offset;
	return ret;
}

/* kmsan_get_origin_address_noruntime() must not be called from within runtime. */
inline
void *kmsan_get_origin_address_inline(u64 addr, size_t size)
{
	struct page *page, *next_page;
	unsigned long page_offset, shadow_size;
	void *ret;
	depot_stack_handle_t origin;
	unsigned long irq_flags;
	size_t pad;

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
		addr -= pad;
		size += pad;
	}
	if (!my_virt_addr_valid(addr)) {
		ENTER_RUNTIME(irq_flags);
		///kmsan_pr_err("not a valid virtual address: %p\n", addr);
		// TODO(glider): Trinity is able to trigger the check below with size=14240.
		// No point in increasing the dummy origin size further.
		if (size > PAGE_SIZE) {
			WARN("kmsan_get_origin_address_inline(%p, %d)\n", addr, size);
			BUG();
		}
		LEAVE_RUNTIME(irq_flags);
		return NULL;
	}

	page = virt_to_page(addr);
	if (!page || !(page->origin)) {
		kmsan_pr_err("not allocated origin for addr %p (page %p)\n", addr, page);
		BUG();
	}
	page_offset = addr % PAGE_SIZE;

	ret = page_address(page->origin) + page_offset;
	return ret;
}

static inline
shadow_origin_ptr_t msan_get_shadow_origin_ptr(u64 addr, u64 size, bool store)
{
	shadow_origin_ptr_t ret;
	void *shadow, *origin;
	unsigned long irq_flags;
	struct page *page, *next_page;
	unsigned long page_offset;
	size_t pad;

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
	if (size > PAGE_SIZE) {
		WARN("size too big in msan_get_shadow_origin_ptr(%p, %d, %d)\n", addr, size, store);
		//BUG();
		ret.s = NULL;
		ret.o = NULL;
		return ret;
	}

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!my_virt_addr_valid(addr)) {
		return ret;
	}
	page = virt_to_page(addr);
	if ((!page) || (!(page->shadow))) {
		return ret;
	}
	page_offset = addr % PAGE_SIZE;
	if ((page_offset + size - 1 > PAGE_SIZE)) {
		/* The access overflows the current page and touches the next
		 * one. Make sure the shadow pages are also consequent.
		 */
		if (!metadata_is_contiguous(addr, size, /*is_origin*/false)) {
			return ret;
		}
	}
	shadow = page_address(page->shadow) + page_offset;
	if (!shadow)
		goto leave;
	ret.s = shadow;

	// TODO(glider): For some reason vmalloc'ed addresses aren't considered valid.
	if (!IS_ALIGNED(addr, 4)) {
		pad = addr % 4;
		addr -= pad;
	}

	page_offset = addr % PAGE_SIZE;
	// Don't check origins, shadow should've checked already.
	origin = page_address(page->origin) + page_offset;
	// origin cannot be NULL, because shadow is already non-NULL.
	BUG_ON(!origin);
	ret.o = origin;
leave:
	return ret;
}

shadow_origin_ptr_t __msan_metadata_ptr_for_load_n(u64 addr, u64 size)
{
	return msan_get_shadow_origin_ptr(addr, size, /*store*/false);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_n);

shadow_origin_ptr_t __msan_metadata_ptr_for_store_n(u64 addr, u64 size)
{
	return msan_get_shadow_origin_ptr(addr, size, /*store*/true);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_n);

#define DECLARE_METADATA_PTR_GETTER(size)	\
shadow_origin_ptr_t __msan_metadata_ptr_for_load_##size(u64 addr)	\
{		\
	return msan_get_shadow_origin_ptr(addr, size, /*store*/false);	\
}		\
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_##size);			\
		\
shadow_origin_ptr_t __msan_metadata_ptr_for_store_##size(u64 addr)	\
{									\
	return msan_get_shadow_origin_ptr(addr, size, /*store*/true);	\
}									\
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_##size);

DECLARE_METADATA_PTR_GETTER(1);
DECLARE_METADATA_PTR_GETTER(2);
DECLARE_METADATA_PTR_GETTER(4);
DECLARE_METADATA_PTR_GETTER(8);


// Essentially a memcpy(shadow(dst), src, size).
// TODO(glider): do we need any checks here?
// TODO(glider): maybe save origins as well?
// Another possible thing to do is to push/pop va_arg shadow.
void __msan_load_arg_shadow(u64 dst, u64 src, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || !kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_mem_to_shadow(dst, src, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_load_arg_shadow);

void __msan_load_arg_origin(u64 dst, u64 src, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || !kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_mem_to_origin(dst, src, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_load_arg_origin);

// Essentially a memcpy(dst, shadow(src), size)
// TODO(glider): do we need any checks here?
// Another possible thing to do is to push/pop va_arg shadow.
void __msan_store_arg_shadow(u64 dst, u64 src, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || !kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_shadow_to_mem(dst, src, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_store_arg_shadow);


void __msan_store_arg_shadow_origin(u64 dst_shadow, u64 dst_origin, u64 src, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || !kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_store_arg_shadow_origin(dst_shadow, dst_origin, src, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_store_arg_shadow_origin);

void *__msan_memmove(void *dst, void *src, u64 n)
{
	void *result;
	void *shadow_dst;
	unsigned long irq_flags;

	result = __memmove(dst, src, n);
	if (!n)
		// Some people call memmove() with zero length.
		return result;
	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): due to a hack kmsan_get_shadow_address() may return NULL
	// for addresses in vmalloc space.
	// Or maybe it's enough to just skip copying invalid addresses?

	/* Ok to skip address check here, we'll do it later. */
	shadow_dst = (void*)kmsan_get_shadow_address((u64)dst, n, /*checked*/false, /*is_store*/true);
	if (shadow_dst)
		kmsan_memmove_shadow(dst, src, n);
	else
		kmsan_pr_err("__msan_memmove(%p, %p, %d): skipping shadow\n", dst, src, n);
	// TODO(glider): origins.
	// We may want to chain every |src| origin with the current stack.
	kmsan_memmove_origins((u64)dst, (u64)src, n);
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memmove);

void *__msan_memcpy(void *dst, const void *src, u64 n)
{
	void *result;
	void *shadow_dst;
	unsigned long irq_flags;
	if ((dst != src) && (!(((u64)dst + n <= (u64)src) || ((u64)src + n <= (u64)dst)))) {
		kmsan_pr_err("==================================================================\n");
		// TODO(glider): avoid __builtin_return_address(1).
		kmsan_pr_err("WARNING: memcpy-param-overlap in %pS\n", __builtin_return_address(1));
		kmsan_pr_err("__msan_memcpy(%p, %p, %d)\n", dst, src, n);
		dump_stack();
		kmsan_pr_err("==================================================================\n");
	}

	result = __memcpy(dst, src, n);
	if (!n)
		// Some people call memcpy() with zero length.
		return result;

	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): see below.
	if (!virt_addr_valid(dst))
		goto leave;
	else {
		if (!virt_addr_valid(src)) {
			///  TODO(glider): handling __vmalloc().
			kmsan_internal_unpoison_shadow(dst, n);
			goto leave;
		}
	}

	/* Ok to skip address check here, we'll do it later. */
	shadow_dst = kmsan_get_shadow_address((u64)dst, n, /*checked*/false, /*is_store*/true);
	// TODO(glider): due to a hack kmsan_get_shadow_address() may return NULL
	// for addresses in vmalloc space.
	// Or maybe it's enough to just skip copying invalid addresses?
	if (shadow_dst)
		kmsan_memcpy_shadow(dst, src, n);
	else
		kmsan_pr_err("__msan_memcpy(%p, %p, %d): skipping shadow\n", dst, src, n);
	// TODO(glider): origins
	// We may want to chain every |src| origin with the current stack.
	kmsan_memcpy_origins((u64)dst, (u64)src, n);
leave:
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memcpy);


void *__msan_memset(void *dst, int c, size_t n)
{
	void *result;
	unsigned long irq_flags;
	depot_stack_handle_t origin, new_origin;
	unsigned int shadow;
	void *caller;

	result = __memset(dst, c, n);
	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): emit stores to param_tls and param_origin_tls in the compiler for KMSAN.
	// (not for MSan, because __msan_memset could be called from the userspace RTL)
	// Take the shadow and origin of |c|.
	///shadow = (unsigned int)(current->kmsan.cstate.param_tls[1]);
	///origin = (depot_stack_handle_t)(current->kmsan.cstate.param_origin_tls[1]);
	shadow = 0;
	kmsan_internal_memset_shadow((u64)dst, shadow, n);
	///new_origin = kmsan_internal_chain_origin(origin, /*full*/true);
	new_origin = 0;
	kmsan_set_origin((u64)dst, n, new_origin);
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memset);

depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
{
	depot_stack_handle_t ret = 0;
	unsigned long irq_flags;

	if (IN_RUNTIME())
		return ret;
	if (!kmsan_ready)
		return ret;

	ENTER_RUNTIME(irq_flags);
	ret = kmsan_internal_chain_origin(origin, /*full*/true);
	LEAVE_RUNTIME(irq_flags);
	return ret;
}
EXPORT_SYMBOL(__msan_chain_origin);

inline void kmsan_internal_memset_shadow_inline(u64 address, int b, size_t size)
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
		shadow_start = kmsan_get_shadow_address(address, to_fill, /*checked*/true, /*is_store*/true);
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

inline
void kmsan_write_aligned_origin_inline(const void *var, size_t size, u32 origin)
{
	u32 *var_cast = (u32 *)var;
	int i;

	BUG_ON((u64)var_cast % 4);
	BUG_ON(size % 4);
	for (i = 0; i < size / 4; i++)
		var_cast[i] = origin;
}


inline void kmsan_set_origin_inline(u64 address, int size, u32 origin)
{
	void *origin_start;
	u64 page_offset;
	size_t to_fill, pad = 0;

	if (!IS_ALIGNED(address, 4)) {
		pad = address % 4;
		address -= pad;
		size += pad;
	}

	while (size > 0) {
		page_offset = address % PAGE_SIZE;
		to_fill = (PAGE_SIZE - page_offset > size) ? size : PAGE_SIZE - page_offset;
		to_fill = ALIGN(to_fill, 4);	// at least 4 bytes
		BUG_ON(!to_fill);
		// Don't check
		origin_start = kmsan_get_origin_address_noruntime(address, to_fill, false);
		if (!origin_start) {
			current->kmsan.is_reporting = true;
			kmsan_pr_err("WARNING: not setting origing for %d bytes starting at %p, because the origin is NULL\n", to_fill, address);
			current->kmsan.is_reporting = false;
			BUG();
		}
		kmsan_write_aligned_origin_inline(origin_start, to_fill, origin);
		address += to_fill;
		size -= to_fill;
	}
}


void __msan_poison_alloca(u64 address, u64 size, char *descr/*checked*/, u64 pc)
{
	depot_stack_handle_t handle;
	unsigned long entries[4];
	struct stack_trace trace = {
		.nr_entries = 4,
		.entries = entries,
		.max_entries = 4,
		.skip = 0
	};
	unsigned long irq_flags;
	u64 size_copy = size, to_fill;
	u64 addr_copy = address;
	u64 page_offset;
	void *shadow_start;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	///inlining this:
        ///kmsan_internal_memset_shadow_inline((u64)address, -1, (size_t)size);

	while (size_copy) {
		page_offset = addr_copy % PAGE_SIZE;
		to_fill = min_num(PAGE_SIZE - page_offset, size_copy);
		shadow_start = kmsan_get_shadow_address_inline(addr_copy, to_fill, true);
		if (!shadow_start) {
			current->kmsan.is_reporting = true;
			kmsan_pr_err("WARNING: not poisoning %d bytes starting at %p, because the shadow is NULL\n", to_fill, addr_copy);
			current->kmsan.is_reporting = false;
			BUG();
		}
		__memset(shadow_start, -1, to_fill);
		addr_copy += to_fill;
		size_copy -= to_fill;
	}

	entries[0] = KMSAN_ALLOCA_MAGIC_ORIGIN;
	entries[1] = (u64)descr;
	entries[2] = __builtin_return_address(0);
	entries[3] = pc;

	ENTER_RUNTIME(irq_flags);
	handle = depot_save_stack(&trace, GFP_ATOMIC);
	LEAVE_RUNTIME(irq_flags);
	// TODO(glider): just a plain origin description isn't enough, let's store the full stack here.
	///handle = kmsan_internal_chain_origin(handle, /*full*/true);
	kmsan_set_origin_inline(address, size, handle);
}
EXPORT_SYMBOL(__msan_poison_alloca);

void __msan_unpoison(void *addr, u64 size)
{
	unsigned long irq_flags;
	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_internal_unpoison_shadow(addr, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_unpoison);

// Compiler API
void __msan_warning_32(u32 origin)
{
	void *caller;
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	caller = __builtin_return_address(0);
	kmsan_report(caller, origin, /*size*/0, /*off_first*/0, /*off_last*/0, /*deep*/false);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_warning_32);

// Per-task getters.
kmsan_context_state *__msan_get_context_state(void)
{
	unsigned long irq_flags;
	kmsan_context_state *ret;

	if (!kmsan_threads_ready) {
		__memset(&kmsan_dummy_state, 0, sizeof(kmsan_dummy_state));
		return &kmsan_dummy_state;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		// We're in runtime, don't care about the shadow.
		///__memset(&kmsan_dummy_state, 0, sizeof(kmsan_dummy_state)); // TODO(glider)
		return &kmsan_dummy_state;
	}
	// No need to enter/leave runtime?
	ENTER_RUNTIME(irq_flags);
	ret = task_kmsan_context_state();
	LEAVE_RUNTIME(irq_flags);

	BUG_ON(!ret);

	return ret;
}
EXPORT_SYMBOL(__msan_get_context_state);
