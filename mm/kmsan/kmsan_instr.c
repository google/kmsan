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

static inline bool is_bad_asm_addr(void *addr, u64 size, bool is_store)
{
	if ((u64)addr < TASK_SIZE) {
		return true;
	}
	if (!kmsan_get_metadata_or_null(addr, size, /*is_origin*/false))
		return true;
	return false;
}

shadow_origin_ptr_t __msan_metadata_ptr_for_load_n(void *addr, u64 size)
{
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/false);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_n);

shadow_origin_ptr_t __msan_metadata_ptr_for_store_n(void *addr, u64 size)
{
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/true);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_n);

#define DECLARE_METADATA_PTR_GETTER(size)	\
shadow_origin_ptr_t __msan_metadata_ptr_for_load_##size(void *addr)	\
{		\
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/false);	\
}		\
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_##size);			\
		\
shadow_origin_ptr_t __msan_metadata_ptr_for_store_##size(void *addr)	\
{									\
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/true);	\
}									\
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_##size);

DECLARE_METADATA_PTR_GETTER(1);
DECLARE_METADATA_PTR_GETTER(2);
DECLARE_METADATA_PTR_GETTER(4);
DECLARE_METADATA_PTR_GETTER(8);

void __msan_instrument_asm_store(void *addr, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	/*
	 * Most of the accesses are below 32 bytes. The two exceptions so far
	 * are clwb() (64 bytes) and FPU state (512 bytes).
	 * It's unlikely that the assembly will touch more than 512 bytes.
	 */
	if (size > 512)
		size = 8;
	if (is_bad_asm_addr(addr, size, /*is_store*/true))
		return;
	ENTER_RUNTIME(irq_flags);
	/* Unpoisoning the memory on best effort. */
	kmsan_internal_unpoison_shadow(addr, size, /*checked*/false);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_instrument_asm_store);

void *__msan_memmove(void *dst, void *src, u64 n)
{
	void *result;
	void *shadow_dst;

	result = __memmove(dst, src, n);
	if (!n)
		/* Some people call memmove() with zero length. */
		return result;
	if (!kmsan_ready || IN_RUNTIME())
		return result;

	/* Ok to skip address check here, we'll do it later. */
	shadow_dst = kmsan_get_metadata_or_null(dst, n, /*is_origin*/false);

	if (!shadow_dst)
		/* Can happen e.g. if the memory is untracked. */
		return result;

	kmsan_memmove_metadata(dst, src, n);

	return result;
}
EXPORT_SYMBOL(__msan_memmove);

void *__msan_memmove_nosanitize(void *dst, void *src, u64 n)
{
	return __memmove(dst, src, n);
}
EXPORT_SYMBOL(__msan_memmove_nosanitize);

void *__msan_memcpy(void *dst, const void *src, u64 n)
{
	void *result;
	void *shadow_dst;

	result = __memcpy(dst, src, n);
	if (!n)
		/* Some people call memcpy() with zero length. */
		return result;

	if (!kmsan_ready || IN_RUNTIME())
		return result;

	/* Ok to skip address check here, we'll do it later. */
	shadow_dst = kmsan_get_metadata_or_null(dst, n, /*is_origin*/false);
	if (!shadow_dst)
		/* Can happen e.g. if the memory is untracked. */
		return result;

	kmsan_memcpy_metadata(dst, (void *)src, n);

	return result;
}
EXPORT_SYMBOL(__msan_memcpy);

void *__msan_memcpy_nosanitize(void *dst, void *src, u64 n)
{
	return __memcpy(dst, src, n);
}
EXPORT_SYMBOL(__msan_memcpy_nosanitize);

void *__msan_memset(void *dst, int c, size_t n)
{
	void *result;
	unsigned long irq_flags;
	depot_stack_handle_t new_origin;
	unsigned int shadow;

	result = __memset(dst, c, n);
	if (!kmsan_ready || IN_RUNTIME())
		return result;

	ENTER_RUNTIME(irq_flags);
	/*
	 * TODO(glider): emit stores to param_tls and param_origin_tls in the
	 * compiler for KMSAN (not for MSan, because __msan_memset could be
	 * called from the userspace RTL).
	 */
	/*
	 * TODO(glider): shall we take the shadow and origin of |c|?
	 *   shadow = (unsigned int)(current->kmsan.cstate.param_tls[1]);
	 *   origin = (depot_stack_handle_t)(current->kmsan.cstate.param_origin_tls[1]);
	 *   new_origin = kmsan_internal_chain_origin(origin, true);
	 */
	shadow = 0;
	kmsan_internal_memset_shadow(dst, shadow, n, /*checked*/false);
	new_origin = 0;
	kmsan_set_origin(dst, n, new_origin, /*checked*/false);
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memset);

void *__msan_memset_nosanitize(void *dst, int c, size_t n)
{
	return __memset(dst, c, n);
}
EXPORT_SYMBOL(__msan_memset_nosanitize);

depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
{
	depot_stack_handle_t ret = 0;
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return ret;

	/* Creating new origins may allocate memory. */
	ENTER_RUNTIME(irq_flags);
	ret = kmsan_internal_chain_origin(origin);
	LEAVE_RUNTIME(irq_flags);
	return ret;
}
EXPORT_SYMBOL(__msan_chain_origin);

inline
void kmsan_write_aligned_origin_inline(void *var, size_t size, u32 origin)
{
	u32 *var_cast = (u32 *)var;
	int i;

	BUG_ON((u64)var_cast % ORIGIN_SIZE);
	BUG_ON(size % ORIGIN_SIZE);
	for (i = 0; i < size / ORIGIN_SIZE; i++)
		var_cast[i] = origin;
}

inline void kmsan_set_origin_inline(void *addr, int size, u32 origin)
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
		to_fill = ALIGN(to_fill, ORIGIN_SIZE);	/* write at least ORIGIN_SIZE bytes */
		BUG_ON(!to_fill);
		origin_start = kmsan_get_metadata_or_null((void *)address, to_fill, /*is_origin*/true);
		if (!origin_start)
			/* Can happen e.g. if the memory is untracked. */
			continue;
		kmsan_write_aligned_origin_inline(origin_start, to_fill, origin);
		address += to_fill;
		size -= to_fill;
	}
}

void __msan_poison_alloca(void *address, u64 size, char *descr)
{
	depot_stack_handle_t handle;
	unsigned long entries[4];
	unsigned long irq_flags;
	u64 size_copy = size, to_fill;
	u64 addr_copy = (u64)address;
	u64 page_offset;
	void *shadow_start;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	while (size_copy) {
		page_offset = addr_copy % PAGE_SIZE;
		to_fill = min(PAGE_SIZE - page_offset, size_copy);
		shadow_start = kmsan_get_metadata_or_null((void *)addr_copy, to_fill, /*is_origin*/false);
		if (!shadow_start)
			/* Can happen e.g. if the memory is untracked. */
			continue;
		__memset(shadow_start, -1, to_fill);
		addr_copy += to_fill;
		size_copy -= to_fill;
	}

	entries[0] = KMSAN_ALLOCA_MAGIC_ORIGIN;
	entries[1] = (u64)descr;
	entries[2] = (u64)__builtin_return_address(0);
	entries[3] = (u64)kmsan_internal_return_address(1);

	/* stack_depot_save() may allocate memory. */
	ENTER_RUNTIME(irq_flags);
	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC);
	LEAVE_RUNTIME(irq_flags);
	kmsan_set_origin_inline(address, size, handle);
}
EXPORT_SYMBOL(__msan_poison_alloca);

void __msan_unpoison_alloca(void *address, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	/* Assuming the shadow exists. */
	kmsan_internal_unpoison_shadow(address, size, /*checked*/true);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_unpoison_alloca);

void __msan_warning(u32 origin)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_report(origin, /*address*/0, /*size*/0,
		/*off_first*/0, /*off_last*/0, /*user_addr*/0, /*deep*/false,
		REASON_ANY);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_warning);

kmsan_context_state *__msan_get_context_state(void)
{
	kmsan_context_state *ret;

	ret = task_kmsan_context_state();
	BUG_ON(!ret);
	return ret;
}
EXPORT_SYMBOL(__msan_get_context_state);
