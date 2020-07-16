// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN compiler API.
 *
 * Copyright (C) 2017-2019 Google LLC
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

static bool is_bad_asm_addr(void *addr, u64 size, bool is_store)
{
	if ((u64)addr < TASK_SIZE)
		return true;
	if (!kmsan_get_metadata(addr, size, META_SHADOW))
		return true;
	return false;
}

struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr, u64 size)
{
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/false);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_n);

struct shadow_origin_ptr __msan_metadata_ptr_for_store_n(void *addr, u64 size)
{
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/true);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_n);

#define DECLARE_METADATA_PTR_GETTER(size)	\
struct shadow_origin_ptr __msan_metadata_ptr_for_load_##size(void *addr) \
{		\
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/false);	\
}		\
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_##size);			\
		\
struct shadow_origin_ptr __msan_metadata_ptr_for_store_##size(void *addr) \
{									\
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/true);	\
}									\
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_##size)

DECLARE_METADATA_PTR_GETTER(1);
DECLARE_METADATA_PTR_GETTER(2);
DECLARE_METADATA_PTR_GETTER(4);
DECLARE_METADATA_PTR_GETTER(8);

void __msan_instrument_asm_store(void *addr, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || kmsan_in_runtime())
		return;
	/*
	 * Most of the accesses are below 32 bytes. The two exceptions so far
	 * are clwb() (64 bytes) and FPU state (512 bytes).
	 * It's unlikely that the assembly will touch more than 512 bytes.
	 */
	if (size > 512) {
		WARN_ONCE(1, "assembly store size too big: %d\n", size);
		size = 8;
	}
	if (is_bad_asm_addr(addr, size, /*is_store*/true))
		return;
	irq_flags = kmsan_enter_runtime();
	/* Unpoisoning the memory on best effort. */
	kmsan_internal_unpoison_shadow(addr, size, /*checked*/false);
	kmsan_leave_runtime(irq_flags);
}
EXPORT_SYMBOL(__msan_instrument_asm_store);

void *__msan_memmove(void *dst, const void *src, size_t n)
{
	void *result;

	result = __memmove(dst, src, n);
	if (!n)
		/* Some people call memmove() with zero length. */
		return result;
	if (!kmsan_ready || kmsan_in_runtime())
		return result;

	kmsan_memmove_metadata(dst, (void *)src, n);

	return result;
}
EXPORT_SYMBOL(__msan_memmove);

void *__msan_memmove_nosanitize(void *dst, void *src, size_t n)
{
	return __memmove(dst, src, n);
}
EXPORT_SYMBOL(__msan_memmove_nosanitize);

void *__msan_memcpy(void *dst, const void *src, size_t n)
{
	void *result;

	result = __memcpy(dst, src, n);
	if (!n)
		/* Some people call memcpy() with zero length. */
		return result;

	if (!kmsan_ready || kmsan_in_runtime())
		return result;

	kmsan_memcpy_metadata(dst, (void *)src, n);

	return result;
}
EXPORT_SYMBOL(__msan_memcpy);

void *__msan_memcpy_nosanitize(void *dst, void *src, size_t n)
{
	return __memcpy(dst, src, n);
}
EXPORT_SYMBOL(__msan_memcpy_nosanitize);

void *__msan_memset(void *dst, int c, size_t n)
{
	void *result;
	unsigned long irq_flags;

	result = __memset(dst, c, n);
	if (!kmsan_ready || kmsan_in_runtime())
		return result;

	irq_flags = kmsan_enter_runtime();
	/*
	 * Clang doesn't pass parameter metadata here, so it is impossible to
	 * use shadow of @c to set up the shadow for @dst.
	 */
	kmsan_internal_unpoison_shadow(dst, n, /*checked*/false);
	kmsan_leave_runtime(irq_flags);

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

	if (!kmsan_ready || kmsan_in_runtime())
		return ret;

	/* Creating new origins may allocate memory. */
	irq_flags = kmsan_enter_runtime();
	ret = kmsan_internal_chain_origin(origin);
	kmsan_leave_runtime(irq_flags);
	return ret;
}
EXPORT_SYMBOL(__msan_chain_origin);

void __msan_poison_alloca(void *address, u64 size, char *descr)
{
	depot_stack_handle_t handle;
	unsigned long entries[4];
	unsigned long irq_flags;

	if (!kmsan_ready || kmsan_in_runtime())
		return;

	kmsan_internal_memset_shadow(address, -1, size, /*checked*/true);

	entries[0] = KMSAN_ALLOCA_MAGIC_ORIGIN;
	entries[1] = (u64)descr;
	entries[2] = (u64)__builtin_return_address(0);
	entries[3] = (u64)kmsan_internal_return_address(1);

	/* stack_depot_save() may allocate memory. */
	irq_flags = kmsan_enter_runtime();
	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC);
	kmsan_leave_runtime(irq_flags);
	kmsan_internal_set_origin(address, size, handle);
}
EXPORT_SYMBOL(__msan_poison_alloca);

void __msan_unpoison_alloca(void *address, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || kmsan_in_runtime())
		return;

	irq_flags = kmsan_enter_runtime();
	kmsan_internal_unpoison_shadow(address, size, /*checked*/true);
	kmsan_leave_runtime(irq_flags);
}
EXPORT_SYMBOL(__msan_unpoison_alloca);

void __msan_warning(u32 origin)
{
	unsigned long irq_flags;

	if (!kmsan_ready || kmsan_in_runtime())
		return;
	irq_flags = kmsan_enter_runtime();
	kmsan_report(origin, /*address*/0, /*size*/0,
		/*off_first*/0, /*off_last*/0, /*user_addr*/0, REASON_ANY);
	kmsan_leave_runtime(irq_flags);
}
EXPORT_SYMBOL(__msan_warning);

struct kmsan_context_state *__msan_get_context_state(void)
{
	struct kmsan_context_state *ret;

	ret = kmsan_task_context_state();
	BUG_ON(!ret);
	return ret;
}
EXPORT_SYMBOL(__msan_get_context_state);
