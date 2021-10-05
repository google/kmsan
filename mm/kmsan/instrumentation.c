// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN compiler API.
 *
 * Copyright (C) 2017-2021 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#include "kmsan.h"
#include <linux/gfp.h>
#include <linux/mm.h>

static bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
{
	if ((u64)addr < TASK_SIZE)
		return true;
	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
		return true;
	return false;
}

struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
							uintptr_t size)
{
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/ false);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_load_n);

struct shadow_origin_ptr __msan_metadata_ptr_for_store_n(void *addr,
							 uintptr_t size)
{
	return kmsan_get_shadow_origin_ptr(addr, size, /*store*/ true);
}
EXPORT_SYMBOL(__msan_metadata_ptr_for_store_n);

#define DECLARE_METADATA_PTR_GETTER(size)                                      \
	struct shadow_origin_ptr __msan_metadata_ptr_for_load_##size(          \
		void *addr)                                                    \
	{                                                                      \
		return kmsan_get_shadow_origin_ptr(addr, size,                 \
						   /*store*/ false);           \
	}                                                                      \
	EXPORT_SYMBOL(__msan_metadata_ptr_for_load_##size);                    \
                                                                               \
	struct shadow_origin_ptr __msan_metadata_ptr_for_store_##size(         \
		void *addr)                                                    \
	{                                                                      \
		return kmsan_get_shadow_origin_ptr(addr, size,                 \
						   /*store*/ true);            \
	}                                                                      \
	EXPORT_SYMBOL(__msan_metadata_ptr_for_store_##size)

DECLARE_METADATA_PTR_GETTER(1);
DECLARE_METADATA_PTR_GETTER(2);
DECLARE_METADATA_PTR_GETTER(4);
DECLARE_METADATA_PTR_GETTER(8);

void __msan_instrument_asm_store(void *addr, uintptr_t size)
{
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
	if (is_bad_asm_addr(addr, size, /*is_store*/ true))
		return;
	kmsan_enter_runtime();
	/* Unpoisoning the memory on best effort. */
	kmsan_internal_unpoison_memory(addr, size, /*checked*/ false);
	kmsan_leave_runtime();
}
EXPORT_SYMBOL(__msan_instrument_asm_store);

void *__msan_memmove(void *dst, const void *src, uintptr_t n)
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

void *__msan_memcpy(void *dst, const void *src, uintptr_t n)
{
	void *result;

	result = __memcpy(dst, src, n);
	if (!n)
		/* Some people call memcpy() with zero length. */
		return result;

	if (!kmsan_ready || kmsan_in_runtime())
		return result;

	/* Using memmove instead of memcpy doesn't affect correctness. */
	kmsan_memmove_metadata(dst, (void *)src, n);

	return result;
}
EXPORT_SYMBOL(__msan_memcpy);

void *__msan_memset(void *dst, int c, uintptr_t n)
{
	void *result;

	result = __memset(dst, c, n);
	if (!kmsan_ready || kmsan_in_runtime())
		return result;

	kmsan_enter_runtime();
	/*
	 * Clang doesn't pass parameter metadata here, so it is impossible to
	 * use shadow of @c to set up the shadow for @dst.
	 */
	kmsan_internal_unpoison_memory(dst, n, /*checked*/ false);
	kmsan_leave_runtime();

	return result;
}
EXPORT_SYMBOL(__msan_memset);

depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
{
	depot_stack_handle_t ret = 0;

	if (!kmsan_ready || kmsan_in_runtime())
		return ret;

	/* Creating new origins may allocate memory. */
	kmsan_enter_runtime();
	ret = kmsan_internal_chain_origin(origin);
	kmsan_leave_runtime();
	return ret;
}
EXPORT_SYMBOL(__msan_chain_origin);

void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
{
	depot_stack_handle_t handle;
	unsigned long entries[4];

	if (!kmsan_ready || kmsan_in_runtime())
		return;

	entries[0] = KMSAN_ALLOCA_MAGIC_ORIGIN;
	entries[1] = (u64)descr;
	entries[2] = (u64)__builtin_return_address(0);
	/*
	 * With frame pointers enabled, it is possible to quickly fetch the
	 * second frame of the caller stack without calling the unwinder.
	 * Without them, simply do not bother.
	 */
	if (IS_ENABLED(CONFIG_UNWINDER_FRAME_POINTER))
		entries[3] = (u64)__builtin_return_address(1);
	else
		entries[3] = 0;

	/* stack_depot_save() may allocate memory. */
	kmsan_enter_runtime();
	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC);
	kmsan_leave_runtime();

	kmsan_internal_set_shadow_origin(address, size, -1, handle,
					 /*checked*/ true);
}
EXPORT_SYMBOL(__msan_poison_alloca);

void __msan_unpoison_alloca(void *address, uintptr_t size)
{
	if (!kmsan_ready || kmsan_in_runtime())
		return;

	kmsan_enter_runtime();
	kmsan_internal_unpoison_memory(address, size, /*checked*/ true);
	kmsan_leave_runtime();
}
EXPORT_SYMBOL(__msan_unpoison_alloca);

void __msan_warning(u32 origin)
{
	if (!kmsan_ready || kmsan_in_runtime())
		return;
	kmsan_enter_runtime();
	kmsan_report(origin, /*address*/ 0, /*size*/ 0,
		     /*off_first*/ 0, /*off_last*/ 0, /*user_addr*/ 0,
		     REASON_ANY);
	kmsan_leave_runtime();
}
EXPORT_SYMBOL(__msan_warning);

struct kmsan_context_state *__msan_get_context_state(void)
{
	struct kmsan_context_state *ret = &kmsan_get_context()->cstate;

	BUG_ON(!ret);
	return ret;
}
EXPORT_SYMBOL(__msan_get_context_state);
