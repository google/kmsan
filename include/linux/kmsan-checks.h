/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN checks to be used for one-off annotations in subsystems.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _LINUX_KMSAN_CHECKS_H
#define _LINUX_KMSAN_CHECKS_H

#include <linux/build_bug.h>
#include <linux/types.h>

#ifdef CONFIG_KMSAN

/*
 * Helper functions that mark the return value initialized.
 * Note that Clang ignores the inline attribute in the cases when a no_sanitize
 * function is called from an instrumented one. For the same reason these
 * functions may not be declared __always_inline - in that case they dissolve in
 * the callers and KMSAN won't be able to notice they should not be
 * instrumented.
 */

__no_sanitize_memory
static inline u8 KMSAN_INIT_1(u8 value)
{
	return value;
}

__no_sanitize_memory
static inline u16 KMSAN_INIT_2(u16 value)
{
	return value;
}

__no_sanitize_memory
static inline u32 KMSAN_INIT_4(u32 value)
{
	return value;
}

__no_sanitize_memory
static inline u64 KMSAN_INIT_8(u64 value)
{
	return value;
}

/* Make the value initialized. */
#define KMSAN_INIT_VALUE(val)		\
	({				\
		typeof(val) __ret;	\
		switch (sizeof(val)) {	\
		case 1:						\
			*(u8 *)&__ret = KMSAN_INIT_1((u8)val);	\
			break;					\
		case 2:						\
			*(u16 *)&__ret = KMSAN_INIT_2((u16)val);\
			break;					\
		case 4:						\
			*(u32 *)&__ret = KMSAN_INIT_4((u32)val);\
			break;					\
		case 8:						\
			*(u64 *)&__ret = KMSAN_INIT_8((u64)val);\
			break;					\
		default:					\
			BUILD_BUG_ON(1);			\
		}						\
		__ret;						\
	}) /**/

/*
 * Mark the memory range as uninitialized. Error reports for that memory will
 * reference the call site of kmsan_poison_shadow() as origin.
 */
void kmsan_poison_shadow(const void *address, size_t size, gfp_t flags);

/* Mark the memory range as initialized. */
void kmsan_unpoison_shadow(const void *address, size_t size);

/*
 * Check the memory range for being initialized and report errors for every
 * uninitialized subrange.
 */
void kmsan_check_memory(const void *address, size_t size);

#else

#define KMSAN_INIT_VALUE(value) (value)

static inline void kmsan_poison_shadow(const void *address, size_t size,
				       gfp_t flags) {}
static inline void kmsan_unpoison_shadow(const void *address, size_t size) {}
static inline void kmsan_check_memory(const void *address, size_t size) {}

#endif

#endif /* _LINUX_KMSAN_CHECKS_H */
