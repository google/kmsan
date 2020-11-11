/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN checks to be used for one-off annotations in subsystems.
 *
 * Copyright (C) 2017-2020 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
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

u8 kmsan_init_1(u8 value);
u16 kmsan_init_2(u16 value);
u32 kmsan_init_4(u32 value);
u64 kmsan_init_8(u64 value);

/**
 * KMSAN_INIT_VALUE - Make the value initialized.
 * @val: 1-, 2-, 4- or 8-byte integer that may be treated as uninitialized by
 *       KMSAN's.
 *
 * Return: value of @val that KMSAN treats as initialized.
 */
#define KMSAN_INIT_VALUE(val)		\
	({				\
		typeof(val) __ret;	\
		switch (sizeof(val)) {	\
		case 1:						\
			*(u8 *)&__ret = kmsan_init_1((u8)val);	\
			break;					\
		case 2:						\
			*(u16 *)&__ret = kmsan_init_2((u16)val);\
			break;					\
		case 4:						\
			*(u32 *)&__ret = kmsan_init_4((u32)val);\
			break;					\
		case 8:						\
			*(u64 *)&__ret = kmsan_init_8((u64)val);\
			break;					\
		default:					\
			BUILD_BUG_ON(1);			\
		}						\
		__ret;						\
	}) /**/

/**
 * kmsan_poison_shadow() - Mark the memory range as uninitialized.
 * @address: address to start with.
 * @size:    size of buffer to poison.
 * @flags:   GFP flags for allocations done by this function.
 *
 * Until other data is written to this range, KMSAN will treat it as
 * uninitialized. Error reports for this memory will reference the call site of
 * kmsan_poison_shadow() as origin.
 */
void kmsan_poison_shadow(const void *address, size_t size, gfp_t flags);

/**
 * kmsan_unpoison_shadow() -  Mark the memory range as initialized.
 * @address: address to start with.
 * @size:    size of buffer to unpoison.
 *
 * Until other data is written to this range, KMSAN will treat it as
 * initialized.
 */
void kmsan_unpoison_shadow(const void *address, size_t size);

/**
 * kmsan_check_memory() - Check the memory range for being initialized.
 * @address: address to start with.
 * @size:    size of buffer to check.
 *
 * If any piece of the given range is marked as uninitialized, KMSAN will report
 * an error.
 */
void kmsan_check_memory(const void *address, size_t size);

/**
 * kmsan_copy_to_user() - Notify KMSAN about a data transfer to userspace.
 * @to:      destination address in the userspace.
 * @from:    source address in the kernel.
 * @to_copy: number of bytes to copy.
 * @left:    number of bytes not copied.
 *
 * If this is a real userspace data transfer, KMSAN checks the bytes that were
 * actually copied to ensure there was no information leak. If @to belongs to
 * the kernel space (which is possible for compat syscalls), KMSAN just copies
 * the metadata.
 */
void kmsan_copy_to_user(const void *to, const void *from, size_t to_copy,
			size_t left);



#else

#define KMSAN_INIT_VALUE(value) (value)

static inline void kmsan_poison_shadow(const void *address, size_t size,
				       gfp_t flags) {}
static inline void kmsan_unpoison_shadow(const void *address, size_t size) {}
static inline void kmsan_check_memory(const void *address, size_t size) {}
static inline void kmsan_copy_to_user(const void *to, const void *from, size_t to_copy,
				      size_t left) {}



#endif

#endif /* _LINUX_KMSAN_CHECKS_H */
