/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN checks to be used for one-off annotations in subsystems.
 *
 * Copyright (C) 2017-2021 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#ifndef _LINUX_KMSAN_CHECKS_H
#define _LINUX_KMSAN_CHECKS_H

#include <linux/types.h>

#ifdef CONFIG_KMSAN

/*
 * Helper functions that mark the return value initialized.
 * See mm/kmsan/annotations.c.
 */
u8 kmsan_init_1(u8 value);
u16 kmsan_init_2(u16 value);
u32 kmsan_init_4(u32 value);
u64 kmsan_init_8(u64 value);

static inline void *kmsan_init_ptr(void *ptr)
{
	return (void *)kmsan_init_8((u64)ptr);
}

static inline char kmsan_init_char(char value)
{
	return (u8)kmsan_init_1((u8)value);
}

#define __decl_kmsan_init_type(type, fn) unsigned type : fn, signed type : fn

/**
 * kmsan_init - Make the value initialized.
 * @val: 1-, 2-, 4- or 8-byte integer that may be treated as uninitialized by
 *       KMSAN.
 *
 * Return: value of @val that KMSAN treats as initialized.
 */
#define kmsan_init(val)                                                        \
	(							\
	(typeof(val))(_Generic((val),				\
		__decl_kmsan_init_type(char, kmsan_init_1),	\
		__decl_kmsan_init_type(short, kmsan_init_2),	\
		__decl_kmsan_init_type(int, kmsan_init_4),	\
		__decl_kmsan_init_type(long, kmsan_init_8),	\
		char : kmsan_init_char,				\
		void * : kmsan_init_ptr)(val)))

/**
 * kmsan_poison_memory() - Mark the memory range as uninitialized.
 * @address: address to start with.
 * @size:    size of buffer to poison.
 * @flags:   GFP flags for allocations done by this function.
 *
 * Until other data is written to this range, KMSAN will treat it as
 * uninitialized. Error reports for this memory will reference the call site of
 * kmsan_poison_memory() as origin.
 */
void kmsan_poison_memory(const void *address, size_t size, gfp_t flags);

/**
 * kmsan_unpoison_memory() -  Mark the memory range as initialized.
 * @address: address to start with.
 * @size:    size of buffer to unpoison.
 *
 * Until other data is written to this range, KMSAN will treat it as
 * initialized.
 */
void kmsan_unpoison_memory(const void *address, size_t size);

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

#define kmsan_init(value) (value)

static inline void kmsan_poison_memory(const void *address, size_t size,
				       gfp_t flags)
{
}
static inline void kmsan_unpoison_memory(const void *address, size_t size)
{
}
static inline void kmsan_check_memory(const void *address, size_t size)
{
}
static inline void kmsan_copy_to_user(const void *to, const void *from,
				      size_t to_copy, size_t left)
{
}

#endif

#endif /* _LINUX_KMSAN_CHECKS_H */
