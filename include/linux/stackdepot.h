/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * A generic stack depot implementation
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on code by Dmitry Chernenkov.
 */

#ifndef _LINUX_STACKDEPOT_H
#define _LINUX_STACKDEPOT_H

#include <linux/gfp.h>

typedef u32 depot_stack_handle_t;
/*
 * Number of bits in the handle that stack depot doesn't use. Users may store
 * information in them.
 */
#define STACK_DEPOT_EXTRA_BITS 5

depot_stack_handle_t __stack_depot_save(unsigned long *entries,
					unsigned int nr_entries,
					unsigned int extra_bits,
					gfp_t gfp_flags, bool can_alloc);

depot_stack_handle_t stack_depot_save(unsigned long *entries,
				      unsigned int nr_entries, gfp_t gfp_flags);

unsigned int stack_depot_fetch(depot_stack_handle_t handle,
			       unsigned long **entries);

unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);

int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
		       int spaces);

void stack_depot_print(depot_stack_handle_t stack);

#ifdef CONFIG_STACKDEPOT
int stack_depot_init(void);
#else
static inline int stack_depot_init(void)
{
	return 0;
}
#endif	/* CONFIG_STACKDEPOT */

#endif
