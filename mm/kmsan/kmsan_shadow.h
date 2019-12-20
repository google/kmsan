/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN shadow API.
 *
 * This should be agnostic to shadow implementation details.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __MM_KMSAN_KMSAN_SHADOW_H
#define __MM_KMSAN_KMSAN_SHADOW_H

#include <asm/cpu_entry_area.h>  /* for CPU_ENTRY_AREA_MAP_SIZE */

struct shadow_origin_ptr {
	void *s, *o;
};

struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
						     bool store);
void *kmsan_get_metadata(void *addr, size_t size, bool is_origin);
void __init kmsan_init_alloc_meta_for_range(void *start, void *end);

#endif  /* __MM_KMSAN_KMSAN_SHADOW_H */
