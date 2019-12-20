// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN hooks for entry_64.S
 *
 * Copyright (C) 2018-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include "kmsan.h"

void kmsan_context_enter(void)
{
	int level = this_cpu_inc_return(kmsan_context_level);

	BUG_ON(level >= KMSAN_NESTED_CONTEXT_MAX);
}
EXPORT_SYMBOL(kmsan_context_enter);

void kmsan_context_exit(void)
{
	int level = this_cpu_dec_return(kmsan_context_level);

	BUG_ON(level < 0);
}
EXPORT_SYMBOL(kmsan_context_exit);

void kmsan_unpoison_pt_regs(struct pt_regs *regs)
{
	if (!kmsan_ready || kmsan_in_runtime())
		return;
	kmsan_internal_unpoison_shadow(regs, sizeof(*regs), /*checked*/true);
}
EXPORT_SYMBOL(kmsan_unpoison_pt_regs);
