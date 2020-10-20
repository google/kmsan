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

void kmsan_unpoison_pt_regs(struct pt_regs *regs)
{
	if (!kmsan_ready || kmsan_in_runtime() || !regs)
		return;
	kmsan_internal_unpoison_shadow(regs, sizeof(*regs), /*checked*/ true);
}
EXPORT_SYMBOL(kmsan_unpoison_pt_regs);
