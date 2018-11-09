/*
 * KMSAN hooks for entry_64.S
 *
 * Copyright (C) 2018 Google, Inc
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/percpu-defs.h>

#include "kmsan.h"

static inline void kmsan_context_enter(void)
{
	int level = this_cpu_read(kmsan_context_level) + 1;
	BUG_ON(level >= KMSAN_NESTED_CONTEXT_MAX);
	this_cpu_write(kmsan_context_level, level);
}

static inline void kmsan_context_exit(void)
{
	int level = this_cpu_read(kmsan_context_level) - 1;
	BUG_ON(level < 0);
	this_cpu_write(kmsan_context_level, level);
}

void kmsan_interrupt_enter(void)
{
	int in_interrupt = this_cpu_read(kmsan_in_interrupt);

	// Turns out it's possible for in_interrupt to be >0 here.
	kmsan_context_enter();
	BUG_ON(in_interrupt > 1);
	// Can't check preempt_count() here, it may be zero.
	this_cpu_write(kmsan_in_interrupt, in_interrupt + 1);
}
EXPORT_SYMBOL(kmsan_interrupt_enter);

void kmsan_interrupt_exit(void)
{
	int in_interrupt = this_cpu_read(kmsan_in_interrupt);

	BUG_ON(!in_interrupt);
	kmsan_context_exit();
	// Can't check preempt_count() here, it may be zero.
	this_cpu_write(kmsan_in_interrupt, in_interrupt - 1);
}
EXPORT_SYMBOL(kmsan_interrupt_exit);

void kmsan_softirq_enter(void)
{
	bool in_softirq = this_cpu_read(kmsan_in_softirq);

	BUG_ON(in_softirq);
	kmsan_context_enter();
	// Can't check preempt_count() here, it may be zero.
	this_cpu_write(kmsan_in_softirq, true);
}
EXPORT_SYMBOL(kmsan_softirq_enter);

void kmsan_softirq_exit(void)
{
	bool in_softirq = this_cpu_read(kmsan_in_softirq);

	BUG_ON(!in_softirq);
	kmsan_context_exit();
	// Can't check preempt_count() here, it may be zero.
	this_cpu_write(kmsan_in_softirq, false);
}
EXPORT_SYMBOL(kmsan_softirq_exit);

void kmsan_nmi_enter(void)
{
	bool in_nmi = this_cpu_read(kmsan_in_nmi);

	BUG_ON(in_nmi);
	BUG_ON(preempt_count() & NMI_MASK);
	kmsan_context_enter();
	this_cpu_write(kmsan_in_nmi, true);
}
EXPORT_SYMBOL(kmsan_nmi_enter);

void kmsan_nmi_exit(void)
{
	bool in_nmi = this_cpu_read(kmsan_in_nmi);

	BUG_ON(!in_nmi);
	BUG_ON(preempt_count() & NMI_MASK);
	kmsan_context_exit();
	this_cpu_write(kmsan_in_nmi, false);

}
EXPORT_SYMBOL(kmsan_nmi_exit);

void kmsan_syscall_enter(void)
{

}
EXPORT_SYMBOL(kmsan_syscall_enter);

void kmsan_syscall_exit(void)
{

}
EXPORT_SYMBOL(kmsan_syscall_exit);

void kmsan_ist_enter(u64 shift_ist)
{
	kmsan_context_enter();
}
EXPORT_SYMBOL(kmsan_ist_enter);

void kmsan_ist_exit(u64 shift_ist)
{
	kmsan_context_exit();
}
EXPORT_SYMBOL(kmsan_ist_exit);

void kmsan_unpoison_pt_regs(struct pt_regs *regs)
{
	if (!kmsan_ready || IN_RUNTIME())
		return;
	kmsan_internal_unpoison_shadow(regs, sizeof(*regs), /*checked*/true);
}
