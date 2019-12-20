/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Assembly bits to safely invoke KMSAN hooks from .S files.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef _ASM_X86_KMSAN_H
#define _ASM_X86_KMSAN_H

#ifdef CONFIG_KMSAN

#ifdef __ASSEMBLY__
.macro KMSAN_PUSH_REGS
	pushq	%rax
	pushq	%rcx
	pushq	%rdx
	pushq	%rdi
	pushq	%rsi
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
.endm

.macro KMSAN_POP_REGS
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rsi
	popq	%rdi
	popq	%rdx
	popq	%rcx
	popq	%rax

.endm

.macro KMSAN_CALL_HOOK fname
	KMSAN_PUSH_REGS
	call \fname
	KMSAN_POP_REGS
.endm

.macro KMSAN_CONTEXT_ENTER
	KMSAN_CALL_HOOK kmsan_context_enter
.endm

.macro KMSAN_CONTEXT_EXIT
	KMSAN_CALL_HOOK kmsan_context_exit
.endm

#define KMSAN_INTERRUPT_ENTER KMSAN_CONTEXT_ENTER
#define KMSAN_INTERRUPT_EXIT KMSAN_CONTEXT_EXIT

#define KMSAN_SOFTIRQ_ENTER KMSAN_CONTEXT_ENTER
#define KMSAN_SOFTIRQ_EXIT KMSAN_CONTEXT_EXIT

#define KMSAN_NMI_ENTER KMSAN_CONTEXT_ENTER
#define KMSAN_NMI_EXIT KMSAN_CONTEXT_EXIT

#define KMSAN_IST_ENTER(shift_ist) KMSAN_CONTEXT_ENTER
#define KMSAN_IST_EXIT(shift_ist) KMSAN_CONTEXT_EXIT

.macro KMSAN_UNPOISON_PT_REGS
	KMSAN_CALL_HOOK kmsan_unpoison_pt_regs
.endm

#else
#error this header must be included into an assembly file
#endif

#else /* ifdef CONFIG_KMSAN */

#define KMSAN_INTERRUPT_ENTER
#define KMSAN_INTERRUPT_EXIT
#define KMSAN_SOFTIRQ_ENTER
#define KMSAN_SOFTIRQ_EXIT
#define KMSAN_NMI_ENTER
#define KMSAN_NMI_EXIT
#define KMSAN_SYSCALL_ENTER
#define KMSAN_SYSCALL_EXIT
#define KMSAN_IST_ENTER(shift_ist)
#define KMSAN_IST_EXIT(shift_ist)
#define KMSAN_UNPOISON_PT_REGS

#endif /* ifdef CONFIG_KMSAN */
#endif /* ifndef _ASM_X86_KMSAN_H */
