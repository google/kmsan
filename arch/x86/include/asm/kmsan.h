/* Adopted from https://github.com/google/ktsan/commit/f213f1b741c9468f6a692b012d40bdcd8d8dffca */
#ifndef _ASM_X86_KMSAN_H
#define _ASM_X86_KMSAN_H

#ifdef CONFIG_KMSAN

#define KMSAN_PUSH_REGS				\
	pushq	%rax;				\
	pushq	%rcx;				\
	pushq	%rdx;				\
	pushq	%rdi;				\
	pushq	%rsi;				\
	pushq	%r8;				\
	pushq	%r9;				\
	pushq	%r10;				\
	pushq	%r11;				\
/**/

#define KMSAN_POP_REGS				\
	popq	%r11;				\
	popq	%r10;				\
	popq	%r9;				\
	popq	%r8;				\
	popq	%rsi;				\
	popq	%rdi;				\
	popq	%rdx;				\
	popq	%rcx;				\
	popq	%rax;				\
/**/

#define KMSAN_INTERRUPT_ENTER			\
	KMSAN_PUSH_REGS				\
	call	kmsan_interrupt_enter;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_INTERRUPT_EXIT			\
	KMSAN_PUSH_REGS				\
	call	kmsan_interrupt_exit;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_SOFTIRQ_ENTER			\
	KMSAN_PUSH_REGS				\
	call	kmsan_softirq_enter;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_SOFTIRQ_EXIT			\
	KMSAN_PUSH_REGS				\
	call	kmsan_softirq_exit;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_NMI_ENTER				\
	KMSAN_PUSH_REGS				\
	call	kmsan_nmi_enter;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_NMI_EXIT				\
	KMSAN_PUSH_REGS				\
	call	kmsan_nmi_exit;			\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_SYSCALL_ENTER			\
	KMSAN_PUSH_REGS				\
	call	kmsan_syscall_enter;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_SYSCALL_EXIT			\
	KMSAN_PUSH_REGS				\
	call	kmsan_syscall_exit;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_IST_ENTER(shift_ist)		\
	KMSAN_PUSH_REGS				\
	movq	$shift_ist, %rdi;		\
	call	kmsan_ist_enter;		\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_IST_EXIT(shift_ist)		\
	KMSAN_PUSH_REGS				\
	movq	$shift_ist, %rdi;		\
	call	kmsan_ist_exit;			\
	KMSAN_POP_REGS				\
/**/

#define KMSAN_UNPOISON_PT_REGS			\
	KMSAN_PUSH_REGS				\
	call	kmsan_unpoison_pt_regs;		\
	KMSAN_POP_REGS				\
/**/


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
