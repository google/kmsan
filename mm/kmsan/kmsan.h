/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN internal declarations.
 *
 * Copyright (C) 2017-2021 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#ifndef __MM_KMSAN_KMSAN_H
#define __MM_KMSAN_KMSAN_H

#include <asm/pgtable_64_types.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/nmi.h>
#include <linux/mm.h>
#include <linux/printk.h>

#include "shadow.h"

#define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
#define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200

#define KMSAN_POISON_NOCHECK 0x0
#define KMSAN_POISON_CHECK 0x1
#define KMSAN_POISON_FREE 0x2

#define KMSAN_ORIGIN_SIZE 4

#define KMSAN_STACK_DEPTH 64

#define KMSAN_META_SHADOW (false)
#define KMSAN_META_ORIGIN (true)

extern bool kmsan_ready;

enum kmsan_bug_reason {
	REASON_ANY,
	REASON_COPY_TO_USER,
	REASON_SUBMIT_URB,
};


void kmsan_print_origin(depot_stack_handle_t origin);

/**
 * kmsan_report() - Report a use of uninitialized value.
 * @origin:    Stack ID of the uninitialized value.
 * @address:   Address at which the memory access happens.
 * @size:      Memory access size.
 * @off_first: Offset (from @address) of the first byte to be reported.
 * @off_last:  Offset (from @address) of the last byte to be reported.
 * @user_addr: When non-NULL, denotes the userspace address to which the kernel
 *             is leaking data.
 * @reason:    Error type from enum kmsan_bug_reason.
 *
 * kmsan_report() prints an error message for a consequent group of bytes
 * sharing the same origin. If an uninitialized value is used in a comparison,
 * this function is called once without specifying the addresses. When checking
 * a memory range, KMSAN may call kmsan_report() multiple times with the same
 * @address, @size, @user_addr and @reason, but different @off_first and
 * @off_last corresponding to different @origin values.
 */
void kmsan_report(depot_stack_handle_t origin, void *address, int size,
		  int off_first, int off_last, const void *user_addr,
		  enum kmsan_bug_reason reason);

DECLARE_PER_CPU(struct kmsan_context, kmsan_percpu_ctx);

static __always_inline struct kmsan_context *kmsan_get_context(void)
{
	return in_task() ? &current->kmsan : raw_cpu_ptr(&kmsan_percpu_ctx);
}

/*
 * When a compiler hook is invoked, it may make a call to instrumented code
 * and eventually call itself recursively. To avoid that, we protect the
 * runtime entry points with kmsan_enter_runtime()/kmsan_leave_runtime() and
 * exit the hook if kmsan_in_runtime() is true. But when an interrupt occurs
 * inside the runtime, the hooks won’t run either, which may lead to errors.
 * Therefore we have to disable interrupts inside the runtime.
 */

static __always_inline bool kmsan_in_runtime(void)
{
	return kmsan_get_context()->kmsan_in_runtime;
}

static __always_inline unsigned long kmsan_enter_runtime(void)
{
	unsigned long irq_flags;
	struct kmsan_context *ctx;

	local_irq_save(irq_flags);
	stop_nmi();
	ctx = kmsan_get_context();
	BUG_ON(ctx->kmsan_in_runtime++);
	return irq_flags;
}

static __always_inline void kmsan_leave_runtime(unsigned long irq_flags)
{
	struct kmsan_context *ctx = kmsan_get_context();

	BUG_ON(--ctx->kmsan_in_runtime);
	restart_nmi();
	local_irq_restore(irq_flags);
}

void kmsan_memmove_metadata(void *dst, void *src, size_t n);

depot_stack_handle_t kmsan_save_stack(void);
depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
						 unsigned int extra_bits);

/*
 * Pack and unpack the origin chain depth and UAF flag to/from the extra bits
 * provided by the stack depot.
 * The UAF flag is stored in the lowest bit, followed by the depth in the upper
 * bits.
 * set_dsh_extra_bits() is responsible for clamping the value.
 */
static __always_inline unsigned int kmsan_extra_bits(unsigned int depth,
						     bool uaf)
{
	return (depth << 1) | uaf;
}

static __always_inline bool kmsan_uaf_from_eb(unsigned int extra_bits)
{
	return extra_bits & 1;
}

static __always_inline unsigned int kmsan_depth_from_eb(unsigned int extra_bits)
{
	return extra_bits >> 1;
}

void kmsan_internal_poison_memory(void *address, size_t size, gfp_t flags,
				  unsigned int poison_flags);
void kmsan_internal_unpoison_memory(void *address, size_t size, bool checked);
void kmsan_internal_set_shadow_origin(void *address, size_t size, int b, u32 origin,
				  bool checked);
depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);

void kmsan_internal_task_create(struct task_struct *task);

bool kmsan_metadata_is_contiguous(void *addr, size_t size);
void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
				 int reason);

struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
void kmsan_setup_meta(struct page *page, struct page *shadow,
		      struct page *origin, int order);

/* Declared in mm/vmalloc.c */
void __vunmap_range_noflush(unsigned long start, unsigned long end);
int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
			       pgprot_t prot, struct page **pages,
			       unsigned int page_shift);

/* Declared in mm/internal.h */
void __free_pages_core(struct page *page, unsigned int order);

void *kmsan_internal_return_address(int arg);
bool kmsan_internal_is_module_addr(void *vaddr);
bool kmsan_internal_is_vmalloc_addr(void *addr);

#endif /* __MM_KMSAN_KMSAN_H */
