/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN internal declarations.
 *
 * Copyright (C) 2017-2020 Google LLC
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

#include "kmsan_shadow.h"

#define KMSAN_MAGIC_MASK 0xffffffffff00
#define KMSAN_ALLOCA_MAGIC_ORIGIN 0x4110c4071900
#define KMSAN_CHAIN_MAGIC_ORIGIN_FULL 0xd419170cba00

#define KMSAN_POISON_NOCHECK 0x0
#define KMSAN_POISON_CHECK 0x1
#define KMSAN_POISON_FREE 0x2

#define ORIGIN_SIZE 4

#define META_SHADOW (false)
#define META_ORIGIN (true)

DECLARE_PER_CPU(struct kmsan_task_state, kmsan_percpu_tstate);

extern spinlock_t report_lock;
extern bool kmsan_ready;

void kmsan_print_origin(depot_stack_handle_t origin);
void kmsan_report(depot_stack_handle_t origin, void *address, int size,
		  int off_first, int off_last, const void *user_addr,
		  int reason);

enum KMSAN_BUG_REASON {
	REASON_ANY,
	REASON_COPY_TO_USER,
	REASON_USE_AFTER_FREE,
	REASON_SUBMIT_URB,
};

/*
 * When a compiler hook is invoked, it may make a call to instrumented code
 * and eventually call itself recursively. To avoid that, we protect the
 * runtime entry points with kmsan_enter_runtime()/kmsan_leave_runtime() and
 * exit the hook if kmsan_in_runtime() is true. But when an interrupt occurs
 * inside the runtime, the hooks won’t run either, which may lead to errors.
 * Therefore we have to disable interrupts inside the runtime.
 */
struct kmsan_task_state *kmsan_get_task_state(void);

static __always_inline bool kmsan_in_runtime(void)
{
	return kmsan_get_task_state()->kmsan_in_runtime;
}

static __always_inline unsigned long kmsan_enter_runtime(void)
{
	int level;
	unsigned long irq_flags;
	struct kmsan_task_state *ctx;

	local_irq_save(irq_flags);
	stop_nmi();
	ctx = kmsan_get_task_state();
	level = ++ctx->kmsan_in_runtime;
	BUG_ON(level != 1);
	return irq_flags;
}

static __always_inline void kmsan_leave_runtime(unsigned long irq_flags)
{
	struct kmsan_task_state *ctx = kmsan_get_task_state();
	int level = --ctx->kmsan_in_runtime;

	if (level)
		panic("kmsan_in_runtime: %d\n", level);
	restart_nmi();
	local_irq_restore(irq_flags);
}

void kmsan_memcpy_metadata(void *dst, void *src, size_t n);
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

void kmsan_internal_poison_shadow(void *address, size_t size, gfp_t flags,
				  unsigned int poison_flags);
void kmsan_internal_unpoison_shadow(void *address, size_t size, bool checked);
void kmsan_internal_memset_shadow(void *address, int b, size_t size,
				  bool checked);
depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);
void kmsan_write_aligned_origin(void *var, size_t size, u32 origin);

void kmsan_internal_task_create(struct task_struct *task);
void kmsan_internal_set_origin(void *addr, int size, u32 origin);
void kmsan_set_origin_checked(void *addr, int size, u32 origin, bool checked);

bool metadata_is_contiguous(void *addr, size_t size, bool is_origin);
void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
				 int reason);

struct page *vmalloc_to_page_or_null(void *vaddr);

/* Declared in mm/vmalloc.c */
void __unmap_kernel_range_noflush(unsigned long start, unsigned long size);
int __map_kernel_range_noflush(unsigned long addr, unsigned long size,
			       pgprot_t prot, struct page **pages);

void *kmsan_internal_return_address(int arg);
bool kmsan_internal_is_module_addr(void *vaddr);
bool kmsan_internal_is_vmalloc_addr(void *addr);

#endif /* __MM_KMSAN_KMSAN_H */
