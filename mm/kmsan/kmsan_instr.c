/*
 * KMSAN compiler API.
 *
 * Copyright (C) 2017 Google, Inc
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */


#include "kmsan.h"
#include <linux/gfp.h>

// TODO(glider): dummy shadow should be per-task.
// TODO(glider): ideally, there should be no dummy shadow once we're initialized.
// I.e. we need to remove IN_RUNTIME checks from the fast path.

void check_param_origin_tls(void)
{
	kmsan_context_state *cstate = task_kmsan_context_state();
	int i;
	unsigned long flags;
	return;
	if (!kmsan_ready)
		return;

	for (i = 0; i < KMSAN_PARAM_SIZE / sizeof(depot_stack_handle_t); i++) {
		if (cstate->param_origin_tls[i]) {
			spin_lock_irqsave(&report_lock, flags);
			dump_stack();
			spin_unlock_irqrestore(&report_lock, flags);
		}
		cstate->param_origin_tls[i] = 0;
	}
	for (i = 0; i < KMSAN_PARAM_SIZE / sizeof(void*); i++) {
		cstate->param_tls[i] = 0;
	}
}

// TODO(glider): remove this fn?
// Looks like it's enough to mark syscall entries non-instrumented.
void kmsan_wipe_params_shadow_origin()
{
	int ind, num;
	unsigned long irq_flags;
	kmsan_context_state *cstate = task_kmsan_context_state();

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME() || !current->kmsan.enabled)
		return;
	ENTER_RUNTIME(irq_flags);
	__memset(cstate->param_origin_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->param_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->va_arg_tls, 0, KMSAN_PARAM_SIZE);
	__memset(cstate->retval_tls, 0, RETVAL_SIZE);
	cstate->retval_origin_tls = 0;
	cstate->origin_tls = 0;
	cstate->va_arg_overflow_size_tls = 0;
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_wipe_params_shadow_origin);

typedef struct {
	u64 s;
	u32 o;
} shadow_origin_1;

typedef struct {
	u64 s;
	u32 o;
} shadow_origin_2;

typedef struct {
	u64 s;
	u32 o;
} shadow_origin_4;

typedef struct {
	u64 s;
	// TODO(glider): make __msan_load_shadow_origin() return 2 32-bit origin slots.
	u32 o;
	//u64 o;
} shadow_origin_8;


#define DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(size, shadow_type) \
shadow_origin_##size __msan_load_shadow_origin_##size(u64 addr) \
{	\
	shadow_origin_##size ret = {0, 0};	\
	shadow_type *shadow;			\
	typeof(ret.o) *origin;			\
	unsigned long irq_flags;		\
						\
	if (!kmsan_ready || IN_RUNTIME()) {	\
		return ret;			\
	}					\
	shadow = kmsan_get_shadow_address_noruntime(addr, size, /*checked*/true);	\
	if (!shadow)				\
		goto leave;			\
	ret.s = (u64)*shadow;			\
	if (!ret.s)				\
		goto leave;			\
	ENTER_RUNTIME(irq_flags);		\
	origin = kmsan_get_origin_address(addr, size, /*checked*/true);	\
	BUG_ON(!origin);			\
	ret.o = *origin;			\
	LEAVE_RUNTIME(irq_flags);		\
leave:						\
	return ret;				\
}						\
EXPORT_SYMBOL(__msan_load_shadow_origin_##size);

DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(1, u8);
DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(2, u16);
DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(4, u32);
DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(8, u64);

typedef struct {
	u64 s;
	u32 o;
} shadow_origin_n;

shadow_origin_n __msan_load_shadow_origin_n_8(u64 addr, u64 size)
{
	shadow_origin_n ret = {0, 0};
	u32 *origin;
	unsigned long irq_flags;
	// TODO(glider): the code actually works for other sizes, but
	// it's interesting whether we need them.
	BUG_ON(size != 3);

	if (!kmsan_ready || IN_RUNTIME()) {
		return ret;
	}
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_shadow_to_mem(&ret.s, addr, size);
	if (!ret.s)
		goto leave;
	origin = kmsan_get_origin_address(addr, size, /*checked*/true);
	BUG_ON(!origin);
	ret.o = *origin;
leave:
	LEAVE_RUNTIME(irq_flags);
	return ret;
}

// TODO(glider): pull this declaration under the macro below.
void __msan_store_shadow_origin_8(u64 addr, u64 s, u64 o)
{
	unsigned long irq_flags;
	u64 *shadow;
	u32 hi_o, lo_o;
	u32 new_hi_o, new_lo_o;

	if (!kmsan_ready || IN_RUNTIME()) {
		return;
	}
	shadow = kmsan_get_shadow_address_noruntime(addr, 8, /*checked*/true);
	if (!shadow)
		goto leave;
	*shadow = s;
	if (!s)
		o = 0;
#if 0
	// TODO(glider): for now only the lower 32 bits matter.
	if (use_chained_origins && o) {
                hi_o = (u32)(o >> 32);
		lo_o = (u32)o;
		new_hi_o = kmsan_internal_chain_origin(hi_o, /*full*/true);
		if (lo_o == hi_o)
			new_lo_o = new_hi_o;
		else
			new_lo_o = kmsan_internal_chain_origin(lo_o, /*full*/true);
		// TODO(glider): in which cases new origin can be 0?
		if (new_hi_o)
			hi_o = new_hi_o;
		if (new_lo_o)
			lo_o = new_lo_o;
	}
	kmsan_set_origin(addr, 4, hi_o);
	kmsan_set_origin(addr + 4, 4, lo_o);
#else
	lo_o = (u32)o;
	ENTER_RUNTIME(irq_flags);
	if (use_chained_origins && o) {
		new_lo_o = kmsan_internal_chain_origin(lo_o, /*full*/true);
		// TODO(glider): in which cases new origin can be 0?
		if (new_lo_o)
			lo_o = new_lo_o;
	}
	kmsan_set_origin(addr, 8, lo_o);
	LEAVE_RUNTIME(irq_flags);
#endif
leave:
	return;
}
EXPORT_SYMBOL(__msan_store_shadow_origin_8);

void __msan_store_shadow_origin_n_8(u64 addr, u64 s, u64 o, u64 size)
{
	unsigned long irq_flags;
	u32 new_o;
	void *shadow;

	if (!kmsan_ready || IN_RUNTIME()) {
		return;
	}
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_mem_to_shadow(addr, &s, size);
	if (!s)
		o = 0;
	if (use_chained_origins && o) {
		new_o = kmsan_internal_chain_origin((u32)o, /*full*/true);
		// TODO(glider): in which cases new origin can be 0?
		if (new_o)
			o = new_o;
	}
	kmsan_set_origin(addr, size, (u32)o);
leave:
	LEAVE_RUNTIME(irq_flags);

}

#define DECLARE_KMSAN_STORE_SHADOW_ORIGIN(size, type_s)	\
void __msan_store_shadow_origin_##size(u64 addr, u64 s, u64 o)	\
{						\
	unsigned long irq_flags;		\
	type_s *shadow;				\
	u32 new_origin;				\
						\
	if (!kmsan_ready || IN_RUNTIME()) {	\
		return;				\
	}					\
	shadow = kmsan_get_shadow_address_noruntime(addr, size, /*checked*/true);	\
	if (!shadow)							\
		goto leave;						\
	*shadow = (type_s)s;							\
	if (!s)								\
		o = 0;							\
	ENTER_RUNTIME(irq_flags);		\
	if (use_chained_origins && o) {					\
		new_origin = kmsan_internal_chain_origin(o, /*full*/true);	\
		/* TODO(glider): in which cases new_origin can be 0? */	\
		if (new_origin)						\
			o = new_origin;					\
	}								\
	kmsan_set_origin(addr, size, o);				\
	LEAVE_RUNTIME(irq_flags);					\
leave:									\
	return;								\
}									\
EXPORT_SYMBOL(__msan_store_shadow_origin_##size);
DECLARE_KMSAN_STORE_SHADOW_ORIGIN(1, u8);
DECLARE_KMSAN_STORE_SHADOW_ORIGIN(2, u16);
DECLARE_KMSAN_STORE_SHADOW_ORIGIN(4, u32);

// Essentially a memcpy(shadow(dst), src, size).
// TODO(glider): do we need any checks here?
// TODO(glider): maybe save origins as well?
// Another possible thing to do is to push/pop va_arg shadow.
void __msan_load_arg_shadow(u64 dst, u64 src, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || !kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_mem_to_shadow(dst, src, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_load_arg_shadow);

// Essentially a memcpy(dst, shadow(src), size).
// TODO(glider): do we need any checks here?
// TODO(glider): maybe save origins as well?
// Another possible thing to do is to push/pop va_arg shadow.
void __msan_store_arg_shadow(u64 dst, u64 src, u64 size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || !kmsan_threads_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_memcpy_shadow_to_mem(dst, src, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_store_arg_shadow);

// TODO(glider): rename to __msan_memmove
void *__msan_memmove(void *dst, void *src, u64 n)
{
	void *result;
	void *shadow_dst;
	unsigned long irq_flags;

	result = __memmove(dst, src, n);
	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): due to a hack kmsan_get_shadow_address() may return NULL
	// for addresses in vmalloc space.
	// Or maybe it's enough to just skip copying invalid addresses?

	/* Ok to skip address check here, we'll do it later. */
	shadow_dst = (void*)kmsan_get_shadow_address((u64)dst, n, /*checked*/false);
	if (shadow_dst)
		kmsan_memmove_shadow(dst, src, n);
	else
		kmsan_pr_err("__msan_memmove(%p, %p, %d): skipping shadow\n", dst, src, n);
	// TODO(glider): origins.
	// We may want to chain every |src| origin with the current stack.
	kmsan_memmove_origins((u64)dst, (u64)src, n);
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memmove);

void *__msan_memcpy(void *dst, const void *src, u64 n)
{
	void *result;
	void *shadow_dst;
	unsigned long irq_flags;
	if ((dst != src) && (!(((u64)dst + n <= (u64)src) || ((u64)src + n <= (u64)dst)))) {
		kmsan_pr_err("==================================================================\n");
		// TODO(glider): avoid __builtin_return_address(1).
		kmsan_pr_err("WARNING: memcpy-param-overlap in %pS\n", __builtin_return_address(1));
		kmsan_pr_err("__msan_memcpy(%p, %p, %d)\n", dst, src, n);
		dump_stack();
		kmsan_pr_err("==================================================================\n");
	}

	result = __memcpy(dst, src, n);

	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): see below.
	if (!virt_addr_valid(dst))
		goto leave;
	else {
		if (!virt_addr_valid(src)) {
			///  TODO(glider): handling __vmalloc().
			kmsan_internal_unpoison_shadow(dst, n);
			goto leave;
		}
	}

	/* Ok to skip address check here, we'll do it later. */
	shadow_dst = kmsan_get_shadow_address((u64)dst, n, /*checked*/false);
	// TODO(glider): due to a hack kmsan_get_shadow_address() may return NULL
	// for addresses in vmalloc space.
	// Or maybe it's enough to just skip copying invalid addresses?
	if (shadow_dst)
		kmsan_memcpy_shadow(dst, src, n);
	else
		kmsan_pr_err("__msan_memcpy(%p, %p, %d): skipping shadow\n", dst, src, n);
	// TODO(glider): origins
	// We may want to chain every |src| origin with the current stack.
	kmsan_memcpy_origins((u64)dst, (u64)src, n);
leave:
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memcpy);


void *__msan_memset(void *dst, int c, size_t n)
{
	void *result;
	unsigned long irq_flags;
	depot_stack_handle_t origin, new_origin;
	unsigned int shadow;
	void *caller;

	result = __memset(dst, c, n);
	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): emit stores to param_tls and param_origin_tls in the compiler for KMSAN.
	// (not for MSan, because __msan_memset could be called from the userspace RTL)
	// Take the shadow and origin of |c|.
	///shadow = (unsigned int)(current->kmsan.cstate.param_tls[1]);
	///origin = (depot_stack_handle_t)(current->kmsan.cstate.param_origin_tls[1]);
	shadow = 0;
	kmsan_internal_memset_shadow((u64)dst, shadow, n);
	///new_origin = kmsan_internal_chain_origin(origin, /*full*/true);
	new_origin = 0;
	kmsan_set_origin((u64)dst, n, new_origin);
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memset);

void __msan_poison_alloca(void *a, u64 size, char *descr/*checked*/, u64 pc)
{
	depot_stack_handle_t handle;
	unsigned long entries[4];
	struct stack_trace trace = {
		.nr_entries = 4,
		.entries = entries,
		.max_entries = 4,
		.skip = 0
	};
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
        kmsan_internal_memset_shadow((u64)a, -1, (size_t)size);
	entries[0] = KMSAN_ALLOCA_MAGIC_ORIGIN;
	entries[1] = (u64)descr;
	entries[2] = __builtin_return_address(0);
	entries[3] = pc;
	handle = depot_save_stack(&trace, GFP_ATOMIC);
	// TODO(glider): just a plain origin description isn't enough, let's store the full stack here.
	///handle = kmsan_internal_chain_origin(handle, /*full*/true);
	kmsan_set_origin((u64)a, (int)size, handle);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_poison_alloca);

void __msan_unpoison(void *addr, u64 size)
{
	unsigned long irq_flags;
	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	kmsan_internal_unpoison_shadow(addr, size);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_unpoison);

// Compiler API
void __msan_warning_32(u32 origin)
{
	void *caller;
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	caller = __builtin_return_address(0);
	kmsan_report(caller, origin);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_warning_32);

// Per-task getters.
kmsan_context_state *__msan_get_context_state(void)
{
	unsigned long irq_flags;
	kmsan_context_state *ret;

	if (!kmsan_threads_ready) {
		__memset(&kmsan_dummy_state, 0, sizeof(kmsan_dummy_state));
		return &kmsan_dummy_state;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		// We're in runtime, don't care about the shadow.
		///__memset(&kmsan_dummy_state, 0, sizeof(kmsan_dummy_state)); // TODO(glider)
		return &kmsan_dummy_state;
	}
	// No need to enter/leave runtime?
	ENTER_RUNTIME(irq_flags);
	ret = task_kmsan_context_state();
	LEAVE_RUNTIME(irq_flags);

	BUG_ON(!ret);

	return ret;
}
EXPORT_SYMBOL(__msan_get_context_state);
