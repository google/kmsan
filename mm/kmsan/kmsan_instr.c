/* KMSAN compiler API
 */

#include "kmsan.h"

// TODO(glider): dummy shadow should be per-task.
// TODO(glider): ideally, there should be no dummy shadow once we're initialized.
// I.e. we need to remove IN_RUNTIME checks from the fast path.

void check_param_origin_tls(void)
{
	int inter = task_tls_index();
	int i;
	unsigned long flags;
	return;
	if (!kmsan_ready)
		return;

	for (i = 0; i < PARAM_SIZE / sizeof(depot_stack_handle_t); i++) {
		///if (current->kmsan.param_origin_tls[inter][i] == 0xfeedface) {
		if (current->kmsan.param_origin_tls[inter][i]) {
			spin_lock_irqsave(&report_lock, flags);
			kmsan_pr_err("bad origin at function start: %p, inter=%d, &inter (~sp): %p\n", current->kmsan.param_origin_tls[inter][i], inter, &inter);
			dump_stack();
			spin_unlock_irqrestore(&report_lock, flags);
		}
		current->kmsan.param_origin_tls[inter][i] = 0;
	}
	for (i = 0; i < PARAM_SIZE / sizeof(void*); i++) {
		current->kmsan.param_tls[inter][i] = 0;
	}
}

// TODO(glider): remove this fn?
// Looks like it's enough to mark syscall entries non-instrumented.
void kmsan_wipe_params_shadow_origin(int inter)
{
	int ind, num;
	unsigned long irq_flags;
	int start = (inter == -1) ? 0 : inter;
	int end = (inter == -1) ? KMSAN_NUM_SHADOW_STACKS : inter + 1;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME() || !current->kmsan.enabled)
		return;
	ENTER_RUNTIME(irq_flags);
	for (ind = start; ind < end; ind++) {
		__memset(current->kmsan.param_origin_tls[ind], 0, PARAM_SIZE);
		__memset(current->kmsan.param_tls[ind], 0, PARAM_SIZE);
		__memset(current->kmsan.va_arg_tls[ind], 0, PARAM_SIZE);
		__memset(current->kmsan.retval_tls[ind], 0, RETVAL_SIZE);
		current->kmsan.retval_origin_tls[ind] = 0;
		current->kmsan.origin_tls[ind] = 0;
		current->kmsan.va_arg_overflow_size_tls[ind] = 0;
	}
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
	// TODO(glider): make __kmsan_load_shadow_origin() return 2 32-bit origin slots.
	u32 o;
	//u64 o;
} shadow_origin_8;


#define DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(size, shadow_type) \
shadow_origin_##size __kmsan_load_shadow_origin_##size(u64 addr) \
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
EXPORT_SYMBOL(__kmsan_load_shadow_origin_##size);

DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(1, u8);
DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(2, u16);
DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(4, u32);
DECLARE_KMSAN_LOAD_SHADOW_ORIGIN(8, u64);

typedef struct {
	u64 s;
	u32 o;
} shadow_origin_n;

shadow_origin_n __kmsan_load_shadow_origin_n_8(u64 addr, u64 size)
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
void __kmsan_store_shadow_origin_8(u64 addr, u64 s, u64 o)
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
EXPORT_SYMBOL(__kmsan_store_shadow_origin_8);

void __kmsan_store_shadow_origin_n_8(u64 addr, u64 s, u64 o, u64 size)
{
	unsigned long irq_flags;
	u32 new_o;
	void *shadow;

	// TODO(glider): the code actually works for other sizes, but
	// it's interesting whether we need them.
	BUG_ON(size != 3);
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
void __kmsan_store_shadow_origin_##size(u64 addr, u64 s, u64 o)	\
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
EXPORT_SYMBOL(__kmsan_store_shadow_origin_##size);
DECLARE_KMSAN_STORE_SHADOW_ORIGIN(1, u8);
DECLARE_KMSAN_STORE_SHADOW_ORIGIN(2, u16);
DECLARE_KMSAN_STORE_SHADOW_ORIGIN(4, u32);

// Essentially a memcpy(shadow(dst), src, size).
// TODO(glider): do we need any checks here?
// TODO(glider): maybe save origins as well?
// Another possible thing to do is to push/pop va_arg shadow.
void __kmsan_load_overflow_arg_shadow(u64 dst, u64 src, u64 size)
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
EXPORT_SYMBOL(__kmsan_load_overflow_arg_shadow);

void __kmsan_restore_va_arg_shadow(u64 dst, u64 src, u64 size)
	__attribute__((alias("__kmsan_load_overflow_arg_shadow")));
EXPORT_SYMBOL(__kmsan_restore_va_arg_shadow);
void __kmsan_load_arg_shadow(u64 dst, u64 src, u64 size)
	__attribute__((alias("__kmsan_load_overflow_arg_shadow")));
EXPORT_SYMBOL(__kmsan_load_arg_shadow);

// Essentially a memcpy(dst, shadow(src), size).
// TODO(glider): do we need any checks here?
// TODO(glider): maybe save origins as well?
// Another possible thing to do is to push/pop va_arg shadow.
void __kmsan_store_overflow_arg_shadow(u64 dst, u64 src, u64 size)
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
EXPORT_SYMBOL(__kmsan_store_overflow_arg_shadow);
void __kmsan_store_arg_shadow(u64 dst, u64 src, u64 size)
	__attribute__((alias("__kmsan_store_overflow_arg_shadow")));
EXPORT_SYMBOL(__kmsan_store_arg_shadow);

// TODO(glider): rename to __kmsan_memmove
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

// TODO(glider): rename to __kmsan_memcpy
void *__msan_memcpy(void *dst, const void *src, u64 n)
{
	void *result;
	void *shadow_dst;
	unsigned long irq_flags;

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


// TODO(glider): rename to __kmsan_memset
void *__msan_memset(void *dst, int c, size_t n)
{
	void *result;
	unsigned long irq_flags;
	depot_stack_handle_t origin, new_origin;
	unsigned int shadow;
	void *caller;
	int inter = task_tls_index();

	result = __memset(dst, c, n);
	if (IN_RUNTIME())
		return result;
	if (!kmsan_ready)
		return result;

	ENTER_RUNTIME(irq_flags);
	// TODO(glider): emit stores to param_tls and param_origin_tls in the compiler for KMSAN.
	// (not for MSan, because __msan_memset could be called from the userspace RTL)
	// Take the shadow and origin of |c|.
	///shadow = (unsigned int)(current->kmsan.param_tls[inter][1]);
	///origin = (depot_stack_handle_t)(current->kmsan.param_origin_tls[inter][1]);
	shadow = 0;
	kmsan_internal_memset_shadow((u64)dst, shadow, n);
	///new_origin = kmsan_internal_chain_origin(origin, /*full*/true);
	new_origin = 0;
	kmsan_set_origin((u64)dst, n, new_origin);
	LEAVE_RUNTIME(irq_flags);

	return result;
}
EXPORT_SYMBOL(__msan_memset);


// TODO(glider): rename to __kmsan_chain_origin, make sure this function is emitted.
// Or do we need it at all?
#if 0
u32 __msan_chain_origin(u32 id)
{
	depot_stack_handle_t handle;
	unsigned long irq_flags;

	if (!use_chained_origins)
		return id;
	if (!kmsan_ready)
		return id;
	if (IN_RUNTIME())
		return id;
	ENTER_RUNTIME(irq_flags);
	handle = kmsan_internal_chain_origin(id, /*full*/false);
	LEAVE_RUNTIME(irq_flags);
	return handle;
}
EXPORT_SYMBOL(__msan_chain_origin);
#endif

void __kmsan_poison_alloca(void *a, u64 size, char *descr/*checked*/, u64 pc)
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
EXPORT_SYMBOL(__kmsan_poison_alloca);

void __kmsan_unpoison(void *addr, u64 size)
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
EXPORT_SYMBOL(__kmsan_unpoison);

// Compiler API
// TODO(glider): rename to __kmsan_warning, pass origin as a parameter.
void __msan_warning(void)
{
	void *caller;
	unsigned long irq_flags;
	int inter = task_tls_index();

	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	caller = __builtin_return_address(0);
	kmsan_report(caller, current->kmsan.origin_tls[inter]);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__msan_warning);

void __kmsan_warning_32(u32 origin)
{
	void *caller;
	unsigned long irq_flags;
	int inter = task_tls_index();

	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	caller = __builtin_return_address(0);
	kmsan_report(caller, origin);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(__kmsan_warning_32);

// Per-task getters.
void *__kmsan_get_retval_tls(void)
{
	int inter = task_tls_index();
	unsigned long irq_flags;
	void *ret;

	if (!kmsan_threads_ready) {
		__memset(kmsan_dummy_retval_tls, 0, RETVAL_SIZE); // TODO
		return kmsan_dummy_retval_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		// We're in runtime, don't care about the shadow.
		///__memset(kmsan_dummy_retval_tls, 0, RETVAL_SIZE); // TODO
		return kmsan_dummy_retval_tls;
	}
	// No need to enter/leave runtime.
	ENTER_RUNTIME(irq_flags);
	ret = current->kmsan.retval_tls[inter];
	///__memset(ret, 0, RETVAL_SIZE); // TODO
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_retval_tls);

u64 *__kmsan_get_va_arg_overflow_size_tls(void)
{
	int inter = task_tls_index();
	u64 *ret;
	unsigned long irq_flags;

	if (!kmsan_threads_ready) {
		kmsan_dummy_va_arg_overflow_size_tls = 0;
		return &kmsan_dummy_va_arg_overflow_size_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		kmsan_dummy_va_arg_overflow_size_tls = 0;
		return &kmsan_dummy_va_arg_overflow_size_tls;
	}

	ENTER_RUNTIME(irq_flags);
	ret = &(current->kmsan.va_arg_overflow_size_tls[inter]);
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_va_arg_overflow_size_tls);

void **__kmsan_get_va_arg_tls(void)
{
	int inter = task_tls_index();
	void **ret;
	unsigned long irq_flags;

	if (!kmsan_threads_ready) {
		__memset(kmsan_dummy_va_arg_tls, 0, PARAM_SIZE); // TODO
		return kmsan_dummy_va_arg_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		// We're in runtime, don't care about the shadow.
		///__memset(kmsan_dummy_va_arg_tls, 0, PARAM_SIZE); // TODO
		return kmsan_dummy_va_arg_tls;
	}

	ENTER_RUNTIME(irq_flags);
	ret = current->kmsan.va_arg_tls[inter];
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_va_arg_tls);

void **__kmsan_get_param_tls(void)
{
	int inter = task_tls_index();
	void **ret;
	unsigned long irq_flags;

	// TODO(glider): disabled shadow tracking across function calls
	if (!kmsan_threads_ready) {
		__memset(kmsan_dummy_param_tls, 0, PARAM_SIZE); // TODO
		return kmsan_dummy_param_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		// We're in runtime, don't care about the shadow.
		///__memset(kmsan_dummy_param_tls, 0, PARAM_SIZE); // TODO
		return kmsan_dummy_param_tls;
	}

	ENTER_RUNTIME(irq_flags);
	ret = current->kmsan.param_tls[inter];
	///__memset(current->kmsan.param_tls[inter], 0, PARAM_SIZE); // TODO
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_param_tls);

// TODO(glider): get rid of current->kmsan.origin_tls.
// Use a parameter to __msan_warning() instead.
u32 *__kmsan_get_origin_tls(void)
{
	int inter = task_tls_index();
	u32 *ret;
	unsigned long irq_flags;

	if (!kmsan_threads_ready) {
		kmsan_dummy_origin_tls = 0;
		return &kmsan_dummy_origin_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		kmsan_dummy_origin_tls = 0;
		return &kmsan_dummy_origin_tls;
	}

	ENTER_RUNTIME(irq_flags);
	ret = &(current->kmsan.origin_tls[inter]);
	*ret = 0;
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_origin_tls);


u32 *__kmsan_get_param_origin_tls(void)
{
	int inter = task_tls_index();
	u32 *ret;
	unsigned long irq_flags;
	int i;
	unsigned long flags;

	// TODO(glider): disabled shadow tracking across function calls
	if (!kmsan_threads_ready) {
		__memset(kmsan_dummy_param_origin_tls, 0, PARAM_SIZE); // TODO
		return kmsan_dummy_param_origin_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		// We're in runtime, don't care about the shadow.
	///	__memset(kmsan_dummy_param_origin_tls, 0, PARAM_SIZE); // TODO
		return kmsan_dummy_param_origin_tls;
	}
	ENTER_RUNTIME(irq_flags);
	///BUG_ON(READ_ONCE(current->kmsan.busy));
#if 0
	if (READ_ONCE(current->kmsan.busy)) {
		pr_err("first stack below\n");
		dump_stack();
		pr_err("first stack above\n");
		WRITE_ONCE(current->kmsan.busy2, 1);
		///while (READ_ONCE(current->kmsan.busy2)) {
		//msleep(2000);
		WRITE_ONCE(current->kmsan.busy2, 0);
		///}
		///BUG();
	}
#endif
	///WRITE_ONCE(current->kmsan.busy, 1);
	ret = current->kmsan.param_origin_tls[inter];
	///check_param_origin_tls();
	///__memset(current->kmsan.param_origin_tls[inter], 0, PARAM_SIZE); // TODO
	///WRITE_ONCE(current->kmsan.busy, 0);
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_param_origin_tls);

int *__kmsan_get_retval_origin_tls(void)
{
	int inter = task_tls_index();
	int *ret;
	unsigned long irq_flags;

	if (!kmsan_threads_ready) {
		kmsan_dummy_retval_origin_tls = 0;
		return &kmsan_dummy_retval_origin_tls;
	}
	__msan_init();
	if (IN_RUNTIME() || !current->kmsan.enabled) {
		kmsan_dummy_retval_origin_tls = 0;
		return &kmsan_dummy_retval_origin_tls;
	}

	ENTER_RUNTIME(irq_flags);
	ret = &(current->kmsan.retval_origin_tls[inter]);
	current->kmsan.retval_origin_tls[inter] = 0; // TODO
	LEAVE_RUNTIME(irq_flags);

	return ret;
}
EXPORT_SYMBOL(__kmsan_get_retval_origin_tls);

