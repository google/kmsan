#ifndef __MM_KMSAN_KMSAN_H
#define __MM_KMSAN_KMSAN_H

#include <asm/current.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/nmi.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <asm/cpu_entry_area.h>  // for CPU_ENTRY_AREA_MAP_SIZE

#define KMSAN_MAGIC_MASK 0xffffffffff00
#define KMSAN_ALLOCA_MAGIC_ORIGIN 0x4110c4071900
#define KMSAN_CHAIN_MAGIC_ORIGIN_FULL 0xd419170cba00

#define ORIGIN_SIZE 4

#define KMSAN_NESTED_CONTEXT_MAX (8)
DECLARE_PER_CPU(kmsan_context_state[KMSAN_NESTED_CONTEXT_MAX], kmsan_percpu_cstate);  // [0] for dummy per-CPU context
DECLARE_PER_CPU(int, kmsan_context_level);  // 0 for task context, |i>0| for kmsan_context_state[i]
DECLARE_PER_CPU(int, kmsan_in_interrupt);
DECLARE_PER_CPU(bool, kmsan_in_softirq);
DECLARE_PER_CPU(bool, kmsan_in_nmi);

extern spinlock_t report_lock;
#define kmsan_pr_err(...) \
	do { \
		if (!is_logbuf_locked()) \
			pr_err(__VA_ARGS__); \
	} while (0)

enum KMSAN_BUG_REASON
{
	REASON_ANY = 0,
	REASON_COPY_TO_USER = 1,
};

typedef struct {
	void* s;
	void* o;
} shadow_origin_ptr_t;
shadow_origin_ptr_t kmsan_get_shadow_origin_ptr(u64 addr, u64 size, bool store);

/*
 * When a compiler hook is invoked, it may make a call to instrumented code
 * and eventually call itself recursively. To avoid that, we protect the
 * runtime entry points with ENTER_RUNTIME()/LEAVE_RUNTIME() macros and exit
 * the hook if IN_RUNTIME() is true. But when an interrupt occurs inside the
 * runtime, the hooks won’t run either, which may lead to errors.
 * Therefore we have to disable interrupts inside the runtime.
 */
DECLARE_PER_CPU(int, kmsan_in_runtime);
DECLARE_PER_CPU(unsigned long, kmsan_runtime_last_caller);
#define IN_RUNTIME()	(this_cpu_read(kmsan_in_runtime))
#define ENTER_RUNTIME(irq_flags) \
	do { \
		preempt_disable(); \
		local_irq_save(irq_flags); \
		stop_nmi();		\
		this_cpu_inc(kmsan_in_runtime); \
		this_cpu_write(kmsan_runtime_last_caller, _THIS_IP_); \
		BUG_ON(this_cpu_read(kmsan_in_runtime) > 1); \
	} while(0)
#define LEAVE_RUNTIME(irq_flags)	\
	do {	\
		this_cpu_dec(kmsan_in_runtime);	\
		if (this_cpu_read(kmsan_in_runtime)) { \
			kmsan_pr_err("kmsan_in_runtime: %d, last_caller: %pF\n", \
				this_cpu_read(kmsan_in_runtime), this_cpu_read(kmsan_runtime_last_caller));	\
			BUG(); \
		}	\
		restart_nmi();		\
		local_irq_restore(irq_flags);	\
		preempt_enable(); } while(0)

void *kmsan_get_metadata_or_null(u64 addr, size_t size, bool is_origin);

void kmsan_memcpy_metadata(u64 dst, u64 src, size_t n);
void kmsan_memmove_metadata(u64 dst, u64 src, size_t n);

extern char dummy_shadow_load_page[PAGE_SIZE];
extern char dummy_origin_load_page[PAGE_SIZE];
extern char dummy_shadow_store_page[PAGE_SIZE];
extern char dummy_origin_store_page[PAGE_SIZE];

extern void *kmsan_dummy_retval_tls[];
extern u64 kmsan_dummy_va_arg_overflow_size_tls;
extern void *kmsan_dummy_va_arg_tls[];
extern void *kmsan_dummy_va_arg_origin_tls[];
extern void *kmsan_dummy_param_tls[];
extern depot_stack_handle_t kmsan_dummy_origin_tls;
extern depot_stack_handle_t kmsan_dummy_param_origin_tls[];
extern depot_stack_handle_t kmsan_dummy_retval_origin_tls;

inline depot_stack_handle_t kmsan_save_stack(void);
inline depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags);
void kmsan_internal_poison_shadow(const volatile void *address, size_t size, gfp_t flags, bool checked);
void kmsan_internal_unpoison_shadow(const volatile void *address, size_t size, bool checked);
void kmsan_internal_memset_shadow(u64 address, int b, size_t size, bool checked);
depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);

void do_kmsan_task_create(struct task_struct *task);
void kmsan_set_origin(u64 address, int size, u32 origin, bool checked);
inline void kmsan_report(void *caller, depot_stack_handle_t origin,
			u64 address, int size,
			int off_first, int off_last, u64 user_addr, bool deep, int reason);

int kmsan_internal_alloc_meta_for_pages(struct page *page, unsigned int order,
				unsigned int actual_size, gfp_t flags, int node);

kmsan_context_state *task_kmsan_context_state(void);

bool metadata_is_contiguous(u64 addr, size_t size, bool is_origin);
int order_from_size(unsigned long size);
void kmsan_internal_check_memory(const volatile void *addr, size_t size, const void *user_addr, int reason);

struct page *vmalloc_to_page_or_null(const void *vaddr);
struct page *virt_to_page_or_null(const void *vaddr);
void *get_cea_shadow_or_null(const void *addr);
void *get_cea_origin_or_null(const void *addr);

// Dummy replacement for __builtin_return_address() which may crash without
// frame pointers.
static inline void *kmsan_internal_return_address(int arg)
{
#ifdef CONFIG_UNWINDER_FRAME_POINTER
	switch (arg) {
		case 1:
			return __builtin_return_address(1);
		case 2:
			return __builtin_return_address(2);
		default:
			BUG();
	}
#else
	unsigned long entries[1];
	struct stack_trace trace = {
		.nr_entries = 0,
		.entries = entries,
		.max_entries = 1,
		.skip = arg
	};
	save_stack_trace(&trace);
	return entries[0];
#endif
}

// Taken from arch/x86/mm/physaddr.h
// TODO(glider): do we need it?
static inline int my_phys_addr_valid(resource_size_t addr)
{
#ifdef CONFIG_PHYS_ADDR_T_64BIT
	return !(addr >> boot_cpu_data.x86_phys_bits);
#else
	return 1;
#endif
}

// Taken from arch/x86/mm/physaddr.c
// TODO(glider): do we need it?
static inline bool my_virt_addr_valid(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	if (unlikely(x > y)) {
		x = y + phys_base;

		if (y >= KERNEL_IMAGE_SIZE)
			return false;
	} else {
		x = y + (__START_KERNEL_map - PAGE_OFFSET);

		/* carry flag will be set if starting x was >= PAGE_OFFSET */
		if ((x > y) || !my_phys_addr_valid(x))
			return false;
	}

	return pfn_valid(x >> PAGE_SHIFT);
}

static inline bool is_cpu_entry_area_addr(u64 addr)
{
	return (addr >= CPU_ENTRY_AREA_BASE) && (addr < CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE);
}

#endif
