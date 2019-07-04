#ifndef __MM_KMSAN_KMSAN_H
#define __MM_KMSAN_KMSAN_H

#include <asm/cpu_entry_area.h>  // for CPU_ENTRY_AREA_MAP_SIZE
#include <asm/current.h>
#include <asm/pgtable_64_types.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/nmi.h>
#include <linux/mm.h>
#include <linux/printk.h>

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

void kmsan_print_origin(depot_stack_handle_t origin);
void kmsan_report(depot_stack_handle_t origin,
		  void *address, int size, int off_first, int off_last,
		  const void *user_addr, bool deep, int reason);

#define shadow_page_for(page) \
	((page)->shadow)

#define shadow_ptr_for(page) \
	(page_address((page)->shadow))

#define origin_page_for(page) \
	((page)->origin)

#define origin_ptr_for(page) \
	(page_address((page)->origin))

#define has_shadow_page(page) \
	(!!((page)->shadow))

#define has_origin_page(page) \
	(!!((page)->origin))

#define set_no_shadow_page(page) 	\
	do {				\
		(page)->shadow = NULL;	\
	} while(0) /**/

#define set_no_origin_page(page) 	\
	do {				\
		(page)->origin = NULL;	\
	} while(0) /**/

enum KMSAN_BUG_REASON
{
	REASON_ANY = 0,
	REASON_COPY_TO_USER = 1,
	REASON_SUBMIT_URB = 2,
};

typedef struct {
	void* s;
	void* o;
} shadow_origin_ptr_t;
shadow_origin_ptr_t kmsan_get_shadow_origin_ptr(void *addr, u64 size, bool store);

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

void *kmsan_get_metadata_or_null(void *addr, size_t size, bool is_origin);

void kmsan_memcpy_metadata(void *dst, void *src, size_t n);
void kmsan_memmove_metadata(void *dst, void *src, size_t n);

depot_stack_handle_t kmsan_save_stack(void);
depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags);
void kmsan_internal_poison_shadow(void *address, size_t size, gfp_t flags, bool checked);
void kmsan_internal_unpoison_shadow(void *address, size_t size, bool checked);
void kmsan_internal_memset_shadow(void *address, int b, size_t size, bool checked);
depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);

void do_kmsan_task_create(struct task_struct *task);
void kmsan_set_origin(void *address, int size, u32 origin, bool checked);
void kmsan_report(depot_stack_handle_t origin,
		  void *address, int size,
		  int off_first, int off_last,
		  const void *user_addr, bool deep, int reason);

int kmsan_internal_alloc_meta_for_pages(struct page *page, unsigned int order,
				unsigned int actual_size, gfp_t flags, int node);

kmsan_context_state *task_kmsan_context_state(void);

bool metadata_is_contiguous(void *addr, size_t size, bool is_origin);
void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr, int reason);

struct page *vmalloc_to_page_or_null(void *vaddr);
struct page *virt_to_page_or_null(void *vaddr);
void *get_cea_shadow_or_null(void *addr);
void *get_cea_origin_or_null(void *addr);

/* Declared in mm/vmalloc.c */
void __vunmap_page_range(unsigned long addr, unsigned long end);
int __vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages);

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

static bool is_module_addr(void *vaddr)
{
	return ((u64)vaddr >= MODULES_VADDR) && ((u64)vaddr < MODULES_END);
}

static inline bool is_cpu_entry_area_addr(void *addr)
{
	return ((u64)addr >= CPU_ENTRY_AREA_BASE) && ((u64)addr < (CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE));
}

static inline bool _is_vmalloc_addr(void *addr)
{
	return ((u64)addr >= VMALLOC_START) && ((u64)addr < VMALLOC_END);
}

static inline void *vmalloc_meta(void *addr, bool is_origin)
{
	u64 addr64 = (u64)addr, off;

	BUG_ON(is_origin && !IS_ALIGNED(addr64, ORIGIN_SIZE));
	if (_is_vmalloc_addr(addr)) {
		return (void *)(addr64 + (is_origin ? VMALLOC_ORIGIN_OFFSET
						: VMALLOC_SHADOW_OFFSET));
	}
	if (is_module_addr(addr)) {
		off = addr64 - MODULES_VADDR;
		return (void *)(off + (is_origin ? MODULES_ORIGIN_START
						: MODULES_SHADOW_START));
	}
	return NULL;
}

static inline void *vmalloc_shadow(void *addr)
{
	return vmalloc_meta(addr, /*is_origin*/false);
}

static inline void *vmalloc_origin(void *addr)
{
	return vmalloc_meta(addr, /*is_origin*/true);
}

#endif  /* __MM_KMSAN_KMSAN_H */
