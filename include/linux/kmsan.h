/* KMSAN */
#ifndef LINUX_KMSAN_H
#define LINUX_KMSAN_H

#include <linux/gfp.h>
#include <linux/stackdepot.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

struct page;
struct kmem_cache;
struct task_struct;
struct vm_struct;


extern bool kmsan_ready;

#ifdef CONFIG_KMSAN
void __init kmsan_initialize_shadow(void);
void __init kmsan_initialize(void);

typedef struct kmsan_task_s kmsan_task_state;
typedef struct kmsan_context_s kmsan_context_state;

// TODO(glider): Factor out params, origins etc. into a separate
// struct kmsan_context_state. Then make those for IRQs and exceptions per-cpu,
// not per-task.
// These constants are defined in the MSan LLVM instrumentation pass.
#define RETVAL_SIZE 800
#define KMSAN_PARAM_SIZE 800

struct kmsan_context_s {
	char param_tls[KMSAN_PARAM_SIZE];
	char retval_tls[RETVAL_SIZE];
	char va_arg_tls[KMSAN_PARAM_SIZE];
	char va_arg_origin_tls[KMSAN_PARAM_SIZE];
	u64 va_arg_overflow_size_tls;
	depot_stack_handle_t param_origin_tls[KMSAN_PARAM_SIZE / sizeof(depot_stack_handle_t)];
	depot_stack_handle_t retval_origin_tls;
	depot_stack_handle_t origin_tls;
};

struct kmsan_task_s {
	bool enabled;
	bool initialization;
	bool allow_reporting;
	bool is_reporting;
	bool debug;

	kmsan_context_state cstate;
};

extern kmsan_context_state kmsan_dummy_state;

void kmsan_task_create(struct task_struct *task);
void kmsan_task_exit(struct task_struct *task);
void kmsan_alloc_shadow_for_region(void *start, size_t size);
int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags);
void kmsan_gup_pgd_range(struct page **pages, int nr);
void kmsan_free_page(struct page *page, unsigned int order);
void kmsan_split_page(struct page *page, unsigned int order);
void kmsan_copy_page_meta(struct page *dst, struct page *src);

void kmsan_poison_slab(struct page *page, gfp_t flags);
void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags);
void kmsan_kfree_large(const void *ptr);
void kmsan_kmalloc(struct kmem_cache *s, const void *object, size_t size,
		  gfp_t flags);
void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags);
void kmsan_slab_free(struct kmem_cache *s, void *object);

void kmsan_slab_setup_object(struct kmem_cache *s, void *object);
void kmsan_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
			size_t size, void *object);

/* vmap */
void kmsan_vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages);
void kmsan_vunmap_page_range(unsigned long addr, unsigned long end);

/* ioremap */
void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
	phys_addr_t phys_addr, pgprot_t prot);
void kmsan_iounmap_page_range(unsigned long start, unsigned long end);

void kmsan_softirq_enter(void);
void kmsan_softirq_exit(void);

void kmsan_clear_page(void *page_addr);
#else

static inline void __init kmsan_initialize_shadow(void) { }
static inline void __init kmsan_initialize(void) { }

static inline void kmsan_task_create(struct task_struct *task) {}
static inline void kmsan_task_exit(struct task_struct *task) {}
static inline void kmsan_alloc_shadow_for_region(void *start, size_t size) {}
static inline int kmsan_alloc_page(
	struct page *page, unsigned int order, gfp_t flags)
{
	return 0;
}
static inline void kmsan_gup_pgd_range(struct page **pages, int nr) {}
static inline void kmsan_free_page(struct page *page, unsigned int order) {}
static inline void kmsan_split_page(struct page *page, unsigned int order) {}
static inline void kmsan_copy_page_meta(struct page *dst, struct page *src) {}

static inline void kmsan_poison_slab(struct page *page, gfp_t flags) {}
static inline void kmsan_kmalloc_large(
	const void *ptr, size_t size, gfp_t flags) {}
static inline void kmsan_kfree_large(const void *ptr) {}
static inline void kmsan_kmalloc(
	struct kmem_cache *s, const void *object, size_t size, gfp_t flags) {}
static inline void kmsan_slab_alloc(
	struct kmem_cache *s, void *object, gfp_t flags) {}
static inline void kmsan_slab_free(struct kmem_cache *s, void *object) {}

static inline void kmsan_slab_setup_object(
	struct kmem_cache *s, void *object) {}
static inline void kmsan_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
	size_t size, void *object) {}

static inline void kmsan_vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages) {}
static inline void kmsan_vunmap_page_range(unsigned long start, unsigned long end) {}

static inline void kmsan_ioremap_page_range(unsigned long start, unsigned long end,
	phys_addr_t phys_addr, pgprot_t prot) {}
static inline void kmsan_iounmap_page_range(unsigned long start, unsigned long end) {}
static inline void kmsan_softirq_enter(void) {}
static inline void kmsan_softirq_exit(void) {}

static inline void kmsan_clear_page(void *page_addr) {}
#endif

#endif /* LINUX_KMSAN_H */
