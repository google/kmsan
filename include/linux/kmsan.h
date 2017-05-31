/* KMSAN */
#ifndef LINUX_KMSAN_H
#define LINUX_KMSAN_H

//#include <linux/mm.h>
//#include <linux/mm_types.h>
//#include <linux/slab.h>
#include <linux/stackdepot.h>
#include <linux/types.h>


struct page;
struct kmem_cache;
struct task_struct;

extern bool kmsan_ready;
extern bool kmsan_threads_ready;
#ifdef CONFIG_KMSAN
void __init kmsan_early_init(void);
void __init kmsan_init(void);
#else
static inline void kmsan_early_init(void) { }
static inline void kmsan_init(void) { }
#endif


#ifdef CONFIG_KMSAN
#define KMSAN_NUM_SHADOW_STACKS 5

typedef struct kmsan_thread_s kmsan_thread_state;


// TODO(glider): Factor out params, origins etc. into a separate
// struct kmsan_context_state. Then make those for IRQs and exceptions per-cpu,
// not per-task.

struct kmsan_thread_s {
	bool enabled;
	bool initialization;
	bool allow_reporting;
	bool is_reporting;
	// TODO(glider): When in_runtime is 1, IRQs are disabled.
	int in_runtime;
	bool is_switching;
	bool debug;
	volatile int busy, busy2; // TODO(glider): debug-only

	void **retval_tls[KMSAN_NUM_SHADOW_STACKS];
	u64 va_arg_overflow_size_tls[KMSAN_NUM_SHADOW_STACKS];
	void **va_arg_tls[KMSAN_NUM_SHADOW_STACKS];
	void **param_tls[KMSAN_NUM_SHADOW_STACKS];
	depot_stack_handle_t origin_tls[KMSAN_NUM_SHADOW_STACKS];
	depot_stack_handle_t *param_origin_tls[KMSAN_NUM_SHADOW_STACKS];
	depot_stack_handle_t retval_origin_tls[KMSAN_NUM_SHADOW_STACKS];
};

// TODO(glider): rename to kmsan_task_create()
void kmsan_thread_create(struct task_struct *task);
void kmsan_task_exit(struct task_struct *task);
void kmsan_alloc_shadow_for_region(void *start, size_t size);
int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags);
void kmsan_free_page(struct page *page, unsigned int order);
void kmsan_split_page(struct page *page, unsigned int order);

void kmsan_poison_slab(struct page *page, gfp_t flags);
void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags);
void kmsan_kfree_large(const void *ptr);
void kmsan_kmalloc(struct kmem_cache *s, const void *object, size_t size,
		  gfp_t flags);
void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags);
bool kmsan_slab_free(struct kmem_cache *s, void *object);

void kmsan_slab_setup_object(struct kmem_cache *s, void *object);
void kmsan_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
			size_t size, void *object);

void kmsan_wipe_params_shadow_origin(int inter);
#else

void kmsan_thread_create(struct task_struct *task) {}
void kmsan_task_exit(struct task_struct *task) {}
void kmsan_alloc_shadow_for_region(void *start, size_t size) {}
int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags, int node) { return 0; }
void kmsan_free_page(struct page *page, unsigned int order) {}
void kmsan_split_page(struct page *page, unsigned int order) {}

void kmsan_cache_create(struct kmem_cache *cache, size_t *size,
			unsigned long *flags) {}


void kmsan_slab_setup_object(struct kmem_cache *s, void *object) {}
void kmsan_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
			size_t size, void *object) {}
void kmsan_wipe_params_shadow_origin(void) {}
#endif

#endif /* LINUX_KMSAN_H */
