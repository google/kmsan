/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN API for subsystems.
 *
 * Copyright (C) 2017-2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef LINUX_KMSAN_H
#define LINUX_KMSAN_H

#include <linux/dma-direction.h>
#include <linux/gfp.h>
#include <linux/stackdepot.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

struct page;
struct kmem_cache;
struct task_struct;
struct sk_buff;
struct urb;

#ifdef CONFIG_KMSAN
void __init kmsan_initialize_shadow(void);
void __init kmsan_initialize(void);

/* These constants are defined in the MSan LLVM instrumentation pass. */
#define KMSAN_RETVAL_SIZE 800
#define KMSAN_PARAM_SIZE 800
#define KMSAN_PARAM_ARRAY_SIZE (KMSAN_PARAM_SIZE / sizeof(depot_stack_handle_t))

struct kmsan_context_state {
	char param_tls[KMSAN_PARAM_SIZE];
	char retval_tls[KMSAN_RETVAL_SIZE];
	char va_arg_tls[KMSAN_PARAM_SIZE];
	char va_arg_origin_tls[KMSAN_PARAM_SIZE];
	u64 va_arg_overflow_size_tls;
	depot_stack_handle_t param_origin_tls[KMSAN_PARAM_ARRAY_SIZE];
	depot_stack_handle_t retval_origin_tls;
	depot_stack_handle_t origin_tls;
};

#undef KMSAN_PARAM_ARRAY_SIZE
#undef KMSAN_PARAM_SIZE
#undef KMSAN_RETVAL_SIZE

struct kmsan_task_state {
	bool allow_reporting;
	struct kmsan_context_state cstate;
};

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

void kmsan_check_skb(const struct sk_buff *skb);
void kmsan_handle_dma(const void *address, size_t size,
		      enum dma_data_direction direction);
void kmsan_handle_urb(const struct urb *urb, bool is_out);
void kmsan_copy_to_user(const void *to, const void *from, size_t to_copy,
			size_t left);

#else

static inline void __init kmsan_initialize_shadow(void) { }
static inline void __init kmsan_initialize(void) { }

static inline void kmsan_task_create(struct task_struct *task) {}
static inline void kmsan_task_exit(struct task_struct *task) {}
static inline void kmsan_alloc_shadow_for_region(void *start, size_t size) {}
static inline int kmsan_alloc_page(struct page *page, unsigned int order,
				   gfp_t flags)
{
	return 0;
}
static inline void kmsan_gup_pgd_range(struct page **pages, int nr) {}
static inline void kmsan_free_page(struct page *page, unsigned int order) {}
static inline void kmsan_split_page(struct page *page, unsigned int order) {}
static inline void kmsan_copy_page_meta(struct page *dst, struct page *src) {}

static inline void kmsan_poison_slab(struct page *page, gfp_t flags) {}
static inline void kmsan_kmalloc_large(const void *ptr, size_t size,
				       gfp_t flags) {}
static inline void kmsan_kfree_large(const void *ptr) {}
static inline void kmsan_kmalloc(struct kmem_cache *s, const void *object,
				 size_t size, gfp_t flags) {}
static inline void kmsan_slab_alloc(struct kmem_cache *s, void *object,
				    gfp_t flags) {}
static inline void kmsan_slab_free(struct kmem_cache *s, void *object) {}

static inline void kmsan_slab_setup_object(struct kmem_cache *s,
					   void *object) {}
static inline void kmsan_post_alloc_hook(struct kmem_cache *s, gfp_t flags,
					 size_t size, void *object) {}

static inline void kmsan_vmap_page_range_noflush(unsigned long start,
						 unsigned long end,
						 pgprot_t prot,
						 struct page **pages) {}
static inline void kmsan_vunmap_page_range(unsigned long start,
					   unsigned long end) {}

static inline void kmsan_ioremap_page_range(unsigned long start,
					    unsigned long end,
					    phys_addr_t phys_addr,
					    pgprot_t prot) {}
static inline void kmsan_iounmap_page_range(unsigned long start,
					    unsigned long end) {}
static inline void kmsan_softirq_enter(void) {}
static inline void kmsan_softirq_exit(void) {}

static inline void kmsan_clear_page(void *page_addr) {}

static inline void kmsan_check_skb(const struct sk_buff *skb) {}
static inline void kmsan_handle_urb(const struct urb *urb, bool is_out) {}
static inline void kmsan_handle_dma(const void *address, size_t size,
				    enum dma_data_direction direction) {}
static inline void kmsan_copy_to_user(
	const void *to, const void *from, size_t to_copy, size_t left) {}

#endif

#endif /* LINUX_KMSAN_H */
