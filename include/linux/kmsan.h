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
struct scatterlist;
struct sk_buff;
struct urb;

#ifdef CONFIG_KMSAN

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

/**
 * kmsan_initialize_shadow() - Initialize KMSAN shadow at boot time.
 *
 * Allocate and initialize KMSAN metadata for early allocations.
 */
void __init kmsan_initialize_shadow(void);

/**
 * kmsan_initialize() - Initialize KMSAN state and enable KMSAN.
 */
void __init kmsan_initialize(void);

/**
 * TODO: need a description here.
 */
bool __init kmsan_memblock_free_pages(struct page *page, unsigned int order);

/**
 * kmsan_task_create() - Initialize KMSAN state for the task.
 * @task: task to initialize.
 */
void kmsan_task_create(struct task_struct *task);

/**
 * kmsan_task_exit() - Notify KMSAN that a task has exited.
 * @task: task about to finish.
 */
void kmsan_task_exit(struct task_struct *task);

/**
 * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
 * @page:  struct page pointer returned by alloc_pages().
 * @order: order of allocated struct page.
 * @flags: GFP flags used by alloc_pages()
 *
 * Return:
 * * 0       - Ok
 * * -ENOMEM - allocation failure
 *
 * KMSAN allocates metadata (shadow and origin pages) for @page and marks
 * 1<<@order pages starting at @page as uninitialized, unless @flags contain
 * __GFP_ZERO.
 */
int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags);

/**
 * kmsan_free_page() - Notify KMSAN about a free_pages() call.
 * @page:  struct page pointer passed to free_pages().
 * @order: order of deallocated struct page.
 *
 * KMSAN deallocates the metadata pages for the given struct page.
 */
void kmsan_free_page(struct page *page, unsigned int order);

/**
 * kmsan_copy_page_meta() - Copy KMSAN metadata between two pages.
 * @dst: destination page.
 * @src: source page.
 *
 * KMSAN copies the contents of metadata pages for @src into the metadata pages
 * for @dst. If @dst has no associated metadata pages, nothing happens.
 * If @src has no associated metadata pages, @dst metadata pages are unpoisoned.
 */
void kmsan_copy_page_meta(struct page *dst, struct page *src);

/**
 * kmsan_gup_pgd_range() - Notify KMSAN about a gup_pgd_range() call.
 * @pages: array of struct page pointers.
 * @nr:    array size.
 *
 * gup_pgd_range() creates new pages, some of which may belong to the userspace
 * memory. In that case these pages should be initialized.
 */
void kmsan_gup_pgd_range(struct page **pages, int nr);

/**
 * kmsan_slab_alloc() - Notify KMSAN about a slab allocation.
 * @s:      slab cache the object belongs to.
 * @object: object pointer.
 * @flags:  GFP flags passed to the allocator.
 *
 * Depending on cache flags and GFP flags, KMSAN sets up the metadata of the
 * newly created object, marking it initialized or uninitialized.
 */
void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags);

/**
 * kmsan_slab_free() - Notify KMSAN about a slab deallocation.
 * @s:      slab cache the object belongs to.
 * @object: object pointer.
 *
 * KMSAN marks the freed object as uninitialized.
 */
void kmsan_slab_free(struct kmem_cache *s, void *object);

/**
 * kmsan_kmalloc_large() - Notify KMSAN about a large slab allocation.
 * @ptr:   object pointer.
 * @size:  object size.
 * @flags: GFP flags passed to the allocator.
 *
 * Similar to kmsan_slab_alloc(), but for large allocations.
 */
void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags);

/**
 * kmsan_kfree_large() - Notify KMSAN about a large slab deallocation.
 * @ptr: object pointer.
 *
 * Similar to kmsan_slab_free(), but for large allocations.
 */
void kmsan_kfree_large(const void *ptr);

/**
 * kmsan_vmap_page_range_noflush() - Notify KMSAN about a vmap.
 * @start: start address of vmapped range.
 * @end:   end address of vmapped range.
 * @prot:  page protection flags used for vmap.
 * @pages: array of pages.
 *
 * KMSAN maps shadow and origin pages of @pages into contiguous ranges in
 * vmalloc metadata address range.
 */
void kmsan_vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages);

/**
 * kmsan_vunmap_page_range() - Notify KMSAN about a vunmap.
 * @addr: start address of vunmapped range.
 * @end:  end address of vunmapped range.
 *
 * KMSAN unmaps the contiguous metadata ranges created by
 * kmsan_vmap_page_range_noflush().
 */
void kmsan_vunmap_page_range(unsigned long addr, unsigned long end);

/**
 * kmsan_ioremap_page_range() - Notify KMSAN about a ioremap_page_range() call.
 * @addr:      range start.
 * @end:       range end.
 * @phys_addr: physical range start.
 * @prot:      page protection flags used for ioremap_page_range().
 *
 * KMSAN creates new metadata pages for the physical pages mapped into the
 * virtual memory.
 */
void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
			      phys_addr_t phys_addr, pgprot_t prot);

/**
 * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
 * @start: range start.
 * @end:   range end.
 *
 * KMSAN unmaps the metadata pages for the given range and, unlike for
 * vunmap_page_range(), also deallocates them.
 */
void kmsan_iounmap_page_range(unsigned long start, unsigned long end);

/**
 * kmsan_context_enter() - Notify KMSAN about a context entry.
 *
 * This function should be called whenever the kernel leaves the current task
 * and enters an IRQ, softirq or NMI context. KMSAN will switch the task state
 * to a per-thread storage.
 */
void kmsan_context_enter(void);

/**
 * kmsan_context_exit() - Notify KMSAN about a context exit.
 *
 * This function should be called when the kernel leaves the previously entered
 * context.
 */
void kmsan_context_exit(void);

/**
 * kmsan_copy_to_user() - Notify KMSAN about a data transfer to userspace.
 * @to:      destination address in the userspace.
 * @from:    source address in the kernel.
 * @to_copy: number of bytes to copy.
 * @left:    number of bytes not copied.
 *
 * If this is a real userspace data transfer, KMSAN checks the bytes that were
 * actually copied to ensure there was no information leak. If @to belongs to
 * the kernel space (which is possible for compat syscalls), KMSAN just copies
 * the metadata.
 */
void kmsan_copy_to_user(const void *to, const void *from, size_t to_copy,
			size_t left);

/**
 * kmsan_check_skb() - Check an sk_buff for being initialized.
 *
 * KMSAN checks the memory belonging to a socket buffer and reports an error if
 * contains uninitialized values.
 */
void kmsan_check_skb(const struct sk_buff *skb);

/**
 * kmsan_handle_dma() - Handle a DMA data transfer.
 * @page:   first page of the buffer.
 * @offset: offset of the buffer within the first page.
 * @size:   buffer size.
 * @dir:    one of possible dma_data_direction values.
 *
 * Depending on @direction, KMSAN:
 * * checks the buffer, if it is copied to device;
 * * initializes the buffer, if it is copied from device;
 * * does both, if this is a DMA_BIDIRECTIONAL transfer.
 */
void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
		      enum dma_data_direction dir);

/**
 * kmsan_handle_dma_sg() - Handle a DMA transfer using scatterlist.
 * @sg:    scatterlist holding DMA buffers.
 * @nents: number of scatterlist entries.
 * @dir:   one of possible dma_data_direction values.
 *
 * Depending on @direction, KMSAN:
 * * checks the buffers in the scatterlist, if they are copied to device;
 * * initializes the buffers, if they are copied from device;
 * * does both, if this is a DMA_BIDIRECTIONAL transfer.
 */
void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
			 enum dma_data_direction dir);

/**
 * kmsan_handle_urb() - Handle a USB data transfer.
 * @urb:    struct urb pointer.
 * @is_out: data transfer direction (true means output to hardware)
 *
 * If @is_out is true, KMSAN checks the transfer buffer of @urb. Otherwise,
 * KMSAN initializes the transfer buffer.
 */
void kmsan_handle_urb(const struct urb *urb, bool is_out);

#else

static inline void __init kmsan_initialize_shadow(void) { }
static inline void __init kmsan_initialize(void) { }

static inline void kmsan_task_create(struct task_struct *task) {}
static inline void kmsan_task_exit(struct task_struct *task) {}

static inline int kmsan_alloc_page(struct page *page, unsigned int order,
				   gfp_t flags)
{
	return 0;
}
static inline void kmsan_free_page(struct page *page, unsigned int order) {}
static inline void kmsan_copy_page_meta(struct page *dst, struct page *src) {}
static inline void kmsan_gup_pgd_range(struct page **pages, int nr) {}

static inline void kmsan_slab_alloc(struct kmem_cache *s, void *object,
				    gfp_t flags) {}
static inline void kmsan_slab_free(struct kmem_cache *s, void *object) {}
static inline void kmsan_kmalloc_large(const void *ptr, size_t size,
				       gfp_t flags) {}
static inline void kmsan_kfree_large(const void *ptr) {}

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

static inline void kmsan_context_enter(void) {}
static inline void kmsan_context_exit(void) {}

static inline void kmsan_copy_to_user(
	const void *to, const void *from, size_t to_copy, size_t left) {}

static inline void kmsan_check_skb(const struct sk_buff *skb) {}
static inline void kmsan_handle_dma(struct page *page, size_t offset,
				    size_t size, enum dma_data_direction dir) {}
static inline void kmsan_handle_urb(const struct urb *urb, bool is_out) {}

#endif

#endif /* LINUX_KMSAN_H */
