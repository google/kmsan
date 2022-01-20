/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KMSAN API for subsystems.
 *
 * Copyright (C) 2017-2022 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */
#ifndef _LINUX_KMSAN_H
#define _LINUX_KMSAN_H

#include <linux/gfp.h>
#include <linux/kmsan-checks.h>
#include <linux/stackdepot.h>
#include <linux/types.h>

struct page;

#ifdef CONFIG_KMSAN

/* These constants are defined in the MSan LLVM instrumentation pass. */
#define KMSAN_RETVAL_SIZE 800
#define KMSAN_PARAM_SIZE 800

struct kmsan_context_state {
	char param_tls[KMSAN_PARAM_SIZE];
	char retval_tls[KMSAN_RETVAL_SIZE];
	char va_arg_tls[KMSAN_PARAM_SIZE];
	char va_arg_origin_tls[KMSAN_PARAM_SIZE];
	u64 va_arg_overflow_size_tls;
	char param_origin_tls[KMSAN_PARAM_SIZE];
	depot_stack_handle_t retval_origin_tls;
};

#undef KMSAN_PARAM_SIZE
#undef KMSAN_RETVAL_SIZE

struct kmsan_ctx {
	struct kmsan_context_state cstate;
	int kmsan_in_runtime;
	bool allow_reporting;
};

/**
 * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
 * @page:  struct page pointer returned by alloc_pages().
 * @order: order of allocated struct page.
 * @flags: GFP flags used by alloc_pages()
 *
 * KMSAN marks 1<<@order pages starting at @page as uninitialized, unless
 * @flags contain __GFP_ZERO.
 */
void kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags);

/**
 * kmsan_free_page() - Notify KMSAN about a free_pages() call.
 * @page:  struct page pointer passed to free_pages().
 * @order: order of deallocated struct page.
 *
 * KMSAN marks freed memory as uninitialized.
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
 * kmsan_map_kernel_range_noflush() - Notify KMSAN about a vmap.
 * @start:	start of vmapped range.
 * @end:	end of vmapped range.
 * @prot:	page protection flags used for vmap.
 * @pages:	array of pages.
 * @page_shift:	page_shift passed to vmap_range_noflush().
 *
 * KMSAN maps shadow and origin pages of @pages into contiguous ranges in
 * vmalloc metadata address range.
 */
void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
				    pgprot_t prot, struct page **pages,
				    unsigned int page_shift);

/**
 * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
 * @start: start of vunmapped range.
 * @end:   end of vunmapped range.
 *
 * KMSAN unmaps the contiguous metadata ranges created by
 * kmsan_map_kernel_range_noflush().
 */
void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);

/**
 * kmsan_ioremap_page_range() - Notify KMSAN about a ioremap_page_range() call.
 * @addr:	range start.
 * @end:	range end.
 * @phys_addr:	physical range start.
 * @prot:	page protection flags used for ioremap_page_range().
 * @page_shift:	page_shift argument passed to vmap_range_noflush().
 *
 * KMSAN creates new metadata pages for the physical pages mapped into the
 * virtual memory.
 */
void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
			      phys_addr_t phys_addr, pgprot_t prot,
			      unsigned int page_shift);

/**
 * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
 * @start: range start.
 * @end:   range end.
 *
 * KMSAN unmaps the metadata pages for the given range and, unlike for
 * vunmap_page_range(), also deallocates them.
 */
void kmsan_iounmap_page_range(unsigned long start, unsigned long end);

#else

static inline int kmsan_alloc_page(struct page *page, unsigned int order,
				   gfp_t flags)
{
	return 0;
}

static inline void kmsan_free_page(struct page *page, unsigned int order)
{
}

static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
{
}

static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
						  unsigned long end,
						  pgprot_t prot,
						  struct page **pages,
						  unsigned int page_shift)
{
}

static inline void kmsan_vunmap_range_noflush(unsigned long start,
					      unsigned long end)
{
}

static inline void kmsan_ioremap_page_range(unsigned long start,
					    unsigned long end,
					    phys_addr_t phys_addr,
					    pgprot_t prot,
					    unsigned int page_shift)
{
}

static inline void kmsan_iounmap_page_range(unsigned long start,
					    unsigned long end)
{
}

#endif

#endif /* _LINUX_KMSAN_H */
