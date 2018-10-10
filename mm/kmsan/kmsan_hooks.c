/*
 * KMSAN hooks for kernel subsystems.
 *
 * These functions handle creation of KMSAN metadata for memory allocations.
 *
 * Copyright (C) 2018 Google, Inc
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */



#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>

#include "../slab.h"
#include "kmsan.h"

/* TODO(glider): do we need to export these symbols? */

/*
 * The functions may call back to instrumented code, which, in turn, may call
 * these hooks again. To avoid re-entrancy, we use __GFP_NO_KMSAN_SHADOW.
 * Instrumented functions shouldn't be called under
 * ENTER_RUNTIME()/LEAVE_RUNTIME(), because this will lead to skipping
 * effects of functions like memset() inside instrumented code.
 */

/* Called from kernel/kthread.c, kernel/fork.c */
void kmsan_thread_create(struct task_struct *task)
{
	unsigned long irq_flags;

	if (!task)
		return;
	ENTER_RUNTIME(irq_flags);
	do_kmsan_thread_create(task);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_thread_create);

/* Called from kernel/exit.c */
void kmsan_task_exit(struct task_struct *task)
{
	unsigned long irq_flags;
	kmsan_thread_state *state = &task->kmsan;
	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	state->enabled = false;
	state->allow_reporting = false;
	state->is_reporting = false;

	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_task_exit);

/* Called from mm/slab.c */
void kmsan_poison_slab(struct page *page, gfp_t flags)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	if (flags & __GFP_ZERO) {
		kmsan_internal_unpoison_shadow(
			page_address(page), PAGE_SIZE << compound_order(page));
	} else {
		kmsan_internal_poison_shadow(
			page_address(page), PAGE_SIZE << compound_order(page),
			flags);
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/slab.c, mm/slub.c */
void kmsan_kmalloc(struct kmem_cache *cache, const void *object, size_t size,
		   gfp_t flags)
{
	unsigned long irq_flags;

	if (unlikely(object == NULL))
		return;
	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	if (flags & __GFP_ZERO) {
		// TODO(glider) do we poison by default?
		kmsan_internal_unpoison_shadow((void *)object, size);
	} else {
		if (!cache->ctor)
			kmsan_internal_poison_shadow((void *)object, size,
							flags);
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/slab.c, mm/slab.h */
void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
{
	kmsan_kmalloc(s, object, s->object_size, flags);
}

/* Called from mm/slab.c, mm/slub.c */
bool kmsan_slab_free(struct kmem_cache *s, void *object)
{
	/* RCU slabs could be legally used after free within the RCU period */
	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
		return false;
	kmsan_internal_poison_shadow((void *)object, s->object_size,
					GFP_KERNEL);
	return true;
}

/* Called from mm/slub.c */
void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
{
	unsigned long irq_flags;

	if (unlikely(ptr == NULL))
		return;
	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	if (flags & __GFP_ZERO) {
		// TODO(glider) do we poison by default?
		kmsan_internal_unpoison_shadow((void *)ptr, size);
	} else {
		kmsan_internal_poison_shadow((void *)ptr, size, flags);
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/slub.c */
void kmsan_kfree_large(const void *ptr)
{
	struct page *page;
	unsigned long irq_flags;

	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	page = virt_to_page_or_null(ptr);
	kmsan_internal_poison_shadow(
		(void *)ptr, PAGE_SIZE << compound_order(page), GFP_KERNEL);
	LEAVE_RUNTIME(irq_flags);
}

bool kmsan_vmalloc_area_node(struct vm_struct *area, gfp_t alloc_mask, gfp_t nested_gfp, gfp_t highmem_mask, pgprot_t prot, int node)
{
	struct page **s_pages, **o_pages;
	struct vm_struct *s_area, *o_area;
	size_t area_size = get_vm_area_size(area);
	unsigned int nr_pages = area->nr_pages;
	unsigned int array_size = nr_pages * sizeof(struct page *);
	unsigned long irq_flags;
	int i;

	if (!kmsan_ready || IN_RUNTIME())
		return true;
	if (alloc_mask & __GFP_NO_KMSAN_SHADOW)
		return true;

	s_area = get_vm_area(area_size, /*flags*/0);
	o_area = get_vm_area(area_size, /*flags*/0);

	if (array_size > PAGE_SIZE) {
		s_pages = __vmalloc_node_flags_caller(array_size, node, nested_gfp|highmem_mask|__GFP_NO_KMSAN_SHADOW, (void*)area->caller);
		o_pages = __vmalloc_node_flags_caller(array_size, node, nested_gfp|highmem_mask|__GFP_NO_KMSAN_SHADOW, (void*)area->caller);
	} else {
		s_pages = kmalloc_node(array_size, nested_gfp | __GFP_NO_KMSAN_SHADOW, node);
		o_pages = kmalloc_node(array_size, nested_gfp | __GFP_NO_KMSAN_SHADOW, node);
	}
	if (!s_pages || !o_pages)
		goto fail;

	for (i = 0; i < area->nr_pages; i++) {
		s_pages[i] = area->pages[i]->shadow;
		o_pages[i] = area->pages[i]->origin;
	}

	s_area->pages = s_pages;
	o_area->pages = o_pages;

	if (map_vm_area(s_area, prot, s_pages))
		goto fail;
	if (map_vm_area(o_area, prot, o_pages))
		goto fail;
	area->shadow = s_area;
	area->origin = o_area;

	area->is_kmsan_tracked = true;
	return true;

fail:
	remove_vm_area(s_area->addr);
	remove_vm_area(o_area->addr);
	kfree(s_area);
	kfree(o_area);
	return false;
}

/* Called from mm/vmalloc.c */
void kmsan_vmap(struct vm_struct *area,
		struct page **pages, unsigned int count, unsigned long flags,
		pgprot_t prot, void *caller)
{
	struct vm_struct *shadow, *origin;
	struct page **s_pages = NULL, **o_pages = NULL;
	unsigned long irq_flags, size;
	int i;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	if (flags & __GFP_NO_KMSAN_SHADOW)
		return;

	size = (unsigned long)count << PAGE_SHIFT;
	// It's important to call get_vm_area_caller() (which calls kmalloc())
	// and kmalloc() outside the runtime.
	// Calling kmalloc() may potentially allocate a new slab without
	// corresponding shadow pages. Accesses to any subsequent allocations
	// from that slab will crash the kernel.
	shadow = get_vm_area_caller(size, flags | __GFP_NO_KMSAN_SHADOW, caller);
	origin = get_vm_area_caller(size, flags | __GFP_NO_KMSAN_SHADOW, caller);
	/* TODO(glider): __GFP_NO_KMSAN_SHADOW below indicates that kmalloc won't be
	 * calling KMSAN hooks again, but it cannot guarantee the allocation
	 * will be performed from an untracked page (we would need a separate
	 * kmalloc cache for that). To make sure the pages are unpoisoned, we also
	 * allocate with __GFP_ZERO.
	 */
	s_pages = kmalloc(count * sizeof(struct page *), GFP_KERNEL | __GFP_NO_KMSAN_SHADOW | __GFP_ZERO);
	if (!s_pages)
		goto err_free;
	o_pages = kmalloc(count * sizeof(struct page *), GFP_KERNEL | __GFP_NO_KMSAN_SHADOW | __GFP_ZERO);
	for (i = 0; i < count; i++) {
		if (!pages[i]->is_kmsan_tracked_page)
			goto err_free;
		s_pages[i] = pages[i]->shadow;
		o_pages[i] = pages[i]->origin;
	}
	// Don't enter the runtime when allocating memory with kmalloc().
	if (map_vm_area(shadow, prot, s_pages) ||
	    map_vm_area(origin, prot, o_pages)) {
		goto err_free;
	}

	shadow->pages = s_pages;
	shadow->nr_pages = count;
	shadow->is_kmsan_tracked = false;
	origin->pages = o_pages;
	origin->nr_pages = count;
	origin->is_kmsan_tracked = false;
	area->shadow = shadow;
	area->origin = origin;
	area->is_kmsan_tracked = true;
	return;
err_free:
	if (s_pages)
		kfree(s_pages);
	if (o_pages)
		kfree(o_pages);
	if (shadow)
		vunmap(shadow->addr);
	if (origin)
		vunmap(origin->addr);
}

/* Called from mm/vmalloc.c */
void kmsan_vunmap(const void *addr, struct vm_struct *area, int deallocate_pages)
{
	unsigned long irq_flags;
	struct vm_struct *vms, *shadow, *origin;
	int i;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	if (!vms || !vms->is_kmsan_tracked)
		return;
	shadow = vms->shadow;
	origin = vms->origin;

	vunmap(vms->shadow->addr);
	vunmap(vms->origin->addr);

	BUG_ON(shadow->nr_pages != origin->nr_pages);
	for (i = 0; i < shadow->nr_pages; i++) {
		BUG_ON(shadow->pages[i]);
		__free_pages(shadow->pages[i], 0);
		BUG_ON(origin->pages[i]);
		__free_pages(origin->pages[i], 0);
	}
	kfree(shadow->pages);
	kfree(origin->pages);
}
EXPORT_SYMBOL(kmsan_vunmap);

/* Called from mm/page_alloc.c, mm/slab.c */
int kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags)
{
	unsigned long irq_flags;
	int ret;

	if (IN_RUNTIME())
		return 0;
	ENTER_RUNTIME(irq_flags);
	ret = kmsan_internal_alloc_meta_for_pages(
		page, order, /*actual_size*/ 0, flags, -1);
	LEAVE_RUNTIME(irq_flags);
	return ret;
}

/* Called from mm/page_alloc.c, mm/slab.c */
void kmsan_free_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin, *cur_page;
	int pages = 1 << order;
	int i;
	unsigned long irq_flags;

	if (!page->is_kmsan_tracked_page) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			cur_page->is_kmsan_tracked_page = true;
			BUG_ON(cur_page->shadow);
		}
		return;
	}

	/* TODO(glider): order? */
	if (!kmsan_ready) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			/* We want is_kmsan_tracked_page() be true for all
			 * deallocated pages.
			 */
			cur_page->is_kmsan_tracked_page = true;
			cur_page->shadow = NULL;
			cur_page->origin = NULL;
		}
		return;
	}

	if (IN_RUNTIME()) {
		/* TODO(glider): looks legit. depot_save_stack() may call
		 * free_pages().
		 */
		return;
	}

	ENTER_RUNTIME(irq_flags);
	if (!page[0].shadow) {
		/* TODO(glider): can we free a page without a shadow?
		 * Maybe if it was allocated at boot time?
		 * Anyway, all shadow pages must be NULL then.
		 */
		for (i = 0; i < pages; i++)
			if (page[i].shadow) {
				current->kmsan.is_reporting = true;
				for (i = 0; i < pages; i++)
					kmsan_pr_err("page[%d].shadow=%px\n",
							i, page[i].shadow);
				current->kmsan.is_reporting = false;
				break;
			}
		LEAVE_RUNTIME(irq_flags);
		return;
	}

	shadow = page[0].shadow;
	origin = page[0].origin;

	/* TODO(glider): this is racy. */
	for (i = 0; i < pages; i++) {
		BUG_ON((page[i].shadow->is_kmsan_tracked_page));
		page[i].shadow = NULL;
		BUG_ON(page[i].origin->is_kmsan_tracked_page);
		page[i].origin = NULL;
	}
	BUG_ON(shadow->is_kmsan_tracked_page);
	__free_pages(shadow, order);

	BUG_ON(origin->is_kmsan_tracked_page);
	__free_pages(origin, order);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_free_page);

/* Called from mm/page_alloc.c */
void kmsan_split_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin;
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	if (!page->is_kmsan_tracked_page)
		return;

	ENTER_RUNTIME(irq_flags);
	if (!page[0].shadow) {
		BUG_ON(page[0].origin);
		LEAVE_RUNTIME(irq_flags);
		return;
	}
	shadow = page[0].shadow;
	split_page(shadow, order);

	origin = page[0].origin;
	split_page(origin, order);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_split_page);

/* Called from drivers/acpi/osl.c */
void kmsan_acpi_map(void *vaddr, unsigned long size)
{
	struct page *page;
	unsigned long irq_flags;
	int order;

	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	page = vmalloc_to_page_or_null(vaddr);
	if (!page) {
		LEAVE_RUNTIME(irq_flags);
		return;
	}
	order = order_from_size(size);
	/* Although the address is virtual, corresponding ACPI physical pages
	 * are consequent.
	 */
	kmsan_internal_alloc_meta_for_pages(page, order, size,
						GFP_KERNEL | __GFP_ZERO, -1);
	LEAVE_RUNTIME(irq_flags);
}

/* Called from drivers/acpi/osl.c */
void kmsan_acpi_unmap(void *vaddr, unsigned long size)
{
	struct page *page;
	unsigned long irq_flags;
	int order;
	int pages, i;
	return;

	if (IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	page = vmalloc_to_page_or_null(vaddr);
	if (size == -1)
		size = get_vm_area_size(find_vm_area(vaddr));
	order = order_from_size(size);
	page->is_kmsan_tracked_page = false;
	if (page->shadow)
		__free_pages(page->shadow, order);
	if (page->origin)
		__free_pages(page->origin, order);
	pages = ALIGN(size, PAGE_SIZE) >> PAGE_SHIFT;
	for (i = 0; i < pages; i++) {
		page[i].shadow = NULL;
		page[i].origin = NULL;
		page[i].is_kmsan_tracked_page = false;
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/memory.c */
void kmsan_copy_page_meta(struct page *dst, struct page *src)
{
	unsigned long irq_flags;

	if (!kmsan_ready)
		return;
	if (IN_RUNTIME())
		return;
	if (!src->is_kmsan_tracked_page) {
		dst->is_kmsan_tracked_page = false;
		dst->shadow = 0;
		dst->origin = 0;
		return;
	}
	if (!dst->is_kmsan_tracked_page)
		return;

	ENTER_RUNTIME(irq_flags);
	if (!src->shadow || !dst->shadow) {
		kmsan_pr_err("Copying %px (page %px, shadow %px) "
				"to %px (page %px, shadow %px)\n",
				page_address(src), src, src->shadow,
				page_address(dst), dst, dst->shadow);
		BUG();
	}
	__memcpy(page_address(dst->shadow), page_address(src->shadow),
		 PAGE_SIZE);
	BUG_ON(!src->origin || !dst->origin);
	__memcpy(page_address(dst->origin), page_address(src->origin),
		 PAGE_SIZE);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_copy_page_meta);

/* Called from kernel/printk/printk.c */
void kmsan_vprintk_func(const char *fmt, va_list args)
{
	const char *cur_p = fmt;
	char cur;

	while ((cur = *cur_p)) {
		if (cur == '%') {
			// TODO(glider): this is inaccurate.
			// Okay, this is actually doing nothing.
		}
		cur_p++;
	}
}

/* Called from include/linux/uaccess.h, include/linux/uaccess.h */
void kmsan_copy_to_user(const void *to, const void *from,
			size_t to_copy, size_t left)
{
	void *shadow;

	/* TODO(glider): at this point we've copied the memory already.
	 * Might be better to check it before copying.
	 */

	/* copy_to_user() may copy zero bytes. No need to check. */
	if (!to_copy)
		return;
	/* Or maybe copy_to_user() failed to copy anything. */
	if (to_copy == left)
		return;
	if ((u64)to < TASK_SIZE) {
		/* This is a user memory access, check it. */
		kmsan_internal_check_memory(from, to_copy - left,
						REASON_COPY_TO_USER);
		return;
	}
	/* Otherwise this is a kernel memory access. This happens when a compat
	 * syscall passes an argument allocated on the kernel stack to a real
	 * syscall.
	 * Don't check anything, just copy the shadow of the copied bytes.
	 */
	shadow = kmsan_get_shadow_address((u64)to, to_copy - left,
					/*checked*/true, /*is_store*/false);
	if (shadow) {
		kmsan_memcpy_shadow((u64)to, (u64)from, to_copy - left);
		kmsan_memcpy_origins((u64)to, (u64)from, to_copy - left);
	}
}
EXPORT_SYMBOL(kmsan_copy_to_user);

