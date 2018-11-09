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

#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <linux/gfp.h>
#include <linux/i2c.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/usb.h>

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

/* For KMSAN_ENABLE and KMSAN_DISABLE */
void kmsan_enter_runtime(unsigned long *flags)
{
	ENTER_RUNTIME(*flags);
}
EXPORT_SYMBOL(kmsan_enter_runtime);

void kmsan_leave_runtime(unsigned long *flags)
{
	LEAVE_RUNTIME(*flags);
}
EXPORT_SYMBOL(kmsan_leave_runtime);

/* Called from kernel/kthread.c, kernel/fork.c */
void kmsan_task_create(struct task_struct *task)
{
	unsigned long irq_flags;

	if (!task)
		return;
	ENTER_RUNTIME(irq_flags);
	do_kmsan_task_create(task);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_task_create);

/* Helper function to allocate page metadata. */
int kmsan_internal_alloc_meta_for_pages(struct page *page, unsigned int order,
					unsigned int actual_size, gfp_t flags, int node)
{
	struct page *shadow, *origin;
	int pages = 1 << order;
	int i;
	bool initialized = (flags & __GFP_ZERO) || !kmsan_ready;
	depot_stack_handle_t handle;

	// If |actual_size| is non-zero, we allocate |1 << order| metadata pages
	// for |actual_size| bytes of memory. We can't set shadow for more than
	// |actual_size >> PAGE_SHIFT| pages in that case.
	if (actual_size)
		pages = ALIGN(actual_size, PAGE_SIZE) >> PAGE_SHIFT;

	if (flags & __GFP_NO_KMSAN_SHADOW) {
		for (i = 0; i < pages; i++) {
			set_no_shadow_page(&page[i]);
			set_no_origin_page(&page[i]);
		}
		return 0;
	}

	flags = GFP_ATOMIC;  // TODO(glider)
	if (initialized)
		flags |= __GFP_ZERO;
	shadow = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	if (!shadow) {
		for (i = 0; i < pages; i++) {
			set_no_shadow_page(&page[i]);
			set_no_shadow_page(&page[i]);
		}
		return -ENOMEM;
	}
	if (!initialized)
		__memset(page_address(shadow), -1, PAGE_SIZE * pages);

	origin = alloc_pages_node(node, flags | __GFP_NO_KMSAN_SHADOW, order);
	// Assume we've allocated the origin.
	if (!origin) {
		__free_pages(shadow, order);
		for (i = 0; i < pages; i++) {
			set_no_shadow_page(&page[i]);
			set_no_origin_page(&page[i]);
		}
		return -ENOMEM;
	}

	if (!initialized) {
		handle = kmsan_save_stack_with_flags(flags);
		// Addresses are page-aligned, pages are contiguous, so it's ok
		// to just fill the origin pages with |handle|.
		for (i = 0; i < PAGE_SIZE * pages / sizeof(handle); i++) {
			((depot_stack_handle_t*)page_address(origin))[i] = handle;
		}
	}

	for (i = 0; i < pages; i++) {
		// TODO(glider): sometimes shadow_page_for(&page[i]) is initialized. Let's skip the check for now.
		///if (shadow_page_for(&page[i])) continue;
		shadow_page_for(&page[i]) = &shadow[i];
		set_no_shadow_page(shadow_page_for(&page[i]));
		set_no_origin_page(shadow_page_for(&page[i]));
		origin_page_for(&page[i]) = &origin[i];
		set_no_shadow_page(origin_page_for(&page[i]));
		set_no_origin_page(origin_page_for(&page[i]));
	}
	return 0;
}


/* Called from kernel/exit.c */
void kmsan_task_exit(struct task_struct *task)
{
	unsigned long irq_flags;
	kmsan_task_state *state = &task->kmsan;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	state->enabled = false;
	state->allow_reporting = false;
	state->is_reporting = false;

	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_task_exit);

/* Called from mm/slub.c */
void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
{
	unsigned long irq_flags;

	if (unlikely(object == NULL))
		return;
	if (!kmsan_ready || IN_RUNTIME())
		return;
	/*
	 * There's a ctor or this is an RCU cache - do nothing. The memory
	 * status hasn't changed since last use.
	 */
	if (s->ctor || (s->flags & SLAB_TYPESAFE_BY_RCU))
		return;

	ENTER_RUNTIME(irq_flags);
	if (flags & __GFP_ZERO) {
		kmsan_internal_unpoison_shadow(object, s->object_size,
					       /*checked*/true);
	} else {
		kmsan_internal_poison_shadow(object, s->object_size, flags,
					     /*checked*/true);
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/slub.c */
void kmsan_slab_free(struct kmem_cache *s, void *object)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);

	/* RCU slabs could be legally used after free within the RCU period */
	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
		goto leave;
	if (s->ctor)
		goto leave;
	kmsan_internal_poison_shadow(object, s->object_size,
				     GFP_KERNEL, /*checked*/true);
leave:
	LEAVE_RUNTIME(irq_flags);
	return;
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
		kmsan_internal_unpoison_shadow((void *)ptr, size, /*checked*/true);
	} else {
		kmsan_internal_poison_shadow((void *)ptr, size, flags, /*checked*/true);
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/slub.c */
void kmsan_kfree_large(const void *ptr)
{
	struct page *page;
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	page = virt_to_page_or_null((void *)ptr);
	kmsan_internal_poison_shadow(
		(void *)ptr, PAGE_SIZE << compound_order(page), GFP_KERNEL, /*checked*/true);
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/page_alloc.c */
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

/* Called from mm/page_alloc.c */
void kmsan_free_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin, *cur_page;
	int pages = 1 << order;
	int i;
	unsigned long irq_flags;

	if (!shadow_page_for(page)) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			BUG_ON(shadow_page_for(cur_page));
		}
		return;
	}

	if (!kmsan_ready) {
		for (i = 0; i < pages; i++) {
			cur_page = &page[i];
			set_no_shadow_page(cur_page);
			set_no_origin_page(cur_page);
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
	if (!has_shadow_page(&page[0])) {
		/* TODO(glider): can we free a page without a shadow?
		 * Maybe if it was allocated at boot time?
		 * Anyway, all shadow pages must be NULL then.
		 */
		for (i = 0; i < pages; i++)
			if (has_shadow_page(&page[i])) {
				current->kmsan.is_reporting = true;
				for (i = 0; i < pages; i++)
					kmsan_pr_err("shadow_page_for(&page[%d])=%px\n",
							i, shadow_page_for(&page[i]));
				current->kmsan.is_reporting = false;
				break;
			}
		LEAVE_RUNTIME(irq_flags);
		return;
	}

	shadow = shadow_page_for(&page[0]);
	origin = origin_page_for(&page[0]);

	/* TODO(glider): this is racy. */
	for (i = 0; i < pages; i++) {
		BUG_ON(has_shadow_page(shadow_page_for(&page[i])));
		set_no_shadow_page(&page[i]);
		BUG_ON(has_shadow_page(origin_page_for(&page[i])));
		set_no_origin_page(&page[i]);
	}
	BUG_ON(has_shadow_page(shadow));
	__free_pages(shadow, order);

	BUG_ON(has_shadow_page(origin));
	__free_pages(origin, order);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_free_page);

/* Called from mm/page_alloc.c */
void kmsan_split_page(struct page *page, unsigned int order)
{
	struct page *shadow, *origin;
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	if (!has_shadow_page(&page[0])) {
		BUG_ON(has_origin_page(&page[0]));
		LEAVE_RUNTIME(irq_flags);
		return;
	}
	shadow = shadow_page_for(&page[0]);
	split_page(shadow, order);

	origin = origin_page_for(&page[0]);
	split_page(origin, order);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_split_page);

/* Called from mm/vmalloc.c */
void kmsan_vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages)
{
	int nr, i, mapped;
	struct page **s_pages, **o_pages;
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	if (!vmalloc_shadow(start))
		return;

	BUG_ON(start >= end);
	nr = (end - start) / PAGE_SIZE;
	s_pages = kzalloc(sizeof(struct page *) * nr, GFP_KERNEL);
	o_pages = kzalloc(sizeof(struct page *) * nr, GFP_KERNEL);
	if (!s_pages || !o_pages)
		goto ret;
	for (i = 0; i < nr; i++) {
		s_pages[i] = shadow_page_for(pages[i]);
		o_pages[i] = origin_page_for(pages[i]);
	}
	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
	prot = PAGE_KERNEL;
	mapped = __vmap_page_range_noflush(vmalloc_shadow(start), vmalloc_shadow(end), prot, s_pages);
	BUG_ON(mapped != nr);
	flush_tlb_kernel_range(vmalloc_shadow(start), vmalloc_shadow(end));
	mapped = __vmap_page_range_noflush(vmalloc_origin(start), vmalloc_origin(end), prot, o_pages);
	BUG_ON(mapped != nr);
	flush_tlb_kernel_range(vmalloc_origin(start), vmalloc_origin(end));
ret:
	if (s_pages)
		kfree(s_pages);
	if (o_pages)
		kfree(o_pages);
}

/* Called from mm/vmalloc.c */
void kmsan_vunmap_page_range(unsigned long start, unsigned long end)
{
	__vunmap_page_range(vmalloc_shadow(start), vmalloc_shadow(end));
	__vunmap_page_range(vmalloc_origin(start), vmalloc_origin(end));
}

/* Called from lib/ioremap.c */
/*
 * This function creates new shadow/origin pages for the physical pages mapped
 * into the virtual memory. If those physical pages already had shadow/origin, those are ignored.
 */
void kmsan_ioremap_page_range(unsigned long start, unsigned long end,
	phys_addr_t phys_addr, pgprot_t prot)
{
	unsigned long irq_flags;
	struct page *shadow, *origin;
	int i, nr;
	unsigned long off = 0;
	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO | __GFP_NO_KMSAN_SHADOW;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	nr = (end - start) / PAGE_SIZE;
	ENTER_RUNTIME(irq_flags);
	for (i = 0; i < nr; i++, off += PAGE_SIZE) {
		shadow = alloc_pages(gfp_mask, 1);
		origin = alloc_pages(gfp_mask, 1);
		__vmap_page_range_noflush(vmalloc_shadow(start + off), vmalloc_shadow(start + off + PAGE_SIZE), prot, &shadow);
		__vmap_page_range_noflush(vmalloc_origin(start + off), vmalloc_origin(start + off + PAGE_SIZE), prot, &origin);
	}
	flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
	flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
	LEAVE_RUNTIME(irq_flags);
}

void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
{
	int i, nr;
	struct page *shadow, *origin;
	unsigned long v_shadow, v_origin;
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	nr = (end - start) / PAGE_SIZE;
	ENTER_RUNTIME(irq_flags);
	v_shadow = (unsigned long)vmalloc_shadow(start);
	v_origin = (unsigned long)vmalloc_origin(start);
	for (i = 0; i < nr; i++, v_shadow += PAGE_SIZE, v_origin += PAGE_SIZE) {
		shadow = vmalloc_to_page_or_null((void *)v_shadow);
		origin = vmalloc_to_page_or_null((void *)v_origin);
		__vunmap_page_range(v_shadow, v_shadow + PAGE_SIZE);
		__vunmap_page_range(v_origin, v_origin + PAGE_SIZE);
		if (shadow)
			__free_pages(shadow, 1);
		if (origin)
			__free_pages(origin, 1);
	}
	LEAVE_RUNTIME(irq_flags);
}

/* Called from mm/memory.c */
void kmsan_copy_page_meta(struct page *dst, struct page *src)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	if (!has_shadow_page(src)) {
		/* TODO(glider): are we leaking pages here? */
		set_no_shadow_page(dst);
		set_no_origin_page(dst);
		return;
	}
	if (!has_shadow_page(dst))
		return;

	ENTER_RUNTIME(irq_flags);
	__memcpy(shadow_ptr_for(dst), shadow_ptr_for(src),
		PAGE_SIZE);
	BUG_ON(!has_origin_page(src) || !has_origin_page(dst));
	__memcpy(origin_ptr_for(dst), origin_ptr_for(src),
		PAGE_SIZE);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_copy_page_meta);


/* Called from include/linux/uaccess.h, include/linux/uaccess.h */
void kmsan_copy_to_user(const void *to, const void *from,
			size_t to_copy, size_t left)
{
	void *shadow;

	if (!kmsan_ready || IN_RUNTIME())
		return;
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
		kmsan_internal_check_memory((void *)from, to_copy - left, to,
						REASON_COPY_TO_USER);
		return;
	}
	/* Otherwise this is a kernel memory access. This happens when a compat
	 * syscall passes an argument allocated on the kernel stack to a real
	 * syscall.
	 * Don't check anything, just copy the shadow of the copied bytes.
	 */
	shadow = kmsan_get_metadata_or_null((void *)to, to_copy - left, /*origin*/false);
	if (shadow) {
		kmsan_memcpy_metadata((void *)to, (void *)from, to_copy - left);
	}
}
EXPORT_SYMBOL(kmsan_copy_to_user);

/* Called from include/linux/highmem.h */
void kmsan_clear_page(void *page_addr)
{
	struct page *page;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	BUG_ON(!IS_ALIGNED((u64)page_addr, PAGE_SIZE));
	page = vmalloc_to_page_or_null(page_addr);
	if (!page)
		page = virt_to_page_or_null(page_addr);
	if (!page || !has_shadow_page(page))
		return;
	__memset(shadow_ptr_for(page), 0, PAGE_SIZE);
	BUG_ON(!has_origin_page(page));
	__memset(origin_ptr_for(page), 0, PAGE_SIZE);
}
EXPORT_SYMBOL(kmsan_clear_page);

void kmsan_poison_shadow(const volatile void *address, size_t size, gfp_t flags)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;
	ENTER_RUNTIME(irq_flags);
	// The users may want to poison/unpoison random memory.
	kmsan_internal_poison_shadow((void *)address, size, flags, /*checked*/true);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_poison_shadow);

void kmsan_unpoison_shadow(const volatile void *address, size_t size)
{
	unsigned long irq_flags;

	if (!kmsan_ready || IN_RUNTIME())
		return;

	ENTER_RUNTIME(irq_flags);
	// The users may want to poison/unpoison random memory.
	kmsan_internal_unpoison_shadow((void *)address, size, /*checked*/false);
	LEAVE_RUNTIME(irq_flags);
}
EXPORT_SYMBOL(kmsan_unpoison_shadow);

void kmsan_check_memory(const volatile void *addr, size_t size)
{
	return kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0, REASON_ANY);
}
EXPORT_SYMBOL(kmsan_check_memory);

void kmsan_gup_pgd_range(struct page **pages, int nr)
{
	int i;
	void *page_addr;

	/*
	 * gup_pgd_range() has just created a number of new pages that KMSAN
	 * treats as uninitialized. In the case they belong to the userspace
	 * memory, unpoison the corresponding kernel pages.
	 */
	for (i = 0; i < nr; i++) {
		page_addr = page_address(pages[i]);
		if (((u64)page_addr < TASK_SIZE) && ((u64)page_addr + PAGE_SIZE < TASK_SIZE))
			kmsan_unpoison_shadow(page_addr, PAGE_SIZE);
	}

}
EXPORT_SYMBOL(kmsan_gup_pgd_range);

/* Helper function to check an SKB. */
void kmsan_check_skb(const struct sk_buff *skb)
{
	int start = skb_headlen(skb);
	struct sk_buff *frag_iter;
	int i, copy;
	skb_frag_t *f;
	u32 p_off, p_len, copied;
	struct page *p;
	u8 *vaddr;

	if (!skb || !skb->len)
		return;

	kmsan_internal_check_memory(skb->data, skb_headlen(skb), 0, REASON_ANY);
	if (skb_is_nonlinear(skb)) {
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			f = &skb_shinfo(skb)->frags[i];

			skb_frag_foreach_page(f,
					      f->page_offset  - start,
					      copy, p, p_off, p_len, copied) {
				vaddr = kmap_atomic(p);
				kmsan_internal_check_memory(vaddr + p_off,
						p_len, /*user_addr*/ 0,
						REASON_ANY);
				kunmap_atomic(vaddr);
			}
		}
	}
	skb_walk_frags(skb, frag_iter)
		kmsan_check_skb(frag_iter);
}
EXPORT_SYMBOL(kmsan_check_skb);

/* Helper function to check an URB. */
void kmsan_handle_urb(const struct urb *urb, bool is_out)
{
	if (!urb)
		return;
	if (is_out)
		kmsan_internal_check_memory(urb->transfer_buffer,
					    urb->transfer_buffer_length,
					    /*user_addr*/ 0, REASON_SUBMIT_URB);
	else
		kmsan_internal_unpoison_shadow(urb->transfer_buffer,
					       urb->transfer_buffer_length,
					       /*checked*/false);
}
EXPORT_SYMBOL(kmsan_handle_urb);

/* Helper function to check I2C-transferred data. */
void kmsan_handle_i2c_transfer(struct i2c_msg *msgs, int num)
{
	int i;

	if (!msgs)
		return;
	for (i = 0; i < num; i++) {
		if (msgs[i].flags & I2C_M_RD)
			kmsan_internal_unpoison_shadow(msgs[i].buf,
						       msgs[i].len,
						       /*checked*/false);
		else
			kmsan_internal_check_memory(msgs[i].buf, msgs[i].len,
						    /*user_addr*/0,
						    REASON_ANY);
	}
}
