// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN hooks for kernel subsystems.
 *
 * These functions handle creation of KMSAN metadata for memory allocations.
 *
 * Copyright (C) 2018-2021 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#include <linux/cacheflush.h>
#include <linux/dma-direction.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/usb.h>

#include "../internal.h"
#include "../slab.h"
#include "kmsan.h"

/*
 * Instrumented functions shouldn't be called under
 * kmsan_enter_runtime()/kmsan_leave_runtime(), because this will lead to
 * skipping effects of functions like memset() inside instrumented code.
 */

static void kmsan_handle_dma_page(const void *addr, size_t size,
				  enum dma_data_direction dir)
{
	switch (dir) {
	case DMA_BIDIRECTIONAL:
		kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
					    REASON_ANY);
		kmsan_internal_unpoison_memory((void *)addr, size,
					       /*checked*/ false);
		break;
	case DMA_TO_DEVICE:
		kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
					    REASON_ANY);
		break;
	case DMA_FROM_DEVICE:
		kmsan_internal_unpoison_memory((void *)addr, size,
					       /*checked*/ false);
		break;
	case DMA_NONE:
		break;
	}
}

/* Helper function to handle DMA data transfers. */
void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
		      enum dma_data_direction dir)
{
	u64 page_offset, to_go, addr;

	if (PageHighMem(page))
		return;
	addr = (u64)page_address(page) + offset;
	/*
	 * The kernel may occasionally give us adjacent DMA pages not belonging
	 * to the same allocation. Process them separately to avoid triggering
	 * internal KMSAN checks.
	 */
	while (size > 0) {
		page_offset = addr % PAGE_SIZE;
		to_go = min(PAGE_SIZE - page_offset, (u64)size);
		kmsan_handle_dma_page((void *)addr, to_go, dir);
		addr += to_go;
		size -= to_go;
	}
}
EXPORT_SYMBOL(kmsan_handle_dma);

void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
			 enum dma_data_direction dir)
{
	struct scatterlist *item;
	int i;

	for_each_sg(sg, item, nents, i)
		kmsan_handle_dma(sg_page(item), item->offset, item->length,
				 dir);
}
EXPORT_SYMBOL(kmsan_handle_dma_sg);

/* Functions from kmsan-checks.h follow. */
void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
{
	if (!kmsan_enabled || kmsan_in_runtime())
		return;
	kmsan_enter_runtime();
	/* The users may want to poison/unpoison random memory. */
	kmsan_internal_poison_memory((void *)address, size, flags,
				     KMSAN_POISON_NOCHECK);
	kmsan_leave_runtime();
}
EXPORT_SYMBOL(kmsan_poison_memory);

void kmsan_unpoison_memory(const void *address, size_t size)
{
	unsigned long ua_flags;

	if (!kmsan_enabled || kmsan_in_runtime())
		return;

	ua_flags = user_access_save();
	kmsan_enter_runtime();
	/* The users may want to poison/unpoison random memory. */
	kmsan_internal_unpoison_memory((void *)address, size,
				       KMSAN_POISON_NOCHECK);
	kmsan_leave_runtime();
	user_access_restore(ua_flags);
}
EXPORT_SYMBOL(kmsan_unpoison_memory);

void kmsan_check_memory(const void *addr, size_t size)
{
	if (!kmsan_enabled)
		return;
	return kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
					   REASON_ANY);
}
EXPORT_SYMBOL(kmsan_check_memory);
