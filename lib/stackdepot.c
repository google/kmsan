// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic stack depot for storing stack traces.
 *
 * Some debugging tools need to save stack traces of certain events which can
 * be later presented to the user. For example, KASAN needs to safe alloc and
 * free stacks for each object, but storing two stack traces per object
 * requires too much memory (e.g. SLUB_DEBUG needs 256 bytes per object for
 * that).
 *
 * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
 * and free stacks repeat a lot, we save about 100x space.
 * Stacks are never removed from depot, so we store them contiguously one after
 * another in a contiguous memory allocation.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on code by Dmitry Chernenkov.
 */

#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/kasan-enabled.h>

#define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)

#define STACK_ALLOC_NULL_PROTECTION_BITS 1
#define STACK_ALLOC_ORDER 2 /* 'Slab' size order for stack depot, 4 pages */
#define STACK_ALLOC_SIZE (1LL << (PAGE_SHIFT + STACK_ALLOC_ORDER))
#define STACK_ALLOC_ALIGN 4
#define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
					STACK_ALLOC_ALIGN)
#define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
		STACK_ALLOC_NULL_PROTECTION_BITS - \
		STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
#define STACK_ALLOC_SLABS_CAP 8192
#define STACK_ALLOC_MAX_SLABS \
	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
	 (1LL << (STACK_ALLOC_INDEX_BITS)) : STACK_ALLOC_SLABS_CAP)

/* The compact structure to store the reference to stacks. */
union handle_parts {
	depot_stack_handle_t handle;
	struct {
		u32 slabindex : STACK_ALLOC_INDEX_BITS;
		u32 offset : STACK_ALLOC_OFFSET_BITS;
		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
		u32 extra : STACK_DEPOT_EXTRA_BITS;
	};
};

struct stack_record {
	struct stack_record *next;	/* Link in the hashtable */
	u32 hash;			/* Hash in the hastable */
	u32 size;			/* Number of frames in the stack */
	union handle_parts handle;
	unsigned long entries[];	/* Variable-sized array of entries. */
};

static bool __stack_depot_want_early_init __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
static bool __stack_depot_early_init_passed __initdata;

static void *stack_slabs[STACK_ALLOC_MAX_SLABS];

static int depot_index;
static int next_slab_inited;
static size_t depot_offset;
static DEFINE_RAW_SPINLOCK(depot_lock);

unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
{
	union handle_parts parts = { .handle = handle };

	return parts.extra;
}
EXPORT_SYMBOL(stack_depot_get_extra_bits);

static bool init_stack_slab(void **prealloc)
{
	if (!*prealloc)
		return false;
	/*
	 * This smp_load_acquire() pairs with smp_store_release() to
	 * |next_slab_inited| below and in depot_alloc_stack().
	 */
	if (smp_load_acquire(&next_slab_inited))
		return true;
	if (stack_slabs[depot_index] == NULL) {
		stack_slabs[depot_index] = *prealloc;
		*prealloc = NULL;
	} else {
		/* If this is the last depot slab, do not touch the next one. */
		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
			stack_slabs[depot_index + 1] = *prealloc;
			*prealloc = NULL;
		}
		/*
		 * This smp_store_release pairs with smp_load_acquire() from
		 * |next_slab_inited| above and in stack_depot_save().
		 */
		smp_store_release(&next_slab_inited, 1);
	}
	return true;
}

/* Allocation of a new stack in raw storage */
static struct stack_record *
depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
{
	struct stack_record *stack;
	size_t required_size = struct_size(stack, entries, size);

	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);

	if (unlikely(depot_offset + required_size > STACK_ALLOC_SIZE)) {
		if (unlikely(depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
			WARN_ONCE(1, "Stack depot reached limit capacity");
			return NULL;
		}
		depot_index++;
		depot_offset = 0;
		/*
		 * smp_store_release() here pairs with smp_load_acquire() from
		 * |next_slab_inited| in stack_depot_save() and
		 * init_stack_slab().
		 */
		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS)
			smp_store_release(&next_slab_inited, 0);
	}
	init_stack_slab(prealloc);
	if (stack_slabs[depot_index] == NULL)
		return NULL;

	stack = stack_slabs[depot_index] + depot_offset;

	stack->hash = hash;
	stack->size = size;
	stack->handle.slabindex = depot_index;
	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
	stack->handle.valid = 1;
	stack->handle.extra = 0;
	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
	depot_offset += required_size;

	return stack;
}

/* one hash table bucket entry per 16kB of memory */
#define STACK_HASH_SCALE	14
/* limited between 4k and 1M buckets */
#define STACK_HASH_ORDER_MIN	12
#define STACK_HASH_ORDER_MAX	20
#define STACK_HASH_SEED 0x9747b28c

static unsigned int stack_hash_order;
static unsigned int stack_hash_mask;

static bool stack_depot_disable;
static struct stack_record **stack_table;

static int __init is_stack_depot_disabled(char *str)
{
	int ret;

	ret = kstrtobool(str, &stack_depot_disable);
	if (!ret && stack_depot_disable) {
		pr_info("Stack Depot is disabled\n");
		stack_table = NULL;
	}
	return 0;
}
early_param("stack_depot_disable", is_stack_depot_disabled);

void __init stack_depot_want_early_init(void)
{
	/* Too late to request early init now */
	WARN_ON(__stack_depot_early_init_passed);

	__stack_depot_want_early_init = true;
}

int __init stack_depot_early_init(void)
{
	unsigned long entries = 0;

	/* This is supposed to be called only once, from mm_init() */
	if (WARN_ON(__stack_depot_early_init_passed))
		return 0;

	__stack_depot_early_init_passed = true;

	if (kasan_enabled() && !stack_hash_order)
		stack_hash_order = STACK_HASH_ORDER_MAX;

	if (!__stack_depot_want_early_init || stack_depot_disable)
		return 0;

	if (stack_hash_order)
		entries = 1UL <<  stack_hash_order;
	stack_table = alloc_large_system_hash("stackdepot",
						sizeof(struct stack_record *),
						entries,
						STACK_HASH_SCALE,
						HASH_EARLY | HASH_ZERO,
						NULL,
						&stack_hash_mask,
						1UL << STACK_HASH_ORDER_MIN,
						1UL << STACK_HASH_ORDER_MAX);

	if (!stack_table) {
		pr_err("Stack Depot hash table allocation failed, disabling\n");
		stack_depot_disable = true;
		return -ENOMEM;
	}

	return 0;
}

int stack_depot_init(void)
{
	static DEFINE_MUTEX(stack_depot_init_mutex);
	int ret = 0;

	mutex_lock(&stack_depot_init_mutex);
	if (!stack_depot_disable && !stack_table) {
		unsigned long entries;
		int scale = STACK_HASH_SCALE;

		if (stack_hash_order) {
			entries = 1UL << stack_hash_order;
		} else {
			entries = nr_free_buffer_pages();
			entries = roundup_pow_of_two(entries);

			if (scale > PAGE_SHIFT)
				entries >>= (scale - PAGE_SHIFT);
			else
				entries <<= (PAGE_SHIFT - scale);
		}

		if (entries < 1UL << STACK_HASH_ORDER_MIN)
			entries = 1UL << STACK_HASH_ORDER_MIN;
		if (entries > 1UL << STACK_HASH_ORDER_MAX)
			entries = 1UL << STACK_HASH_ORDER_MAX;

		pr_info("Stack Depot allocating hash table of %lu entries with kvcalloc\n",
				entries);
		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
		if (!stack_table) {
			pr_err("Stack Depot hash table allocation failed, disabling\n");
			stack_depot_disable = true;
			ret = -ENOMEM;
		}
		stack_hash_mask = entries - 1;
	}
	mutex_unlock(&stack_depot_init_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(stack_depot_init);

/* Calculate hash for a stack */
static inline u32 hash_stack(unsigned long *entries, unsigned int size)
{
	return jhash2((u32 *)entries,
		      array_size(size,  sizeof(*entries)) / sizeof(u32),
		      STACK_HASH_SEED);
}

/* Use our own, non-instrumented version of memcmp().
 *
 * We actually don't care about the order, just the equality.
 */
static inline
int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
			unsigned int n)
{
	for ( ; n-- ; u1++, u2++) {
		if (*u1 != *u2)
			return 1;
	}
	return 0;
}

/* Find a stack that is equal to the one stored in entries in the hash */
static inline struct stack_record *find_stack(struct stack_record *bucket,
					     unsigned long *entries, int size,
					     u32 hash)
{
	struct stack_record *found;

	for (found = bucket; found; found = found->next) {
		if (found->hash == hash &&
		    found->size == size &&
		    !stackdepot_memcmp(entries, found->entries, size))
			return found;
	}
	return NULL;
}

/**
 * stack_depot_snprint - print stack entries from a depot into a buffer
 *
 * @handle:	Stack depot handle which was returned from
 *		stack_depot_save().
 * @buf:	Pointer to the print buffer
 *
 * @size:	Size of the print buffer
 *
 * @spaces:	Number of leading spaces to print
 *
 * Return:	Number of bytes printed.
 */
int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
		       int spaces)
{
	unsigned long *entries;
	unsigned int nr_entries;

	nr_entries = stack_depot_fetch(handle, &entries);
	return nr_entries ? stack_trace_snprint(buf, size, entries, nr_entries,
						spaces) : 0;
}
EXPORT_SYMBOL_GPL(stack_depot_snprint);

/**
 * stack_depot_print - print stack entries from a depot
 *
 * @stack:		Stack depot handle which was returned from
 *			stack_depot_save().
 *
 */
void stack_depot_print(depot_stack_handle_t stack)
{
	unsigned long *entries;
	unsigned int nr_entries;

	nr_entries = stack_depot_fetch(stack, &entries);
	if (nr_entries > 0)
		stack_trace_print(entries, nr_entries, 0);
}
EXPORT_SYMBOL_GPL(stack_depot_print);

/**
 * stack_depot_fetch - Fetch stack entries from a depot
 *
 * @handle:		Stack depot handle which was returned from
 *			stack_depot_save().
 * @entries:		Pointer to store the entries address
 *
 * Return: The number of trace entries for this depot.
 */
unsigned int stack_depot_fetch(depot_stack_handle_t handle,
			       unsigned long **entries)
{
	union handle_parts parts = { .handle = handle };
	void *slab;
	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
	struct stack_record *stack;

	*entries = NULL;
	if (!handle)
		return 0;

	if (parts.slabindex > depot_index) {
		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
			parts.slabindex, depot_index, handle);
		return 0;
	}
	slab = stack_slabs[parts.slabindex];
	if (!slab)
		return 0;
	stack = slab + offset;

	*entries = stack->entries;
	return stack->size;
}
EXPORT_SYMBOL_GPL(stack_depot_fetch);

/**
 * __stack_depot_save - Save a stack trace from an array
 *
 * @entries:		Pointer to storage array
 * @nr_entries:		Size of the storage array
 * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
 * @alloc_flags:	Allocation gfp flags
 * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
 *
 * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
 * %true, is allowed to replenish the stack slab pool in case no space is left
 * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
 * any allocations and will fail if no space is left to store the stack trace.
 *
 * If the stack trace in @entries is from an interrupt, only the portion up to
 * interrupt entry is saved.
 *
 * Additional opaque flags can be passed in @extra_bits, stored in the unused
 * bits of the stack handle, and retrieved using stack_depot_get_extra_bits()
 * without calling stack_depot_fetch().
 *
 * Context: Any context, but setting @can_alloc to %false is required if
 *          alloc_pages() cannot be used from the current context. Currently
 *          this is the case from contexts where neither %GFP_ATOMIC nor
 *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
 *
 * Return: The handle of the stack struct stored in depot, 0 on failure.
 */
depot_stack_handle_t __stack_depot_save(unsigned long *entries,
					unsigned int nr_entries,
					unsigned int extra_bits,
					gfp_t alloc_flags, bool can_alloc)
{
	struct stack_record *found = NULL, **bucket;
	union handle_parts retval = { .handle = 0 };
	struct page *page = NULL;
	void *prealloc = NULL;
	unsigned long flags;
	u32 hash;

	/*
	 * If this stack trace is from an interrupt, including anything before
	 * interrupt entry usually leads to unbounded stackdepot growth.
	 *
	 * Because use of filter_irq_stacks() is a requirement to ensure
	 * stackdepot can efficiently deduplicate interrupt stacks, always
	 * filter_irq_stacks() to simplify all callers' use of stackdepot.
	 */
	nr_entries = filter_irq_stacks(entries, nr_entries);

	if (unlikely(nr_entries == 0) || stack_depot_disable)
		goto fast_exit;

	hash = hash_stack(entries, nr_entries);
	bucket = &stack_table[hash & stack_hash_mask];

	/*
	 * Fast path: look the stack trace up without locking.
	 * The smp_load_acquire() here pairs with smp_store_release() to
	 * |bucket| below.
	 */
	found = find_stack(smp_load_acquire(bucket), entries,
			   nr_entries, hash);
	if (found)
		goto exit;

	/*
	 * Check if the current or the next stack slab need to be initialized.
	 * If so, allocate the memory - we won't be able to do that under the
	 * lock.
	 *
	 * The smp_load_acquire() here pairs with smp_store_release() to
	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
	 */
	if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
		/*
		 * Zero out zone modifiers, as we don't have specific zone
		 * requirements. Keep the flags related to allocation in atomic
		 * contexts and I/O.
		 */
		alloc_flags &= ~GFP_ZONEMASK;
		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
		alloc_flags |= __GFP_NOWARN;
		page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);
		if (page)
			prealloc = page_address(page);
	}

	raw_spin_lock_irqsave(&depot_lock, flags);

	found = find_stack(*bucket, entries, nr_entries, hash);
	if (!found) {
		struct stack_record *new = depot_alloc_stack(entries, nr_entries, hash, &prealloc);

		if (new) {
			new->next = *bucket;
			/*
			 * This smp_store_release() pairs with
			 * smp_load_acquire() from |bucket| above.
			 */
			smp_store_release(bucket, new);
			found = new;
		}
	} else if (prealloc) {
		/*
		 * We didn't need to store this stack trace, but let's keep
		 * the preallocated memory for the future.
		 */
		WARN_ON(!init_stack_slab(&prealloc));
	}

	raw_spin_unlock_irqrestore(&depot_lock, flags);
exit:
	if (prealloc) {
		/* Nobody used this memory, ok to free it. */
		free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
	}
	if (found)
		retval.handle = found->handle.handle;
fast_exit:
	retval.extra = extra_bits;

	return retval.handle;
}
EXPORT_SYMBOL_GPL(__stack_depot_save);

/**
 * stack_depot_save - Save a stack trace from an array
 *
 * @entries:		Pointer to storage array
 * @nr_entries:		Size of the storage array
 * @alloc_flags:	Allocation gfp flags
 *
 * Context: Contexts where allocations via alloc_pages() are allowed.
 *          See __stack_depot_save() for more details.
 *
 * Return: The handle of the stack struct stored in depot, 0 on failure.
 */
depot_stack_handle_t stack_depot_save(unsigned long *entries,
				      unsigned int nr_entries,
				      gfp_t alloc_flags)
{
	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
}
EXPORT_SYMBOL_GPL(stack_depot_save);
