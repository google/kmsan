// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN error reporting routines.
 *
 * Copyright (C) 2019-2021 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#include <linux/console.h>
#include <linux/moduleparam.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>

#include "kmsan.h"

DEFINE_SPINLOCK(kmsan_report_lock);
int panic_on_kmsan __read_mostly;
core_param(panic_on_kmsan, panic_on_kmsan, int, 0644);

/*
 * Skip internal KMSAN frames.
 */
static int get_stack_skipnr(const unsigned long stack_entries[],
			    int num_entries)
{
	int len, skip;
	char buf[64];

	for (skip = 0; skip < num_entries; ++skip) {
		len = scnprintf(buf, sizeof(buf), "%ps",
				(void *)stack_entries[skip]);

		/* Never show __msan_* or kmsan_* functions. */
		if ((strnstr(buf, "__msan_", len) == buf) ||
		    (strnstr(buf, "kmsan_", len) == buf))
			continue;

		/*
		 * No match for runtime functions -- @skip entries to skip to
		 * get to first frame of interest.
		 */
		break;
	}

	return skip;
}

void kmsan_print_origin(depot_stack_handle_t origin)
{
	unsigned long *entries = NULL, *chained_entries = NULL;
	unsigned int nr_entries, chained_nr_entries, skipnr;
	void *pc1 = NULL, *pc2 = NULL;
	depot_stack_handle_t head;
	unsigned long magic;
	char *descr = NULL;

	if (!origin)
		return;

	while (true) {
		nr_entries = stack_depot_fetch(origin, &entries);
		magic = nr_entries ? entries[0] : 0;
		if ((nr_entries == 4) && (magic == KMSAN_ALLOCA_MAGIC_ORIGIN)) {
			descr = (char *)entries[1];
			pc1 = (void *)entries[2];
			pc2 = (void *)entries[3];
			pr_err("Local variable %s created at:\n", descr);
			if (pc1)
				pr_err(" %pS\n", pc1);
			if (pc2)
				pr_err(" %pS\n", pc2);
			break;
		}
		if ((nr_entries == 3) && (magic == KMSAN_CHAIN_MAGIC_ORIGIN)) {
			head = entries[1];
			origin = entries[2];
			pr_err("Uninit was stored to memory at:\n");
			chained_nr_entries =
				stack_depot_fetch(head, &chained_entries);
			kmsan_internal_unpoison_memory(
				chained_entries,
				chained_nr_entries * sizeof(*chained_entries),
				/*checked*/ false);
			skipnr = get_stack_skipnr(chained_entries,
						  chained_nr_entries);
			stack_trace_print(chained_entries + skipnr,
					  chained_nr_entries - skipnr, 0);
			pr_err("\n");
			continue;
		}
		pr_err("Uninit was created at:\n");
		if (nr_entries) {
			skipnr = get_stack_skipnr(entries, nr_entries);
			stack_trace_print(entries + skipnr, nr_entries - skipnr,
					  0);
		} else {
			pr_err("(stack is not available)\n");
		}
		break;
	}
}

/**
 * kmsan_report() - Report a use of uninitialized value.
 * @origin:    Stack ID of the uninitialized value.
 * @address:   Address at which the memory access happens.
 * @size:      Memory access size.
 * @off_first: Offset (from @address) of the first byte to be reported.
 * @off_last:  Offset (from @address) of the last byte to be reported.
 * @user_addr: When non-NULL, denotes the userspace address to which the kernel
 *             is leaking data.
 * @reason:    Error type from enum kmsan_bug_reason.
 *
 * kmsan_report() prints an error message for a consequent group of bytes
 * sharing the same origin. If an uninitialized value is used in a comparison,
 * this function is called once without specifying the addresses. When checking
 * a memory range, KMSAN may call kmsan_report() multiple times with the same
 * @address, @size, @user_addr and @reason, but different @off_first and
 * @off_last corresponding to different @origin values.
 */
void kmsan_report(depot_stack_handle_t origin, void *address, int size,
		  int off_first, int off_last, const void *user_addr,
		  enum kmsan_bug_reason reason)
{
	unsigned long stack_entries[KMSAN_STACK_DEPTH] = { 0 };
	int num_stack_entries, skipnr;
	char *bug_type = NULL;
	unsigned long flags;
	bool is_uaf;

	if (!kmsan_ready)
		return;
	if (!current->kmsan.allow_reporting)
		return;
	if (!origin)
		return;

	current->kmsan.allow_reporting = false;
	spin_lock_irqsave(&kmsan_report_lock, flags);
	pr_err("=====================================================\n");
	is_uaf = kmsan_uaf_from_eb(stack_depot_get_extra_bits(origin));
	switch (reason) {
	case REASON_ANY:
		bug_type = is_uaf ? "use-after-free" : "uninit-value";
		break;
	case REASON_COPY_TO_USER:
		bug_type = is_uaf ? "kernel-infoleak-after-free" :
					  "kernel-infoleak";
		break;
	case REASON_SUBMIT_URB:
		bug_type = is_uaf ? "kernel-usb-infoleak-after-free" :
					  "kernel-usb-infoleak";
		break;
	}

	num_stack_entries =
		stack_trace_save(stack_entries, KMSAN_STACK_DEPTH, 1);
	skipnr = get_stack_skipnr(stack_entries, num_stack_entries);

	pr_err("BUG: KMSAN: %s in %pS\n", bug_type, stack_entries[skipnr]);
	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
			  0);
	pr_err("\n");

	kmsan_print_origin(origin);

	if (size) {
		pr_err("\n");
		if (off_first == off_last)
			pr_err("Byte %d of %d is uninitialized\n", off_first,
			       size);
		else
			pr_err("Bytes %d-%d of %d are uninitialized\n",
			       off_first, off_last, size);
	}
	if (address)
		pr_err("Memory access of size %d starts at %px\n", size,
		       address);
	if (user_addr && reason == REASON_COPY_TO_USER)
		pr_err("Data copied to user address %px\n", user_addr);
	pr_err("=====================================================\n");
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&kmsan_report_lock, flags);
	if (panic_on_kmsan)
		panic("panic_on_kmsan set ...\n");
	current->kmsan.allow_reporting = true;
}
