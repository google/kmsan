// SPDX-License-Identifier: GPL-2.0
/*
 * KMSAN error reporting routines.
 *
 * Copyright (C) 2019 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/console.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>

#include "kmsan.h"

DEFINE_SPINLOCK(report_lock);

void kmsan_print_origin(depot_stack_handle_t origin)
{
	unsigned long *entries = NULL, *chained_entries = NULL;
	unsigned long nr_entries, chained_nr_entries, magic;
	char *descr = NULL;
	void *pc1 = NULL, *pc2 = NULL;
	depot_stack_handle_t head;

	if (!origin)
		return;

	while (true) {
		nr_entries = stack_depot_fetch(origin, &entries);
		magic = nr_entries ? (entries[0] & KMSAN_MAGIC_MASK) : 0;
		if ((nr_entries == 4) && (magic == KMSAN_ALLOCA_MAGIC_ORIGIN)) {
			descr = (char *)entries[1];
			pc1 = (void *)entries[2];
			pc2 = (void *)entries[3];
			pr_err("Local variable %s created at:\n", descr);
			pr_err(" %pS\n", pc1);
			pr_err(" %pS\n", pc2);
			break;
		}
		if ((nr_entries == 3) &&
		    (magic == KMSAN_CHAIN_MAGIC_ORIGIN_FULL)) {
			head = entries[1];
			origin = entries[2];
			pr_err("Uninit was stored to memory at:\n");
			chained_nr_entries =
				stack_depot_fetch(head, &chained_entries);
			kmsan_internal_unpoison_shadow(
				chained_entries,
				chained_nr_entries * sizeof(*chained_entries),
				/*checked*/ false);
			stack_trace_print(chained_entries, chained_nr_entries,
					  0);
			pr_err("\n");
			continue;
		}
		pr_err("Uninit was created at:\n");
		if (nr_entries)
			stack_trace_print(entries, nr_entries, 0);
		else
			pr_err("(stack is not available)\n");
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
 * @reason:    Error type from KMSAN_BUG_REASON enum.
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
		  int reason)
{
	unsigned long flags;
	bool is_uaf;
	char *bug_type = NULL;

	if (!kmsan_ready)
		return;
	if (!current->kmsan.allow_reporting)
		return;
	if (!origin)
		return;

	current->kmsan.allow_reporting = false;
	spin_lock_irqsave(&report_lock, flags);
	pr_err("=====================================================\n");
	is_uaf = kmsan_uaf_from_eb(get_dsh_extra_bits(origin));
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
	pr_err("BUG: KMSAN: %s in %pS\n", bug_type,
	       kmsan_internal_return_address(2));
	dump_stack();
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
	spin_unlock_irqrestore(&report_lock, flags);
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");
	current->kmsan.allow_reporting = true;
}
