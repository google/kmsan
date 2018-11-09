/*
 * KMSAN error reporting routines.
 *
 * Copyright (C) 2019 Google, Inc
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
	unsigned long nr_entries, chained_nr_entries;
	char *descr = NULL;
	void *pc1 = NULL, *pc2 = NULL;
	depot_stack_handle_t head;

	if (!origin) {
		kmsan_pr_err("Origin not found, presumably a false report.\n");
		return;
	}

	while (true) {
		nr_entries = stack_depot_fetch(origin, &entries);
		if ((nr_entries == 4) &&
		    ((entries[0] & KMSAN_MAGIC_MASK) == KMSAN_ALLOCA_MAGIC_ORIGIN)) {
			descr = (char *)entries[1];
			pc1 = (void *)entries[2];
			pc2 = (void *)entries[3];
			kmsan_pr_err("Local variable description: %s\n", descr);
			kmsan_pr_err("Variable was created at:\n");
			kmsan_pr_err(" %pS\n", pc1);
			kmsan_pr_err(" %pS\n", pc2);
			break;
		}
		if (nr_entries == 3) {
			if ((entries[0] & KMSAN_MAGIC_MASK) == KMSAN_CHAIN_MAGIC_ORIGIN_FULL) {
				head = entries[1];
				origin = entries[2];
				kmsan_pr_err("Uninit was stored to memory at:\n");
				chained_nr_entries = stack_depot_fetch(head, &chained_entries);
				stack_trace_print(chained_entries, chained_nr_entries, 0);
				kmsan_pr_err("\n");
				continue;
			}
		}
		kmsan_pr_err("Uninit was created at:\n");
		if (entries)
			stack_trace_print(entries, nr_entries, 0);
		else
			kmsan_pr_err("No stack\n");
		break;
	}
}

/*
 * TODO(glider): |deep| is a dirty hack to skip an additional frame when
 * calling kmsan_report() from kmsan_copy_to_user().
 */
void kmsan_report(depot_stack_handle_t origin,
		  void *address, int size, int off_first, int off_last,
		  const void *user_addr, bool deep, int reason)
{
	unsigned long flags;
	unsigned long *entries;
	unsigned int nr_entries;

	if (!kmsan_ready)
		return;
	if (!current->kmsan.allow_reporting)
		return;
	if (is_console_locked() || is_logbuf_locked())
		return;

	/* TODO(glider): temporarily disabling reports without origins. */
	if (!origin)
		return;

	nr_entries = stack_depot_fetch(origin, &entries);

	/* TODO(glider) */
	current->kmsan.allow_reporting = false;
	current->kmsan.is_reporting = true;
	spin_lock_irqsave(&report_lock, flags);
	kmsan_pr_err("==================================================================\n");
	/* TODO(glider): inline this properly */
	switch (reason) {
		case REASON_ANY:
			kmsan_pr_err("BUG: KMSAN: uninit-value in %pS\n", deep ? kmsan_internal_return_address(2) : kmsan_internal_return_address(1));
			break;
		case REASON_COPY_TO_USER:
			kmsan_pr_err("BUG: KMSAN: kernel-infoleak in %pS\n", deep ? kmsan_internal_return_address(2) : kmsan_internal_return_address(1));
			break;
		case REASON_SUBMIT_URB:
			kmsan_pr_err("BUG: KMSAN: kernel-usb-infoleak in %pS\n", deep ? kmsan_internal_return_address(2) : kmsan_internal_return_address(1));
			break;
	}
	dump_stack();
	kmsan_pr_err("\n");

	kmsan_print_origin(origin);

	if (size) {
		kmsan_pr_err("\n");
		if (off_first == off_last)
			kmsan_pr_err("Byte %d of %d is uninitialized\n", off_first, size);
		else
			kmsan_pr_err("Bytes %d-%d of %d are uninitialized\n", off_first, off_last, size);
	}
	if (address)
		kmsan_pr_err("Memory access of size %d starts at %px\n", size, address);
	if (user_addr && reason == REASON_COPY_TO_USER)
		kmsan_pr_err("Data copied to user address %px\n", user_addr);
	kmsan_pr_err("==================================================================\n");
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&report_lock, flags);
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");
	current->kmsan.is_reporting = false;
	current->kmsan.allow_reporting = true;
}


