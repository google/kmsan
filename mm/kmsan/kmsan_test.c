// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for KMSAN.
 * For each test case checks the presence (or absence) of generated reports.
 * Relies on 'console' tracepoint to capture reports as they appear in the
 * kernel log.
 * Vastly borrowed from KFENCE
 *
 * Copyright (C) 2021, Google LLC.
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

#include <kunit/test.h>
#include "kmsan.h"

#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kmsan.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <trace/events/printk.h>


/* Report as observed from console. */
static struct {
	spinlock_t lock;
	int nlines;
	char lines[1][256];
	bool ignore;
} observed = {
	.lock = __SPIN_LOCK_UNLOCKED(observed.lock),
};

/* Probe for console output: obtains observed lines of interest. */
static void probe_console(void *ignore, const char *buf, size_t len)
{
	unsigned long flags;
	int nlines;

	if (observed.ignore)
		return;
	spin_lock_irqsave(&observed.lock, flags);
	nlines = observed.nlines;

	if (strnstr(buf, "BUG: KMSAN: ", len) && strnstr(buf, "test_", len)) {
		/*
		 * KMSAN report and related to the test.
		 *
		 * The provided @buf is not NUL-terminated; copy no more than
		 * @len bytes and let strscpy() add the missing NUL-terminator.
		 */
		strscpy(observed.lines[0], buf, min(len + 1, sizeof(observed.lines[0])));
		nlines = 1;
	}

	WRITE_ONCE(observed.nlines, nlines); /* Publish new nlines. */
	spin_unlock_irqrestore(&observed.lock, flags);
}

/* Check if a report related to the test exists. */
static bool report_available(void)
{
	return READ_ONCE(observed.nlines) == ARRAY_SIZE(observed.lines);
}

/* Information we expect in a report. */
struct expect_report {
	enum kmsan_bug_reason reason; /* Error type. */
	void *fn; /* Function pointer to expected function where access occurred. */
};

/* Check observed report matches information in @r. */
static bool report_matches(const struct expect_report *r)
{
	bool ret = false;
	unsigned long flags;
	typeof(observed.lines) expect;
	const char *end;
	char *cur;

	observed.ignore = true;
	/* Doubled-checked locking. */
	if (!report_available())
		return false;

	/* Generate expected report contents. */

	/* Title */
	cur = expect[0];
	end = &expect[0][sizeof(expect[0]) - 1];

	switch (r->reason) {
	case REASON_ANY:
		cur += scnprintf(cur, end - cur, "BUG: KMSAN: uninit-value");
		break;
	case REASON_COPY_TO_USER:
		cur += scnprintf(cur, end - cur, "BUG: KMSAN: kernel-infoleak");
		break;
	case REASON_SUBMIT_URB:
		break;
	}

	scnprintf(cur, end - cur, " in %pS", r->fn);
	/* The exact offset won't match, remove it; also strip module name. */
	cur = strchr(expect[0], '+');
	if (cur)
		*cur = '\0';

	spin_lock_irqsave(&observed.lock, flags);
	if (!report_available())
		goto out; /* A new report is being captured. */

	/* Finally match expected output to what we actually observed. */
	ret = strstr(observed.lines[0], expect[0]);
out:
	spin_unlock_irqrestore(&observed.lock, flags);

	return ret;
}

/* ===== Test cases ===== */

// Prevent replacing branch with select in LLVM.
noinline void check_true(char *arg) {
	pr_info("%s is true\n", arg);
}

noinline void check_false(char *arg) {
	pr_info("%s is false\n", arg);
}

#define CHECK(x)				\
	do {					\
		if (x)				\
			check_true(#x);		\
		else				\
			check_false(#x);	\
	} while (0)

static void test_uninit_kmalloc(struct kunit *test)
{
	int *ptr;
	struct expect_report expect = {
		.reason = REASON_ANY,
		.fn = test_uninit_kmalloc,
	};


	pr_info("-----------------------------\n");
	pr_info("uninitialized kmalloc test (UMR report)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	pr_info("kmalloc returned %p\n", ptr);
	CHECK(*ptr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static struct kunit_case kmsan_test_cases[] = {
	KUNIT_CASE(test_uninit_kmalloc),
	{},
};

/* ===== End test cases ===== */

static int test_init(struct kunit *test)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&observed.lock, flags);
	for (i = 0; i < ARRAY_SIZE(observed.lines); i++)
		observed.lines[i][0] = '\0';
	observed.nlines = 0;
	observed.ignore = false;
	spin_unlock_irqrestore(&observed.lock, flags);

	return 0;
}

static void test_exit(struct kunit *test)
{
}

static struct kunit_suite kmsan_test_suite = {
	.name = "kmsan",
	.test_cases = kmsan_test_cases,
	.init = test_init,
	.exit = test_exit,
};
static struct kunit_suite *kmsan_test_suites[] = { &kmsan_test_suite, NULL };

static void register_tracepoints(struct tracepoint *tp, void *ignore)
{
	check_trace_callback_type_console(probe_console);
	if (!strcmp(tp->name, "console"))
		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
}

static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
{
	if (!strcmp(tp->name, "console"))
		tracepoint_probe_unregister(tp, probe_console, NULL);
}

/*
 * We only want to do tracepoints setup and teardown once, therefore we have to
 * customize the init and exit functions and cannot rely on kunit_test_suite().
 */
static int __init kmsan_test_init(void)
{
	/*
	 * Because we want to be able to build the test as a module, we need to
	 * iterate through all known tracepoints, since the static registration
	 * won't work here.
	 */
	for_each_kernel_tracepoint(register_tracepoints, NULL);
	return __kunit_test_suites_init(kmsan_test_suites);
}

static void kmsan_test_exit(void)
{
	__kunit_test_suites_exit(kmsan_test_suites);
	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
	tracepoint_synchronize_unregister();
}

late_initcall(kmsan_test_init);
module_exit(kmsan_test_exit);

MODULE_LICENSE("GPL v2"); // TODO
MODULE_AUTHOR("Alexander Potapenko <glider@google.com>");
