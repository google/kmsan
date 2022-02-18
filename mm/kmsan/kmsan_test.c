// SPDX-License-Identifier: GPL-2.0
/*
 * Test cases for KMSAN.
 * For each test case checks the presence (or absence) of generated reports.
 * Relies on 'console' tracepoint to capture reports as they appear in the
 * kernel log.
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

static DEFINE_PER_CPU(int, per_cpu_var);

/* Report as observed from console. */
static struct {
	spinlock_t lock;
	bool available;
	bool ignore; /* Stop console output collection. */
	char header[256];
} observed = {
	.lock = __SPIN_LOCK_UNLOCKED(observed.lock),
};

/* Probe for console output: obtains observed lines of interest. */
static void probe_console(void *ignore, const char *buf, size_t len)
{
	unsigned long flags;

	if (observed.ignore)
		return;
	spin_lock_irqsave(&observed.lock, flags);

	if (strnstr(buf, "BUG: KMSAN: ", len)) {
		/*
		 * KMSAN report and related to the test.
		 *
		 * The provided @buf is not NUL-terminated; copy no more than
		 * @len bytes and let strscpy() add the missing NUL-terminator.
		 */
		strscpy(observed.header, buf,
			min(len + 1, sizeof(observed.header)));
		WRITE_ONCE(observed.available, true);
		observed.ignore = true;
	}
	spin_unlock_irqrestore(&observed.lock, flags);
}

/* Check if a report related to the test exists. */
static bool report_available(void)
{
	return READ_ONCE(observed.available);
}

/* Information we expect in a report. */
struct expect_report {
	const char *error_type; /* Error type. */
	/*
	 * Kernel symbol from the error header, or NULL if no report is
	 * expected.
	 */
	const char *symbol;
};

/* Check observed report matches information in @r. */
static bool report_matches(const struct expect_report *r)
{
	typeof(observed.header) expected_header;
	unsigned long flags;
	bool ret = false;
	const char *end;
	char *cur;

	/* Doubled-checked locking. */
	if (!report_available() || !r->symbol)
		return (!report_available() && !r->symbol);

	/* Generate expected report contents. */

	/* Title */
	cur = expected_header;
	end = &expected_header[sizeof(expected_header) - 1];

	cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);

	scnprintf(cur, end - cur, " in %s", r->symbol);
	/* The exact offset won't match, remove it; also strip module name. */
	cur = strchr(expected_header, '+');
	if (cur)
		*cur = '\0';

	spin_lock_irqsave(&observed.lock, flags);
	if (!report_available())
		goto out; /* A new report is being captured. */

	/* Finally match expected output to what we actually observed. */
	ret = strstr(observed.header, expected_header);
out:
	spin_unlock_irqrestore(&observed.lock, flags);

	return ret;
}

/* ===== Test cases ===== */

/* Prevent replacing branch with select in LLVM. */
static noinline void check_true(char *arg)
{
	pr_info("%s is true\n", arg);
}

static noinline void check_false(char *arg)
{
	pr_info("%s is false\n", arg);
}

#define USE(x)                                                                 \
	do {                                                                   \
		if (x)                                                         \
			check_true(#x);                                        \
		else                                                           \
			check_false(#x);                                       \
	} while (0)

#define EXPECTATION_ETYPE_FN(e, reason, fn)                                    \
	struct expect_report e = {                                             \
		.error_type = reason,                                          \
		.symbol = fn,                                                  \
	}

#define EXPECTATION_NO_REPORT(e) EXPECTATION_ETYPE_FN(e, NULL, NULL)
#define EXPECTATION_UNINIT_VALUE_FN(e, fn)                                     \
	EXPECTATION_ETYPE_FN(e, "uninit-value", fn)
#define EXPECTATION_UNINIT_VALUE(e) EXPECTATION_UNINIT_VALUE_FN(e, __func__)
#define EXPECTATION_USE_AFTER_FREE(e)                                          \
	EXPECTATION_ETYPE_FN(e, "use-after-free", __func__)

static int signed_sum3(int a, int b, int c)
{
	return a + b + c;
}

static void test_uninit_kmalloc(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE(expect);
	int *ptr;

	kunit_info(test, "uninitialized kmalloc test (UMR report)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	USE(*ptr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_init_kmalloc(struct kunit *test)
{
	EXPECTATION_NO_REPORT(expect);
	int *ptr;

	kunit_info(test, "initialized kmalloc test (no reports)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	memset(ptr, 0, sizeof(int));
	USE(*ptr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_init_kzalloc(struct kunit *test)
{
	EXPECTATION_NO_REPORT(expect);
	int *ptr;

	kunit_info(test, "initialized kzalloc test (no reports)\n");
	ptr = kzalloc(sizeof(int), GFP_KERNEL);
	USE(*ptr);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_uninit_multiple_args(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE(expect);
	volatile char b = 3, c;
	volatile int a;

	kunit_info(test, "uninitialized local passed to fn (UMR report)\n");
	USE(signed_sum3(a, b, c));
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_uninit_stack_var(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE(expect);
	volatile int cond;

	kunit_info(test, "uninitialized stack variable (UMR report)\n");
	USE(cond);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_init_stack_var(struct kunit *test)
{
	EXPECTATION_NO_REPORT(expect);
	volatile int cond = 1;

	kunit_info(test, "initialized stack variable (no reports)\n");
	USE(cond);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static noinline void two_param_fn_2(int arg1, int arg2)
{
	USE(arg1);
	USE(arg2);
}

static noinline void one_param_fn(int arg)
{
	two_param_fn_2(arg, arg);
	USE(arg);
}

static noinline void two_param_fn(int arg1, int arg2)
{
	int init = 0;

	one_param_fn(init);
	USE(arg1);
	USE(arg2);
}

static void test_params(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE_FN(expect, "two_param_fn");
	volatile int uninit, init = 1;

	kunit_info(test,
		   "uninit passed through a function parameter (UMR report)\n");
	two_param_fn(uninit, init);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static noinline void do_uninit_local_array(char *array, int start, int stop)
{
	volatile char uninit;
	int i;

	for (i = start; i < stop; i++)
		array[i] = uninit;
}

static void test_uninit_kmsan_check_memory(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE_FN(expect, "test_uninit_kmsan_check_memory");
	volatile char local_array[8];

	kunit_info(
		test,
		"kmsan_check_memory() called on uninit local (UMR report)\n");
	do_uninit_local_array((char *)local_array, 5, 7);

	kmsan_check_memory((char *)local_array, 8);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_init_kmsan_vmap_vunmap(struct kunit *test)
{
	EXPECTATION_NO_REPORT(expect);
	const int npages = 2;
	struct page **pages;
	void *vbuf;
	int i;

	kunit_info(test, "pages initialized via vmap (no reports)\n");

	pages = kmalloc_array(npages, sizeof(struct page), GFP_KERNEL);
	for (i = 0; i < npages; i++)
		pages[i] = alloc_page(GFP_KERNEL);
	vbuf = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
	memset(vbuf, 0xfe, npages * PAGE_SIZE);
	for (i = 0; i < npages; i++)
		kmsan_check_memory(page_address(pages[i]), PAGE_SIZE);

	if (vbuf)
		vunmap(vbuf);
	for (i = 0; i < npages; i++)
		if (pages[i])
			__free_page(pages[i]);
	kfree(pages);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_init_vmalloc(struct kunit *test)
{
	EXPECTATION_NO_REPORT(expect);
	int npages = 8, i;
	char *buf;

	kunit_info(test, "pages initialized via vmap (no reports)\n");
	buf = vmalloc(PAGE_SIZE * npages);
	buf[0] = 1;
	memset(buf, 0xfe, PAGE_SIZE * npages);
	USE(buf[0]);
	for (i = 0; i < npages; i++)
		kmsan_check_memory(&buf[PAGE_SIZE * i], PAGE_SIZE);
	vfree(buf);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_uaf(struct kunit *test)
{
	EXPECTATION_USE_AFTER_FREE(expect);
	volatile int value;
	volatile int *var;

	kunit_info(test, "use-after-free in kmalloc-ed buffer (UMR report)\n");
	var = kmalloc(80, GFP_KERNEL);
	var[3] = 0xfeedface;
	kfree((int *)var);
	/* Copy the invalid value before checking it. */
	value = var[3];
	USE(value);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_percpu_propagate(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE(expect);
	volatile int uninit, check;

	kunit_info(test,
		   "uninit local stored to per_cpu memory (UMR report)\n");

	this_cpu_write(per_cpu_var, uninit);
	check = this_cpu_read(per_cpu_var);
	USE(check);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static void test_printk(struct kunit *test)
{
	EXPECTATION_UNINIT_VALUE_FN(expect, "number");
	volatile int uninit;

	kunit_info(test, "uninit local passed to pr_info() (UMR report)\n");
	pr_info("%px contains %d\n", &uninit, uninit);
	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
}

static struct kunit_case kmsan_test_cases[] = {
	KUNIT_CASE(test_uninit_kmalloc),
	KUNIT_CASE(test_init_kmalloc),
	KUNIT_CASE(test_init_kzalloc),
	KUNIT_CASE(test_uninit_multiple_args),
	KUNIT_CASE(test_uninit_stack_var),
	KUNIT_CASE(test_init_stack_var),
	KUNIT_CASE(test_params),
	KUNIT_CASE(test_uninit_kmsan_check_memory),
	KUNIT_CASE(test_init_kmsan_vmap_vunmap),
	KUNIT_CASE(test_init_vmalloc),
	KUNIT_CASE(test_uaf),
	KUNIT_CASE(test_percpu_propagate),
	KUNIT_CASE(test_printk),
	{},
};

/* ===== End test cases ===== */

static int test_init(struct kunit *test)
{
	unsigned long flags;

	spin_lock_irqsave(&observed.lock, flags);
	observed.header[0] = '\0';
	observed.ignore = false;
	observed.available = false;
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

late_initcall_sync(kmsan_test_init);
module_exit(kmsan_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexander Potapenko <glider@google.com>");
