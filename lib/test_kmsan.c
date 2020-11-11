// SPDX-License-Identifier: GPL-2.0
/*
 * Module for testing KMSAN.
 *
 * Copyright (C) 2017-2020 Google LLC
 * Author: Alexander Potapenko <glider@google.com>
 *
 */

/*
 * Tests below use noinline and volatile to work around compiler optimizations
 * that may mask KMSAN bugs.
 */
#define pr_fmt(fmt) "kmsan test: %s : " fmt, __func__

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kmsan-checks.h>

#define CHECK(x)					\
	do {						\
		if (x)					\
			pr_info(#x " is true\n");	\
		else					\
			pr_info(#x " is false\n");	\
	} while (0)

int signed_sum3(int a, int b, int c)
{
	return a + b + c;
}

noinline void uninit_kmalloc_test(void)
{
	int *ptr;

	pr_info("-----------------------------\n");
	pr_info("uninitialized kmalloc test (UMR report)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	pr_info("kmalloc returned %p\n", ptr);
	CHECK(*ptr);
}
noinline void init_kmalloc_test(void)
{
	int *ptr;

	pr_info("-----------------------------\n");
	pr_info("initialized kmalloc test (no reports)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	memset(ptr, 0, sizeof(int));
	pr_info("kmalloc returned %p\n", ptr);
	CHECK(*ptr);
}

noinline void init_kzalloc_test(void)
{
	int *ptr;

	pr_info("-----------------------------\n");
	pr_info("initialized kzalloc test (no reports)\n");
	ptr = kzalloc(sizeof(int), GFP_KERNEL);
	pr_info("kzalloc returned %p\n", ptr);
	CHECK(*ptr);
}

noinline void uninit_multiple_args_test(void)
{
	volatile int a;
	volatile char b = 3, c;

	pr_info("-----------------------------\n");
	pr_info("uninitialized local passed to fn (UMR report)\n");
	CHECK(signed_sum3(a, b, c));
}

noinline void uninit_stack_var_test(void)
{
	int cond;

	pr_info("-----------------------------\n");
	pr_info("uninitialized stack variable (UMR report)\n");
	CHECK(cond);
}

noinline void init_stack_var_test(void)
{
	volatile int cond = 1;

	pr_info("-----------------------------\n");
	pr_info("initialized stack variable (no reports)\n");
	CHECK(cond);
}

noinline void two_param_fn_2(int arg1, int arg2)
{
	CHECK(arg1);
	CHECK(arg2);
}

noinline void one_param_fn(int arg)
{
	two_param_fn_2(arg, arg);
	CHECK(arg);
}

noinline void two_param_fn(int arg1, int arg2)
{
	int init = 0;

	one_param_fn(init);
	CHECK(arg1);
	CHECK(arg2);
}

noinline void params_test(void)
{
	volatile int uninit, init = 1;

	pr_info("-----------------------------\n");
	pr_info("uninit passed through a function parameter (UMR report)\n");
	two_param_fn(uninit, init);
}

noinline void do_uninit_local_array(char *array, int start, int stop)
{
	int i;
	volatile char uninit;

	for (i = start; i < stop; i++)
		array[i] = uninit;
}

noinline void uninit_kmsan_check_memory_test(void)
{
	volatile char local_array[8];

	pr_info("-----------------------------\n");
	pr_info("kmsan_check_memory() called on uninit local (UMR report)\n");
	do_uninit_local_array((char *)local_array, 5, 7);

	kmsan_check_memory((char *)local_array, 8);
}

noinline void init_kmsan_vmap_vunmap_test(void)
{
	const int npages = 2;
	struct page *pages[npages];
	void *vbuf;
	int i;

	pr_info("-----------------------------\n");
	pr_info("pages initialized via vmap (no reports)\n");

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
}

noinline void init_vmalloc_test(void)
{
	char *buf;
	int npages = 8, i;

	pr_info("-----------------------------\n");
	pr_info("pages initialized via vmap (no reports)\n");
	buf = vmalloc(PAGE_SIZE * npages);
	buf[0] = 1;
	memset(buf, 0xfe, PAGE_SIZE * npages);
	CHECK(buf[0]);
	for (i = 0; i < npages; i++)
		kmsan_check_memory(&buf[PAGE_SIZE * i], PAGE_SIZE);
	vfree(buf);
}

noinline void uaf_test(void)
{
	volatile int *var;

	pr_info("-----------------------------\n");
	pr_info("use-after-free in kmalloc-ed buffer (UMR report)\n");
	var = kmalloc(80, GFP_KERNEL);
	var[3] = 0xfeedface;
	kfree((int *)var);
	CHECK(var[3]);
}

noinline void printk_test(void)
{
	volatile int uninit;

	pr_info("-----------------------------\n");
	pr_info("uninit local passed to pr_info() (UMR report)\n");
	pr_info("%px contains %d\n", &uninit, uninit);
}

static noinline int __init kmsan_tests_init(void)
{
	uninit_kmalloc_test();
	init_kmalloc_test();
	init_kzalloc_test();
	uninit_multiple_args_test();
	uninit_stack_var_test();
	init_stack_var_test();
	params_test();
	uninit_kmsan_check_memory_test();
	init_kmsan_vmap_vunmap_test();
	init_vmalloc_test();
	uaf_test();
	printk_test();
	return -EAGAIN;
}

module_init(kmsan_tests_init);
MODULE_LICENSE("GPL");
