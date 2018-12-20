/*
 * Module for testing KMSAN.
 *
 * Copyright (C) 2017 Google, Inc
 * Author: Alexander Potapenko <glider@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#define pr_fmt(fmt) "kmsan test: %s : " fmt, __func__

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kmsan-checks.h>

#define CHECK(x)					\
	do {						\
		if (x) 					\
			pr_info(#x " is true\n");	\
		else					\
			pr_info(#x " is false\n");	\
	} while(0)

void noinline use_integer(int cond)
{
	CHECK(cond);
}

int signed_sum3(int a, int b, int c)
{
	return a + b + c;
}

void noinline uninit_kmalloc_test(void)
{
	int *ptr;

	pr_info("-----------------------------\n");
	pr_info("uninitialized kmalloc test (UMR report)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	pr_info("kmalloc returned %p\n", ptr);
	CHECK(*ptr);
}
void noinline init_kmalloc_test(void)
{
	int *ptr;

	pr_info("-----------------------------\n");
	pr_info("initialized kmalloc test (no reports)\n");
	ptr = kmalloc(sizeof(int), GFP_KERNEL);
	memset(ptr, 0, sizeof(int));
	pr_info("kmalloc returned %p\n", ptr);
	CHECK(*ptr);
}

void noinline init_kzalloc_test(void)
{
	int *ptr;

	pr_info("-----------------------------\n");
	pr_info("initialized kzalloc test (no reports)\n");
	ptr = kzalloc(sizeof(int), GFP_KERNEL);
	pr_info("kzalloc returned %p\n", ptr);
	CHECK(*ptr);
}

void noinline uninit_multiple_args_test(void)
{
	volatile int a;
	volatile char b = 3, c;
	CHECK(signed_sum3(a, b, c));
}

extern void *my_kmsan_get_shadow_address_1(void *addr);
void noinline uninit_stack_var_test(void)
{
	int cond;
	pr_err("uninit_stack_var_test: %p\n", uninit_stack_var_test);
	pr_err("&cond: %p\n", (void*)&cond);

	pr_info("-----------------------------\n");
	pr_info("uninitialized stack variable (UMR report)\n");
	CHECK(cond);
}

void noinline init_stack_var_test(void)
{
	volatile int cond = 1;

	pr_info("-----------------------------\n");
	pr_info("initialized stack variable (no reports)\n");
	CHECK(cond);
}

void noinline two_param_fn_2(int arg1, int arg2)
{
	CHECK(arg1);
	CHECK(arg2);
}

void noinline one_param_fn(int arg)
{
	two_param_fn_2(arg, arg);
	CHECK(arg);
}

void noinline two_param_fn(int arg1, int arg2)
{
	int init = 0;
	one_param_fn(init);
	CHECK(arg1);
	CHECK(arg2);
}

void params_test(void)
{
	int uninit, init = 1;
	two_param_fn(uninit, init);
}

void noinline do_uninit_local_array(char *array, int start, int stop)
{
	int i;
	volatile char uninit;
	for (i = start; i < stop; i++)
		array[i] = uninit;
}

void noinline uninit_kmsan_check_memory_test(void)
{
	volatile char local_array[8];

	pr_info("-----------------------------\n");
	pr_info("uninitialized stack local checked with kmsan_check_memory()\n");
	do_uninit_local_array((char*)local_array, 5, 7);

	kmsan_check_memory((char*)local_array, 8);
}

void noinline init_kmsan_vmap_vunmap_test(void)
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

void noinline init_vmalloc(void)
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

static noinline int __init kmsan_tests_init(void)
{
	uninit_kmalloc_test();
	init_kmalloc_test();
	init_kzalloc_test();
	uninit_multiple_args_test();
	uninit_stack_var_test();
	init_stack_var_test();
	uninit_kmsan_check_memory_test();
	init_kmsan_vmap_vunmap_test();
	init_vmalloc();
	return -EAGAIN;
}

module_init(kmsan_tests_init);
MODULE_LICENSE("GPL");
