/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGE_64_H
#define _ASM_X86_PAGE_64_H

#include <asm/page_64_types.h>

#ifndef __ASSEMBLY__
#include <asm/alternative.h>

/* duplicated to the one in bootmem.h */
extern unsigned long max_pfn;
extern unsigned long phys_base;

extern unsigned long page_offset_base;
extern unsigned long vmalloc_base;
extern unsigned long vmemmap_base;

static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}

#ifdef CONFIG_DEBUG_VIRTUAL
extern unsigned long __phys_addr(unsigned long);
extern unsigned long __phys_addr_symbol(unsigned long);
#else
#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_symbol(x) \
	((unsigned long)(x) - __START_KERNEL_map + phys_base)
#endif

#define __phys_reloc_hide(x)	(x)

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)          ((pfn) < max_pfn)
#endif

void clear_page_orig(void *page);
void clear_page_rep(void *page);
void clear_page_erms(void *page);

// This is an assembly header, avoid including too much of kmsan.h
#ifdef CONFIG_KMSAN
void kmsan_clear_page(void *page_addr);
#endif
__no_sanitize_memory
static inline void clear_page(void *page)
{
#ifdef CONFIG_KMSAN
	// alternative_call_2() changes |page|.
	void *page_copy = page;
#endif
	alternative_call_2(clear_page_orig,
			   clear_page_rep, X86_FEATURE_REP_GOOD,
			   clear_page_erms, X86_FEATURE_ERMS,
			   "=D" (page),
			   "0" (page)
			   : "cc", "memory", "rax", "rcx");
#ifdef CONFIG_KMSAN
	// Clear KMSAN shadow for the pages that have it.
	kmsan_clear_page(page_copy);
#endif
}

void copy_page(void *to, void *from);

#endif	/* !__ASSEMBLY__ */

#ifdef CONFIG_X86_VSYSCALL_EMULATION
# define __HAVE_ARCH_GATE_AREA 1
#endif

#endif /* _ASM_X86_PAGE_64_H */
