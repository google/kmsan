#ifndef _LINUX_KMSAN_CHECKS_H
#define _LINUX_KMSAN_CHECKS_H
#include <linux/types.h>

void kmsan_enter_runtime(unsigned long *flags);
void kmsan_leave_runtime(unsigned long *flags);

#define KMSAN_DISABLE(flags) \
	do {	\
		kmsan_enter_runtime(&(flags));	\
	} while(0)
#define KMSAN_ENABLE(flags) \
	do {	\
		kmsan_leave_runtime(&(flags));	\
	} while(0)

#ifdef CONFIG_KMSAN
void kmsan_poison_shadow(void *address, size_t size, gfp_t flags);
void kmsan_unpoison_shadow(void *address, size_t size);
void kmsan_check_memory(const void *address, size_t size);
void *__msan_memcpy(void *dst, const void *src, u64 n);

#else
void kmsan_poison_shadow(void *address, size_t size, gfp_t flags) {}
void kmsan_unpoison_shadow(void *address, size_t size) {}
void kmsan_check_memory(const void *address, size_t size) {}
void *__msan_memcpy(void *dst, const void *src, u64 n) {}
#endif

#endif /* _LINUX_KMSAN_CHECKS_H */
