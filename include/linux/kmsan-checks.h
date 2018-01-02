#ifndef _LINUX_KMSAN_CHECKS_H
#define _LINUX_KMSAN_CHECKS_H
#include <linux/types.h>


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
void kmsan_copy_to_user(const void *to, const void *from, size_t to_copy, size_t left);
void *__msan_memcpy(void *dst, const void *src, u64 n);
void kmsan_enter_runtime(unsigned long *flags);
void kmsan_leave_runtime(unsigned long *flags);
void kmsan_csum_partial_copy_generic(const void *src, const void *dst,
		size_t len);

#else
static inline void kmsan_poison_shadow(void *address, size_t size, gfp_t flags) {}
static inline void kmsan_unpoison_shadow(void *address, size_t size) {}
static inline void kmsan_check_memory(const void *address, size_t size) {}
static inline void kmsan_copy_to_user(
	const void *to, const void *from, size_t to_copy, size_t left) {}
static inline void *__msan_memcpy(void *dst, const void *src, u64 n)
{
	return NULL;
}

static inline void kmsan_enter_runtime(unsigned long *flags) {}
static inline void kmsan_leave_runtime(unsigned long *flags) {}
static void kmsan_csum_partial_copy_generic(const void *src, const void *dst,
						size_t len) {}

#endif

#endif /* _LINUX_KMSAN_CHECKS_H */
