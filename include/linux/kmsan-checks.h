#ifndef _LINUX_KMSAN_CHECKS_H
#define _LINUX_KMSAN_CHECKS_H

#include <linux/bug.h>
#include <linux/types.h>

struct i2c_msg;
struct sk_buff;
struct urb;

#define KMSAN_DISABLE(flags) \
	do {	\
		kmsan_enter_runtime(&(flags));	\
	} while(0)
#define KMSAN_ENABLE(flags) \
	do {	\
		kmsan_leave_runtime(&(flags));	\
	} while(0)

#ifdef CONFIG_KMSAN

// Helper functions that mark the return value initialized.
// Note that Clang ignores the inline attribute in the cases when a no_sanitize
// function is called from an instrumented one.

__no_sanitize_memory
static inline unsigned char KMSAN_INIT_1(unsigned char value) {
	return value;
}

__no_sanitize_memory
static inline unsigned short KMSAN_INIT_2(unsigned short value) {
	return value;
}

__no_sanitize_memory
static inline unsigned int KMSAN_INIT_4(unsigned int value) {
	return value;
}

__no_sanitize_memory
static inline unsigned long KMSAN_INIT_8(unsigned long value) {
	return value;
}

#define KMSAN_INIT_VALUE(val)		\
	({				\
		typeof(val) __ret;	\
		switch (sizeof(val)) {	\
		case 1:						\
			*(unsigned char *)&__ret = KMSAN_INIT_1(	\
					(unsigned char)val);	\
			break;					\
		case 2:						\
			*(unsigned short *)&__ret = KMSAN_INIT_2(	\
					(unsigned short)val);	\
			break;					\
		case 4:						\
			*(unsigned int *)&__ret = KMSAN_INIT_4(	\
					(unsigned int)val);	\
			break;					\
		case 8:						\
			*(unsigned long *)&__ret = KMSAN_INIT_8(	\
					(unsigned long)val);	\
			break;					\
		default:					\
			BUG();					\
		}						\
		__ret;						\
	}) /**/

void kmsan_poison_shadow(const volatile void *address, size_t size, gfp_t flags);
void kmsan_unpoison_shadow(const volatile void *address, size_t size);
void kmsan_check_memory(const volatile void *address, size_t size);
void kmsan_check_skb(const struct sk_buff *skb);
void kmsan_handle_urb(const struct urb *urb, bool is_out);
void kmsan_handle_i2c_transfer(struct i2c_msg *msgs, int num);
void kmsan_copy_to_user(const void *to, const void *from, size_t to_copy, size_t left);
void *__msan_memcpy(void *dst, const void *src, u64 n);
void kmsan_enter_runtime(unsigned long *flags);
void kmsan_leave_runtime(unsigned long *flags);

#else

#define KMSAN_INIT_VALUE(value) (value)

static inline void kmsan_poison_shadow(const volatile void *address, size_t size, gfp_t flags) {}
static inline void kmsan_unpoison_shadow(const volatile void *address, size_t size) {}
static inline void kmsan_check_memory(const volatile void *address, size_t size) {}
static inline void kmsan_check_skb(const struct sk_buff *skb) {}
static inline void kmsan_handle_urb(const struct urb *urb, bool is_out) {}
static inline void kmsan_handle_i2c_transfer(struct i2c_msg *msgs, int num) {}
static inline void kmsan_copy_to_user(
	const void *to, const void *from, size_t to_copy, size_t left) {}
static inline void *__msan_memcpy(void *dst, const void *src, size_t n)
{
	return NULL;
}

static inline void kmsan_enter_runtime(unsigned long *flags) {}
static inline void kmsan_leave_runtime(unsigned long *flags) {}

#endif

#endif /* _LINUX_KMSAN_CHECKS_H */
