#include <linux/export.h>
#include <linux/kmsan-checks.h>


#define DECLARE_KMSAN_INIT(size, t)	\
__no_sanitize_memory			\
t kmsan_init_##size(t value)	\
{					\
	return value;			\
}					\
EXPORT_SYMBOL(kmsan_init_##size) /* */

DECLARE_KMSAN_INIT(1, u8);
DECLARE_KMSAN_INIT(2, u16);
DECLARE_KMSAN_INIT(4, u32);
DECLARE_KMSAN_INIT(8, u64);
