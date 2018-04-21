/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CONFIG_KMSAN
# ifdef CONFIG_X86_32
#  include <asm/checksum_32.h>
# else
#  include <asm/checksum_64.h>
# endif
#else
/*
 * KMSAN poorly understands assembly, so it uses generic functions.
 * TODO(dvyukov): properly support CONFIG_GENERIC_CSUM instead and
 * enable it for KMSAN and KASAN.
 */
# include <linux/types.h>
# include <asm-generic/checksum.h>
#endif
