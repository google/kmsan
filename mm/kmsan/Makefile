obj-y := core.o instrumentation.o init.o hooks.o report.o shadow.o annotations.o

KMSAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n

KMSAN_SANITIZE_kmsan_annotations.o := y

# KMSAN runtime functions may enable UACCESS checks, so build them without
# stackprotector to avoid objtool warnings.
CFLAGS_kmsan_instr.o := $(call cc-option, -fno-stack-protector)
CFLAGS_kmsan_shadow.o := $(call cc-option, -fno-stack-protector)
CFLAGS_hooks.o := $(call cc-option, -fno-stack-protector)

obj-$(CONFIG_KMSAN_KUNIT_TEST) += kmsan_test.o
KMSAN_SANITIZE_kmsan_test.o := y
CFLAGS_kmsan_test.o += $(call cc-disable-warning, uninitialized)
