obj-y := core.o instrumentation.o init.o hooks.o report.o shadow.o annotations.o

KMSAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n

KMSAN_SANITIZE_kmsan_annotations.o := y

CC_FLAGS_KMSAN_RUNTIME := $(call cc-option, -fno-stack-protector)

# KMSAN runtime functions may enable UACCESS checks, so build them without
# stackprotector to avoid objtool warnings.
CFLAGS_annotations.o := $(CC_FLAGS_KMSAN_RUNTIME)
CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
CFLAGS_instrumentation.o := $(CC_FLAGS_KMSAN_RUNTIME)
CFLAGS_report.o := $(CC_FLAGS_KMSAN_RUNTIME)
CFLAGS_shadow.o := $(CC_FLAGS_KMSAN_RUNTIME)

obj-$(CONFIG_KMSAN_KUNIT_TEST) += kmsan_test.o
KMSAN_SANITIZE_kmsan_test.o := y
CFLAGS_kmsan_test.o += $(call cc-disable-warning, uninitialized)
