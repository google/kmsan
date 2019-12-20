obj-y := kmsan.o kmsan_instr.o kmsan_init.o kmsan_hooks.o kmsan_report.o kmsan_shadow.o

# KMSAN runtime functions may enable UACCESS checks, so build them without
# stackprotector to avoid objtool warnings.
CFLAGS_kmsan_instr.o := $(call cc-option, -fno-stack-protector)
CFLAGS_kmsan_shadow.o := $(call cc-option, -fno-stack-protector)
CFLAGS_kmsan_hooks.o := $(call cc-option, -fno-stack-protector)

KMSAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n
