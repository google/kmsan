#!/usr/bin/env python
from collections import defaultdict
import optparse
import os
import subprocess
import sys
import time

WORLD_PATH = os.path.dirname(os.path.abspath(__file__))

COMPILER_PATH = {'gcc': 'gcc',
    #'clang': WORLD_PATH + '/third_party/llvm-build/Release+Asserts/bin/clang'
    #'clang': '/home/glider/src/llvm/llvm/llvm_cmake_build/bin/clang',
    'clang': '/usr/local/google/src/llvm/llvm/llvm_cmake_build/bin/clang',
}

FILTER = {'gcc': ['-Qunused-arguments', '-no-integrated-as', '-mno-global-merge',
    '-Wdate-time', '-Wno-unknown-warning-option', '-Wno-initializer-overrides', '-Wno-tautological-compare',
    '-Wincompatible-pointer-types', '-Wno-gnu', '-Wno-format-invalid-specifier',
    '-Werror=date-time', '-Werror=incompatible-pointer-types',
],'clang': []}
SOURCE = 'source'
WRAPPER_LOG = WORLD_PATH + '/wrapper.log'
LOG = sys.stderr
LOG_OPTIONS = {'time': True, 'argv': True, 'kmsan_inst': True}

def compiler(flags):
    path = 'clang'
    #if SOURCE == 'security/selinux/hooks.c':
    #    return 'gcc'
    return path    # no need to use GCC for now
    if SOURCE in flags:
        source = flags[SOURCE]
        #print >>LOG, source
        # kernel/* ok
        # kernel/[st] broken
        # kernel/[kmpstuw] broken
        # kernel/[abckmpstuw] broken
        # kernel/[abcdefgkmpstuw] ok
        # kernel/[defgkmpstuw] ok
        # kernel/[defgkm] ok
        # kernel/[defg] ok
        # kernel/[de] broken
        # kernel/[fg] ok
        # kernel/[f] broken
        # kernel/[g] ok -- that's kernel/groups.h
        if source.startswith('kernel/'):
            pieces = source.split('/')
            if pieces[1][0] in ['g']:
                path = 'gcc'
        #print >>LOG, path
    return path

def filter_args(argv, cname):
    new_argv = []
    for arg in argv:
        if arg not in FILTER[cname]:
            new_argv.append(arg)
    return new_argv

def add_to_list(lst, prefix, files):
    for f in files:
        lst.append(prefix + f)

def setup_exact_blacklist():
    blacklist = []
    # Allocator code, stack depot.
    blacklist += ['mm/slab.c', 'mm/slub.c', 'mm/slab_common.c', 'lib/stackdepot.c']
    # Deadlocks because of recursion.
    blacklist += ['lib/vsprintf.c']
    # KMSAN itself.
    blacklist += ['mm/kmsan/kmsan.c', 'mm/kmsan/kmsan_init.c', 'mm/kmsan/kmsan_instr.c', 'mm/kmsan/kmsan_util.c']
    # Won't link.
    blacklist += ['arch/x86/boot/early_serial_console.c', 'arch/x86/boot/compressed/early_serial_console.c']
    blacklist += ['arch/x86/boot/compressed/error.c', 'arch/x86/boot/compressed/cmdline.c']
    blacklist += ['arch/x86/boot/compressed/string.c', 'arch/x86/boot/compressed/misc.c', 'arch/x86/boot/compressed/cpuflags.c']
    blacklist += ['arch/x86/entry/vdso/vgetcpu.c', 'arch/x86/entry/vdso/vclock_gettime.c']
    # unsupported option '-fsanitize=kernel-memory' for target 'i386-unknown-linux-code16'
    blacklist += ['arch/x86/boot/cpu.c', 'arch/x86/boot/cmdline.c', 'arch/x86/boot/edd.c', 'arch/x86/boot/cpuflags.c', 'arch/x86/boot/main.c']
    blacklist += ['arch/x86/boot/a20.c', 'arch/x86/boot/cpucheck.c', 'arch/x86/boot/printf.c', 'arch/x86/boot/memory.c', 'arch/x86/boot/video-bios.c']
    blacklist += ['arch/x86/boot/pm.c', 'arch/x86/boot/string.c', 'arch/x86/boot/version.c', 'arch/x86/boot/video.c', 'arch/x86/boot/video-vga.c']
    blacklist += ['arch/x86/boot/regs.c', 'arch/x86/boot/video-vesa.c', 'arch/x86/boot/tty.c', 'arch/x86/boot/video-mode.c']
    blacklist += ['arch/x86/realmode/rm/wakemain.c', 'arch/x86/realmode/rm/video-vga.c', 'arch/x86/realmode/rm/regs.c']
    blacklist += ['arch/x86/realmode/rm/video-bios.c', 'arch/x86/realmode/rm/video-mode.c', 'arch/x86/realmode/rm/video-vesa.c']
    blacklist += ['arch/x86/entry/vdso/vdso32/vclock_gettime.c']
    # reboot loop
    blacklist += ['mm/vmstat.c', 'mm/page_alloc.c']
    # TODO(glider): or maybe we can instrument main.c?
    blacklist += ['init/main.c']
    # Too much time spent in __kernel_text_address() and friends, which are mostly harmless.
    blacklist += ['kernel/extable.c']
    # Ditto for module_address etc. This is unfortunate, because kernel/module.c contains other code as well.
    blacklist += ['kernel/module.c']
    return blacklist

def want_msan_for_file(source):
    if source.endswith('.S'):
        return False
    # Order of application: exact blacklist > starts_whitelist > starts_blacklist
    starts_whitelist = []
    starts_blacklist = []
    # Only exact filenames, no wildcards here!
    exact_blacklist = setup_exact_blacklist()

    starts_blacklist += ['arch/x86/']

    for i in 'm':
        starts_blacklist.append('mm/' + i)

    starts_blacklist += ['kernel/']

    mm_black = ['percpu.c', 'pagewalk.c', 'percpu-km.c', 'pgtable-generic.c']
    mm_black += ['percpu-vm.c', 'page_counter.c', 'page_ext.c', 'page_idle.c', 'page_io.c', 'page_isolation.c']
    mm_black += ['page_owner.c', 'page_poison.c']
    add_to_list(starts_blacklist, 'mm/', mm_black)

    # TODO: printk takes lock, calls memchr() on uninit memory, memchr() reports an uninit and attempts to take the same lock.
    # TODO: lib/vsprintf.c deadlocks when printing reports.

    arch_x86_kernel_white = ['time.c', 'apic/apic.c', 'apic/io_apic.c', 'acpi/boot.c', 'process.c', 'rtc.c', 'irq.c', 'sys_x86_64.c', 'hpet.c']
    arch_x86_kernel_white += ['pcspeaker.c', 'process_64.c', 'perf_regs.c', 'ldt.c', 'cpu/microcode/core.c']
    add_to_list(starts_whitelist, 'arch/x86/kernel/', arch_x86_kernel_white)
    starts_whitelist += ['arch/x86/kernel/apic/']

    starts_whitelist += ['arch/x86/pci/', 'arch/x86/lib/', 'arch/x86/boot/', 'arch/x86/events/', 'arch/x86/realmode/rm/']
    for i in 'abhiprstuv':
        starts_whitelist.append('arch/x86/kernel/cpu/' + i)

    starts_whitelist += ['arch/x86/entry/vdso/', 'arch/x86/mm/', 'arch/x86/platform/']

    starts_whitelist += ['kernel/printk/printk.c']
    #starts_whitelist += ['arch/x86/kernel/cpu/']

    for i in 'abcdeghijnrtw':
        starts_whitelist.append('kernel/' + i)

    mm_white = ['backing-dev.c', 'util.c', 'vmalloc.c', 'mmap.c', 'rmap.c', 'interval_tree.c', 'shmem.c', 'readahead.c']
    mm_white += ['filemap.c', 'swap.c', 'truncate.c', 'page-writeback.c', 'swap_state.c', 'memory.c', 'swapfile.c', 'mlock.c', 'mprotect.c']
    mm_white += ['mremap.c', 'mmzone.c', 'process_vm_access.c', 'mempolicy.c', 'migrate.c']
    add_to_list(starts_whitelist, 'mm/', mm_white)

    kernel_locking_white = ['rwsem-spinlock.c', 'rwsem-xadd.c', 'rtmutex.c']
    add_to_list(starts_whitelist, 'kernel/locking/', kernel_locking_white)

    kernel_white = ['softirq.c', 'smpboot.c', 'workqueue.c', 'kthread.c', 'stop_machine.c', 'fork.c', 'exit.c', 'groups.c', 'signal.c']
    kernel_white += ['audit.c', 'params.c', 'pid.c', 'cred.c', 'user.c', 'nsproxy.c', 'kmod.c', 'smp.c', 'cpu.c', 'futex.c', 'kallsyms.c']
    kernel_white += ['sys.c', 'ptrace.c']
    add_to_list(starts_whitelist, 'kernel/', kernel_white)
    starts_whitelist += ['kernel/trace/', 'kernel/events/', 'kernel/irq/', 'kernel/rcu/', 'kernel/time/', 'kernel/sched/', 'kernel/power/']

    for black in exact_blacklist:
        if source == black:
            if LOG_OPTIONS['kmsan_inst']:
                print >>LOG, 'kmsan: exact_blacklist: skipping %s' % source
            return False
    for white in starts_whitelist:
        if source.startswith(white):
            if LOG_OPTIONS['kmsan_inst']:
                print >>LOG, 'kmsan: instrumenting %s' % source
            return True
    for black in starts_blacklist:
        if source.startswith(black):
            if LOG_OPTIONS['kmsan_inst']:
                print >>LOG, 'kmsan: starts_blacklist: skipping %s' % source
            return False

    if (source):
        if LOG_OPTIONS['kmsan_inst']:
            print >>LOG, 'kmsan: instrumenting %s' % source

    # For existing source files return True.
    return bool(source)


def msan_argv(flags, argv):
    source = flags[SOURCE]
    #argv += ['-Wno-address-of-packed-member', '-g', '-v']
    argv += ['-Wno-address-of-packed-member', '-g']
    if want_msan_for_file(source):
        argv += ['-fsanitize=kernel-memory', '-mllvm', '-msan-kernel=1', '-mllvm', '-msan-keep-going=1', '-mllvm', '-msan-track-origins=2']
#        ]
#        '-fsanitize-memory-track-origins=2']
    return argv

def compiler_argv(flags, argv):
    cname = compiler(flags)
    new_argv = [COMPILER_PATH[cname]] + filter_args(argv, cname)
    if os.getenv('USE_MSAN') or True:
        new_argv = msan_argv(flags, new_argv)
    return new_argv

def make_flags(argv):
    flags = defaultdict(str)
    argv = argv[1:]
    for arg in argv:
        if arg.endswith('.c'):
            flags[SOURCE] = arg
        if arg.endswith('.S'):
            flags[SOURCE] = arg
    return flags, argv

def main(argv):
    global LOG
    LOG = file(WRAPPER_LOG, 'a+')
    if LOG_OPTIONS['argv']:
        print >>LOG, ' '.join(argv)
    flags, argv = make_flags(argv)
    new_argv = compiler_argv(flags, argv)
    #print >>LOG, ' '.join(new_argv)
    start_time = time.time()
    ret = subprocess.call(new_argv)
    end_time = time.time()
    if LOG_OPTIONS['time']:
        print >> LOG, 'Time elapsed: {:.3f} seconds'.format(end_time - start_time)
    LOG.close()
    return ret


if __name__ == '__main__':
    sys.exit(main(sys.argv))
