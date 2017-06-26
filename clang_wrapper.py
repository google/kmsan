#!/usr/bin/env python
from collections import defaultdict
import optparse
import os
import subprocess
import sys
import time

WORLD_PATH = os.path.dirname(os.path.abspath(__file__))

COMPILER_PATH = {
    'gcc': 'gcc',
    'clang': os.getenv('KMSAN_CLANG_PATH'),
}

FILTER = {'gcc': ['-Qunused-arguments', '-no-integrated-as', '-mno-global-merge',
    '-Wdate-time', '-Wno-unknown-warning-option', '-Wno-initializer-overrides', '-Wno-tautological-compare',
    '-Wincompatible-pointer-types', '-Wno-gnu', '-Wno-format-invalid-specifier',
    '-Werror=date-time', '-Werror=incompatible-pointer-types',
],'clang': ['-fno-inline-functions-called-once']}
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
    blacklist += ['mm/vmstat.c', 'mm/page_alloc.c', 'arch/x86/kernel/nmi.c']
    # TODO(glider): or maybe we can instrument main.c?
    blacklist += ['init/main.c']
    # Too much time spent in __kernel_text_address() and friends, which are mostly harmless.
    blacklist += ['kernel/extable.c']
    # Ditto for module_address etc. This is unfortunate, because kernel/module.c contains other code as well.
    blacklist += ['kernel/module.c']
    # Don't instrument kcov.
    blacklist += ['kernel/kcov.c']
    # Boot-time crashes.
    blacklist += ['arch/x86/kernel/cpu/common.c']
    return blacklist

def want_msan_for_file(source):
    if source.endswith('.S'):
        return False
    # Order of application: exact blacklist > starts_whitelist > starts_blacklist
    starts_whitelist = []
    # This is empty, as we want to instrument everything not explicitly blacklisted.
    starts_blacklist = []
    # Only exact filenames, no wildcards here!
    exact_blacklist = setup_exact_blacklist()

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
    argv += ['-Wno-address-of-packed-member', '-g']
    if want_msan_for_file(source):
        argv += ['-fsanitize=kernel-memory']
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
