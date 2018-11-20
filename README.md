# KMSAN (KernelMemorySanitizer)

`KMSAN` is a dynamic tool for detecting uninitialized memory accesses in the Linux kernel.
It was integrated into the Linux kernel in version 6.1.
KMSAN works by instrumenting the kernel code at compile time and checking for accesses to uninitialized memory at run time.

Contact: @ramosian-glider

## Code

*   Linux 6.1+ contains a fully-working KMSAN implementation which can be used out of the box.
*   Forked kernel branches with KMSAN patches are available at https://github.com/google/kmsan. These will be kept around for posterity. Branches after 6.1 are still used for development.

## How to build


```
export WORLD=`pwd`
```

In order to build a kernel with KMSAN you'll need a fresh Clang. Please refer to https://clang.llvm.org/get_started.html and https://llvm.org/docs/CMake.html for the instructions on how to build Clang. Otherwise, consider using prebuilt compiler binaries from the Chromium project:

```
cd $WORLD
# Instruction taken from http://llvm.org/docs/LibFuzzer.html
mkdir TMP_CLANG
cd TMP_CLANG
git clone https://chromium.googlesource.com/chromium/src/tools/clang
cd ..
TMP_CLANG/clang/scripts/update.py
cd $WORLD
export KMSAN_CLANG_PATH=`pwd`/third_party/llvm-build/Release+Asserts/bin/
```


### Configure and build the kernel
```
cd $WORLD
git clone https://github.com/google/kmsan.git kmsan
cd kmsan
# Now configure the kernel. You basically need to enable CONFIG_KMSAN and CONFIG_KCOV,
# plus maybe some 9P options to interact with QEMU.
cp .config.example .config
make CC=$KMSAN_CLANG_PATH -j64 -k 2>&1 | tee build.log
```

### Run the kernel
You can refer to https://github.com/ramosian-glider/clang-kernel-build for the instructions
on running the freshly built kernel in a QEMU VM.
Also consider running a KMSAN-instrumented kernel under [syzkaller](https://github.com/google/syzkaller).

## Trophies

There is an outdated list of trophies at https://github.com/google/kmsan/wiki/KMSAN-Trophies.
Most of the bugs found with KMSAN can be seen at https://syzkaller.appspot.com/upstream/fixed (search for KMSAN).

## How does it work?
Please refer to the [Documentation](https://docs.kernel.org/next/dev-tools/kmsan.html) in the upstream Linux kernel.

In a [talk at FaMAF-UNC](https://www.youtube.com/watch?v=LNs2U-3m3yg), I attempted to provide a comprehensive overview of the implementation details of KMSAN in 2021. The kernel part starts at 19:30, listen at 1.25x to save time).
