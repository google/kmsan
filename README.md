# KMSAN (KernelMemorySanitizer)

`KMSAN` is a detector of uninitialized memory use for the Linux kernel. It is
currently in development.

Contact: @ramosian-glider

## Code

*   The kernel branch with KMSAN patches is available at https://github.com/google/kmsan
*   These will be upstreamed someday, stay tuned!

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

See https://github.com/google/kmsan/wiki/KMSAN-Trophies for the list of trophies.

## Known issues

1. `CONFIG_DRM_AMD_DC_DCN1_0` doesn't work with Clang because of https://bugs.llvm.org/show_bug.cgi?id=38738.
To work around the problem, disable `CONFIG_DRM_AMD_DC`
2. `CONFIG_UNWINDER_ORC` doesn't work yet, use `CONFIG_UNWINDER_FRAME_POINTER`.
