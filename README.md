# KMSAN (KernelMemorySanitizer)

`KMSAN` is a detector of uninitialized memory use for the Linux kernel. It is
currently in development.

Contact: ramosian-glider@

## Code

*   The kernel branch with KMSAN patches is available at https://github.com/google/kmsan
*   These will be upstreamed someday, stay tuned!

## How to build

In order to build a kernel with KMSAN you'll need a fresh Clang (8.0.0, trunk 341646 or greater)

```
export WORLD=`pwd`
```

### Build Clang
```
# Starting from r341646 any Clang revision should work, but due to changed default flag values
# a version >= r348261 is recommended.
R=348261
svn co -r $R http://llvm.org/svn/llvm-project/llvm/trunk llvm
cd llvm
(cd tools && svn co -r $R http://llvm.org/svn/llvm-project/cfe/trunk clang)
(cd projects && svn co -r $R http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt)
mkdir llvm_cmake_build && cd llvm_cmake_build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON ../
make -j64 clang
export KMSAN_CLANG_PATH=`pwd`/bin/clang
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
