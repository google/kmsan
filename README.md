# KMSAN (KernelMemorySanitier)

`KMSAN` is a detector of uninitialized memory use for the Linux kernel. It is
currently in development.

Contact: ramosian-glider@

## Code

*   The kernel branch with KMSAN patches is available at https://github.com/google/kmsan
*   Patches for LLVM: [LLVM patch](https://github.com/google/kmsan/blob/master/kmsan-llvm.patch),
    [Clang patch](https://github.com/google/kmsan/blob/master/kmsan-clang.patch)

## How to build

In order to build a kernel with KMSAN you'll need a custom Clang built from a patched tree on LLVM r298239.

```
export WORLD=`pwd`
```

### Build Clang
```
# I sometimes forget to update this revision.
# Please refer to the contents of kmsan-llvm.patch in that case.
R=329054
svn co -r $R http://llvm.org/svn/llvm-project/llvm/trunk llvm
cd llvm
(cd tools && svn co -r $R http://llvm.org/svn/llvm-project/cfe/trunk clang)
(cd projects && svn co -r $R http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt)
wget https://raw.githubusercontent.com/google/kmsan/master/kmsan-llvm.patch
patch -p0 -i kmsan-llvm.patch
wget https://raw.githubusercontent.com/google/kmsan/master/kmsan-clang.patch
(cd tools/clang && patch -p0 -i kmsan-clang.patch)
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
# Note that clang_wrapper.py expects $KMSAN_CLANG_PATH to point to a Clang binary!
make CC=`pwd`/clang_wrapper.py -j64 -k 2>&1 | tee build.log
```

### Run the kernel
You can refer to https://github.com/ramosian-glider/clang-kernel-build for the instructions
on running the freshly built kernel in a QEMU VM.
Also consider running a KMSAN-instrumented kernel under [syzkaller](https://github.com/google/syzkaller).

## Trophies

See https://github.com/google/kmsan/wiki/KMSAN-Trophies for the list of trophies.
