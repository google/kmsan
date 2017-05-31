# KMSAN (KernelMemorySanitier)

`KMSAN` is a detector of uninitialized memory use for the Linux kernel. It is
currently in development.

Contact: ramosian-glider@

## Code

*   The kernel branch with KMSAN patches is available at https://github.com/google/kmsan
*   Patches for LLVM r298239: [LLVM patch](https://github.com/google/kmsan/blob/master/kmsan-llvm.patch),
    [Clang patch](https://github.com/google/kmsan/blob/master/kmsan-clang.patch)
*   Clang wrapper: https://github.com/google/kmsan/blob/master/clang_wrapper.py

## How to build

In order to build a kernel with KMSAN you'll need a custom Clang built from a patched tree on LLVM r298239.

```
export WORLD=`pwd`
```

### Build Clang
```
R=298239
svn co -r $R http://llvm.org/svn/llvm-project/llvm/trunk llvm
cd llvm
(cd tools && svn co -r $R http://llvm.org/svn/llvm-project/cfe/trunk clang)
(cd projects && svn co -r $R http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt)
wget https://raw.githubusercontent.com/google/kmsan/master/kmsan-llvm.patch
patch -p0 -i kmsan-llvm.patch
# Apply a patch fixing https://bugs.llvm.org/show_bug.cgi?id=32842
wget https://reviews.llvm.org/file/data/sktw7c6s7lpz7ah3p6ib/PHID-FILE-v75mhkvsosaxnkl55lki/D32915.diff
patch -p0 -i D32915.diff
wget https://raw.githubusercontent.com/google/kmsan/master/kmsan-clang.patch
(cd tools/clang && patch -p0 -i ../../kmsan-clang.patch)
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

*   [`tmp.b_page` uninitialized in
    `generic_block_bmap()`](https://lkml.org/lkml/2016/12/22/158)
    *   Writeup:
        https://github.com/google/kmsan/blob/master/kmsan-first-bug-writeup.txt
    *   Status: taken to the ext4 tree (according to Ted Ts'o), upstream fix pending
*   [`strlen()` called on non-terminated string in `bind()` for
    `AF_PACKET`](https://lkml.org/lkml/2017/2/28/270)
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/540e2894f7905538740aaf122bd8e0548e1c34a4)
*   [too short socket address passed to
    `selinux_socket_bind()`](https://lkml.org/lkml/2017/3/3/524)
    *   Status: reported upstream
*   [uninitialized `msg.msg_flags` in `recvfrom`
    syscall](https://lkml.org/lkml/2017/3/7/361)
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/9f138fa609c47403374a862a08a41394be53d461)
*   [incorrect input length validation in nl_fib_input()]()
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/c64c0b3cac4c5b8cb093727d2c19743ea3965c0b)
        by Eric Dumazet
*   [uninitialized `sockc.tsflags` in
    udpv6_sendmsg()](https://lkml.org/lkml/2017/3/21/505)
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/d515684d78148884d5fc425ba904c50f03844020)
*   [incorrect input length validation in
    packet_getsockopt()](https://lkml.org/lkml/2017/4/25/628)
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/fd2c83b35752f0a8236b976978ad4658df14a59f)
*   [incorrect input length validation in raw_send_hdrinc()
    and rawv6_send_hdrinc()](https://lkml.org/lkml/2017/5/3/351)
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/86f4c90a1c5c1493f07f2d12c1079f5bf01936f2)
*   [missing check of nlmsg_parse() return value in
    rtnl_fdb_dump()](https://lkml.org/lkml/2017/5/23/346)
    *   Status: [fixed
        upstream](https://github.com/torvalds/linux/commit/0ff50e83b5122e836ca492fefb11656b225ac29c)
