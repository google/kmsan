=============================
KernelMemorySanitizer (KMSAN)
=============================

KMSAN is a detector of uninitialized memory.
It is based on compiler instrumentation, and is quite similar to the userspace
MemorySanitizer tool (http://clang.llvm.org/docs/MemorySanitizer.html).
The goal behind creating it is to make a tool that is both faster and more precise than kmemcheck.

KMSAN and Clang
===============

In order for KMSAN to work the kernel must be
built with Clang, which is so far the only compiler that has KMSAN support.
The kernel instrumentation pass is based on the userspace MemorySanitizer tool
(http://clang.llvm.org/docs/MemorySanitizer.html). Because of the instrumentation
complexity it's unlikely that any other compiler will support KMSAN soon.

Right now the instrumentation pass supports only X86 and isn't upstreamed yet.

How to build
============
This part is subject to change, as we're going to upstream our patches to LLVM and Linux kernel.

First, one needs to check out LLVM r298107, apply ``kmsan-llvm.patch`` to the llvm/ dir and
``kmsan-clang.patch`` to the llvm/tools/clang/ dir, and build Clang for Linux.

Second, configure and make the kernel using the supplied Clang wrapper::

  make CC=$CLANG_PATH/clang defconfig
  make CC=`pwd`/clang_wrapper.py 2>&1 | tee build.log

How KMSAN works
===============

KMSAN shadow memory
-------------------

KMSAN associates a so-called shadow byte with every byte of kernel memory.
A bit in the shadow byte is set iff the corresponding bit of the kernel memory byte is uninitialized.
Marking memory uninitialized (i.e. setting its shadow bytes to 0xff) is called poisoning,
marking it initialized (setting the shadow bytes to 0x00) is called unpoisoning.

When a new variable is allocated on stack or heap, it's poisoned by default (unless it's a stack variable
that is immediately initialized, or a heap variable allocated with ``__GFP_ZERO``).

The compiler instrumentation tracks the shadow values with the help from the runtime library in ``mm/kmsan/``.
The shadow value of a basic or compound type is an array of bytes of the same length.

When a constant value is written into memory, that memory is unpoisoned.
When a value is read from memory, its shadow memory is also obtained and propagated into all the operations
which use that value. For every instruction that takes one or more values the compiler generates the code that
calculates the shadow of the result depending on those values and their shadows.

Example::

  int a = 0xff;
  int b;
  int c = a | b;

In this case the shadow of ``a`` is ``0``, shadow of ``b`` is ``0xffffffff``, shadow of ``c`` is
``0xffffff00``. This means that the upper three bytes of ``c`` are uninitialized, while the lower byte
is initialized.


Origin tracking
---------------

Every four bytes of kernel memory also have a so-called origin assigned to them.
This origin describes the point in program execution at which the uninitialized value was created.
Every origin is associated with a creation stack, which lets the user figure out what's going on.

Unlike the user-space MemorySanitizer, KMSAN always has origin tracking enabled, because reports without
origins have shown themselves useless.

When an uninitialized variable is allocated on stack or heap, a new origin value is created, and
that variable's origin is filled with that value.
When the a value is read from memory, its origin is also read and kept together with the shadow.
For every instruction that takes one or more values the origin of the result is one of the origins
corresponding to any of the uninitialized inputs.
If a poisoned value is written into memory, its origin is written to the corresponding storage as well.

Example 1::

  int a = 0;
  int b;
  int c = a + b;

In this case the origin of ``@b`` is generated upon function entry, and is stored to the origin of `|c|`
right before the addition result is written into memory.

Several variables may share the same origin address, if they are stored in the same four-byte chunk.
In this case every write to either variable updates the origin for all of them.

Example 2::

  int combine(short a, short b) {
    union ret_t {
      int i;
      short s[2];
    } ret;
    ret.s[0] = a;
    ret.s[1] = b;
    return ret.i;
  }

If ``@a`` is initialized and ``@b`` is not, the shadow of the result would be 0xffff0000, and the origin
of the result would be the origin of ``@b@``. ``ret.s[0]`` would have the same origin, but it will be
never used, because that variable is initialized.

If both function arguments are uninitialized, only the origin of the second argument is preserved.

Origin chaining
~~~~~~~~~~~~~~~
A special mode allows to create a new origin for every memory store. The new origin references both
its creation stack and the previous origin the memory location had.
This eases the debugging greatly, but may also cause increased memory consumption. Therefore we limit
the length of origin chains in the runtime.


Clang instrumentation API
-------------------------

(Some of the functions use ``__msan`` prefixes instead of ``__kmsan`` for historical reasons.
Those are gonna change.)

Shadow manipulation
~~~~~~~~~~~~~~~~~~~
For every memory access the corresponding function is emitted that returns the shadow address of
that memory. That function also checks if the shadow of the memory in the range [``addr``, ``addr + n``) is
contiguous and reports an error otherwise::

  u64 __kmsan_get_shadow_address_{1,2,4,8,16}(u64 addr)
  u64 __kmsan_get_shadow_address_n(u64 addr, u64 n)

Origin tracking
~~~~~~~~~~~~~~~
For every memory load and store KMSAN API functions are also emitted that read the corresponding
origin values::

  u32 __kmsan_load_origin(u64 addr) -- load the origin for the address
  void __kmsan_store_origin(u64 addr, u32 origin) -- save the origin for the address

A special function is used to create a new origin value for a local variable and set the origin of that variable to that value::

  void __msan_set_alloca_origin(void *a, u64 size, char *descr, u64 pc) -- create a new origin

Getters for per-task data
~~~~~~~~~~~~~~~~~~~~~~~~~

(These have the ``_tls`` suffixes for historical reasons)

Calls to the following 7 functions are unconditionally inserted at the beginning of every
instrumented function (this is subject to change in the future). They are used to pass additional
parameters between instrumented functions preserving the ABI::

  void *__kmsan_get_retval_tls(void) -- callee will store the shadow of the return value here
  int *__kmsan_get_retval_origin_tls(void) -- callee will store origin of the return value here
  void **__kmsan_get_param_tls(void) -- shadow array for callee's parameters
  void **__kmsan_get_va_arg_tls(void) -- shadow array for callee's vararg parameters
  u32 *__kmsan_get_param_origin_tls(void) -- origin array for callee's parameters
  u64 *__kmsan_get_va_arg_overflow_size_tls(void) -- TODO(glider): document this properly
  u32 *__kmsan_get_origin_tls(void) -- store the origin to be reported when calling __msan_warning()

``__kmsan_get_origin_tls()`` is essentially a parameter to ``__msan_warning()``, and should be
replaced with such.


String functions
~~~~~~~~~~~~~~~~

The compiler inserts them in place of real ``memcpy()``/``memmove()``/``memset()``, or when
data structures are initialized or copied. These functions copy or set the shadow and origin
together with the data::

  void *__msan_memcpy(void *dst, void *src, u64 n)
  void *__msan_memmove(void *dst, void *src, u64 n)
  void *__msan_memset(void *dst, int c, size_t n)

Error reporting
~~~~~~~~~~~~~~~

For each pointer dereference and each condition the compiler emits a shadow check that calls
``__msan_warning()`` in the case a poisoned value is being used::

  void __msan_warning()

Before the call the origin of the poisoned value is stored into ``*__kmsan_get_origin_tls()``. ``__msan_warning()`` reports the use of
uninitialized value together with the stack trace of the current memory access and the chain of
stack traces obtained from the origin value (see example report).


Disabling the instrumentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A function can be marked with ``__attribute__((no_sanitize("kernel-memory")))``.
Doing so doesn't remove KMSAN instrumentation from it, however it makes the compiler ignore the
uninitialized values coming from the function's inputs, and initialize the function's outputs.

Runtime library
---------------
The code is located in ``mm/kmsan/``.

Metadata allocation
~~~~~~~~~~~~~~~~~~~
The metadata is currently stored in ``struct page``; for each page there are two pointers::

  struct page *shadow;
  struct page *origin;

Every time a ``struct page`` is allocated, the runtime library allocates two additional pages to
hold its shadow page and origin page. This is done by adding hooks to ``alloc_pages()``/``free_pages()`` in
``mm/page_alloc.c``. To avoid allocating the metadata for non-interesting pages (shadow/origin page themselves,
stackdepot storage etc. the ``__GFP_NO_KMSAN_SHADOW`` flag is used.

There is a problem related to this: when two contiguous memory blocks are allocated with two different
``alloc_pages()`` calls, their shadow pages may not be contiguous. So, if a memory access crosses
the boundary of a memory block, the accesses to shadow/origin memory need to be carefully splitted to
avoid memory corruption.
Because the compiler instrumentation for a memory write simply obtains the pointer to the shadow address
and writes to its contents, it's impossible to split that write on the fly or prevent the page overrun.
Instead, we check the access size in ``__kmsan_get_shadow_address_X()`` and return a pointer to a fake shadow
region in the case of an error.

Unfortunately at boot time we need to allocate the shadow and origin memory for the kernel data (``.data``,
``.bss`` etc.) and the percpu memory regions, the size of which is not a power of 2. As a result, we have to
allocate the metadata page by page, so that it is also non-contiguous, while it may be perfectly valid
to access the corresponding kernel memory across page boundaries.
This can be probably fixed by allocating 1<<N pages at once, splitting them and deallocating the rest.

In addition, it turns out that not every address has a ``struct page`` corresponding to it.
(TODO(glider): need to check this)

Example report
--------------
Here's an example of a real KMSAN report in ``packet_bind_spkt()``::

  ==================================================================
  BUG: KMSAN: use of unitialized memory
  CPU: 0 PID: 1074 Comm: packet Not tainted 4.8.0-rc6+ #1891
  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
   0000000000000000 ffff88006b6dfc08 ffffffff82559ae8 ffff88006b6dfb48
   ffffffff818a7c91 ffffffff85b9c870 0000000000000092 ffffffff85b9c550
   0000000000000000 0000000000000092 00000000ec400911 0000000000000002
  Call Trace:
   [<     inline     >] __dump_stack lib/dump_stack.c:15
   [<ffffffff82559ae8>] dump_stack+0x238/0x290 lib/dump_stack.c:51
   [<ffffffff818a6626>] kmsan_report+0x276/0x2e0 mm/kmsan/kmsan.c:1003
   [<ffffffff818a783b>] __msan_warning+0x5b/0xb0 mm/kmsan/kmsan_instr.c:424
   [<     inline     >] strlen lib/string.c:484
   [<ffffffff8259b58d>] strlcpy+0x9d/0x200 lib/string.c:144
   [<ffffffff84b2eca4>] packet_bind_spkt+0x144/0x230 net/packet/af_packet.c:3132
   [<ffffffff84242e4d>] SYSC_bind+0x40d/0x5f0 net/socket.c:1370
   [<ffffffff84242a22>] SyS_bind+0x82/0xa0 net/socket.c:1356
   [<ffffffff8515991b>] entry_SYSCALL_64_fastpath+0x13/0x8f arch/x86/entry/entry_64.o:?
  chained origin: 00000000eba00911
   [<ffffffff810bb787>] save_stack_trace+0x27/0x50 arch/x86/kernel/stacktrace.c:67
   [<     inline     >] kmsan_save_stack_with_flags mm/kmsan/kmsan.c:322
   [<     inline     >] kmsan_save_stack mm/kmsan/kmsan.c:334
   [<ffffffff818a59f8>] kmsan_internal_chain_origin+0x118/0x1e0 mm/kmsan/kmsan.c:527
   [<ffffffff818a7773>] __msan_set_alloca_origin4+0xc3/0x130 mm/kmsan/kmsan_instr.c:380
   [<ffffffff84242b69>] SYSC_bind+0x129/0x5f0 net/socket.c:1356
   [<ffffffff84242a22>] SyS_bind+0x82/0xa0 net/socket.c:1356
   [<ffffffff8515991b>] entry_SYSCALL_64_fastpath+0x13/0x8f arch/x86/entry/entry_64.o:?
  origin description: ----address@SYSC_bind (origin=00000000eb400911)
  ==================================================================

The report tells that the local variable ``address`` was created uninitialized in ``SYSC_bind()``
(the ``bind`` system call implementation). The lower stack trace corresponds to the place where
this variable was created.

The upper stack shows where the uninit value was used - in ``strlen()``.
It turned out that the contents of ``address`` were partially copied from the userspace, but the
buffer wasn't zero-terminated and contained some trailing uninitialized bytes.
``packet_bind_spkt()`` didn't check the length of the buffer, but called ``strlcpy()`` on it, which
called ``strlen()``, which started reading the buffer byte by byte till it hit the uninitialized memory.

Misc details
------------

Handling interrupts
~~~~~~~~~~~~~~~~~~~

Registers don't have (easily calculatable) shadow or origin associated with them.
We can assume that the registers are always initialized.

KMSAN vs. kmemcheck
===================

As ``kmemcheck`` maintainers claim, ``kmemcheck`` is prone to false positives.
In particular, it does not propagate the uninitialized bits through arithmetic operations,
e.g. doesn't understand when those bits are masked out.

Under ``kmemcheck`` the kernel performs the following steps every time a memory
access happens:

  * try to access the memory
  * handle a pagefault and investigate whether there's a bug
  * temporarily mark the page present
  * single-step one instruction and generate a debug exception
  * handle the exception and marks the page hidden again
  * resume execution

, which is quite slow.

References
==========

E. Stepanov, K. Serebryany. MemorySanitizer: fast detector of uninitialized memory use in C++.
In Proceedings of CGO 2015.
