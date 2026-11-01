# [AArch64] Truncating store through an addrspace(271) (`__ptr32`) pointer is emitted at the full width of the untruncated value

**Version:** clang 22.1.7 (llvm-project a255c1ed36a1d06f79bd2633ba9f8d900153007c). Targets `aarch64-linux-gnu` and `aarch64-linux-android29`, at both `-O0` and `-O2`.

## Summary
A `trunc` from i64 followed by a `store` of the narrow type through a pointer in address space 271 or 272 (`__ptr32 __sptr` / `__ptr32 __uptr` under `-fms-extensions`) is compiled to a 64-bit store of the untruncated value. A store of i32 or i8 therefore writes 8 bytes and clobbers the 4 to 7 bytes after its target.

The same store through an address-space-0 pointer is correct. Loads through addrspace(271) are correct, including extending loads. A store whose value is already i32 (no `trunc`) is also correct.

The IR is valid and the frontend output is correct (`store i32 %t, ptr addrspace(271) %p, align 4`). The problem appears in instruction selection.

## Reproducer

```llvm
define void @trunc_i64_i32(ptr %bin, i64 %v) {
  %slot = getelementptr i8, ptr %bin, i64 4
  %p = load ptr addrspace(271), ptr %slot, align 4
  %t = trunc i64 %v to i32
  store i32 %t, ptr addrspace(271) %p, align 4
  ret void
}

define void @trunc_i64_i8(ptr %bin, i64 %v) {
  %slot = getelementptr i8, ptr %bin, i64 4
  %p = load ptr addrspace(271), ptr %slot, align 4
  %t = trunc i64 %v to i8
  store i8 %t, ptr addrspace(271) %p, align 1
  ret void
}

; same store through an addrspace(0) pointer, for comparison
define void @trunc_i64_i32_as0(ptr %bin, i64 %v) {
  %slot = getelementptr i8, ptr %bin, i64 4
  %p = load ptr, ptr %slot, align 8
  %t = trunc i64 %v to i32
  store i32 %t, ptr %p, align 4
  ret void
}
```

`clang --target=aarch64-linux-gnu -O2 -S -o - repro.ll` (also `llc -mtriple=aarch64-linux-gnu`):

```
trunc_i64_i32:
        ldr     w8, [x0, #4]
        str     x1, [x8]        // expected: str w1, [x8]
trunc_i64_i8:
        ldr     w8, [x0, #4]
        str     x1, [x8]        // expected: strb w1, [x8]
trunc_i64_i32_as0:
        ...
        str     w1, [x8]        // correct
```

The same C reproducer (`-fms-extensions`):

```c
typedef unsigned int u32;
void f(char *bin, int *node) {
  **(u32 * __ptr32 __uptr *)(bin + 4) = (u32)(__UINTPTR_TYPE__)node;   // emits str x1
}
```

## Likely cause
On AArch64, loads and stores through the MS 32-bit address spaces are custom-lowered: the 32-bit pointer is zero- or sign-extended to 64 bits, and the access is re-emitted through the extended address. For a `TRUNCSTORE`, which is what DAG combine forms from `trunc` plus `store`, the rebuilt node appears to become a plain `store` of the wide value, discarding the truncating store's memory VT. The non-truncating i32 store and the extending loads already take the right path.

On x86-64 the same IR is correct.

## Impact
This is silent memory corruption in any code that stores through `__ptr32` pointers on AArch64. We hit it in a recompiled 32-bit x86 program. A free-list insert, `**(u32 * __ptr32 *)(bin + 4) = (u32)node`, zeroed the neighbouring field, and the program crashed later in an unrelated function.

Workaround: access the lvalue through an addrspace(0) pointer, for example `*(T *)&lvalue`. That emits the correct `str w` / `strh` / `strb`.
