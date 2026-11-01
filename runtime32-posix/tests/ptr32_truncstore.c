/* clang's AArch64 backend stores a narrowed value through a __ptr32 pointer (LLVM's address space 271)
   with the wide value's width: `**(undefined4 * PTR32 *)p = (undefined4)host_ptr` became `str x`, 8
   bytes over a 4-byte field. FFXIV's AllocatorHeap::InsertFreeBlock (0x4f5620, inlined in Free
   0x4f60a0) zeroed the next free block's `prev` that way and its RemoveFreeBlock followed the 0
   (2026-11-01, clang 22.1.7). translate32 wraps every store through such a pointer in GEN_NE, which
   Ghidra32.h makes an access through a host pointer on hosts that are not x86.

   Runtime32Posix.cmake compiles this with the gen flags to assembly and fails when a store here is
   wider than its type (`str x` / a wide `stur`): each function stores 4, 2 or 1 byte. */
#include "Ghidra32.h"

void store4_ptr(char *p, int *v) { GEN_NE(**(undefined4 * PTR32 *)(p + 4)) = (undefined4)(uintptr_t)v; }
void store4_u64(char *p, unsigned long long v) { GEN_NE(**(undefined4 * PTR32 *)(p + 4)) = (undefined4)v; }
void store2_ptr(char *p, int *v) { GEN_NE(**(undefined2 * PTR32 *)(p + 4)) = (undefined2)(uintptr_t)v; }
void store1_u64(char *p, unsigned long long v) { GEN_NE(**(undefined * PTR32 *)(p + 4)) = (undefined)v; }
