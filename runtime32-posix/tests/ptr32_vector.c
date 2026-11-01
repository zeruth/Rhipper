/* Clang's loop vectorizer turns a loop of 32-bit pointer stores into a vector addrspacecast,
   <N x ptr> to <N x ptr addrspace(271)>, that the AArch64 backend cannot legalize ("Do not know how
   to split this operator's operand!"); translations copy structs dword by dword into __ptr32 fields
   this way. RUNTIME32_POSIX_GEN_FLAGS carries -fno-vectorize for it: this must compile with them.
   (The SLP vectorizer leaves these casts scalar, copy_ptr32_4, so it stays on. Seen with clang 22.1.)

     clang --target=aarch64-linux-android29 -O2 -fms-extensions -c ptr32_vector.c          (crashes)
     clang --target=aarch64-linux-android29 -O2 -fms-extensions -fno-vectorize -c ...       (builds) */
typedef void *__ptr32 __uptr p32;

void copy_ptr32(p32 *dst, const unsigned int *src)
{
  int i;
  for (i = 0; i < 345; i++)
    dst[i] = (void *)(__UINTPTR_TYPE__)src[i]; /* through a native pointer, as the translations do */
}

/* the same four stores without the loop, for the SLP vectorizer */
void copy_ptr32_4(p32 *dst, const unsigned int *src)
{
  dst[0] = (void *)(__UINTPTR_TYPE__)src[0];
  dst[1] = (void *)(__UINTPTR_TYPE__)src[1];
  dst[2] = (void *)(__UINTPTR_TYPE__)src[2];
  dst[3] = (void *)(__UINTPTR_TYPE__)src[3];
}
