/* With -fshort-wchar (wchar_t 2 bytes, as the reference's WCHAR) clang's loop idiom pass turns a
   UTF-16 length loop into a call to wcslen, and on Android that is bionic's, which counts 4-byte
   units: every length came out half, GetModuleHandleW(L"KERNEL32.DLL") asked for "KERNEL" and the
   reference exited at once (2026-10-31). RUNTIME32_POSIX_GEN_FLAGS carries -fno-builtin-wcslen, and
   the runtime's own C++ is built without -fshort-wchar. This is linked with -nostdlib: a wcslen
   the compiler put in fails the link. */
typedef unsigned short wchar16;

__SIZE_TYPE__ len16(const wchar16 *s)
{
  __SIZE_TYPE__ n = 0;
  while (s[n])
    n++;
  return n;
}

wchar16 kernel32[] = {'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0};
const wchar16 *volatile which = kernel32;   /* (not folded to 8) */

int start(void)
{
  return (int)len16(which);
}
