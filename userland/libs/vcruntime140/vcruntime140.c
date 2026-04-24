/*
 * userland/libs/vcruntime140/vcruntime140.c
 *
 * Freestanding CustomOS vcruntime140.dll — memory intrinsics
 * (memset / memcpy / memmove). Retires the batch-5 flat stubs
 * in kernel/subsystems/win32/stubs.cpp.
 *
 * These three functions are the workhorse of any MSVC-built
 * PE: the CRT uses them for virtually every non-trivial data
 * movement, and clang itself generates direct calls to them
 * for large aggregate copies and zero-inits (`struct s = {0};`,
 * `*p = other_struct;`, etc.).
 *
 * All three implementations are byte-at-a-time loops so the
 * compiler can't "optimise" them into... calls to themselves.
 * `__attribute__((no_builtin("memset", "memcpy", "memmove")))`
 * and `-fno-builtin` on the command line cooperate to keep
 * the bodies loop-shaped.
 *
 * Build: tools/build-vcruntime140-dll.sh
 *   clang --target=x86_64-pc-windows-msvc + lld-link /dll
 *   /noentry /nodefaultlib /base:0x10030000.
 */

typedef unsigned long long size_t;

/* `(a)buf_*` annotations keep clang from "helpfully" recognising
 * the loops as memset/memcpy and turning them into tail calls
 * to themselves. -fno-builtin in the build script does the same
 * at a coarser granularity; the attributes are belt + braces. */
#define NO_BUILTIN_MEMOPS __attribute__((no_builtin("memset", "memcpy", "memmove")))

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memset(void* dst, int c, size_t n)
{
    unsigned char*      d = (unsigned char*) dst;
    const unsigned char v = (unsigned char) c;
    for (size_t i = 0; i < n; ++i)
        d[i] = v;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memcpy(void* dst, const void* src, size_t n)
{
    unsigned char*       d = (unsigned char*) dst;
    const unsigned char* s = (const unsigned char*) src;
    for (size_t i = 0; i < n; ++i)
        d[i] = s[i];
    return dst;
}

/* memmove has to handle overlap: if dst > src but dst < src+n,
 * a forward copy clobbers the source before it's read. Detect
 * the overlap-going-forward case and copy backward. */
__declspec(dllexport) NO_BUILTIN_MEMOPS void* memmove(void* dst, const void* src, size_t n)
{
    unsigned char*       d = (unsigned char*) dst;
    const unsigned char* s = (const unsigned char*) src;
    if (d == s || n == 0)
        return dst;
    if (d < s)
    {
        for (size_t i = 0; i < n; ++i)
            d[i] = s[i];
    }
    else
    {
        for (size_t i = n; i > 0; --i)
            d[i - 1] = s[i - 1];
    }
    return dst;
}
