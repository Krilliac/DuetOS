#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * Virtual memory
 *
 * SYS_VMAP   = 28 — bump-allocate `size` bytes (page-rounded)
 *              from the per-process vmap arena, return VA.
 * SYS_VUNMAP = 29 — release a (va, size) range; returns 0 on
 *              hit, -1 if outside the arena.
 *
 * Both ignore Win32's lpAddress / flAllocationType / flProtect
 * args today. v0 vmap pages are always RW+NX (W^X), so
 * VirtualProtect is a no-op that just round-trips the previous
 * protection value to keep CRT-startup probe round-trips happy.
 * ------------------------------------------------------------------ */

typedef unsigned long long SIZE_T;
typedef unsigned int PROT;

__declspec(dllexport) void* VirtualAlloc(void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    /* MEM_WRITE_WATCH (0x00200000) requires the kernel to track
     * which pages have been written since the alloc — we don't
     * have that bookkeeping. Reject explicitly so callers fall
     * back to a non-watched allocation rather than silently
     * receiving a region that won't honour GetWriteWatch. */
    if ((flAllocationType & 0x00200000u) != 0)
        return (void*)0;
    /* T5-01 partial: route through SYS_VIRTUAL_ALLOC (199) which
     * tracks regions, honours reserve/commit, and respects
     * flProtect. Default flAllocationType = 0 (no flag) acts
     * like real Windows MEM_RESERVE|MEM_COMMIT — alloc-and-commit.
     * Default flProtect = 0 maps to PAGE_READWRITE. */
    DWORD alloc_type = flAllocationType;
    if ((alloc_type & 0x3000u) == 0) /* neither MEM_COMMIT nor MEM_RESERVE */
        alloc_type |= 0x1000u | 0x2000u;
    DWORD prot = flProtect;
    if (prot == 0)
        prot = 0x04u; /* PAGE_READWRITE */
    /* SYS_VIRTUAL_ALLOC reads r10 for the hint VA. GCC/Clang's
     * register asm syntax pins a specific register across the
     * inline asm so r10 lands where the kernel expects. */
    register long long _r10 asm("r10") = (long long)(unsigned long long)(UINT_PTR)lpAddress;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)199), /* SYS_VIRTUAL_ALLOC */
                       "D"((long long)dwSize), "S"((long long)alloc_type), "d"((long long)prot), "r"(_r10)
                     : "memory");
    return (void*)rv;
}

/* VirtualAllocEx ignores the extra HANDLE arg in v0 (the flat
 * stub aliases this to VirtualAlloc — same here). */
__declspec(dllexport) void* VirtualAllocEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD flAllocationType,
                                           DWORD flProtect)
{
    (void)hProcess;
    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) BOOL VirtualFree(void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    /* T5-01 partial: route through SYS_VIRTUAL_FREE (200) which
     * honours MEM_DECOMMIT (0x4000) vs MEM_RELEASE (0x8000).
     * If neither flag is set, default to MEM_RELEASE — caller's
     * intent matches Win32's "release everything" pattern. */
    DWORD ft = dwFreeType;
    if ((ft & 0xC000u) == 0)
        ft |= 0x8000u;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)200), /* SYS_VIRTUAL_FREE */
                       "D"((long long)lpAddress), "S"((long long)dwSize), "d"((long long)ft)
                     : "memory");
    return rv != 0;
}

__declspec(dllexport) BOOL VirtualFreeEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    (void)hProcess;
    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

__declspec(dllexport) BOOL VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
    /* T5-01 partial: route through SYS_VIRTUAL_PROTECT (201). The
     * kernel-side handler updates the page tables for committed
     * pages and writes the previous protection into the caller's
     * out pointer. Pages outside the W^X envelope (any
     * PAGE_EXECUTE_*) are rejected with rax=0. */
    register long long _r10 asm("r10") = (long long)(unsigned long long)(UINT_PTR)lpflOldProtect;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)201), /* SYS_VIRTUAL_PROTECT */
                       "D"((long long)lpAddress), "S"((long long)dwSize), "d"((long long)flNewProtect), "r"(_r10)
                     : "memory");
    return rv != 0;
}

__declspec(dllexport) BOOL VirtualProtectEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD flNewProtect,
                                            DWORD* lpflOldProtect)
{
    (void)hProcess;
    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

/* ------------------------------------------------------------------
 * lstr* family — Windows' historic string helpers,
 * still imported by older / port-compat code paths in real
 * MSVC PEs. Same semantics as str / wcs intrinsics without
 * the SEH wrappers real Windows applies on top.
 * ------------------------------------------------------------------ */

#define NO_BUILTIN_LSTR __attribute__((no_builtin("strlen", "strcmp", "strcpy")))

__declspec(dllexport) NO_BUILTIN_LSTR int lstrlenA(const char* s)
{
    if (s == (const char*)0)
        return 0; /* lstrlenA NUL-input returns 0, not crash */
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) NO_BUILTIN_LSTR int lstrcmpA(const char* a, const char* b)
{
    if (a == (const char*)0 || b == (const char*)0)
        return (a == b) ? 0 : (a == (const char*)0 ? -1 : 1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

__declspec(dllexport) NO_BUILTIN_LSTR int lstrcmpiA(const char* a, const char* b)
{
    if (a == (const char*)0 || b == (const char*)0)
        return (a == b) ? 0 : (a == (const char*)0 ? -1 : 1);
    for (;; ++a, ++b)
    {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
    }
}

__declspec(dllexport) NO_BUILTIN_LSTR char* lstrcpyA(char* dst, const char* src)
{
    if (dst == (char*)0 || src == (const char*)0)
        return dst;
    char* d = dst;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL */
    }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_LSTR char* lstrcatA(char* dst, const char* src)
{
    if (dst == (char*)0 || src == (const char*)0)
        return dst;
    char* d = dst;
    while (*d != 0)
        ++d;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL */
    }
    return dst;
}

typedef unsigned short wchar_t16; /* Win32 wchar_t is UTF-16 */

__declspec(dllexport) int lstrlenW(const wchar_t16* s)
{
    if (s == (const WCHAR_t*)0)
        return 0;
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) int lstrcmpW(const wchar_t16* a, const wchar_t16* b)
{
    if (a == (const WCHAR_t*)0 || b == (const WCHAR_t*)0)
        return (a == b) ? 0 : (a == (const WCHAR_t*)0 ? -1 : 1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)*a - (int)*b;
}

__declspec(dllexport) int lstrcmpiW(const wchar_t16* a, const wchar_t16* b)
{
    if (a == (const WCHAR_t*)0 || b == (const WCHAR_t*)0)
        return (a == b) ? 0 : (a == (const WCHAR_t*)0 ? -1 : 1);
    for (;; ++a, ++b)
    {
        wchar_t16 ca = *a;
        wchar_t16 cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16)(cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int)ca - (int)cb;
    }
}

__declspec(dllexport) wchar_t16* lstrcpyW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*)0 || src == (const WCHAR_t*)0)
        return dst;
    wchar_t16* d = dst;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL */
    }
    return dst;
}

/* ------------------------------------------------------------------
 * MulDiv — kernel32 integer scale helper.
 *
 * Computes (nNumber * nNumerator) / nDenominator, rounding the result
 * to the nearest integer (ties away from zero), using a 64-bit
 * intermediate so the product can't overflow before the divide. This
 * is the canonical DPI / GDI scaling primitive (e.g.
 * MulDiv(value, dpi, 96)) that real Win32 PEs import directly from
 * kernel32 — it was MISSING, so any PE importing it failed to load.
 * Returns -1 on a zero denominator or when the rounded result doesn't
 * fit in a signed 32-bit int (matches Windows). Mirrors the
 * ReactOS/Wine implementation.
 * ------------------------------------------------------------------ */
__declspec(dllexport) int MulDiv(int nNumber, int nNumerator, int nDenominator)
{
    long long product;
    if (nDenominator == 0)
        return -1;
    product = (long long)nNumber * (long long)nNumerator;
    /* Round to nearest, ties away from zero — add/sub half the
     * denominator with the sign of the product before truncating. */
    if (product >= 0)
        product += nDenominator / 2;
    else
        product -= nDenominator / 2;
    product /= nDenominator;
    if (product > 2147483647LL || product < (-2147483647LL - 1))
        return -1;
    return (int)product;
}
