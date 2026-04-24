/*
 * userland/libs/msvcrt/msvcrt.c
 *
 * Freestanding DuetOS msvcrt.dll — string intrinsics
 * (strlen, strcmp, strcpy, strchr, wcslen, wcscmp, wcscpy,
 * wcschr). Retires the batch-7 + 29/31 flat stubs in
 * kernel/subsystems/win32/stubs.cpp.
 *
 * All implementations are plain C loops. `-fno-builtin` +
 * `__attribute__((no_builtin(...)))` prevent clang from
 * recognising the loops as str or wcs intrinsics and turning
 * them into tail calls to themselves.
 *
 * Build: tools/build-msvcrt-dll.sh
 *   clang --target=x86_64-pc-windows-msvc + lld-link /dll
 *   /noentry /nodefaultlib /base:0x10040000.
 */

typedef unsigned long long size_t;
typedef unsigned short     wchar_t16; /* Win32 wchar_t is UTF-16, 16 bits */

/* Clang recognises a subset of the str* builtins but not every
 * wcs* name (wcscpy / wcschr aren't in its builtin list). Only
 * list the names clang actually knows; -fno-builtin on the
 * command line handles the rest. */
#define NO_BUILTIN_STR __attribute__((no_builtin("strlen", "strcmp", "strcpy", "strchr")))
#define NO_BUILTIN_WCS __attribute__((no_builtin("wcslen", "wcscmp")))

/* ------------------------------------------------------------------
 * Narrow string intrinsics (ASCII / UTF-8 bytes)
 * ------------------------------------------------------------------ */

__declspec(dllexport) NO_BUILTIN_STR size_t strlen(const char* s)
{
    size_t n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) NO_BUILTIN_STR int strcmp(const char* a, const char* b)
{
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    /* Compare as unsigned to match real Windows msvcrt's
     * contract (byte-lexicographic). */
    return (int) (unsigned char) *a - (int) (unsigned char) *b;
}

__declspec(dllexport) NO_BUILTIN_STR char* strcpy(char* dst, const char* src)
{
    char* d = dst;
    while ((*d++ = *src++) != 0) { /* copy including NUL */ }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strchr(const char* s, int c)
{
    const char ch = (char) c;
    for (;; ++s)
    {
        if (*s == ch)
            return (char*) s; /* per POSIX: strchr may match the NUL */
        if (*s == 0)
            return (char*) 0;
    }
}

/* ------------------------------------------------------------------
 * Wide string intrinsics (UTF-16LE)
 * ------------------------------------------------------------------ */

__declspec(dllexport) NO_BUILTIN_WCS size_t wcslen(const wchar_t16* s)
{
    size_t n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) NO_BUILTIN_WCS int wcscmp(const wchar_t16* a, const wchar_t16* b)
{
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    /* u16 difference cast to int (matches MS wcscmp). */
    return (int) *a - (int) *b;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcscpy(wchar_t16* dst, const wchar_t16* src)
{
    wchar_t16* d = dst;
    while ((*d++ = *src++) != 0) { /* copy including NUL16 */ }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcschr(const wchar_t16* s, wchar_t16 c)
{
    for (;; ++s)
    {
        if (*s == c)
            return (wchar_t16*) s;
        if (*s == 0)
            return (wchar_t16*) 0;
    }
}
