/*
 * userland/libs/kernel32_32/kernel32_32_nls.h
 *
 * The pure code-page / collation core of the i386 (PE32) kernel32
 * companion. Freestanding: no libc, no kernel headers, no syscalls —
 * every function below is a total function of its arguments, which is
 * what lets tests/host/test_kernel32_32_nls.cpp exercise the real
 * conversion logic instead of a re-typed copy of it.
 *
 * kernel32_32_nls.c wraps each of these in the __stdcall export the
 * PE32 importer binds to; the wrapper adds nothing but the calling
 * convention.
 *
 * Semantics are mirrored from the x86_64 sibling
 * (userland/libs/kernel32/kernel32_sync.c for the conversions,
 * kernel32_io.c for CompareStringW) so a guest sees the same answers
 * whichever bitness it runs at.
 *
 * GAP: the conversions are 1:1 byte <-> UTF-16 code unit and ignore
 * the requested code page entirely. Correct for ASCII, correct for
 * Latin-1 (which is what GetACP reports, 1252), wrong for UTF-8
 * (65001) multi-byte sequences and for any DBCS page. Revisit when a
 * real code-page table lands; GetCPInfo already advertises no DBCS
 * lead-byte ranges, so the two are at least consistent today.
 */

#ifndef DUETOS_KERNEL32_32_NLS_H
#define DUETOS_KERNEL32_32_NLS_H

/* CSTR_* return codes for the CompareString family. */
#define DUET32_CSTR_LESS_THAN 1
#define DUET32_CSTR_EQUAL 2
#define DUET32_CSTR_GREATER_THAN 3

/* NORM_IGNORECASE — the one dwCmpFlags bit we honour. */
#define DUET32_NORM_IGNORECASE 0x00000001u

/* Measure a possibly-NUL-terminated input the way the Win32 NLS
 * functions do: a negative count means "walk to the NUL and include
 * it in the result", a non-negative count is taken verbatim. */
static inline int Duet32NlsInputLenA(const char* s, int count)
{
    if (count >= 0)
        return count;
    int n = 0;
    while (s[n] != 0)
        ++n;
    return n + 1; /* include the terminator, as Win32 does for -1 */
}

static inline int Duet32NlsInputLenW(const unsigned short* s, int count)
{
    if (count >= 0)
        return count;
    int n = 0;
    while (s[n] != 0)
        ++n;
    return n + 1;
}

/* MultiByteToWideChar core. A zero destination capacity (or a NULL
 * destination) is the documented "how big a buffer do I need?" query
 * and returns the required count without writing anything. */
// GAP: an undersized (but non-zero) destination truncates and reports
// the truncated count; Windows returns 0 and sets
// ERROR_INSUFFICIENT_BUFFER. Mirrors the x86_64 sibling's choice so
// the two bitnesses agree; revisit together with it.
static inline int Duet32MultiByteToWideChar(const char* src, int src_len, unsigned short* dst, int dst_cap)
{
    if (src == (const char*)0)
        return 0;
    const int in_len = Duet32NlsInputLenA(src, src_len);
    if (dst_cap == 0 || dst == (unsigned short*)0)
        return in_len;
    const int copy = in_len < dst_cap ? in_len : dst_cap;
    for (int i = 0; i < copy; ++i)
        dst[i] = (unsigned short)(unsigned char)src[i];
    return copy;
}

/* WideCharToMultiByte core. Same size-query convention. */
static inline int Duet32WideCharToMultiByte(const unsigned short* src, int src_len, char* dst, int dst_cap)
{
    if (src == (const unsigned short*)0)
        return 0;
    const int in_len = Duet32NlsInputLenW(src, src_len);
    if (dst_cap == 0 || dst == (char*)0)
        return in_len;
    const int copy = in_len < dst_cap ? in_len : dst_cap;
    for (int i = 0; i < copy; ++i)
        dst[i] = (char)(src[i] & 0xFF);
    return copy;
}

/* Ordinal UTF-16 comparison, optionally folding A-Z to a-z. Returns a
 * CSTR_* code, or 0 for an invalid argument — the Win32 error value.
 *
 * Ordinal (not locale-collated) is the documented behaviour for
 * LOCALE_INVARIANT / LOCALE_NEUTRAL, which is what this DLL reports
 * everywhere, so callers passing those get exactly what Windows
 * would give them.
 */
// GAP: no collation tables - a caller passing a real LCID gets ordinal
// order, which differs from Windows for accented and non-Latin text.
static inline int Duet32CompareStringW(unsigned int flags, const unsigned short* a, int a_len, const unsigned short* b,
                                       int b_len)
{
    if (a == (const unsigned short*)0 || b == (const unsigned short*)0)
        return 0;
    int n1 = a_len;
    if (n1 < 0)
    {
        n1 = 0;
        while (a[n1] != 0)
            ++n1;
    }
    int n2 = b_len;
    if (n2 < 0)
    {
        n2 = 0;
        while (b[n2] != 0)
            ++n2;
    }
    const int n = n1 < n2 ? n1 : n2;
    const int fold = (flags & DUET32_NORM_IGNORECASE) != 0;
    for (int i = 0; i < n; ++i)
    {
        unsigned short x = a[i];
        unsigned short y = b[i];
        if (fold)
        {
            if (x >= 'A' && x <= 'Z')
                x = (unsigned short)(x + ('a' - 'A'));
            if (y >= 'A' && y <= 'Z')
                y = (unsigned short)(y + ('a' - 'A'));
        }
        if (x < y)
            return DUET32_CSTR_LESS_THAN;
        if (x > y)
            return DUET32_CSTR_GREATER_THAN;
    }
    if (n1 < n2)
        return DUET32_CSTR_LESS_THAN;
    if (n1 > n2)
        return DUET32_CSTR_GREATER_THAN;
    return DUET32_CSTR_EQUAL;
}

#endif /* DUETOS_KERNEL32_32_NLS_H */
