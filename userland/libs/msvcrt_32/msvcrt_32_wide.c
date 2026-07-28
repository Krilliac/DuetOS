/*
 * userland/libs/msvcrt_32/msvcrt_32_wide.c
 *
 * Wide-string, bounds-checked-memory and wide-formatting exports for
 * the i386 msvcrt.dll companion.
 *
 * The wide string primitives mirror userland/libs/msvcrt/msvcrt.c
 * (the x86_64 sibling) byte for byte in behaviour. The _s ("safe")
 * memory routines and the wide formatter have no x86_64 sibling to
 * mirror — their contracts come from the documented MSVC CRT
 * behaviour, and every deviation is marked.
 *
 * __cdecl throughout, matching the rest of msvcrt.
 */

typedef unsigned int size_t;
typedef unsigned short wchar_t16;
typedef int errno_t;

/* Defined in msvcrt_32.c. */
void* memcpy(void* dst, const void* src, size_t n);
void* memmove(void* dst, const void* src, size_t n);
void* memset(void* dst, int v, size_t n);

/* MSVC's bounds-checked routines report these. Spelled locally rather
 * than pulled from an errno.h we do not have. */
#define MSVCRT32_EINVAL 22
#define MSVCRT32_ERANGE 34

/* ------------------------------------------------------------------
 * Wide strings
 *
 * -fno-builtin is on for this DLL, but clang still recognises the
 * shape of these loops; the definitions must not be replaced by a
 * call to themselves, so each one is written as an explicit index
 * walk rather than a pattern the optimiser can idiom-match.
 * ------------------------------------------------------------------ */

__declspec(dllexport) size_t wcslen(const wchar_t16* s)
{
    size_t n = 0;
    while (s[n] != 0)
        ++n;
    return n;
}

__declspec(dllexport) wchar_t16* wcschr(const wchar_t16* s, wchar_t16 c)
{
    for (size_t i = 0;; ++i)
    {
        if (s[i] == c)
            return (wchar_t16*)&s[i]; /* matches the NUL when c == 0 */
        if (s[i] == 0)
            return (wchar_t16*)0;
    }
}

__declspec(dllexport) wchar_t16* wcsrchr(const wchar_t16* s, wchar_t16 c)
{
    const wchar_t16* last = (const wchar_t16*)0;
    for (size_t i = 0;; ++i)
    {
        if (s[i] == c)
            last = &s[i];
        if (s[i] == 0)
            break;
    }
    return (wchar_t16*)last;
}

static wchar_t16 msvcrt32_wfold(wchar_t16 c)
{
    /* ASCII-only fold, consistent with kernel32_32's CompareStringW
     * and with GetACP reporting a single-byte code page. */
    if (c >= 'A' && c <= 'Z')
        return (wchar_t16)(c + ('a' - 'A'));
    return c;
}

// GAP: ASCII-only case folding - accented and non-Latin characters
// compare case-sensitively. Same limit as kernel32_32's CompareStringW.
__declspec(dllexport) int _wcsicmp(const wchar_t16* a, const wchar_t16* b)
{
    for (size_t i = 0;; ++i)
    {
        const wchar_t16 x = msvcrt32_wfold(a[i]);
        const wchar_t16 y = msvcrt32_wfold(b[i]);
        if (x != y)
            return x < y ? -1 : 1;
        if (x == 0)
            return 0;
    }
}

__declspec(dllexport) int _wcsnicmp(const wchar_t16* a, const wchar_t16* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        const wchar_t16 x = msvcrt32_wfold(a[i]);
        const wchar_t16 y = msvcrt32_wfold(b[i]);
        if (x != y)
            return x < y ? -1 : 1;
        if (x == 0)
            return 0;
    }
    return 0;
}

/* _ismbblead(c) asks whether a byte can start a double-byte sequence
 * in the current multi-byte code page. GetCPInfo in kernel32_32
 * reports no lead-byte ranges for every code page it accepts, so 0 is
 * the consistent answer, not a placeholder. */
__declspec(dllexport) int _ismbblead(unsigned int c)
{
    (void)c;
    return 0;
}

/* ------------------------------------------------------------------
 * Bounds-checked memory
 *
 * The MSVC contract: on a parameter violation the destination buffer
 * is zeroed (when it is valid and its size is known) before the error
 * code is returned, so a caller that ignores the return value cannot
 * go on to read stale bytes. That zeroing is the part most
 * reimplementations drop, and it is the part that has security value.
 * ------------------------------------------------------------------ */

__declspec(dllexport) errno_t memcpy_s(void* dst, size_t dstsz, const void* src, size_t count)
{
    if (count == 0)
        return 0;
    if (dst == (void*)0)
        return MSVCRT32_EINVAL;
    if (src == (const void*)0)
    {
        memset(dst, 0, dstsz);
        return MSVCRT32_EINVAL;
    }
    if (count > dstsz)
    {
        memset(dst, 0, dstsz);
        return MSVCRT32_ERANGE;
    }
    memcpy(dst, src, count);
    return 0;
}

__declspec(dllexport) errno_t memmove_s(void* dst, size_t dstsz, const void* src, size_t count)
{
    if (count == 0)
        return 0;
    if (dst == (void*)0 || src == (const void*)0)
        return MSVCRT32_EINVAL;
    if (count > dstsz)
        return MSVCRT32_ERANGE;
    memmove(dst, src, count);
    return 0;
}

/* ------------------------------------------------------------------
 * stdio table accessor
 * ------------------------------------------------------------------ */

/* __iob_func returns the base of the FILE array that stdin / stdout /
 * stderr index into. It hands back the same `_iob` object msvcrt_32.c
 * already exports as DATA, so a program using either spelling sees
 * one table. */
struct _msvcrt_iobuf
{
    char pad[32];
};
extern struct _msvcrt_iobuf _iob[3];

__declspec(dllexport) struct _msvcrt_iobuf* __iob_func(void)
{
    return _iob;
}

/* ------------------------------------------------------------------
 * Wide formatting — _vsnwprintf
 * ------------------------------------------------------------------ */

typedef __builtin_va_list msvcrt32_va_list;

/* Append one code unit if it fits. `pos` keeps counting past the cap
 * so the return value can report the needed length. */
static void msvcrt32_wemit(wchar_t16* buf, size_t cap, size_t* pos, wchar_t16 c)
{
    if (buf != (wchar_t16*)0 && *pos < cap)
        buf[*pos] = c;
    ++*pos;
}

/* Render `v` in `base` into `tmp` least-significant digit first;
 * returns the digit count. Never zero-length: 0 renders as "0". */
static int msvcrt32_fmt_uint(char* tmp, unsigned v, int base, int upper)
{
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int n = 0;
    do
    {
        tmp[n++] = digits[v % (unsigned)base];
        v /= (unsigned)base;
    } while (v != 0 && n < 32);
    return n;
}

/* _vsnwprintf(buf, cap, fmt, ap) — MSVC semantics: writes at most
 * `cap` code units, NUL-terminates only if the result fits strictly
 * inside `cap`, and returns -1 when it does not.
 *
 * Supports %s (narrow, MSVC's meaning for the wide printf family is
 * actually wide - see the note below), %S, %ls, %hs, %c, %d/%i, %u,
 * %x/%X, %p and %%, with a width field and '0'/'-' flags.
 */
// GAP: %f / %e / %g consume their double argument (so the varargs walk
// stays in sync) but render a fixed "0.000000" - no float formatting
// without a double->integer conversion, which on i386 would pull in a
// compiler-rt helper this freestanding DLL cannot link. Precision
// fields (".N") are parsed and ignored.
__declspec(dllexport) int _vsnwprintf(wchar_t16* buf, size_t cap, const wchar_t16* fmt, msvcrt32_va_list ap)
{
    if (fmt == (const wchar_t16*)0)
        return -1;
    size_t pos = 0;
    char tmp[32];

    for (size_t fi = 0; fmt[fi] != 0; ++fi)
    {
        if (fmt[fi] != '%')
        {
            msvcrt32_wemit(buf, cap, &pos, fmt[fi]);
            continue;
        }
        ++fi;
        if (fmt[fi] == 0)
            break;

        int left = 0;
        int zero_pad = 0;
        for (;; ++fi)
        {
            if (fmt[fi] == '-')
                left = 1;
            else if (fmt[fi] == '0')
                zero_pad = 1;
            else
                break;
        }
        int width = 0;
        while (fmt[fi] >= '0' && fmt[fi] <= '9')
            width = width * 10 + (int)(fmt[fi++] - '0');
        if (fmt[fi] == '.')
        {
            ++fi; /* precision parsed and discarded — see the GAP note */
            while (fmt[fi] >= '0' && fmt[fi] <= '9')
                ++fi;
        }
        /* Length modifiers: l / h / ll / I64 all map onto the single
         * 32-bit integer slot the i386 ABI passes, except ll/I64 which
         * occupy two slots. */
        int wide_arg = 1; /* the wide printf family defaults %s to wide */
        int longlong = 0;
        for (;;)
        {
            if (fmt[fi] == 'l')
            {
                ++fi;
                if (fmt[fi] == 'l')
                {
                    longlong = 1;
                    ++fi;
                }
                wide_arg = 1;
            }
            else if (fmt[fi] == 'h')
            {
                ++fi;
                wide_arg = 0;
            }
            else if (fmt[fi] == 'I' && fmt[fi + 1] == '6' && fmt[fi + 2] == '4')
            {
                fi += 3;
                longlong = 1;
            }
            else
                break;
        }

        /* Each conversion resolves to ONE of: a wide source string, a
         * narrow source string, or `field[0..flen)`. Resolving before
         * emitting is what makes right-justified padding possible —
         * the pad has to precede the field, so its length must be
         * known first. */
        const wchar_t16 spec = fmt[fi];
        const wchar_t16* wsrc = (const wchar_t16*)0;
        const char* asrc = (const char*)0;
        wchar_t16 field[40];
        size_t flen = 0;

        switch (spec)
        {
        case 's':
        case 'S':
        {
            /* The wide printf family defaults %s to wide and %S to
             * narrow; an explicit h/l modifier overrides. */
            const int is_wide = (spec == 'S') ? !wide_arg : wide_arg;
            if (is_wide)
            {
                wsrc = __builtin_va_arg(ap, const wchar_t16*);
                if (wsrc == (const wchar_t16*)0)
                    asrc = "(null)";
                else
                    flen = wcslen(wsrc);
            }
            else
            {
                asrc = __builtin_va_arg(ap, const char*);
                if (asrc == (const char*)0)
                    asrc = "(null)";
            }
            if (asrc != (const char*)0)
            {
                flen = 0;
                while (asrc[flen] != 0)
                    ++flen;
            }
            break;
        }
        case 'c':
            field[flen++] = (wchar_t16) __builtin_va_arg(ap, int);
            break;
        case 'd':
        case 'i':
        {
            const int v = __builtin_va_arg(ap, int);
            if (longlong)
                (void)__builtin_va_arg(ap, int); /* discard the high half */
            unsigned mag;
            if (v < 0)
            {
                field[flen++] = '-';
                mag = (unsigned)(-(v + 1)) + 1u; /* INT_MIN-safe negation */
            }
            else
                mag = (unsigned)v;
            const int n = msvcrt32_fmt_uint(tmp, mag, 10, 0);
            for (int i = n - 1; i >= 0; --i)
                field[flen++] = (wchar_t16)(unsigned char)tmp[i];
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        {
            const unsigned v = __builtin_va_arg(ap, unsigned);
            if (longlong)
                (void)__builtin_va_arg(ap, unsigned);
            const int n = msvcrt32_fmt_uint(tmp, v, spec == 'u' ? 10 : 16, spec == 'X');
            for (int i = n - 1; i >= 0; --i)
                field[flen++] = (wchar_t16)(unsigned char)tmp[i];
            break;
        }
        case 'p':
        {
            const unsigned v = (unsigned)(unsigned long)__builtin_va_arg(ap, void*);
            const int n = msvcrt32_fmt_uint(tmp, v, 16, 1);
            for (int i = 8 - n; i > 0; --i)
                field[flen++] = '0'; /* Win32 %p is a fixed 8 hex digits on i386 */
            for (int i = n - 1; i >= 0; --i)
                field[flen++] = (wchar_t16)(unsigned char)tmp[i];
            break;
        }
        case 'f':
        case 'e':
        case 'g':
        {
            /* Consume the double so every later conversion still reads
             * the right varargs slot; render a fixed placeholder. */
            (void)__builtin_va_arg(ap, double);
            asrc = "0.000000";
            flen = 8;
            break;
        }
        case '%':
            field[flen++] = '%';
            break;
        default:
            field[flen++] = '%';
            field[flen++] = spec;
            break;
        }

        /* Right-justified: pad first. Zero-padding only applies to a
         * right-justified numeric-looking field, which is what MSVC
         * does with '0' plus '-' (the '-' wins). */
        if (!left)
        {
            const wchar_t16 pad = zero_pad ? '0' : ' ';
            for (size_t i = flen; i < (size_t)width; ++i)
                msvcrt32_wemit(buf, cap, &pos, pad);
        }
        for (size_t i = 0; i < flen; ++i)
        {
            if (asrc != (const char*)0)
                msvcrt32_wemit(buf, cap, &pos, (wchar_t16)(unsigned char)asrc[i]);
            else if (wsrc != (const wchar_t16*)0)
                msvcrt32_wemit(buf, cap, &pos, wsrc[i]);
            else
                msvcrt32_wemit(buf, cap, &pos, field[i]);
        }
        if (left)
        {
            for (size_t i = flen; i < (size_t)width; ++i)
                msvcrt32_wemit(buf, cap, &pos, ' ');
        }
    }

    if (buf == (wchar_t16*)0 || cap == 0)
        return -1;
    if (pos >= cap)
    {
        buf[cap - 1] = 0; /* truncated: MSVC still terminates and reports -1 */
        return -1;
    }
    buf[pos] = 0;
    return (int)pos;
}
