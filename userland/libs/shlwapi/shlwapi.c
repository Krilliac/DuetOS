/*
 * userland/libs/shlwapi/shlwapi.c
 *
 * Freestanding DuetOS shlwapi.dll. 16 Path* / Str* string
 * helpers — almost all pure-C loops. PathFileExistsA/W is the
 * one exception: it issues SYS_FILE_QUERY_ATTRIBUTES (= 151) so
 * a real existence check works against the kernel's mounted
 * filesystems instead of unconditionally returning FALSE.
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned short wchar_t16;
typedef unsigned long long size_t;

#define NO_BUILTIN_LOOPS __attribute__((no_builtin("strlen", "strcmp", "strstr")))

static size_t wlen(const wchar_t16* s)
{
    size_t n = 0;
    while (s && s[n])
        ++n;
    return n;
}

static size_t alen(const char* s)
{
    size_t n = 0;
    while (s && s[n])
        ++n;
    return n;
}

/* Path* narrow */

/* Translate a Win32 path prefix to the kernel's "/disk/N" form.
 * Inline mirror of kernel32::Win32PathPrefixA so shlwapi keeps
 * its build-time independence from kernel32. Returns the number
 * of bytes consumed from `in`. */
static unsigned long path_xlat_prefix(const char* in, char* out, unsigned long out_cap, unsigned long* out_written)
{
    *out_written = 0;
    if (out_cap == 0)
        return 0;
    out[0] = 0;
    unsigned long ci = 0;
    /* Strip "\\?\" extended-length prefix(es). */
    for (;;)
    {
        if ((in[ci] == '\\' || in[ci] == '/') && (in[ci + 1] == '\\' || in[ci + 1] == '/') && in[ci + 2] == '?' &&
            (in[ci + 3] == '\\' || in[ci + 3] == '/'))
            ci += 4;
        else
            break;
    }
    char letter = in[ci];
    if (((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')) && in[ci + 1] == ':')
    {
        char upper = (letter >= 'a' && letter <= 'z') ? (char)(letter - 'a' + 'A') : letter;
        int idx = (upper < 'C') ? 0 : (upper - 'C');
        const char* prefix = "/disk/";
        unsigned long pi = 0;
        while (prefix[pi] && pi + 1 < out_cap)
        {
            out[pi] = prefix[pi];
            ++pi;
        }
        if (pi + 1 < out_cap)
        {
            if (idx >= 10)
                out[pi++] = (char)('0' + (idx / 10));
            if (pi + 1 < out_cap)
                out[pi++] = (char)('0' + (idx % 10));
        }
        out[pi] = 0;
        *out_written = pi;
        ci += 2;
    }
    return ci;
}

static void path_xlat_full(const char* in, char* out, unsigned long out_cap)
{
    if (out_cap == 0)
        return;
    unsigned long prefix_len = 0;
    unsigned long consumed = path_xlat_prefix(in, out, out_cap, &prefix_len);
    in += consumed;
    unsigned long ci = prefix_len;
    while (in[0] != 0 && ci + 1 < out_cap)
    {
        char c = (in[0] == '\\') ? '/' : in[0];
        out[ci] = c;
        ++ci;
        ++in;
    }
    out[ci] = 0;
}

__declspec(dllexport) BOOL PathFileExistsA(const char* p)
{
    if (!p)
        return 0;
    char kpath[256];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    path_xlat_full(p, kpath, sizeof(kpath));
    int len = 0;
    while (kpath[len] != 0 && len < 255)
        ++len;
    if (len == 0)
        return 0;
    /* SYS_FILE_QUERY_ATTRIBUTES = 151. Out-buffer = 56-byte
     * FILE_NETWORK_OPEN_INFORMATION blob; we ignore the contents
     * and just check the NTSTATUS return. */
    unsigned char info[56];
    long long status;
    register long long r10 __asm__("r10") = (long long)sizeof(info);
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)kpath), "S"((long long)len), "d"((long long)info), "r"(r10)
                     : "memory");
    return status == 0 ? 1 : 0;
}

__declspec(dllexport) char* PathFindExtensionA(const char* p)
{
    if (!p)
        return (char*)0;
    size_t n = alen(p);
    const char* dot = (const char*)0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '.')
            dot = p + i;
    return (char*)(dot ? dot : p + n);
}

__declspec(dllexport) char* PathFindFileNameA(const char* p)
{
    if (!p)
        return (char*)0;
    size_t n = alen(p);
    size_t last_sep = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i + 1;
    return (char*)(p + last_sep);
}

/* Path* wide */

__declspec(dllexport) BOOL PathFileExistsW(const wchar_t16* p)
{
    if (!p)
        return 0;
    char ascii[256];
    int i = 0;
    while (i < 255 && p[i] != 0)
    {
        ascii[i] = (char)(p[i] & 0xFF);
        ++i;
    }
    ascii[i] = 0;
    return PathFileExistsA(ascii);
}

__declspec(dllexport) wchar_t16* PathFindExtensionW(const wchar_t16* p)
{
    if (!p)
        return (wchar_t16*)0;
    size_t n = wlen(p);
    const wchar_t16* dot = (const wchar_t16*)0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '.')
            dot = p + i;
    return (wchar_t16*)(dot ? dot : p + n);
}

__declspec(dllexport) wchar_t16* PathFindFileNameW(const wchar_t16* p)
{
    if (!p)
        return (wchar_t16*)0;
    size_t n = wlen(p);
    size_t last_sep = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i + 1;
    return (wchar_t16*)(p + last_sep);
}

__declspec(dllexport) BOOL PathIsDirectoryW(const wchar_t16* p)
{
    (void)p;
    return 0; /* Nothing is a directory since nothing exists. */
}

__declspec(dllexport) BOOL PathRemoveFileSpecW(wchar_t16* p)
{
    if (!p)
        return 0;
    size_t n = wlen(p);
    size_t last_sep = (size_t)-1;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i;
    if (last_sep == (size_t)-1)
        return 0;
    p[last_sep] = 0;
    return 1;
}

__declspec(dllexport) void PathStripPathW(wchar_t16* p)
{
    if (!p)
        return;
    size_t n = wlen(p);
    size_t last_sep = 0;
    int found = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
        {
            last_sep = i + 1;
            found = 1;
        }
    if (!found)
        return;
    size_t j = 0;
    for (size_t i = last_sep; i <= n; ++i)
        p[j++] = p[i];
}

__declspec(dllexport) BOOL PathAddBackslashW(wchar_t16* p)
{
    if (!p)
        return 0;
    size_t n = wlen(p);
    if (n > 0 && (p[n - 1] == '\\' || p[n - 1] == '/'))
        return 1;
    p[n] = '\\';
    p[n + 1] = 0;
    return 1;
}

__declspec(dllexport) BOOL PathAppendW(wchar_t16* dst, const wchar_t16* more)
{
    if (!dst || !more)
        return 0;
    PathAddBackslashW(dst);
    size_t j = wlen(dst);
    for (size_t i = 0; more[i]; ++i)
        dst[j + i] = more[i];
    dst[j + wlen(more)] = 0;
    return 1;
}

__declspec(dllexport) wchar_t16* PathCombineW(wchar_t16* dst, const wchar_t16* base, const wchar_t16* tail)
{
    if (!dst)
        return (wchar_t16*)0;
    if (base)
    {
        size_t i;
        for (i = 0; base[i]; ++i)
            dst[i] = base[i];
        dst[i] = 0;
    }
    else
        dst[0] = 0;
    if (tail)
    {
        PathAddBackslashW(dst);
        size_t j = wlen(dst);
        for (size_t i = 0; tail[i]; ++i)
            dst[j + i] = tail[i];
        dst[j + wlen(tail)] = 0;
    }
    return dst;
}

/* Str* */

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpW(const wchar_t16* a, const wchar_t16* b)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)*a - (int)*b;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpNW(const wchar_t16* a, const wchar_t16* b, int n)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    for (int i = 0; i < n; ++i)
    {
        if (!a[i] || a[i] != b[i])
            return (int)a[i] - (int)b[i];
    }
    return 0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS wchar_t16* StrStrW(const wchar_t16* haystack, const wchar_t16* needle)
{
    if (!haystack || !needle)
        return (wchar_t16*)0;
    if (!needle[0])
        return (wchar_t16*)haystack;
    for (size_t i = 0; haystack[i]; ++i)
    {
        size_t j = 0;
        while (needle[j] && haystack[i + j] == needle[j])
            ++j;
        if (!needle[j])
            return (wchar_t16*)(haystack + i);
    }
    return (wchar_t16*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS wchar_t16* StrStrIW(const wchar_t16* haystack, const wchar_t16* needle)
{
    if (!haystack || !needle)
        return (wchar_t16*)0;
    if (!needle[0])
        return (wchar_t16*)haystack;
    for (size_t i = 0; haystack[i]; ++i)
    {
        size_t j = 0;
        while (needle[j])
        {
            wchar_t16 h = haystack[i + j];
            wchar_t16 n = needle[j];
            if (h >= 'A' && h <= 'Z')
                h = (wchar_t16)(h + ('a' - 'A'));
            if (n >= 'A' && n <= 'Z')
                n = (wchar_t16)(n + ('a' - 'A'));
            if (h != n)
                break;
            ++j;
        }
        if (!needle[j])
            return (wchar_t16*)(haystack + i);
    }
    return (wchar_t16*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpIW(const wchar_t16* a, const wchar_t16* b)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *b)
    {
        wchar_t16 ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16)(cb + ('a' - 'A'));
        if (ca != cb)
            return (int)ca - (int)cb;
        ++a;
        ++b;
    }
    return (int)*a - (int)*b;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpNIW(const wchar_t16* a, const wchar_t16* b, int n)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    for (int i = 0; i < n; ++i)
    {
        wchar_t16 ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16)(cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int)ca - (int)cb;
    }
    return 0;
}

/* ---- ANSI string helpers ---- */

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpA(const char* a, const char* b)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpNA(const char* a, const char* b, int n)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    for (int i = 0; i < n; ++i)
    {
        if (!a[i] || a[i] != b[i])
            return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    }
    return 0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpIA(const char* a, const char* b)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpNIA(const char* a, const char* b, int n)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    for (int i = 0; i < n; ++i)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
    }
    return 0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS char* StrStrA(const char* haystack, const char* needle)
{
    if (!haystack || !needle)
        return (char*)0;
    if (!needle[0])
        return (char*)haystack;
    for (size_t i = 0; haystack[i]; ++i)
    {
        size_t j = 0;
        while (needle[j] && haystack[i + j] == needle[j])
            ++j;
        if (!needle[j])
            return (char*)(haystack + i);
    }
    return (char*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS char* StrStrIA(const char* haystack, const char* needle)
{
    if (!haystack || !needle)
        return (char*)0;
    if (!needle[0])
        return (char*)haystack;
    for (size_t i = 0; haystack[i]; ++i)
    {
        size_t j = 0;
        while (needle[j])
        {
            char h = haystack[i + j];
            char n = needle[j];
            if (h >= 'A' && h <= 'Z')
                h = (char)(h + ('a' - 'A'));
            if (n >= 'A' && n <= 'Z')
                n = (char)(n + ('a' - 'A'));
            if (h != n)
                break;
            ++j;
        }
        if (!needle[j])
            return (char*)(haystack + i);
    }
    return (char*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS char* StrChrA(const char* s, int c)
{
    if (!s)
        return (char*)0;
    while (*s)
    {
        if (*s == (char)c)
            return (char*)s;
        ++s;
    }
    return (c == 0) ? (char*)s : (char*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS wchar_t16* StrChrW(const wchar_t16* s, wchar_t16 c)
{
    if (!s)
        return (wchar_t16*)0;
    while (*s)
    {
        if (*s == c)
            return (wchar_t16*)s;
        ++s;
    }
    return (c == 0) ? (wchar_t16*)s : (wchar_t16*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS char* StrRChrA(const char* s, const char* end, int c)
{
    if (!s)
        return (char*)0;
    if (!end)
        end = s + alen(s);
    const char* p = end;
    while (p > s)
    {
        --p;
        if (*p == (char)c)
            return (char*)p;
    }
    return (char*)0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS wchar_t16* StrRChrW(const wchar_t16* s, const wchar_t16* end, wchar_t16 c)
{
    if (!s)
        return (wchar_t16*)0;
    if (!end)
        end = s + wlen(s);
    const wchar_t16* p = end;
    while (p > s)
    {
        --p;
        if (*p == c)
            return (wchar_t16*)p;
    }
    return (wchar_t16*)0;
}

/* ---- Path predicates / mutators (pure logic) ---- */

/* Relative iff first character isn't '\\' or '/' AND not "X:" drive. */
__declspec(dllexport) BOOL PathIsRelativeA(const char* p)
{
    if (!p || !p[0])
        return 1;
    if (p[0] == '\\' || p[0] == '/')
        return 0;
    if (p[1] == ':')
        return 0;
    return 1;
}

__declspec(dllexport) BOOL PathIsRelativeW(const wchar_t16* p)
{
    if (!p || !p[0])
        return 1;
    if (p[0] == '\\' || p[0] == '/')
        return 0;
    if (p[1] == ':')
        return 0;
    return 1;
}

__declspec(dllexport) void PathRemoveExtensionA(char* p)
{
    if (!p)
        return;
    size_t n = alen(p);
    for (size_t i = n; i > 0; --i)
    {
        char c = p[i - 1];
        if (c == '\\' || c == '/')
            return;
        if (c == '.')
        {
            p[i - 1] = 0;
            return;
        }
    }
}

__declspec(dllexport) void PathRemoveExtensionW(wchar_t16* p)
{
    if (!p)
        return;
    size_t n = wlen(p);
    for (size_t i = n; i > 0; --i)
    {
        wchar_t16 c = p[i - 1];
        if (c == '\\' || c == '/')
            return;
        if (c == '.')
        {
            p[i - 1] = 0;
            return;
        }
    }
}

__declspec(dllexport) BOOL PathRemoveBackslashA(char* p)
{
    if (!p)
        return 0;
    size_t n = alen(p);
    if (n > 0 && (p[n - 1] == '\\' || p[n - 1] == '/'))
    {
        p[n - 1] = 0;
        return 1;
    }
    return 0;
}

__declspec(dllexport) BOOL PathRemoveBackslashW(wchar_t16* p)
{
    if (!p)
        return 0;
    size_t n = wlen(p);
    if (n > 0 && (p[n - 1] == '\\' || p[n - 1] == '/'))
    {
        p[n - 1] = 0;
        return 1;
    }
    return 0;
}

__declspec(dllexport) BOOL PathAddBackslashA(char* p)
{
    if (!p)
        return 0;
    size_t n = alen(p);
    if (n > 0 && (p[n - 1] == '\\' || p[n - 1] == '/'))
        return 1;
    p[n] = '\\';
    p[n + 1] = 0;
    return 1;
}

/* PathMatchSpec: case-insensitive glob matching of '*' and '?'. */
static int match_spec_w(const wchar_t16* s, const wchar_t16* pat)
{
    while (*pat)
    {
        if (*pat == '*')
        {
            ++pat;
            if (!*pat)
                return 1;
            while (*s)
            {
                if (match_spec_w(s, pat))
                    return 1;
                ++s;
            }
            return 0;
        }
        if (!*s)
            return 0;
        if (*pat != '?')
        {
            wchar_t16 a = *s, b = *pat;
            if (a >= 'A' && a <= 'Z')
                a = (wchar_t16)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z')
                b = (wchar_t16)(b + ('a' - 'A'));
            if (a != b)
                return 0;
        }
        ++s;
        ++pat;
    }
    return *s == 0;
}

__declspec(dllexport) BOOL PathMatchSpecW(const wchar_t16* s, const wchar_t16* pat)
{
    if (!s || !pat)
        return 0;
    return match_spec_w(s, pat);
}

/* PathCanonicalizeW — collapse "..". */
__declspec(dllexport) BOOL PathCanonicalizeW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*)0 || src == (const wchar_t16*)0)
        return 0;
    int j = 0;
    int i = 0;
    while (src[i] != 0)
        dst[j++] = src[i++];
    dst[j] = 0;
    int k = 0;
    while (k + 3 < j)
    {
        if (dst[k] == '\\' && dst[k + 1] == '.' && dst[k + 2] == '.' && dst[k + 3] == '\\')
        {
            int back = k;
            while (back > 0 && dst[back - 1] != '\\')
                --back;
            if (back > 0)
                --back;
            int shift = (k + 3) - back;
            for (int m = back; m + shift <= j; ++m)
                dst[m] = dst[m + shift];
            j -= shift;
            k = back > 0 ? back - 1 : 0;
        }
        else
            ++k;
    }
    dst[j] = 0;
    return 1;
}

/* PathRenameExtensionW. */
__declspec(dllexport) BOOL PathRenameExtensionW(wchar_t16* path, const wchar_t16* new_ext)
{
    if (path == (wchar_t16*)0 || new_ext == (const wchar_t16*)0)
        return 0;
    int n = 0;
    while (path[n] != 0)
        ++n;
    int dot = -1;
    for (int i = n - 1; i >= 0; --i)
    {
        if (path[i] == '.')
        {
            dot = i;
            break;
        }
        if (path[i] == '\\' || path[i] == '/')
            break;
    }
    int trim = (dot >= 0) ? dot : n;
    int j = 0;
    while (new_ext[j] != 0)
    {
        path[trim + j] = new_ext[j];
        ++j;
    }
    path[trim + j] = 0;
    return 1;
}

/* PathQuoteSpacesW — wrap path in "" if it contains a space. */
__declspec(dllexport) void PathQuoteSpacesW(wchar_t16* p)
{
    if (p == (wchar_t16*)0)
        return;
    int has_space = 0;
    int n = 0;
    while (p[n] != 0)
    {
        if (p[n] == ' ')
            has_space = 1;
        ++n;
    }
    if (!has_space)
        return;
    /* Shift right by 1 to make room for opening quote, then append closing quote. */
    for (int i = n; i >= 0; --i)
        p[i + 1] = p[i];
    p[0] = '"';
    p[n + 1] = '"';
    p[n + 2] = 0;
}

/* PathUnquoteSpacesW — strip outer "" if present. */
__declspec(dllexport) void PathUnquoteSpacesW(wchar_t16* p)
{
    if (p == (wchar_t16*)0 || p[0] != '"')
        return;
    int n = 0;
    while (p[n] != 0)
        ++n;
    if (n < 2 || p[n - 1] != '"')
        return;
    for (int i = 0; i < n - 2; ++i)
        p[i] = p[i + 1];
    p[n - 2] = 0;
}
