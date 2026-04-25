/*
 * userland/libs/shlwapi/shlwapi.c
 *
 * Freestanding DuetOS shlwapi.dll. 16 Path* / Str*
 * string helpers — all pure-C loops. No syscall dependency.
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

__declspec(dllexport) BOOL PathFileExistsA(const char* p)
{
    (void)p;
    return 0; /* v0: every path "doesn't exist" — real FS-backed. */
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
    (void)p;
    return 0;
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

__declspec(dllexport) void PathRemoveFileSpecW(wchar_t16* p)
{
    if (!p)
        return;
    size_t n = wlen(p);
    size_t last_sep = (size_t)-1;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i;
    if (last_sep != (size_t)-1)
        p[last_sep] = 0;
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
