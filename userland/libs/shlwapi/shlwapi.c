/*
 * userland/libs/shlwapi/shlwapi.c
 *
 * Freestanding DuetOS shlwapi.dll. 16 Path* / Str*
 * string helpers — all pure-C loops. No syscall dependency.
 */

typedef int                BOOL;
typedef unsigned int       DWORD;
typedef unsigned short     wchar_t16;
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
    (void) p;
    return 0; /* v0: every path "doesn't exist" — real FS-backed. */
}

__declspec(dllexport) char* PathFindExtensionA(const char* p)
{
    if (!p)
        return (char*) 0;
    size_t n       = alen(p);
    const char* dot = (const char*) 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '.')
            dot = p + i;
    return (char*) (dot ? dot : p + n);
}

__declspec(dllexport) char* PathFindFileNameA(const char* p)
{
    if (!p)
        return (char*) 0;
    size_t n         = alen(p);
    size_t last_sep  = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i + 1;
    return (char*) (p + last_sep);
}

/* Path* wide */

__declspec(dllexport) BOOL PathFileExistsW(const wchar_t16* p)
{
    (void) p;
    return 0;
}

__declspec(dllexport) wchar_t16* PathFindExtensionW(const wchar_t16* p)
{
    if (!p)
        return (wchar_t16*) 0;
    size_t           n   = wlen(p);
    const wchar_t16* dot = (const wchar_t16*) 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '.')
            dot = p + i;
    return (wchar_t16*) (dot ? dot : p + n);
}

__declspec(dllexport) wchar_t16* PathFindFileNameW(const wchar_t16* p)
{
    if (!p)
        return (wchar_t16*) 0;
    size_t n        = wlen(p);
    size_t last_sep = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i + 1;
    return (wchar_t16*) (p + last_sep);
}

__declspec(dllexport) BOOL PathIsDirectoryW(const wchar_t16* p)
{
    (void) p;
    return 0; /* Nothing is a directory since nothing exists. */
}

__declspec(dllexport) void PathRemoveFileSpecW(wchar_t16* p)
{
    if (!p)
        return;
    size_t n        = wlen(p);
    size_t last_sep = (size_t) -1;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
            last_sep = i;
    if (last_sep != (size_t) -1)
        p[last_sep] = 0;
}

__declspec(dllexport) void PathStripPathW(wchar_t16* p)
{
    if (!p)
        return;
    size_t n        = wlen(p);
    size_t last_sep = 0;
    int    found   = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == '\\' || p[i] == '/')
        {
            last_sep = i + 1;
            found    = 1;
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
    p[n]     = '\\';
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
        return (wchar_t16*) 0;
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
    return (int) *a - (int) *b;
}

__declspec(dllexport) NO_BUILTIN_LOOPS int StrCmpNW(const wchar_t16* a, const wchar_t16* b, int n)
{
    if (!a || !b)
        return (a == b) ? 0 : (a ? 1 : -1);
    for (int i = 0; i < n; ++i)
    {
        if (!a[i] || a[i] != b[i])
            return (int) a[i] - (int) b[i];
    }
    return 0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS wchar_t16* StrStrW(const wchar_t16* haystack, const wchar_t16* needle)
{
    if (!haystack || !needle)
        return (wchar_t16*) 0;
    if (!needle[0])
        return (wchar_t16*) haystack;
    for (size_t i = 0; haystack[i]; ++i)
    {
        size_t j = 0;
        while (needle[j] && haystack[i + j] == needle[j])
            ++j;
        if (!needle[j])
            return (wchar_t16*) (haystack + i);
    }
    return (wchar_t16*) 0;
}

__declspec(dllexport) NO_BUILTIN_LOOPS wchar_t16* StrStrIW(const wchar_t16* haystack, const wchar_t16* needle)
{
    if (!haystack || !needle)
        return (wchar_t16*) 0;
    if (!needle[0])
        return (wchar_t16*) haystack;
    for (size_t i = 0; haystack[i]; ++i)
    {
        size_t j = 0;
        while (needle[j])
        {
            wchar_t16 h = haystack[i + j];
            wchar_t16 n = needle[j];
            if (h >= 'A' && h <= 'Z')
                h = (wchar_t16) (h + ('a' - 'A'));
            if (n >= 'A' && n <= 'Z')
                n = (wchar_t16) (n + ('a' - 'A'));
            if (h != n)
                break;
            ++j;
        }
        if (!needle[j])
            return (wchar_t16*) (haystack + i);
    }
    return (wchar_t16*) 0;
}
