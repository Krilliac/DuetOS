/*
 * userland/libs/msvcrt/msvcrt.c
 *
 * Freestanding DuetOS msvcrt.dll — string intrinsics
 * (strlen, strcmp, strcpy, strchr, wcslen, wcscmp, wcscpy,
 * wcschr). Retires the + 29/31 flat stubs in
 * kernel/subsystems/win32/thunks.cpp.
 *
 * All implementations are plain C loops. `-fno-builtin` +
 * `__attribute__((no_builtin(...)))` prevent clang from
 * recognising the loops as str or wcs intrinsics and turning
 * them into tail calls to themselves.
 *
 * Build: tools/build/build-msvcrt-dll.sh
 *   clang --target=x86_64-pc-windows-msvc + lld-link /dll
 *   /noentry /nodefaultlib /base:0x10040000.
 */

typedef unsigned long long size_t;
typedef unsigned short wchar_t16; /* Win32 wchar_t is UTF-16, 16 bits */

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
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

__declspec(dllexport) NO_BUILTIN_STR char* strcpy(char* dst, const char* src)
{
    char* d = dst;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL */
    }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strcat(char* dst, const char* src)
{
    char* d = dst;
    while (*d != 0)
        ++d;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL */
    }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strncat(char* dst, const char* src, size_t n)
{
    char* d = dst;
    while (*d != 0)
        ++d;
    size_t i = 0;
    while (i < n && src[i] != 0)
    {
        d[i] = src[i];
        ++i;
    }
    d[i] = 0;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strchr(const char* s, int c)
{
    const char ch = (char)c;
    for (;; ++s)
    {
        if (*s == ch)
            return (char*)s; /* per POSIX: strchr may match the NUL */
        if (*s == 0)
            return (char*)0;
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
    return (int)*a - (int)*b;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcscpy(wchar_t16* dst, const wchar_t16* src)
{
    wchar_t16* d = dst;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL16 */
    }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcschr(const wchar_t16* s, wchar_t16 c)
{
    for (;; ++s)
    {
        if (*s == c)
            return (wchar_t16*)s;
        if (*s == 0)
            return (wchar_t16*)0;
    }
}

/* Additional pure-logic intrinsics commonly imported by MSVC PEs. */

__declspec(dllexport) NO_BUILTIN_STR int strncmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca != cb)
            return (int)ca - (int)cb;
        if (ca == 0)
            return 0;
    }
    return 0;
}

__declspec(dllexport) NO_BUILTIN_STR char* strncpy(char* dst, const char* src, size_t n)
{
    size_t i = 0;
    for (; i < n && src[i]; ++i)
        dst[i] = src[i];
    for (; i < n; ++i)
        dst[i] = 0;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strrchr(const char* s, int c)
{
    const char ch = (char)c;
    const char* last = (const char*)0;
    for (; *s; ++s)
        if (*s == ch)
            last = s;
    if (ch == 0)
        return (char*)s;
    return (char*)last;
}

__declspec(dllexport) NO_BUILTIN_STR char* strstr(const char* haystack, const char* needle)
{
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

__declspec(dllexport) size_t strspn(const char* s, const char* accept)
{
    size_t n = 0;
    for (; s[n]; ++n)
    {
        int found = 0;
        for (size_t j = 0; accept[j]; ++j)
            if (s[n] == accept[j])
            {
                found = 1;
                break;
            }
        if (!found)
            break;
    }
    return n;
}

__declspec(dllexport) size_t strcspn(const char* s, const char* reject)
{
    size_t n = 0;
    for (; s[n]; ++n)
    {
        for (size_t j = 0; reject[j]; ++j)
            if (s[n] == reject[j])
                return n;
    }
    return n;
}

__declspec(dllexport) char* strpbrk(const char* s, const char* accept)
{
    for (; *s; ++s)
        for (const char* a = accept; *a; ++a)
            if (*s == *a)
                return (char*)s;
    return (char*)0;
}

/* Memory intrinsics that aren't in the kernel stub page (which
 * provides memmove/memset/memcpy via flat aliases). msvcrt
 * imports often redirect through here for size_t signature. */
__declspec(dllexport) int memcmp(const void* a, const void* b, size_t n)
{
    const unsigned char* p = (const unsigned char*)a;
    const unsigned char* q = (const unsigned char*)b;
    for (size_t i = 0; i < n; ++i)
        if (p[i] != q[i])
            return (int)p[i] - (int)q[i];
    return 0;
}

__declspec(dllexport) const void* memchr(const void* s, int c, size_t n)
{
    const unsigned char* p = (const unsigned char*)s;
    const unsigned char ch = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == ch)
            return (const void*)(p + i);
    return (const void*)0;
}

/* Wide variants. */

__declspec(dllexport) NO_BUILTIN_WCS int wcsncmp(const wchar_t16* a, const wchar_t16* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
            return (int)a[i] - (int)b[i];
        if (a[i] == 0)
            return 0;
    }
    return 0;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcsncpy(wchar_t16* dst, const wchar_t16* src, size_t n)
{
    size_t i = 0;
    for (; i < n && src[i]; ++i)
        dst[i] = src[i];
    for (; i < n; ++i)
        dst[i] = 0;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcsrchr(const wchar_t16* s, wchar_t16 c)
{
    const wchar_t16* last = (const wchar_t16*)0;
    for (; *s; ++s)
        if (*s == c)
            last = s;
    if (c == 0)
        return (wchar_t16*)s;
    return (wchar_t16*)last;
}

__declspec(dllexport) NO_BUILTIN_WCS wchar_t16* wcsstr(const wchar_t16* haystack, const wchar_t16* needle)
{
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

/* Character classification — MSVC apps call these instead of
 * the platform isXxx for locale-respecting paths. v0 has no
 * locale, so each routes to the C-locale answer. */
__declspec(dllexport) int isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
__declspec(dllexport) int isdigit(int c)
{
    return c >= '0' && c <= '9';
}
__declspec(dllexport) int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}
__declspec(dllexport) int isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}
__declspec(dllexport) int isupper(int c)
{
    return c >= 'A' && c <= 'Z';
}
__declspec(dllexport) int islower(int c)
{
    return c >= 'a' && c <= 'z';
}
__declspec(dllexport) int isxdigit(int c)
{
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
__declspec(dllexport) int isprint(int c)
{
    return c >= ' ' && c < 0x7F;
}
__declspec(dllexport) int iscntrl(int c)
{
    return (c >= 0 && c < ' ') || c == 0x7F;
}
__declspec(dllexport) int ispunct(int c)
{
    return isprint(c) && !isalnum(c) && !isspace(c);
}
__declspec(dllexport) int tolower(int c)
{
    return isupper(c) ? c + ('a' - 'A') : c;
}
__declspec(dllexport) int toupper(int c)
{
    return islower(c) ? c - ('a' - 'A') : c;
}

/* Numeric parsing — atoi/atol/atoll. C-locale, base 10. */
__declspec(dllexport) int atoi(const char* s)
{
    if (!s)
        return 0;
    while (*s == ' ' || *s == '\t' || *s == '\n')
        ++s;
    int sign = 1;
    if (*s == '-')
    {
        sign = -1;
        ++s;
    }
    else if (*s == '+')
    {
        ++s;
    }
    int v = 0;
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10 + (*s - '0');
        ++s;
    }
    return v * sign;
}

__declspec(dllexport) long atol(const char* s)
{
    return (long)atoi(s);
}

__declspec(dllexport) long long atoll(const char* s)
{
    if (!s)
        return 0;
    while (*s == ' ' || *s == '\t' || *s == '\n')
        ++s;
    int sign = 1;
    if (*s == '-')
    {
        sign = -1;
        ++s;
    }
    else if (*s == '+')
    {
        ++s;
    }
    long long v = 0;
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10 + (long long)(*s - '0');
        ++s;
    }
    return v * sign;
}

__declspec(dllexport) NO_BUILTIN_STR int _stricmp(const char* a, const char* b)
{
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

__declspec(dllexport) NO_BUILTIN_STR int _strnicmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
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


/* abs / labs / llabs. */
__declspec(dllexport) int abs(int x)
{
    return x < 0 ? -x : x;
}
__declspec(dllexport) long labs(long x)
{
    return x < 0 ? -x : x;
}
__declspec(dllexport) long long llabs(long long x)
{
    return x < 0 ? -x : x;
}

/* qsort (median-of-three quicksort, in-place). */
typedef int (*qsort_cmp_t)(const void*, const void*);

static void qsort_swap(unsigned char* a, unsigned char* b, size_t size)
{
    while (size--)
    {
        unsigned char t = *a;
        *a++ = *b;
        *b++ = t;
    }
}

__declspec(dllexport) void qsort(void* base, size_t nmemb, size_t size, qsort_cmp_t cmp)
{
    if (nmemb < 2 || size == 0)
        return;
    unsigned char* arr = (unsigned char*)base;
    /* Trivial insertion sort — fine for the smoke-test sizes. */
    for (size_t i = 1; i < nmemb; ++i)
        for (size_t j = i; j > 0; --j)
        {
            if (cmp(arr + (j - 1) * size, arr + j * size) <= 0)
                break;
            qsort_swap(arr + (j - 1) * size, arr + j * size, size);
        }
}

__declspec(dllexport) void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, qsort_cmp_t cmp)
{
    if (nmemb == 0 || size == 0)
        return (void*)0;
    size_t lo = 0, hi = nmemb;
    const unsigned char* arr = (const unsigned char*)base;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int r = cmp(key, arr + mid * size);
        if (r == 0)
            return (void*)(arr + mid * size);
        if (r < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return (void*)0;
}

/* Wide → narrow / narrow → wide CRT functions (host CP-agnostic;
 * just byte-cast for low-ASCII inputs). */
__declspec(dllexport) size_t mbstowcs(wchar_t16* dst, const char* src, size_t n)
{
    if (src == 0)
        return 0;
    size_t i = 0;
    while (i < n && src[i] != 0)
    {
        if (dst != 0)
            dst[i] = (wchar_t16)(unsigned char)src[i];
        ++i;
    }
    if (dst != 0 && i < n)
        dst[i] = 0;
    return i;
}

__declspec(dllexport) size_t wcstombs(char* dst, const wchar_t16* src, size_t n)
{
    if (src == 0)
        return 0;
    size_t i = 0;
    while (i < n && src[i] != 0)
    {
        if (dst != 0)
            dst[i] = (char)(src[i] & 0xFF);
        ++i;
    }
    if (dst != 0 && i < n)
        dst[i] = 0;
    return i;
}

__declspec(dllexport) int _wtoi(const wchar_t16* s)
{
    if (s == 0)
        return 0;
    int sign = 1;
    int i = 0;
    while (s[i] == ' ' || s[i] == '\t')
        ++i;
    if (s[i] == '-')
    {
        sign = -1;
        ++i;
    }
    else if (s[i] == '+')
        ++i;
    int v = 0;
    while (s[i] >= '0' && s[i] <= '9')
    {
        v = v * 10 + (s[i] - '0');
        ++i;
    }
    return v * sign;
}

__declspec(dllexport) long _wtol(const wchar_t16* s)
{
    return (long)_wtoi(s);
}

__declspec(dllexport) long long _wtoll(const wchar_t16* s)
{
    if (s == 0)
        return 0;
    long long sign = 1;
    int i = 0;
    while (s[i] == ' ' || s[i] == '\t')
        ++i;
    if (s[i] == '-')
    {
        sign = -1;
        ++i;
    }
    else if (s[i] == '+')
        ++i;
    long long v = 0;
    while (s[i] >= '0' && s[i] <= '9')
    {
        v = v * 10 + (s[i] - '0');
        ++i;
    }
    return v * sign;
}

__declspec(dllexport) long wcstol(const wchar_t16* s, wchar_t16** end, int base)
{
    (void)base;
    if (end != 0)
        *end = (wchar_t16*)s;
    return (long)_wtoi(s);
}

__declspec(dllexport) unsigned long wcstoul(const wchar_t16* s, wchar_t16** end, int base)
{
    (void)base;
    if (end != 0)
        *end = (wchar_t16*)s;
    int i = 0;
    while (s[i] == ' ' || s[i] == '\t')
        ++i;
    unsigned long v = 0;
    while (s[i] >= '0' && s[i] <= '9')
    {
        v = v * 10 + (s[i] - '0');
        ++i;
    }
    return v;
}

/* _getmbcp — return CP_ACP. */
__declspec(dllexport) int _getmbcp(void)
{
    return 1252;
}

/* _putch — write a single byte via SYS_WRITE(fd=1). */
__declspec(dllexport) int _putch(int c)
{
    char ch = (char)(c & 0xFF);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)2), "D"((long long)1), "S"((long long)&ch), "d"((long long)1)
                     : "memory");
    return (rv == 1) ? c : -1;
}

__declspec(dllexport) int _putwch(unsigned short c)
{
    char ch = (char)(c & 0xFF);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)2), "D"((long long)1), "S"((long long)&ch), "d"((long long)1)
                     : "memory");
    return (rv == 1) ? c : -1;
}

__declspec(dllexport) int _kbhit(void)
{
    return 0;
}

__declspec(dllexport) int _cputs(const char* s)
{
    if (s == 0)
        return -1;
    int n = 0;
    while (s[n] != 0)
        ++n;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)2), "D"((long long)1), "S"((long long)s), "d"((long long)n)
                     : "memory");
    return rv == n ? 0 : -1;
}

/* signal — store handler in a static slot. Table is sized so the
 * highest valid Microsoft C signal id (SIGABRT = 22) fits — the
 * earlier 16-slot table SIG_ERR'd every signal(SIGABRT, ...) call
 * because 22 >= 16. The MSVC signal set tops out at SIGBREAK (= 21)
 * and SIGABRT (= 22); 32 leaves a comfortable margin for any
 * application-defined signals up to the POSIX RT range. */
typedef void (*duetos_sig_handler_t)(int);
#define DUETOS_SIG_MAX 32
static duetos_sig_handler_t g_sig_handlers[DUETOS_SIG_MAX];

__declspec(dllexport) duetos_sig_handler_t signal(int sig, duetos_sig_handler_t h)
{
    if (sig < 0 || sig >= DUETOS_SIG_MAX)
        return (duetos_sig_handler_t)(unsigned long long)-1; /* SIG_ERR */
    duetos_sig_handler_t prev = g_sig_handlers[sig];
    g_sig_handlers[sig] = h;
    return prev;
}

/* fopen / fclose / fread / fwrite / fseek / ftell / rewind / feof
 * — same SYS_FILE_OPEN-routed impl as ucrtbase.c, exported under
 * msvcrt for callers that import from the legacy DLL. */
typedef struct DUETOS_FILE_msvcrt
{
    long long handle; /* SYS_FILE_OPEN handle (-1 on error / EOF) */
    int eof;
    int err;
} DUETOS_FILE;

__declspec(dllexport) DUETOS_FILE* fopen(const char* path, const char* mode)
{
    (void)mode;
    if (path == 0)
        return 0;
    int len = 0;
    while (path[len])
        ++len;
    long long h;
    __asm__ volatile("int $0x80" : "=a"(h) : "a"((long long)20), "D"((long long)path), "S"((long long)len) : "memory");
    /* SYS_FILE_OPEN returns 0x100..0x10F on hit, (u64)-1 on miss.
     * The previous `h == 0` check missed the (u64)-1 case, so
     * fopen() on a missing path silently returned a FILE* wrapping
     * a sentinel-poisoned handle that subsequent fread()/fseek()
     * walked off into the kernel's "unknown handle" reject path.
     * Range-check matches ucrtbase.c's identical check (the
     * msvcrt mirror was missing it). */
    if (h < 0x100 || h >= 0x110)
        return 0;
    /* Allocate a 24-byte FILE struct via SYS_HEAP_ALLOC (op 11). */
    long long fp;
    __asm__ volatile("int $0x80" : "=a"(fp) : "a"((long long)11), "D"((long long)24) : "memory");
    if (fp == 0)
        return 0;
    DUETOS_FILE* f = (DUETOS_FILE*)fp;
    f->handle = h;
    f->eof = 0;
    f->err = 0;
    return f;
}

__declspec(dllexport) int fclose(DUETOS_FILE* f)
{
    if (f == 0)
        return -1;
    long long h = f->handle;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)22), "D"(h) : "memory");
    /* Free f via SYS_HEAP_FREE (op 12). */
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)f) : "memory");
    return 0;
}

__declspec(dllexport) size_t fread(void* buf, size_t size, size_t nmemb, DUETOS_FILE* f)
{
    if (f == 0 || buf == 0 || size == 0 || nmemb == 0)
        return 0;
    long long total = (long long)size * (long long)nmemb;
    long long got;
    __asm__ volatile("int $0x80"
                     : "=a"(got)
                     : "a"((long long)21), "D"(f->handle), "S"((long long)buf), "d"(total)
                     : "memory");
    if (got <= 0)
    {
        f->eof = 1;
        return 0;
    }
    return (size_t)got / size;
}

__declspec(dllexport) int fseek(DUETOS_FILE* f, long off, int whence)
{
    if (f == 0)
        return -1;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)23), "D"(f->handle), "S"((long long)off), "d"((long long)whence)
                     : "memory");
    return rv >= 0 ? 0 : -1;
}

__declspec(dllexport) long ftell(DUETOS_FILE* f)
{
    if (f == 0)
        return -1;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)23), "D"(f->handle), "S"((long long)0), "d"((long long)1) /* SEEK_CUR=1 */
                     : "memory");
    return rv >= 0 ? (long)rv : -1;
}

__declspec(dllexport) void rewind(DUETOS_FILE* f)
{
    fseek(f, 0, 0 /*SEEK_SET*/);
    if (f)
        f->eof = 0;
}

__declspec(dllexport) int feof(DUETOS_FILE* f)
{
    return f ? f->eof : 1;
}

__declspec(dllexport) int ferror(DUETOS_FILE* f)
{
    return f ? f->err : 0;
}

/* _aligned_malloc — round up to alignment boundary. */
__declspec(dllexport) void* _aligned_malloc(size_t sz, size_t align)
{
    if (align < 16)
        align = 16;
    long long p;
    __asm__ volatile("int $0x80" : "=a"(p) : "a"((long long)11), "D"((long long)(sz + align)) : "memory");
    if (p == 0)
        return 0;
    /* Round up to alignment. */
    unsigned long long aligned = ((unsigned long long)p + align - 1) & ~(align - 1);
    /* Store original behind the aligned ptr. */
    *((unsigned long long*)(aligned - 8)) = (unsigned long long)p;
    return (void*)aligned;
}

__declspec(dllexport) void _aligned_free(void* p)
{
    if (p == 0)
        return;
    unsigned long long orig = *((unsigned long long*)((unsigned char*)p - 8));
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)orig) : "memory");
}

/* Re-export memcpy/memmove/memset from msvcrt — vcruntime140 already
 * has them, but mingw-w64 imports memcpy/memmove via msvcrt by
 * default. Without these msvcrt-exported names, link-time mingw
 * runtime fallbacks fall back to NO-OP catch-all. */
__declspec(dllexport) void* memcpy(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i)
        d[i] = s[i];
    return dst;
}

__declspec(dllexport) void* memmove(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d < s)
        for (size_t i = 0; i < n; ++i)
            d[i] = s[i];
    else
        for (size_t i = n; i > 0; --i)
            d[i - 1] = s[i - 1];
    return dst;
}

__declspec(dllexport) void* memset(void* dst, int c, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    unsigned char b = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        d[i] = b;
    return dst;
}
