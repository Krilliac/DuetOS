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

/* ==================================================================
 * C-runtime stdio (real, routed to SYS_WRITE / SYS_FILE_WRITE)
 *
 * Real Windows console exes (sort.exe, where.exe, hostname.exe)
 * import their stdio from msvcrt.dll — objdump confirms
 * `msvcrt.dll!__iob_func`, `msvcrt.dll!fprintf`,
 * `msvcrt.dll!_fileno`. They do `stdout = &__iob_func()[1]`,
 * `stderr = &__iob_func()[2]` and print via fprintf — which had
 * no flat thunk row, so output was swallowed by the catch-all
 * NO-OP. Implementing real exports here (preloaded-DLL EAT wins
 * over the flat thunk table) restores their console output.
 *
 * CRITICAL: classic msvcrt x64 sizeof(FILE) == 48. The exe adds
 * 0x30 (=48) per index after calling __iob_func, so the static
 * table's stride MUST be 48 bytes or stdout/stderr land on the
 * wrong entry. We store the route (0/1/2) in the first 8 bytes
 * and pad to 48.
 * ================================================================== */

typedef struct DUETOS_IOB_msvcrt
{
    long long route; /* 0 = stdin, 1 = stdout, 2 = stderr */
    long long pad[5];
} DUETOS_IOB;

_Static_assert(sizeof(DUETOS_IOB) == 48, "msvcrt FILE stride must be classic-msvcrt 48 bytes");

static DUETOS_IOB g_iob[3] = {{0, {0, 0, 0, 0, 0}}, {1, {0, 0, 0, 0, 0}}, {2, {0, 0, 0, 0, 0}}};

__declspec(dllexport) DUETOS_IOB* __iob_func(void)
{
    return &g_iob[0];
}

/* Map a FILE* the exe handed us back to a route index (0/1/2).
 * The exe computes &__iob_func()[N] so the pointer should land
 * exactly on a 48-byte boundary; we CLAMP to 0..2 so a slightly
 * off pointer still prints rather than faulting. A pointer
 * outside the table band (a fopen FILE*, below) is reported as
 * -1 by the caller, which checks the band first. */
static int iob_route(const void* f)
{
    long long delta = (const char*)f - (const char*)&g_iob[0];
    long long idx = delta / 48;
    if (idx < 0)
        idx = 0;
    if (idx > 2)
        idx = 2;
    return (int)idx;
}

/* True if f points inside the static __iob table (a std stream)
 * rather than at a heap FILE returned by fopen(). */
static int iob_is_std(const void* f)
{
    const char* base = (const char*)&g_iob[0];
    const char* p = (const char*)f;
    return p >= base && p < base + sizeof(g_iob);
}

/* Low-level: write n bytes to fd via SYS_WRITE (syscall 2). */
static void msvcrt_sys_write(int fd, const char* p, long long n)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)2), "D"((long long)fd), "S"((long long)p), "d"(n)
                     : "memory");
}

/* fwrite: std streams (1/2) route to SYS_WRITE(fd=1); a heap
 * FILE* (fopen band 0x100..0x10F stored as the first 8 bytes)
 * routes to SYS_FILE_WRITE (43). */
__declspec(dllexport) size_t fwrite(const void* ptr, size_t sz, size_t nmemb, void* f)
{
    if (!ptr || !f || sz == 0 || nmemb == 0)
        return 0;
    size_t total = sz * nmemb;
    if (iob_is_std(f))
    {
        /* stdin(0) silently drops on write; stdout/stderr -> fd 1. */
        if (iob_route(f) != 0)
            msvcrt_sys_write(1, (const char*)ptr, (long long)total);
        return nmemb;
    }
    /* Heap FILE* from this file's fopen(): handle is first 8 bytes. */
    DUETOS_FILE* fp = (DUETOS_FILE*)f;
    if (fp->handle >= 0x100 && fp->handle < 0x110)
    {
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)43), "D"(fp->handle), "S"((long long)ptr), "d"((long long)total)
                         : "memory");
        if (rv <= 0)
        {
            fp->err = 1;
            return 0;
        }
        return (size_t)rv / sz;
    }
    return 0;
}

__declspec(dllexport) int fputs(const char* s, void* f)
{
    if (!s || !f)
        return -1;
    size_t n = 0;
    while (s[n])
        ++n;
    if (fwrite(s, 1, n, f) != n)
        return -1;
    return 0;
}

__declspec(dllexport) int fputc(int c, void* f)
{
    char b = (char)c;
    if (fwrite(&b, 1, 1, f) != 1)
        return -1;
    return c;
}

__declspec(dllexport) int puts(const char* s)
{
    if (!s)
        s = "(null)";
    size_t n = 0;
    while (s[n])
        ++n;
    msvcrt_sys_write(1, s, (long long)n);
    msvcrt_sys_write(1, "\n", 1);
    return (int)n + 1;
}

/* Streams are unbuffered (every write hits the syscall directly),
 * so fflush is a no-op success. */
__declspec(dllexport) int fflush(void* f)
{
    (void)f;
    return 0;
}

/* _fileno: return the std-stream index (0/1/2) for a std FILE*,
 * or the kernel handle for a heap FILE*. */
__declspec(dllexport) int _fileno(void* f)
{
    if (!f)
        return -1;
    if (iob_is_std(f))
        return iob_route(f);
    return (int)((DUETOS_FILE*)f)->handle;
}

/* _get_osfhandle: map a CRT fd (0/1/2) to the Win32 std
 * pseudo-handle DWORDs (-10/-11/-12). Other fds: pass through. */
__declspec(dllexport) long long _get_osfhandle(int fd)
{
    switch (fd)
    {
    case 0:
        return -10;
    case 1:
        return -11;
    case 2:
        return -12;
    default:
        return (long long)fd;
    }
}

/* ------------------------------------------------------------------
 * Minimal printf family (ported from ucrtbase.c vfmt — the DLLs
 * are independent freestanding TUs that duplicate helpers; do NOT
 * cross-call). Supports %d/i/u/x/X/p/s/c/%, width (space or 0
 * pad) and l/ll/z length modifiers. No float, no %n, no locale.
 * ------------------------------------------------------------------ */

static int msvcrt_emit_char(char* buf, size_t cap, size_t* pos, char c)
{
    if (buf && *pos + 1 < cap)
        buf[*pos] = c;
    (*pos)++;
    return 1;
}

static void msvcrt_emit_str(char* buf, size_t cap, size_t* pos, const char* s, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        msvcrt_emit_char(buf, cap, pos, s[i]);
}

static void msvcrt_emit_pad(char* buf, size_t cap, size_t* pos, int width, int printed, char fill)
{
    while (printed < width)
    {
        msvcrt_emit_char(buf, cap, pos, fill);
        ++printed;
    }
}

static int msvcrt_fmt_int(char* tmp, unsigned long long v, int base, int upper)
{
    int n = 0;
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (v == 0)
    {
        tmp[n++] = '0';
        return n;
    }
    while (v)
    {
        tmp[n++] = digits[v % (unsigned)base];
        v /= (unsigned)base;
    }
    return n;
}

#define va_list __builtin_va_list
#define va_start __builtin_va_start
#define va_end __builtin_va_end
#define va_arg_ptr(ap, type) (__builtin_va_arg(ap, type))

static int msvcrt_vfmt(char* buf, size_t cap, const char* fmt, va_list ap)
{
    size_t pos = 0;
    while (*fmt)
    {
        if (*fmt != '%')
        {
            msvcrt_emit_char(buf, cap, &pos, *fmt++);
            continue;
        }
        ++fmt;
        char pad = ' ';
        if (*fmt == '0')
        {
            pad = '0';
            ++fmt;
        }
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');
        int mod = 0; /* 0=int, 1=long, 2=long long, 3=size_t */
        if (*fmt == 'l')
        {
            mod = 1;
            ++fmt;
            if (*fmt == 'l')
            {
                mod = 2;
                ++fmt;
            }
        }
        else if (*fmt == 'z')
        {
            mod = 3;
            ++fmt;
        }
        char spec = *fmt++;
        if (spec == 0)
            break;
        char tmp[32];
        switch (spec)
        {
        case 'c':
        {
            char c = (char)va_arg_ptr(ap, int);
            msvcrt_emit_pad(buf, cap, &pos, width, 1, pad);
            msvcrt_emit_char(buf, cap, &pos, c);
            break;
        }
        case 's':
        {
            const char* s = va_arg_ptr(ap, const char*);
            if (!s)
                s = "(null)";
            size_t n = 0;
            while (s[n])
                ++n;
            msvcrt_emit_pad(buf, cap, &pos, width, (int)n, pad);
            msvcrt_emit_str(buf, cap, &pos, s, n);
            break;
        }
        case 'd':
        case 'i':
        {
            long long v;
            if (mod == 2)
                v = va_arg_ptr(ap, long long);
            else if (mod == 3)
                v = (long long)va_arg_ptr(ap, size_t);
            else if (mod == 1)
                v = va_arg_ptr(ap, long);
            else
                v = va_arg_ptr(ap, int);
            int neg = 0;
            unsigned long long u;
            if (v < 0)
            {
                neg = 1;
                u = (unsigned long long)(-v);
            }
            else
                u = (unsigned long long)v;
            int n = msvcrt_fmt_int(tmp, u, 10, 0);
            int total = n + (neg ? 1 : 0);
            msvcrt_emit_pad(buf, cap, &pos, width, total, pad);
            if (neg)
                msvcrt_emit_char(buf, cap, &pos, '-');
            for (int i = n - 1; i >= 0; --i)
                msvcrt_emit_char(buf, cap, &pos, tmp[i]);
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        {
            unsigned long long v;
            if (mod == 2)
                v = va_arg_ptr(ap, unsigned long long);
            else if (mod == 3)
                v = va_arg_ptr(ap, size_t);
            else if (mod == 1)
                v = va_arg_ptr(ap, unsigned long);
            else
                v = va_arg_ptr(ap, unsigned int);
            int base = (spec == 'u') ? 10 : 16;
            int upper = (spec == 'X');
            int n = msvcrt_fmt_int(tmp, v, base, upper);
            msvcrt_emit_pad(buf, cap, &pos, width, n, pad);
            for (int i = n - 1; i >= 0; --i)
                msvcrt_emit_char(buf, cap, &pos, tmp[i]);
            break;
        }
        case 'p':
        {
            unsigned long long v = (unsigned long long)va_arg_ptr(ap, void*);
            msvcrt_emit_str(buf, cap, &pos, "0x", 2);
            int n = msvcrt_fmt_int(tmp, v, 16, 0);
            for (int i = n - 1; i >= 0; --i)
                msvcrt_emit_char(buf, cap, &pos, tmp[i]);
            break;
        }
        case '%':
            msvcrt_emit_char(buf, cap, &pos, '%');
            break;
        default:
            msvcrt_emit_char(buf, cap, &pos, '%');
            msvcrt_emit_char(buf, cap, &pos, spec);
            break;
        }
    }
    if (buf && cap > 0)
        buf[pos < cap ? pos : cap - 1] = 0;
    return (int)pos;
}

__declspec(dllexport) int vsnprintf(char* buf, size_t cap, const char* fmt, va_list ap)
{
    return msvcrt_vfmt(buf, cap, fmt, ap);
}

__declspec(dllexport) int _vsnprintf(char* buf, size_t cap, const char* fmt, va_list ap)
{
    return msvcrt_vfmt(buf, cap, fmt, ap);
}

__declspec(dllexport) int snprintf(char* buf, size_t cap, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = msvcrt_vfmt(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}

__declspec(dllexport) int vfprintf(void* f, const char* fmt, va_list ap)
{
    char buf[1024];
    int n = msvcrt_vfmt(buf, sizeof(buf), fmt, ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, f);
    return n;
}

__declspec(dllexport) int fprintf(void* f, const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = msvcrt_vfmt(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, f);
    return n;
}

__declspec(dllexport) int vprintf(const char* fmt, va_list ap)
{
    char buf[1024];
    int n = msvcrt_vfmt(buf, sizeof(buf), fmt, ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    msvcrt_sys_write(1, buf, (long long)n);
    return n;
}

__declspec(dllexport) int printf(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = msvcrt_vfmt(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    msvcrt_sys_write(1, buf, (long long)n);
    return n;
}

/* _vsnwprintf — where.exe wide variant. Format the ASCII result
 * via the narrow vfmt, then widen byte->u16.
 * GAP: non-ASCII format output (multibyte / wide %ls) is not
 * handled — each narrow byte is zero-extended. where.exe's usage
 * text is pure ASCII so this suffices; revisit if a wide caller
 * needs real UTF-16 formatting. */
__declspec(dllexport) int _vsnwprintf(wchar_t16* buf, size_t cap, const wchar_t16* wfmt, va_list ap)
{
    if (!buf || cap == 0)
        return 0;
    /* Narrow the format string (ASCII band only). */
    char nfmt[512];
    size_t fi = 0;
    while (wfmt[fi] && fi < sizeof(nfmt) - 1)
    {
        nfmt[fi] = (char)(wfmt[fi] & 0xFF);
        ++fi;
    }
    nfmt[fi] = 0;
    char nbuf[1024];
    int n = msvcrt_vfmt(nbuf, sizeof(nbuf), nfmt, ap);
    if (n > (int)sizeof(nbuf) - 1)
        n = (int)sizeof(nbuf) - 1;
    size_t i = 0;
    for (; i < (size_t)n && i < cap - 1; ++i)
        buf[i] = (wchar_t16)(unsigned char)nbuf[i];
    buf[i] = 0;
    return (int)i;
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
