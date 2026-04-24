/*
 * userland/libs/ucrtbase/ucrtbase.c
 *
 * Freestanding CustomOS ucrtbase.dll. Retires the batch-6 / 9
 * UCRT runtime stubs in kernel/subsystems/win32/stubs.cpp.
 *
 * Covers:
 *   - Heap allocation: malloc, free, calloc, realloc,
 *     _aligned_malloc, _aligned_free.
 *   - Terminators: exit, _exit.
 *   - CRT startup shims: _initterm, _initterm_e, _cexit,
 *     _c_exit, _set_app_type, __setusermatherr,
 *     _configthreadlocale.
 *   - String intrinsics (aliased from msvcrt — ucrtbase
 *     exports them too in real Windows).
 *
 * Native syscalls used:
 *   SYS_EXIT = 0, SYS_HEAP_ALLOC = 11, SYS_HEAP_FREE = 12,
 *   SYS_HEAP_REALLOC = 15.
 *
 * Build: tools/build-ucrtbase-dll.sh at /base:0x10050000.
 */

typedef unsigned int       UINT;
typedef unsigned long long size_t;

#define UCRT_NORETURN __attribute__((noreturn))

#define NO_BUILTIN_STR __attribute__((no_builtin("strlen", "strcmp", "strcpy", "strchr")))
#define NO_BUILTIN_MEM __attribute__((no_builtin("memset", "memcpy")))

/* ------------------------------------------------------------------
 * Heap allocation
 * ------------------------------------------------------------------ */

__declspec(dllexport) void* malloc(size_t size)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 11), "D"((long long) size) : "memory");
    return (void*) rv;
}

__declspec(dllexport) void free(void* ptr)
{
    if (ptr == (void*) 0)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 12), "D"((long long) ptr) : "memory");
}

__declspec(dllexport) NO_BUILTIN_MEM void* calloc(size_t n, size_t size)
{
    const size_t total = n * size;
    void*        p     = malloc(total);
    if (p == (void*) 0)
        return (void*) 0;
    /* Zero-fill the returned region. Byte loop keeps clang
     * from recognising this as memset and calling itself. */
    unsigned char* b = (unsigned char*) p;
    for (size_t i = 0; i < total; ++i)
        b[i] = 0;
    return p;
}

__declspec(dllexport) void* realloc(void* ptr, size_t size)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 15), "D"((long long) ptr), "S"((long long) size)
                     : "memory");
    return (void*) rv;
}

/* _aligned_malloc / _aligned_free — v0 ignores the alignment
 * argument and treats them as plain malloc/free. Our heap
 * returns 8-byte-aligned blocks anyway, which covers every
 * caller today (CRT callers that ask for 16 or 32 get 8, but
 * no existing PE has tripped on that yet). A future slice can
 * add real alignment by over-allocating + storing a back-
 * pointer. */
__declspec(dllexport) void* _aligned_malloc(size_t size, size_t alignment)
{
    (void) alignment;
    return malloc(size);
}

__declspec(dllexport) void _aligned_free(void* ptr)
{
    free(ptr);
}

/* ------------------------------------------------------------------
 * Terminators (noreturn)
 * ------------------------------------------------------------------ */

__declspec(dllexport) UCRT_NORETURN void exit(int code)
{
    __asm__ volatile("int $0x80" : : "a"((long) 0), "D"((long) code));
    __builtin_unreachable();
}

__declspec(dllexport) UCRT_NORETURN void _exit(int code)
{
    __asm__ volatile("int $0x80" : : "a"((long) 0), "D"((long) code));
    __builtin_unreachable();
}

/* ------------------------------------------------------------------
 * CRT startup no-ops
 *
 * These are called by the MSVC CRT's entry glue during
 * process init. Real implementations iterate function-pointer
 * tables (_initterm) or install error handlers. Our PEs have
 * been running with flat-stub return-zero versions of these
 * since batch 6 — preserving that behaviour keeps every
 * existing PE stable.
 * ------------------------------------------------------------------ */

/* void _initterm(PVPFV first, PVPFV last); — iterate the
 * [first, last) range of void(*)(void) function pointers and
 * call each. Real Windows does this; our flat stub skipped
 * it. Preserve the flat-stub behaviour (no-op) for now. */
__declspec(dllexport) void _initterm(void** first, void** last)
{
    (void) first;
    (void) last;
}

/* int _initterm_e(PVFV first, PVFV last); — like _initterm
 * but each callback returns int; stop on first non-zero.
 * Return 0 (success). */
__declspec(dllexport) int _initterm_e(void** first, void** last)
{
    (void) first;
    (void) last;
    return 0;
}

__declspec(dllexport) void _cexit(void)
{
}
__declspec(dllexport) void _c_exit(void)
{
}
__declspec(dllexport) void _set_app_type(int t)
{
    (void) t;
}
__declspec(dllexport) int __setusermatherr(void* handler)
{
    (void) handler;
    return 0;
}
__declspec(dllexport) int _configthreadlocale(int per_thread)
{
    (void) per_thread;
    return 0;
}

/* ------------------------------------------------------------------
 * String intrinsics — duplicated from msvcrt so PEs that import
 * `ucrtbase.dll!strlen` resolve via this DLL instead of the
 * flat stubs. Real Windows exports these from both msvcrt and
 * ucrtbase; we follow the convention.
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
    return (int) (unsigned char) *a - (int) (unsigned char) *b;
}

__declspec(dllexport) NO_BUILTIN_STR char* strcpy(char* dst, const char* src)
{
    char* d = dst;
    while ((*d++ = *src++) != 0) { }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strchr(const char* s, int c)
{
    const char ch = (char) c;
    for (;; ++s)
    {
        if (*s == ch)
            return (char*) s;
        if (*s == 0)
            return (char*) 0;
    }
}

/* ------------------------------------------------------------------
 * Number conversion (slice 17)
 *
 * Retires the api-ms-win-crt-convert atoi / atol / strtol /
 * strtoul aliases. Small loops, well-defined semantics, no
 * syscall needed.
 *
 * MSVC-ABI sizes (LLP64):
 *   int           = 32-bit
 *   long          = 32-bit  <- not 64, unlike Unix!
 *   long long     = 64-bit
 * ------------------------------------------------------------------ */

typedef int           atoi_int;
typedef long          atoi_long; /* MSVC long = 32-bit */
typedef unsigned long atoi_ulong;

static int is_space(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int digit_value(int c, int base)
{
    int v;
    if (c >= '0' && c <= '9')
        v = c - '0';
    else if (c >= 'a' && c <= 'z')
        v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'Z')
        v = c - 'A' + 10;
    else
        return -1;
    return v < base ? v : -1;
}

__declspec(dllexport) atoi_int atoi(const char* s)
{
    while (is_space(*s))
        ++s;
    int neg = 0;
    if (*s == '-')
    {
        neg = 1;
        ++s;
    }
    else if (*s == '+')
        ++s;
    atoi_int v = 0;
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10 + (*s - '0');
        ++s;
    }
    return neg ? -v : v;
}

__declspec(dllexport) atoi_long atol(const char* s)
{
    /* atol returns long (32-bit on MSVC); reuse atoi body. */
    return (atoi_long) atoi(s);
}

__declspec(dllexport) atoi_long strtol(const char* s, char** endptr, int base)
{
    const char* p = s;
    while (is_space(*p))
        ++p;
    int neg = 0;
    if (*p == '-')
    {
        neg = 1;
        ++p;
    }
    else if (*p == '+')
        ++p;
    /* Auto-detect base when caller passes 0. */
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
            base = 16;
        }
        else if (p[0] == '0')
        {
            ++p;
            base = 8;
        }
        else
            base = 10;
    }
    else if (base == 16 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    atoi_long v  = 0;
    int       dv;
    while ((dv = digit_value(*p, base)) >= 0)
    {
        v = v * base + dv;
        ++p;
    }
    if (endptr != (char**) 0)
        *endptr = (char*) p;
    return neg ? -v : v;
}

__declspec(dllexport) atoi_ulong strtoul(const char* s, char** endptr, int base)
{
    /* Same parse as strtol but no sign handling on the
     * output — however we still accept a leading sign as
     * MSVC does (negation wraps modulo 2^32). */
    const char* p = s;
    while (is_space(*p))
        ++p;
    int neg = 0;
    if (*p == '-')
    {
        neg = 1;
        ++p;
    }
    else if (*p == '+')
        ++p;
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
            base = 16;
        }
        else if (p[0] == '0')
        {
            ++p;
            base = 8;
        }
        else
            base = 10;
    }
    else if (base == 16 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    atoi_ulong v = 0;
    int        dv;
    while ((dv = digit_value(*p, base)) >= 0)
    {
        v = v * (atoi_ulong) base + (atoi_ulong) dv;
        ++p;
    }
    if (endptr != (char**) 0)
        *endptr = (char*) p;
    return neg ? (atoi_ulong) (-(atoi_long) v) : v;
}

/* ------------------------------------------------------------------
 * C++ runtime helpers (slice 17)
 *
 * terminate() / _invalid_parameter_noinfo_noreturn() — the
 * C++ runtime's abort paths. Both map to SYS_EXIT with a
 * distinguishing exit code.
 * ------------------------------------------------------------------ */

__declspec(dllexport) UCRT_NORETURN void terminate(void)
{
    /* MSVC's convention: exit code 3 after abort-signal. */
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) 3));
    __builtin_unreachable();
}

__declspec(dllexport) UCRT_NORETURN void _invalid_parameter_noinfo_noreturn(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) 0xC000000D)); /* STATUS_INVALID_PARAMETER */
    __builtin_unreachable();
}
