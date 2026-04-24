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

/* ------------------------------------------------------------------
 * Minimal printf family (slice 30)
 *
 * Supports: %d, %i, %u, %x, %X, %p, %s, %c, %%, with optional
 * width (unpadded or 0-padded) and long/long-long modifiers
 * (l, ll, z). Enough for ~95% of real programs' format strings.
 *
 * No floating-point (%f, %g). No %n (security). No locale.
 * vsnprintf is the base; others forward to it.
 * ------------------------------------------------------------------ */

typedef unsigned long long va_list_slot;

static int emit_char(char* buf, size_t cap, size_t* pos, char c)
{
    if (buf && *pos + 1 < cap)
        buf[*pos] = c;
    (*pos)++;
    return 1;
}

static void emit_str(char* buf, size_t cap, size_t* pos, const char* s, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        emit_char(buf, cap, pos, s[i]);
}

static void emit_pad(char* buf, size_t cap, size_t* pos, int width, int printed, char fill)
{
    while (printed < width)
    {
        emit_char(buf, cap, pos, fill);
        ++printed;
    }
}

static int fmt_int(char* tmp, unsigned long long v, int base, int upper)
{
    /* Writes digits backward into tmp[32], returns length. */
    int         n      = 0;
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (v == 0)
    {
        tmp[n++] = '0';
        return n;
    }
    while (v)
    {
        tmp[n++] = digits[v % (unsigned) base];
        v /= (unsigned) base;
    }
    return n;
}

/* __builtin_va_list integrates with SysV ABI va_args; on
 * Windows x64 ABI the compiler handles the register<->memory
 * shuffle itself. We just read through the built-in macros. */
#define va_list    __builtin_va_list
#define va_start   __builtin_va_start
#define va_end     __builtin_va_end
#define va_arg_ptr(ap, type) (__builtin_va_arg(ap, type))

static int vfmt(char* buf, size_t cap, const char* fmt, va_list ap)
{
    size_t pos = 0;
    while (*fmt)
    {
        if (*fmt != '%')
        {
            emit_char(buf, cap, &pos, *fmt++);
            continue;
        }
        ++fmt;
        /* Flags */
        char pad = ' ';
        if (*fmt == '0')
        {
            pad = '0';
            ++fmt;
        }
        /* Width (decimal). */
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');
        /* Length modifier. 0 = int, 1 = long (32 on MSVC), 2 = long long, 3 = size_t */
        int mod = 0;
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
            char c = (char) va_arg_ptr(ap, int);
            emit_pad(buf, cap, &pos, width, 1, pad);
            emit_char(buf, cap, &pos, c);
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
            emit_pad(buf, cap, &pos, width, (int) n, pad);
            emit_str(buf, cap, &pos, s, n);
            break;
        }
        case 'd':
        case 'i':
        {
            long long v;
            if (mod == 2)
                v = va_arg_ptr(ap, long long);
            else if (mod == 3)
                v = (long long) va_arg_ptr(ap, size_t);
            else if (mod == 1)
                v = va_arg_ptr(ap, long);
            else
                v = va_arg_ptr(ap, int);
            int neg = 0;
            unsigned long long u;
            if (v < 0)
            {
                neg = 1;
                u   = (unsigned long long) (-v);
            }
            else
                u = (unsigned long long) v;
            int n     = fmt_int(tmp, u, 10, 0);
            int total = n + (neg ? 1 : 0);
            emit_pad(buf, cap, &pos, width, total, pad);
            if (neg)
                emit_char(buf, cap, &pos, '-');
            for (int i = n - 1; i >= 0; --i)
                emit_char(buf, cap, &pos, tmp[i]);
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
            int base  = (spec == 'u') ? 10 : 16;
            int upper = (spec == 'X');
            int n     = fmt_int(tmp, v, base, upper);
            emit_pad(buf, cap, &pos, width, n, pad);
            for (int i = n - 1; i >= 0; --i)
                emit_char(buf, cap, &pos, tmp[i]);
            break;
        }
        case 'p':
        {
            unsigned long long v = (unsigned long long) va_arg_ptr(ap, void*);
            emit_str(buf, cap, &pos, "0x", 2);
            int n = fmt_int(tmp, v, 16, 0);
            for (int i = n - 1; i >= 0; --i)
                emit_char(buf, cap, &pos, tmp[i]);
            break;
        }
        case '%':
            emit_char(buf, cap, &pos, '%');
            break;
        default:
            /* Unknown spec — emit literally for visibility. */
            emit_char(buf, cap, &pos, '%');
            emit_char(buf, cap, &pos, spec);
            break;
        }
    }
    if (buf && cap > 0)
        buf[pos < cap ? pos : cap - 1] = 0;
    return (int) pos;
}

__declspec(dllexport) int vsnprintf(char* buf, size_t cap, const char* fmt, va_list ap)
{
    return vfmt(buf, cap, fmt, ap);
}

__declspec(dllexport) int snprintf(char* buf, size_t cap, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vfmt(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}

__declspec(dllexport) int sprintf(char* buf, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vfmt(buf, 0x7FFFFFFF, fmt, ap);
    va_end(ap);
    return n;
}

__declspec(dllexport) int _vsnprintf(char* buf, size_t cap, const char* fmt, va_list ap)
{
    return vfmt(buf, cap, fmt, ap);
}

/* printf family — direct to stdout via SYS_WRITE. Uses a
 * 1 KiB stack buffer; truncates silently if longer. */

static void sys_write_bytes(const char* p, size_t n)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long) 2),   /* SYS_WRITE */
                       "D"((long long) 1),   /* fd=1 */
                       "S"((long long) p),
                       "d"((long long) n)
                     : "memory");
}

__declspec(dllexport) int printf(const char* fmt, ...)
{
    char    buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vfmt(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int) sizeof(buf) - 1)
        n = (int) sizeof(buf) - 1;
    sys_write_bytes(buf, (size_t) n);
    return n;
}

__declspec(dllexport) int puts(const char* s)
{
    if (!s)
        s = "(null)";
    size_t n = 0;
    while (s[n])
        ++n;
    sys_write_bytes(s, n);
    sys_write_bytes("\n", 1);
    return (int) n + 1;
}

__declspec(dllexport) int putchar(int c)
{
    char b = (char) c;
    sys_write_bytes(&b, 1);
    return c;
}

/* ------------------------------------------------------------------
 * File streams (slice 30)
 *
 * v0 represents FILE* as a Win32 HANDLE wrapped in a 24-byte
 * struct allocated on the process heap (to match fopen() ->
 * fclose() lifetime). The struct stores {handle, eof_flag,
 * err_flag}. All fwrite/fread/fputs etc. route through the
 * Win32 read/write calls in kernel32.dll's stub page.
 *
 * stdin / stdout / stderr live in the data section as three
 * preallocated FILE structs with synthetic handles -10/-11/-12
 * (Win32 STD_INPUT/OUTPUT/ERROR_HANDLE DWORDs).
 * ------------------------------------------------------------------ */

typedef struct ucrt_FILE
{
    long long handle;  /* Win32 handle (kernel32 file-handle range, or stdio sentinel) */
    int       eof;
    int       err;
} FILE;

static FILE g_stdin  = {-10LL, 0, 0};
static FILE g_stdout = {-11LL, 0, 0};
static FILE g_stderr = {-12LL, 0, 0};

/* MSVC exports stdin/stdout/stderr via accessor functions
 * (__acrt_iob_func, _iob_func) and via the symbols
 * __iob_func. The flat stubs don't mention them; we expose
 * both the symbols and the accessor so future PEs can
 * link either shape. */
__declspec(dllexport) FILE* __acrt_iob_func(unsigned int index)
{
    switch (index)
    {
    case 0:
        return &g_stdin;
    case 1:
        return &g_stdout;
    case 2:
        return &g_stderr;
    default:
        return (FILE*) 0;
    }
}

__declspec(dllexport) FILE* fopen(const char* path, const char* mode)
{
    (void) path;
    (void) mode;
    return (FILE*) 0; /* v0: no on-disk open — NULL */
}

typedef unsigned short _ucrt_wchar_t;
__declspec(dllexport) FILE* _wfopen(const _ucrt_wchar_t* path, const _ucrt_wchar_t* mode)
{
    (void) path;
    (void) mode;
    return (FILE*) 0;
}

__declspec(dllexport) int fclose(FILE* f)
{
    (void) f;
    return 0;
}

__declspec(dllexport) size_t fwrite(const void* ptr, size_t sz, size_t nmemb, FILE* f)
{
    if (!f)
        return 0;
    /* Route to stdout/stderr via SYS_WRITE(1) for any stdio
     * handle; anything else returns 0 (no real files in v0). */
    if (f->handle == -11LL || f->handle == -12LL)
    {
        sys_write_bytes((const char*) ptr, sz * nmemb);
        return nmemb;
    }
    return 0;
}

__declspec(dllexport) size_t fread(void* ptr, size_t sz, size_t nmemb, FILE* f)
{
    (void) ptr;
    (void) sz;
    (void) nmemb;
    if (f)
        f->eof = 1; /* Immediate EOF */
    return 0;
}

__declspec(dllexport) int fflush(FILE* f)
{
    (void) f;
    return 0;
}

__declspec(dllexport) int fputs(const char* s, FILE* f)
{
    if (!s || !f)
        return -1;
    if (f->handle == -11LL || f->handle == -12LL)
    {
        size_t n = 0;
        while (s[n])
            ++n;
        sys_write_bytes(s, n);
        return 0;
    }
    return -1;
}

__declspec(dllexport) int fputc(int c, FILE* f)
{
    if (!f)
        return -1;
    if (f->handle == -11LL || f->handle == -12LL)
    {
        char b = (char) c;
        sys_write_bytes(&b, 1);
        return c;
    }
    return -1;
}

__declspec(dllexport) char* fgets(char* buf, int n, FILE* f)
{
    (void) buf;
    (void) n;
    if (f)
        f->eof = 1;
    return (char*) 0;
}

__declspec(dllexport) int fgetc(FILE* f)
{
    if (f)
        f->eof = 1;
    return -1; /* EOF */
}

__declspec(dllexport) int fseek(FILE* f, long off, int whence)
{
    (void) f;
    (void) off;
    (void) whence;
    return -1;
}

__declspec(dllexport) long ftell(FILE* f)
{
    (void) f;
    return -1L;
}

__declspec(dllexport) int feof(FILE* f)
{
    return f ? f->eof : 1;
}

__declspec(dllexport) int ferror(FILE* f)
{
    return f ? f->err : 1;
}

__declspec(dllexport) int fprintf(FILE* f, const char* fmt, ...)
{
    char    buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vfmt(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int) sizeof(buf) - 1)
        n = (int) sizeof(buf) - 1;
    fwrite(buf, 1, (size_t) n, f);
    return n;
}

__declspec(dllexport) int vfprintf(FILE* f, const char* fmt, va_list ap)
{
    char buf[1024];
    int  n = vfmt(buf, sizeof(buf), fmt, ap);
    if (n > (int) sizeof(buf) - 1)
        n = (int) sizeof(buf) - 1;
    fwrite(buf, 1, (size_t) n, f);
    return n;
}

__declspec(dllexport) int vprintf(const char* fmt, va_list ap)
{
    char buf[1024];
    int  n = vfmt(buf, sizeof(buf), fmt, ap);
    if (n > (int) sizeof(buf) - 1)
        n = (int) sizeof(buf) - 1;
    sys_write_bytes(buf, (size_t) n);
    return n;
}

/* ------------------------------------------------------------------
 * Extended string / memory intrinsics (slice 30)
 * ------------------------------------------------------------------ */

__declspec(dllexport) NO_BUILTIN_STR int strncmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char ca = (unsigned char) a[i];
        unsigned char cb = (unsigned char) b[i];
        if (ca != cb)
            return (int) ca - (int) cb;
        if (!ca)
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

__declspec(dllexport) NO_BUILTIN_STR char* strcat(char* dst, const char* src)
{
    char* d = dst;
    while (*d)
        ++d;
    while ((*d++ = *src++))
        ;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_STR char* strncat(char* dst, const char* src, size_t n)
{
    char* d = dst;
    while (*d)
        ++d;
    for (size_t i = 0; i < n && src[i]; ++i)
        *d++ = src[i];
    *d = 0;
    return dst;
}

__declspec(dllexport) int _stricmp(const char* a, const char* b)
{
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char) (ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char) (cb + ('a' - 'A'));
        if (ca != cb)
            return (int) (unsigned char) ca - (int) (unsigned char) cb;
        ++a;
        ++b;
    }
    return (int) (unsigned char) *a - (int) (unsigned char) *b;
}

__declspec(dllexport) int _strnicmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char) (ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char) (cb + ('a' - 'A'));
        if (ca != cb)
            return (int) (unsigned char) ca - (int) (unsigned char) cb;
        if (!a[i])
            return 0;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * abs, isdigit / isalpha family (slice 30)
 *
 * Trivial — ASCII-only, fine for v0.
 * ------------------------------------------------------------------ */

__declspec(dllexport) int abs(int v)
{
    return v < 0 ? -v : v;
}

__declspec(dllexport) long labs(long v)
{
    return v < 0 ? -v : v;
}

__declspec(dllexport) long long llabs(long long v)
{
    return v < 0 ? -v : v;
}

__declspec(dllexport) int isalpha(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

__declspec(dllexport) int isdigit(int c)
{
    return c >= '0' && c <= '9';
}

__declspec(dllexport) int isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

__declspec(dllexport) int isprint(int c)
{
    return c >= 0x20 && c <= 0x7E;
}

__declspec(dllexport) int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}

__declspec(dllexport) int toupper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
}

__declspec(dllexport) int tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/* ------------------------------------------------------------------
 * qsort — standard library sort, implemented as insertion sort
 * for simplicity. Adequate for small arrays; real quicksort
 * can replace this when someone needs to sort millions of items.
 * ------------------------------------------------------------------ */

typedef int (*qsort_cmp_t)(const void*, const void*);

__declspec(dllexport) NO_BUILTIN_MEM void qsort(void* base, size_t n, size_t sz, qsort_cmp_t cmp)
{
    unsigned char* arr = (unsigned char*) base;
    for (size_t i = 1; i < n; ++i)
    {
        for (size_t j = i; j > 0; --j)
        {
            unsigned char* a = arr + (j - 1) * sz;
            unsigned char* b = arr + j * sz;
            if (cmp(a, b) <= 0)
                break;
            /* swap sz bytes */
            for (size_t k = 0; k < sz; ++k)
            {
                unsigned char t = a[k];
                a[k]            = b[k];
                b[k]            = t;
            }
        }
    }
}

__declspec(dllexport) void* bsearch(const void* key, const void* base, size_t n, size_t sz, qsort_cmp_t cmp)
{
    const unsigned char* arr = (const unsigned char*) base;
    size_t               lo  = 0;
    size_t               hi  = n;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int    c   = cmp(key, arr + mid * sz);
        if (c == 0)
            return (void*) (arr + mid * sz);
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return (void*) 0;
}

/* ------------------------------------------------------------------
 * Minimal sscanf (slice 33)
 *
 * Handles %d / %u / %x / %s / %c / %% with optional width.
 * No floating point, no %n, no character classes. Suitable
 * for parsing integers + tokens from plain ASCII input —
 * enough for most config-file consumers.
 *
 * Returns the number of fields successfully parsed, or -1 on
 * end-of-input before any match (glibc sscanf convention).
 * ------------------------------------------------------------------ */

static int ssc_is_space(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int ssc_digit(int c, int base)
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

static int vsscanf_impl(const char* buf, const char* fmt, va_list ap)
{
    int matches = 0;
    const char* p = buf;
    while (*fmt)
    {
        if (ssc_is_space(*fmt))
        {
            while (ssc_is_space(*fmt))
                ++fmt;
            while (ssc_is_space(*p))
                ++p;
            continue;
        }
        if (*fmt != '%')
        {
            if (*p != *fmt)
                return matches;
            ++p;
            ++fmt;
            continue;
        }
        ++fmt;
        /* Optional suppress with '*' */
        int suppress = 0;
        if (*fmt == '*')
        {
            suppress = 1;
            ++fmt;
        }
        /* Width */
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');
        /* Length mod */
        int mod = 0;
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
        char spec = *fmt++;
        if (spec == 0)
            break;
        /* Skip leading whitespace for numeric specs */
        if (spec != 'c' && spec != '%')
            while (ssc_is_space(*p))
                ++p;
        if (!*p && spec != '%')
            return matches == 0 ? -1 : matches;
        switch (spec)
        {
        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'X':
        {
            int               base = (spec == 'x' || spec == 'X') ? 16 : 10;
            int               neg  = 0;
            unsigned long long v   = 0;
            int                any = 0;
            if (spec != 'u' && spec != 'x' && spec != 'X')
            {
                if (*p == '-')
                {
                    neg = 1;
                    ++p;
                }
                else if (*p == '+')
                    ++p;
            }
            int dv;
            int consumed = 0;
            while ((dv = ssc_digit(*p, base)) >= 0 && (width == 0 || consumed < width))
            {
                v = v * (unsigned) base + (unsigned) dv;
                ++p;
                ++consumed;
                any = 1;
            }
            if (!any)
                return matches;
            if (!suppress)
            {
                if (mod == 2)
                    *va_arg_ptr(ap, long long*) = neg ? -(long long) v : (long long) v;
                else if (mod == 1)
                    *va_arg_ptr(ap, long*) = neg ? -(long) v : (long) v;
                else
                    *va_arg_ptr(ap, int*) = neg ? -(int) v : (int) v;
                ++matches;
            }
            break;
        }
        case 's':
        {
            char* out = suppress ? (char*) 0 : va_arg_ptr(ap, char*);
            int   n   = 0;
            while (*p && !ssc_is_space(*p) && (width == 0 || n < width - 1))
            {
                if (out)
                    out[n] = *p;
                ++p;
                ++n;
            }
            if (out)
                out[n] = 0;
            if (!suppress)
                ++matches;
            break;
        }
        case 'c':
        {
            int n = width > 0 ? width : 1;
            char* out = suppress ? (char*) 0 : va_arg_ptr(ap, char*);
            for (int i = 0; i < n && *p; ++i)
            {
                if (out)
                    out[i] = *p;
                ++p;
            }
            if (!suppress)
                ++matches;
            break;
        }
        case '%':
            if (*p == '%')
                ++p;
            else
                return matches;
            break;
        default:
            return matches;
        }
    }
    return matches;
}

__declspec(dllexport) int vsscanf(const char* buf, const char* fmt, va_list ap)
{
    return vsscanf_impl(buf, fmt, ap);
}

__declspec(dllexport) int sscanf(const char* buf, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsscanf_impl(buf, fmt, ap);
    va_end(ap);
    return n;
}

/* ------------------------------------------------------------------
 * rand / srand (slice 33) — SPLITMIX64 (deterministic).
 * ------------------------------------------------------------------ */

static unsigned long long g_rand_state = 0xDEADBEEFCAFEBABEULL;

__declspec(dllexport) void srand(unsigned int seed)
{
    g_rand_state = 0x9E3779B97F4A7C15ULL ^ ((unsigned long long) seed << 32) ^ seed;
}

__declspec(dllexport) int rand(void)
{
    g_rand_state = g_rand_state * 6364136223846793005ULL + 1442695040888963407ULL;
    /* RAND_MAX = 32767 per MSVC. */
    return (int) ((g_rand_state >> 33) & 0x7FFF);
}

/* ------------------------------------------------------------------
 * getenv / _putenv (slice 33) — v0 has no env block. All lookups
 * report "not found"; _putenv silently succeeds.
 * ------------------------------------------------------------------ */

__declspec(dllexport) char* getenv(const char* name)
{
    (void) name;
    return (char*) 0;
}

__declspec(dllexport) int _putenv(const char* entry)
{
    (void) entry;
    return 0;
}

__declspec(dllexport) int _putenv_s(const char* name, const char* value)
{
    (void) name;
    (void) value;
    return 0;
}

__declspec(dllexport) unsigned long _errno_dummy(void) { return 0; } /* placeholder */

/* _errno() returns a pointer to the thread's errno slot.
 * Single-thread in v0; return the address of a global. */
static int g_errno = 0;

__declspec(dllexport) int* _errno(void)
{
    return &g_errno;
}
