/*
 * userland/libs/ucrtbase/ucrtbase.c
 *
 * Freestanding DuetOS ucrtbase.dll. Retires the prior
 * UCRT runtime stubs in kernel/subsystems/win32/thunks.cpp.
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
 * Build: tools/build/build-ucrtbase-dll.sh at /base:0x10050000.
 */

typedef unsigned int UINT;
typedef unsigned long long size_t;

#define UCRT_NORETURN __attribute__((noreturn))
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

#define NO_BUILTIN_STR __attribute__((no_builtin("strlen", "strcmp", "strcpy", "strchr")))
#define NO_BUILTIN_MEM __attribute__((no_builtin("memset", "memcpy")))

/* ------------------------------------------------------------------
 * Heap allocation
 * ------------------------------------------------------------------ */

__declspec(dllexport) void* malloc(size_t size)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)size) : "memory");
    return (void*)rv;
}

__declspec(dllexport) void free(void* ptr)
{
    if (ptr == (void*)0)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)ptr) : "memory");
}

__declspec(dllexport) NO_BUILTIN_MEM void* calloc(size_t n, size_t size)
{
    /* Overflow guard: `n * size` is the textbook calloc footgun.
     * Without this check, calloc(0x100000000, 0x100000000) wraps to
     * total=0, malloc returns a near-empty block, and the caller
     * writes off the end. Reject before the multiply. */
    if (n != 0 && size > (size_t)-1 / n)
        return (void*)0;
    const size_t total = n * size;
    void* p = malloc(total);
    if (p == (void*)0)
        return (void*)0;
    /* Zero-fill the returned region. Byte loop keeps clang
     * from recognising this as memset and calling itself. */
    unsigned char* b = (unsigned char*)p;
    for (size_t i = 0; i < total; ++i)
        b[i] = 0;
    return p;
}

__declspec(dllexport) void* realloc(void* ptr, size_t size)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)15), "D"((long long)ptr), "S"((long long)size) : "memory");
    return (void*)rv;
}

/* _aligned_malloc / _aligned_free — v0 ignores the alignment
 * argument and treats them as plain malloc/free. Our heap
 * returns 8-byte-aligned blocks anyway, which covers every
 * caller today (CRT callers that ask for 16 or 32 get 8, but
 * no existing PE has tripped on that yet). A follow-up can
 * add real alignment by over-allocating + storing a back-
 * pointer. */
__declspec(dllexport) void* _aligned_malloc(size_t size, size_t alignment)
{
    (void)alignment;
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
    __asm__ volatile("int $0x80" : : "a"((long)0), "D"((long)code));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) UCRT_NORETURN void _exit(int code)
{
    __asm__ volatile("int $0x80" : : "a"((long)0), "D"((long)code));
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * CRT startup no-ops
 *
 * These are called by the MSVC CRT's entry glue during
 * process init. Real implementations iterate function-pointer
 * tables (_initterm) or install error handlers. Our PEs have
 * been running with flat-stub return-zero versions of these
 * — preserving that behaviour keeps every existing PE
 * stable.
 * ------------------------------------------------------------------ */

/* void _initterm(PVPFV first, PVPFV last); — iterate the
 * [first, last) range of void(*)(void) function pointers and
 * call each. Real Windows does this; our flat stub skipped
 * it. Preserve the flat-stub behaviour (no-op) for now. */
__declspec(dllexport) void _initterm(void** first, void** last)
{
    (void)first;
    (void)last;
}

/* int _initterm_e(PVFV first, PVFV last); — like _initterm
 * but each callback returns int; stop on first non-zero.
 * Return 0 (success). */
__declspec(dllexport) int _initterm_e(void** first, void** last)
{
    (void)first;
    (void)last;
    return 0;
}

__declspec(dllexport) void _cexit(void) {}
__declspec(dllexport) void _c_exit(void) {}
__declspec(dllexport) void _set_app_type(int t)
{
    (void)t;
}
__declspec(dllexport) int __setusermatherr(void* handler)
{
    (void)handler;
    return 0;
}
__declspec(dllexport) int _configthreadlocale(int per_thread)
{
    (void)per_thread;
    return 0;
}

/* ------------------------------------------------------------------
 * Thread creation — _beginthread + _beginthreadex.
 *
 * Both wrap SYS_THREAD_CREATE (syscall 45) which spawns a new Task
 * sharing the caller's Process / AddressSpace / cap set. The kernel
 * returns a Win32 pseudo-handle (kWin32ThreadBase + slot, i.e.
 * 0x400..0x407) on success or a negative errno on failure
 * (cap denied, slot-table full, etc.). _beginthread's "auto-close" semantic is
 * a no-op here because the kernel reclaims slots on thread exit
 * regardless of CloseHandle calls.
 *
 * The MSVC CRT signature differences:
 *   _beginthread(start, stack, arg) — start returns void
 *   _beginthreadex(security, stack, start, arg, initflag, *thrdid)
 *                                 — start returns unsigned int
 * The kernel doesn't care about the start function's return type
 * (a thread that returns from its entry function lands in the
 * kernel-side teardown either way), so both signatures route to
 * the same syscall. stack_size is ignored — the kernel uses a
 * fixed kV0ThreadStackPages allocation per thread.
 *
 * SYS_THREAD_CREATE = 45 takes:
 *   rdi = user-mode start VA
 *   rsi = user-mode arg
 * and returns the handle in rax.
 * ------------------------------------------------------------------ */

typedef unsigned long long uintptr_t;

static inline long long ucrt_thread_create(void* start, void* arg)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)45), "D"((long long)(unsigned long long)start),
                       "S"((long long)(unsigned long long)arg)
                     : "memory");
    return rv;
}

__declspec(dllexport) uintptr_t _beginthread(void (*start)(void*), unsigned stack_size, void* arg)
{
    (void)stack_size;
    if (start == 0)
    {
        return (uintptr_t)-1L;
    }
    const long long handle = ucrt_thread_create((void*)start, arg);
    return handle < 0 ? (uintptr_t)-1L : (uintptr_t)handle;
}

__declspec(dllexport) uintptr_t _beginthreadex(void* security, unsigned stack_size, unsigned (*start)(void*), void* arg,
                                               unsigned initflag, unsigned* thrdaddr)
{
    (void)security;
    (void)stack_size;
    (void)initflag;
    if (start == 0)
    {
        return 0;
    }
    const long long handle = ucrt_thread_create((void*)start, arg);
    if (handle < 0)
    {
        if (thrdaddr != 0)
        {
            *thrdaddr = 0;
        }
        return 0;
    }
    if (thrdaddr != 0)
    {
        // Use the low bits of the handle as the thread-id surrogate.
        // Win32 thread IDs are u32; the handle base 0x400 fits.
        *thrdaddr = (unsigned)((uintptr_t)handle & 0xFFFFFFFFu);
    }
    return (uintptr_t)handle;
}

__declspec(dllexport) void _endthread(void)
{
    // Thread exit is reached either by returning from the start
    // function (kernel-side teardown handles that) or by an
    // explicit ExitThread / SYS_EXIT. _endthread is the legacy
    // "I'm done" marker; route to SYS_EXIT(0) so the calling
    // thread cleanly leaves.
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)0), "D"((long long)0) : "memory");
    (void)discard;
}

__declspec(dllexport) void _endthreadex(unsigned retval)
{
    (void)retval;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)0), "D"((long long)retval) : "memory");
    (void)discard;
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

__declspec(dllexport) NO_BUILTIN_STR char* strchr(const char* s, int c)
{
    const char ch = (char)c;
    for (;; ++s)
    {
        if (*s == ch)
            return (char*)s;
        if (*s == 0)
            return (char*)0;
    }
}

/* ------------------------------------------------------------------
 * Number conversion
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

typedef int atoi_int;
typedef long atoi_long; /* MSVC long = 32-bit */
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
    return (atoi_long)atoi(s);
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

    atoi_long v = 0;
    int dv;
    while ((dv = digit_value(*p, base)) >= 0)
    {
        v = v * base + dv;
        ++p;
    }
    if (endptr != (char**)0)
        *endptr = (char*)p;
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
    int dv;
    while ((dv = digit_value(*p, base)) >= 0)
    {
        v = v * (atoi_ulong)base + (atoi_ulong)dv;
        ++p;
    }
    if (endptr != (char**)0)
        *endptr = (char*)p;
    return neg ? (atoi_ulong)(-(atoi_long)v) : v;
}

/* ------------------------------------------------------------------
 * C++ runtime helpers
 *
 * terminate() / _invalid_parameter_noinfo_noreturn() — the
 * C++ runtime's abort paths. Both map to SYS_EXIT with a
 * distinguishing exit code.
 * ------------------------------------------------------------------ */

__declspec(dllexport) UCRT_NORETURN void terminate(void)
{
    /* MSVC's convention: exit code 3 after abort-signal. */
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) UCRT_NORETURN void _invalid_parameter_noinfo_noreturn(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)0xC000000D)); /* STATUS_INVALID_PARAMETER */
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * Minimal printf family
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

/* __builtin_va_list integrates with SysV ABI va_args; on
 * Windows x64 ABI the compiler handles the register<->memory
 * shuffle itself. We just read through the built-in macros. */
#define va_list __builtin_va_list
#define va_start __builtin_va_start
#define va_end __builtin_va_end
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
            char c = (char)va_arg_ptr(ap, int);
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
            emit_pad(buf, cap, &pos, width, (int)n, pad);
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
            int n = fmt_int(tmp, u, 10, 0);
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
            int base = (spec == 'u') ? 10 : 16;
            int upper = (spec == 'X');
            int n = fmt_int(tmp, v, base, upper);
            emit_pad(buf, cap, &pos, width, n, pad);
            for (int i = n - 1; i >= 0; --i)
                emit_char(buf, cap, &pos, tmp[i]);
            break;
        }
        case 'p':
        {
            unsigned long long v = (unsigned long long)va_arg_ptr(ap, void*);
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
    return (int)pos;
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
                     : "a"((long long)2), /* SYS_WRITE */
                       "D"((long long)1), /* fd=1 */
                       "S"((long long)p), "d"((long long)n)
                     : "memory");
}

__declspec(dllexport) int printf(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vfmt(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    sys_write_bytes(buf, (size_t)n);
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
    return (int)n + 1;
}

__declspec(dllexport) int putchar(int c)
{
    char b = (char)c;
    sys_write_bytes(&b, 1);
    return c;
}

/* ------------------------------------------------------------------
 * File streams
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
    long long handle; /* Win32 handle (kernel32 file-handle range, or stdio sentinel) */
    int eof;
    int err;
} FILE;

static FILE g_stdin = {-10LL, 0, 0};
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
        return (FILE*)0;
    }
}

/* Real fopen: route to SYS_FILE_OPEN (20) which takes rdi =
 * ASCII path ptr, rsi = path length. Returns a kernel handle
 * in 0x100..0x10F (Win32 file-handle range) on success, or -1
 * on miss. Wrap that in a FILE* allocated on the process heap.
 *
 * Mode string is parsed for 'r'/'w'/'a' for diagnostic /
 * read-vs-write disambiguation; v0 only really supports reads
 * but we still fail a write-mode open on an unknown path the
 * same way — returns NULL. */

static FILE* alloc_FILE_wrapping(long long handle)
{
    /* Heap-allocate the 24-byte FILE struct so fclose can free
     * it. SYS_HEAP_ALLOC = 11. */
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)sizeof(FILE)) : "memory");
    if (rv == 0)
        return (FILE*)0;
    FILE* f = (FILE*)rv;
    f->handle = handle;
    f->eof = 0;
    f->err = 0;
    return f;
}

__declspec(dllexport) FILE* fopen(const char* path, const char* mode)
{
    if (!path)
        return (FILE*)0;
    (void)mode;
    /* Compute length. */
    long long n = 0;
    while (path[n])
        ++n;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)20),   /* SYS_FILE_OPEN */
                       "D"((long long)path), /* rdi = path */
                       "S"(n)                /* rsi = length */
                     : "memory");
    if (rv < 0x100 || rv >= 0x110)
        return (FILE*)0; /* out-of-range = failure */
    return alloc_FILE_wrapping(rv);
}

typedef unsigned short _ucrt_wchar_t;
__declspec(dllexport) FILE* _wfopen(const _ucrt_wchar_t* path, const _ucrt_wchar_t* mode)
{
    if (!path)
        return (FILE*)0;
    (void)mode;
    /* UTF-16 -> ASCII strip on stack. */
    char ascii[256];
    long long n = 0;
    while (n < 255 && path[n])
    {
        ascii[n] = (char)(path[n] & 0xFF);
        ++n;
    }
    ascii[n] = 0;
    return fopen(ascii, (const char*)0);
}

__declspec(dllexport) int fclose(FILE* f)
{
    if (!f)
        return -1;
    /* Close kernel handle if this is a real file (not a stdio
     * sentinel -10/-11/-12). SYS_FILE_CLOSE = 22. */
    if (f->handle >= 0x100 && f->handle < 0x110)
    {
        long long discard;
        __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)22), "D"(f->handle) : "memory");
    }
    /* Free the FILE struct back to the heap. SYS_HEAP_FREE = 12. */
    long long discard2;
    __asm__ volatile("int $0x80" : "=a"(discard2) : "a"((long long)12), "D"((long long)f) : "memory");
    return 0;
}

__declspec(dllexport) size_t fwrite(const void* ptr, size_t sz, size_t nmemb, FILE* f)
{
    if (!f || !ptr || sz == 0 || nmemb == 0)
        return 0;
    size_t total = sz * nmemb;
    /* stdout / stderr sentinels — route through SYS_WRITE(fd=1)
     * which the kernel sinks at the serial console. */
    if (f->handle == -11LL || f->handle == -12LL)
    {
        sys_write_bytes((const char*)ptr, total);
        return nmemb;
    }
    /* Real file handle (Win32-shaped 0x100..0x10F) — route to
     * SYS_FILE_WRITE (43). rdi = handle, rsi = buf, rdx = count.
     * Returns bytes written, or negative on error. */
    if (f->handle >= 0x100 && f->handle < 0x110)
    {
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)43),   /* SYS_FILE_WRITE */
                           "D"(f->handle),       /* rdi = handle */
                           "S"((long long)ptr),  /* rsi = buf */
                           "d"((long long)total) /* rdx = count */
                         : "memory");
        if (rv <= 0)
        {
            f->err = 1;
            return 0;
        }
        /* Return whole-element count actually written. fwrite
         * conventionally returns nmemb-actually-written, not bytes;
         * partial-element writes round down. */
        return (size_t)rv / sz;
    }
    return 0;
}

__declspec(dllexport) size_t fread(void* ptr, size_t sz, size_t nmemb, FILE* f)
{
    if (!f || !ptr || sz == 0 || nmemb == 0)
        return 0;
    /* stdio sentinels can't be read in v0. */
    if (f->handle < 0x100 || f->handle >= 0x110)
    {
        f->eof = 1;
        return 0;
    }
    size_t total = sz * nmemb;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)21),   /* SYS_FILE_READ */
                       "D"(f->handle),       /* rdi = handle */
                       "S"((long long)ptr),  /* rsi = buf */
                       "d"((long long)total) /* rdx = count */
                     : "memory");
    if (rv <= 0)
    {
        f->eof = 1;
        return 0;
    }
    /* Partial read = EOF on next call. */
    if ((size_t)rv < total)
        f->eof = 1;
    return (size_t)rv / sz;
}

__declspec(dllexport) int fflush(FILE* f)
{
    (void)f;
    return 0;
}

/* setvbuf / setbuf — no-op success. The DuetOS CRT doesn't buffer
 * stream output today (every fwrite / fputs / fprintf hits the
 * underlying SYS_WRITE syscall directly). When buffered I/O lands,
 * setvbuf needs to remember the buffer + mode on the FILE struct
 * so the next fflush respects it. */
#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

__declspec(dllexport) int setvbuf(FILE* f, char* buf, int mode, size_t size)
{
    (void)f;
    (void)buf;
    (void)mode;
    (void)size;
    return 0;
}

__declspec(dllexport) void setbuf(FILE* f, char* buf)
{
    (void)f;
    (void)buf;
}

/* tmpnam / tmpfile — generate a temp-directory path and (for
 * tmpfile) open a writable handle to it. The drive sentinel
 * matches GetTempPathA's `X:\` (see kernel32.c) so apps that
 * round-trip through GetTempPath / fopen see the same root.
 * The name counter is process-local; collisions are
 * caller-visible (fopen returns NULL if the file exists). */
static unsigned int g_tmp_counter = 0;

#define L_tmpnam 32

__declspec(dllexport) char* tmpnam(char* buf)
{
    static char internal_buf[L_tmpnam];
    char* dst = buf ? buf : internal_buf;
    /* Format: "X:\\Temp\\duetXXXX.tmp" — 19 bytes + NUL fits in 32. */
    const char prefix[] = "X:\\Temp\\duet";
    int i = 0;
    while (prefix[i] && i < L_tmpnam - 1)
    {
        dst[i] = prefix[i];
        ++i;
    }
    /* 4 hex digits of the counter so two consecutive calls
     * produce different names. */
    unsigned int v = ++g_tmp_counter;
    const char hex[] = "0123456789ABCDEF";
    for (int j = 3; j >= 0 && i < L_tmpnam - 1; --j)
        dst[i++] = hex[(v >> (j * 4)) & 0xF];
    const char suffix[] = ".tmp";
    int k = 0;
    while (suffix[k] && i < L_tmpnam - 1)
        dst[i++] = suffix[k++];
    dst[i] = 0;
    return dst;
}

__declspec(dllexport) FILE* tmpfile(void)
{
    char name[L_tmpnam];
    tmpnam(name);
    /* "w+b" — read+write, truncate to zero. fopen handles the
     * open. Note: we don't auto-delete on close (Windows has
     * FILE_FLAG_DELETE_ON_CLOSE; our v0 doesn't). Caller is
     * responsible for unlink if they care. */
    return fopen(name, "w+b");
}

/* MSVC-suffixed variant: same behaviour, takes a buffer + size. */
__declspec(dllexport) int tmpnam_s(char* buf, size_t size)
{
    if (!buf || size < L_tmpnam)
        return 22; /* EINVAL */
    tmpnam(buf);
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
        char b = (char)c;
        sys_write_bytes(&b, 1);
        return c;
    }
    return -1;
}

/* fgets: read one byte at a time via fread, stop at \n or EOF.
 * Returns buf on success, NULL on immediate EOF. Consistent
 * with the C standard: if we hit EOF with no bytes read, NULL;
 * otherwise buf is returned even if the line has no '\n'. */
__declspec(dllexport) char* fgets(char* buf, int n, FILE* f)
{
    if (!buf || n <= 1 || !f)
        return (char*)0;
    int i = 0;
    while (i < n - 1)
    {
        char c;
        size_t got = fread(&c, 1, 1, f);
        if (got == 0)
            break;
        buf[i++] = c;
        if (c == '\n')
            break;
    }
    if (i == 0)
        return (char*)0;
    buf[i] = 0;
    return buf;
}

__declspec(dllexport) int fgetc(FILE* f)
{
    unsigned char c;
    size_t got = fread(&c, 1, 1, f);
    if (got == 0)
        return -1; /* EOF */
    return (int)c;
}

/* fseek: SYS_FILE_SEEK = 23, rdi=handle, rsi=offset, rdx=whence.
 * Whence 0/1/2 match SEEK_SET/CUR/END in both worlds.
 * Returns 0 on success (matches C stdlib contract). */
__declspec(dllexport) int fseek(FILE* f, long off, int whence)
{
    if (!f || f->handle < 0x100 || f->handle >= 0x110)
        return -1;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)23), /* SYS_FILE_SEEK */
                       "D"(f->handle), "S"((long long)off), "d"((long long)whence)
                     : "memory");
    if (rv < 0)
        return -1;
    /* Seek succeeded -> clear EOF flag. */
    f->eof = 0;
    return 0;
}

/* ftell: use SEEK_CUR with offset=0 to query the current cursor
 * without moving. Kernel SYS_FILE_SEEK returns the new position
 * in rax. */
__declspec(dllexport) long ftell(FILE* f)
{
    if (!f || f->handle < 0x100 || f->handle >= 0x110)
        return -1L;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)23),                /* SYS_FILE_SEEK */
                       "D"(f->handle), "S"((long long)0), /* offset 0 */
                       "d"((long long)1)                  /* SEEK_CUR */
                     : "memory");
    return rv < 0 ? -1L : (long)rv;
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
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vfmt(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, f);
    return n;
}

__declspec(dllexport) int vfprintf(FILE* f, const char* fmt, va_list ap)
{
    char buf[1024];
    int n = vfmt(buf, sizeof(buf), fmt, ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, f);
    return n;
}

__declspec(dllexport) int vprintf(const char* fmt, va_list ap)
{
    char buf[1024];
    int n = vfmt(buf, sizeof(buf), fmt, ap);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    sys_write_bytes(buf, (size_t)n);
    return n;
}

/* ------------------------------------------------------------------
 * Extended string / memory intrinsics
 * ------------------------------------------------------------------ */

__declspec(dllexport) NO_BUILTIN_STR int strncmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb)
            return (int)ca - (int)cb;
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

__declspec(dllexport) int _strnicmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        if (!a[i])
            return 0;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * abs, isdigit / isalpha family
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
    unsigned char* arr = (unsigned char*)base;
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
                a[k] = b[k];
                b[k] = t;
            }
        }
    }
}

__declspec(dllexport) void* bsearch(const void* key, const void* base, size_t n, size_t sz, qsort_cmp_t cmp)
{
    const unsigned char* arr = (const unsigned char*)base;
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int c = cmp(key, arr + mid * sz);
        if (c == 0)
            return (void*)(arr + mid * sz);
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return (void*)0;
}

/* ------------------------------------------------------------------
 * Minimal sscanf
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
            int base = (spec == 'x' || spec == 'X') ? 16 : 10;
            int neg = 0;
            unsigned long long v = 0;
            int any = 0;
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
                v = v * (unsigned)base + (unsigned)dv;
                ++p;
                ++consumed;
                any = 1;
            }
            if (!any)
                return matches;
            if (!suppress)
            {
                if (mod == 2)
                    *va_arg_ptr(ap, long long*) = neg ? -(long long)v : (long long)v;
                else if (mod == 1)
                    *va_arg_ptr(ap, long*) = neg ? -(long)v : (long)v;
                else
                    *va_arg_ptr(ap, int*) = neg ? -(int)v : (int)v;
                ++matches;
            }
            break;
        }
        case 's':
        {
            char* out = suppress ? (char*)0 : va_arg_ptr(ap, char*);
            int n = 0;
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
            char* out = suppress ? (char*)0 : va_arg_ptr(ap, char*);
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
 * rand / srand — SPLITMIX64 (deterministic).
 * ------------------------------------------------------------------ */

static unsigned long long g_rand_state = 0xDEADBEEFCAFEBABEULL;

__declspec(dllexport) void srand(unsigned int seed)
{
    g_rand_state = 0x9E3779B97F4A7C15ULL ^ ((unsigned long long)seed << 32) ^ seed;
}

__declspec(dllexport) int rand(void)
{
    g_rand_state = g_rand_state * 6364136223846793005ULL + 1442695040888963407ULL;
    /* RAND_MAX = 32767 per MSVC. */
    return (int)((g_rand_state >> 33) & 0x7FFF);
}

/* ------------------------------------------------------------------
 * getenv / _putenv — small static defaults block plus a mutable
 * overlay that `_putenv` / `_putenv_s` write into. `getenv`
 * consults the overlay first so user-set variables shadow the
 * built-in defaults.
 *
 * GAP: process-wide env block. The overlay is per-DLL-instance
 * (one ucrtbase per process), which matches MSVC's contract for
 * statically-linked CRT but won't survive a fork. v0 has no fork
 * primitive so this is the right shape for now.
 * ------------------------------------------------------------------ */

/* Static defaults. Real Windows programs consult these during
 * CRT init (PATH for spawn, TEMP for temp files, USERNAME for
 * profile lookup). The return-pointer storage is the literal
 * string data — callers must not mutate. Real MSVC ucrt does
 * the same (getenv returns pointer into a per-process env
 * block). */

static const struct
{
    const char* name;
    const char* value;
} k_env_vars[] = {
    {"PATH", "X:\\;X:\\System;X:\\bin"},
    {"PATHEXT", ".EXE;.COM;.BAT"},
    {"TEMP", "X:\\Temp"},
    {"TMP", "X:\\Temp"},
    {"USERNAME", "user"},
    {"USERDOMAIN", "DUETOS"},
    {"USERPROFILE", "X:\\Users\\user"},
    {"COMPUTERNAME", "DUETOS"},
    {"SYSTEMROOT", "X:\\"},
    {"WINDIR", "X:\\"},
    {"OS", "DuetOS_NT"},
    {"PROCESSOR_ARCHITECTURE", "AMD64"},
    {"NUMBER_OF_PROCESSORS", "1"},
    {"APPDATA", "X:\\Users\\user\\AppData\\Roaming"},
    {"LOCALAPPDATA", "X:\\Users\\user\\AppData\\Local"},
    {"PROGRAMFILES", "X:\\Program Files"},
    {"COMSPEC", "X:\\cmd.exe"},
};

static int env_name_eq(const char* a, const char* b)
{
    /* Windows env var names are case-insensitive. */
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z')
            ca = (char)(ca - ('a' - 'A'));
        if (cb >= 'a' && cb <= 'z')
            cb = (char)(cb - ('a' - 'A'));
        if (ca != cb)
            return 0;
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

#define UCRT_ENV_OVERLAY_MAX 32
#define UCRT_ENV_NAME_MAX 64
#define UCRT_ENV_VAL_MAX 256

static struct
{
    int in_use;
    char name[UCRT_ENV_NAME_MAX];
    char value[UCRT_ENV_VAL_MAX];
} g_env_overlay[UCRT_ENV_OVERLAY_MAX];

static int env_copy_bounded(char* dst, const char* src, int max)
{
    int i = 0;
    while (i + 1 < max && src[i] != 0)
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = 0;
    return i;
}

static int env_overlay_find(const char* name)
{
    for (int i = 0; i < UCRT_ENV_OVERLAY_MAX; ++i)
        if (g_env_overlay[i].in_use && env_name_eq(g_env_overlay[i].name, name))
            return i;
    return -1;
}

static int env_overlay_upsert(const char* name, const char* value)
{
    /* Empty value unsets the variable. */
    int existing = env_overlay_find(name);
    if (value == (const char*)0 || value[0] == 0)
    {
        if (existing >= 0)
            g_env_overlay[existing].in_use = 0;
        return 0;
    }
    int slot = existing;
    if (slot < 0)
    {
        for (int i = 0; i < UCRT_ENV_OVERLAY_MAX; ++i)
            if (!g_env_overlay[i].in_use)
            {
                slot = i;
                break;
            }
    }
    if (slot < 0)
        return -1; /* overlay full */
    env_copy_bounded(g_env_overlay[slot].name, name, UCRT_ENV_NAME_MAX);
    env_copy_bounded(g_env_overlay[slot].value, value, UCRT_ENV_VAL_MAX);
    g_env_overlay[slot].in_use = 1;
    return 0;
}

__declspec(dllexport) char* getenv(const char* name)
{
    if (!name)
        return (char*)0;
    int ov = env_overlay_find(name);
    if (ov >= 0)
        return g_env_overlay[ov].value;
    for (size_t i = 0; i < sizeof(k_env_vars) / sizeof(k_env_vars[0]); ++i)
        if (env_name_eq(k_env_vars[i].name, name))
            return (char*)k_env_vars[i].value;
    return (char*)0;
}

__declspec(dllexport) int _putenv(const char* entry)
{
    /* `entry` is "NAME=VALUE". Empty VALUE unsets the variable.
     * Returns 0 on success, -1 on error (no '=' or overlay full). */
    if (entry == (const char*)0)
        return -1;
    int eq = -1;
    for (int i = 0; entry[i] != 0; ++i)
        if (entry[i] == '=')
        {
            eq = i;
            break;
        }
    if (eq <= 0)
        return -1; /* no '=' or empty name */
    char name_buf[UCRT_ENV_NAME_MAX];
    int n = (eq < UCRT_ENV_NAME_MAX - 1) ? eq : (UCRT_ENV_NAME_MAX - 1);
    for (int i = 0; i < n; ++i)
        name_buf[i] = entry[i];
    name_buf[n] = 0;
    return env_overlay_upsert(name_buf, entry + eq + 1);
}

__declspec(dllexport) int _putenv_s(const char* name, const char* value)
{
    /* MSVC contract: NULL name → EINVAL (22). Empty value unsets. */
    if (name == (const char*)0 || name[0] == 0)
        return 22; /* EINVAL */
    if (value == (const char*)0)
        return 22;
    if (env_overlay_upsert(name, value) != 0)
        return 12; /* ENOMEM — overlay full */
    return 0;
}

/* _errno() returns a pointer to the thread's errno slot.
 * Single-thread in v0; return the address of a global. */
static int g_errno = 0;

__declspec(dllexport) int* _errno(void)
{
    return &g_errno;
}

/* ==================================================================
 * Modern UCRT startup surface
 *
 * Statically-linked UCRT exes (cmd.exe, anything built with a
 * recent MSVC /MT) drive `mainCRTStartup` through this sequence
 * during init:
 *
 *   _initterm_e(__xi_a, __xi_z)            // C init
 *   _initialize_narrow_environment()       // env block
 *   _configure_narrow_argv(mode)           // argv parse
 *   _get_initial_narrow_environment()      // -> char**
 *   __p___argc() / __p___argv()            // -> &__argc / &__argv
 *   _initialize_onexit_table(table)        // atexit ledger
 *   ...
 *   main(__argc, __argv, _environ)
 *
 * The fatal bit for us: the CRT *dereferences* the pointers
 * `__p___argv()` and `__p___argc()` hand back. A NO-OP stub that
 * returns 0 makes the CRT read through a null pointer -> #PF
 * (0xc0000005), which is exactly where cmd.exe died before this
 * surface existed. So these must return the address of real
 * storage, even if the storage holds a minimal { argc=1,
 * argv={"X:\\cmd.exe", NULL} } program model.
 * ================================================================== */

/* The narrow program model. One synthetic arg (the program name)
 * so `__argc >= 1` and `__argv[0]` is a valid C string — the shape
 * every argv-walking CRT expects. `_environ` is an empty,
 * NULL-terminated vector (getenv() still works via the k_env_vars
 * table above; this block is only what the CRT hands to main()). */
static char g_arg0[] = "X:\\cmd.exe";
static char* g_argv[2] = {g_arg0, (char*)0};
/* `__argv` is a `char**` global; __p___argv() returns its
 * address (char***). g_argv_ptr IS that global; it points at the
 * vector above. Likewise g_environ_ptr for `_environ`. */
static char** g_argv_ptr = g_argv;
static int g_argc = 1;
static char* g_environ[1] = {(char*)0};
static char** g_environ_ptr = g_environ;
static int g_commode = 0;
static int g_fmode = 0;

/* __p___argv() -> &__argv (char***); __p___argc() -> &__argc.
 * The CRT reads *__p___argv() to get argv and *__p___argc() for
 * argc, then passes both to main(). Returning the address of real
 * storage is what keeps that dereference from faulting. */
__declspec(dllexport) char*** __p___argv(void)
{
    return &g_argv_ptr;
}

__declspec(dllexport) int* __p___argc(void)
{
    return &g_argc;
}

/* __p__commode -> &_commode (file-commit mode flag). The CRT
 * reads/writes this during stdio init; a real backing int is all
 * it needs. */
__declspec(dllexport) int* __p__commode(void)
{
    return &g_commode;
}

/* _get_initial_narrow_environment() -> char** environ. Returns
 * the NULL-terminated (empty) environment vector. The CRT stores
 * this as the `_environ` global and hands it to main(). */
__declspec(dllexport) char** _get_initial_narrow_environment(void)
{
    return g_environ_ptr;
}

/* _initialize_narrow_environment() — set up the narrow env block.
 * Ours is statically constructed (empty + NULL terminator), so
 * there's nothing to build at runtime. Return 0 = success. */
__declspec(dllexport) int _initialize_narrow_environment(void)
{
    return 0;
}

/* _configure_narrow_argv(mode) — parse the command line into
 * __argv/__argc. Our program model is the single synthetic arg0
 * built above; there's no real command line to tokenise in v0, so
 * this is a success no-op. Return 0 = success. */
__declspec(dllexport) int _configure_narrow_argv(int mode)
{
    (void)mode;
    return 0;
}

/* ------------------------------------------------------------------
 * Wide (UTF-16) command-line + argv surface for wWinMain / wmain PEs.
 *
 * The narrow block above serves main()/WinMain() apps; wide-entry
 * GUI apps (charmap.exe and friends) go through a parallel set the
 * wWinMainCRTStartup glue calls before wWinMain:
 *
 *   _configure_wide_argv(mode)                 // wide argv parse
 *   _initialize_wide_environment()             // (covered elsewhere)
 *   lpCmdLine = _get_wide_winmain_command_line()  // -> wWinMain arg
 *
 * `_get_wide_winmain_command_line()` returning NULL is fatal: the
 * startup glue walks the returned pointer to strip the program
 * name, dereferencing it immediately. Observed as a charmap
 * 0xc0000005 the instant `_o__get_wide_winmain_command_line` hit the
 * catch-all NO-OP (which returns 0). Return a valid, NUL-terminated
 * wide string. For a bare launch the WinMain command line is the
 * text *after* the program name — empty — so an empty wide string is
 * both non-faulting and semantically correct.
 *
 * Built as an explicit `_ucrt_wchar_t` array, not an `L""` literal:
 * the cross-toolchain's `wchar_t` is 32-bit, but this file's wide
 * type is 16-bit (unsigned short), matching Win32 UTF-16.
 * ------------------------------------------------------------------ */
static _ucrt_wchar_t g_wcmdline[1] = {0};
static _ucrt_wchar_t* g_wargv[1] = {(_ucrt_wchar_t*)0};
static _ucrt_wchar_t** g_wargv_ptr = g_wargv;

__declspec(dllexport) _ucrt_wchar_t* _get_wide_winmain_command_line(void)
{
    return g_wcmdline;
}

__declspec(dllexport) char* _get_narrow_winmain_command_line(void)
{
    /* Narrow analog: empty command line (text after the program
     * name). g_arg0 is the program name itself, not the cmdline. */
    static char narrow_cmdline[1] = {0};
    return narrow_cmdline;
}

/* _configure_wide_argv(mode) — wide argv parse. Same single
 * synthetic-arg0 model as the narrow path; nothing to tokenise. */
__declspec(dllexport) int _configure_wide_argv(int mode)
{
    (void)mode;
    return 0;
}

/* __p___wargv() -> &__wargv (wide argv). The CRT reads *__p___wargv()
 * to hand wmain its argv. Backed by real storage so the deref is
 * safe; the vector is empty (NULL-terminated). */
__declspec(dllexport) _ucrt_wchar_t*** __p___wargv(void)
{
    return &g_wargv_ptr;
}

/* _initialize_wide_environment() — wide env block setup. Mirrors
 * the narrow no-op; the env is statically empty. Return 0. */
__declspec(dllexport) int _initialize_wide_environment(void)
{
    return 0;
}

/* ------------------------------------------------------------------
 * onexit / atexit ledger
 *
 * The CRT registers cleanup callbacks through an "onexit table"
 * (an opaque struct the CRT allocates/embeds; we treat it as a
 * 3-pointer { first, last, end } the docs describe). v0 keeps a
 * single process-wide fixed-size table and runs nothing at exit
 * (the kernel reclaims everything on SYS_EXIT), so register simply
 * records the function pointer and returns success. This is enough
 * for the startup sequence to complete; full atexit dispatch can
 * land when a PE actually relies on a registered finaliser running
 * before teardown.
 * ------------------------------------------------------------------ */

typedef int (*ucrt_onexit_fn)(void);

typedef struct ucrt_onexit_table
{
    ucrt_onexit_fn* first;
    ucrt_onexit_fn* last;
    ucrt_onexit_fn* end;
} ucrt_onexit_table_t;

/* _initialize_onexit_table(table) — zero the table so the CRT
 * sees an empty, valid ledger. Return 0 = success. */
__declspec(dllexport) int _initialize_onexit_table(ucrt_onexit_table_t* table)
{
    if (table == (ucrt_onexit_table_t*)0)
        return -1;
    table->first = (ucrt_onexit_fn*)0;
    table->last = (ucrt_onexit_fn*)0;
    table->end = (ucrt_onexit_fn*)0;
    return 0;
}

/* _register_onexit_function(table, fn) — record a finaliser. v0
 * doesn't run them (kernel teardown handles cleanup), so this is a
 * success no-op that keeps the CRT's atexit() path happy. */
__declspec(dllexport) int _register_onexit_function(ucrt_onexit_table_t* table, ucrt_onexit_fn fn)
{
    (void)table;
    (void)fn;
    return 0;
}

/* _crt_atexit(fn) — the global-table variant of the above. Same
 * no-op contract. */
__declspec(dllexport) int _crt_atexit(ucrt_onexit_fn fn)
{
    (void)fn;
    return 0;
}

/* _callnewh(size) — the new-handler hook the CRT calls when an
 * allocation fails. With no installed handler the C++ contract is
 * "return 0" (caller then throws bad_alloc / returns null). */
__declspec(dllexport) int _callnewh(size_t size)
{
    (void)size;
    return 0;
}

/* ------------------------------------------------------------------
 * Startup mode setters — all success no-ops returning 0.
 *
 * _set_fmode / _set_new_mode select text-vs-binary stdio default
 * and the malloc-failure-calls-new-handler flag. _setmode changes
 * a specific fd's translation mode. _seh_filter_exe is the
 * top-level SEH filter the CRT installs (0 = EXCEPTION_CONTINUE_
 * SEARCH, i.e. don't swallow). _invalid_parameter_noinfo is the
 * non-noreturn sibling of _invalid_parameter_noinfo_noreturn — the
 * CRT calls it on a bad arg and EXPECTS to continue, so it must
 * return (not exit).
 * ------------------------------------------------------------------ */

__declspec(dllexport) int _set_fmode(int mode)
{
    g_fmode = mode;
    return 0;
}

__declspec(dllexport) int _set_new_mode(int newhandlermode)
{
    (void)newhandlermode;
    return 0;
}

__declspec(dllexport) int _setmode(int fd, int mode)
{
    (void)fd;
    /* Return the "previous mode"; text (0x4000 = _O_TEXT) is the
     * conventional default. Callers that ignore the return are the
     * common case. */
    (void)mode;
    return 0x4000;
}

__declspec(dllexport) int _seh_filter_exe(unsigned int code, void* ptrs)
{
    (void)code;
    (void)ptrs;
    return 0; /* EXCEPTION_CONTINUE_SEARCH */
}

__declspec(dllexport) void _invalid_parameter_noinfo(void) {}

__declspec(dllexport) void _purecall(void) {}

/* ------------------------------------------------------------------
 * Low-level fd / pipe / popen stubs
 *
 * cmd.exe imports these but the banner path doesn't exercise them
 * (they back _popen / pipe redirection / the raw-fd console).
 * v0 returns the C "failure" sentinel so any caller that DOES hit
 * them fails cleanly rather than faulting:
 *   _open_osfhandle / _tell -> -1
 *   _pipe / _pclose / _dup / _dup2 / _close -> -1
 *   _wpopen -> NULL
 *   _getch -> -1 (EOF)
 * ------------------------------------------------------------------ */

__declspec(dllexport) long long _open_osfhandle(long long osfhandle, int flags)
{
    (void)osfhandle;
    (void)flags;
    return -1;
}

__declspec(dllexport) long _tell(int fd)
{
    (void)fd;
    return -1L;
}

__declspec(dllexport) int _pipe(int* fds, unsigned int psize, int textmode)
{
    (void)fds;
    (void)psize;
    (void)textmode;
    return -1;
}

__declspec(dllexport) int _pclose(FILE* stream)
{
    (void)stream;
    return -1;
}

__declspec(dllexport) FILE* _wpopen(const _ucrt_wchar_t* command, const _ucrt_wchar_t* mode)
{
    (void)command;
    (void)mode;
    return (FILE*)0;
}

__declspec(dllexport) int _close(int fd)
{
    (void)fd;
    return -1;
}

__declspec(dllexport) int _dup(int fd)
{
    (void)fd;
    return -1;
}

__declspec(dllexport) int _dup2(int fd1, int fd2)
{
    (void)fd1;
    (void)fd2;
    return -1;
}

__declspec(dllexport) int _getch(void)
{
    return -1; /* EOF — no console input wired in v0 */
}

/* ------------------------------------------------------------------
 * _ultoa / _ultoa_s — unsigned-long to ASCII in an arbitrary radix
 * (2..36). MSVC long = 32-bit. _ultoa assumes the caller's buffer
 * is large enough (33 bytes covers base-2 of a 32-bit value);
 * _ultoa_s bounds-checks against the supplied size.
 * ------------------------------------------------------------------ */

static int ultoa_core(unsigned long value, char* buf, int radix, size_t cap)
{
    if (radix < 2 || radix > 36)
    {
        if (cap > 0)
            buf[0] = 0;
        return 22; /* EINVAL */
    }
    char tmp[33];
    int n = 0;
    const char* digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    if (value == 0)
        tmp[n++] = '0';
    while (value)
    {
        tmp[n++] = digits[value % (unsigned long)radix];
        value /= (unsigned long)radix;
    }
    /* Need n digits + NUL. */
    if (cap != 0 && (size_t)(n + 1) > cap)
    {
        buf[0] = 0;
        return 34; /* ERANGE */
    }
    int o = 0;
    for (int i = n - 1; i >= 0; --i)
        buf[o++] = tmp[i];
    buf[o] = 0;
    return 0;
}

__declspec(dllexport) char* _ultoa(unsigned long value, char* buf, int radix)
{
    ultoa_core(value, buf, radix, 0);
    return buf;
}

__declspec(dllexport) int _ultoa_s(unsigned long value, char* buf, size_t size, int radix)
{
    if (buf == (char*)0 || size == 0)
        return 22; /* EINVAL */
    return ultoa_core(value, buf, radix, size);
}

/* ------------------------------------------------------------------
 * Wide-character string + ctype family
 *
 * UTF-16 wchar_t (16-bit). ASCII-range case folding is all v0
 * needs — the CRT calls these during locale/console setup. Non-
 * ASCII wide chars pass through unchanged (no Unicode tables).
 * ------------------------------------------------------------------ */

static _ucrt_wchar_t w_lower(_ucrt_wchar_t c)
{
    return (c >= 'A' && c <= 'Z') ? (_ucrt_wchar_t)(c + ('a' - 'A')) : c;
}

static _ucrt_wchar_t w_upper(_ucrt_wchar_t c)
{
    return (c >= 'a' && c <= 'z') ? (_ucrt_wchar_t)(c - ('a' - 'A')) : c;
}

__declspec(dllexport) int _wcsicmp(const _ucrt_wchar_t* a, const _ucrt_wchar_t* b)
{
    while (*a && *b)
    {
        _ucrt_wchar_t ca = w_lower(*a), cb = w_lower(*b);
        if (ca != cb)
            return (int)ca - (int)cb;
        ++a;
        ++b;
    }
    return (int)w_lower(*a) - (int)w_lower(*b);
}

__declspec(dllexport) int _wcsnicmp(const _ucrt_wchar_t* a, const _ucrt_wchar_t* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        _ucrt_wchar_t ca = w_lower(a[i]), cb = w_lower(b[i]);
        if (ca != cb)
            return (int)ca - (int)cb;
        if (!a[i])
            return 0;
    }
    return 0;
}

__declspec(dllexport) _ucrt_wchar_t* _wcslwr(_ucrt_wchar_t* s)
{
    if (s == (_ucrt_wchar_t*)0)
        return s;
    for (_ucrt_wchar_t* p = s; *p; ++p)
        *p = w_lower(*p);
    return s;
}

__declspec(dllexport) _ucrt_wchar_t* _wcsupr(_ucrt_wchar_t* s)
{
    // NOTE: in-place uppercase — the caller must hand us a WRITABLE
    // buffer (MSVC's contract). A read-only/literal string here is a
    // caller bug, not ours; the NULL guard only catches the cheap
    // case. cmd.exe trips this against a non-writable wide string
    // during locale init (see commit body / Win32-Surface-Status).
    if (s == (_ucrt_wchar_t*)0)
        return s;
    for (_ucrt_wchar_t* p = s; *p; ++p)
        *p = w_upper(*p);
    return s;
}

/* _wtol — wide string to long (MSVC long = 32-bit). */
__declspec(dllexport) long _wtol(const _ucrt_wchar_t* s)
{
    while (*s == ' ' || *s == '\t')
        ++s;
    int neg = 0;
    if (*s == '-')
    {
        neg = 1;
        ++s;
    }
    else if (*s == '+')
        ++s;
    long v = 0;
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10 + (long)(*s - '0');
        ++s;
    }
    return neg ? -v : v;
}

/* wcsspn — length of the initial wide-string segment of `s`
 * consisting only of chars from `accept`. Narrow strspn's twin. */
__declspec(dllexport) size_t wcsspn(const _ucrt_wchar_t* s, const _ucrt_wchar_t* accept)
{
    size_t n = 0;
    for (; s[n]; ++n)
    {
        const _ucrt_wchar_t* a = accept;
        int found = 0;
        for (; *a; ++a)
            if (*a == s[n])
            {
                found = 1;
                break;
            }
        if (!found)
            break;
    }
    return n;
}

/* iswXXX — wide ctype, ASCII range only. */
__declspec(dllexport) int iswalpha(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

__declspec(dllexport) int iswdigit(int c)
{
    return c >= '0' && c <= '9';
}

__declspec(dllexport) int iswspace(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

__declspec(dllexport) int iswxdigit(int c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

__declspec(dllexport) int towlower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

__declspec(dllexport) int towupper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
}

/* setlocale(category, locale) — v0 has only the "C" locale. Return
 * the literal "C" so callers that inspect the result see a valid,
 * non-NULL locale name; NULL would signal failure. */
__declspec(dllexport) char* setlocale(int category, const char* locale)
{
    (void)category;
    (void)locale;
    static char c_locale[] = "C";
    return c_locale;
}

/* _time32 — seconds since the Unix epoch, 32-bit. v0 has no
 * wall-clock wired to a syscall here, so return a fixed plausible
 * timestamp (2024-01-01 00:00:00 UTC = 1704067200). Callers that
 * seed an RNG or stamp output get a stable value; callers that
 * need real time will surface as a GAP when they appear. */
__declspec(dllexport) long _time32(long* out)
{
    const long fixed = 1704067200L; /* GAP: fixed clock — no time syscall wired here yet */
    if (out != (long*)0)
        *out = fixed;
    return fixed;
}

/* ------------------------------------------------------------------
 * __stdio_common_* — the modern UCRT stdio backend.
 *
 * Recent CRTs route printf/sprintf/scanf through these shared
 * entry points instead of the legacy `_vsnprintf`. The signature
 * carries a 64-bit `options` flag word ahead of the buffer.
 * We forward to the existing narrow vfmt() backend; the wide
 * variants down-convert UTF-16 format/output by truncating to the
 * low byte (ASCII-range correct, which is all the startup banner
 * path needs).
 *
 * Signatures (UCRT):
 *   __stdio_common_vfprintf(opts, FILE*, fmt, locale, va)
 *   __stdio_common_vswprintf(opts, wbuf, cap, wfmt, locale, va)
 *   __stdio_common_vswprintf_s(opts, wbuf, cap, wfmt, locale, va)
 *   __stdio_common_vswscanf(opts, wbuf, cap, wfmt, locale, va)
 * ------------------------------------------------------------------ */

__declspec(dllexport) int __stdio_common_vfprintf(unsigned long long options, FILE* stream, const char* format,
                                                  void* locale, va_list arglist)
{
    (void)options;
    (void)locale;
    char buf[1024];
    int n = vfmt(buf, sizeof(buf), format, arglist);
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, stream);
    return n;
}

/* Down-convert a UTF-16 format string to ASCII on the stack so the
 * narrow vfmt() can consume it. Truncates non-ASCII; fine for the
 * %s/%d/%x startup banner formats. */
static int wfmt_to_narrow(char* out, size_t out_cap, const _ucrt_wchar_t* wfmt)
{
    size_t i = 0;
    for (; wfmt[i] && i + 1 < out_cap; ++i)
        out[i] = (char)(wfmt[i] & 0xFF);
    out[i] = 0;
    return (int)i;
}

/* __stdio_common_vfwprintf — wide formatted output to a stream. This
 * is the backend modern UCRT routes fwprintf / vfwprintf / fputws
 * through. ftp.exe prints its interactive "ftp> " prompt via this
 * path; without it the prompt vanished into the catch-all NO-OP and
 * ftp read EOF on an empty stdin and exited. Down-convert the wide
 * format to ASCII (matching the other wide variants here) and emit
 * through the same narrow stream-write path as __stdio_common_vfprintf
 * so the prompt reaches the console. */
__declspec(dllexport) int __stdio_common_vfwprintf(unsigned long long options, FILE* stream,
                                                   const _ucrt_wchar_t* format, void* locale, va_list arglist)
{
    (void)options;
    (void)locale;
    char nfmt[512];
    wfmt_to_narrow(nfmt, sizeof(nfmt), format);
    char buf[1024];
    int n = vfmt(buf, sizeof(buf), nfmt, arglist);
    if (n < 0)
        return -1;
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    fwrite(buf, 1, (size_t)n, stream);
    return n;
}

__declspec(dllexport) int __stdio_common_vswprintf(unsigned long long options, _ucrt_wchar_t* buffer, size_t count,
                                                   const _ucrt_wchar_t* format, void* locale, va_list arglist)
{
    (void)options;
    (void)locale;
    if (buffer == (_ucrt_wchar_t*)0 || count == 0)
        return -1;
    char nfmt[512];
    wfmt_to_narrow(nfmt, sizeof(nfmt), format);
    char nbuf[1024];
    int n = vfmt(nbuf, sizeof(nbuf), nfmt, arglist);
    if (n < 0)
        return -1;
    /* Widen the narrow result back into the caller's UTF-16 buffer. */
    size_t o = 0;
    for (; o + 1 < count && nbuf[o] != 0; ++o)
        buffer[o] = (_ucrt_wchar_t)(unsigned char)nbuf[o];
    buffer[o] = 0;
    return (int)o;
}

__declspec(dllexport) int __stdio_common_vswprintf_s(unsigned long long options, _ucrt_wchar_t* buffer, size_t count,
                                                     const _ucrt_wchar_t* format, void* locale, va_list arglist)
{
    return __stdio_common_vswprintf(options, buffer, count, format, locale, arglist);
}

/* __stdio_common_vswscanf — wide sscanf backend. Down-convert both
 * the input and the format to ASCII, run the narrow vsscanf. The
 * `%s`/`%c` outputs land in narrow buffers; wide-output specs would
 * need widening but the startup path doesn't use them.
 * GAP: wide-output scan specs (%ls into wchar buffer) unimplemented. */
__declspec(dllexport) int __stdio_common_vswscanf(unsigned long long options, const _ucrt_wchar_t* buffer, size_t count,
                                                  const _ucrt_wchar_t* format, void* locale, va_list arglist)
{
    (void)options;
    (void)count;
    (void)locale;
    char nbuf[512];
    char nfmt[256];
    size_t i = 0;
    for (; buffer[i] && i + 1 < sizeof(nbuf); ++i)
        nbuf[i] = (char)(buffer[i] & 0xFF);
    nbuf[i] = 0;
    wfmt_to_narrow(nfmt, sizeof(nfmt), format);
    return vsscanf_impl(nbuf, nfmt, arglist);
}
