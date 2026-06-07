/*
 * userland/libs/msvcrt_32/msvcrt_32.c
 *
 * Freestanding DuetOS msvcrt.dll (i386 / PE32 variant) — covers the
 * string/memory intrinsics every MSVC-built PE32 calls during CRT
 * startup plus the handful of `_*` runtime helpers used by typical
 * Windows console / GUI apps.
 *
 * Companion to userland/libs/msvcrt/msvcrt.c (the PE32+ x86_64
 * variant). Built with clang --target=i686-pc-windows-msvc + lld-link
 * /machine:x86 /dll. Output basename "msvcrt.dll" so the PE Export
 * Directory's Name field matches the i386 importer's descriptor.
 *
 * msvcrt's exports use __cdecl (NOT __stdcall) — that's the historical
 * Windows runtime convention; the caller cleans up the stack so each
 * stub's `ret` is plain (no operand byte).
 */

typedef unsigned int size_t;
typedef int ssize_t;

/* ------------------------------------------------------------------
 * Core string / memory intrinsics. MSVC PEs sprinkle calls to these
 * throughout — every struct copy / zero-init compiles to one of them.
 * The implementations below are byte-at-a-time for correctness; the
 * compiler doesn't get to apply its own memcpy intrinsic at this
 * boundary because we're the implementation.
 * ------------------------------------------------------------------ */

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
    {
        for (size_t i = 0; i < n; ++i)
            d[i] = s[i];
    }
    else
    {
        for (size_t i = n; i > 0; --i)
            d[i - 1] = s[i - 1];
    }
    return dst;
}

__declspec(dllexport) void* memset(void* dst, int v, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    for (size_t i = 0; i < n; ++i)
        d[i] = (unsigned char)v;
    return dst;
}

__declspec(dllexport) int memcmp(const void* a, const void* b, size_t n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; ++i)
    {
        if (x[i] != y[i])
            return (int)x[i] - (int)y[i];
    }
    return 0;
}

__declspec(dllexport) size_t strlen(const char* s)
{
    size_t n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) int strcmp(const char* a, const char* b)
{
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

__declspec(dllexport) int strncmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        if (a[i] != b[i] || a[i] == 0)
            return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    }
    return 0;
}

__declspec(dllexport) char* strcpy(char* dst, const char* src)
{
    char* p = dst;
    while ((*p++ = *src++) != 0)
        ;
    return dst;
}

__declspec(dllexport) char* strncpy(char* dst, const char* src, size_t n)
{
    size_t i = 0;
    for (; i < n && src[i]; ++i)
        dst[i] = src[i];
    for (; i < n; ++i)
        dst[i] = 0;
    return dst;
}

__declspec(dllexport) char* strcat(char* dst, const char* src)
{
    char* p = dst;
    while (*p)
        ++p;
    while ((*p++ = *src++) != 0)
        ;
    return dst;
}

__declspec(dllexport) char* strchr(const char* s, int c)
{
    char target = (char)c;
    while (*s)
    {
        if (*s == target)
            return (char*)s;
        ++s;
    }
    if (target == 0)
        return (char*)s;
    return 0;
}

__declspec(dllexport) char* strrchr(const char* s, int c)
{
    char target = (char)c;
    const char* last = 0;
    while (*s)
    {
        if (*s == target)
            last = s;
        ++s;
    }
    if (target == 0)
        return (char*)s;
    return (char*)last;
}

__declspec(dllexport) char* strstr(const char* hay, const char* needle)
{
    if (!*needle)
        return (char*)hay;
    for (; *hay; ++hay)
    {
        const char* h = hay;
        const char* n = needle;
        while (*h && *n && *h == *n)
        {
            ++h;
            ++n;
        }
        if (!*n)
            return (char*)hay;
    }
    return 0;
}

__declspec(dllexport) int _stricmp(const char* a, const char* b)
{
    for (;; ++a, ++b)
    {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z')
            x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z')
            y = (char)(y - 'A' + 'a');
        if (x != y || x == 0)
            return (int)(unsigned char)x - (int)(unsigned char)y;
    }
}

__declspec(dllexport) int _strnicmp(const char* a, const char* b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z')
            x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z')
            y = (char)(y - 'A' + 'a');
        if (x != y || x == 0)
            return (int)(unsigned char)x - (int)(unsigned char)y;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * MSVC CRT helpers. These are the "_*" symbols MSVC-built PEs call
 * from their startup code. v0 returns safe defaults — the goal is
 * "PE survives CRT startup" not "CRT actually does anything".
 * ------------------------------------------------------------------ */

__declspec(dllexport) int* _errno(void)
{
    static int errno_slot = 0;
    return &errno_slot;
}

__declspec(dllexport) void _amsg_exit(int code)
{
    /* MSVC CRT's assertion-failure path. SYS_EXIT with the message
     * code so the boot log shows which CRT assertion fired. */
    __asm__ volatile("int $0x80" : : "a"(0), "b"(code) : "memory");
    __builtin_unreachable();
}

__declspec(dllexport) void _assert(const char* msg, const char* file, unsigned line)
{
    (void)msg;
    (void)file;
    (void)line;
    _amsg_exit(0xA55E72ED); /* sentinel "assertion exit" code */
}

__declspec(dllexport) void exit(int code)
{
    __asm__ volatile("int $0x80" : : "a"(0), "b"(code) : "memory");
    __builtin_unreachable();
}

__declspec(dllexport) void _exit(int code)
{
    exit(code);
}

__declspec(dllexport) void abort(void)
{
    exit(3);
}

/* _initterm walks a NULL-terminated array of function pointers,
 * calling each. MSVC CRT startup uses this to run static initialisers
 * and pre/post-main hooks. v0 walks the table and calls each
 * non-NULL entry; the cdecl convention means no register cleanup. */
__declspec(dllexport) void _initterm(void (**start)(void), void (**end)(void))
{
    for (void (**p)(void) = start; p < end; ++p)
    {
        if (*p)
            (*p)();
    }
}

__declspec(dllexport) int _initterm_e(int (**start)(void), int (**end)(void))
{
    for (int (**p)(void) = start; p < end; ++p)
    {
        if (*p)
        {
            int rc = (*p)();
            if (rc != 0)
                return rc;
        }
    }
    return 0;
}

/* __set_app_type / __setusermatherr — pure CRT bookkeeping. v0 no-op. */
__declspec(dllexport) void __set_app_type(int app_type)
{
    (void)app_type;
}

__declspec(dllexport) void __setusermatherr(void* handler)
{
    (void)handler;
}

/* _iob is the FILE* array MSVC CRT references for stdin/stdout/stderr.
 * Real CRT layout: 32-byte FILE struct × 3. v0 returns a fixed-size
 * static array zeroed out — MSVC reads from offset 0..0x20 per entry. */
struct _msvcrt_iobuf
{
    char pad[32];
};
__declspec(dllexport) struct _msvcrt_iobuf _iob[3] = {{{0}}, {{0}}, {{0}}};

/* __p__commode / __p__fmode return pointers to text/binary-mode
 * flags. v0 returns pointers to fixed slots set to text mode (0). */
__declspec(dllexport) int* __p__commode(void)
{
    static int commode = 0;
    return &commode;
}

__declspec(dllexport) int* __p__fmode(void)
{
    static int fmode = 0;
    return &fmode;
}

/* __p__acmdln / __p__wcmdln return pointers to the command-line
 * string. v0 returns a fixed sentinel; kernel32's GetCommandLineA
 * carries the same v0 string. */
__declspec(dllexport) char** __p__acmdln(void)
{
    static const char* cmdln = "a.exe";
    return (char**)&cmdln;
}

/* __getmainargs: ancient MSVC entry-point setup. Fills out argc/argv/envp
 * via caller-provided pointers. v0 returns argc=1 / argv=[program, NULL]
 * / envp=NULL. The do_wildcard / new_mode params are ignored. */
__declspec(dllexport) int __getmainargs(int* argc, char*** argv, char*** envp, int do_wildcard, void* new_mode)
{
    (void)do_wildcard;
    (void)new_mode;
    static char* g_argv[2] = {(char*)"a.exe", 0};
    static char* g_envp[1] = {0};
    if (argc)
        *argc = 1;
    if (argv)
        *argv = g_argv;
    if (envp)
        *envp = g_envp;
    return 0;
}

__declspec(dllexport) void __initenv(void)
{
    /* v0 no-op. Real MSVC CRT populates the env-block pointer. */
}

/* ------------------------------------------------------------------
 * Stubbed I/O. These return failure consistently so callers fall
 * back to whatever error path they expect. File I/O lands when the
 * VFS-aware PE32 spawn slice does.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void* fopen(const char* path, const char* mode)
{
    (void)path;
    (void)mode;
    return 0;
}

__declspec(dllexport) int fclose(void* fp)
{
    (void)fp;
    return 0;
}

__declspec(dllexport) size_t fread(void* buf, size_t sz, size_t n, void* fp)
{
    (void)buf;
    (void)sz;
    (void)n;
    (void)fp;
    return 0;
}

__declspec(dllexport) size_t fwrite(const void* buf, size_t sz, size_t n, void* fp)
{
    (void)buf;
    (void)sz;
    (void)n;
    (void)fp;
    return 0;
}

__declspec(dllexport) int fputs(const char* s, void* fp)
{
    (void)s;
    (void)fp;
    return 0;
}

__declspec(dllexport) int fflush(void* fp)
{
    (void)fp;
    return 0;
}

__declspec(dllexport) int feof(void* fp)
{
    (void)fp;
    return 1;
}

__declspec(dllexport) int ferror(void* fp)
{
    (void)fp;
    return 0;
}

/* malloc / calloc / free / realloc — forward to the per-process
 * Win32 heap via kernel32!HeapAlloc semantics. v0 wires a simple
 * bump allocator inside a per-DLL .bss arena (~64 KiB) until a
 * proper malloc lands. This keeps PE32 CRT-startup callers from
 * page-faulting on the very first malloc. */
#define MSVCRT32_ARENA_BYTES 65536
static unsigned char g_arena[MSVCRT32_ARENA_BYTES];
static size_t g_arena_cursor = 0;

/* GS-08: realloc needs the old block's size to copy min(old_sz, sz) and
 * avoid an out-of-bounds read past the original allocation. The bump
 * allocator carries no per-block header, so record (offset, len) for each
 * live block in a small side table. Bounded by MSVCRT32_ARENA_BYTES / 16
 * (the minimum aligned alloc), so it can never overflow before the arena
 * itself OOMs. Lookup is linear — fine at this scale; the real heap port
 * replaces the whole arena. */
#define MSVCRT32_MAX_BLOCKS (MSVCRT32_ARENA_BYTES / 16)
static size_t g_block_off[MSVCRT32_MAX_BLOCKS];
static size_t g_block_len[MSVCRT32_MAX_BLOCKS];
static size_t g_block_count = 0;

__declspec(dllexport) void* malloc(size_t sz)
{
    if (sz == 0)
        return 0;
    /* 16-byte align. */
    sz = (sz + 15) & ~(size_t)15;
    if (g_arena_cursor + sz > sizeof(g_arena))
        return 0;
    void* p = &g_arena[g_arena_cursor];
    /* GS-08: record this block's offset + length so realloc can bound its
     * copy to the old size. */
    if (g_block_count < MSVCRT32_MAX_BLOCKS)
    {
        g_block_off[g_block_count] = g_arena_cursor;
        g_block_len[g_block_count] = sz;
        ++g_block_count;
    }
    g_arena_cursor += sz;
    return p;
}

__declspec(dllexport) void* calloc(size_t n, size_t sz)
{
    /* GS-07: overflow guard mirrors ucrtbase.c calloc. Without it,
     * n * sz can wrap to a small nonzero total, malloc hands back a
     * tiny block, and the caller writes off the end. Reject before
     * the multiply. */
    if (n != 0 && sz > (size_t)-1 / n)
        return 0;
    size_t total = n * sz;
    void* p = malloc(total);
    if (p)
        memset(p, 0, total);
    return p;
}

__declspec(dllexport) void free(void* p)
{
    /* Bump allocator — free is a no-op. The arena fills up across
     * the process lifetime; a long-running PE eventually OOMs.
     * v0 acceptable; real free needs the heap port. */
    (void)p;
}

__declspec(dllexport) void* realloc(void* p, size_t sz)
{
    void* np = malloc(sz);
    if (np && p)
    {
        /* GS-08: copy min(old_sz, sz) so we never read past the original
         * block. Look the old size up in the side table; if p isn't a
         * known arena block (foreign pointer), copy nothing — reading
         * from an unknown provenance would be the OOB read we're
         * guarding against. */
        size_t copy = 0;
        if ((unsigned char*)p >= g_arena && (unsigned char*)p < g_arena + sizeof(g_arena))
        {
            size_t off = (size_t)((unsigned char*)p - g_arena);
            for (size_t i = 0; i < g_block_count; ++i)
            {
                if (g_block_off[i] == off)
                {
                    copy = g_block_len[i] < sz ? g_block_len[i] : sz;
                    break;
                }
            }
        }
        if (copy)
            memcpy(np, p, copy);
    }
    return np;
}

/* puts: write s + "\n" to stdout. Used by hello-world style PEs.
 * We forward to int 0x80 SYS_WRITE directly. */
__declspec(dllexport) int puts(const char* s)
{
    size_t n = strlen(s);
    __asm__ volatile("int $0x80" : : "a"(2 /* SYS_WRITE */), "b"(1 /* fd=1 */), "c"(s), "d"(n) : "memory");
    /* Append newline. */
    static const char nl[] = "\n";
    __asm__ volatile("int $0x80" : : "a"(2), "b"(1), "c"(nl), "d"(1u) : "memory");
    return (int)n;
}

/* atoi / atol / atof: minimal numeric parse. */
__declspec(dllexport) int atoi(const char* s)
{
    int sign = 1, v = 0;
    while (*s == ' ' || *s == '\t')
        ++s;
    if (*s == '-')
    {
        sign = -1;
        ++s;
    }
    else if (*s == '+')
    {
        ++s;
    }
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10 + (*s - '0');
        ++s;
    }
    return sign * v;
}

__declspec(dllexport) long atol(const char* s)
{
    return atoi(s);
}

/* ------------------------------------------------------------------
 * MSVC stack-probe primitives — _chkstk / __chkstk / _alloca_probe
 * live in chkstk.S. They share one body that walks ESP down a
 * page at a time, probing each page (so a stack-guard hit faults
 * at the probe instead of mid-prologue), then commits the new
 * ESP. Exported via msvcrt_32.def.
 * ------------------------------------------------------------------ */
