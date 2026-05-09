/*
 * userland/libs/vcruntime140/vcruntime140.c
 *
 * Freestanding DuetOS vcruntime140.dll — memory intrinsics
 * (memset / memcpy / memmove). Retires the corresponding flat stubs
 * in kernel/subsystems/win32/thunks.cpp.
 *
 * These three functions are the workhorse of any MSVC-built
 * PE: the CRT uses them for virtually every non-trivial data
 * movement, and clang itself generates direct calls to them
 * for large aggregate copies and zero-inits (`struct s = {0};`,
 * `*p = other_struct;`, etc.).
 *
 * All three implementations are byte-at-a-time loops so the
 * compiler can't "optimise" them into... calls to themselves.
 * `__attribute__((no_builtin("memset", "memcpy", "memmove")))`
 * and `-fno-builtin` on the command line cooperate to keep
 * the bodies loop-shaped.
 *
 * Build: tools/build/build-vcruntime140-dll.sh
 *   clang --target=x86_64-pc-windows-msvc + lld-link /dll
 *   /noentry /nodefaultlib /base:0x10030000.
 */

typedef unsigned long long size_t;

/* `(a)buf_*` annotations keep clang from "helpfully" recognising
 * the loops as memset/memcpy and turning them into tail calls
 * to themselves. -fno-builtin in the build script does the same
 * at a coarser granularity; the attributes are belt + braces. */
#define NO_BUILTIN_MEMOPS __attribute__((no_builtin("memset", "memcpy", "memmove")))

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memset(void* dst, int c, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char v = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        d[i] = v;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memcpy(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i)
        d[i] = s[i];
    return dst;
}

/* memmove has to handle overlap: if dst > src but dst < src+n,
 * a forward copy clobbers the source before it's read. Detect
 * the overlap-going-forward case and copy backward. */
__declspec(dllexport) NO_BUILTIN_MEMOPS void* memmove(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d == s || n == 0)
        return dst;
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

__declspec(dllexport) NO_BUILTIN_MEMOPS int memcmp(const void* a, const void* b, size_t n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; ++i)
        if (x[i] != y[i])
            return (int)x[i] - (int)y[i];
    return 0;
}

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memchr(const void* ptr, int c, size_t n)
{
    const unsigned char* p = (const unsigned char*)ptr;
    unsigned char ch = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == ch)
            return (void*)(p + i);
    return (void*)0;
}

/* ------------------------------------------------------------------
 * SEH / C++ exception stubs
 *
 * Real Windows unwinds through .pdata/.xdata at exception
 * time. v0 has no unwind machinery. We provide:
 *
 * - __C_specific_handler / __CxxFrameHandler3 — return
 *   ExceptionContinueSearch (1). This tells the OS exception
 *   dispatcher "I don't handle this, keep looking". Since we
 *   have no dispatcher, this path only runs if the program
 *   explicitly calls it (rare outside exception tables).
 *
 * - _CxxThrowException — noreturn; SYS_EXIT(3) = abort.
 *
 * - _purecall — pure virtual call bug; terminate.
 *
 * - __std_terminate — terminate() entry point.
 *
 * - __std_exception_copy / _destroy — exception object
 *   management. No-op.
 *
 * - __vcrt_InitializeCriticalSectionEx — delegated from the
 *   flat-stub CS init to the v2 API. Forward to Init CS.
 * ------------------------------------------------------------------ */

#define SEH_NORETURN __attribute__((noreturn))
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

__declspec(dllexport) unsigned long __C_specific_handler(void* ExceptionRecord, void* EstablisherFrame,
                                                         void* ContextRecord, void* DispatcherContext)
{
    (void)ExceptionRecord;
    (void)EstablisherFrame;
    (void)ContextRecord;
    (void)DispatcherContext;
    return 1; /* ExceptionContinueSearch */
}

__declspec(dllexport) unsigned long __CxxFrameHandler3(void* ExceptionRecord, void* EstablisherFrame,
                                                       void* ContextRecord, void* DispatcherContext)
{
    (void)ExceptionRecord;
    (void)EstablisherFrame;
    (void)ContextRecord;
    (void)DispatcherContext;
    return 1;
}

__declspec(dllexport) unsigned long __CxxFrameHandler4(void* ExceptionRecord, void* EstablisherFrame,
                                                       void* ContextRecord, void* DispatcherContext)
{
    (void)ExceptionRecord;
    (void)EstablisherFrame;
    (void)ContextRecord;
    (void)DispatcherContext;
    return 1;
}

__declspec(dllexport) SEH_NORETURN void _CxxThrowException(void* object, const void* throwInfo)
{
    (void)object;
    (void)throwInfo;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) SEH_NORETURN void _purecall(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) SEH_NORETURN void __std_terminate(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) void __std_exception_copy(void* from, void* to)
{
    (void)from;
    (void)to;
}

__declspec(dllexport) void __std_exception_destroy(void* what)
{
    (void)what;
}

/* __vcrt_InitializeCriticalSectionEx — same contract as
 * kernel32.dll!InitializeCriticalSectionEx: zero the 40-byte
 * CRITICAL_SECTION, return BOOL TRUE. Inlined here so the
 * DLL doesn't depend on kernel32 being loaded first. */
__declspec(dllexport) int __vcrt_InitializeCriticalSectionEx(void* cs, unsigned int spin, unsigned int flags)
{
    (void)spin;
    (void)flags;
    if (cs != (void*)0)
    {
        unsigned char* b = (unsigned char*)cs;
        for (int i = 0; i < 40; ++i)
            b[i] = 0;
    }
    return 1;
}

/* RtlUnwind / RtlUnwindEx stubs — normally provided by
 * ntdll, but some PEs import them via vcruntime140 indirectly.
 * v0 can't unwind; noreturn fall-through to abort. */
__declspec(dllexport) SEH_NORETURN void __CxxUnwind(void* target_frame, void* target_ip, void* exc_record,
                                                    void* return_value)
{
    (void)target_frame;
    (void)target_ip;
    (void)exc_record;
    (void)return_value;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * /GS stack-cookie facade (T9-02 v0)
 *
 * MSVC /GS-protected functions emit a save / check pair around the
 * stack frame. The save reads `__security_cookie` and stores it
 * just below the saved frame pointer; the check reloads it and
 * calls `__security_check_cookie(saved)` on exit. The check function
 * compares against `__security_cookie` and, on mismatch, calls
 * `__report_gsfailure` (noreturn).
 *
 * v0 takes the lowest-effort posture: provide the variable +
 * the check + the failure path as exports. The compiler's
 * save/check pair is a self-consistent comparison of the same
 * value across one function call — no external mutator can flip
 * it — so the no-op check stays "consistent → no false abort".
 * Real cookie randomisation requires the PE loader reading the
 * SecurityCookie field of IMAGE_LOAD_CONFIG_DIRECTORY and
 * stamping a per-image fresh value; that's the T9-02 follow-on.
 *
 * `__security_cookie` lives in vcruntime140's data section so
 * every PE that imports it sees the same backing storage. The
 * value below is the documented MSVC default cookie
 * (`0x00002B992DDFA232` on x64), which the per-image cookie
 * normally overrides at startup. Apps whose CRT calls
 * `__security_init_cookie` (no-op here) keep the default.
 * ------------------------------------------------------------------ */
__declspec(dllexport) unsigned long long __security_cookie = 0x00002B992DDFA232ULL;
__declspec(dllexport) unsigned long long __security_cookie_complement = ~0x00002B992DDFA232ULL;

__declspec(dllexport) void __security_init_cookie(void)
{
    /* No randomness source wired in — leave the default in place. */
}

__declspec(dllexport) void __security_check_cookie(unsigned long long cookie)
{
    /* Compiler's save/check pair compares the value to itself
     * across one function call; if they differ, real corruption
     * occurred. Trip the abort path (matches Windows' contract:
     * `__report_gsfailure` is noreturn). */
    if (cookie != __security_cookie)
    {
        __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
        DUET_USER_TRAP_UNREACHABLE();
    }
}

__declspec(dllexport) SEH_NORETURN void __report_gsfailure(unsigned long long cookie)
{
    (void)cookie;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

/* MSVC also emits __report_rangefailure for /GS-related range
 * checks (e.g. variable-length array bounds). Treat as fatal. */
__declspec(dllexport) SEH_NORETURN void __report_rangefailure(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * CFG (Control Flow Guard) facade (T9-03 v0)
 *
 * CFG-enabled binaries (compiled with /guard:cf) call
 * `_guard_check_icall(target)` before each indirect call to verify
 * the target is in the per-image CFG bitmap. The PE loader
 * normally patches the per-image function pointer slots
 * (`__guard_check_icall_fptr`, `__guard_dispatch_icall_fptr`)
 * to point at ntdll's enforcement helpers; absent that, the
 * pointers stay at their compile-time defaults which point at
 * exactly these no-op shims.
 *
 * v0 doesn't enforce CFG — the bitmap isn't materialised — so
 * both helpers reduce to "trust the call." `_guard_check_icall`
 * just returns; `_guard_dispatch_icall` is a naked tail call
 * to whatever target the compiler put in `rax`.
 *
 * Real enforcement waits for a PE loader that walks
 * IMAGE_LOAD_CONFIG_DIRECTORY's GuardCFCheckFunctionPointer
 * field and either patches per-image slots to enforcement
 * helpers or zeroes them so the compiler's default fallback
 * (these shims) runs.
 * ------------------------------------------------------------------ */
__declspec(dllexport) void _guard_check_icall(void* target)
{
    (void)target;
}

/* `_guard_dispatch_icall` must do `jmp rax` (the indirect target
 * the compiler placed in rax pre-call). Naked function so the
 * prologue / epilogue don't clobber the register. */
__declspec(dllexport) __attribute__((naked)) void _guard_dispatch_icall(void)
{
    __asm__ volatile("jmpq *%rax");
}

/* XFG (eXtended Flow Guard) — same shape as CFG but with a
 * type-hash check. Same v0 stance: trust the call. */
__declspec(dllexport) void _guard_xfg_check_icall(void* target)
{
    (void)target;
}

__declspec(dllexport) __attribute__((naked)) void _guard_xfg_dispatch_icall(void)
{
    __asm__ volatile("jmpq *%rax");
}
