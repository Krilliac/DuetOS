/*
 * userland/libs/msvcp140/msvcp140.c
 *
 * Freestanding DuetOS msvcp140.dll — the C++ std:: runtime
 * DLL. Retires 17 batch-13a flat-stub rows.
 *
 * Real MSVCP140 is huge (thousands of exports). This v0 covers
 * only the subset real-world PEs (like windows-kill.exe) import
 * during startup: std::_Xbad_alloc / _Xlength_error /
 * _Xout_of_range throw helpers, std::basic_ostream<char> output
 * stubs, uncaught_exception, and a few err_map helpers.
 *
 * All exports resolve via `/export:MangledName=InternalName`
 * aliases in a .def file (mangled C++ names contain ? @ / <
 * which can't appear on a bash command line without escaping).
 *
 * Build: tools/build-msvcp140-dll.sh at /base:0x10080000.
 */

typedef int BOOL;

#define NORETURN __attribute__((noreturn))

/* ------------------------------------------------------------------
 * Throw helpers — SYS_EXIT(3) = abort. The MSVC C++ runtime
 * convention for _Xbad_alloc / _Xlength_error / _Xout_of_range
 * is to throw an exception; we can't unwind, so terminate the
 * process with exit code 3 (SIGABRT). Matches the flat stub at
 * kOffTerminate.
 * ------------------------------------------------------------------ */

__declspec(dllexport) NORETURN void msvcp_terminate(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) 3));
    __builtin_unreachable();
}

/* ------------------------------------------------------------------
 * Return-zero family — used for ostream sputc, error maps,
 * uncaught_exception. All return 0 / FALSE / NULL.
 * ------------------------------------------------------------------ */

__declspec(dllexport) long long msvcp_return_zero(void)
{
    return 0;
}

/* ------------------------------------------------------------------
 * Return-this family — any ostream op that "returns *this" just
 * passes the first arg (rcx under Win64) back in rax.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void* msvcp_return_this(void* self)
{
    return self;
}

/* ------------------------------------------------------------------
 * No-op for void-returning std methods (_Osfx / setstate).
 * ------------------------------------------------------------------ */

__declspec(dllexport) void msvcp_void_nop(void)
{
}

/* ------------------------------------------------------------------
 * basic_ios::widen(char c) -> char — pass-through. Matches the
 * flat stub at kOffWiden which returns the low byte of rdx.
 * ------------------------------------------------------------------ */

__declspec(dllexport) char msvcp_widen(void* self, char c)
{
    (void) self;
    return c;
}

/* ------------------------------------------------------------------
 * basic_streambuf::sputn(ptr, count) — real implementation:
 * issue SYS_WRITE(fd=1, ptr, count), returns bytes written.
 * Matches the flat stub at kOffSputn.
 * ------------------------------------------------------------------ */

__declspec(dllexport) long long msvcp_sputn(void* self, const void* ptr, long long count)
{
    (void) self;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 2),        /* SYS_WRITE */
                       "D"((long long) 1),        /* fd = stdout */
                       "S"((long long) ptr),
                       "d"((long long) count)
                     : "memory");
    return rv >= 0 ? rv : 0;
}
