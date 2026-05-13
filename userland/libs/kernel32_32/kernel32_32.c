/*
 * userland/libs/kernel32_32/kernel32_32.c
 *
 * Freestanding DuetOS kernel32.dll (i386 / PE32 variant) — ring-3
 * 32-bit code that implements the minimum Win32 entry surface a
 * PE32 image is likely to import.
 *
 * Companion to userland/libs/kernel32/kernel32.c (the PE32+ x86_64
 * variant). Both share the kernel-side syscall table (SYS_EXIT=0,
 * SYS_GETPID=1, SYS_GETPROCID=8, SYS_GETLASTERROR=9,
 * SYS_SETLASTERROR=10, ...) but use different ABIs to invoke it.
 *
 * Native 32-bit syscall ABI (mirrors Linux i386 because that's the
 * register set the i386 architecture exposes):
 *     int $0x80
 *     eax = syscall number
 *     ebx = arg1, ecx = arg2, edx = arg3, esi = arg4, edi = arg5, ebp = arg6
 *     eax = return value on exit
 *
 * The kernel's isr_common detects a 32-bit caller via CS=0x3B in the
 * trap frame and remaps these into the SysV AMD64 slots the C++
 * SyscallDispatch expects — see kernel/arch/x86_64/exceptions.S.
 *
 * Build target: i686-pc-windows-msvc (clang --target plus lld-link
 * /machine:x86 /dll /noentry /nodefaultlib). Result is a PE32 (i386)
 * DLL with Machine=0x014C, OptHdrMagic=0x10B.
 *
 * Layer-4 minimum surface: just the calls pe32_smoke uses. Future
 * slices grow this to the full ~150-export kernel32 footprint.
 */

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;

#define WIN32_NORETURN __attribute__((noreturn))

/* Single-arg syscall trampoline: eax = nr, ebx = arg1. */
static inline int duet_syscall1(int nr, unsigned a1)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1) : "memory");
    return rv;
}

/* No-arg syscall trampoline: eax = nr. */
static inline int duet_syscall0(int nr)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr) : "memory");
    return rv;
}

/* ------------------------------------------------------------------
 * Noreturn terminators (SYS_EXIT = 0, ebx = exit code)
 * ------------------------------------------------------------------ */

__declspec(dllexport) WIN32_NORETURN void __stdcall ExitProcess(UINT uExitCode)
{
    /* SYS_EXIT does not return; the kernel destroys the task and
     * never resumes user mode. The ud2 is unreachable but keeps
     * the compiler from inserting a fallthrough into whatever
     * follows in .text. */
    duet_syscall1(0 /* SYS_EXIT */, uExitCode);
    __asm__ volatile("ud2" ::: "memory");
    __builtin_unreachable();
}

__declspec(dllexport) WIN32_NORETURN BOOL __stdcall TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    (void)hProcess;
    duet_syscall1(0 /* SYS_EXIT */, uExitCode);
    __asm__ volatile("ud2" ::: "memory");
    __builtin_unreachable();
}

/* ------------------------------------------------------------------
 * Process / thread identity (syscall-backed)
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD __stdcall GetCurrentProcessId(void)
{
    return (DWORD)duet_syscall0(8 /* SYS_GETPROCID */);
}

__declspec(dllexport) DWORD __stdcall GetCurrentThreadId(void)
{
    return (DWORD)duet_syscall0(1 /* SYS_GETPID */);
}

/* ------------------------------------------------------------------
 * Pseudo-handles (constant returns)
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall GetCurrentProcess(void)
{
    return (HANDLE)(unsigned)-1;
}

__declspec(dllexport) HANDLE __stdcall GetCurrentThread(void)
{
    return (HANDLE)(unsigned)-2;
}

/* ------------------------------------------------------------------
 * Last-error slot (syscall-backed)
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD __stdcall GetLastError(void)
{
    return (DWORD)duet_syscall0(9 /* SYS_GETLASTERROR */);
}

__declspec(dllexport) void __stdcall SetLastError(DWORD err)
{
    duet_syscall1(10 /* SYS_SETLASTERROR */, err);
}
