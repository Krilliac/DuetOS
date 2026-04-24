/*
 * userland/libs/kernel32/kernel32.c
 *
 * Freestanding CustomOS kernel32.dll — ring-3 code that
 * implements Win32 entry points by issuing native int 0x80
 * syscalls, running OUTSIDE the kernel. This is the first
 * "real" userland DLL in the project: a PE import of
 * `kernel32.dll!GetCurrentProcessId` now resolves via
 * stage-2 slice-6's via-DLL path to code in THIS file
 * rather than to a hand-assembled stub in
 * kernel/subsystems/win32/stubs.cpp.
 *
 * Stage-2 slice 10 scope — a single entry point:
 *
 *     DWORD GetCurrentProcessId(void)   -> SYS_GETPROCID (8)
 *
 * Chosen as the first retirement because:
 *   - Trivially equivalent to the existing 8-byte flat stub
 *     (`mov eax, 8; int 0x80; ret`). The C compiler produces
 *     bit-identical-in-effect code, so every PE that already
 *     calls GetCurrentProcessId (hello_winapi, windows-kill,
 *     etc.) continues to return the same pid.
 *   - Exercises the multi-DLL preload path with a DLL whose
 *     own name (`kernel32.dll`) actually matches incoming
 *     import references — so slice-6's via-DLL-name match
 *     fires and the IAT is patched to point here.
 *
 * Future slices add more entry points. Every addition is a
 * net retirement: the stub in kernel/subsystems/win32/stubs.cpp
 * for the same DLL+function becomes dead code (still present
 * as a fallback but never reached because the via-DLL path
 * runs first). A later refactor will sweep dead stubs once
 * the retirement train is rolling.
 *
 * Build: see tools/build-kernel32-dll.sh. The DLL is linked
 * with /dll /noentry /nodefaultlib /base:0x10020000 — 1 MiB
 * above customdll2.dll (no VA collision with either of the
 * earlier test DLLs or with any PE ImageBase we hand out).
 */

typedef unsigned int DWORD;

__declspec(dllexport) DWORD GetCurrentProcessId(void)
{
    /* SYS_GETPROCID = 8. Kernel returns CurrentProcess()->pid
     * in rax. We truncate to DWORD (low 32 bits) to match the
     * Win32 GetCurrentProcessId prototype. */
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long) 8) : "memory");
    return (DWORD) rv;
}
