/*
 * userland/apps/hello_winapi/hello.c
 *
 * First CustomOS userland program that talks to "Win32" — i.e.
 * calls real imported functions through a real Import Address
 * Table rather than going to the native int 0x80 syscall ABI
 * directly.
 *
 * What this exercises end-to-end:
 *
 *   1. The C source calls ExitProcess(42) like any Win32 program.
 *   2. lld-link resolves ExitProcess against the minimal
 *      kernel32.lib import library produced from kernel32.def.
 *   3. The linker emits an Import Directory + IAT referencing
 *      "kernel32.dll!ExitProcess".
 *   4. The resulting PE carries a real base-relocation table
 *      (FileAlignment=512, no /dynamicbase:no).
 *   5. On load, the CustomOS PE loader:
 *        a. Parses + reports the PE (as before).
 *        b. Applies the base relocations (NEW — v0 only handled
 *           fixed-base images).
 *        c. Walks the IAT, looks each import up in the
 *           kernel-resident Win32 stub table, patches the IAT
 *           slot with the stub VA (NEW).
 *   6. The stub page (NEW — per-process, mapped R-X at a fixed
 *      high-user VA) contains tiny machine-code thunks that
 *      translate the Win32 calling convention into a native
 *      CustomOS syscall.
 *   7. Control transfer: PE entry -> CALL IAT slot -> stub page ->
 *      int 0x80 -> SYS_EXIT(42) -> process destroyed with code 42.
 *
 * If any link in that chain is broken, the boot log tells us
 * which — PeReport dumps the PE layout, the loader logs each
 * resolved/unresolved import, and the scheduler logs the exit
 * code.
 *
 * Build (host): see tools/build-hello-winapi.sh.
 */

// Forward-declare ExitProcess manually so we don't need the
// Windows SDK headers. __stdcall is the classic Win32 calling
// convention on x86 — on x64 it's ignored (all Win32 APIs use
// the x64 ABI), but we keep the annotation for clarity.
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

// _start because we're linking with /nodefaultlib — there's no
// CRT entry point. Control transfers here directly from the PE
// loader (rsp = stack_top, rax/rbx/etc. undefined; only rsp is
// guaranteed).
void _start(void)
{
    // If the import resolver has done its job, this call jumps
    // into the stub page, which thunks to SYS_EXIT(42).
    //
    // Exit code 42 is arbitrary but distinctive — the native
    // SpawnPeFile path logs the exit code, so "42" in the boot
    // serial is the success signature for this test.
    ExitProcess(42);
}
