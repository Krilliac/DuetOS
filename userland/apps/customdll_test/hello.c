/*
 * userland/apps/customdll_test/hello.c
 *
 * Stage-2 slice 6 end-to-end test. First userland PE that
 * imports functions from a real loaded DLL (`customdll.dll`)
 * rather than from the flat kernel-hosted stubs page.
 *
 * What this exercises:
 *   1. lld-link resolves CustomAdd / CustomMul / CustomVersion
 *      against the minimal customdll.lib produced by
 *      llvm-dlltool from customdll.def — so the PE's Import
 *      Directory names `customdll.dll` as an import source.
 *   2. At SpawnPeFile, the kernel DllLoad's customdll.dll into
 *      the process's AS BEFORE PeLoad runs.
 *   3. ResolveImports (stage-2 slice 6) matches each import's
 *      `customdll.dll` name against the pre-loaded DllImage,
 *      patches the IAT slot with the DLL's export VA directly —
 *      no stubs-page trampoline, no syscall round-trip.
 *   4. At ring-3 entry, this program's indirect calls through
 *      the IAT land straight in customdll.dll's .text section.
 *
 * Expected serial-log signature on success:
 *
 *     [pe-resolve] via-dll customdll.dll!CustomAdd      -> 0x...
 *     [pe-resolve] via-dll customdll.dll!CustomMul      -> 0x...
 *     [pe-resolve] via-dll customdll.dll!CustomVersion  -> 0x...
 *     ... ring-3 spawn ...
 *     [I] sys : exit rc val=0x1234
 *
 * The exit code 0x1234 is `CustomAdd(0x1000, 0x0234)` — a
 * successful round-trip through the DLL. Any mismatch in the
 * three call results produces 0xBAD0 instead, so a regression
 * is visible at a glance in the boot log.
 */

typedef int            BOOL;
typedef unsigned int   DWORD;
typedef unsigned int   UINT;

// ---- customdll.dll imports ------------------------------------
__declspec(dllimport) int      CustomAdd(int a, int b);
__declspec(dllimport) int      CustomMul(int a, int b);
__declspec(dllimport) unsigned CustomVersion(void);

// ---- kernel32.dll imports -------------------------------------
__declspec(dllimport) void __stdcall ExitProcess(UINT uExitCode);

void _start(void)
{
    // Call every customdll export so all three get IAT-patched
    // through the slice-6 via-DLL path on load. If any call
    // returns the wrong value, the exit code drops to 0xBAD0 —
    // makes a boot-log regression obvious.
    const int      add_result = CustomAdd(0x1000, 0x0234); // 0x1234
    const int      mul_result = CustomMul(3, 4);           // 12
    const unsigned ver_result = CustomVersion();           // 0x200

    const UINT rc =
        (add_result == 0x1234 && mul_result == 12 && ver_result == 0x200u) ? (UINT) add_result : 0xBAD0u;

    ExitProcess(rc);
}
