/*
 * userland/apps/hello_winapi/hello.c
 *
 * First CustomOS userland program that talks to "Win32" —
 * real imported functions through a real Import Address Table.
 *
 * v0 scope:
 *   - GetStdHandle(STD_OUTPUT_HANDLE) -> HANDLE
 *   - WriteFile(handle, buf, n, &written, NULL) -> BOOL
 *   - ExitProcess(42)
 *
 * What this exercises end-to-end:
 *
 *   1. lld-link resolves the three imports against the minimal
 *      kernel32.lib produced by llvm-dlltool from kernel32.def.
 *   2. The resulting PE carries an Import Directory with three
 *      kernel32.dll entries.
 *   3. On load, the CustomOS PE loader's ResolveImports walks
 *      the IAT and patches each slot with the stub VA from
 *      kernel/subsystems/win32/stubs.cpp.
 *   4. Each IAT-routed call lands in the per-process stubs
 *      page at 0x60000000 + stub_offset, which translates the
 *      Windows x64 ABI into a CustomOS int 0x80 syscall.
 *   5. The WriteFile stub maps to SYS_WRITE(1, buf, n); the
 *      ExitProcess stub maps to SYS_EXIT(code).
 *
 * Success is observable in the serial log as:
 *     [hello-winapi] printed via kernel32.WriteFile!
 *     [I] sys : exit rc val=0x2a
 *
 * Exit code 42 stays as the "success signature" — distinctive
 * enough to spot in boot logs alongside the zero-exit
 * compliance tasks.
 */

typedef void* HANDLE;
typedef unsigned int DWORD;
typedef int BOOL;
typedef const void* LPCVOID;
typedef DWORD* LPDWORD;

#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL   __stdcall WriteFile(HANDLE hFile,
                                                 LPCVOID lpBuffer,
                                                 DWORD nNumberOfBytesToWrite,
                                                 LPDWORD lpNumberOfBytesWritten,
                                                 void* lpOverlapped);
__declspec(dllimport) void   __stdcall ExitProcess(unsigned int uExitCode);

static const char kMsg[] = "[hello-winapi] printed via kernel32.WriteFile!\n";
#define kMsgLen ((DWORD)(sizeof(kMsg) - 1))

void _start(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    // Intentionally pass a non-null lpNumberOfBytesWritten so
    // the stub exercises its output-param store path (matches
    // the Win32 contract: 0 on failure, n on success). The
    // value isn't checked here — the point is the side
    // effect.
    DWORD written = 0;
    WriteFile(out, kMsg, kMsgLen, &written, 0);
    ExitProcess(42);
}
