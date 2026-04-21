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

// Batch 1 — console I/O
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL   __stdcall WriteFile(HANDLE hFile,
                                                 LPCVOID lpBuffer,
                                                 DWORD nNumberOfBytesToWrite,
                                                 LPDWORD lpNumberOfBytesWritten,
                                                 void* lpOverlapped);
__declspec(dllimport) void   __stdcall ExitProcess(unsigned int uExitCode);

// Batch 2 — process/thread lifecycle
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);
__declspec(dllimport) HANDLE __stdcall GetCurrentThread(void);
__declspec(dllimport) DWORD  __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD  __stdcall GetCurrentThreadId(void);
__declspec(dllimport) BOOL   __stdcall TerminateProcess(HANDLE hProcess, unsigned int uExitCode);

// Batch 3 — last-error slot
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void  __stdcall SetLastError(DWORD dwErrCode);

// Batch 4 — critical sections (v0 no-ops)
// CRITICAL_SECTION is 40 bytes on x64: {PDEBUG_INFO, LONG,
// LONG, HANDLE, HANDLE, ULONG_PTR}. We only need the size
// right — the stub zeros the whole struct and never reads
// the fields.
typedef struct
{
    void* _opaque[5];
} CRITICAL_SECTION, *LPCRITICAL_SECTION;
__declspec(dllimport) void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION);
__declspec(dllimport) void __stdcall EnterCriticalSection(LPCRITICAL_SECTION);
__declspec(dllimport) void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION);
__declspec(dllimport) void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION);

// Batch 5 — vcruntime140 memory intrinsics. CRT functions
// use the plain x64 calling convention (no __stdcall
// decoration — __stdcall is ignored on x64 anyway, but we
// keep the annotations to match vcruntime140.dll's export
// table on a real Windows system). size_t is 64-bit on x64.
typedef unsigned long long size_t;
__declspec(dllimport) void* memset(void* dst, int c, size_t n);
__declspec(dllimport) void* memcpy(void* dst, const void* src, size_t n);
__declspec(dllimport) void* memmove(void* dst, const void* src, size_t n);

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

    // Exercise every batch-2 stub. The `volatile` sinks keep
    // the reads from being DCE'd — without them lld-link
    // could drop the IAT entries as unused and we'd never
    // see the resolver log the new functions.
    volatile HANDLE p_sink   = GetCurrentProcess();
    volatile HANDLE t_sink   = GetCurrentThread();
    volatile DWORD  pid_sink = GetCurrentProcessId();
    volatile DWORD  tid_sink = GetCurrentThreadId();
    (void)p_sink;
    (void)t_sink;
    (void)pid_sink;
    (void)tid_sink;

    // TerminateProcess is [[noreturn]] in practice — can't
    // call it without skipping ExitProcess. Pull its IAT
    // entry in via a function-pointer sink instead.
    typedef BOOL(__stdcall * tp_fn_t)(HANDLE, unsigned int);
    volatile tp_fn_t tp_sink = TerminateProcess;
    (void)tp_sink;

    // Batch 4 round-trip: init + enter + leave + delete a
    // local CRITICAL_SECTION. Any stub that crashes would
    // take out the process with #PF/#GP. Reaching the next
    // line means all four resolved AND executed.
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    DeleteCriticalSection(&cs);

    // Batch 5 round-trip: memset a buffer with filler, then
    // memcpy a message over the front, then print with
    // WriteFile. If memset or memcpy is broken the output
    // won't match the expected string.
    char membuf[64];
    memset(membuf, '=', sizeof(membuf)); // fill with '=' -- proves memset
    const char mmsg[] = "[vcruntime140] memset+memcpy+memmove OK\n";
    memcpy(membuf, mmsg, sizeof(mmsg) - 1); // overwrite prefix -- proves memcpy
    // Overlap test for memmove: shift the tail right by 1,
    // forcing the backward-copy branch (dst > src, regions
    // overlap). If the forward-copy branch ran by mistake,
    // the trailing bytes would get corrupted to '\n\n\n...'.
    memmove(membuf + 1, membuf, sizeof(mmsg) - 2);
    // Restore the leading char so the message reads clean.
    membuf[0] = '[';
    DWORD mwritten = 0;
    WriteFile(out, membuf, sizeof(mmsg) - 1, &mwritten, 0);

    // Batch 3 round-trip: store a distinctive value via
    // SetLastError, read it back via GetLastError, exit with
    // whatever came back. If the slot works, the kernel log
    // shows `[I] sys : exit rc val=0xBEEF`. Any other value
    // means the round-trip is broken — the serial log
    // becomes the assertion.
    SetLastError(0xBEEF);
    ExitProcess(GetLastError());
}
