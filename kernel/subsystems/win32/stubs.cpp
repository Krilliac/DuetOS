#include "stubs.h"

namespace customos::win32
{

namespace
{

// ---------------------------------------------------------------
// Stub bytecode.
//
// Each entry is a handful of raw x86-64 instructions, packed
// back-to-back. The layout is:
//
//   offset 0x00:  ExitProcess stub  (9 bytes)
//
// Future entries append at the current end. IAT slots point
// at (kWin32StubsVa + entry.offset), so stable offsets matter
// only within a single boot — we regenerate + re-map the page
// per process anyway, no persistence between runs.
//
// The assembly is hand-assembled rather than emitted from a
// .S file because (a) it's trivial, (b) a .S file would be
// position-dependent and we want to drop these bytes into a
// runtime-allocated frame, (c) a .S file would mean a second
// user-mode target in the build which is a premature
// abstraction for v0.
// ---------------------------------------------------------------

// Stub offsets. Kept as named constants so the table below
// stays readable and so two exports (WriteFile + WriteConsoleA)
// can alias to the same offset without duplicating the code.
constexpr u32 kOffExitProcess = 0x00;        // batch 1 — 9 bytes
constexpr u32 kOffGetStdHandle = 0x09;       // batch 1 — 3 bytes
constexpr u32 kOffWriteFile = 0x0C;          // batch 1 — 44 bytes
constexpr u32 kOffGetCurrentProcess = 0x38;  // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentThread = 0x40;   // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentProcessId = 0x48; // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentThreadId = 0x50;  // batch 2 — 8 bytes
constexpr u32 kOffTerminateProcess = 0x58;    // batch 2 — 9 bytes

constexpr u8 kStubsBytes[] = {
    // --- ExitProcess (offset 0x00, 9 bytes) --------------------
    // Windows x64 ABI: first arg (uExitCode) in RCX.
    // CustomOS native ABI: syscall # in RAX, first arg in RDI,
    // SYS_EXIT = 0.
    0x48, 0x89, 0xCF, // 0x00 mov rdi, rcx      ; code
    0x31, 0xC0,       // 0x03 xor eax, eax      ; rax = 0 = SYS_EXIT
    0xCD, 0x80,       // 0x05 int 0x80
    0x0F, 0x0B,       // 0x07 ud2               ; [[noreturn]]

    // --- GetStdHandle (offset 0x09, 3 bytes) -------------------
    // Win32: HANDLE GetStdHandle(DWORD nStdHandle).
    // nStdHandle is STD_INPUT_HANDLE (-10), STD_OUTPUT_HANDLE
    // (-11), or STD_ERROR_HANDLE (-12), each represented as
    // the low 32 bits of a DWORD (e.g. 0xFFFFFFF5).
    //
    // v0 semantic: pass the DWORD through as the HANDLE. The
    // downstream WriteFile stub ignores the handle and always
    // routes to SYS_WRITE(fd=1). This is correct for any
    // program whose only use of GetStdHandle is to pass the
    // result to WriteFile / WriteConsoleA — which is every
    // console "hello world" we care about.
    //
    // `mov eax, ecx` zero-extends ecx into rax (x86-64 32-bit
    // op clears upper 32 bits), so STD_OUTPUT_HANDLE's
    // 0xFFFFFFF5 becomes 0x00000000FFFFFFF5 as a HANDLE.
    0x89, 0xC8, // 0x09 mov eax, ecx
    0xC3,       // 0x0B ret

    // --- WriteFile / WriteConsoleA (offset 0x0C, 44 bytes) -----
    // Win32 signatures (identical shape, that's why we alias):
    //   BOOL WriteFile(HANDLE hFile,        rcx
    //                  LPCVOID lpBuffer,    rdx
    //                  DWORD nBytes,        r8
    //                  LPDWORD lpWritten,   r9
    //                  LPOVERLAPPED ovl);   [rsp+0x28]
    //   BOOL WriteConsoleA(HANDLE hConsoleOutput, rcx
    //                      LPCVOID lpBuffer,      rdx
    //                      DWORD nChars,          r8
    //                      LPDWORD lpCharsOut,    r9
    //                      LPVOID lpReserved);    [rsp+0x28]
    //
    // v0 semantic: ignore the handle + the trailing reserved/
    // overlapped arg, issue SYS_WRITE(1, buf, n), and store
    // the result count back into *lpWritten (clamped to 0 on
    // syscall error). Return BOOL = (rax >= 0).
    //
    // int 0x80 preserves all registers except RAX, so r9 (the
    // lpWritten pointer) survives the syscall and we can use
    // it to store the output count without saving.
    0x48, 0x89, 0xD6,             // 0x0C mov rsi, rdx         ; buf
    0x4C, 0x89, 0xC2,             // 0x0F mov rdx, r8          ; n
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0x12 mov edi, 1           ; fd = 1 (stdout)
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x17 mov eax, 2           ; SYS_WRITE
    0xCD, 0x80,                   // 0x1C int 0x80             ; rax = n or -1

    // If lpWritten (r9) != NULL, store max(rax, 0) as DWORD.
    0x4D, 0x85, 0xC9, // 0x1E test r9, r9
    0x74, 0x0B,       // 0x21 je +0x0B -> 0x2E
    0x31, 0xC9,       // 0x23 xor ecx, ecx
    0x48, 0x85, 0xC0, // 0x25 test rax, rax
    0x0F, 0x49, 0xC8, // 0x28 cmovns ecx, eax  ; ecx = rax if rax>=0, else 0
    0x41, 0x89, 0x09, // 0x2B mov [r9], ecx

    // BOOL return: 1 if rax >= 0, else 0.
    0x48, 0x85, 0xC0, // 0x2E test rax, rax
    0x0F, 0x99, 0xC0, // 0x31 setns al
    0x0F, 0xB6, 0xC0, // 0x34 movzx eax, al
    0xC3,             // 0x37 ret

    // === Batch 2: process/thread lifecycle ====================

    // --- GetCurrentProcess (offset 0x38, 8 bytes) --------------
    // Win32: HANDLE GetCurrentProcess(void). Returns the
    // pseudo-handle (HANDLE)(-1) = 0xFFFFFFFFFFFFFFFF. Any
    // function that receives this value treats it as "the
    // current process" without going through the real handle
    // table. Mirrors the literal Windows behavior — OpenProcess
    // on this pseudo-handle never opens anything.
    0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // 0x38 mov rax, -1
    0xC3,                                     // 0x3F ret

    // --- GetCurrentThread (offset 0x40, 8 bytes) ---------------
    // Win32: HANDLE GetCurrentThread(void). Pseudo-handle
    // (HANDLE)(-2) = 0xFFFFFFFFFFFFFFFE.
    0x48, 0xC7, 0xC0, 0xFE, 0xFF, 0xFF, 0xFF, // 0x40 mov rax, -2
    0xC3,                                     // 0x47 ret

    // --- GetCurrentProcessId (offset 0x48, 8 bytes) ------------
    // Win32: DWORD GetCurrentProcessId(void). Maps to
    // SYS_GETPROCID = 8 which returns CurrentProcess()->pid.
    // Return value in rax (low 32 bits → DWORD).
    0xB8, 0x08, 0x00, 0x00, 0x00, // 0x48 mov eax, 8 (SYS_GETPROCID)
    0xCD, 0x80,                   // 0x4D int 0x80
    0xC3,                         // 0x4F ret

    // --- GetCurrentThreadId (offset 0x50, 8 bytes) -------------
    // Win32: DWORD GetCurrentThreadId(void). Maps to
    // SYS_GETPID = 1 which returns the scheduler task id.
    // Distinct value from the process id — the kernel log's
    // `[sched] created task id=N` is this value.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x50 mov eax, 1 (SYS_GETPID)
    0xCD, 0x80,                   // 0x55 int 0x80
    0xC3,                         // 0x57 ret

    // --- TerminateProcess (offset 0x58, 9 bytes) ---------------
    // Win32: BOOL TerminateProcess(HANDLE hProcess, UINT
    // uExitCode). The hProcess arg (rcx) is ignored in v0 —
    // we always terminate the calling process. Real Windows
    // would walk the handle table and kill the target; for
    // our single-process model this reduces to ExitProcess
    // with the exit code coming from rdx instead of rcx.
    //
    // Bytes identical in shape to ExitProcess but with rdx
    // as the source register for the exit code.
    0x48, 0x89, 0xD7, // 0x58 mov rdi, rdx          ; code
    0x31, 0xC0,       // 0x5B xor eax, eax          ; SYS_EXIT
    0xCD, 0x80,       // 0x5D int 0x80
    0x0F, 0x0B,       // 0x5F ud2                   ; [[noreturn]]
};

static_assert(sizeof(kStubsBytes) <= 4096, "Win32 stubs page fits in one 4 KiB page");
static_assert(sizeof(kStubsBytes) == 0x61, "stub layout drifted; update kOff* constants");

struct StubEntry
{
    const char* dll;
    const char* func;
    u32 offset;
};

constexpr StubEntry kStubsTable[] = {
    // Batch 1 — console I/O
    {"kernel32.dll", "ExitProcess", kOffExitProcess},
    {"kernel32.dll", "GetStdHandle", kOffGetStdHandle},
    // WriteFile and WriteConsoleA share the same stub — both
    // take the same 5-arg shape and we ignore the handle +
    // trailing arg anyway. Aliasing keeps the stubs page
    // small and means any improvement (clamping, error
    // codes, real handle dispatch) lands in both at once.
    {"kernel32.dll", "WriteFile", kOffWriteFile},
    {"kernel32.dll", "WriteConsoleA", kOffWriteFile},
    // Batch 2 — process/thread lifecycle
    {"kernel32.dll", "GetCurrentProcess", kOffGetCurrentProcess},
    {"kernel32.dll", "GetCurrentThread", kOffGetCurrentThread},
    {"kernel32.dll", "GetCurrentProcessId", kOffGetCurrentProcessId},
    {"kernel32.dll", "GetCurrentThreadId", kOffGetCurrentThreadId},
    {"kernel32.dll", "TerminateProcess", kOffTerminateProcess},
};

// Case-insensitive strcmp for ASCII. Win32 DLL name
// capitalisation is inconsistent (lld-link writes
// "kernel32.dll", MSVC's linker writes "KERNEL32.dll"); we
// match either.
bool AsciiCaseEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z')
            ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return *a == 0 && *b == 0;
}

bool AsciiEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        if (*a++ != *b++)
            return false;
    }
    return *a == 0 && *b == 0;
}

} // namespace

void Win32StubsPopulate(u8* dst)
{
    if (dst == nullptr)
        return;
    for (u64 i = 0; i < sizeof(kStubsBytes); ++i)
        dst[i] = kStubsBytes[i];
}

bool Win32StubsLookup(const char* dll, const char* func, u64* out_va)
{
    if (dll == nullptr || func == nullptr || out_va == nullptr)
        return false;
    for (const StubEntry& e : kStubsTable)
    {
        if (!AsciiCaseEqual(e.dll, dll))
            continue;
        if (!AsciiEqual(e.func, func))
            continue;
        *out_va = kWin32StubsVa + e.offset;
        return true;
    }
    return false;
}

} // namespace customos::win32
