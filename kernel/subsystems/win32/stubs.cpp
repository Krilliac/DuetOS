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
constexpr u32 kOffGetLastError = 0x61;        // batch 3 — 8 bytes
constexpr u32 kOffSetLastError = 0x69;        // batch 3 — 10 bytes
constexpr u32 kOffInitCritSec = 0x74;         // batch 4 — 18 bytes
constexpr u32 kOffCritSecNop = 0x86;          // batch 4 — 1 byte (ret)
constexpr u32 kOffMemmove = 0x87;             // batch 5 — 45 bytes (memcpy aliases)
constexpr u32 kOffMemset = 0xB4;              // batch 5 — 19 bytes

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

    // === Batch 3: last-error slot =============================

    // --- GetLastError (offset 0x61, 8 bytes) -------------------
    // Win32: DWORD GetLastError(void). Returns
    // Process.win32_last_error via SYS_GETLASTERROR = 9.
    0xB8, 0x09, 0x00, 0x00, 0x00, // 0x61 mov eax, 9 (SYS_GETLASTERROR)
    0xCD, 0x80,                   // 0x66 int 0x80
    0xC3,                         // 0x68 ret

    // --- SetLastError (offset 0x69, 10 bytes) ------------------
    // Win32: void SetLastError(DWORD dwErrCode). Forwards
    // the code to SYS_SETLASTERROR = 10 via rdi. No return
    // value to massage — the Win32 prototype is void, so
    // whatever the syscall leaves in rax is fine.
    0x48, 0x89, 0xCF,             // 0x69 mov rdi, rcx
    0xB8, 0x0A, 0x00, 0x00, 0x00, // 0x6C mov eax, 10 (SYS_SETLASTERROR)
    0xCD, 0x80,                   // 0x71 int 0x80
    0xC3,                         // 0x73 ret

    // === Batch 4: critical sections (v0 no-ops) ===============

    // --- InitializeCriticalSection (offset 0x74, 18 bytes) -----
    // Aliased by InitializeCriticalSectionEx and
    // InitializeCriticalSectionAndSpinCount. Zero out the
    // 40-byte CRITICAL_SECTION at [rcx], return BOOL TRUE.
    //
    // v0 is single-task per process, so a critical section
    // with no recursion tracking, no owning-thread check, and
    // no semaphore is semantically correct — there's nothing
    // to serialize against. A future slice will replace this
    // when a multi-threading model lands.
    //
    // Assumes DF=0 on entry (Win64 ABI contract). Uses rdi
    // (scratch, caller-saved), clobbers rcx (scratch), eax.
    0x48, 0x89, 0xCF,             // 0x74 mov rdi, rcx
    0xB9, 0x28, 0x00, 0x00, 0x00, // 0x77 mov ecx, 40
    0x31, 0xC0,                   // 0x7C xor eax, eax
    0xF3, 0xAA,                   // 0x7E rep stosb
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x80 mov eax, 1 (BOOL TRUE for Ex variants)
    0xC3,                         // 0x85 ret

    // --- CritSec nop (offset 0x86, 1 byte) ---------------------
    // Shared stub for EnterCriticalSection / LeaveCriticalSection
    // / DeleteCriticalSection. All three are `void(LPCS)`;
    // with no contention to handle they collapse to a single
    // return.
    0xC3, // 0x86 ret

    // === Batch 5: vcruntime140 memory intrinsics ==============
    //
    // CRITICAL ABI NOTE: the Microsoft x64 ABI marks RDI, RSI,
    // RBX, RBP, R12-R15 as NONVOLATILE (callee-saved) — the
    // opposite of the SysV convention where rdi/rsi are
    // scratch. A stub that uses rdi as a scratch register
    // (e.g. as the destination of rep movsb) MUST save and
    // restore it, or the caller's rdi is silently trashed
    // across the call. Every stub here pushes the nonvolatile
    // registers it touches and pops them before ret.

    // --- memmove (offset 0x87, 45 bytes) -----------------------
    // Signature: void* memmove(void* dst=rcx, const void* src=rdx, size_t n=r8).
    // memcpy aliases to this — memmove is a strict superset
    // (handles overlapping regions) and produces the same
    // result as memcpy when regions don't overlap, so aliasing
    // is safe. Returns the original dst in rax.
    //
    // Strategy: if dst <= src (non-overlap or src above dst)
    // forward-copy with rep movsb. Otherwise backward-copy
    // with DF=1 + adjusted start pointers, then restore DF=0
    // (Win64 ABI contract).
    //
    // Saves nonvolatile rsi, rdi around the work.
    0x56,                 // 0x87 push rsi
    0x57,                 // 0x88 push rdi
    0x49, 0x89, 0xC9,     // 0x89 mov r9, rcx     ; save dst for return
    0x48, 0x89, 0xCF,     // 0x8C mov rdi, rcx    ; dst
    0x48, 0x89, 0xD6,     // 0x8F mov rsi, rdx    ; src
    0x4C, 0x89, 0xC1,     // 0x92 mov rcx, r8     ; n
    0x48, 0x39, 0xF7,     // 0x95 cmp rdi, rsi
    0x76, 0x12,           // 0x98 jbe +18 -> 0xAC (forward path)
    // backward-copy path (dst > src, overlap-safe)
    0x48, 0x01, 0xCF,     // 0x9A add rdi, rcx
    0x48, 0xFF, 0xCF,     // 0x9D dec rdi
    0x48, 0x01, 0xCE,     // 0xA0 add rsi, rcx
    0x48, 0xFF, 0xCE,     // 0xA3 dec rsi
    0xFD,                 // 0xA6 std
    0xF3, 0xA4,           // 0xA7 rep movsb
    0xFC,                 // 0xA9 cld
    0xEB, 0x02,           // 0xAA jmp +2 -> 0xAE (skip forward's rep movsb)
    // forward-copy path
    0xF3, 0xA4,           // 0xAC rep movsb
    // common epilogue
    0x4C, 0x89, 0xC8,     // 0xAE mov rax, r9     ; return dst
    0x5F,                 // 0xB1 pop rdi
    0x5E,                 // 0xB2 pop rsi
    0xC3,                 // 0xB3 ret

    // --- memset (offset 0xB4, 19 bytes) ------------------------
    // Signature: void* memset(void* dst=rcx, int c=rdx, size_t n=r8).
    // Byte value is the low 8 bits of c (edx). Returns dst.
    // Saves nonvolatile rdi.
    0x57,                 // 0xB4 push rdi
    0x49, 0x89, 0xC9,     // 0xB5 mov r9, rcx     ; save dst for return
    0x48, 0x89, 0xCF,     // 0xB8 mov rdi, rcx    ; dst
    0x89, 0xD0,           // 0xBB mov eax, edx    ; al = c
    0x4C, 0x89, 0xC1,     // 0xBD mov rcx, r8     ; n
    0xF3, 0xAA,           // 0xC0 rep stosb
    0x4C, 0x89, 0xC8,     // 0xC2 mov rax, r9     ; return dst
    0x5F,                 // 0xC5 pop rdi
    0xC3,                 // 0xC6 ret
};

static_assert(sizeof(kStubsBytes) <= 4096, "Win32 stubs page fits in one 4 KiB page");
static_assert(sizeof(kStubsBytes) == 0xC7, "stub layout drifted; update kOff* constants");

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
    // Batch 3 — last-error slot
    {"kernel32.dll", "GetLastError", kOffGetLastError},
    {"kernel32.dll", "SetLastError", kOffSetLastError},
    // Batch 4 — critical sections (v0 no-ops)
    {"kernel32.dll", "InitializeCriticalSection", kOffInitCritSec},
    {"kernel32.dll", "InitializeCriticalSectionEx", kOffInitCritSec},
    {"kernel32.dll", "InitializeCriticalSectionAndSpinCount", kOffInitCritSec},
    {"kernel32.dll", "EnterCriticalSection", kOffCritSecNop},
    {"kernel32.dll", "LeaveCriticalSection", kOffCritSecNop},
    {"kernel32.dll", "DeleteCriticalSection", kOffCritSecNop},
    // Batch 5 — vcruntime140 memory intrinsics
    {"vcruntime140.dll", "memmove", kOffMemmove},
    // memcpy is safe to alias to memmove — memmove is a strict
    // superset (handles overlap), same return value contract.
    {"vcruntime140.dll", "memcpy", kOffMemmove},
    {"vcruntime140.dll", "memset", kOffMemset},
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
