#include "stubs.h"

#include "../../arch/x86_64/serial.h"
#include "nt_syscall_table_generated.h"

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
constexpr u32 kOffExitProcess = 0x00;         // batch 1 — 9 bytes
constexpr u32 kOffGetStdHandle = 0x09;        // batch 1 — 3 bytes
constexpr u32 kOffWriteFile = 0x0C;           // batch 1 — 44 bytes
constexpr u32 kOffGetCurrentProcess = 0x38;   // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentThread = 0x40;    // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentProcessId = 0x48; // batch 2 — 8 bytes
constexpr u32 kOffGetCurrentThreadId = 0x50;  // batch 2 — 8 bytes
constexpr u32 kOffTerminateProcess = 0x58;    // batch 2 — 9 bytes
constexpr u32 kOffGetLastError = 0x61;        // batch 3 — 8 bytes
constexpr u32 kOffSetLastError = 0x69;        // batch 3 — 10 bytes
constexpr u32 kOffInitCritSec = 0x74;         // batch 4 — 18 bytes
constexpr u32 kOffCritSecNop = 0x86;          // batch 4 — 1 byte (ret)
constexpr u32 kOffMemmove = 0x87;             // batch 5 — 45 bytes (memcpy aliases)
constexpr u32 kOffMemset = 0xB4;              // batch 5 — 19 bytes
constexpr u32 kOffReturnZero = 0xC7;          // batch 6 — 3 bytes  (shared "xor eax,eax; ret")
constexpr u32 kOffTerminate = 0xCA;           // batch 6 — 11 bytes (SYS_EXIT(3))
constexpr u32 kOffInvalidParam = 0xD5;        // batch 6 — 11 bytes (SYS_EXIT(0xC0000417))
constexpr u32 kOffStrcmp = 0xE0;              // batch 7 — 29 bytes
constexpr u32 kOffStrlen = 0xFD;              // batch 7 — 17 bytes
constexpr u32 kOffWcslen = 0x10E;             // batch 7 — 22 bytes
constexpr u32 kOffStrchr = 0x124;             // batch 7 — 23 bytes
constexpr u32 kOffStrcpy = 0x13B;             // batch 7 — 23 bytes
constexpr u32 kOffReturnOne = 0x152;          // batch 8 — 6 bytes (shared "mov eax, 1; ret")
constexpr u32 kOffHeapAlloc = 0x158;          // batch 9 — 11 bytes
constexpr u32 kOffHeapFree = 0x163;           // batch 9 — 16 bytes
constexpr u32 kOffGetProcessHeap = 0x173;     // batch 9 — 8 bytes
constexpr u32 kOffMalloc = 0x17B;             // batch 9 — 11 bytes
constexpr u32 kOffFree = 0x186;               // batch 9 — 11 bytes
constexpr u32 kOffCalloc = 0x191;             // batch 9 — 35 bytes
constexpr u32 kOffOpenProcessToken = 0x1B4;   // batch 10 — 13 bytes
constexpr u32 kOffLookupPrivVal = 0x1C1;      // batch 10 — 13 bytes
constexpr u32 kOffInitSListHead = 0x1CE;      // batch 10 — 16 bytes
constexpr u32 kOffGetSysTimeFT = 0x1DE;       // batch 10 — 8 bytes
constexpr u32 kOffOpenProcess = 0x1E6;        // batch 10 — 4 bytes
constexpr u32 kOffGetExitCodeThread = 0x1EA;  // batch 10 — 12 bytes
constexpr u32 kOffQueryPerfCounter = 0x1F6;   // batch 11 — 16 bytes
constexpr u32 kOffQueryPerfFreq = 0x206;      // batch 11 — 13 bytes
constexpr u32 kOffGetTickCount = 0x213;       // batch 11 — 12 bytes (shared w/ GetTickCount64)
constexpr u32 kOffHeapSize = 0x21F;           // batch 14 — 11 bytes
constexpr u32 kOffHeapRealloc = 0x22A;        // batch 14 — 14 bytes
constexpr u32 kOffRealloc = 0x238;            // batch 14 — 14 bytes
constexpr u32 kOffMissLogger = 0x246;         // batch 15 — 41 bytes
constexpr u32 kOffPArgc = 0x26F;              // batch 16 —  6 bytes
constexpr u32 kOffPArgv = 0x275;              // batch 16 —  6 bytes
constexpr u32 kOffPCommode = 0x27B;           // batch 17 —  6 bytes
constexpr u32 kOffSputn = 0x281;              // batch 18 — 19 bytes
constexpr u32 kOffReturnThis = 0x294;         // batch 18 —  4 bytes
constexpr u32 kOffWiden = 0x298;              // batch 18 —  4 bytes
constexpr u32 kOffHresultEFail = 0x29C;       // batch 19 —  6 bytes
constexpr u32 kOffGetSysTimeFTReal = 0x2A2;   // batch 20 — 13 bytes
constexpr u32 kOffQpcNs = 0x2AF;              // batch 21 — 13 bytes
constexpr u32 kOffQpfNs = 0x2BC;              // batch 21 — 10 bytes
constexpr u32 kOffSleep = 0x2CB;              // batch 22 — 12 bytes (push/pop rdi)
constexpr u32 kOffSwitchToThread = 0x2D7;     // batch 22 — 10 bytes
constexpr u32 kOffGetCmdLineW = 0x2E1;        // batch 23 — 6 bytes
constexpr u32 kOffGetCmdLineA = 0x2E7;        // batch 23 — 6 bytes
constexpr u32 kOffGetEnvBlockW = 0x2ED;       // batch 23 — 6 bytes
constexpr u32 kOffCreateFileW = 0x2F3;        // batch 24 — 59 bytes (UTF-16 strip + open)
constexpr u32 kOffReadFile = 0x32E;           // batch 24 — 46 bytes
constexpr u32 kOffCloseHandle = 0x35C;        // batch 24 — 15 bytes
constexpr u32 kOffSetFilePtrEx = 0x36B;       // batch 24 — 38 bytes
constexpr u32 kOffGetFileSizeEx = 0x391;      // batch 25 — 29 bytes
constexpr u32 kOffGetModuleHandleW = 0x3AE;   // batch 25 — 17 bytes
constexpr u32 kOffCreateMutexW = 0x3BF;       // batch 26 — 13 bytes
constexpr u32 kOffWaitForObj = 0x3CC;         // batch 26 — 38 bytes (mutex-aware)
constexpr u32 kOffReleaseMutex = 0x3F2;       // batch 26 — 24 bytes
constexpr u32 kOffWriteConsoleW = 0x40A;      // batch 27 — 96 bytes (UTF-16 strip + SYS_WRITE)
constexpr u32 kOffGetConsoleMode = 0x46A;     // batch 27 — 12 bytes
constexpr u32 kOffGetConsoleCP = 0x476;       // batch 27 — 6 bytes
constexpr u32 kOffVirtualAlloc = 0x47C;       // batch 28 — 13 bytes
constexpr u32 kOffVirtualFree = 0x489;        // batch 28 — 29 bytes
constexpr u32 kOffVirtualProtect = 0x4A6;     // batch 28 — 18 bytes
constexpr u32 kOffLstrlenW = 0x4B8;           // batch 29 — 15 bytes
constexpr u32 kOffLstrcmpW = 0x4C7;           // batch 29 — 37 bytes
constexpr u32 kOffLstrcpyW = 0x4EC;           // batch 29 — 27 bytes
constexpr u32 kOffIsWow64 = 0x507;            // batch 30 — 17 bytes
constexpr u32 kOffGetVersionExW = 0x518;      // batch 30 — 34 bytes
constexpr u32 kOffLstrlenA = 0x53A;           // batch 31 — 14 bytes
constexpr u32 kOffLstrcmpA = 0x548;           // batch 31 — 37 bytes
constexpr u32 kOffLstrcpyA = 0x56D;           // batch 31 — 26 bytes

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
    0x56,             // 0x87 push rsi
    0x57,             // 0x88 push rdi
    0x49, 0x89, 0xC9, // 0x89 mov r9, rcx     ; save dst for return
    0x48, 0x89, 0xCF, // 0x8C mov rdi, rcx    ; dst
    0x48, 0x89, 0xD6, // 0x8F mov rsi, rdx    ; src
    0x4C, 0x89, 0xC1, // 0x92 mov rcx, r8     ; n
    0x48, 0x39, 0xF7, // 0x95 cmp rdi, rsi
    0x76, 0x12,       // 0x98 jbe +18 -> 0xAC (forward path)
    // backward-copy path (dst > src, overlap-safe)
    0x48, 0x01, 0xCF, // 0x9A add rdi, rcx
    0x48, 0xFF, 0xCF, // 0x9D dec rdi
    0x48, 0x01, 0xCE, // 0xA0 add rsi, rcx
    0x48, 0xFF, 0xCE, // 0xA3 dec rsi
    0xFD,             // 0xA6 std
    0xF3, 0xA4,       // 0xA7 rep movsb
    0xFC,             // 0xA9 cld
    0xEB, 0x02,       // 0xAA jmp +2 -> 0xAE (skip forward's rep movsb)
    // forward-copy path
    0xF3, 0xA4, // 0xAC rep movsb
    // common epilogue
    0x4C, 0x89, 0xC8, // 0xAE mov rax, r9     ; return dst
    0x5F,             // 0xB1 pop rdi
    0x5E,             // 0xB2 pop rsi
    0xC3,             // 0xB3 ret

    // --- memset (offset 0xB4, 19 bytes) ------------------------
    // Signature: void* memset(void* dst=rcx, int c=rdx, size_t n=r8).
    // Byte value is the low 8 bits of c (edx). Returns dst.
    // Saves nonvolatile rdi.
    0x57,             // 0xB4 push rdi
    0x49, 0x89, 0xC9, // 0xB5 mov r9, rcx     ; save dst for return
    0x48, 0x89, 0xCF, // 0xB8 mov rdi, rcx    ; dst
    0x89, 0xD0,       // 0xBB mov eax, edx    ; al = c
    0x4C, 0x89, 0xC1, // 0xBD mov rcx, r8     ; n
    0xF3, 0xAA,       // 0xC0 rep stosb
    0x4C, 0x89, 0xC8, // 0xC2 mov rax, r9     ; return dst
    0x5F,             // 0xC5 pop rdi
    0xC3,             // 0xC6 ret

    // === Batch 6: UCRT CRT-startup shims ======================

    // --- Return-zero (offset 0xC7, 3 bytes) --------------------
    // Shared stub for every apiset/ucrt function whose v0
    // semantic is "report success, do nothing". In the
    // Windows x64 ABI a function that returns int/LONG/BOOL
    // writes to eax; zero-extended to rax; the caller reads
    // eax. `xor eax, eax` produces 0 in rax too.
    //
    // Used by: _configure_narrow_argv,
    // _initialize_narrow_environment, _configthreadlocale,
    // _set_new_mode, _set_fmode, _crt_atexit,
    // _register_onexit_function, _initialize_onexit_table,
    // _seh_filter_exe, _register_thread_local_exe_atexit_callback,
    // _initterm_e, _get_initial_narrow_environment (returns
    // char** — null pointer is semantically "empty env").
    0x31, 0xC0, // 0xC7 xor eax, eax
    0xC3,       // 0xC9 ret

    // --- terminate (offset 0xCA, 11 bytes) ---------------------
    // std::terminate semantics: [[noreturn]] abort. Exit
    // with code 3 (same as POSIX SIGABRT-ish — 3 is the
    // conventional abort exit in the CRT).
    0xBF, 0x03, 0x00, 0x00, 0x00, // 0xCA mov edi, 3
    0x31, 0xC0,                   // 0xCF xor eax, eax   ; SYS_EXIT
    0xCD, 0x80,                   // 0xD1 int 0x80
    0x0F, 0x0B,                   // 0xD3 ud2

    // --- _invalid_parameter_noinfo_noreturn (offset 0xD5, 11) --
    // UCRT's "caller violated a contract" bailout. Windows
    // returns STATUS_INVALID_CRT_PARAMETER (0xC0000417). We
    // exit with that so the code is observable in the serial
    // log.
    0xBF, 0x17, 0x04, 0x00, 0xC0, // 0xD5 mov edi, 0xC0000417
    0x31, 0xC0,                   // 0xDA xor eax, eax   ; SYS_EXIT
    0xCD, 0x80,                   // 0xDC int 0x80
    0x0F, 0x0B,                   // 0xDE ud2

    // === Batch 7: CRT string intrinsics =======================

    // --- strcmp (offset 0xE0, 29 bytes) ------------------------
    // int strcmp(const char* a=rcx, const char* b=rdx).
    // Returns (int)(unsigned)*a - (int)(unsigned)*b at first
    // mismatch, or 0 if both reach NUL simultaneously.
    // Byte-at-a-time loop; doesn't touch any nonvolatile
    // register (rcx, rdx, rax are all caller-saved).
    0x8A, 0x01,       // 0xE0 mov al, [rcx]
    0x8A, 0x12,       // 0xE2 mov dl, [rdx]
    0x38, 0xD0,       // 0xE4 cmp al, dl
    0x75, 0x0C,       // 0xE6 jne +12 -> 0xF4 .done
    0x84, 0xC0,       // 0xE8 test al, al
    0x74, 0x08,       // 0xEA je +8 -> 0xF4 .done
    0x48, 0xFF, 0xC1, // 0xEC inc rcx
    0x48, 0xFF, 0xC2, // 0xEF inc rdx
    0xEB, 0xEC,       // 0xF2 jmp -20 -> 0xE0 .loop
    // .done:
    0x0F, 0xB6, 0xC0, // 0xF4 movzx eax, al
    0x0F, 0xB6, 0xD2, // 0xF7 movzx edx, dl
    0x29, 0xD0,       // 0xFA sub eax, edx
    0xC3,             // 0xFC ret

    // --- strlen (offset 0xFD, 17 bytes) ------------------------
    // size_t strlen(const char* s=rcx). Walks until NUL,
    // returns byte count.
    0x48, 0x89, 0xC8, // 0xFD mov rax, rcx    ; save start
    0x80, 0x38, 0x00, // 0x100 cmp byte [rax], 0
    0x74, 0x05,       // 0x103 je +5 -> 0x10A .done
    0x48, 0xFF, 0xC0, // 0x105 inc rax
    0xEB, 0xF6,       // 0x108 jmp -10 -> 0x100 .loop
    // .done:
    0x48, 0x29, 0xC8, // 0x10A sub rax, rcx   ; length = end - start
    0xC3,             // 0x10D ret

    // --- wcslen (offset 0x10E, 22 bytes) -----------------------
    // size_t wcslen(const wchar_t* s=rcx). Identical shape
    // to strlen but 2-byte stride and the final length is
    // divided by 2 (UTF-16 char count).
    0x48, 0x89, 0xC8,       // 0x10E mov rax, rcx
    0x66, 0x83, 0x38, 0x00, // 0x111 cmp word [rax], 0
    0x74, 0x06,             // 0x115 je +6 -> 0x11D .done
    0x48, 0x83, 0xC0, 0x02, // 0x117 add rax, 2
    0xEB, 0xF4,             // 0x11B jmp -12 -> 0x111 .loop
    // .done:
    0x48, 0x29, 0xC8, // 0x11D sub rax, rcx
    0x48, 0xD1, 0xE8, // 0x120 shr rax, 1     ; byte count / 2 = chars
    0xC3,             // 0x123 ret

    // --- strchr (offset 0x124, 23 bytes) -----------------------
    // char* strchr(const char* s=rcx, int c=rdx).
    // Returns pointer to first byte matching (char)c,
    // including the terminating NUL, or nullptr if not
    // found. Matches Win32/ISO C semantics.
    0x88, 0xD0,       // 0x124 mov al, dl      ; byte to find
    0x38, 0x01,       // 0x126 cmp [rcx], al
    0x74, 0x0A,       // 0x128 je +10 -> 0x134 .found
    0x80, 0x39, 0x00, // 0x12A cmp byte [rcx], 0
    0x74, 0x09,       // 0x12D je +9 -> 0x138 .notfound
    0x48, 0xFF, 0xC1, // 0x12F inc rcx
    0xEB, 0xF2,       // 0x132 jmp -14 -> 0x126 .loop
    // .found:
    0x48, 0x89, 0xC8, // 0x134 mov rax, rcx
    0xC3,             // 0x137 ret
    // .notfound:
    0x31, 0xC0, // 0x138 xor eax, eax
    0xC3,       // 0x13A ret

    // --- strcpy (offset 0x13B, 23 bytes) -----------------------
    // char* strcpy(char* dst=rcx, const char* src=rdx).
    // Copies bytes including NUL terminator, returns dst.
    // Uses r8b (scratch byte, caller-saved) as the transfer
    // register — can't use dl since rdx is the source
    // pointer.
    0x48, 0x89, 0xC8, // 0x13B mov rax, rcx    ; save dst
    0x44, 0x8A, 0x02, // 0x13E mov r8b, [rdx]
    0x44, 0x88, 0x01, // 0x141 mov [rcx], r8b
    0x45, 0x84, 0xC0, // 0x144 test r8b, r8b
    0x74, 0x08,       // 0x147 je +8 -> 0x151 .done
    0x48, 0xFF, 0xC1, // 0x149 inc rcx
    0x48, 0xFF, 0xC2, // 0x14C inc rdx
    0xEB, 0xED,       // 0x14F jmp -19 -> 0x13E .loop
    // .done:
    0xC3, // 0x151 ret

    // === Batch 8: kernel32 safe-ignore shims ==================

    // --- Return-one (offset 0x152, 6 bytes) --------------------
    // Shared stub for Win32 functions whose v0 semantic is
    // "report success, do nothing". Mostly BOOL-returning
    // functions where TRUE (1) means "succeeded" — e.g.
    // CloseHandle, SetConsoleCtrlHandler. Some callers
    // branch on the BOOL, so 1 is the safe default.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x152 mov eax, 1
    0xC3,                         // 0x157 ret

    // === Batch 9: Win32 process heap ==========================
    //
    // Per-process heap backed by SYS_HEAP_ALLOC / SYS_HEAP_FREE,
    // serviced by kernel/subsystems/win32/heap.cpp against the
    // 16-page region mapped at 0x50000000 during PeLoad.
    //
    // Flag arguments (dwFlags on HeapAlloc / HeapFree) are
    // IGNORED in v0. Notable consequence: HEAP_ZERO_MEMORY
    // (0x8) is not honoured — callers that need zeroed memory
    // must use calloc (which zeros explicitly) or memset
    // afterwards. HEAP_GENERATE_EXCEPTIONS (0x4) is also
    // ignored — OOM returns NULL, never raises.

    // --- HeapAlloc (offset 0x158, 11 bytes) --------------------
    // LPVOID HeapAlloc(HANDLE hHeap=rcx, DWORD dwFlags=rdx, SIZE_T dwBytes=r8).
    // v0: ignore hHeap + dwFlags. Pass dwBytes through to
    // SYS_HEAP_ALLOC. rax = returned VA or 0 on OOM.
    0x4C, 0x89, 0xC7,             // 0x158 mov rdi, r8
    0xB8, 0x0B, 0x00, 0x00, 0x00, // 0x15B mov eax, 11 (SYS_HEAP_ALLOC)
    0xCD, 0x80,                   // 0x160 int 0x80
    0xC3,                         // 0x162 ret

    // --- HeapFree (offset 0x163, 16 bytes) ---------------------
    // BOOL HeapFree(HANDLE hHeap=rcx, DWORD dwFlags=rdx, LPVOID lpMem=r8).
    // v0: ignore hHeap + dwFlags. Pass lpMem to SYS_HEAP_FREE.
    // Always return TRUE — the kernel side silently ignores
    // null/out-of-range pointers (Win32 contract: free(NULL)
    // is legal and should not fail).
    0x4C, 0x89, 0xC7,             // 0x163 mov rdi, r8
    0xB8, 0x0C, 0x00, 0x00, 0x00, // 0x166 mov eax, 12 (SYS_HEAP_FREE)
    0xCD, 0x80,                   // 0x16B int 0x80
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x16D mov eax, 1  ; BOOL TRUE
    0xC3,                         // 0x172 ret

    // --- GetProcessHeap (offset 0x173, 8 bytes) ----------------
    // HANDLE GetProcessHeap(void). Returns the heap base VA
    // as an opaque handle. v0 collapses all heap handles to
    // the same value; HeapAlloc's stub ignores it.
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x50, // 0x173 mov rax, 0x50000000
    0xC3,                                     // 0x17A ret

    // --- malloc (offset 0x17B, 11 bytes) -----------------------
    // void* malloc(size_t size=rcx).
    // Identical to HeapAlloc but takes size in rcx (x64 ABI
    // first arg position) instead of r8.
    0x48, 0x89, 0xCF,             // 0x17B mov rdi, rcx
    0xB8, 0x0B, 0x00, 0x00, 0x00, // 0x17E mov eax, 11 (SYS_HEAP_ALLOC)
    0xCD, 0x80,                   // 0x183 int 0x80
    0xC3,                         // 0x185 ret

    // --- free (offset 0x186, 11 bytes) -------------------------
    // void free(void* ptr=rcx).
    // No return value; rax left as syscall result (0) which
    // is fine — C "void" discards it.
    0x48, 0x89, 0xCF,             // 0x186 mov rdi, rcx
    0xB8, 0x0C, 0x00, 0x00, 0x00, // 0x189 mov eax, 12 (SYS_HEAP_FREE)
    0xCD, 0x80,                   // 0x18E int 0x80
    0xC3,                         // 0x190 ret

    // --- calloc (offset 0x191, 35 bytes) -----------------------
    // void* calloc(size_t count=rcx, size_t size=rdx).
    // Allocate count*size bytes and zero-fill. Zero on OOM.
    //
    // Implementation:
    //   rcx = count * size (imul is nonzero-trashing, rdx is
    //         only read; after imul, rdx is untouched)
    //   r9  = saved count*size (for the stosb loop)
    //   SYS_HEAP_ALLOC preserves r9 (int 0x80 only writes rax).
    //   On success: rep stosb zeros [rdi, rdi+rcx); push/pop
    //   rax around the loop because stosb destroys rdi, rcx.
    0x48, 0x0F, 0xAF, 0xCA,       // 0x191 imul rcx, rdx       ; rcx = count*size
    0x48, 0x89, 0xCF,             // 0x195 mov rdi, rcx        ; arg: size
    0x49, 0x89, 0xC9,             // 0x198 mov r9, rcx         ; save size for stosb
    0xB8, 0x0B, 0x00, 0x00, 0x00, // 0x19B mov eax, 11 (SYS_HEAP_ALLOC)
    0xCD, 0x80,                   // 0x1A0 int 0x80            ; rax = ptr or 0
    0x48, 0x85, 0xC0,             // 0x1A2 test rax, rax
    0x74, 0x0C,                   // 0x1A5 jz +12 -> 0x1B3 (ret)
    0x48, 0x89, 0xC7,             // 0x1A7 mov rdi, rax        ; dst
    0x4C, 0x89, 0xC9,             // 0x1AA mov rcx, r9         ; count
    0x50,                         // 0x1AD push rax            ; preserve return
    0x30, 0xC0,                   // 0x1AE xor al, al          ; zero byte
    0xF3, 0xAA,                   // 0x1B0 rep stosb
    0x58,                         // 0x1B2 pop rax
    0xC3,                         // 0x1B3 ret

    // === Batch 10: advapi32 + kernel32 safe-ignore expansion ==
    //
    // advapi32 token/privilege dance: every caller of these
    // expects BOOL return + out-params filled in with
    // "something plausible". v0 gives them all 1s so the
    // setup code path proceeds to the eventual privileged
    // operation (which we can't actually perform anyway).

    // --- OpenProcessToken (offset 0x1B4, 13 bytes) -------------
    // Win32: BOOL OpenProcessToken(HANDLE Process=rcx,
    //                              DWORD DesiredAccess=rdx,
    //                              PHANDLE TokenHandle=r8).
    // Out-param: *TokenHandle = 1 (non-null fake handle).
    // Return TRUE.
    0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x1B4 mov qword [r8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x1BB mov eax, 1
    0xC3,                                     // 0x1C0 ret

    // --- LookupPrivilegeValueW (offset 0x1C1, 13 bytes) --------
    // Win32: BOOL LookupPrivilegeValueW(LPCWSTR System=rcx,
    //                                   LPCWSTR Name=rdx,
    //                                   PLUID Luid=r8).
    // Out-param: *Luid = {LowPart=1, HighPart=0} (LUID is a
    // pair of 32-bit fields in one u64). Non-zero so
    // AdjustTokenPrivileges doesn't treat it as invalid.
    0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x1C1 mov qword [r8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x1C8 mov eax, 1
    0xC3,                                     // 0x1CD ret

    // --- InitializeSListHead (offset 0x1CE, 16 bytes) ----------
    // Win32: void InitializeSListHead(PSLIST_HEADER=rcx).
    // SLIST_HEADER is 16 bytes on x64 (two pointers / atomic
    // state). Zeroing is the correct initialisation — an
    // empty interlocked SList is all-zero.
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,       // 0x1CE mov qword [rcx], 0
    0x48, 0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, // 0x1D5 mov qword [rcx+8], 0
    0xC3,                                           // 0x1DD ret

    // --- GetSystemTimeAsFileTime (offset 0x1DE, 8 bytes) -------
    // Win32: void GetSystemTimeAsFileTime(LPFILETIME=rcx).
    // FILETIME is {u32 low; u32 high} = 8 bytes representing
    // 100ns ticks since 1601-01-01. v0 returns 0 — programs
    // that use this for logging timestamps will see 1601 for
    // every log line. Real implementation would need
    // SYS_GETTIME. Deferred.
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x1DE mov qword [rcx], 0
    0xC3,                                     // 0x1E5 ret

    // --- OpenProcess (offset 0x1E6, 4 bytes) -------------------
    // Win32: HANDLE OpenProcess(DWORD Access=rcx,
    //                           BOOL Inherit=rdx,
    //                           DWORD ProcessId=r8).
    // Return the PID itself as the handle. Any later call
    // that receives this handle (e.g. GetExitCodeProcess)
    // can still identify the process if we ever wire up
    // real process-handle tables. For now it's just a
    // non-null value derived from the input so programs
    // that sanity-check "same PID in == same handle out"
    // still work.
    0x4C, 0x89, 0xC0, // 0x1E6 mov rax, r8
    0xC3,             // 0x1E9 ret

    // --- GetExitCodeThread (offset 0x1EA, 12 bytes) ------------
    // Win32: BOOL GetExitCodeThread(HANDLE=rcx, LPDWORD Exit=rdx).
    // Out-param: *Exit = STILL_ACTIVE (0x103). Tells the
    // caller "the thread is still running" — the safe answer
    // for a hosted environment with no real thread exit
    // codes. Return TRUE.
    0xC7, 0x02, 0x03, 0x01, 0x00, 0x00, // 0x1EA mov dword [rdx], 0x103
    0xB8, 0x01, 0x00, 0x00, 0x00,       // 0x1F0 mov eax, 1
    0xC3,                               // 0x1F5 ret

    // === Batch 11: performance counters + tick count =========
    //
    // Backed by SYS_PERF_COUNTER (13), which returns the
    // kernel's tick counter from arch::TimerTicks(). 100 Hz =
    // 10 ms per tick; the stubs convert to Win32's semantic
    // appropriately (raw u64 counter for QPC, ticks*10 for
    // GetTickCount).

    // --- QueryPerformanceCounter (offset 0x1F6, 16 bytes) ------
    // Win32: BOOL QueryPerformanceCounter(LARGE_INTEGER* ctr=rcx).
    // Out-param: *ctr = current tick count (u64).
    // Return TRUE.
    0xB8, 0x0D, 0x00, 0x00, 0x00, // 0x1F6 mov eax, 13 (SYS_PERF_COUNTER)
    0xCD, 0x80,                   // 0x1FB int 0x80           ; rax = ticks
    0x48, 0x89, 0x01,             // 0x1FD mov [rcx], rax
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x200 mov eax, 1
    0xC3,                         // 0x205 ret

    // --- QueryPerformanceFrequency (offset 0x206, 13 bytes) ----
    // Win32: BOOL QueryPerformanceFrequency(LARGE_INTEGER* freq=rcx).
    // Out-param: *freq = 100 (Hz). Matches the kernel tick
    // frequency so (counter_end - counter_start) / freq
    // gives seconds correctly.
    // Return TRUE.
    0x48, 0xC7, 0x01, 0x64, 0x00, 0x00, 0x00, // 0x206 mov qword [rcx], 100
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x20D mov eax, 1
    0xC3,                                     // 0x212 ret

    // --- GetTickCount / GetTickCount64 (offset 0x213, 12 bytes) -
    // Win32: DWORD GetTickCount(void), ULONGLONG GetTickCount64(void).
    // Both return milliseconds since boot. We scale the 100 Hz
    // tick counter by 10 to convert to ms.
    //   * GetTickCount truncates to 32 bits — caller reads
    //     only EAX; upper half of RAX is ignored.
    //   * GetTickCount64 returns the full RAX.
    // Same implementation either way.
    0xB8, 0x0D, 0x00, 0x00, 0x00, // 0x213 mov eax, 13 (SYS_PERF_COUNTER)
    0xCD, 0x80,                   // 0x218 int 0x80
    0x48, 0x6B, 0xC0, 0x0A,       // 0x21A imul rax, rax, 10 ; ticks -> ms
    0xC3,                         // 0x21E ret

    // === Batch 14: real HeapSize + HeapReAlloc ================
    //
    // Upgrades the v0 "return 0" stubs from batch 9 to real
    // syscalls backed by kernel/subsystems/win32/heap.cpp.
    // Payload-capacity tracking falls out for free from the
    // 16-byte block header the allocator already writes — the
    // kernel reads `header.size` and subtracts kHeaderSize.

    // --- HeapSize (offset 0x21F, 11 bytes) ---------------------
    // Win32: SIZE_T HeapSize(HANDLE hHeap=rcx, DWORD dwFlags=rdx, LPCVOID lpMem=r8).
    // Ignores hHeap + dwFlags (v0 has one heap per process).
    // Pass lpMem through rdi to SYS_HEAP_SIZE = 14; kernel
    // returns the block's payload capacity in rax.
    0x4C, 0x89, 0xC7,             // 0x21F mov rdi, r8
    0xB8, 0x0E, 0x00, 0x00, 0x00, // 0x222 mov eax, 14 (SYS_HEAP_SIZE)
    0xCD, 0x80,                   // 0x227 int 0x80
    0xC3,                         // 0x229 ret

    // --- HeapReAlloc (offset 0x22A, 14 bytes) ------------------
    // Win32: LPVOID HeapReAlloc(HANDLE hHeap=rcx, DWORD dwFlags=rdx,
    //                           LPVOID lpMem=r8, SIZE_T dwBytes=r9).
    // Translate to the two-arg SYS_HEAP_REALLOC = 15: rdi =
    // lpMem (r8), rsi = dwBytes (r9). hHeap + dwFlags ignored.
    // Return value in rax (new VA, or 0 on failure).
    0x4C, 0x89, 0xC7,             // 0x22A mov rdi, r8
    0x4C, 0x89, 0xCE,             // 0x22D mov rsi, r9
    0xB8, 0x0F, 0x00, 0x00, 0x00, // 0x230 mov eax, 15 (SYS_HEAP_REALLOC)
    0xCD, 0x80,                   // 0x235 int 0x80
    0xC3,                         // 0x237 ret

    // --- realloc (offset 0x238, 14 bytes) ----------------------
    // Win32/ucrt: void* realloc(void* ptr=rcx, size_t size=rdx).
    // Same syscall as HeapReAlloc but arguments come from
    // rcx / rdx (standard C calling convention position) —
    // shuffle into rdi / rsi and invoke.
    0x48, 0x89, 0xCF,             // 0x238 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x23B mov rsi, rdx
    0xB8, 0x0F, 0x00, 0x00, 0x00, // 0x23E mov eax, 15 (SYS_HEAP_REALLOC)
    0xCD, 0x80,                   // 0x243 int 0x80
    0xC3,                         // 0x245 ret

    // --- miss-logger (offset 0x246, 35 bytes) -----------------
    // Catch-all trampoline for every unresolved import. Two-step
    // decode of the caller's control flow so we recover the IAT
    // slot VA that matches what the PE loader staged:
    //
    //   step A  (caller's `call qword [rip+rel32]` is actually
    //            `call rel32` because MSVC emits 5-byte direct
    //            CALLs to tiny 6-byte import "thunks", not the
    //            `call [IAT]` pattern). So [rsp] - 4 gives the
    //            rel32 of the CALL; adding it to [rsp] yields
    //            the thunk's VA (e.g. 0x140004F4E).
    //
    //   step B  At the thunk, bytes are `FF 25 rel32_2` — an
    //            indirect `jmp qword [rip+rel32_2]`. rel32_2 is
    //            relative to the byte after the jmp, so
    //            IAT_slot_VA = thunk + 6 + rel32_2.
    //
    // The kernel side looks up IAT_slot_VA in the per-process
    // miss table populated at load time and logs the function
    // name. Each call still returns 0 (same as the old stub).
    //
    // Guard: before decoding, check that the byte immediately
    // preceding the return address is `0xE8` (the `call rel32`
    // opcode). If not, the caller used an indirect call pattern
    // (`call rax`, `call [reg+disp]`, vtable dispatch, etc.);
    // the decode would alias whatever bytes happen to sit there,
    // yielding a plausible-looking but entirely wrong slot VA
    // that surfaces as `<unmapped>`. Skipping the syscall in
    // that case keeps the log honest — "no legible call
    // pattern" becomes silence rather than fake data.
    //
    // Regs: we clobber rax, rcx, rdi — all caller-saved under
    // any Win64 callable we'd be substituted for, and the syscall
    // path preserves the rest. No save/restore needed.
    0x48, 0x8B, 0x04, 0x24,       // 0x246 mov rax, [rsp]               ; return addr
    0x80, 0x78, 0xFB, 0xE8,       // 0x24A cmp byte [rax-5], 0xE8        ; CALL rel32?
    0x75, 0x1C,                   // 0x24E jne +28 -> 0x26C              ; skip decode+syscall
    0x48, 0x63, 0x48, 0xFC,       // 0x250 movsxd rcx, dword [rax-4]    ; CALL rel32
    0x48, 0x01, 0xC1,             // 0x254 add rcx, rax                 ; rcx = thunk VA
    0x48, 0x63, 0x41, 0x02,       // 0x257 movsxd rax, dword [rcx+2]    ; thunk's JMP rel32
    0x48, 0x01, 0xC8,             // 0x25B add rax, rcx                 ; rax = thunk + rel32
    0x48, 0x83, 0xC0, 0x06,       // 0x25E add rax, 6                   ; rax = IAT slot VA
    0x48, 0x89, 0xC7,             // 0x262 mov rdi, rax                 ; arg0 = IAT slot VA
    0xB8, 0x10, 0x00, 0x00, 0x00, // 0x265 mov eax, 16 (SYS_WIN32_MISS_LOG)
    0xCD, 0x80,                   // 0x26A int 0x80
    // .skip target — common epilogue returns 0 for both paths.
    0x31, 0xC0, // 0x26C xor eax, eax
    0xC3,       // 0x26E ret

    // === Batch 16: CRT argc / argv accessors ==================
    //
    // The MSVC CRT's `__scrt_common_main_seh` reads argc/argv via
    // two accessor functions rather than touching globals directly:
    //
    //   int*     __p___argc(void);
    //   char***  __p___argv(void);
    //
    // They return addresses into a process-wide storage block the
    // CRT initialises during startup. In CustomOS that storage is
    // the "proc-env" page at `kProcEnvVa` (0x65000000), populated
    // by `Win32ProcEnvPopulate` during PE load with argc=1 and
    // argv=[program_name, NULL].
    //
    // The absolute address fits in 32 bits (0x65000000 < 2^32), so
    // `mov eax, imm32; ret` is 6 bytes — the upper 32 bits of RAX
    // are zeroed by the x86-64 ABI for any 32-bit dest op, giving
    // us the right 64-bit pointer without a 10-byte movabs.

    // --- __p___argc (offset 0x26F, 6 bytes) --------------------
    // Returns &argc (int*). argc lives at kProcEnvVa + 0x00.
    0xB8, 0x00, 0x00, 0x00, 0x65, // 0x26F mov eax, 0x65000000
    0xC3,                         // 0x274 ret

    // --- __p___argv (offset 0x275, 6 bytes) --------------------
    // Returns &argv (char***). argv (a char**) lives at
    // kProcEnvVa + 0x08.
    0xB8, 0x08, 0x00, 0x00, 0x65, // 0x275 mov eax, 0x65000008
    0xC3,                         // 0x27A ret

    // === Batch 17: UCRT stdio accessors =======================

    // --- __p__commode (offset 0x27B, 6 bytes) ------------------
    // int* __p__commode(void) — returns a pointer to the
    // `_commode` global, which encodes the default file-mode
    // flags (0 = O_TEXT, _O_BINARY = 0x4000, …). Callers of
    // _fmode / __p__commode read this value to pick buffered
    // vs. line-buffered vs. binary I/O; they never write it
    // in v0 workloads. We point at a zero int in the proc-env
    // page — "default text mode" — which is what UCRT itself
    // initialises it to.
    0xB8, 0x00, 0x02, 0x00, 0x65, // 0x27B mov eax, 0x65000200
    0xC3,                         // 0x280 ret

    // === Batch 18: C++ iostream output ========================
    //
    // MSVCP140 virtual methods that would normally sit behind
    // `std::cout.rdbuf()->sputn(...)` / `std::cout << x` virtual
    // dispatch. When a PE imports these BY NAME (rather than
    // through vtables loaded from MSVCP140 at runtime), these
    // IAT-direct stubs let the output actually reach serial.
    //
    // Coverage note: winkill's own std::cout path today goes
    // via virtual dispatch through a zero vtable (from the
    // fake-object data-miss pad), so these stubs aren't called
    // by winkill's current execution path. They unblock any
    // future slice that constructs a real `std::cout` whose
    // streambuf vtable points at kOffSputn etc., and they work
    // immediately for programs that take the method's address
    // directly (e.g. `auto f = &basic_streambuf::sputn`).

    // --- sputn (offset 0x281, 19 bytes) ------------------------
    // `streamsize basic_streambuf<char>::sputn(const char* s, streamsize n)`.
    // Args: rcx=this (ignored), rdx=s, r8=n. Returns count in rax.
    // Direct SYS_WRITE(1, s, n); kernel caps at kSyscallWriteMax
    // (256) and returns the actual count — so the caller's
    // count-check (`rv == n`) will match for small buffers and
    // trip on larger ones, which is the honest behaviour.
    0x48, 0x89, 0xD6,             // 0x281 mov rsi, rdx        ; buf
    0x4C, 0x89, 0xC2,             // 0x284 mov rdx, r8         ; n
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0x287 mov edi, 1          ; fd = stdout
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x28C mov eax, 2 (SYS_WRITE)
    0xCD, 0x80,                   // 0x291 int 0x80
    0xC3,                         // 0x293 ret                 ; rax = count

    // --- return-this (offset 0x294, 4 bytes) -------------------
    // `basic_ostream& basic_ostream::flush()` and any Win32
    // method whose contract is "do nothing, return *this".
    // Args: rcx=this. Returns rcx.
    0x48, 0x89, 0xC8, // 0x294 mov rax, rcx
    0xC3,             // 0x297 ret

    // --- widen (offset 0x298, 4 bytes) -------------------------
    // `char basic_ios<char>::widen(char c)`. Identity on char.
    // Args: rcx=this (ignored), dl=c. Returns c in al.
    0x0F, 0xB6, 0xC2, // 0x298 movzx eax, dl
    0xC3,             // 0x29B ret

    // === Batch 19: D3D / DXGI — HRESULT E_FAIL ================
    //
    // Any PE that imports d3d11 / d3d12 / dxgi entry points
    // lands on this stub. Returns HRESULT E_FAIL
    // (0x80004005) so the caller's "no graphics available"
    // fallback path activates cleanly. Prevents the caller
    // from treating the miss-logger's 0-return as success
    // (HRESULT S_OK == 0), which would lead to a null-deref
    // on the returned IDirect3D*/ID3D11*/IDXGI* interface.
    //
    // Wire-up target: a future slice redirects this IAT
    // landing through a syscall to
    // subsystems::graphics::D3D11CreateDeviceStub etc., so the
    // kernel log records exactly which D3D entry point got
    // called. For v0, returning E_FAIL is enough to make the
    // caller's fallback branch fire.

    // --- HRESULT E_FAIL (offset 0x29C, 6 bytes) ----------------
    // `mov eax, 0x80004005; ret`. The 32-bit form zero-extends
    // to rax; HRESULT is 32-bit so upper bits don't matter.
    0xB8, 0x05, 0x40, 0x00, 0x80, // 0x29C mov eax, 0x80004005
    0xC3,                         // 0x2A1 ret

    // === Batch 20: real GetSystemTimeAsFileTime ===============
    //
    // Replaces the old `0x1DE` stub (which wrote 0 into *rcx).
    // Issues SYS_GETTIME_FT (17) which samples the CMOS RTC and
    // returns a Windows FILETIME (100 ns ticks since 1601-01-01).
    // Then stores the result into *rcx (the caller's LPFILETIME).
    //
    // Register discipline:
    //   - rcx must survive the int 0x80 so we can write *rcx at
    //     the end. int 0x80 preserves all GPRs except rax, so we
    //     don't need to save/restore rcx, but we push it anyway
    //     as paranoia for any future syscall that might clobber
    //     arguments.
    //   - Nothing else matters (caller-saved under Win64 ABI).
    //
    // 13 bytes total.
    0x51,                         // 0x2A2 push rcx
    0xB8, 0x11, 0x00, 0x00, 0x00, // 0x2A3 mov eax, 17 (SYS_GETTIME_FT)
    0xCD, 0x80,                   // 0x2A8 int 0x80                ; rax = FILETIME
    0x59,                         // 0x2AA pop rcx
    0x48, 0x89, 0x01,             // 0x2AB mov [rcx], rax
    0xC3,                         // 0x2AE ret

    // === Batch 21: HPET-backed QueryPerformance{Counter,Frequency} ===
    //
    // The old QPC at 0x1F6 returned LAPIC tick counter (100 Hz)
    // and the old QPF at 0x206 returned 100. Replacing both so
    // QPC returns nanoseconds since boot (via SYS_NOW_NS → HPET)
    // and QPF returns 1 GHz (= 1e9, matching nanoseconds).
    //
    // Any (counter_end - counter_start) / frequency computation
    // a caller does now yields real seconds with ~70 ns granularity.
    // The old 0x1F6 and 0x206 stubs stay as dead page bytes.

    // --- QPC via SYS_NOW_NS (offset 0x2AF, 15 bytes) -----------
    // Win32: BOOL QueryPerformanceCounter(LARGE_INTEGER* ctr=rcx).
    0x51,                         // 0x2AF push rcx
    0xB8, 0x12, 0x00, 0x00, 0x00, // 0x2B0 mov eax, 18 (SYS_NOW_NS)
    0xCD, 0x80,                   // 0x2B5 int 0x80         ; rax = ns since boot
    0x59,                         // 0x2B7 pop rcx
    0x48, 0x89, 0x01,             // 0x2B8 mov [rcx], rax
    0xB0, 0x01,                   // 0x2BB mov al, 1        ; BOOL TRUE (low byte)
    0xC3,                         // 0x2BD ret

    // --- QPF via constant 1'000'000'000 (offset 0x2BE, 13 bytes) --
    // Win32: BOOL QueryPerformanceFrequency(LARGE_INTEGER* freq=rcx).
    // 1e9 = 0x3B9ACA00 fits in a positive imm32, so the
    // `mov qword [rcx], imm32` encoding sign-extends to
    // 0x00000000_3B9ACA00 — exactly the 64-bit value we want.
    0x48, 0xC7, 0x01, 0x00, 0xCA, 0x9A, 0x3B, // 0x2BE mov qword [rcx], 0x3B9ACA00
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x2C5 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x2CA ret

    // --- Sleep (offset 0x2CB, 12 bytes) ------------------------
    // Win32: void Sleep(DWORD dwMilliseconds=ecx). Routes to
    // SYS_SLEEP_MS. The kernel handles the ms==0 special case
    // (yield instead of sleep) so we just forward the value.
    //
    // CRITICAL: RDI is CALLEE-SAVED in the Win32 x64 ABI. We
    // clobber it to set up the SYS_SLEEP_MS arg, so we MUST
    // push/pop it across the syscall — otherwise the caller's
    // RDI-resident local (often a pointer or function pointer
    // by MSVC/clang's register allocator) survives Sleep with
    // value `dwMilliseconds`, and the next deref/call through
    // that "pointer" #PFs at cr2 = ms. (Hit live during the
    // Batch 22 bring-up: Sleep(50) → cr2=0x32.)
    //
    // `mov edi, ecx` is a 32-bit move — x86_64 zero-extends the
    // upper half of rdi automatically, so a DWORD `ms` becomes a
    // u64 with the high bits cleared, matching what SYS_SLEEP_MS
    // expects in rdi.
    0x57,                         // 0x2CB push rdi            ; save callee-saved
    0x89, 0xCF,                   // 0x2CC mov edi, ecx        ; ms -> rdi
    0xB8, 0x13, 0x00, 0x00, 0x00, // 0x2CE mov eax, 19         ; SYS_SLEEP_MS
    0xCD, 0x80,                   // 0x2D3 int 0x80
    0x5F,                         // 0x2D5 pop rdi             ; restore
    0xC3,                         // 0x2D6 ret

    // --- SwitchToThread (offset 0x2D7, 10 bytes) ---------------
    // Win32: BOOL SwitchToThread(void). Returns nonzero if a
    // thread switch happened, 0 if no other ready thread was
    // available. Maps to SYS_YIELD; we return 1 (TRUE)
    // optimistically — callers use the return as a hint, not a
    // strict assertion of "another thread ran". The real check
    // would require comparing scheduler tick counters before
    // and after, which isn't worth the kernel-side complexity.
    //
    // No callee-saved regs touched — only RAX (caller-saved).
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x2D7 mov eax, 3          ; SYS_YIELD
    0xCD, 0x80,                   // 0x2DC int 0x80
    0xB0, 0x01,                   // 0x2DE mov al, 1           ; BOOL TRUE
    0xC3,                         // 0x2E0 ret

    // === Batch 23: command line + environment ================
    //
    // Each of these stubs returns a pointer into the proc-env
    // page. The destination addresses live in the low 4 GiB
    // (kProcEnvVa = 0x65000000), so a 32-bit `mov eax, imm32`
    // followed by `ret` is enough — x86_64 zero-extends the
    // upper half of rax automatically.
    //
    // Win32 contract: GetCommandLineW returns a non-NULL
    // pointer to a wide cmdline string for the lifetime of the
    // process. The CRT calls this exactly once during startup
    // to populate __wargv; downstream callers see argv via
    // __p___argv (already wired in batch 16).

    // --- GetCommandLineW (offset 0x2E1, 6 bytes) ---------------
    // Returns LPCWSTR = kProcEnvVa + kProcEnvCmdlineWOff
    //                 = 0x65000300 (low 4 GiB).
    0xB8, 0x00, 0x03, 0x00, 0x65, // 0x2E1 mov eax, 0x65000300
    0xC3,                         // 0x2E6 ret

    // --- GetCommandLineA (offset 0x2E7, 6 bytes) ---------------
    // Returns LPCSTR = kProcEnvVa + kProcEnvCmdlineAOff
    //                = 0x65000380.
    0xB8, 0x80, 0x03, 0x00, 0x65, // 0x2E7 mov eax, 0x65000380
    0xC3,                         // 0x2EC ret

    // --- GetEnvironmentStringsW (offset 0x2ED, 6 bytes) --------
    // Returns LPWCH = kProcEnvVa + kProcEnvEnvBlockWOff
    //               = 0x65000400. The block is two NUL bytes
    // (an empty env), so any caller that walks it stops
    // immediately. FreeEnvironmentStringsW is a Win32 cleanup
    // hook — registered as a no-op (returns TRUE) below.
    0xB8, 0x00, 0x04, 0x00, 0x65, // 0x2ED mov eax, 0x65000400
    0xC3,                         // 0x2F2 ret

    // === Batch 24: file I/O ===================================
    //
    // Win32 handle table lives on Process; SYS_FILE_OPEN /
    // SYS_FILE_READ / SYS_FILE_CLOSE / SYS_FILE_SEEK route in.
    // Handles returned to user mode are 0x100..0x10F (so they
    // never collide with INVALID_HANDLE_VALUE = -1).

    // --- CreateFileW (offset 0x2F3, 59 bytes) -----------------
    // Win32: HANDLE CreateFileW(LPCWSTR lpFileName=rcx, DWORD
    //          dwDesiredAccess, DWORD dwShareMode,
    //          LPSECURITY_ATTRIBUTES lpSec, DWORD dwCreate,
    //          DWORD dwFlags, HANDLE hTemplate);
    //
    // v0 ignores every flag — opens read-only no matter what.
    // The wide path in rcx gets stripped to ASCII on a stack-
    // local 256-byte buffer, then SYS_FILE_OPEN routes it to
    // the kernel.
    //
    // RDI / RSI are CALLEE-SAVED in the Win32 x64 ABI — same
    // bug class that bit Sleep in batch 22; both are saved+
    // restored across the syscall.
    0x57,                                     // 0x2F3 push rdi
    0x56,                                     // 0x2F4 push rsi
    0x48, 0x81, 0xEC, 0x08, 0x01, 0x00, 0x00, // 0x2F5 sub rsp, 0x108  ; 264-byte ASCII buf
    0x48, 0x89, 0xE7,                         // 0x2FC mov rdi, rsp    ; rdi = ASCII dst
    0x31, 0xD2,                               // 0x2FF xor edx, edx    ; idx = 0
    // .loop:
    0x83, 0xFA, 0xFF,       // 0x301 cmp edx, 0xFF    ; cap at 255
    0x73, 0x10,             // 0x304 jae +0x10 (.done)
    0x0F, 0xB7, 0x04, 0x51, // 0x306 movzx eax, word [rcx+rdx*2]  ; load wide char
    0x66, 0x85, 0xC0,       // 0x30A test ax, ax      ; NUL?
    0x74, 0x07,             // 0x30D jz +0x07 (.done)
    0x88, 0x04, 0x17,       // 0x30F mov [rdi+rdx], al ; ASCII low byte
    0xFF, 0xC2,             // 0x312 inc edx
    0xEB, 0xEB,             // 0x314 jmp .loop (-0x15)
    // .done:
    0xC6, 0x04, 0x17, 0x00,                   // 0x316 mov byte [rdi+rdx], 0  ; NUL terminate
    0x48, 0x89, 0xD6,                         // 0x31A mov rsi, rdx    ; len -> rsi (arg 1)
    0xB8, 0x14, 0x00, 0x00, 0x00,             // 0x31D mov eax, 20     ; SYS_FILE_OPEN
    0xCD, 0x80,                               // 0x322 int 0x80
    0x48, 0x81, 0xC4, 0x08, 0x01, 0x00, 0x00, // 0x324 add rsp, 0x108  ; restore stack
    0x5E,                                     // 0x32B pop rsi
    0x5F,                                     // 0x32C pop rdi
    0xC3,                                     // 0x32D ret

    // --- ReadFile (offset 0x32E, 46 bytes) --------------------
    // Win32: BOOL ReadFile(HANDLE rcx, LPVOID buf=rdx,
    //          DWORD count=r8, LPDWORD lpRead=r9, LPOVERLAPPED).
    // Maps to SYS_FILE_READ; stores byte count in *lpRead if
    // non-NULL; returns TRUE on success (rax >= 0).
    0x57,                         // 0x32E push rdi
    0x56,                         // 0x32F push rsi
    0x48, 0x89, 0xCF,             // 0x330 mov rdi, rcx     ; handle
    0x48, 0x89, 0xD6,             // 0x333 mov rsi, rdx     ; buf
    0x4C, 0x89, 0xC2,             // 0x336 mov rdx, r8      ; count
    0xB8, 0x15, 0x00, 0x00, 0x00, // 0x339 mov eax, 21      ; SYS_FILE_READ
    0xCD, 0x80,                   // 0x33E int 0x80
    // *lpRead = max(rax, 0) if r9 != NULL
    0x4D, 0x85, 0xC9, // 0x340 test r9, r9
    0x74, 0x0B,       // 0x343 jz +0x0B
    0x31, 0xC9,       // 0x345 xor ecx, ecx
    0x48, 0x85, 0xC0, // 0x347 test rax, rax
    0x0F, 0x49, 0xC8, // 0x34A cmovns ecx, eax
    0x41, 0x89, 0x09, // 0x34D mov [r9], ecx
    // BOOL = (rax >= 0)
    0x48, 0x85, 0xC0, // 0x350 test rax, rax
    0x0F, 0x99, 0xC0, // 0x353 setns al
    0x0F, 0xB6, 0xC0, // 0x356 movzx eax, al
    0x5E,             // 0x359 pop rsi
    0x5F,             // 0x35A pop rdi
    0xC3,             // 0x35B ret

    // --- CloseHandle (offset 0x35C, 15 bytes) -----------------
    // Win32: BOOL CloseHandle(HANDLE rcx). SYS_FILE_CLOSE
    // tolerates non-file handles (no-op + return 0), so this
    // also harmlessly handles the historical no-op CloseHandle
    // call sites (e.g. CreateEventW pseudo-handles).
    0x57,                         // 0x35C push rdi
    0x48, 0x89, 0xCF,             // 0x35D mov rdi, rcx
    0xB8, 0x16, 0x00, 0x00, 0x00, // 0x360 mov eax, 22      ; SYS_FILE_CLOSE
    0xCD, 0x80,                   // 0x365 int 0x80
    0xB0, 0x01,                   // 0x367 mov al, 1        ; BOOL TRUE
    0x5F,                         // 0x369 pop rdi
    0xC3,                         // 0x36A ret

    // --- SetFilePointerEx (offset 0x36B, 38 bytes) ------------
    // Win32: BOOL SetFilePointerEx(HANDLE rcx,
    //          LARGE_INTEGER off=rdx, LARGE_INTEGER* newPos=r8,
    //          DWORD dwMoveMethod=r9).
    // Maps to SYS_FILE_SEEK; writes new position to *r8 if
    // non-NULL; returns TRUE iff rax >= 0.
    0x57,                         // 0x36B push rdi
    0x56,                         // 0x36C push rsi
    0x48, 0x89, 0xCF,             // 0x36D mov rdi, rcx     ; handle
    0x48, 0x89, 0xD6,             // 0x370 mov rsi, rdx     ; offset
    0x4C, 0x89, 0xCA,             // 0x373 mov rdx, r9      ; whence
    0xB8, 0x17, 0x00, 0x00, 0x00, // 0x376 mov eax, 23      ; SYS_FILE_SEEK
    0xCD, 0x80,                   // 0x37B int 0x80
    0x4D, 0x85, 0xC0,             // 0x37D test r8, r8
    0x74, 0x03,                   // 0x380 jz +0x03
    0x49, 0x89, 0x00,             // 0x382 mov [r8], rax
    0x48, 0x85, 0xC0,             // 0x385 test rax, rax
    0x0F, 0x99, 0xC0,             // 0x388 setns al
    0x0F, 0xB6, 0xC0,             // 0x38B movzx eax, al
    0x5E,                         // 0x38E pop rsi
    0x5F,                         // 0x38F pop rdi
    0xC3,                         // 0x390 ret

    // === Batch 25: file stat + module lookup ==================

    // --- GetFileSizeEx (offset 0x391, 29 bytes) ---------------
    // Win32: BOOL GetFileSizeEx(HANDLE rcx, LARGE_INTEGER* rdx).
    // Maps to SYS_FILE_FSTAT — non-destructive size query that
    // doesn't perturb the read cursor (vs. SEEK_END which
    // would).
    0x57,                         // 0x391 push rdi
    0x56,                         // 0x392 push rsi
    0x48, 0x89, 0xCF,             // 0x393 mov rdi, rcx     ; handle
    0x48, 0x89, 0xD6,             // 0x396 mov rsi, rdx     ; out ptr
    0xB8, 0x18, 0x00, 0x00, 0x00, // 0x399 mov eax, 24      ; SYS_FILE_FSTAT
    0xCD, 0x80,                   // 0x39E int 0x80
    0x31, 0xC9,                   // 0x3A0 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x3A2 test rax, rax    ; ZF=1 iff success (rax==0)
    0x0F, 0x94, 0xC1,             // 0x3A5 sete cl
    0x0F, 0xB6, 0xC1,             // 0x3A8 movzx eax, cl
    0x5E,                         // 0x3AB pop rsi
    0x5F,                         // 0x3AC pop rdi
    0xC3,                         // 0x3AD ret

    // --- GetModuleHandleW (offset 0x3AE, 17 bytes) ------------
    // Win32: HMODULE GetModuleHandleW(LPCWSTR lpModuleName=rcx).
    //
    // v0 supports exactly the lpModuleName == NULL form (returns
    // the EXE's own HMODULE) — that's what the CRT calls during
    // startup to populate __ImageBase. Any non-NULL name returns
    // 0 (= "module not in our process" → caller's GetLastError
    // path runs). The EXE's image base lives in the proc-env
    // page at kProcEnvVa + kProcEnvModuleBaseOff (= 0x65000500),
    // populated by Win32ProcEnvPopulate from the PE loader.
    0x48, 0x85, 0xC9,                               // 0x3AE test rcx, rcx
    0x75, 0x09,                                     // 0x3B1 jne +0x09 -> .not_null
    0x48, 0x8B, 0x04, 0x25, 0x00, 0x05, 0x00, 0x65, // 0x3B3 mov rax, [0x65000500]
    0xC3,                                           // 0x3BB ret
    // .not_null:
    0x31, 0xC0, // 0x3BC xor eax, eax
    0xC3,       // 0x3BE ret

    // === Batch 26: Win32 mutex (real waitqueue-backed) =========

    // --- CreateMutexW (offset 0x3BF, 13 bytes) ----------------
    // Win32: HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES rcx,
    //          BOOL bInitialOwner=rdx, LPCWSTR lpName=r8).
    // Ignores attrs + name; forwards bInitialOwner to
    // SYS_MUTEX_CREATE which returns the kWin32MutexBase + slot
    // pseudo-handle directly.
    0x57,                         // 0x3BF push rdi
    0x48, 0x89, 0xD7,             // 0x3C0 mov rdi, rdx       ; bInitialOwner
    0xB8, 0x19, 0x00, 0x00, 0x00, // 0x3C3 mov eax, 25        ; SYS_MUTEX_CREATE
    0xCD, 0x80,                   // 0x3C8 int 0x80
    0x5F,                         // 0x3CA pop rdi
    0xC3,                         // 0x3CB ret

    // --- WaitForSingleObject (offset 0x3CC, 38 bytes) ---------
    // Win32: DWORD WaitForSingleObject(HANDLE rcx, DWORD timeout=rdx).
    //
    // Dispatches by handle range:
    //   * Mutex range (0x200..0x207): SYS_MUTEX_WAIT.
    //   * Anything else: pseudo-signal (return 0 = WAIT_OBJECT_0)
    //     to preserve the slice-10 batch-10 behaviour for events,
    //     thread handles, etc., that the v0 stubs don't track.
    //
    // RDI / RSI saved+restored — Win32 ABI callee-saved.
    0x57,                               // 0x3CC push rdi
    0x56,                               // 0x3CD push rsi
    0x48, 0x89, 0xC8,                   // 0x3CE mov rax, rcx       ; handle
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x3D1 sub rax, 0x200     ; rax -= base
    0x48, 0x83, 0xF8, 0x08,             // 0x3D7 cmp rax, 8         ; in mutex range?
    0x73, 0x10,                         // 0x3DB jae .pseudo (+0x10)
    0x48, 0x89, 0xCF,                   // 0x3DD mov rdi, rcx       ; handle
    0x48, 0x89, 0xD6,                   // 0x3E0 mov rsi, rdx       ; timeout_ms
    0xB8, 0x1A, 0x00, 0x00, 0x00,       // 0x3E3 mov eax, 26        ; SYS_MUTEX_WAIT
    0xCD, 0x80,                         // 0x3E8 int 0x80
    0x5E,                               // 0x3EA pop rsi
    0x5F,                               // 0x3EB pop rdi
    0xC3,                               // 0x3EC ret
    // .pseudo:
    0x31, 0xC0, // 0x3ED xor eax, eax       ; WAIT_OBJECT_0 = 0
    0x5E,       // 0x3EF pop rsi
    0x5F,       // 0x3F0 pop rdi
    0xC3,       // 0x3F1 ret

    // --- ReleaseMutex (offset 0x3F2, 24 bytes) ----------------
    // Win32: BOOL ReleaseMutex(HANDLE rcx).
    // SYS_MUTEX_RELEASE returns 0 on success, -1 on failure;
    // BOOL = (rax == 0).
    0x57,                         // 0x3F2 push rdi
    0x48, 0x89, 0xCF,             // 0x3F3 mov rdi, rcx
    0xB8, 0x1B, 0x00, 0x00, 0x00, // 0x3F6 mov eax, 27         ; SYS_MUTEX_RELEASE
    0xCD, 0x80,                   // 0x3FB int 0x80
    0x31, 0xC9,                   // 0x3FD xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x3FF test rax, rax
    0x0F, 0x94, 0xC1,             // 0x402 sete cl
    0x0F, 0xB6, 0xC1,             // 0x405 movzx eax, cl
    0x5F,                         // 0x408 pop rdi
    0xC3,                         // 0x409 ret

    // === Batch 27: console APIs ================================

    // --- WriteConsoleW (offset 0x40A, 96 bytes) ---------------
    // Win32: BOOL WriteConsoleW(HANDLE rcx, const void* rdx,
    //          DWORD nChars=r8, LPDWORD lpCharsOut=r9,
    //          LPVOID lpReserved=[rsp+0x28]).
    //
    // Strips UTF-16LE to low-byte ASCII on a 512-byte stack
    // buffer (capped — longer writes truncate), then routes
    // through SYS_WRITE(fd=1). Stores wide-char count to
    // *lpCharsOut if non-NULL. Returns TRUE always — SYS_WRITE
    // to stdout is gated only by kCapSerialConsole, and a
    // denial there is flagged upstream via the denial counter.
    //
    // Saves RDI / RSI / R12 / R13 — all callee-saved in Win32
    // x64 ABI. R12/R13 used as scratch for count + out-ptr
    // preservation across the syscall.
    0x57,                                     // 0x40A push rdi
    0x56,                                     // 0x40B push rsi
    0x41, 0x54,                               // 0x40C push r12
    0x41, 0x55,                               // 0x40E push r13
    0x48, 0x81, 0xEC, 0x08, 0x02, 0x00, 0x00, // 0x410 sub rsp, 0x208  ; 512-byte ASCII buf + 8 pad
    0x48, 0x89, 0xE7,                         // 0x417 mov rdi, rsp    ; dst
    0x48, 0x89, 0xD6,                         // 0x41A mov rsi, rdx    ; src (wide)
    0x4D, 0x89, 0xC4,                         // 0x41D mov r12, r8     ; nChars (save)
    0x4D, 0x89, 0xCD,                         // 0x420 mov r13, r9     ; lpCharsOut (save)
    0x31, 0xC9,                               // 0x423 xor ecx, ecx    ; i = 0
    // .loop:
    0x4C, 0x39, 0xE1,                         // 0x425 cmp rcx, r12    ; i < count?
    0x73, 0x15,                               // 0x428 jae .done (+0x15)
    0x48, 0x81, 0xF9, 0x00, 0x02, 0x00, 0x00, // 0x42A cmp rcx, 0x200  ; i < 512?
    0x73, 0x0C,                               // 0x431 jae .done (+0x0C)
    0x0F, 0xB7, 0x04, 0x4E,                   // 0x433 movzx eax, word [rsi+rcx*2]
    0x88, 0x04, 0x0F,                         // 0x437 mov [rdi+rcx], al
    0x48, 0xFF, 0xC1,                         // 0x43A inc rcx
    0xEB, 0xE6,                               // 0x43D jmp .loop (-0x1A)
    // .done: rcx = actual ASCII byte count
    0x48, 0x89, 0xCA,             // 0x43F mov rdx, rcx    ; len for SYS_WRITE
    0x48, 0x89, 0xFE,             // 0x442 mov rsi, rdi    ; buf = ASCII dst
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0x445 mov edi, 1      ; fd = stdout
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x44A mov eax, 2      ; SYS_WRITE
    0xCD, 0x80,                   // 0x44F int 0x80
    0x4D, 0x85, 0xED,             // 0x451 test r13, r13   ; lpCharsOut != NULL?
    0x74, 0x04,                   // 0x454 jz .skip (+4)
    0x45, 0x89, 0x65, 0x00,       // 0x456 mov [r13+0], r12d   ; store wide-char count
    // .skip:
    0x48, 0x81, 0xC4, 0x08, 0x02, 0x00, 0x00, // 0x45A add rsp, 0x208
    0x41, 0x5D,                               // 0x461 pop r13
    0x41, 0x5C,                               // 0x463 pop r12
    0x5E,                                     // 0x465 pop rsi
    0x5F,                                     // 0x466 pop rdi
    0xB0, 0x01,                               // 0x467 mov al, 1       ; BOOL TRUE
    0xC3,                                     // 0x469 ret

    // --- GetConsoleMode (offset 0x46A, 12 bytes) --------------
    // Win32: BOOL GetConsoleMode(HANDLE rcx, DWORD* rdx).
    // Returns a plausible flag combination —
    //   ENABLE_PROCESSED_OUTPUT (0x1) | ENABLE_WRAP_AT_EOL (0x2) |
    //   ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x4) = 0x7.
    // Callers that query-then-modify + SetConsoleMode round-trip
    // see the mode they set (SetConsoleMode is kOffReturnOne, so
    // the write is a no-op; the next Get returns the same
    // constant). Good enough for v0 — modern terminal-aware
    // tools see "VT processing is on, so emit escape codes" and
    // that's what our serial sink wants anyway.
    0xC7, 0x02, 0x07, 0x00, 0x00, 0x00, // 0x46A mov dword [rdx], 7
    0xB8, 0x01, 0x00, 0x00, 0x00,       // 0x470 mov eax, 1 (BOOL TRUE)
    0xC3,                               // 0x475 ret

    // --- GetConsoleCP / GetConsoleOutputCP (offset 0x476, 6 bytes) --
    // Win32: UINT GetConsoleCP(void). Returns the input code page.
    // We report CP_UTF8 = 65001 = 0xFDE9, which matches modern
    // Windows default (post-2019 "beta: use UTF-8") and tells
    // callers their wide-char strings have already been decoded
    // on our side. Aliased for GetConsoleOutputCP below.
    0xB8, 0xE9, 0xFD, 0x00, 0x00, // 0x476 mov eax, 65001 (CP_UTF8)
    0xC3,                         // 0x47B ret

    // === Batch 28: virtual memory (VirtualAlloc/Free/Protect) ==

    // --- VirtualAlloc (offset 0x47C, 13 bytes) ----------------
    // Win32: LPVOID VirtualAlloc(LPVOID rcx, SIZE_T rdx,
    //          DWORD flAllocationType=r8, DWORD flProtect=r9).
    // v0 ignores rcx (caller's preferred address), r8, r9 —
    // just forwards the size to SYS_VMAP which bump-allocates
    // RW+NX+User pages. Kernel returns the VA; stub returns it
    // verbatim (or 0 on arena exhaustion).
    0x57,                         // 0x47C push rdi
    0x48, 0x89, 0xD7,             // 0x47D mov rdi, rdx       ; size
    0xB8, 0x1C, 0x00, 0x00, 0x00, // 0x480 mov eax, 28        ; SYS_VMAP
    0xCD, 0x80,                   // 0x485 int 0x80
    0x5F,                         // 0x487 pop rdi
    0xC3,                         // 0x488 ret

    // --- VirtualFree (offset 0x489, 29 bytes) -----------------
    // Win32: BOOL VirtualFree(LPVOID rcx, SIZE_T rdx,
    //          DWORD dwFreeType=r8).
    // v0: no-op with range validation. Ignores rdx + r8;
    // SYS_VUNMAP returns 0 if the VA is in the vmap arena, -1
    // otherwise. BOOL = (rax == 0).
    0x57,                         // 0x489 push rdi
    0x56,                         // 0x48A push rsi
    0x48, 0x89, 0xCF,             // 0x48B mov rdi, rcx       ; va
    0x48, 0x89, 0xD6,             // 0x48E mov rsi, rdx       ; size
    0xB8, 0x1D, 0x00, 0x00, 0x00, // 0x491 mov eax, 29        ; SYS_VUNMAP
    0xCD, 0x80,                   // 0x496 int 0x80
    0x31, 0xC9,                   // 0x498 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x49A test rax, rax
    0x0F, 0x94, 0xC1,             // 0x49D sete cl
    0x0F, 0xB6, 0xC1,             // 0x4A0 movzx eax, cl
    0x5E,                         // 0x4A3 pop rsi
    0x5F,                         // 0x4A4 pop rdi
    0xC3,                         // 0x4A5 ret

    // --- VirtualProtect (offset 0x4A6, 18 bytes) --------------
    // Win32: BOOL VirtualProtect(LPVOID rcx, SIZE_T rdx,
    //          DWORD flNewProtect=r8, PDWORD lpflOldProtect=r9).
    // v0 is a no-op: every vmap page is RW+NX by construction
    // (W^X policy — no W+X). If r9 is non-NULL we write
    // PAGE_READWRITE (0x04) back as the "old" protection so
    // MSVC CRT's VirtualProtect-probe round-trip sees a
    // plausible value. Return TRUE.
    0x4D, 0x85, 0xC9,                         // 0x4A6 test r9, r9
    0x74, 0x07,                               // 0x4A9 jz .skip (+7)
    0x41, 0xC7, 0x01, 0x04, 0x00, 0x00, 0x00, // 0x4AB mov dword [r9], 4 (PAGE_READWRITE)
    // .skip:
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x4B2 mov eax, 1 (BOOL TRUE)
    0xC3,                         // 0x4B7 ret

    // === Batch 29: wide-string helpers =========================

    // --- lstrlenW (offset 0x4B8, 15 bytes) --------------------
    // Win32: int lstrlenW(LPCWSTR rcx). Scans for a u16 zero and
    // returns the wide-char count. No SEH, no CP check — just
    // the classic strlen shape on 16-bit elements.
    0x31, 0xC0, // 0x4B8 xor eax, eax
    // .loop:
    0x66, 0x83, 0x3C, 0x41, 0x00, // 0x4BA cmp word [rcx + rax*2], 0
    0x74, 0x05,                   // 0x4BF je .done (+5)
    0x48, 0xFF, 0xC0,             // 0x4C1 inc rax
    0xEB, 0xF4,                   // 0x4C4 jmp .loop (-12)
    // .done:
    0xC3, // 0x4C6 ret

    // --- lstrcmpW (offset 0x4C7, 37 bytes) --------------------
    // Win32: int lstrcmpW(LPCWSTR rcx, LPCWSTR rdx).
    // Returns 0 if equal, negative if s1 < s2, positive if s1 > s2.
    // Pure compute — no locale folding (lstrcmpW is ordinal
    // compare; lstrcmpiW would case-fold, which we don't stub).
    0x31, 0xC0, // 0x4C7 xor eax, eax      ; i = 0
    // .loop:
    0x44, 0x0F, 0xB7, 0x04, 0x41, // 0x4C9 movzx r8d, word [rcx+rax*2]
    0x44, 0x0F, 0xB7, 0x0C, 0x42, // 0x4CE movzx r9d, word [rdx+rax*2]
    0x45, 0x39, 0xC8,             // 0x4D3 cmp r8d, r9d
    0x75, 0x0D,                   // 0x4D6 jne .diff (+0x0D)
    0x45, 0x85, 0xC0,             // 0x4D8 test r8d, r8d       ; both NUL?
    0x74, 0x05,                   // 0x4DB je .equal (+5)
    0x48, 0xFF, 0xC0,             // 0x4DD inc rax
    0xEB, 0xE7,                   // 0x4E0 jmp .loop (-0x19)
    // .equal:
    0x31, 0xC0, // 0x4E2 xor eax, eax
    0xC3,       // 0x4E4 ret
    // .diff:
    0x44, 0x89, 0xC0, // 0x4E5 mov eax, r8d     ; signed diff
    0x44, 0x29, 0xC8, // 0x4E8 sub eax, r9d
    0xC3,             // 0x4EB ret

    // --- lstrcpyW (offset 0x4EC, 27 bytes) --------------------
    // Win32: LPWSTR lstrcpyW(LPWSTR rcx, LPCWSTR rdx).
    // Returns the destination pointer (rcx). Copies wide chars
    // including the terminating NUL. Classic strcpy shape on
    // 16-bit elements — no length check, caller's responsibility
    // to size the destination.
    0x48, 0x89, 0xC8, // 0x4EC mov rax, rcx    ; save dst for return
    0x45, 0x31, 0xC0, // 0x4EF xor r8d, r8d    ; i = 0
    // .loop:
    0x46, 0x0F, 0xB7, 0x0C, 0x42, // 0x4F2 movzx r9d, word [rdx+r8*2]
    0x66, 0x46, 0x89, 0x0C, 0x41, // 0x4F7 mov word [rcx+r8*2], r9w
    0x45, 0x85, 0xC9,             // 0x4FC test r9d, r9d   ; copied NUL?
    0x74, 0x05,                   // 0x4FF je .done (+5)
    0x49, 0xFF, 0xC0,             // 0x501 inc r8
    0xEB, 0xEC,                   // 0x504 jmp .loop (-0x14)
    // .done:
    0xC3, // 0x506 ret

    // === Batch 30: system-info probes ==========================

    // --- IsWow64Process (offset 0x507, 17 bytes) --------------
    // Win32: BOOL IsWow64Process(HANDLE rcx, PBOOL rdx).
    // Writes FALSE to *Wow64Process (we're a native x64 process;
    // there's no 32-bit emulation subsystem in v0 anyway) and
    // returns TRUE. If the out-ptr is NULL we skip the write —
    // real Windows also tolerates this.
    0x48, 0x85, 0xD2,                   // 0x507 test rdx, rdx
    0x74, 0x06,                         // 0x50A jz .skip (+6)
    0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x50C mov dword [rdx], 0 (FALSE)
    // .skip:
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x512 mov eax, 1 (BOOL TRUE)
    0xC3,                         // 0x517 ret

    // --- GetVersionExW (offset 0x518, 34 bytes) ---------------
    // Win32: BOOL GetVersionExW(POSVERSIONINFOW rcx).
    //
    // Layout of OSVERSIONINFOW:
    //   0x00  dwOSVersionInfoSize  <- caller-set; we leave alone
    //   0x04  dwMajorVersion       <- we write 10 (Win10)
    //   0x08  dwMinorVersion       <- we write 0
    //   0x0C  dwBuildNumber        <- we write 19041 (Win10 2004)
    //   0x10  dwPlatformId         <- we write 2 (VER_PLATFORM_WIN32_NT)
    //   0x14  szCSDVersion[128]    <- leave caller's zero-init
    //
    // 19041 = 0x4A61; fits in imm32 signed. Picked to look like a
    // recent-ish Windows 10 build so feature-gate probes see a
    // plausible "new enough" version.
    //
    // GetVersionEx (ANSI) aliases to this — the first five DWORDs
    // are layout-identical; only szCSDVersion differs (ANSI vs
    // wide), which we don't touch.
    0xC7, 0x41, 0x04, 0x0A, 0x00, 0x00, 0x00, // 0x518 mov dword [rcx+0x04], 10    (major)
    0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, // 0x51F mov dword [rcx+0x08], 0     (minor)
    0xC7, 0x41, 0x0C, 0x61, 0x4A, 0x00, 0x00, // 0x526 mov dword [rcx+0x0C], 19041 (build)
    0xC7, 0x41, 0x10, 0x02, 0x00, 0x00, 0x00, // 0x52D mov dword [rcx+0x10], 2     (NT platform)
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x534 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x539 ret

    // === Batch 31: ANSI-byte string helpers ====================
    // Symmetric to batch 29 but for single-byte LPCSTR inputs.

    // --- lstrlenA (offset 0x53A, 14 bytes) --------------------
    // Win32: int lstrlenA(LPCSTR rcx). Byte-strlen.
    0x31, 0xC0, // 0x53A xor eax, eax
    // .loop:
    0x80, 0x3C, 0x01, 0x00, // 0x53C cmp byte [rcx+rax*1], 0
    0x74, 0x05,             // 0x540 je .done (+5)
    0x48, 0xFF, 0xC0,       // 0x542 inc rax
    0xEB, 0xF5,             // 0x545 jmp .loop (-11)
    // .done:
    0xC3, // 0x547 ret

    // --- lstrcmpA (offset 0x548, 37 bytes) --------------------
    // Win32: int lstrcmpA(LPCSTR rcx, LPCSTR rdx). Byte-strcmp
    // (ordinal — no locale fold). 0 / negative / positive per
    // classic strcmp contract.
    0x31, 0xC0, // 0x548 xor eax, eax
    // .loop:
    0x44, 0x0F, 0xB6, 0x04, 0x01, // 0x54A movzx r8d, byte [rcx+rax]
    0x44, 0x0F, 0xB6, 0x0C, 0x02, // 0x54F movzx r9d, byte [rdx+rax]
    0x45, 0x39, 0xC8,             // 0x554 cmp r8d, r9d
    0x75, 0x0D,                   // 0x557 jne .diff (+0x0D)
    0x45, 0x85, 0xC0,             // 0x559 test r8d, r8d
    0x74, 0x05,                   // 0x55C je .equal (+5)
    0x48, 0xFF, 0xC0,             // 0x55E inc rax
    0xEB, 0xE7,                   // 0x561 jmp .loop (-0x19)
    // .equal:
    0x31, 0xC0, // 0x563 xor eax, eax
    0xC3,       // 0x565 ret
    // .diff:
    0x44, 0x89, 0xC0, // 0x566 mov eax, r8d
    0x44, 0x29, 0xC8, // 0x569 sub eax, r9d
    0xC3,             // 0x56C ret

    // --- lstrcpyA (offset 0x56D, 26 bytes) --------------------
    // Win32: LPSTR lstrcpyA(LPSTR rcx, LPCSTR rdx). Byte-strcpy,
    // returns dst (rcx).
    0x48, 0x89, 0xC8, // 0x56D mov rax, rcx   ; save dst for return
    0x45, 0x31, 0xC0, // 0x570 xor r8d, r8d   ; i = 0
    // .loop:
    0x46, 0x0F, 0xB6, 0x0C, 0x02, // 0x573 movzx r9d, byte [rdx+r8]
    0x46, 0x88, 0x0C, 0x01,       // 0x578 mov byte [rcx+r8], r9b
    0x45, 0x85, 0xC9,             // 0x57C test r9d, r9d
    0x74, 0x05,                   // 0x57F je .done (+5)
    0x49, 0xFF, 0xC0,             // 0x581 inc r8
    0xEB, 0xED,                   // 0x584 jmp .loop (-0x13)
    // .done:
    0xC3, // 0x586 ret
};

static_assert(sizeof(kStubsBytes) <= 4096, "Win32 stubs page fits in one 4 KiB page");
static_assert(sizeof(kStubsBytes) == 0x587, "stub layout drifted; update kOff* constants");
// Keep the hand-assembled __p___argc / __p___argv addresses in
// sync with the public proc-env layout constants. The stub
// bytes encode 0x65000000 and 0x65000008 directly; if stubs.h
// moves the page VA or the argc / argv-ptr offsets, these
// bytes must follow.
static_assert(kProcEnvVa == 0x65000000ULL, "proc-env page VA no longer matches __p___argc stub bytes");
static_assert(kProcEnvArgcOff == 0x00, "argc offset no longer matches __p___argc stub bytes");
static_assert(kProcEnvArgvPtrOff == 0x08, "argv-ptr offset no longer matches __p___argv stub bytes");
static_assert(kProcEnvCommodeOff == 0x200, "commode offset no longer matches __p__commode stub bytes");

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

    // Batch 6 — UCRT CRT-startup shims.
    //
    // Most of these are "return success, do nothing" stubs that
    // let a CRT-driven startup sequence advance far enough for
    // main() to get called. They live under api-set DLL names
    // (api-ms-win-crt-*-l1-1-0.dll) on modern Windows — each
    // apiset forwards to ucrtbase.dll. The real runtime is
    // distributed across both; programs reference whichever
    // DLL name the linker chose.
    //
    // We register each stub under ALL plausible DLL names the
    // import resolver might see (apiset, ucrtbase, and the
    // legacy msvcrt.dll where applicable). The lookup scan is
    // linear and small — duplicate entries are cheap.

    // Return-0 family (spread across several apisets).
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_onexit_table", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_onexit_function", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_crt_atexit", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_configure_narrow_argv", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initialize_narrow_environment", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_initial_narrow_environment", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_seh_filter_exe", kOffReturnZero},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_register_thread_local_exe_atexit_callback", kOffReturnZero},
    {"api-ms-win-crt-locale-l1-1-0.dll", "_configthreadlocale", kOffReturnZero},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_set_new_mode", kOffReturnZero},
    {"api-ms-win-crt-stdio-l1-1-0.dll", "_set_fmode", kOffReturnZero},

    // Return-void family.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_initterm", kOffCritSecNop},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_cexit", kOffCritSecNop},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_c_exit", kOffCritSecNop},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_set_app_type", kOffCritSecNop},
    {"api-ms-win-crt-math-l1-1-0.dll", "__setusermatherr", kOffCritSecNop},

    // Exit family — `exit` and `_exit` alias ExitProcess
    // (same rcx=code ABI, same SYS_EXIT semantic).
    {"api-ms-win-crt-runtime-l1-1-0.dll", "exit", kOffExitProcess},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_exit", kOffExitProcess},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "terminate", kOffTerminate},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_invalid_parameter_noinfo_noreturn", kOffInvalidParam},
    // Same functions surface directly under ucrtbase too.
    {"ucrtbase.dll", "exit", kOffExitProcess},
    {"ucrtbase.dll", "_exit", kOffExitProcess},
    {"ucrtbase.dll", "terminate", kOffTerminate},

    // Batch 7 — CRT string intrinsics. Pure functions; no
    // kernel state, no ABI surprises. Register under the
    // apiset + ucrtbase + msvcrt names to cover all three
    // common link paths.
    {"api-ms-win-crt-string-l1-1-0.dll", "strcmp", kOffStrcmp},
    {"api-ms-win-crt-string-l1-1-0.dll", "strlen", kOffStrlen},
    {"api-ms-win-crt-string-l1-1-0.dll", "wcslen", kOffWcslen},
    {"api-ms-win-crt-string-l1-1-0.dll", "strchr", kOffStrchr},
    {"api-ms-win-crt-string-l1-1-0.dll", "strcpy", kOffStrcpy},
    {"ucrtbase.dll", "strcmp", kOffStrcmp},
    {"ucrtbase.dll", "strlen", kOffStrlen},
    {"ucrtbase.dll", "wcslen", kOffWcslen},
    {"ucrtbase.dll", "strchr", kOffStrchr},
    {"ucrtbase.dll", "strcpy", kOffStrcpy},
    {"msvcrt.dll", "strcmp", kOffStrcmp},
    {"msvcrt.dll", "strlen", kOffStrlen},
    {"msvcrt.dll", "wcslen", kOffWcslen},
    {"msvcrt.dll", "strchr", kOffStrchr},
    {"msvcrt.dll", "strcpy", kOffStrcpy},

    // Batch 8 — kernel32 "safe ignore" shims. These functions
    // do real work on Windows but can safely return a sentinel
    // value in v0 without causing the caller to immediately
    // crash. Most of them surface in the windows-kill.exe
    // import list; this batch narrows that gap.
    //
    // Return-zero family (returns NULL / FALSE / 0):
    //   GetModuleHandle* — NULL means "module not found"
    //     (or, for NULL arg, a default that's fine to be 0).
    //   GetProcAddress   — NULL means "symbol not exported";
    //     caller falls back.
    //   IsDebuggerPresent          — FALSE = not debugged.
    //   IsProcessorFeaturePresent  — FALSE = feature absent;
    //     caller uses non-SIMD fallback path.
    //   SetUnhandledExceptionFilter — NULL = no previous filter.
    //   UnhandledExceptionFilter    — 0 = EXCEPTION_CONTINUE_SEARCH.
    // GetModuleHandleA / GetModuleHandleW / GetProcAddress moved to
    // batch 25 below — GetModuleHandleW(NULL) now returns the EXE
    // image base instead of always-zero. The Win32StubsLookup walk
    // returns the first match, so the real entries take precedence
    // by appearing earlier in the table.
    {"kernel32.dll", "IsDebuggerPresent", kOffReturnZero},
    {"kernel32.dll", "IsDebuggerPresent", kOffReturnZero},
    {"kernel32.dll", "IsProcessorFeaturePresent", kOffReturnZero},
    {"kernel32.dll", "SetUnhandledExceptionFilter", kOffReturnZero},
    {"kernel32.dll", "UnhandledExceptionFilter", kOffReturnZero},

    // Return-one family (returns TRUE / 1 = success):
    //   SetConsoleCtrlHandler — pretend we registered.
    {"kernel32.dll", "SetConsoleCtrlHandler", kOffReturnOne},

    // Batch 24 — file I/O. Real handle table on Process,
    // backed by SYS_FILE_OPEN / SYS_FILE_READ / SYS_FILE_CLOSE
    // / SYS_FILE_SEEK. CloseHandle is the file-close path —
    // also harmlessly handles non-file handles (the kernel
    // SYS_FILE_CLOSE returns 0 for an unrecognised handle).
    {"kernel32.dll", "CreateFileW", kOffCreateFileW},
    {"kernel32.dll", "ReadFile", kOffReadFile},
    {"kernel32.dll", "CloseHandle", kOffCloseHandle},
    {"kernel32.dll", "SetFilePointerEx", kOffSetFilePtrEx},

    // Batch 25 — file stat + module lookup. GetFileSizeEx is
    // backed by SYS_FILE_FSTAT (non-destructive size).
    // GetModuleHandleW(NULL) returns the EXE image base from
    // the proc-env page; any non-NULL name returns 0. Library
    // loading is unsupported in v0 — LoadLibraryW/A return 0
    // (failed) and GetProcAddress returns 0 (not found). Apps
    // that GetProcAddress for an optional API gracefully fall
    // back to their non-dynamic path.
    {"kernel32.dll", "GetFileSizeEx", kOffGetFileSizeEx},
    {"kernel32.dll", "GetFileSize", kOffGetFileSizeEx}, // close enough for callers w/ small files
    {"kernel32.dll", "GetModuleHandleW", kOffGetModuleHandleW},
    {"kernel32.dll", "GetModuleHandleA", kOffGetModuleHandleW}, // ASCII path also accepts NULL
    {"kernel32.dll", "GetModuleHandleExW", kOffReturnZero},
    {"kernel32.dll", "GetModuleHandleExA", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryW", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryA", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryExW", kOffReturnZero},
    {"kernel32.dll", "LoadLibraryExA", kOffReturnZero},
    {"kernel32.dll", "FreeLibrary", kOffReturnOne}, // pretend success
    {"kernel32.dll", "GetProcAddress", kOffReturnZero},

    // Batch 26 — Win32 mutex (real waitqueue-backed semantics).
    // CreateMutexW allocates a per-process slot returning a 0x200+
    // pseudo-handle. WaitForSingleObject dispatches by handle range
    // — mutex handles route to SYS_MUTEX_WAIT, anything else
    // pseudo-signals as before. ReleaseMutex routes to
    // SYS_MUTEX_RELEASE. All three are recursive (Win32 contract).
    // CloseHandle (batch 24) handles mutex slots too via range
    // dispatch in SYS_FILE_CLOSE.
    {"kernel32.dll", "CreateMutexW", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexA", kOffCreateMutexW},
    {"kernel32.dll", "CreateMutexExW", kOffCreateMutexW}, // ignores extra Ex args
    {"kernel32.dll", "WaitForSingleObject", kOffWaitForObj},
    {"kernel32.dll", "WaitForSingleObjectEx", kOffWaitForObj},
    {"kernel32.dll", "ReleaseMutex", kOffReleaseMutex},

    // Batch 27 — console APIs. WriteConsoleW is the major
    // Unicode-output entry point; the stub UTF-16-strips to
    // ASCII on a stack buffer and routes through SYS_WRITE
    // (same path as WriteFile-to-stdout). GetConsoleMode /
    // GetConsoleCP / GetConsoleOutputCP hand back plausible
    // constants (VT processing enabled, UTF-8 code page). The
    // Set* counterparts are no-ops that return TRUE.
    {"kernel32.dll", "WriteConsoleW", kOffWriteConsoleW},
    {"kernel32.dll", "GetConsoleMode", kOffGetConsoleMode},
    {"kernel32.dll", "SetConsoleMode", kOffReturnOne},
    {"kernel32.dll", "GetConsoleCP", kOffGetConsoleCP},
    {"kernel32.dll", "GetConsoleOutputCP", kOffGetConsoleCP},
    {"kernel32.dll", "SetConsoleCP", kOffReturnOne},
    {"kernel32.dll", "SetConsoleOutputCP", kOffReturnOne},
    // OutputDebugString* is a debugger-notification call. Real
    // Windows silently drops when no debugger is attached. We
    // do the same — kOffReturnZero returns 0 as a `void` sink
    // (both signatures: LPCWSTR / LPCSTR, no return).
    {"kernel32.dll", "OutputDebugStringW", kOffReturnZero},
    {"kernel32.dll", "OutputDebugStringA", kOffReturnZero},

    // Batch 28 — virtual memory. VirtualAlloc is the single
    // most-requested Win32 memory primitive for non-trivial
    // PEs (JIT, CoreCLR, TLS setup, custom allocators). Bump-
    // only arena at 0x40000000..+512KiB per process.
    // VirtualFree is a no-op (range-check only). VirtualProtect
    // no-ops and echoes PAGE_READWRITE back — W^X forbids the
    // RWX pages a JIT would actually want, so a second slice
    // adds a separate "JIT image" mechanism when a real JIT
    // workload needs it.
    {"kernel32.dll", "VirtualAlloc", kOffVirtualAlloc},
    {"kernel32.dll", "VirtualAllocEx", kOffVirtualAlloc}, // ignores the extra HANDLE arg
    {"kernel32.dll", "VirtualFree", kOffVirtualFree},
    {"kernel32.dll", "VirtualFreeEx", kOffVirtualFree},
    {"kernel32.dll", "VirtualProtect", kOffVirtualProtect},
    {"kernel32.dll", "VirtualProtectEx", kOffVirtualProtect},
    {"kernel32.dll", "VirtualQuery", kOffReturnZero}, // v0 query returns 0 = failed
    {"kernel32.dll", "VirtualQueryEx", kOffReturnZero},

    // Batch 29 — wide-string helpers. Pure-compute primitives
    // heavily used by multilingual PEs and MSVC CRT. lstrcmpW
    // is ordinal compare (no locale fold — lstrcmpiW would
    // case-fold, not stubbed). lstrlen has a hard cap of
    // effectively "until NUL" — a wild unterminated string
    // scans forever, matching the documented Win32 behaviour.
    {"kernel32.dll", "lstrlenW", kOffLstrlenW},
    {"kernel32.dll", "lstrcmpW", kOffLstrcmpW},
    {"kernel32.dll", "lstrcpyW", kOffLstrcpyW},

    // Batch 30 — system-info probes. IsWow64Process returns FALSE
    // (native x64 process, no 32-bit emulation). GetVersionEx*
    // reports Windows 10 build 19041 (2004 / 20H1) — a modern-
    // enough version to pass most feature-gate checks without
    // triggering "too new, not yet supported" fallbacks apps
    // have for very recent builds.
    {"kernel32.dll", "IsWow64Process", kOffIsWow64},
    {"kernel32.dll", "IsWow64Process2", kOffIsWow64}, // fills similar PBOOL
    {"kernel32.dll", "GetVersionExW", kOffGetVersionExW},
    {"kernel32.dll", "GetVersionExA", kOffGetVersionExW}, // ASCII CSD left untouched

    // Batch 31 — ANSI-byte string helpers. Symmetric to batch 29
    // but for LPCSTR. Pure compute, no syscalls.
    {"kernel32.dll", "lstrlenA", kOffLstrlenA},
    {"kernel32.dll", "lstrcmpA", kOffLstrcmpA},
    {"kernel32.dll", "lstrcpyA", kOffLstrcpyA},

    // Batch 9 — Win32 process heap, backed by the per-process
    // 16-page region at 0x50000000 and SYS_HEAP_ALLOC /
    // SYS_HEAP_FREE. See kernel/subsystems/win32/heap.cpp.
    //
    // kernel32 heap exports: take a HANDLE arg that v0
    // ignores — GetProcessHeap returns the same cookie
    // HeapAlloc ignores, so it's internally consistent.
    {"kernel32.dll", "GetProcessHeap", kOffGetProcessHeap},
    {"kernel32.dll", "HeapAlloc", kOffHeapAlloc},
    {"kernel32.dll", "HeapFree", kOffHeapFree},
    // HeapCreate: Win32 normally creates a private heap.
    // v0 collapses to the shared process heap — same handle
    // as GetProcessHeap. HeapDestroy is a no-op returning
    // TRUE (we never actually free the heap pages).
    {"kernel32.dll", "HeapCreate", kOffGetProcessHeap},
    {"kernel32.dll", "HeapDestroy", kOffReturnOne},
    // HeapReAlloc / HeapSize: backed by SYS_HEAP_REALLOC +
    // SYS_HEAP_SIZE as of batch 14 — block header carries the
    // rounded-up size so we can translate both operations
    // without extra per-block bookkeeping.
    {"kernel32.dll", "HeapReAlloc", kOffHeapRealloc},
    {"kernel32.dll", "HeapSize", kOffHeapSize},

    // UCRT / msvcrt / apiset heap names — all forward to the
    // same syscall-backed stubs. realloc returns NULL; malloc
    // and free are straight-through.
    {"api-ms-win-crt-heap-l1-1-0.dll", "malloc", kOffMalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "free", kOffFree},
    {"api-ms-win-crt-heap-l1-1-0.dll", "calloc", kOffCalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "realloc", kOffRealloc},
    // _aligned_malloc / _aligned_free: v0 ignores alignment.
    // The allocator already returns 8-byte aligned pointers,
    // which covers most callers (16-byte alignment failure
    // will surface later if anything needs AVX/SSE locals
    // stored in a heap allocation).
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_malloc", kOffMalloc},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_aligned_free", kOffFree},

    {"ucrtbase.dll", "malloc", kOffMalloc},
    {"ucrtbase.dll", "free", kOffFree},
    {"ucrtbase.dll", "calloc", kOffCalloc},
    {"ucrtbase.dll", "realloc", kOffRealloc},
    {"ucrtbase.dll", "_aligned_malloc", kOffMalloc},
    {"ucrtbase.dll", "_aligned_free", kOffFree},

    {"msvcrt.dll", "malloc", kOffMalloc},
    {"msvcrt.dll", "free", kOffFree},
    {"msvcrt.dll", "calloc", kOffCalloc},
    {"msvcrt.dll", "realloc", kOffRealloc},

    // Batch 10 — advapi32 privilege/token + kernel32 event /
    // wait / system-time / process shims. Mostly "return
    // success and do nothing" since the kernel has no real
    // security model, no multi-threading in user land, and
    // no wall-clock yet. The exceptions are the two advapi32
    // token stubs that fill an out-param (see stub comments)
    // and the three kernel32 functions with real out-param
    // contracts (InitializeSListHead, GetSystemTimeAsFileTime,
    // GetExitCodeThread).

    // advapi32 — privilege/token dance. All BOOL-returning.
    {"advapi32.dll", "OpenProcessToken", kOffOpenProcessToken},
    {"advapi32.dll", "LookupPrivilegeValueW", kOffLookupPrivVal},
    // ASCII variant shares the same stub — v0 ignores the
    // name string entirely.
    {"advapi32.dll", "LookupPrivilegeValueA", kOffLookupPrivVal},
    {"advapi32.dll", "AdjustTokenPrivileges", kOffReturnOne},
    // Uppercase aliases — llvm-dlltool writes the DLL name
    // using the .def file's LIBRARY line verbatim, but some
    // linkers normalise to uppercase. Register both so
    // capitalisation in the PE's import table (either way)
    // hits the stub.
    {"ADVAPI32.dll", "OpenProcessToken", kOffOpenProcessToken},
    {"ADVAPI32.dll", "LookupPrivilegeValueW", kOffLookupPrivVal},
    {"ADVAPI32.dll", "LookupPrivilegeValueA", kOffLookupPrivVal},
    {"ADVAPI32.dll", "AdjustTokenPrivileges", kOffReturnOne},

    // kernel32 — event objects (v0: no real signalling, every
    // event is "always signaled"; CreateEventW returns a fake
    // non-null handle; SetEvent/ResetEvent return TRUE).
    {"kernel32.dll", "CreateEventW", kOffReturnOne},
    {"kernel32.dll", "CreateEventA", kOffReturnOne},
    {"kernel32.dll", "SetEvent", kOffReturnOne},
    {"kernel32.dll", "ResetEvent", kOffReturnOne},

    // kernel32 — wait (v0: immediate return with
    // WaitForSingleObject moved to batch 26 below — now mutex-aware.
    // The stub still pseudo-signals (returns 0 = WAIT_OBJECT_0) for
    // non-mutex handles, preserving the original batch-10 contract
    // for events / thread handles that v0 doesn't track.

    // kernel32 — interlocked SList (zero-init an SList head).
    {"kernel32.dll", "InitializeSListHead", kOffInitSListHead},

    // kernel32 — system time. Reads the CMOS RTC via
    // SYS_GETTIME_FT and writes the FILETIME into *rcx. The
    // old kOffGetSysTimeFT stub at 0x1DE (writes 0) remains
    // in the page as dead bytes — not worth restructuring the
    // layout to reclaim 8 bytes.
    {"kernel32.dll", "GetSystemTimeAsFileTime", kOffGetSysTimeFTReal},

    // kernel32 — process handles. OpenProcess returns the
    // PID as the handle (non-null iff PID != 0). Real
    // implementations would have a handle table; the handle
    // value is opaque to callers so this "identity"
    // mapping is fine.
    {"kernel32.dll", "OpenProcess", kOffOpenProcess},
    {"kernel32.dll", "GetExitCodeThread", kOffGetExitCodeThread},
    {"kernel32.dll", "GenerateConsoleCtrlEvent", kOffReturnOne},

    // Batch 11 — performance counters, tick count, and the
    // Rtl*/Toolhelp32/thread-management clusters. The perf
    // counter family is REAL — backed by SYS_PERF_COUNTER
    // and the kernel 100 Hz tick. The rest are safe no-ops
    // that let callers proceed without crashing:
    //   * Rtl* unwind family returns 0 — "no function entry
    //     found" / "no frames captured". Code that uses
    //     these for crash-report formatting gets an empty
    //     report but doesn't fault.
    //   * Toolhelp32 snapshot returns 1 (non-null handle)
    //     but Process32First returns FALSE — program sees
    //     an empty process list.
    //   * CreateRemoteThread returns 0 (NULL) — the target
    //     program handles failure gracefully per the Win32
    //     contract (GetLastError returns the last set
    //     error; our stub stack doesn't populate that yet).
    // QueryPerformance{Counter,Frequency} upgraded (batch 21) to
    // HPET-backed nanosecond resolution. The old stubs at 0x1F6
    // / 0x206 stay in the page as dead bytes.
    {"kernel32.dll", "QueryPerformanceCounter", kOffQpcNs},
    {"kernel32.dll", "QueryPerformanceFrequency", kOffQpfNs},
    {"kernel32.dll", "GetTickCount", kOffGetTickCount},
    {"kernel32.dll", "GetTickCount64", kOffGetTickCount},

    // Batch 22 — Sleep + SwitchToThread (timer + voluntary yield).
    // Sleep routes to SYS_SLEEP_MS; SwitchToThread routes to
    // SYS_YIELD. SleepEx ignores its bAlertable arg and aliases
    // to Sleep — no APC delivery in v0, so the alertable form
    // would never actually fire user-mode APCs anyway.
    {"kernel32.dll", "Sleep", kOffSleep},
    {"kernel32.dll", "SleepEx", kOffSleep},
    {"kernel32.dll", "SwitchToThread", kOffSwitchToThread},

    // Batch 23 — command line + environment (proc-env page reads).
    // GetCommandLineW / GetCommandLineA hand back pointers into
    // the proc-env page populated by Win32ProcEnvPopulate at PE
    // load. GetEnvironmentVariableW returns 0 (var-not-found)
    // for every query in v0; that's a documented success-case
    // outcome of the Win32 contract and cleanly degrades for
    // any caller that has a default. GetEnvironmentStringsW
    // returns a pointer to an empty block (two NUL bytes).
    // FreeEnvironmentStringsW is a no-op returning TRUE.
    {"kernel32.dll", "GetCommandLineW", kOffGetCmdLineW},
    {"kernel32.dll", "GetCommandLineA", kOffGetCmdLineA},
    {"kernel32.dll", "GetEnvironmentVariableW", kOffReturnZero},
    {"kernel32.dll", "GetEnvironmentVariableA", kOffReturnZero},
    {"kernel32.dll", "GetEnvironmentStringsW", kOffGetEnvBlockW},
    {"kernel32.dll", "GetEnvironmentStrings", kOffGetEnvBlockW},
    {"kernel32.dll", "FreeEnvironmentStringsW", kOffReturnOne},
    {"kernel32.dll", "FreeEnvironmentStringsA", kOffReturnOne},
    {"kernel32.dll", "SetEnvironmentVariableW", kOffReturnOne}, // pretend success
    {"kernel32.dll", "SetEnvironmentVariableA", kOffReturnOne},

    // Rtl* unwind (v0: empty / not-found sentinels)
    {"kernel32.dll", "RtlCaptureStackBackTrace", kOffReturnZero},
    {"kernel32.dll", "RtlCaptureContext", kOffReturnZero},
    {"kernel32.dll", "RtlLookupFunctionEntry", kOffReturnZero},
    {"kernel32.dll", "RtlVirtualUnwind", kOffReturnZero},

    // Toolhelp32 + thread management (empty snapshot / no
    // ops). Real implementation requires the kernel to
    // expose the process table to ring 3 — deferred.
    {"kernel32.dll", "CreateToolhelp32Snapshot", kOffReturnOne},
    {"kernel32.dll", "Process32First", kOffReturnZero},
    {"kernel32.dll", "Process32FirstW", kOffReturnZero},
    {"kernel32.dll", "Process32Next", kOffReturnZero},
    {"kernel32.dll", "Process32NextW", kOffReturnZero},
    {"kernel32.dll", "CreateRemoteThread", kOffReturnZero},
    {"kernel32.dll", "ResumeThread", kOffReturnZero},
    {"kernel32.dll", "GetExitCodeProcess", kOffGetExitCodeThread},

    // Batch 12 — dbghelp + vcruntime SEH + UCRT convert.
    // All aliases to existing stubs; no new bytecode.
    //
    // dbghelp: symbol-table code paths. Succeed-but-find-nothing
    // is the safe stub semantic for crash loggers that call
    // SymFromAddr — they'll print "address=0x???" instead of
    // "file:line", but never fault.
    {"dbghelp.dll", "SymInitialize", kOffReturnOne},
    {"dbghelp.dll", "SymCleanup", kOffReturnOne},
    {"dbghelp.dll", "SymFromAddr", kOffReturnZero},

    // vcruntime SEH / C++ ABI — any program that actually
    // throws or dispatches a pure-virtual call will hit these.
    // We route them to SYS_EXIT(3) so a crash is visible in
    // the log (rc=0x3) rather than a silent #PF. Non-terminal
    // ones return 0.
    {"vcruntime140.dll", "__CxxFrameHandler3", kOffTerminate},
    {"vcruntime140.dll", "__C_specific_handler", kOffTerminate},
    {"vcruntime140.dll", "_CxxThrowException", kOffTerminate},
    {"vcruntime140.dll", "_purecall", kOffTerminate},
    {"vcruntime140.dll", "__std_terminate", kOffTerminate},
    {"vcruntime140.dll", "__std_exception_copy", kOffReturnZero},
    {"vcruntime140.dll", "__std_exception_destroy", kOffReturnZero},
    // Same shape as InitCritSec: zero-init 40 bytes at [rcx].
    {"vcruntime140.dll", "__vcrt_InitializeCriticalSectionEx", kOffInitCritSec},

    // UCRT convert — return 0 for every parse. Callers that
    // check errno get the wrong answer (we don't wire errno)
    // but won't crash.
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtoul", kOffReturnZero},
    {"api-ms-win-crt-convert-l1-1-0.dll", "strtol", kOffReturnZero},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atoi", kOffReturnZero},
    {"api-ms-win-crt-convert-l1-1-0.dll", "atol", kOffReturnZero},
    {"ucrtbase.dll", "strtoul", kOffReturnZero},
    {"ucrtbase.dll", "strtol", kOffReturnZero},
    {"ucrtbase.dll", "atoi", kOffReturnZero},
    {"ucrtbase.dll", "atol", kOffReturnZero},
    {"msvcrt.dll", "strtoul", kOffReturnZero},
    {"msvcrt.dll", "strtol", kOffReturnZero},
    {"msvcrt.dll", "atoi", kOffReturnZero},
    {"msvcrt.dll", "atol", kOffReturnZero},

    // Batch 13a — MSVCP140 throw helpers + small-return
    // helpers. All aliases. The `?_X*_error` + `?_Xbad_alloc`
    // family are unconditionally-throwing functions; under
    // Windows a caller wraps them in try/catch. We don't have
    // SEH, so reaching any of these is a crash by definition —
    // route to SYS_EXIT(3) so the serial log shows a
    // recognisable rc=3 instead of a #PF at some arbitrary
    // site.
    //
    // The `?_Winerror_*` + `?_Syserror_*` functions map Win32
    // error codes to human strings or category values; callers
    // format the result into log output. Returning 0 (or the
    // null string) is plausible "no translation available".
    //
    // `?uncaught_exception@std@@YA_NXZ` is std::uncaught_exception()
    // which returns bool — safe answer is false (no exception
    // currently in flight), i.e. kOffReturnZero.
    //
    // Not yet covered: the cout / basic_ostream cluster.
    // windows-kill.exe's next UNRESOLVED after this batch
    // lands will be in that group.
    {"MSVCP140.dll", "?_Xbad_alloc@std@@YAXXZ", kOffTerminate},
    {"MSVCP140.dll", "?_Xlength_error@std@@YAXPEBD@Z", kOffTerminate},
    {"MSVCP140.dll", "?_Xout_of_range@std@@YAXPEBD@Z", kOffTerminate},
    {"MSVCP140.dll", "?_Syserror_map@std@@YAPEBDH@Z", kOffReturnZero},
    {"MSVCP140.dll", "?_Winerror_map@std@@YAHH@Z", kOffReturnZero},
    {"MSVCP140.dll", "?_Winerror_message@std@@YAKKPEADK@Z", kOffReturnZero},
    {"MSVCP140.dll", "?uncaught_exception@std@@YA_NXZ", kOffReturnZero},

    // Batch 16 — MSVC CRT argc / argv accessors. These are the
    // first real-valued reads the CRT's __scrt_common_main_seh
    // makes during startup: `argc = *__p___argc()` and
    // `argv = *__p___argv()`. Prior to this batch they landed on
    // the catch-all NO-OP stub, returned 0, and the CRT faulted
    // when it dereferenced the zero. Now they return pointers
    // into the per-process proc-env page (kProcEnvVa), which the
    // PE loader populates with argc=1 and argv=[program_name, NULL].
    //
    // Registered under every DLL the resolver might see the
    // import under — api-ms-win-crt-runtime is the modern apiset,
    // ucrtbase is where the code lives, msvcrt is the legacy
    // name.
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argc", kOffPArgc},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv", kOffPArgv},
    {"ucrtbase.dll", "__p___argc", kOffPArgc},
    {"ucrtbase.dll", "__p___argv", kOffPArgv},
    {"msvcrt.dll", "__p___argc", kOffPArgc},
    {"msvcrt.dll", "__p___argv", kOffPArgv},

    // Batch 17 — UCRT stdio accessors. `__p__commode` returns
    // &_commode for callers that want the default-file-mode
    // flags (every UCRT-linked program reads it during startup
    // to pick text vs binary I/O). `_callnewh` is the C++
    // new-handler trampoline; v0 always "no handler set" so
    // the caller throws bad_alloc or returns failure — aliased
    // to the shared return-zero stub.
    {"api-ms-win-crt-stdio-l1-1-0.dll", "__p__commode", kOffPCommode},
    {"ucrtbase.dll", "__p__commode", kOffPCommode},
    {"msvcrt.dll", "__p__commode", kOffPCommode},
    {"api-ms-win-crt-heap-l1-1-0.dll", "_callnewh", kOffReturnZero},
    {"ucrtbase.dll", "_callnewh", kOffReturnZero},
    {"msvcrt.dll", "_callnewh", kOffReturnZero},

    // Batch 18 — MSVCP140 iostream methods. Direct-call paths
    // (via IAT) now do the right thing; virtual-dispatch paths
    // still walk the fake-object data-miss pad. The mangled
    // names are the MSVC x64 form (`?method@class@@Q..Z`).
    //
    // sputn → real SYS_WRITE; writes chars to serial and
    // returns the count. Same for the `MSVCP140` and MSVCP110
    // variants (older CRT link paths).
    {"MSVCP140.dll", "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z", kOffSputn},
    {"msvcp140.dll", "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z", kOffSputn},

    // sputc → "can't usefully write one char without spilling
    // to stack" in a hand-assembled stub. Fall through to the
    // return-zero family for now; a PE that relies on sputc
    // (rare — operator<< for char goes through put()) will see
    // "0 chars written" and can degrade. Revisit if it matters.
    {"MSVCP140.dll", "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z", kOffReturnZero},

    // put → returns *this (chainable). Doesn't actually emit
    // the char in v0 — the call still does its real work if
    // the caller reads a buffer pointer off the return value
    // (nobody does).
    {"MSVCP140.dll", "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z", kOffReturnThis},

    // flush → returns *this. No buffers to drain in v0.
    {"MSVCP140.dll", "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ", kOffReturnThis},

    // _Osfx (sentry epilog) → void, no-op.
    {"MSVCP140.dll", "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ", kOffCritSecNop},

    // setstate → void, no-op. (Silently drops the bits; any
    // code that inspects rdstate() later sees goodbit.)
    {"MSVCP140.dll", "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z", kOffCritSecNop},

    // widen → char identity.
    {"MSVCP140.dll", "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z", kOffWiden},

    // operator<<(int) / operator<<(unsigned long) /
    // operator<<(manipulator) — all three chain `*this` as
    // the return value. The int/ulong forms also conceptually
    // emit a formatted number; we don't format, but the
    // chaining return lets `cout << x << y << z` typecheck +
    // run past the first call site. Output is silent.
    {"MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z", kOffReturnThis},
    {"MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z", kOffReturnThis},
    {"MSVCP140.dll", "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z",
     kOffReturnThis},

    // Batch 19 — D3D / DXGI create-device family. Returning
    // HRESULT E_FAIL lets a caller's "no graphics" fallback
    // kick in. Covers the entry points DXVK / vkd3d-proton
    // intercept at the top of their translation chain:
    //
    //   D3D11CreateDevice / D3D11CreateDeviceAndSwapChain
    //     — MSVC d3d11.dll direct
    //   D3D12CreateDevice
    //     — MSVC d3d12.dll direct
    //   CreateDXGIFactory / CreateDXGIFactory1 / CreateDXGIFactory2
    //     — dxgi.dll, prerequisite for D3D device creation
    //   Direct3DCreate9 / Direct3DCreate9Ex
    //     — legacy d3d9.dll entry
    //
    // Direct3DCreate9 returns an IDirect3D9* — NULL on failure.
    // E_FAIL (0x80004005) in eax still lands as a non-NULL
    // pointer from the caller's perspective. For the pre-D3D10
    // path we use kOffReturnZero instead.
    {"d3d11.dll", "D3D11CreateDevice", kOffHresultEFail},
    {"d3d11.dll", "D3D11CreateDeviceAndSwapChain", kOffHresultEFail},
    {"D3D11.dll", "D3D11CreateDevice", kOffHresultEFail},
    {"D3D11.dll", "D3D11CreateDeviceAndSwapChain", kOffHresultEFail},
    {"d3d12.dll", "D3D12CreateDevice", kOffHresultEFail},
    {"d3d12.dll", "D3D12GetDebugInterface", kOffHresultEFail},
    {"d3d12.dll", "D3D12SerializeRootSignature", kOffHresultEFail},
    {"D3D12.dll", "D3D12CreateDevice", kOffHresultEFail},
    {"dxgi.dll", "CreateDXGIFactory", kOffHresultEFail},
    {"dxgi.dll", "CreateDXGIFactory1", kOffHresultEFail},
    {"dxgi.dll", "CreateDXGIFactory2", kOffHresultEFail},
    {"DXGI.dll", "CreateDXGIFactory", kOffHresultEFail},
    {"DXGI.dll", "CreateDXGIFactory1", kOffHresultEFail},
    {"DXGI.dll", "CreateDXGIFactory2", kOffHresultEFail},
    // d3d9 predates HRESULT-first API — it returns an interface
    // pointer, NULL = failure. Alias to the shared return-zero
    // stub rather than E_FAIL.
    {"d3d9.dll", "Direct3DCreate9", kOffReturnZero},
    {"d3d9.dll", "Direct3DCreate9Ex", kOffHresultEFail},
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

namespace
{
// Write a little-endian u64 at `dst`.
inline void StoreLeU64(u8* dst, u64 value)
{
    for (u64 b = 0; b < 8; ++b)
        dst[b] = static_cast<u8>((value >> (b * 8)) & 0xFFULL);
}
} // namespace

void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name, u64 module_base)
{
    if (proc_env_page == nullptr)
        return;

    // Caller is expected to have zeroed the frame, but be
    // defensive — populate only the specific fields we own,
    // leaving the rest at its incoming value.
    u8* const page = proc_env_page;

    // EXE module base — what GetModuleHandleW(NULL) hands back.
    // u64, little-endian. Read directly by the GetModuleHandleW
    // stub; no syscall on the hot path.
    StoreLeU64(page + kProcEnvModuleBaseOff, module_base);

    // argc = 1. Stored as a little-endian u32 at offset 0.
    page[kProcEnvArgcOff + 0] = 0x01;
    page[kProcEnvArgcOff + 1] = 0x00;
    page[kProcEnvArgcOff + 2] = 0x00;
    page[kProcEnvArgcOff + 3] = 0x00;

    // argv = &proc_env_page[kProcEnvArgvArrayOff] expressed in
    // user VA. Little-endian u64 at offset 0x08.
    const u64 argv_user_va = kProcEnvVa + kProcEnvArgvArrayOff;
    StoreLeU64(page + kProcEnvArgvPtrOff, argv_user_va);

    // Copy program_name into the string area (offset 0x40). Cap
    // at kProcEnvStringBudget - 1 to guarantee NUL termination.
    // A null / empty name becomes "a.exe" — Windows convention
    // for a program with no recorded argv[0].
    const char* name = (program_name != nullptr && program_name[0] != '\0') ? program_name : "a.exe";
    u64 copied = 0;
    while (copied + 1 < kProcEnvStringBudget)
    {
        const char c = name[copied];
        if (c == '\0')
            break;
        page[kProcEnvStringOff + copied] = static_cast<u8>(c);
        ++copied;
    }
    page[kProcEnvStringOff + copied] = 0;

    // argv[0] = &proc_env_page[kProcEnvStringOff] in user VA.
    const u64 argv0_user_va = kProcEnvVa + kProcEnvStringOff;
    StoreLeU64(page + kProcEnvArgvArrayOff, argv0_user_va);
    // argv[1] = NULL — already zero, but set explicitly so the
    // contract is visible in the page dump. Any callers that
    // walk argv until NULL (Win32 CRT + most Unix main())
    // stop here.
    StoreLeU64(page + kProcEnvArgvArrayOff + 8, 0);

    // Wide + ANSI command line. Both forms hold just the
    // program name; multi-arg cmdlines arrive when a real spawn
    // API plumbs argv through. Wide form is UTF-16LE — every
    // ASCII byte becomes the same byte followed by a 0x00
    // high-half byte; that covers every name we'd plausibly
    // emit for a v0 PE.
    {
        u8* const w = page + kProcEnvCmdlineWOff;
        u8* const a = page + kProcEnvCmdlineAOff;
        for (u64 i = 0; i < copied; ++i)
        {
            // Both buffers fit comfortably (256 / 128 wide chars,
            // 128 ascii); kProcEnvStringBudget already capped
            // `copied` at 255 so neither overflows.
            w[2 * i + 0] = static_cast<u8>(name[i]);
            w[2 * i + 1] = 0;
            a[i] = static_cast<u8>(name[i]);
        }
        // Wide NUL = 2 bytes of 0; ANSI NUL = 1 byte. Both
        // already-zeroed by caller, but write explicitly for
        // page-dump readability.
        w[2 * copied + 0] = 0;
        w[2 * copied + 1] = 0;
        a[copied] = 0;
    }

    // Empty wide environment block. An env block is a
    // contiguous run of UTF-16LE `KEY=VALUE\0` entries, plus a
    // final extra NUL terminating the list. The minimum legal
    // empty block is two zero bytes (`\0\0`). Already zeroed
    // — touch nothing.
    (void)kProcEnvEnvBlockWOff; // documented; no init needed for empty form

    // Data-miss "fake object". PE data imports whose names the
    // stub table doesn't know (e.g. std::cout) get an IAT slot
    // of `kProcEnvVa + kProcEnvDataMissOff`. Dereferenced as
    // `mov rax, [cout_iat]`, the caller reads the u64 stored
    // here — which we set to `kProcEnvVa + kProcEnvDataMissOff
    // + 8`, a pointer into the same page, 8 bytes further in,
    // where everything remains zero.
    //
    // The MSVC virtual-dispatch idiom (`mov rax, [this]; movslq
    // rcx, [rax+4]; mov rdi, [rcx+this+0x48]; test rdi, rdi;
    // jle ...`) then walks:
    //
    //   rax = [data_miss] = data_miss + 8     ; mapped
    //   rcx = [rax + 4]   = 0                 ; zero-read
    //   rdi = [this + 0x48] = 0               ; zero-read
    //   test rdi, rdi -> jle TAKEN
    //
    // The caller takes its "uninitialised / empty-stream" error
    // branch instead of faulting. Good enough for the first pass
    // past an unstubbed `std::cout` — it doesn't print, but it
    // stops crashing.
    const u64 fake_obj_va = kProcEnvVa + kProcEnvDataMissOff + 8;
    StoreLeU64(page + kProcEnvDataMissOff, fake_obj_va);
}

bool Win32StubsLookup(const char* dll, const char* func, u64* out_va)
{
    return Win32StubsLookupKind(dll, func, out_va, nullptr);
}

bool Win32StubsLookupCatchAll(u64* out_va)
{
    if (out_va == nullptr)
        return false;
    // Route through the miss-logger rather than the bare
    // "xor eax,eax; ret" stub. Behaviourally identical at the
    // call site (returns 0), but each call emits a
    // [win32-miss] line so the boot log identifies, in real
    // time, exactly which unstubbed import the PE just reached.
    *out_va = kWin32StubsVa + kOffMissLogger;
    return true;
}

bool Win32StubsLookupDataCatchAll(u64* out_va)
{
    if (out_va == nullptr)
        return false;
    // Point at a fixed offset inside the proc-env page, guaranteed
    // to be zero-filled (Win32ProcEnvPopulate touches only
    // 0x00..0x140). `mov rax, [data_iat]` then reads 0 instead of
    // the miss-logger's opcode bytes.
    *out_va = kProcEnvVa + kProcEnvDataMissOff;
    return true;
}

bool IsLikelyDataImport(const char* func)
{
    if (func == nullptr || func[0] != '?')
        return false;
    // MSVC mangling for a static/global data symbol is
    //   ?<name>@[<scope>@...]@@3<type-spec>[<type-modifiers>]
    // The `3` after `@@` is the storage-class letter for
    // "static data / global". Functions use storage classes
    // like Q (public non-static), A/B (access), or encode the
    // calling convention after `@@` — none of those is `3`.
    //
    // Walk to the first `@@` (end of qualified name) and inspect
    // the byte that follows. Cap the scan at a defensive 256
    // chars so a malformed name can't run off the end.
    for (u64 i = 1; i < 256; ++i)
    {
        const char c0 = func[i];
        if (c0 == '\0')
            return false;
        if (c0 != '@')
            continue;
        if (func[i + 1] != '@')
            continue;
        return func[i + 2] == '3';
    }
    return false;
}

bool Win32StubsLookupKind(const char* dll, const char* func, u64* out_va, bool* out_is_noop)
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
        if (out_is_noop != nullptr)
        {
            // "No-op / safe-ignore" stubs are the ones whose
            // entire implementation is a constant return. They
            // silently succeed but never actually do the thing
            // the Win32 contract asks for. Flag the exact
            // offsets so a reader of the boot log can tell
            // which imports land on real syscalls vs. shims.
            *out_is_noop = (e.offset == kOffReturnZero) || (e.offset == kOffReturnOne) ||
                           (e.offset == kOffCritSecNop) || (e.offset == kOffGetProcessHeap);
        }
        return true;
    }
    return false;
}

void Win32LogNtCoverage()
{
    // Re-walk the generated table at boot to print the scoreboard.
    // The compile-time `kBedrockNtSyscallsCovered` already has the
    // count, but doing one runtime sweep here also confirms the
    // table linked correctly into the kernel binary (catches a
    // future "header included but not referenced anywhere" rot).
    using namespace ::customos::subsystems::win32;
    u32 covered = 0;
    for (u32 i = 0; i < kBedrockNtSyscallCount; ++i)
    {
        if (kBedrockNtSyscalls[i].customos_sys != kSysNtNotImpl)
            ++covered;
    }
    arch::SerialWrite("[win32] ntdll bedrock coverage: ");
    arch::SerialWriteHex(covered);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kBedrockNtSyscallCount);
    arch::SerialWrite(" (generated table = ");
    arch::SerialWriteHex(kBedrockNtSyscallsCovered);
    arch::SerialWrite(")\n");
}

} // namespace customos::win32
