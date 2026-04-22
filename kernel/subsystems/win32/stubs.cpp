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
constexpr u32 kOffMissLogger = 0x246;         // batch 15 — 24 bytes
constexpr u32 kOffPArgc = 0x269;              // batch 16 —  6 bytes
constexpr u32 kOffPArgv = 0x26F;              // batch 16 —  6 bytes

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
    // Regs: we clobber rax, rcx, rdi — all caller-saved under
    // any Win64 callable we'd be substituted for, and the syscall
    // path preserves the rest. No save/restore needed.
    0x48, 0x8B, 0x04, 0x24,       // 0x246 mov rax, [rsp]               ; return addr (post-CALL)
    0x48, 0x63, 0x48, 0xFC,       // 0x24A movsxd rcx, dword [rax-4]    ; CALL rel32
    0x48, 0x01, 0xC1,             // 0x24E add rcx, rax                 ; rcx = thunk VA
    0x48, 0x63, 0x41, 0x02,       // 0x251 movsxd rax, dword [rcx+2]    ; thunk's JMP rel32
    0x48, 0x01, 0xC8,             // 0x255 add rax, rcx                 ; rax = thunk + rel32
    0x48, 0x83, 0xC0, 0x06,       // 0x258 add rax, 6                   ; rax = IAT slot VA
    0x48, 0x89, 0xC7,             // 0x25C mov rdi, rax                 ; arg0 = IAT slot VA
    0xB8, 0x10, 0x00, 0x00, 0x00, // 0x25F mov eax, 16 (SYS_WIN32_MISS_LOG)
    0xCD, 0x80,                   // 0x264 int 0x80
    0x31, 0xC0,                   // 0x266 xor eax, eax
    0xC3,                         // 0x268 ret

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

    // --- __p___argc (offset 0x269, 6 bytes) --------------------
    // Returns &argc (int*). argc lives at kProcEnvVa + 0x00.
    0xB8, 0x00, 0x00, 0x00, 0x65, // 0x269 mov eax, 0x65000000
    0xC3,                         // 0x26E ret

    // --- __p___argv (offset 0x26F, 6 bytes) --------------------
    // Returns &argv (char***). argv (a char**) lives at
    // kProcEnvVa + 0x08.
    0xB8, 0x08, 0x00, 0x00, 0x65, // 0x26F mov eax, 0x65000008
    0xC3,                         // 0x274 ret
};

static_assert(sizeof(kStubsBytes) <= 4096, "Win32 stubs page fits in one 4 KiB page");
static_assert(sizeof(kStubsBytes) == 0x275, "stub layout drifted; update kOff* constants");
// Keep the hand-assembled __p___argc / __p___argv addresses in
// sync with the public proc-env layout constants. The stub
// bytes encode 0x65000000 and 0x65000008 directly; if stubs.h
// moves the page VA or the argc / argv-ptr offsets, these
// bytes must follow.
static_assert(kProcEnvVa == 0x65000000ULL, "proc-env page VA no longer matches __p___argc stub bytes");
static_assert(kProcEnvArgcOff == 0x00, "argc offset no longer matches __p___argc stub bytes");
static_assert(kProcEnvArgvPtrOff == 0x08, "argv-ptr offset no longer matches __p___argv stub bytes");

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
    {"kernel32.dll", "GetModuleHandleA", kOffReturnZero},
    {"kernel32.dll", "GetModuleHandleW", kOffReturnZero},
    {"kernel32.dll", "GetProcAddress", kOffReturnZero},
    {"kernel32.dll", "IsDebuggerPresent", kOffReturnZero},
    {"kernel32.dll", "IsProcessorFeaturePresent", kOffReturnZero},
    {"kernel32.dll", "SetUnhandledExceptionFilter", kOffReturnZero},
    {"kernel32.dll", "UnhandledExceptionFilter", kOffReturnZero},

    // Return-one family (returns TRUE / 1 = success):
    //   CloseHandle          — pretend we closed it.
    //   SetConsoleCtrlHandler — pretend we registered.
    {"kernel32.dll", "CloseHandle", kOffReturnOne},
    {"kernel32.dll", "SetConsoleCtrlHandler", kOffReturnOne},

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
    // WAIT_OBJECT_0 = 0; single-threaded processes never
    // actually block, so "already signaled" is correct for
    // any handle they pass in).
    {"kernel32.dll", "WaitForSingleObject", kOffReturnZero},
    {"kernel32.dll", "WaitForSingleObjectEx", kOffReturnZero},

    // kernel32 — interlocked SList (zero-init an SList head).
    {"kernel32.dll", "InitializeSListHead", kOffInitSListHead},

    // kernel32 — system time placeholder. Real impl needs
    // a SYS_GETTIME backing syscall; deferred.
    {"kernel32.dll", "GetSystemTimeAsFileTime", kOffGetSysTimeFT},

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
    {"kernel32.dll", "QueryPerformanceCounter", kOffQueryPerfCounter},
    {"kernel32.dll", "QueryPerformanceFrequency", kOffQueryPerfFreq},
    {"kernel32.dll", "GetTickCount", kOffGetTickCount},
    {"kernel32.dll", "GetTickCount64", kOffGetTickCount},

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

void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name)
{
    if (proc_env_page == nullptr)
        return;

    // Caller is expected to have zeroed the frame, but be
    // defensive — populate only the specific fields we own,
    // leaving the rest at its incoming value.
    u8* const page = proc_env_page;

    // argc = 1. Stored as a little-endian u32 at offset 0.
    page[kProcEnvArgcOff + 0] = 0x01;
    page[kProcEnvArgcOff + 1] = 0x00;
    page[kProcEnvArgcOff + 2] = 0x00;
    page[kProcEnvArgcOff + 3] = 0x00;

    // argv = &proc_env_page[kProcEnvArgvArrayOff] expressed in
    // user VA. Little-endian u64 at offset 0x08.
    const u64 argv_user_va = kProcEnvVa + kProcEnvArgvArrayOff;
    for (u64 b = 0; b < 8; ++b)
        page[kProcEnvArgvPtrOff + b] = static_cast<u8>((argv_user_va >> (b * 8)) & 0xFFULL);

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
    for (u64 b = 0; b < 8; ++b)
        page[kProcEnvArgvArrayOff + b] = static_cast<u8>((argv0_user_va >> (b * 8)) & 0xFFULL);
    // argv[1] = NULL — already zero, but set explicitly so the
    // contract is visible in the page dump. Any callers that
    // walk argv until NULL (Win32 CRT + most Unix main())
    // stop here.
    for (u64 b = 0; b < 8; ++b)
        page[kProcEnvArgvArrayOff + 8 + b] = 0;
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

} // namespace customos::win32
