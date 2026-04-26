    // --- ExitProcess (offset 0x00, 9 bytes) --------------------
    // Windows x64 ABI: first arg (uExitCode) in RCX.
    // DuetOS native ABI: syscall # in RAX, first arg in RDI,
    // SYS_EXIT = 0.
    0x48, 0x89, 0xCF, // 0x00 mov rdi, rcx ; code
    0x31, 0xC0,       // 0x03 xor eax, eax ; rax = 0 = SYS_EXIT
    0xCD, 0x80,       // 0x05 int 0x80
    0x0F, 0x0B,       // 0x07 ud2 ; [[noreturn]]

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
    // BOOL WriteFile(HANDLE hFile, rcx
    // LPCVOID lpBuffer, rdx
    // DWORD nBytes, r8
    // LPDWORD lpWritten, r9
    // LPOVERLAPPED ovl); [rsp+0x28]
    // BOOL WriteConsoleA(HANDLE hConsoleOutput, rcx
    // LPCVOID lpBuffer, rdx
    // DWORD nChars, r8
    // LPDWORD lpCharsOut, r9
    // LPVOID lpReserved); [rsp+0x28]
    //
    // v0 semantic: ignore the handle + the trailing reserved/
    // overlapped arg, issue SYS_WRITE(1, buf, n), and store
    // the result count back into *lpWritten (clamped to 0 on
    // syscall error). Return BOOL = (rax >= 0).
    //
    // Win64 ABI fix: rdi + rsi are callee-saved. Original stub
    // wrote `mov edi, 1` / `mov rsi, rdx` directly — clobbered
    // the caller's values. Now saved + restored via push/pop.
    // `mov eax, 2` + `mov edi, 1` each compress to push-imm8 +
    // pop-reg (3 bytes instead of 5), freeing 4 bytes to cover
    // the 4-byte push/pop rdi+rsi cost. Stub stays at 44 bytes.
    //
    // int 0x80 preserves all registers except RAX, so r9 (the
    // lpWritten pointer) survives the syscall and we can use
    // it to store the output count without saving.
    0x56,             // 0x0C push rsi
    0x57,             // 0x0D push rdi
    0x48, 0x89, 0xD6, // 0x0E mov rsi, rdx ; buf
    0x4C, 0x89, 0xC2, // 0x11 mov rdx, r8 ; n
    0x6A, 0x01,       // 0x14 push 1
    0x5F,             // 0x16 pop rdi ; fd = 1 (stdout)
    0x6A, 0x02,       // 0x17 push 2
    0x58,             // 0x19 pop rax ; SYS_WRITE
    0xCD, 0x80,       // 0x1A int 0x80 ; rax = n or -1

    // If lpWritten (r9) != NULL, store max(rax, 0) as DWORD.
    0x4D, 0x85, 0xC9, // 0x1C test r9, r9
    0x74, 0x0B,       // 0x1F je +0x0B -> 0x2C
    0x31, 0xC9,       // 0x21 xor ecx, ecx
    0x48, 0x85, 0xC0, // 0x23 test rax, rax
    0x0F, 0x49, 0xC8, // 0x26 cmovns ecx, eax ; ecx = rax if rax>=0, else 0
    0x41, 0x89, 0x09, // 0x29 mov [r9], ecx

    // BOOL return: 1 if rax >= 0, else 0. Restore rdi + rsi
    // (Win64 callee-saved) before returning.
    0x48, 0x85, 0xC0, // 0x2C test rax, rax
    0x0F, 0x99, 0xC0, // 0x2F setns al
    0x0F, 0xB6, 0xC0, // 0x32 movzx eax, al
    0x5F,             // 0x35 pop rdi
    0x5E,             // 0x36 pop rsi
    0xC3,             // 0x37 ret

    // === process/thread lifecycle ====================

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
    0x48, 0x89, 0xD7, // 0x58 mov rdi, rdx ; code
    0x31, 0xC0,       // 0x5B xor eax, eax ; SYS_EXIT
    0xCD, 0x80,       // 0x5D int 0x80
    0x0F, 0x0B,       // 0x5F ud2 ; [[noreturn]]

    // === last-error slot =============================

    // --- GetLastError (offset 0x61, 8 bytes) -------------------
    // Win32: DWORD GetLastError(void). Returns
    // Process.win32_last_error via SYS_GETLASTERROR = 9.
    0xB8, 0x09, 0x00, 0x00, 0x00, // 0x61 mov eax, 9 (SYS_GETLASTERROR)
    0xCD, 0x80,                   // 0x66 int 0x80
    0xC3,                         // 0x68 ret

    // --- SetLastError (offset 0x69, 11 bytes) ------------------
    // Win32: void SetLastError(DWORD dwErrCode). Forwards
    // the code to SYS_SETLASTERROR = 10 via rdi. No return
    // value to massage — the Win32 prototype is void, so
    // whatever the syscall leaves in rax is fine.
    //
    // Win64 ABI fix: save/restore rdi. `push 10; pop rax`
    // (3 bytes) replaces `mov eax, 10` (5 bytes) to free the
    // 2 bytes needed for push rdi / pop rdi.
    0x57,             // 0x69 push rdi
    0x48, 0x89, 0xCF, // 0x6A mov rdi, rcx
    0x6A, 0x0A,       // 0x6D push 10
    0x58,             // 0x6F pop rax
    0xCD, 0x80,       // 0x70 int 0x80
    0x5F,             // 0x72 pop rdi
    0xC3,             // 0x73 ret

    // === critical sections (v0 no-ops) ===============

    // --- InitializeCriticalSection (offset 0x74, 18 bytes) -----
    // Aliased by InitializeCriticalSectionEx and
    // InitializeCriticalSectionAndSpinCount. Zero out the
    // 40-byte CRITICAL_SECTION at [rcx], return BOOL TRUE.
    //
    // v0 is single-task per process, so a critical section
    // with no recursion tracking, no owning-thread check, and
    // no semaphore is semantically correct — there's nothing
    // to serialize against. a follow-up will replace this
    // when a multi-threading model lands.
    //
    // Assumes DF=0 on entry (Win64 ABI contract). Uses rdi
    // (scratch in SysV, but CALLEE-SAVED in Win64 — push/pop
    // rdi around the rep stosb so the caller's rdi survives).
    // `mov ecx, 40` compresses to `push 40; pop rcx` to free
    // 2 bytes for the push/pop rdi pair; stub stays at 18
    // bytes.
    0x57,                         // 0x74 push rdi
    0x48, 0x89, 0xCF,             // 0x75 mov rdi, rcx
    0x6A, 0x28,                   // 0x78 push 40
    0x59,                         // 0x7A pop rcx
    0x31, 0xC0,                   // 0x7B xor eax, eax
    0xF3, 0xAA,                   // 0x7D rep stosb
    0x5F,                         // 0x7F pop rdi
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x80 mov eax, 1 (BOOL TRUE for Ex variants)
    0xC3,                         // 0x85 ret

    // --- CritSec nop (offset 0x86, 1 byte) ---------------------
    // Shared stub for EnterCriticalSection / LeaveCriticalSection
    // / DeleteCriticalSection. All three are `void(LPCS)`;
    // with no contention to handle they collapse to a single
    // return.
    0xC3, // 0x86 ret

    // === vcruntime140 memory intrinsics ==============
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
    0x49, 0x89, 0xC9, // 0x89 mov r9, rcx ; save dst for return
    0x48, 0x89, 0xCF, // 0x8C mov rdi, rcx ; dst
    0x48, 0x89, 0xD6, // 0x8F mov rsi, rdx ; src
    0x4C, 0x89, 0xC1, // 0x92 mov rcx, r8 ; n
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
    0x4C, 0x89, 0xC8, // 0xAE mov rax, r9 ; return dst
    0x5F,             // 0xB1 pop rdi
    0x5E,             // 0xB2 pop rsi
    0xC3,             // 0xB3 ret

    // --- memset (offset 0xB4, 19 bytes) ------------------------
    // Signature: void* memset(void* dst=rcx, int c=rdx, size_t n=r8).
    // Byte value is the low 8 bits of c (edx). Returns dst.
    // Saves nonvolatile rdi.
    0x57,             // 0xB4 push rdi
    0x49, 0x89, 0xC9, // 0xB5 mov r9, rcx ; save dst for return
    0x48, 0x89, 0xCF, // 0xB8 mov rdi, rcx ; dst
    0x89, 0xD0,       // 0xBB mov eax, edx ; al = c
    0x4C, 0x89, 0xC1, // 0xBD mov rcx, r8 ; n
    0xF3, 0xAA,       // 0xC0 rep stosb
    0x4C, 0x89, 0xC8, // 0xC2 mov rax, r9 ; return dst
    0x5F,             // 0xC5 pop rdi
    0xC3,             // 0xC6 ret

    // === UCRT CRT-startup shims ======================

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
    0x31, 0xC0,                   // 0xCF xor eax, eax ; SYS_EXIT
    0xCD, 0x80,                   // 0xD1 int 0x80
    0x0F, 0x0B,                   // 0xD3 ud2

    // --- _invalid_parameter_noinfo_noreturn (offset 0xD5, 11) --
    // UCRT's "caller violated a contract" bailout. Windows
    // returns STATUS_INVALID_CRT_PARAMETER (0xC0000417). We
    // exit with that so the code is observable in the serial
    // log.
    0xBF, 0x17, 0x04, 0x00, 0xC0, // 0xD5 mov edi, 0xC0000417
    0x31, 0xC0,                   // 0xDA xor eax, eax ; SYS_EXIT
    0xCD, 0x80,                   // 0xDC int 0x80
    0x0F, 0x0B,                   // 0xDE ud2

    // === CRT string intrinsics =======================

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
    0x48, 0x89, 0xC8, // 0xFD mov rax, rcx ; save start
    0x80, 0x38, 0x00, // 0x100 cmp byte [rax], 0
    0x74, 0x05,       // 0x103 je +5 -> 0x10A .done
    0x48, 0xFF, 0xC0, // 0x105 inc rax
    0xEB, 0xF6,       // 0x108 jmp -10 -> 0x100 .loop
    // .done:
    0x48, 0x29, 0xC8, // 0x10A sub rax, rcx ; length = end - start
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
    0x48, 0xD1, 0xE8, // 0x120 shr rax, 1 ; byte count / 2 = chars
    0xC3,             // 0x123 ret

    // --- strchr (offset 0x124, 23 bytes) -----------------------
    // char* strchr(const char* s=rcx, int c=rdx).
    // Returns pointer to first byte matching (char)c,
    // including the terminating NUL, or nullptr if not
    // found. Matches Win32/ISO C semantics.
    0x88, 0xD0,       // 0x124 mov al, dl ; byte to find
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
    0x48, 0x89, 0xC8, // 0x13B mov rax, rcx ; save dst
    0x44, 0x8A, 0x02, // 0x13E mov r8b, [rdx]
    0x44, 0x88, 0x01, // 0x141 mov [rcx], r8b
    0x45, 0x84, 0xC0, // 0x144 test r8b, r8b
    0x74, 0x08,       // 0x147 je +8 -> 0x151 .done
    0x48, 0xFF, 0xC1, // 0x149 inc rcx
    0x48, 0xFF, 0xC2, // 0x14C inc rdx
    0xEB, 0xED,       // 0x14F jmp -19 -> 0x13E .loop
    // .done:
    0xC3, // 0x151 ret

    // === kernel32 safe-ignore shims ==================

    // --- Return-one (offset 0x152, 6 bytes) --------------------
    // Shared stub for Win32 functions whose v0 semantic is
    // "report success, do nothing". Mostly BOOL-returning
    // functions where TRUE (1) means "succeeded" — e.g.
    // CloseHandle, SetConsoleCtrlHandler. Some callers
    // branch on the BOOL, so 1 is the safe default.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x152 mov eax, 1
    0xC3,                         // 0x157 ret

    // === Win32 process heap ==========================
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
    //
    // Win64 ABI: rdi is callee-saved. Must save + restore
    // around the `mov rdi, r8`. Fits in same 11 bytes by
    // compressing `mov eax, 11` (5 bytes) to `push 11; pop rax`
    // (3 bytes), freeing 2 bytes for the push/pop rdi pair.
    0x57,             // 0x158 push rdi
    0x4C, 0x89, 0xC7, // 0x159 mov rdi, r8
    0x6A, 0x0B,       // 0x15C push 11
    0x58,             // 0x15E pop rax
    0xCD, 0x80,       // 0x15F int 0x80
    0x5F,             // 0x161 pop rdi
    0xC3,             // 0x162 ret

    // --- HeapFree (offset 0x163, 16 bytes) ---------------------
    // BOOL HeapFree(HANDLE hHeap=rcx, DWORD dwFlags=rdx, LPVOID lpMem=r8).
    // v0: ignore hHeap + dwFlags. Pass lpMem to SYS_HEAP_FREE.
    // Always return TRUE — the kernel side silently ignores
    // null/out-of-range pointers (Win32 contract: free(NULL)
    // is legal and should not fail).
    //
    // Win64 ABI fix: save/restore rdi around the `mov rdi, r8`.
    // `mov eax, 12` compresses to `push 12; pop rax` (3 bytes,
    // saves 2) which covers the 2-byte push rdi / pop rdi pair.
    // Keeps total size at 16.
    0x57,                         // 0x163 push rdi
    0x4C, 0x89, 0xC7,             // 0x164 mov rdi, r8
    0x6A, 0x0C,                   // 0x167 push 12
    0x58,                         // 0x169 pop rax
    0xCD, 0x80,                   // 0x16A int 0x80
    0x5F,                         // 0x16C pop rdi
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x16D mov eax, 1 ; BOOL TRUE
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
    // first arg position) instead of r8. Same Win64 ABI fix:
    // save/restore rdi; compress `mov eax, 11` to fit.
    0x57,             // 0x17B push rdi
    0x48, 0x89, 0xCF, // 0x17C mov rdi, rcx
    0x6A, 0x0B,       // 0x17F push 11
    0x58,             // 0x181 pop rax
    0xCD, 0x80,       // 0x182 int 0x80
    0x5F,             // 0x184 pop rdi
    0xC3,             // 0x185 ret

    // --- free (offset 0x186, 11 bytes) -------------------------
    // void free(void* ptr=rcx).
    // No return value; rax left as syscall result (0) which
    // is fine — C "void" discards it. Win64 ABI fix: preserve
    // rdi across the `mov rdi, rcx`.
    //
    // CRITICAL: this stub was the root cause of the
    // stress-test crash. A caller allocates rdi to hold the
    // malloc IAT pointer, calls malloc, then calls free (which
    // clobbered rdi), then tries to call malloc again via rdi —
    // jumping to the freed block address (0x5000xxxx range).
    0x57,             // 0x186 push rdi
    0x48, 0x89, 0xCF, // 0x187 mov rdi, rcx
    0x6A, 0x0C,       // 0x18A push 12
    0x58,             // 0x18C pop rax
    0xCD, 0x80,       // 0x18D int 0x80
    0x5F,             // 0x18F pop rdi
    0xC3,             // 0x190 ret

    // --- calloc (offset 0x191, 35 bytes) -----------------------
    // void* calloc(size_t count=rcx, size_t size=rdx).
    // Allocate count*size bytes and zero-fill. Zero on OOM.
    //
    // Implementation:
    // rcx = count * size (imul is nonzero-trashing, rdx is
    // only read; after imul, rdx is untouched)
    // r9 = saved count*size (for the stosb loop)
    // SYS_HEAP_ALLOC preserves r9 (int 0x80 only writes rax).
    // On success: rep stosb zeros [rdi, rdi+rcx); push/pop
    // rax around the loop because stosb destroys rdi, rcx.
    //
    // Win64 ABI fix: save/restore rdi (callee-saved). Compressed
    // `mov eax, 11` frees 2 bytes for push/pop rdi; stub stays
    // at 35 bytes. The fail-path jz still skips 12 bytes (the
    // zero-fill sequence) to land on the shared `pop rdi; ret`.
    0x57,                   // 0x191 push rdi
    0x48, 0x0F, 0xAF, 0xCA, // 0x192 imul rcx, rdx ; rcx = count*size
    0x48, 0x89, 0xCF,       // 0x196 mov rdi, rcx ; arg: size
    0x49, 0x89, 0xC9,       // 0x199 mov r9, rcx ; save size for stosb
    0x6A, 0x0B,             // 0x19C push 11 (SYS_HEAP_ALLOC)
    0x58,                   // 0x19E pop rax
    0xCD, 0x80,             // 0x19F int 0x80 ; rax = ptr or 0
    0x48, 0x85, 0xC0,       // 0x1A1 test rax, rax
    0x74, 0x0C,             // 0x1A4 jz +12 -> 0x1B2 (pop rdi; ret)
    0x48, 0x89, 0xC7,       // 0x1A6 mov rdi, rax ; dst
    0x4C, 0x89, 0xC9,       // 0x1A9 mov rcx, r9 ; count
    0x50,                   // 0x1AC push rax ; preserve return
    0x30, 0xC0,             // 0x1AD xor al, al ; zero byte
    0xF3, 0xAA,             // 0x1AF rep stosb
    0x58,                   // 0x1B1 pop rax
    0x5F,                   // 0x1B2 pop rdi
    0xC3,                   // 0x1B3 ret

    // === advapi32 + kernel32 safe-ignore expansion ==
    //
    // advapi32 token/privilege dance: every caller of these
    // expects BOOL return + out-params filled in with
    // "something plausible". v0 gives them all 1s so the
    // setup code path proceeds to the eventual privileged
    // operation (which we can't actually perform anyway).

    // --- OpenProcessToken (offset 0x1B4, 13 bytes) -------------
    // Win32: BOOL OpenProcessToken(HANDLE Process=rcx,
    // DWORD DesiredAccess=rdx,
    // PHANDLE TokenHandle=r8).
    // Out-param: *TokenHandle = 1 (non-null fake handle).
    // Return TRUE.
    0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x1B4 mov qword [r8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x1BB mov eax, 1
    0xC3,                                     // 0x1C0 ret

    // --- LookupPrivilegeValueW (offset 0x1C1, 13 bytes) --------
    // Win32: BOOL LookupPrivilegeValueW(LPCWSTR System=rcx,
    // LPCWSTR Name=rdx,
    // PLUID Luid=r8).
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
    // Superseded — the IAT binding table now routes
    // GetSystemTimeAsFileTime to kOffGetSysTimeFTReal
    // (offset 0x2A6) which issues SYS_GETTIME_FT to sample the
    // CMOS RTC and return a real FILETIME. The zero-writing
    // bytes below remain so the existing thunk layout stays
    // frozen; no import lands here.
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x1DE mov qword [rcx], 0
    0xC3,                                     // 0x1E5 ret

    // --- OpenProcess (offset 0x1E6, 4 bytes) -------------------
    // Win32: HANDLE OpenProcess(DWORD Access=rcx,
    // BOOL Inherit=rdx,
    // DWORD ProcessId=r8).
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

    // === performance counters + tick count =========
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
    0xCD, 0x80,                   // 0x1FB int 0x80 ; rax = ticks
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
    // * GetTickCount truncates to 32 bits — caller reads
    // only EAX; upper half of RAX is ignored.
    // * GetTickCount64 returns the full RAX.
    // Same implementation either way.
    0xB8, 0x0D, 0x00, 0x00, 0x00, // 0x213 mov eax, 13 (SYS_PERF_COUNTER)
    0xCD, 0x80,                   // 0x218 int 0x80
    0x48, 0x6B, 0xC0, 0x0A,       // 0x21A imul rax, rax, 10 ; ticks -> ms
    0xC3,                         // 0x21E ret

    // === real HeapSize + HeapReAlloc ================
    //
    // Upgrades the v0 "return 0" stubs to real
    // syscalls backed by kernel/subsystems/win32/heap.cpp.
    // Payload-capacity tracking falls out for free from the
    // 16-byte block header the allocator already writes — the
    // kernel reads `header.size` and subtracts kHeaderSize.

    // --- HeapSize (offset 0x21F, 11 bytes) ---------------------
    // Win32: SIZE_T HeapSize(HANDLE hHeap=rcx, DWORD dwFlags=rdx, LPCVOID lpMem=r8).
    // Ignores hHeap + dwFlags (v0 has one heap per process).
    // Pass lpMem through rdi to SYS_HEAP_SIZE = 14; kernel
    // returns the block's payload capacity in rax.
    //
    // Win64 ABI fix: save/restore rdi; compress mov eax imm.
    0x57,             // 0x21F push rdi
    0x4C, 0x89, 0xC7, // 0x220 mov rdi, r8
    0x6A, 0x0E,       // 0x223 push 14
    0x58,             // 0x225 pop rax
    0xCD, 0x80,       // 0x226 int 0x80
    0x5F,             // 0x228 pop rdi
    0xC3,             // 0x229 ret

    // --- HeapReAlloc (offset 0x22A, 16 bytes) ------------------
    // Win32: LPVOID HeapReAlloc(HANDLE hHeap=rcx, DWORD dwFlags=rdx,
    // LPVOID lpMem=r8, SIZE_T dwBytes=r9).
    // Translate to the two-arg SYS_HEAP_REALLOC = 15: rdi =
    // lpMem (r8), rsi = dwBytes (r9). hHeap + dwFlags ignored.
    // Return value in rax (new VA, or 0 on failure).
    //
    // Win64 ABI fix: save/restore rdi AND rsi (both callee-saved).
    // Compression of `mov eax, 15` covers only one of the two
    // push/pop pairs; stub grows by +2 bytes (14 → 16).
    0x57,             // 0x22A push rdi
    0x56,             // 0x22B push rsi
    0x4C, 0x89, 0xC7, // 0x22C mov rdi, r8
    0x4C, 0x89, 0xCE, // 0x22F mov rsi, r9
    0x6A, 0x0F,       // 0x232 push 15
    0x58,             // 0x234 pop rax
    0xCD, 0x80,       // 0x235 int 0x80
    0x5E,             // 0x237 pop rsi
    0x5F,             // 0x238 pop rdi
    0xC3,             // 0x239 ret

    // --- realloc (offset 0x23A, 16 bytes) ----------------------
    // Win32/ucrt: void* realloc(void* ptr=rcx, size_t size=rdx).
    // Same syscall as HeapReAlloc but arguments come from
    // rcx / rdx (standard C calling convention position) —
    // shuffle into rdi / rsi and invoke.
    //
    // Same Win64 ABI fix as HeapReAlloc. +2 bytes (14 → 16).
    0x57,             // 0x23A push rdi
    0x56,             // 0x23B push rsi
    0x48, 0x89, 0xCF, // 0x23C mov rdi, rcx
    0x48, 0x89, 0xD6, // 0x23F mov rsi, rdx
    0x6A, 0x0F,       // 0x242 push 15
    0x58,             // 0x244 pop rax
    0xCD, 0x80,       // 0x245 int 0x80
    0x5E,             // 0x247 pop rsi
    0x5F,             // 0x248 pop rdi
    0xC3,             // 0x249 ret

    // --- miss-logger (offset 0x24A, 41 bytes) -----------------
    // Catch-all trampoline for every unresolved import. Two-step
    // decode of the caller's control flow so we recover the IAT
    // slot VA that matches what the PE loader staged:
    //
    // step A (caller's `call qword [rip+rel32]` is actually
    // `call rel32` because MSVC emits 5-byte direct
    // CALLs to tiny 6-byte import "thunks", not the
    // `call [IAT]` pattern). So [rsp] - 4 gives the
    // rel32 of the CALL; adding it to [rsp] yields
    // the thunk's VA (e.g. 0x140004F4E).
    //
    // step B At the thunk, bytes are `FF 25 rel32_2` — an
    // indirect `jmp qword [rip+rel32_2]`. rel32_2 is
    // relative to the byte after the jmp, so
    // IAT_slot_VA = thunk + 6 + rel32_2.
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
    0x48, 0x8B, 0x04, 0x24,       // 0x24A mov rax, [rsp] ; return addr
    0x80, 0x78, 0xFB, 0xE8,       // 0x24E cmp byte [rax-5], 0xE8 ; CALL rel32?
    0x75, 0x1C,                   // 0x252 jne +28 -> 0x270 ; skip decode+syscall
    0x48, 0x63, 0x48, 0xFC,       // 0x254 movsxd rcx, dword [rax-4] ; CALL rel32
    0x48, 0x01, 0xC1,             // 0x258 add rcx, rax ; rcx = thunk VA
    0x48, 0x63, 0x41, 0x02,       // 0x25B movsxd rax, dword [rcx+2] ; thunk's JMP rel32
    0x48, 0x01, 0xC8,             // 0x25F add rax, rcx ; rax = thunk + rel32
    0x48, 0x83, 0xC0, 0x06,       // 0x262 add rax, 6 ; rax = IAT slot VA
    0x48, 0x89, 0xC7,             // 0x266 mov rdi, rax ; arg0 = IAT slot VA
    0xB8, 0x10, 0x00, 0x00, 0x00, // 0x269 mov eax, 16 (SYS_WIN32_MISS_LOG)
    0xCD, 0x80,                   // 0x26E int 0x80
    // .skip target — common epilogue returns 0 for both paths.
    0x31, 0xC0, // 0x270 xor eax, eax
    0xC3,       // 0x272 ret

    // === CRT argc / argv accessors ==================
    //
    // The MSVC CRT's `__scrt_common_main_seh` reads argc/argv via
    // two accessor functions rather than touching globals directly:
    //
    // int* __p___argc(void);
    // char*** __p___argv(void);
    //
    // They return addresses into a process-wide storage block the
    // CRT initialises during startup. In DuetOS that storage is
    // the "proc-env" page at `kProcEnvVa` (0x65000000), populated
    // by `Win32ProcEnvPopulate` during PE load with argc=1 and
    // argv=[program_name, NULL].
    //
    // The absolute address fits in 32 bits (0x65000000 < 2^32), so
    // `mov eax, imm32; ret` is 6 bytes — the upper 32 bits of RAX
    // are zeroed by the x86-64 ABI for any 32-bit dest op, giving
    // us the right 64-bit pointer without a 10-byte movabs.

    // --- __p___argc (offset 0x273, 6 bytes) --------------------
    // Returns &argc (int*). argc lives at kProcEnvVa + 0x00.
    0xB8, 0x00, 0x00, 0x00, 0x65, // 0x273 mov eax, 0x65000000
    0xC3,                         // 0x278 ret

    // --- __p___argv (offset 0x279, 6 bytes) --------------------
    // Returns &argv (char***). argv (a char**) lives at
    // kProcEnvVa + 0x08.
    0xB8, 0x08, 0x00, 0x00, 0x65, // 0x279 mov eax, 0x65000008
    0xC3,                         // 0x27E ret

    // === UCRT stdio accessors =======================

    // --- __p__commode (offset 0x27F, 6 bytes) ------------------
    // int* __p__commode(void) — returns a pointer to the
    // `_commode` global, which encodes the default file-mode
    // flags (0 = O_TEXT, _O_BINARY = 0x4000, …). Callers of
    // _fmode / __p__commode read this value to pick buffered
    // vs. line-buffered vs. binary I/O; they never write it
    // in v0 workloads. We point at a zero int in the proc-env
    // page — "default text mode" — which is what UCRT itself
    // initialises it to.
    0xB8, 0x00, 0x02, 0x00, 0x65, // 0x27F mov eax, 0x65000200
    0xC3,                         // 0x284 ret

    // === C++ iostream output ========================
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
    // a follow-up that constructs a real `std::cout` whose
    // streambuf vtable points at kOffSputn etc., and they work
    // immediately for programs that take the method's address
    // directly (e.g. `auto f = &basic_streambuf::sputn`).

    // --- sputn (offset 0x285, 19 bytes) ------------------------
    // `streamsize basic_streambuf<char>::sputn(const char* s, streamsize n)`.
    // Args: rcx=this (ignored), rdx=s, r8=n. Returns count in rax.
    // Direct SYS_WRITE(1, s, n); kernel caps at kSyscallWriteMax
    // (256) and returns the actual count — so the caller's
    // count-check (`rv == n`) will match for small buffers and
    // trip on larger ones, which is the honest behaviour.
    //
    // Win64 ABI fix: save/restore rdi + rsi. Compressed imm8
    // loads free the 4 bytes needed for 2 push/pop pairs;
    // stub stays at 19 bytes.
    0x56,             // 0x285 push rsi
    0x57,             // 0x286 push rdi
    0x48, 0x89, 0xD6, // 0x287 mov rsi, rdx ; buf
    0x4C, 0x89, 0xC2, // 0x28A mov rdx, r8 ; n
    0x6A, 0x01,       // 0x28D push 1
    0x5F,             // 0x28F pop rdi ; fd = stdout
    0x6A, 0x02,       // 0x290 push 2
    0x58,             // 0x292 pop rax ; SYS_WRITE
    0xCD, 0x80,       // 0x293 int 0x80
    0x5F,             // 0x295 pop rdi
    0x5E,             // 0x296 pop rsi
    0xC3,             // 0x297 ret ; rax = count

    // --- return-this (offset 0x298, 4 bytes) -------------------
    // `basic_ostream& basic_ostream::flush()` and any Win32
    // method whose contract is "do nothing, return *this".
    // Args: rcx=this. Returns rcx.
    0x48, 0x89, 0xC8, // 0x298 mov rax, rcx
    0xC3,             // 0x29B ret

    // --- widen (offset 0x29C, 4 bytes) -------------------------
    // `char basic_ios<char>::widen(char c)`. Identity on char.
    // Args: rcx=this (ignored), dl=c. Returns c in al.
    0x0F, 0xB6, 0xC2, // 0x29C movzx eax, dl
    0xC3,             // 0x29F ret

    // === D3D / DXGI — HRESULT E_FAIL ================
    //
    // Any PE that imports d3d11 / d3d12 / dxgi entry points
    // lands on this stub. Returns HRESULT E_FAIL
    // (0x80004005) so the caller's "no graphics available"
    // fallback path activates cleanly. Prevents the caller
    // from treating the miss-logger's 0-return as success
    // (HRESULT S_OK == 0), which would lead to a null-deref
    // on the returned IDirect3D*/ID3D11*/IDXGI* interface.
    //
    // Wire-up target: a follow-up redirects this IAT
    // landing through a syscall to
    // subsystems::graphics::D3D11CreateDeviceStub etc., so the
    // kernel log records exactly which D3D entry point got
    // called. For v0, returning E_FAIL is enough to make the
    // caller's fallback branch fire.

    // --- HRESULT E_FAIL (offset 0x2A0, 6 bytes) ----------------
    // `mov eax, 0x80004005; ret`. The 32-bit form zero-extends
    // to rax; HRESULT is 32-bit so upper bits don't matter.
    0xB8, 0x05, 0x40, 0x00, 0x80, // 0x2A0 mov eax, 0x80004005
    0xC3,                         // 0x2A5 ret

    // === real GetSystemTimeAsFileTime ===============
    //
    // Replaces the old `0x1DE` stub (which wrote 0 into *rcx).
    // Issues SYS_GETTIME_FT (17) which samples the CMOS RTC and
    // returns a Windows FILETIME (100 ns ticks since 1601-01-01).
    // Then stores the result into *rcx (the caller's LPFILETIME).
    //
    // Register discipline:
    // - rcx must survive the int 0x80 so we can write *rcx at
    // the end. int 0x80 preserves all GPRs except rax, so we
    // don't need to save/restore rcx, but we push it anyway
    // as paranoia for any future syscall that might clobber
    // arguments.
    // - Nothing else matters (caller-saved under Win64 ABI).
    //
    // 13 bytes total.
    0x51,                         // 0x2A6 push rcx
    0xB8, 0x11, 0x00, 0x00, 0x00, // 0x2A7 mov eax, 17 (SYS_GETTIME_FT)
    0xCD, 0x80,                   // 0x2AC int 0x80 ; rax = FILETIME
    0x59,                         // 0x2AE pop rcx
    0x48, 0x89, 0x01,             // 0x2AF mov [rcx], rax
    0xC3,                         // 0x2B2 ret

    // === HPET-backed QueryPerformance{Counter,Frequency} ===
    //
    // The old QPC at 0x1F6 returned LAPIC tick counter (100 Hz)
    // and the old QPF at 0x206 returned 100. Replacing both so
    // QPC returns nanoseconds since boot (via SYS_NOW_NS → HPET)
    // and QPF returns 1 GHz (= 1e9, matching nanoseconds).
    //
    // Any (counter_end - counter_start) / frequency computation
    // a caller does now yields real seconds with ~70 ns granularity.
    // The old 0x1F6 and 0x206 stubs stay as dead page bytes.

    // --- QPC via SYS_NOW_NS (offset 0x2B3, 15 bytes) -----------
    // Win32: BOOL QueryPerformanceCounter(LARGE_INTEGER* ctr=rcx).
    0x51,                         // 0x2B3 push rcx
    0xB8, 0x12, 0x00, 0x00, 0x00, // 0x2B4 mov eax, 18 (SYS_NOW_NS)
    0xCD, 0x80,                   // 0x2B9 int 0x80 ; rax = ns since boot
    0x59,                         // 0x2BB pop rcx
    0x48, 0x89, 0x01,             // 0x2BC mov [rcx], rax
    0xB0, 0x01,                   // 0x2BF mov al, 1 ; BOOL TRUE (low byte)
    0xC3,                         // 0x2C1 ret

    // --- QPF via constant 1'000'000'000 (offset 0x2C2, 13 bytes) --
    // Win32: BOOL QueryPerformanceFrequency(LARGE_INTEGER* freq=rcx).
    // 1e9 = 0x3B9ACA00 fits in a positive imm32, so the
    // `mov qword [rcx], imm32` encoding sign-extends to
    // 0x00000000_3B9ACA00 — exactly the 64-bit value we want.
    0x48, 0xC7, 0x01, 0x00, 0xCA, 0x9A, 0x3B, // 0x2C2 mov qword [rcx], 0x3B9ACA00
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x2C9 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x2CE ret

    // --- Sleep (offset 0x2CF, 12 bytes) ------------------------
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
    // bring-up: Sleep(50) → cr2=0x32.)
    //
    // `mov edi, ecx` is a 32-bit move — x86_64 zero-extends the
    // upper half of rdi automatically, so a DWORD `ms` becomes a
    // u64 with the high bits cleared, matching what SYS_SLEEP_MS
    // expects in rdi.
    0x57,                         // 0x2CF push rdi ; save callee-saved
    0x89, 0xCF,                   // 0x2D0 mov edi, ecx ; ms -> rdi
    0xB8, 0x13, 0x00, 0x00, 0x00, // 0x2D2 mov eax, 19 ; SYS_SLEEP_MS
    0xCD, 0x80,                   // 0x2D7 int 0x80
    0x5F,                         // 0x2D9 pop rdi ; restore
    0xC3,                         // 0x2DA ret

    // --- SwitchToThread (offset 0x2DB, 10 bytes) ---------------
    // Win32: BOOL SwitchToThread(void). Returns nonzero if a
    // thread switch happened, 0 if no other ready thread was
    // available. Maps to SYS_YIELD; we return 1 (TRUE)
    // optimistically — callers use the return as a hint, not a
    // strict assertion of "another thread ran". The real check
    // would require comparing scheduler tick counters before
    // and after, which isn't worth the kernel-side complexity.
    //
    // No callee-saved regs touched — only RAX (caller-saved).
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x2DB mov eax, 3 ; SYS_YIELD
    0xCD, 0x80,                   // 0x2E0 int 0x80
    0xB0, 0x01,                   // 0x2E2 mov al, 1 ; BOOL TRUE
    0xC3,                         // 0x2E4 ret

    // === command line + environment ================
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
    // __p___argv (already wired).

    // --- GetCommandLineW (offset 0x2E5, 6 bytes) ---------------
    // Returns LPCWSTR = kProcEnvVa + kProcEnvCmdlineWOff
    // = 0x65000300 (low 4 GiB).
    0xB8, 0x00, 0x03, 0x00, 0x65, // 0x2E5 mov eax, 0x65000300
    0xC3,                         // 0x2EA ret

    // --- GetCommandLineA (offset 0x2EB, 6 bytes) ---------------
    // Returns LPCSTR = kProcEnvVa + kProcEnvCmdlineAOff
    // = 0x65000380.
    0xB8, 0x80, 0x03, 0x00, 0x65, // 0x2EB mov eax, 0x65000380
    0xC3,                         // 0x2F0 ret

    // --- GetEnvironmentStringsW (offset 0x2F1, 6 bytes) --------
    // Returns LPWCH = kProcEnvVa + kProcEnvEnvBlockWOff
    // = 0x65000400. The block is two NUL bytes
    // (an empty env), so any caller that walks it stops
    // immediately. FreeEnvironmentStringsW is a Win32 cleanup
    // hook — registered as a no-op (returns TRUE) below.
    0xB8, 0x00, 0x04, 0x00, 0x65, // 0x2F1 mov eax, 0x65000400
    0xC3,                         // 0x2F6 ret

    // === file I/O ===================================
    //
    // Win32 handle table lives on Process; SYS_FILE_OPEN /
    // SYS_FILE_READ / SYS_FILE_CLOSE / SYS_FILE_SEEK route in.
    // Handles returned to user mode are 0x100..0x10F (so they
    // never collide with INVALID_HANDLE_VALUE = -1).

    // --- CreateFileW (offset 0x2F7, 59 bytes) -----------------
    // Win32: HANDLE CreateFileW(LPCWSTR lpFileName=rcx, DWORD
    // dwDesiredAccess, DWORD dwShareMode,
    // LPSECURITY_ATTRIBUTES lpSec, DWORD dwCreate,
    // DWORD dwFlags, HANDLE hTemplate);
    //
    // v0 ignores every flag — opens read-only no matter what.
    // The wide path in rcx gets stripped to ASCII on a stack-
    // local 256-byte buffer, then SYS_FILE_OPEN routes it to
    // the kernel.
    //
    // RDI / RSI are CALLEE-SAVED in the Win32 x64 ABI — same
    // bug class that bit Sleep; both are saved+
    // restored across the syscall.
    0x57,                                     // 0x2F7 push rdi
    0x56,                                     // 0x2F8 push rsi
    0x48, 0x81, 0xEC, 0x08, 0x01, 0x00, 0x00, // 0x2F9 sub rsp, 0x108 ; 264-byte ASCII buf
    0x48, 0x89, 0xE7,                         // 0x300 mov rdi, rsp ; rdi = ASCII dst
    0x31, 0xD2,                               // 0x303 xor edx, edx ; idx = 0
    // .loop:
    0x83, 0xFA, 0xFF,       // 0x305 cmp edx, 0xFF ; cap at 255
    0x73, 0x10,             // 0x308 jae +0x10 (.done)
    0x0F, 0xB7, 0x04, 0x51, // 0x30A movzx eax, word [rcx+rdx*2] ; load wide char
    0x66, 0x85, 0xC0,       // 0x30E test ax, ax ; NUL?
    0x74, 0x07,             // 0x311 jz +0x07 (.done)
    0x88, 0x04, 0x17,       // 0x313 mov [rdi+rdx], al ; ASCII low byte
    0xFF, 0xC2,             // 0x316 inc edx
    0xEB, 0xEB,             // 0x318 jmp .loop (-0x15)
    // .done:
    0xC6, 0x04, 0x17, 0x00,                   // 0x31A mov byte [rdi+rdx], 0 ; NUL terminate
    0x48, 0x89, 0xD6,                         // 0x31E mov rsi, rdx ; len -> rsi (arg 1)
    0xB8, 0x14, 0x00, 0x00, 0x00,             // 0x321 mov eax, 20 ; SYS_FILE_OPEN
    0xCD, 0x80,                               // 0x326 int 0x80
    0x48, 0x81, 0xC4, 0x08, 0x01, 0x00, 0x00, // 0x328 add rsp, 0x108 ; restore stack
    0x5E,                                     // 0x32F pop rsi
    0x5F,                                     // 0x330 pop rdi
    0xC3,                                     // 0x331 ret

    // --- ReadFile (offset 0x332, 46 bytes) --------------------
    // Win32: BOOL ReadFile(HANDLE rcx, LPVOID buf=rdx,
    // DWORD count=r8, LPDWORD lpRead=r9, LPOVERLAPPED).
    // Maps to SYS_FILE_READ; stores byte count in *lpRead if
    // non-NULL; returns TRUE on success (rax >= 0).
    0x57,                         // 0x332 push rdi
    0x56,                         // 0x333 push rsi
    0x48, 0x89, 0xCF,             // 0x334 mov rdi, rcx ; handle
    0x48, 0x89, 0xD6,             // 0x337 mov rsi, rdx ; buf
    0x4C, 0x89, 0xC2,             // 0x33A mov rdx, r8 ; count
    0xB8, 0x15, 0x00, 0x00, 0x00, // 0x33D mov eax, 21 ; SYS_FILE_READ
    0xCD, 0x80,                   // 0x342 int 0x80
    // *lpRead = max(rax, 0) if r9 != NULL
    0x4D, 0x85, 0xC9, // 0x344 test r9, r9
    0x74, 0x0B,       // 0x347 jz +0x0B
    0x31, 0xC9,       // 0x349 xor ecx, ecx
    0x48, 0x85, 0xC0, // 0x34B test rax, rax
    0x0F, 0x49, 0xC8, // 0x34E cmovns ecx, eax
    0x41, 0x89, 0x09, // 0x351 mov [r9], ecx
    // BOOL = (rax >= 0)
    0x48, 0x85, 0xC0, // 0x354 test rax, rax
    0x0F, 0x99, 0xC0, // 0x357 setns al
    0x0F, 0xB6, 0xC0, // 0x35A movzx eax, al
    0x5E,             // 0x35D pop rsi
    0x5F,             // 0x35E pop rdi
    0xC3,             // 0x35F ret

    // --- CloseHandle (offset 0x360, 15 bytes) -----------------
    // Win32: BOOL CloseHandle(HANDLE rcx). SYS_FILE_CLOSE
    // tolerates non-file handles (no-op + return 0), so this
    // also harmlessly handles the historical no-op CloseHandle
    // call sites (e.g. CreateEventW pseudo-handles).
    0x57,                         // 0x360 push rdi
    0x48, 0x89, 0xCF,             // 0x361 mov rdi, rcx
    0xB8, 0x16, 0x00, 0x00, 0x00, // 0x364 mov eax, 22 ; SYS_FILE_CLOSE
    0xCD, 0x80,                   // 0x369 int 0x80
    0xB0, 0x01,                   // 0x36B mov al, 1 ; BOOL TRUE
    0x5F,                         // 0x36D pop rdi
    0xC3,                         // 0x36E ret

    // --- SetFilePointerEx (offset 0x36F, 38 bytes) ------------
    // Win32: BOOL SetFilePointerEx(HANDLE rcx,
    // LARGE_INTEGER off=rdx, LARGE_INTEGER* newPos=r8,
    // DWORD dwMoveMethod=r9).
    // Maps to SYS_FILE_SEEK; writes new position to *r8 if
    // non-NULL; returns TRUE iff rax >= 0.
    0x57,                         // 0x36F push rdi
    0x56,                         // 0x370 push rsi
    0x48, 0x89, 0xCF,             // 0x371 mov rdi, rcx ; handle
    0x48, 0x89, 0xD6,             // 0x374 mov rsi, rdx ; offset
    0x4C, 0x89, 0xCA,             // 0x377 mov rdx, r9 ; whence
    0xB8, 0x17, 0x00, 0x00, 0x00, // 0x37A mov eax, 23 ; SYS_FILE_SEEK
    0xCD, 0x80,                   // 0x37F int 0x80
    0x4D, 0x85, 0xC0,             // 0x381 test r8, r8
    0x74, 0x03,                   // 0x384 jz +0x03
    0x49, 0x89, 0x00,             // 0x386 mov [r8], rax
    0x48, 0x85, 0xC0,             // 0x389 test rax, rax
    0x0F, 0x99, 0xC0,             // 0x38C setns al
    0x0F, 0xB6, 0xC0,             // 0x38F movzx eax, al
    0x5E,                         // 0x392 pop rsi
    0x5F,                         // 0x393 pop rdi
    0xC3,                         // 0x394 ret

    // === file stat + module lookup ==================

    // --- GetFileSizeEx (offset 0x395, 29 bytes) ---------------
    // Win32: BOOL GetFileSizeEx(HANDLE rcx, LARGE_INTEGER* rdx).
    // Maps to SYS_FILE_FSTAT — non-destructive size query that
    // doesn't perturb the read cursor (vs. SEEK_END which
    // would).
    0x57,                         // 0x395 push rdi
    0x56,                         // 0x396 push rsi
    0x48, 0x89, 0xCF,             // 0x397 mov rdi, rcx ; handle
    0x48, 0x89, 0xD6,             // 0x39A mov rsi, rdx ; out ptr
    0xB8, 0x18, 0x00, 0x00, 0x00, // 0x39D mov eax, 24 ; SYS_FILE_FSTAT
    0xCD, 0x80,                   // 0x3A2 int 0x80
    0x31, 0xC9,                   // 0x3A4 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x3A6 test rax, rax ; ZF=1 iff success (rax==0)
    0x0F, 0x94, 0xC1,             // 0x3A9 sete cl
    0x0F, 0xB6, 0xC1,             // 0x3AC movzx eax, cl
    0x5E,                         // 0x3AF pop rsi
    0x5F,                         // 0x3B0 pop rdi
    0xC3,                         // 0x3B1 ret

    // --- GetModuleHandleW (offset 0x3B2, 17 bytes) ------------
    // Win32: HMODULE GetModuleHandleW(LPCWSTR lpModuleName=rcx).
    //
    // v0 supports exactly the lpModuleName == NULL form (returns
    // the EXE's own HMODULE) — that's what the CRT calls during
    // startup to populate __ImageBase. Any non-NULL name returns
    // 0 (= "module not in our process" → caller's GetLastError
    // path runs). The EXE's image base lives in the proc-env
    // page at kProcEnvVa + kProcEnvModuleBaseOff (= 0x65000500),
    // populated by Win32ProcEnvPopulate from the PE loader.
    0x48, 0x85, 0xC9,                               // 0x3B2 test rcx, rcx
    0x75, 0x09,                                     // 0x3B5 jne +0x09 -> .not_null
    0x48, 0x8B, 0x04, 0x25, 0x00, 0x05, 0x00, 0x65, // 0x3B7 mov rax, [0x65000500]
    0xC3,                                           // 0x3BF ret
    // .not_null:
    0x31, 0xC0, // 0x3C0 xor eax, eax
    0xC3,       // 0x3C2 ret

    // === Win32 mutex (real waitqueue-backed) =========

    // --- CreateMutexW (offset 0x3C3, 13 bytes) ----------------
    // Win32: HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES rcx,
    // BOOL bInitialOwner=rdx, LPCWSTR lpName=r8).
    // Ignores attrs + name; forwards bInitialOwner to
    // SYS_MUTEX_CREATE which returns the kWin32MutexBase + slot
    // pseudo-handle directly.
    0x57,                         // 0x3C3 push rdi
    0x48, 0x89, 0xD7,             // 0x3C4 mov rdi, rdx ; bInitialOwner
    0xB8, 0x19, 0x00, 0x00, 0x00, // 0x3C7 mov eax, 25 ; SYS_MUTEX_CREATE
    0xCD, 0x80,                   // 0x3CC int 0x80
    0x5F,                         // 0x3CE pop rdi
    0xC3,                         // 0x3CF ret

    // --- WaitForSingleObject (offset 0x3D0, 38 bytes) ---------
    // Win32: DWORD WaitForSingleObject(HANDLE rcx, DWORD timeout=rdx).
    //
    // Dispatches by handle range:
    // * Mutex range (0x200..0x207): SYS_MUTEX_WAIT.
    // * Anything else: pseudo-signal (return 0 = WAIT_OBJECT_0)
    // to preserve the behaviour for events,
    // thread handles, etc., that the v0 stubs don't track.
    //
    // RDI / RSI saved+restored — Win32 ABI callee-saved.
    0x57,                               // 0x3D0 push rdi
    0x56,                               // 0x3D1 push rsi
    0x48, 0x89, 0xC8,                   // 0x3D2 mov rax, rcx ; handle
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x3D5 sub rax, 0x200 ; rax -= base
    0x48, 0x83, 0xF8, 0x08,             // 0x3DB cmp rax, 8 ; in mutex range?
    0x73, 0x10,                         // 0x3DF jae .pseudo (+0x10)
    0x48, 0x89, 0xCF,                   // 0x3E1 mov rdi, rcx ; handle
    0x48, 0x89, 0xD6,                   // 0x3E4 mov rsi, rdx ; timeout_ms
    0xB8, 0x1A, 0x00, 0x00, 0x00,       // 0x3E7 mov eax, 26 ; SYS_MUTEX_WAIT
    0xCD, 0x80,                         // 0x3EC int 0x80
    0x5E,                               // 0x3EE pop rsi
    0x5F,                               // 0x3EF pop rdi
    0xC3,                               // 0x3F0 ret
    // .pseudo:
    0x31, 0xC0, // 0x3F1 xor eax, eax ; WAIT_OBJECT_0 = 0
    0x5E,       // 0x3F3 pop rsi
    0x5F,       // 0x3F4 pop rdi
    0xC3,       // 0x3F5 ret

    // --- ReleaseMutex (offset 0x3F6, 24 bytes) ----------------
    // Win32: BOOL ReleaseMutex(HANDLE rcx).
    // SYS_MUTEX_RELEASE returns 0 on success, -1 on failure;
    // BOOL = (rax == 0).
    0x57,                         // 0x3F6 push rdi
    0x48, 0x89, 0xCF,             // 0x3F7 mov rdi, rcx
    0xB8, 0x1B, 0x00, 0x00, 0x00, // 0x3FA mov eax, 27 ; SYS_MUTEX_RELEASE
    0xCD, 0x80,                   // 0x3FF int 0x80
    0x31, 0xC9,                   // 0x401 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x403 test rax, rax
    0x0F, 0x94, 0xC1,             // 0x406 sete cl
    0x0F, 0xB6, 0xC1,             // 0x409 movzx eax, cl
    0x5F,                         // 0x40C pop rdi
    0xC3,                         // 0x40D ret

    // === console APIs ================================

    // --- WriteConsoleW (offset 0x40E, 96 bytes) ---------------
    // Win32: BOOL WriteConsoleW(HANDLE rcx, const void* rdx,
    // DWORD nChars=r8, LPDWORD lpCharsOut=r9,
    // LPVOID lpReserved=[rsp+0x28]).
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
    0x57,                                     // 0x40E push rdi
    0x56,                                     // 0x40F push rsi
    0x41, 0x54,                               // 0x410 push r12
    0x41, 0x55,                               // 0x412 push r13
    0x48, 0x81, 0xEC, 0x08, 0x02, 0x00, 0x00, // 0x414 sub rsp, 0x208 ; 512-byte ASCII buf + 8 pad
    0x48, 0x89, 0xE7,                         // 0x41B mov rdi, rsp ; dst
    0x48, 0x89, 0xD6,                         // 0x41E mov rsi, rdx ; src (wide)
    0x4D, 0x89, 0xC4,                         // 0x421 mov r12, r8 ; nChars (save)
    0x4D, 0x89, 0xCD,                         // 0x424 mov r13, r9 ; lpCharsOut (save)
    0x31, 0xC9,                               // 0x427 xor ecx, ecx ; i = 0
    // .loop:
    0x4C, 0x39, 0xE1,                         // 0x429 cmp rcx, r12 ; i < count?
    0x73, 0x15,                               // 0x42C jae .done (+0x15)
    0x48, 0x81, 0xF9, 0x00, 0x02, 0x00, 0x00, // 0x42E cmp rcx, 0x200 ; i < 512?
    0x73, 0x0C,                               // 0x435 jae .done (+0x0C)
    0x0F, 0xB7, 0x04, 0x4E,                   // 0x437 movzx eax, word [rsi+rcx*2]
    0x88, 0x04, 0x0F,                         // 0x43B mov [rdi+rcx], al
    0x48, 0xFF, 0xC1,                         // 0x43E inc rcx
    0xEB, 0xE6,                               // 0x441 jmp .loop (-0x1A)
    // .done: rcx = actual ASCII byte count
    0x48, 0x89, 0xCA,             // 0x443 mov rdx, rcx ; len for SYS_WRITE
    0x48, 0x89, 0xFE,             // 0x446 mov rsi, rdi ; buf = ASCII dst
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0x449 mov edi, 1 ; fd = stdout
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x44E mov eax, 2 ; SYS_WRITE
    0xCD, 0x80,                   // 0x453 int 0x80
    0x4D, 0x85, 0xED,             // 0x455 test r13, r13 ; lpCharsOut != NULL?
    0x74, 0x04,                   // 0x458 jz .skip (+4)
    0x45, 0x89, 0x65, 0x00,       // 0x45A mov [r13+0], r12d ; store wide-char count
    // .skip:
    0x48, 0x81, 0xC4, 0x08, 0x02, 0x00, 0x00, // 0x45E add rsp, 0x208
    0x41, 0x5D,                               // 0x465 pop r13
    0x41, 0x5C,                               // 0x467 pop r12
    0x5E,                                     // 0x469 pop rsi
    0x5F,                                     // 0x46A pop rdi
    0xB0, 0x01,                               // 0x46B mov al, 1 ; BOOL TRUE
    0xC3,                                     // 0x46D ret

    // --- GetConsoleMode (offset 0x46E, 12 bytes) --------------
    // Win32: BOOL GetConsoleMode(HANDLE rcx, DWORD* rdx).
    // Returns a plausible flag combination —
    // ENABLE_PROCESSED_OUTPUT (0x1) | ENABLE_WRAP_AT_EOL (0x2) |
    // ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x4) = 0x7.
    // Callers that query-then-modify + SetConsoleMode round-trip
    // see the mode they set (SetConsoleMode is kOffReturnOne, so
    // the write is a no-op; the next Get returns the same
    // constant). Good enough for v0 — modern terminal-aware
    // tools see "VT processing is on, so emit escape codes" and
    // that's what our serial sink wants anyway.
    0xC7, 0x02, 0x07, 0x00, 0x00, 0x00, // 0x46E mov dword [rdx], 7
    0xB8, 0x01, 0x00, 0x00, 0x00,       // 0x474 mov eax, 1 (BOOL TRUE)
    0xC3,                               // 0x479 ret

    // --- GetConsoleCP / GetConsoleOutputCP (offset 0x47A, 6 bytes) --
    // Win32: UINT GetConsoleCP(void). Returns the input code page.
    // We report CP_UTF8 = 65001 = 0xFDE9, which matches modern
    // Windows default (post-2019 "beta: use UTF-8") and tells
    // callers their wide-char strings have already been decoded
    // on our side. Aliased for GetConsoleOutputCP below.
    0xB8, 0xE9, 0xFD, 0x00, 0x00, // 0x47A mov eax, 65001 (CP_UTF8)
    0xC3,                         // 0x47F ret

    // === virtual memory (VirtualAlloc/Free/Protect) ==

    // --- VirtualAlloc (offset 0x480, 13 bytes) ----------------
    // Win32: LPVOID VirtualAlloc(LPVOID rcx, SIZE_T rdx,
    // DWORD flAllocationType=r8, DWORD flProtect=r9).
    // v0 ignores rcx (caller's preferred address), r8, r9 —
    // just forwards the size to SYS_VMAP which bump-allocates
    // RW+NX+User pages. Kernel returns the VA; stub returns it
    // verbatim (or 0 on arena exhaustion).
    0x57,                         // 0x480 push rdi
    0x48, 0x89, 0xD7,             // 0x481 mov rdi, rdx ; size
    0xB8, 0x1C, 0x00, 0x00, 0x00, // 0x484 mov eax, 28 ; SYS_VMAP
    0xCD, 0x80,                   // 0x489 int 0x80
    0x5F,                         // 0x48B pop rdi
    0xC3,                         // 0x48C ret

    // --- VirtualFree (offset 0x48D, 29 bytes) -----------------
    // Win32: BOOL VirtualFree(LPVOID rcx, SIZE_T rdx,
    // DWORD dwFreeType=r8).
    // v0: no-op with range validation. Ignores rdx + r8;
    // SYS_VUNMAP returns 0 if the VA is in the vmap arena, -1
    // otherwise. BOOL = (rax == 0).
    0x57,                         // 0x48D push rdi
    0x56,                         // 0x48E push rsi
    0x48, 0x89, 0xCF,             // 0x48F mov rdi, rcx ; va
    0x48, 0x89, 0xD6,             // 0x492 mov rsi, rdx ; size
    0xB8, 0x1D, 0x00, 0x00, 0x00, // 0x495 mov eax, 29 ; SYS_VUNMAP
    0xCD, 0x80,                   // 0x49A int 0x80
    0x31, 0xC9,                   // 0x49C xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x49E test rax, rax
    0x0F, 0x94, 0xC1,             // 0x4A1 sete cl
    0x0F, 0xB6, 0xC1,             // 0x4A4 movzx eax, cl
    0x5E,                         // 0x4A7 pop rsi
    0x5F,                         // 0x4A8 pop rdi
    0xC3,                         // 0x4A9 ret

    // --- VirtualProtect (offset 0x4AA, 18 bytes) --------------
    // Win32: BOOL VirtualProtect(LPVOID rcx, SIZE_T rdx,
    // DWORD flNewProtect=r8, PDWORD lpflOldProtect=r9).
    // v0 is a no-op: every vmap page is RW+NX by construction
    // (W^X policy — no W+X). If r9 is non-NULL we write
    // PAGE_READWRITE (0x04) back as the "old" protection so
    // MSVC CRT's VirtualProtect-probe round-trip sees a
    // plausible value. Return TRUE.
    0x4D, 0x85, 0xC9,                         // 0x4AA test r9, r9
    0x74, 0x07,                               // 0x4AD jz .skip (+7)
    0x41, 0xC7, 0x01, 0x04, 0x00, 0x00, 0x00, // 0x4AF mov dword [r9], 4 (PAGE_READWRITE)
    // .skip:
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x4B6 mov eax, 1 (BOOL TRUE)
    0xC3,                         // 0x4BB ret

    // === wide-string helpers =========================

    // --- lstrlenW (offset 0x4BC, 15 bytes) --------------------
    // Win32: int lstrlenW(LPCWSTR rcx). Scans for a u16 zero and
    // returns the wide-char count. No SEH, no CP check — just
    // the classic strlen shape on 16-bit elements.
    0x31, 0xC0, // 0x4BC xor eax, eax
    // .loop:
    0x66, 0x83, 0x3C, 0x41, 0x00, // 0x4BE cmp word [rcx + rax*2], 0
    0x74, 0x05,                   // 0x4C3 je .done (+5)
    0x48, 0xFF, 0xC0,             // 0x4C5 inc rax
    0xEB, 0xF4,                   // 0x4C8 jmp .loop (-12)
    // .done:
    0xC3, // 0x4CA ret

    // --- lstrcmpW (offset 0x4CB, 37 bytes) --------------------
    // Win32: int lstrcmpW(LPCWSTR rcx, LPCWSTR rdx).
    // Returns 0 if equal, negative if s1 < s2, positive if s1 > s2.
    // Pure compute — no locale folding (lstrcmpW is ordinal
    // compare; lstrcmpiW would case-fold, which we don't stub).
    0x31, 0xC0, // 0x4CB xor eax, eax ; i = 0
    // .loop:
    0x44, 0x0F, 0xB7, 0x04, 0x41, // 0x4CD movzx r8d, word [rcx+rax*2]
    0x44, 0x0F, 0xB7, 0x0C, 0x42, // 0x4D2 movzx r9d, word [rdx+rax*2]
    0x45, 0x39, 0xC8,             // 0x4D7 cmp r8d, r9d
    0x75, 0x0D,                   // 0x4DA jne .diff (+0x0D)
    0x45, 0x85, 0xC0,             // 0x4DC test r8d, r8d ; both NUL?
    0x74, 0x05,                   // 0x4DF je .equal (+5)
    0x48, 0xFF, 0xC0,             // 0x4E1 inc rax
    0xEB, 0xE7,                   // 0x4E4 jmp .loop (-0x19)
    // .equal:
    0x31, 0xC0, // 0x4E6 xor eax, eax
    0xC3,       // 0x4E8 ret
    // .diff:
    0x44, 0x89, 0xC0, // 0x4E9 mov eax, r8d ; signed diff
    0x44, 0x29, 0xC8, // 0x4EC sub eax, r9d
    0xC3,             // 0x4EF ret

    // --- lstrcpyW (offset 0x4F0, 27 bytes) --------------------
    // Win32: LPWSTR lstrcpyW(LPWSTR rcx, LPCWSTR rdx).
    // Returns the destination pointer (rcx). Copies wide chars
    // including the terminating NUL. Classic strcpy shape on
    // 16-bit elements — no length check, caller's responsibility
    // to size the destination.
    0x48, 0x89, 0xC8, // 0x4F0 mov rax, rcx ; save dst for return
    0x45, 0x31, 0xC0, // 0x4F3 xor r8d, r8d ; i = 0
    // .loop:
    0x46, 0x0F, 0xB7, 0x0C, 0x42, // 0x4F6 movzx r9d, word [rdx+r8*2]
    0x66, 0x46, 0x89, 0x0C, 0x41, // 0x4FB mov word [rcx+r8*2], r9w
    0x45, 0x85, 0xC9,             // 0x500 test r9d, r9d ; copied NUL?
    0x74, 0x05,                   // 0x503 je .done (+5)
    0x49, 0xFF, 0xC0,             // 0x505 inc r8
    0xEB, 0xEC,                   // 0x508 jmp .loop (-0x14)
    // .done:
    0xC3, // 0x50A ret

    // === system-info probes ==========================

    // --- IsWow64Process (offset 0x50B, 17 bytes) --------------
    // Win32: BOOL IsWow64Process(HANDLE rcx, PBOOL rdx).
    // Writes FALSE to *Wow64Process (we're a native x64 process;
    // there's no 32-bit emulation subsystem in v0 anyway) and
    // returns TRUE. If the out-ptr is NULL we skip the write —
    // real Windows also tolerates this.
    0x48, 0x85, 0xD2,                   // 0x50B test rdx, rdx
    0x74, 0x06,                         // 0x50E jz .skip (+6)
    0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x510 mov dword [rdx], 0 (FALSE)
    // .skip:
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x516 mov eax, 1 (BOOL TRUE)
    0xC3,                         // 0x51B ret

    // --- GetVersionExW (offset 0x51C, 34 bytes) ---------------
    // Win32: BOOL GetVersionExW(POSVERSIONINFOW rcx).
    //
    // Layout of OSVERSIONINFOW:
    // 0x00 dwOSVersionInfoSize <- caller-set; we leave alone
    // 0x04 dwMajorVersion <- we write 10 (Win10)
    // 0x08 dwMinorVersion <- we write 0
    // 0x0C dwBuildNumber <- we write 19041 (Win10 2004)
    // 0x10 dwPlatformId <- we write 2 (VER_PLATFORM_WIN32_NT)
    // 0x14 szCSDVersion[128] <- leave caller's zero-init
    //
    // 19041 = 0x4A61; fits in imm32 signed. Picked to look like a
    // recent-ish Windows 10 build so feature-gate probes see a
    // plausible "new enough" version.
    //
    // GetVersionEx (ANSI) aliases to this — the first five DWORDs
    // are layout-identical; only szCSDVersion differs (ANSI vs
    // wide), which we don't touch.
    0xC7, 0x41, 0x04, 0x0A, 0x00, 0x00, 0x00, // 0x51C mov dword [rcx+0x04], 10 (major)
    0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, // 0x523 mov dword [rcx+0x08], 0 (minor)
    0xC7, 0x41, 0x0C, 0x61, 0x4A, 0x00, 0x00, // 0x52A mov dword [rcx+0x0C], 19041 (build)
    0xC7, 0x41, 0x10, 0x02, 0x00, 0x00, 0x00, // 0x531 mov dword [rcx+0x10], 2 (NT platform)
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x538 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x53D ret

    // === ANSI-byte string helpers ====================
    // Symmetric to but for single-byte LPCSTR inputs.

    // --- lstrlenA (offset 0x53E, 14 bytes) --------------------
    // Win32: int lstrlenA(LPCSTR rcx). Byte-strlen.
    0x31, 0xC0, // 0x53E xor eax, eax
    // .loop:
    0x80, 0x3C, 0x01, 0x00, // 0x540 cmp byte [rcx+rax*1], 0
    0x74, 0x05,             // 0x544 je .done (+5)
    0x48, 0xFF, 0xC0,       // 0x546 inc rax
    0xEB, 0xF5,             // 0x549 jmp .loop (-11)
    // .done:
    0xC3, // 0x54B ret

    // --- lstrcmpA (offset 0x54C, 37 bytes) --------------------
    // Win32: int lstrcmpA(LPCSTR rcx, LPCSTR rdx). Byte-strcmp
    // (ordinal — no locale fold). 0 / negative / positive per
    // classic strcmp contract.
    0x31, 0xC0, // 0x54C xor eax, eax
    // .loop:
    0x44, 0x0F, 0xB6, 0x04, 0x01, // 0x54E movzx r8d, byte [rcx+rax]
    0x44, 0x0F, 0xB6, 0x0C, 0x02, // 0x553 movzx r9d, byte [rdx+rax]
    0x45, 0x39, 0xC8,             // 0x558 cmp r8d, r9d
    0x75, 0x0D,                   // 0x55B jne .diff (+0x0D)
    0x45, 0x85, 0xC0,             // 0x55D test r8d, r8d
    0x74, 0x05,                   // 0x560 je .equal (+5)
    0x48, 0xFF, 0xC0,             // 0x562 inc rax
    0xEB, 0xE7,                   // 0x565 jmp .loop (-0x19)
    // .equal:
    0x31, 0xC0, // 0x567 xor eax, eax
    0xC3,       // 0x569 ret
    // .diff:
    0x44, 0x89, 0xC0, // 0x56A mov eax, r8d
    0x44, 0x29, 0xC8, // 0x56D sub eax, r9d
    0xC3,             // 0x570 ret

    // --- lstrcpyA (offset 0x571, 26 bytes) --------------------
    // Win32: LPSTR lstrcpyA(LPSTR rcx, LPCSTR rdx). Byte-strcpy,
    // returns dst (rcx).
    0x48, 0x89, 0xC8, // 0x571 mov rax, rcx ; save dst for return
    0x45, 0x31, 0xC0, // 0x574 xor r8d, r8d ; i = 0
    // .loop:
    0x46, 0x0F, 0xB6, 0x0C, 0x02, // 0x577 movzx r9d, byte [rdx+r8]
    0x46, 0x88, 0x0C, 0x01,       // 0x57C mov byte [rcx+r8], r9b
    0x45, 0x85, 0xC9,             // 0x580 test r9d, r9d
    0x74, 0x05,                   // 0x583 je .done (+5)
    0x49, 0xFF, 0xC0,             // 0x585 inc r8
    0xEB, 0xED,                   // 0x588 jmp .loop (-0x13)
    // .done:
    0xC3, // 0x58A ret

    // === path-query stubs ============================
    //
    // All v0 paths report a single fixed "X:\" — the minimum
    // legal Windows drive-qualified absolute path. Consumers
    // that do literal path comparisons (DllMain "am I in
    // System32?") see a non-NULL, well-formed path and don't
    // crash; consumers that actually try to open the returned
    // path get a normal not-found result from our VFS. Future
    // a follow-up can plumb the real PE path through when spawn
    // actually knows it.
    //
    // Encoding: "X:\" is 3 wide chars + NUL = 8 bytes = 2 dwords:
    // dword 0 : 0x003A 0x0058 (': X' little-endian) = 0x003A0058
    // dword 1 : 0x0000 0x005C ('\0 \\' LE) = 0x0000005C

    // --- GetModuleFileNameW (offset 0x58B, 24 bytes) ----------
    // Win32: DWORD GetModuleFileNameW(HMODULE rcx, LPWSTR rdx, DWORD r8).
    // Writes "X:\\\0" to rdx if r8 > 0, returns 3 (chars w/o NUL).
    0x45, 0x85, 0xC0,                         // 0x58B test r8d, r8d
    0x74, 0x0D,                               // 0x58E jz .skip (+0x0D) — past both mov-dword writes (6+7=13)
    0xC7, 0x02, 0x58, 0x00, 0x3A, 0x00,       // 0x590 mov dword [rdx], 0x003A0058 (L'X:')
    0xC7, 0x42, 0x04, 0x5C, 0x00, 0x00, 0x00, // 0x596 mov dword [rdx+4], 0x0000005C (L'\\\0')
    // .skip:
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x59D mov eax, 3
    0xC3,                         // 0x5A2 ret

    // --- GetCurrentDirectoryW (offset 0x5A3, 31 bytes) --------
    // Win32: DWORD GetCurrentDirectoryW(DWORD nBufferLength=rcx, LPWSTR lpBuffer=rdx).
    // Returns 3 chars written (w/o NUL) if rcx >= 4; else returns
    // 4 (required size INCLUDING NUL) without writing — standard
    // Win32 convention for "buffer too small".
    0x48, 0x83, 0xF9, 0x04,       // 0x5A3 cmp rcx, 4
    0x73, 0x06,                   // 0x5A7 jae .copy (+6)
    0xB8, 0x04, 0x00, 0x00, 0x00, // 0x5A9 mov eax, 4 (required incl. NUL)
    0xC3,                         // 0x5AE ret
    // .copy:
    0xC7, 0x02, 0x58, 0x00, 0x3A, 0x00,       // 0x5AF mov dword [rdx], 0x003A0058
    0xC7, 0x42, 0x04, 0x5C, 0x00, 0x00, 0x00, // 0x5B5 mov dword [rdx+4], 0x0000005C
    0xB8, 0x03, 0x00, 0x00, 0x00,             // 0x5BC mov eax, 3
    0xC3,                                     // 0x5C1 ret

    // === encoding converters =========================
    //
    // v0 treats both directions as simple byte-extend / byte-
    // truncate. That's correct for 7-bit ASCII under any of the
    // standard single-byte code pages + CP_UTF8 (which is itself
    // ASCII-compatible for the low 128 code points). Non-ASCII
    // UTF-8 sequences would need real decoding — not implemented,
    // documented as v0 limitation.
    //
    // Stack-arg layout at entry, after `push rdi; push rsi`:
    // [rsp+0] saved rsi
    // [rsp+8] saved rdi
    // [rsp+16] return address
    // [rsp+24] shadow arg 1 (rcx spill slot)
    // [rsp+32] shadow arg 2 (rdx spill slot)
    // [rsp+40] shadow arg 3 (r8 spill slot)
    // [rsp+48] shadow arg 4 (r9 spill slot)
    // [rsp+56] arg 5 = output pointer
    // [rsp+64] arg 6 = output capacity

    // --- MultiByteToWideChar (offset 0x5C2, 49 bytes) ---------
    // Win32: int MultiByteToWideChar(UINT CP=rcx, DWORD flags=rdx,
    // LPCCH lpMultiByteStr=r8, int cbMultiByte=r9,
    // LPWSTR dst=[rsp+0x28], int cchWideChar=[rsp+0x30]).
    //
    // v0 routes each source byte through `movzx r16, byte` and
    // stores as wide char. Copies min(cbMultiByte, cchWideChar)
    // chars, returns count written. If cchWideChar == 0, returns
    // cbMultiByte (size-query mode). Caller is expected to pass
    // an actual byte count (not -1); a follow-up handles the
    // NUL-terminated variant.
    0x57,                         // 0x5C2 push rdi
    0x56,                         // 0x5C3 push rsi
    0x48, 0x8B, 0x7C, 0x24, 0x38, // 0x5C4 mov rdi, [rsp+0x38] ; dst (LPWSTR)
    0x8B, 0x4C, 0x24, 0x40,       // 0x5C9 mov ecx, [rsp+0x40] ; cchWideChar (dst_cap)
    0x44, 0x89, 0xCE,             // 0x5CD mov esi, r9d ; cbMultiByte (src_len)
    0x85, 0xC9,                   // 0x5D0 test ecx, ecx
    0x74, 0x1A,                   // 0x5D2 jz .size_query (+0x1A)
    0x31, 0xC0,                   // 0x5D4 xor eax, eax
    // .loop:
    0x39, 0xF0,                   // 0x5D6 cmp eax, esi
    0x73, 0x11,                   // 0x5D8 jae .done (+0x11)
    0x39, 0xC8,                   // 0x5DA cmp eax, ecx
    0x73, 0x0D,                   // 0x5DC jae .done (+0x0D)
    0x41, 0x0F, 0xB6, 0x14, 0x00, // 0x5DE movzx edx, byte [r8+rax*1]
    0x66, 0x89, 0x14, 0x47,       // 0x5E3 mov [rdi+rax*2], dx
    0xFF, 0xC0,                   // 0x5E7 inc eax
    0xEB, 0xEB,                   // 0x5E9 jmp .loop (-0x15)
    // .done:
    0x5E, // 0x5EB pop rsi
    0x5F, // 0x5EC pop rdi
    0xC3, // 0x5ED ret
    // .size_query:
    0x89, 0xF0, // 0x5EE mov eax, esi
    0x5E,       // 0x5F0 pop rsi
    0x5F,       // 0x5F1 pop rdi
    0xC3,       // 0x5F2 ret

    // --- WideCharToMultiByte (offset 0x5F3, 48 bytes) ---------
    // Win32: int WideCharToMultiByte(UINT CP=rcx, DWORD flags=rdx,
    // LPCWCH lpWideCharStr=r8, int cchWideChar=r9,
    // LPSTR dst=[rsp+0x28], int cbMultiByte=[rsp+0x30],
    // LPCCH lpDefaultChar=[rsp+0x38] (ignored),
    // LPBOOL lpUsedDefaultChar=[rsp+0x40] (ignored)).
    //
    // v0 truncates each wide char to its low byte — correct for
    // ASCII-range content, loses high-plane data otherwise.
    0x57,                         // 0x5F3 push rdi
    0x56,                         // 0x5F4 push rsi
    0x48, 0x8B, 0x7C, 0x24, 0x38, // 0x5F5 mov rdi, [rsp+0x38] ; dst (LPSTR)
    0x8B, 0x4C, 0x24, 0x40,       // 0x5FA mov ecx, [rsp+0x40] ; cbMultiByte (dst_cap)
    0x44, 0x89, 0xCE,             // 0x5FE mov esi, r9d ; cchWideChar (src_len)
    0x85, 0xC9,                   // 0x601 test ecx, ecx
    0x74, 0x19,                   // 0x603 jz .size_query (+0x19)
    0x31, 0xC0,                   // 0x605 xor eax, eax
    // .loop:
    0x39, 0xF0,                   // 0x607 cmp eax, esi
    0x73, 0x10,                   // 0x609 jae .done (+0x10)
    0x39, 0xC8,                   // 0x60B cmp eax, ecx
    0x73, 0x0C,                   // 0x60D jae .done (+0x0C)
    0x41, 0x0F, 0xB7, 0x14, 0x40, // 0x60F movzx edx, word [r8+rax*2]
    0x88, 0x14, 0x07,             // 0x614 mov [rdi+rax*1], dl
    0xFF, 0xC0,                   // 0x617 inc eax
    0xEB, 0xEC,                   // 0x619 jmp .loop (-0x14)
    // .done:
    0x5E, // 0x61B pop rsi
    0x5F, // 0x61C pop rdi
    0xC3, // 0x61D ret
    // .size_query:
    0x89, 0xF0, // 0x61E mov eax, esi
    0x5E,       // 0x620 pop rsi
    0x5F,       // 0x621 pop rdi
    0xC3,       // 0x622 ret

    // === identity queries ============================
    //
    // Fixed-string probes for "who am I on this machine?"
    // queries. Real Windows writes the NetBIOS name / SAM user.
    // v0 hands back constants: user = "user" (4 chars), computer
    // = "DuetOS" (8 chars). Both follow the same in/out-size
    // shape: *pcchSize is capacity on entry, chars-written-
    // including-NUL on exit.

    // --- GetUserNameW (offset 0x623, 47 bytes) ----------------
    // Win32: BOOL GetUserNameW(LPWSTR rcx, LPDWORD rdx).
    // If *rdx >= 5, write L"user\0", *rdx = 5, return TRUE.
    // Else, *rdx = 5 (required), return FALSE.
    0x8B, 0x02,                               // 0x623 mov eax, [rdx] (capacity in wide chars)
    0x83, 0xF8, 0x05,                         // 0x625 cmp eax, 5
    0x72, 0x1F,                               // 0x628 jb .small (+0x1F = 31)
    0xC7, 0x01, 0x75, 0x00, 0x73, 0x00,       // 0x62A mov dword [rcx], 0x00730075 (L"us")
    0xC7, 0x41, 0x04, 0x65, 0x00, 0x72, 0x00, // 0x630 mov dword [rcx+4], 0x00720065 (L"er")
    0x66, 0xC7, 0x41, 0x08, 0x00, 0x00,       // 0x637 mov word [rcx+8], 0 (NUL)
    0xC7, 0x02, 0x05, 0x00, 0x00, 0x00,       // 0x63D mov dword [rdx], 5 (chars incl NUL)
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x643 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x648 ret
    // .small:
    0xC7, 0x02, 0x05, 0x00, 0x00, 0x00, // 0x649 mov dword [rdx], 5 (required)
    0x31, 0xC0,                         // 0x64F xor eax, eax (BOOL FALSE)
    0xC3,                               // 0x651 ret

    // --- GetComputerNameW (offset 0x652, 61 bytes) ------------
    // Win32: BOOL GetComputerNameW(LPWSTR rcx, LPDWORD rdx).
    // Writes L"DuetOS\0" (9 wide chars incl NUL) if buffer
    // has room. Same size-convention as GetUserNameW.
    0x8B, 0x02,                               // 0x652 mov eax, [rdx]
    0x83, 0xF8, 0x09,                         // 0x654 cmp eax, 9
    0x72, 0x2D,                               // 0x657 jb .small (+0x2D = 45)
    0xC7, 0x01, 0x43, 0x00, 0x75, 0x00,       // 0x659 mov dword [rcx], 0x00750043 (L"Cu")
    0xC7, 0x41, 0x04, 0x73, 0x00, 0x74, 0x00, // 0x65F mov dword [rcx+4], 0x00740073 (L"st")
    0xC7, 0x41, 0x08, 0x6F, 0x00, 0x6D, 0x00, // 0x666 mov dword [rcx+8], 0x006D006F (L"om")
    0xC7, 0x41, 0x0C, 0x4F, 0x00, 0x53, 0x00, // 0x66D mov dword [rcx+12], 0x0053004F (L"OS")
    0x66, 0xC7, 0x41, 0x10, 0x00, 0x00,       // 0x674 mov word [rcx+16], 0 (NUL)
    0xC7, 0x02, 0x09, 0x00, 0x00, 0x00,       // 0x67A mov dword [rdx], 9
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x680 mov eax, 1
    0xC3,                                     // 0x685 ret
    // .small:
    0xC7, 0x02, 0x09, 0x00, 0x00, 0x00, // 0x686 mov dword [rdx], 9 (required)
    0x31, 0xC0,                         // 0x68C xor eax, eax
    0xC3,                               // 0x68E ret

    // === system-directory queries ====================
    //
    // GetWindowsDirectoryW / GetSystemDirectoryW have buffer-
    // first signatures (rcx = buffer, rdx = size). We report
    // the minimal "X:\\" path for both — same content as
    // GetCurrentDirectoryW, but the args are in opposite order
    // so a separate stub is needed. GetTempPathW has the SAME
    // sig as GetCurrentDirectoryW (size first, buffer second),
    // so it aliases to kOffGetCurrentDirW below.

    // --- GetWindowsDirectoryW / GetSystemDirectoryW (offset 0x68F, 30 bytes) ---
    // Win32: UINT GetWindowsDirectoryW(LPWSTR rcx, UINT rdx).
    // UINT GetSystemDirectoryW(LPWSTR rcx, UINT rdx).
    // Buffer-first sig: writes L"X:\\\0" if rdx >= 4, returns 3.
    // Else returns 4 (required size incl NUL). Same content for
    // both — DuetOS has no filesystem distinction between
    // "Windows" dir and "System32" dir.
    0x83, 0xFA, 0x04,                         // 0x68F cmp edx, 4
    0x72, 0x13,                               // 0x692 jb .small (+0x13 = 19)
    0xC7, 0x01, 0x58, 0x00, 0x3A, 0x00,       // 0x694 mov dword [rcx], 0x003A0058
    0xC7, 0x41, 0x04, 0x5C, 0x00, 0x00, 0x00, // 0x69A mov dword [rcx+4], 0x0000005C
    0xB8, 0x03, 0x00, 0x00, 0x00,             // 0x6A1 mov eax, 3
    0xC3,                                     // 0x6A6 ret
    // .small:
    0xB8, 0x04, 0x00, 0x00, 0x00, // 0x6A7 mov eax, 4 (required incl NUL)
    0xC3,                         // 0x6AC ret

    // === misc — drives + error mode + format msg ====

    // --- GetLogicalDrives (offset 0x6AD, 6 bytes) -------------
    // Win32: DWORD GetLogicalDrives(void). Returns a bitmap of
    // drive letters (bit 0 = A:, bit 23 = X:). v0 reports only
    // X: — matches our single fixed path.
    0xB8, 0x00, 0x00, 0x80, 0x00, // 0x6AD mov eax, 0x00800000 (bit 23 = X:)
    0xC3,                         // 0x6B2 ret

    // --- GetDriveType (offset 0x6B3, 6 bytes) -----------------
    // Win32: UINT GetDriveType{A,W}(LPCxSTR rcx). Returns the
    // drive type. v0 always returns 3 (DRIVE_FIXED) — X: is a
    // "fixed" logical drive in DuetOS land.
    0xB8, 0x03, 0x00, 0x00, 0x00, // 0x6B3 mov eax, 3 (DRIVE_FIXED)
    0xC3,                         // 0x6B8 ret

    // === registry + file-attributes constant stubs ==

    // --- return-two (offset 0x6B9, 6 bytes) -------------------
    // Win32: typed as LSTATUS / LONG. Reg* APIs return
    // ERROR_FILE_NOT_FOUND (2) when a key / value doesn't exist.
    // Shared stub for all v0 registry queries.
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x6B9 mov eax, 2
    0xC3,                         // 0x6BE ret

    // --- return-minus-1 (offset 0x6BF, 6 bytes) ---------------
    // Win32 GetFileAttributesW returns INVALID_FILE_ATTRIBUTES
    // (= 0xFFFFFFFF) when the path doesn't exist — caller's
    // "file not present" fallback kicks in. Shared stub for any
    // DWORD-returning API that signals "not found" with -1.
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // 0x6BF mov eax, 0xFFFFFFFF
    0xC3,                         // 0x6C4 ret

    // --- return-priority-normal (offset 0x6C5, 6 bytes) -------
    // Win32 GetPriorityClass returns a priority-class constant.
    // NORMAL_PRIORITY_CLASS = 0x20. Most apps probe this
    // value; reporting "normal" means they don't try to bump
    // themselves to REALTIME (which would fail anyway).
    0xB8, 0x20, 0x00, 0x00, 0x00, // 0x6C5 mov eax, 0x20 (NORMAL_PRIORITY_CLASS)
    0xC3,                         // 0x6CA ret

    // === Interlocked* atomic operations ==============
    //
    // Real hardware LOCK-prefix instructions — these are correct
    // atomic semantics, not no-ops. v0 is effectively single-CPU
    // from ring 3's perspective (preemption but not SMP-ring-3
    // yet), but LOCK prefixes are cheap on UP and required for
    // future SMP ring-3 correctness, so we emit them now.

    // --- InterlockedIncrement (offset 0x6CB, 12 bytes) --------
    // Win32: LONG InterlockedIncrement(LONG volatile *rcx).
    // Returns NEW value. Implementation: xadd eax=1, then inc.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x6CB mov eax, 1
    0xF0, 0x0F, 0xC1, 0x01,       // 0x6D0 lock xadd [rcx], eax ; eax=old, [rcx]+=1
    0xFF, 0xC0,                   // 0x6D4 inc eax ; eax = new
    0xC3,                         // 0x6D6 ret

    // --- InterlockedDecrement (offset 0x6D7, 12 bytes) --------
    // Win32: LONG InterlockedDecrement(LONG volatile *rcx).
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // 0x6D7 mov eax, -1
    0xF0, 0x0F, 0xC1, 0x01,       // 0x6DC lock xadd [rcx], eax ; eax=old, [rcx]+=-1
    0xFF, 0xC8,                   // 0x6E0 dec eax ; eax = new
    0xC3,                         // 0x6E2 ret

    // --- InterlockedCompareExchange (offset 0x6E3, 8 bytes) ---
    // Win32: LONG InterlockedCompareExchange(LONG* rcx,
    // LONG exchange=rdx, LONG compare=r8).
    // If *rcx == compare: *rcx = exchange; return compare.
    // Else: return *rcx (unchanged). LOCK CMPXCHG does this
    // atomically; compare arg is loaded into EAX so CMPXCHG
    // compares against it, and on success stores EDX.
    0x44, 0x89, 0xC0,       // 0x6E3 mov eax, r8d ; compare -> EAX
    0xF0, 0x0F, 0xB1, 0x11, // 0x6E6 lock cmpxchg [rcx], edx
    0xC3,                   // 0x6EA ret

    // --- InterlockedExchange (offset 0x6EB, 5 bytes) ----------
    // Win32: LONG InterlockedExchange(LONG* rcx, LONG val=rdx).
    // Atomic XCHG reg/mem is implicitly locked — no LOCK prefix
    // needed. Returns the OLD value.
    0x89, 0xD0, // 0x6EB mov eax, edx ; val -> EAX
    0x87, 0x01, // 0x6ED xchg [rcx], eax ; EAX = old, [rcx] = val
    0xC3,       // 0x6EF ret

    // --- InterlockedExchangeAdd (offset 0x6F0, 7 bytes) -------
    // Win32: LONG InterlockedExchangeAdd(LONG* rcx, LONG add=rdx).
    // Returns the OLD value; *rcx += add.
    0x89, 0xD0,             // 0x6F0 mov eax, edx ; add -> EAX
    0xF0, 0x0F, 0xC1, 0x01, // 0x6F2 lock xadd [rcx], eax ; EAX = old, [rcx] += add
    0xC3,                   // 0x6F6 ret

    // === 64-bit Interlocked atomics ==================
    //
    // 64-bit counterparts to . REX.W prefix (0x48) makes
    // the ops 64-bit wide. `mov rax, -1` uses the full 7-byte
    // sign-extended form — `mov eax, -1` would zero-extend to
    // 0x00000000FFFFFFFF which is NOT -1 in 64-bit.

    // --- InterlockedIncrement64 (offset 0x6F7, 14 bytes) ------
    // Win32: LONGLONG InterlockedIncrement64(LONGLONG* rcx).
    // mov eax, 1 zero-extends to rax = 1. Returns NEW value.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0x6F7 mov eax, 1
    0xF0, 0x48, 0x0F, 0xC1, 0x01, // 0x6FC lock xadd [rcx], rax
    0x48, 0xFF, 0xC0,             // 0x701 inc rax
    0xC3,                         // 0x704 ret

    // --- InterlockedDecrement64 (offset 0x705, 16 bytes) ------
    // Win32: LONGLONG InterlockedDecrement64(LONGLONG* rcx).
    // `mov rax, -1` sign-extends imm32 0xFFFFFFFF to rax = -1.
    0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // 0x705 mov rax, -1
    0xF0, 0x48, 0x0F, 0xC1, 0x01,             // 0x70C lock xadd [rcx], rax
    0x48, 0xFF, 0xC8,                         // 0x711 dec rax
    0xC3,                                     // 0x714 ret

    // --- InterlockedCompareExchange64 (offset 0x715, 9 bytes) -
    // Win32: LONGLONG InterlockedCompareExchange64(LONGLONG* rcx,
    // LONGLONG exchange=rdx, LONGLONG compare=r8).
    0x4C, 0x89, 0xC0,             // 0x715 mov rax, r8 ; compare -> RAX
    0xF0, 0x48, 0x0F, 0xB1, 0x11, // 0x718 lock cmpxchg [rcx], rdx
    0xC3,                         // 0x71D ret

    // --- InterlockedExchange64 (offset 0x71E, 7 bytes) --------
    // Win32: LONGLONG InterlockedExchange64(LONGLONG* rcx,
    // LONGLONG val=rdx). XCHG with memory implicitly LOCKs.
    0x48, 0x89, 0xD0, // 0x71E mov rax, rdx
    0x48, 0x87, 0x01, // 0x721 xchg [rcx], rax
    0xC3,             // 0x724 ret

    // --- InterlockedExchangeAdd64 (offset 0x725, 9 bytes) -----
    // Win32: LONGLONG InterlockedExchangeAdd64(LONGLONG* rcx,
    // LONGLONG add=rdx). Returns OLD value.
    0x48, 0x89, 0xD0,             // 0x725 mov rax, rdx
    0xF0, 0x48, 0x0F, 0xC1, 0x01, // 0x728 lock xadd [rcx], rax
    0xC3,                         // 0x72D ret

    // --- return-status-not-implemented (offset 0x72E, 6 bytes) --
    // NT-layer (ntdll) functions return NTSTATUS codes. 0xC00000BB
    // = STATUS_NOT_IMPLEMENTED is the documented "this function
    // isn't supported" code — callers either fall back or
    // propagate the status up. Shared stub for ntdll bindings
    // where v0 has no real impl.
    0xB8, 0xBB, 0x00, 0x00, 0xC0, // 0x72E mov eax, 0xC00000BB
    0xC3,                         // 0x733 ret

    // === real event handles ==========================
    //
    // Replaces the kOffReturnOne CreateEventW no-op
    // with genuine per-process event state. Infrastructure
    // parallels 's mutex layer. Events have no owner,
    // no recursion — just a signaled flag + waitqueue. Manual-
    // vs. auto-reset differ only in whether SetEvent wakes all
    // or one, and whether a successful wait clears the signal.

    // --- CreateEventW (offset 0x734, 18 bytes) ----------------
    // Win32: HANDLE CreateEventW(LPSECURITY_ATTRIBUTES rcx,
    // BOOL bManualReset=rdx, BOOL bInitialState=r8,
    // LPCWSTR lpName=r9).
    // Attrs + name ignored in v0. Forwards bManualReset/
    // bInitialState to SYS_EVENT_CREATE.
    0x57,                         // 0x734 push rdi
    0x56,                         // 0x735 push rsi
    0x48, 0x89, 0xD7,             // 0x736 mov rdi, rdx ; bManualReset
    0x4C, 0x89, 0xC6,             // 0x739 mov rsi, r8 ; bInitialState
    0xB8, 0x1E, 0x00, 0x00, 0x00, // 0x73C mov eax, 30 ; SYS_EVENT_CREATE
    0xCD, 0x80,                   // 0x741 int 0x80
    0x5E,                         // 0x743 pop rsi
    0x5F,                         // 0x744 pop rdi
    0xC3,                         // 0x745 ret

    // --- SetEvent (offset 0x746, 15 bytes) --------------------
    // Win32: BOOL SetEvent(HANDLE rcx). Routes to SYS_EVENT_SET.
    // Returns TRUE (SYS_EVENT_SET succeeds for any valid handle).
    0x57,                         // 0x746 push rdi
    0x48, 0x89, 0xCF,             // 0x747 mov rdi, rcx
    0xB8, 0x1F, 0x00, 0x00, 0x00, // 0x74A mov eax, 31 ; SYS_EVENT_SET
    0xCD, 0x80,                   // 0x74F int 0x80
    0xB0, 0x01,                   // 0x751 mov al, 1 ; BOOL TRUE
    0x5F,                         // 0x753 pop rdi
    0xC3,                         // 0x754 ret

    // --- ResetEvent (offset 0x755, 15 bytes) ------------------
    // Win32: BOOL ResetEvent(HANDLE rcx).
    0x57,                         // 0x755 push rdi
    0x48, 0x89, 0xCF,             // 0x756 mov rdi, rcx
    0xB8, 0x20, 0x00, 0x00, 0x00, // 0x759 mov eax, 32 ; SYS_EVENT_RESET
    0xCD, 0x80,                   // 0x75E int 0x80
    0xB0, 0x01,                   // 0x760 mov al, 1
    0x5F,                         // 0x762 pop rdi
    0xC3,                         // 0x763 ret

    // --- WaitForSingleObject v2 (offset 0x764, 66 bytes) ------
    // Upgraded version of 's WaitForSingleObject that
    // dispatches THREE ranges:
    // * Mutex range (0x200..0x207): SYS_MUTEX_WAIT.
    // * Event range (0x300..0x307): SYS_EVENT_WAIT.
    // * Anything else: pseudo-signal (return WAIT_OBJECT_0),
    // preserving 's "unknown handle is already
    // signaled" contract for 's CreateEventW no-op
    // return value (= 1, outside both ranges).
    //
    // RDI / RSI saved + restored — Win32 ABI callee-saved.
    0x57,                               // 0x764 push rdi
    0x56,                               // 0x765 push rsi
    0x48, 0x89, 0xC8,                   // 0x766 mov rax, rcx
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x769 sub rax, 0x200
    0x48, 0x83, 0xF8, 0x08,             // 0x76F cmp rax, 8
    0x72, 0x11,                         // 0x773 jb .mutex (+0x11 = 17)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0x775 sub rax, 0x100 (now 0x300..0x307 -> 0..7)
    0x48, 0x83, 0xF8, 0x08,             // 0x77B cmp rax, 8
    0x72, 0x15,                         // 0x77F jb .event (+0x15 = 21)
    // .pseudo:
    0x31, 0xC0, // 0x781 xor eax, eax (WAIT_OBJECT_0)
    0x5E,       // 0x783 pop rsi
    0x5F,       // 0x784 pop rdi
    0xC3,       // 0x785 ret
    // .mutex:
    0x48, 0x89, 0xCF,             // 0x786 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x789 mov rsi, rdx
    0xB8, 0x1A, 0x00, 0x00, 0x00, // 0x78C mov eax, 26 (SYS_MUTEX_WAIT)
    0xCD, 0x80,                   // 0x791 int 0x80
    0x5E,                         // 0x793 pop rsi
    0x5F,                         // 0x794 pop rdi
    0xC3,                         // 0x795 ret
    // .event:
    0x48, 0x89, 0xCF,             // 0x796 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x799 mov rsi, rdx
    0xB8, 0x21, 0x00, 0x00, 0x00, // 0x79C mov eax, 33 (SYS_EVENT_WAIT)
    0xCD, 0x80,                   // 0x7A1 int 0x80
    0x5E,                         // 0x7A3 pop rsi
    0x5F,                         // 0x7A4 pop rdi
    0xC3,                         // 0x7A5 ret

    // === real TLS (persistent slot storage) ==========
    //
    // Per-process 64-slot table with u64 storage per slot + a
    // 64-bit bitmap for in-use tracking. Supersedes 's
    // alias-to-kOffReturnMinus1 TlsAlloc which always claimed
    // TLS_OUT_OF_INDEXES. Single-threaded process in v0 means
    // "thread-local" == "process-local" — but the CRT uses TLS
    // for errno / locale / exception state without caring about
    // multi-thread semantics, so the storage is what matters.

    // --- TlsAlloc (offset 0x7A6, 8 bytes) ---------------------
    // Win32: DWORD TlsAlloc(void). Returns slot 0..63 or -1.
    0xB8, 0x22, 0x00, 0x00, 0x00, // 0x7A6 mov eax, 34 (SYS_TLS_ALLOC)
    0xCD, 0x80,                   // 0x7AB int 0x80
    0xC3,                         // 0x7AD ret

    // --- TlsFree (offset 0x7AE, 24 bytes) ---------------------
    // Win32: BOOL TlsFree(DWORD rcx). Returns TRUE on success.
    0x57,                         // 0x7AE push rdi
    0x48, 0x89, 0xCF,             // 0x7AF mov rdi, rcx
    0xB8, 0x23, 0x00, 0x00, 0x00, // 0x7B2 mov eax, 35 (SYS_TLS_FREE)
    0xCD, 0x80,                   // 0x7B7 int 0x80
    0x31, 0xC9,                   // 0x7B9 xor ecx, ecx
    0x48, 0x85, 0xC0,             // 0x7BB test rax, rax
    0x0F, 0x94, 0xC1,             // 0x7BE sete cl
    0x0F, 0xB6, 0xC1,             // 0x7C1 movzx eax, cl
    0x5F,                         // 0x7C4 pop rdi
    0xC3,                         // 0x7C5 ret

    // --- TlsGetValue (offset 0x7C6, 13 bytes) -----------------
    // Win32: LPVOID TlsGetValue(DWORD rcx). Returns stored
    // value (or 0 on bad index).
    0x57,                         // 0x7C6 push rdi
    0x48, 0x89, 0xCF,             // 0x7C7 mov rdi, rcx
    0xB8, 0x24, 0x00, 0x00, 0x00, // 0x7CA mov eax, 36 (SYS_TLS_GET)
    0xCD, 0x80,                   // 0x7CF int 0x80
    0x5F,                         // 0x7D1 pop rdi
    0xC3,                         // 0x7D2 ret

    // --- TlsSetValue (offset 0x7D3, 20 bytes) -----------------
    // Win32: BOOL TlsSetValue(DWORD rcx, LPVOID rdx).
    0x57,                         // 0x7D3 push rdi
    0x56,                         // 0x7D4 push rsi
    0x48, 0x89, 0xCF,             // 0x7D5 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x7D8 mov rsi, rdx
    0xB8, 0x25, 0x00, 0x00, 0x00, // 0x7DB mov eax, 37 (SYS_TLS_SET)
    0xCD, 0x80,                   // 0x7E0 int 0x80
    0xB0, 0x01,                   // 0x7E2 mov al, 1 (BOOL TRUE)
    0x5E,                         // 0x7E4 pop rsi
    0x5F,                         // 0x7E5 pop rdi
    0xC3,                         // 0x7E6 ret

    // === ntdll virtual-memory primitives =============
    //
    // Previously the import resolver mapped both
    // `ntdll!NtAllocateVirtualMemory` and `NtFreeVirtualMemory`
    // to `kOffReturnStatusNotImpl` — a 6-byte stub returning
    // `STATUS_NOT_IMPLEMENTED`. PE binaries that bypass kernel32
    // (CRT internals, anti-debug, JITs) and call the Nt
    // primitives directly would fail. Now they actually allocate
    // and free pages by routing through the same SYS_VMAP /
    // SYS_VUNMAP that backs `kernel32!VirtualAlloc` / `VirtualFree`.
    //
    // Win64 ABI for both: rcx, rdx, r8, r9 are arg regs; rsi
    // and rdi are callee-saved (so we push/pop them).
    // STATUS_NOT_IMPLEMENTED is 0xC00000BB; STATUS_NO_MEMORY is
    // 0xC0000017; STATUS_INVALID_PARAMETER is 0xC000000D.

    // --- NtAllocateVirtualMemory (offset 0x7E7, 36 bytes) ----
    // Win64: NTSTATUS NtAllocateVirtualMemory(
    // HANDLE rcx, // ProcessHandle (ignored — must be self)
    // PVOID* rdx, // BaseAddress (in/out)
    // ULONG_PTR r8, // ZeroBits (ignored)
    // PSIZE_T r9, // RegionSize (in/out)
    // ULONG [rsp+0x28], // AllocationType (ignored — always commit)
    // ULONG [rsp+0x30]) // Protect (ignored — RW+NX)
    //
    // Stub semantics: read *RegionSize, hand it to SYS_VMAP,
    // write the returned VA to *BaseAddress, leave *RegionSize
    // alone (kernel rounds up internally; v0 reports the
    // requested size). Returns STATUS_SUCCESS or STATUS_NO_MEMORY.
    0x57,                         // 0x7E7 push rdi
    0x56,                         // 0x7E8 push rsi
    0x49, 0x8B, 0x39,             // 0x7E9 mov rdi, [r9] ; size from *RegionSize
    0xB8, 0x1C, 0x00, 0x00, 0x00, // 0x7EC mov eax, 28 ; SYS_VMAP
    0xCD, 0x80,                   // 0x7F1 int 0x80
    0x48, 0x85, 0xC0,             // 0x7F3 test rax, rax ; 0 = OOM
    0x74, 0x0B,                   // 0x7F6 jz .fail (+11)
    0x48, 0x89, 0x02,             // 0x7F8 mov [rdx], rax ; *BaseAddress = VA
    0x49, 0x89, 0x39,             // 0x7FB mov [r9], rdi ; echo size back
    0x31, 0xC0,                   // 0x7FE xor eax, eax ; STATUS_SUCCESS
    0x5E,                         // 0x800 pop rsi
    0x5F,                         // 0x801 pop rdi
    0xC3,                         // 0x802 ret
    // .fail:
    0xB8, 0x17, 0x00, 0x00, 0xC0, // 0x803 mov eax, 0xC0000017 ; STATUS_NO_MEMORY
    0x5E,                         // 0x808 pop rsi
    0x5F,                         // 0x809 pop rdi
    0xC3,                         // 0x80A ret

    // --- NtFreeVirtualMemory (offset 0x80B, 33 bytes) --------
    // Win64: NTSTATUS NtFreeVirtualMemory(
    // HANDLE rcx, // ProcessHandle (ignored)
    // PVOID* rdx, // BaseAddress (in/out)
    // PSIZE_T r8, // RegionSize (in/out)
    // ULONG r9) // FreeType (ignored — always release)
    //
    // Stub semantics: read *BaseAddress and *RegionSize, hand
    // them to SYS_VUNMAP. Kernel returns 0 on success or non-
    // zero if the VA isn't in the per-process vmap arena.
    0x57,                         // 0x80B push rdi
    0x56,                         // 0x80C push rsi
    0x48, 0x8B, 0x3A,             // 0x80D mov rdi, [rdx] ; VA from *BaseAddress
    0x49, 0x8B, 0x30,             // 0x810 mov rsi, [r8] ; size from *RegionSize
    0xB8, 0x1D, 0x00, 0x00, 0x00, // 0x813 mov eax, 29 ; SYS_VUNMAP
    0xCD, 0x80,                   // 0x818 int 0x80
    0x48, 0x85, 0xC0,             // 0x81A test rax, rax
    0x75, 0x05,                   // 0x81D jnz .fail (+5)
    0x31, 0xC0,                   // 0x81F xor eax, eax ; STATUS_SUCCESS
    0x5E,                         // 0x821 pop rsi
    0x5F,                         // 0x822 pop rdi
    0xC3,                         // 0x823 ret
    // .fail:
    0xB8, 0x0D, 0x00, 0x00, 0xC0, // 0x824 mov eax, 0xC000000D ; STATUS_INVALID_PARAMETER
    0x5E,                         // 0x829 pop rsi
    0x5F,                         // 0x82A pop rdi
    0xC3,                         // 0x82B ret

    // === SYSTEMTIME / FILETIME pointer-output APIs =====
    //
    // The previous commit (8a8ce9b) deliberately skipped these:
    // a `mov eax,1; ret` stub leaves a caller-allocated SYSTEMTIME
    // uninitialised, and CRTs that consume it treat year=0 as a
    // sentinel that breaks date math. Real stub bytes now bridge
    // the Win64 calling convention (rcx, rdx) to our kernel
    // syscall ABI (rdi, rsi) via int 0x80 with SYS_GETTIME_ST (40),
    // SYS_ST_TO_FT (41), SYS_FT_TO_ST (42).

    // --- GetSystemTime / GetLocalTime (offset 0x82C, 11 bytes) -----
    // Win32 ABI: void GetSystemTime(LPSYSTEMTIME=rcx).
    // GetLocalTime aliases to the same stub — we have no timezone
    // database yet, so local == UTC.
    0x48, 0x89, 0xCF,             // 0x82C mov rdi, rcx ; SYSTEMTIME* out
    0xB8, 0x28, 0x00, 0x00, 0x00, // 0x82F mov eax, 40 ; SYS_GETTIME_ST
    0xCD, 0x80,                   // 0x834 int 0x80
    0xC3,                         // 0x836 ret

    // --- SystemTimeToFileTime (offset 0x837, 14 bytes) -----------
    // Win32 ABI: BOOL SystemTimeToFileTime(const SYSTEMTIME* = rcx,
    // LPFILETIME = rdx).
    // Kernel returns 0 on success in rax — matches Win32 TRUE
    // (non-zero). On EFAULT or invalid input, kernel writes
    // u64(-1) which is also non-zero; the caller can't tell the
    // difference at v0 granularity, but a well-behaved input
    // always succeeds.
    0x48, 0x89, 0xCF,             // 0x837 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x83A mov rsi, rdx
    0xB8, 0x29, 0x00, 0x00, 0x00, // 0x83D mov eax, 41 ; SYS_ST_TO_FT
    0xCD, 0x80,                   // 0x842 int 0x80
    0xC3,                         // 0x844 ret

    // --- FileTimeToSystemTime (offset 0x845, 14 bytes) -----------
    // Win32 ABI: BOOL FileTimeToSystemTime(const FILETIME* = rcx,
    // LPSYSTEMTIME = rdx).
    0x48, 0x89, 0xCF,             // 0x845 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x848 mov rsi, rdx
    0xB8, 0x2A, 0x00, 0x00, 0x00, // 0x84B mov eax, 42 ; SYS_FT_TO_ST
    0xCD, 0x80,                   // 0x850 int 0x80
    0xC3,                         // 0x852 ret

    // === real NTSTATUS-returning ntdll time/perf =========
    //
    // Unlike kernel32's BOOL-returning APIs, NtQuerySystemTime /
    // NtQueryPerformanceCounter return NTSTATUS (0 on success).
    // These dedicated stubs keep that contract exact.

    // --- NtQuerySystemTime (offset 0x853, 16 bytes) --------------
    // NT ABI: NTSTATUS NtQuerySystemTime(PLARGE_INTEGER out=rcx).
    // Fill *out via SYS_GETTIME_FT and return STATUS_SUCCESS (0).
    0x48, 0x89, 0xCF,             // 0x853 mov rdi, rcx
    0xB8, 0x11, 0x00, 0x00, 0x00, // 0x856 mov eax, 17 ; SYS_GETTIME_FT
    0xCD, 0x80,                   // 0x85B int 0x80 ; rax = FILETIME ticks
    0x48, 0x89, 0x01,             // 0x85D mov [rcx], rax
    0x31, 0xC0,                   // 0x860 xor eax, eax ; STATUS_SUCCESS
    0xC3,                         // 0x862 ret

    // --- NtQueryPerformanceCounter (offset 0x863, 28 bytes) ------
    // NT ABI:
    // NTSTATUS NtQueryPerformanceCounter(
    // PLARGE_INTEGER Counter=rcx, PLARGE_INTEGER Freq=rdx)
    // Counter is mandatory; Frequency is optional.
    0x48, 0x89, 0xCF,                         // 0x863 mov rdi, rcx
    0xB8, 0x12, 0x00, 0x00, 0x00,             // 0x866 mov eax, 18 ; SYS_NOW_NS
    0xCD, 0x80,                               // 0x86B int 0x80 ; rax = ns
    0x48, 0x89, 0x01,                         // 0x86D mov [rcx], rax
    0x48, 0x85, 0xD2,                         // 0x870 test rdx, rdx
    0x74, 0x07,                               // 0x873 jz .done
    0x48, 0xC7, 0x02, 0x00, 0xCA, 0x9A, 0x3B, // 0x875 mov qword [rdx], 1_000_000_000
    // .done:
    0x31, 0xC0, // 0x87C xor eax, eax ; STATUS_SUCCESS
    0xC3,       // 0x87E ret

    // === real CreateThread via SYS_THREAD_CREATE =====
    //
    // Win32: HANDLE CreateThread(
    // LPSECURITY_ATTRIBUTES lpThreadAttributes, // rcx (ignored)
    // SIZE_T dwStackSize, // rdx (ignored — kernel picks)
    // LPTHREAD_START_ROUTINE lpStartAddress, // r8
    // LPVOID lpParameter, // r9
    // DWORD dwCreationFlags, // [rsp+0x28] (ignored — always-run)
    // LPDWORD lpThreadId); // [rsp+0x30] (optional out)
    //
    // DuetOS: SYS_THREAD_CREATE (45) with start_va in rdi,
    // param in rsi. Returns handle or 0xFFFFFFFFFFFFFFFF on
    // failure. The Win32 contract is "handle or NULL on fail" —
    // we translate -1 to 0 at the tail.
    //
    // --- CreateThread (offset 0x87F, 39 bytes) -----------------
    // Win64 ABI: rdi + rsi are callee-saved — save/restore around
    // the syscall so callers that hold IAT slots in rdi (which
    // MSVC's code generator routinely does) survive the call.
    // Added after syscall_stress.exe hit a latent bug
    // where rdi was clobbered and main jumped through the wrecked
    // rdi into the thread proc directly.
    0x57,                         // 0x87F push rdi
    0x56,                         // 0x880 push rsi
    0x4C, 0x89, 0xC7,             // 0x881 mov rdi, r8 ; start
    0x4C, 0x89, 0xCE,             // 0x884 mov rsi, r9 ; param
    0xB8, 0x2D, 0x00, 0x00, 0x00, // 0x887 mov eax, 45 ; SYS_THREAD_CREATE
    0xCD, 0x80,                   // 0x88C int 0x80 ; rax = handle or -1
    // We pushed 16 bytes, so lpThreadId (originally at [rsp+0x30])
    // is now at [rsp+0x40].
    0x48, 0x8B, 0x4C, 0x24, 0x40, // 0x88E mov rcx, [rsp+0x40]
    0x48, 0x85, 0xC9,             // 0x893 test rcx, rcx
    0x74, 0x02,                   // 0x896 je +2 -> 0x89A
    0x89, 0x01,                   // 0x898 mov [rcx], eax
    // Translate -1 (any high bits set) to 0 for Win32 "NULL" handle
    // semantics.
    0x48, 0x83, 0xF8, 0xFF, // 0x89A cmp rax, -1
    0x75, 0x03,             // 0x89E jne +3 -> 0x8A3
    0x31, 0xC0,             // 0x8A0 xor eax, eax
    0x90,                   // 0x8A2 nop (padding so cmp/jne/xor lands exactly 3 bytes)
    0x5E,                   // 0x8A3 pop rsi
    0x5F,                   // 0x8A4 pop rdi
    0xC3,                   // 0x8A5 ret

    // --- ThreadExitTramp (offset 0x8A6, 6 bytes) ---------------
    // Landing site when a Win32 thread proc returns. DoThreadCreate
    // writes (kWin32ThunksVa + 0x8A2) to [stack_top - 8] so the
    // thread proc's final `ret` pops this VA into RIP. The thread
    // proc's return value is still in EAX (Win32 __stdcall). We
    // copy it to EDI (SYS_EXIT's first arg) then issue SYS_EXIT(0).
    // SYS_EXIT kills just this task — the process's other threads
    // (e.g. main waiting on the event) are unaffected. Noreturn.
    0x89, 0xC7, // 0x8A6 mov edi, eax ; thread retcode
    0x31, 0xC0, // 0x8A8 xor eax, eax ; SYS_EXIT = 0
    0xCD, 0x80, // 0x8AA int 0x80 ; noreturn

    // === =============================================

    // --- ExitThread (offset 0x8AC, 9 bytes) -------------------
    // Win32: void ExitThread(DWORD dwExitCode). rcx = exit code.
    // Maps to SYS_EXIT — kills only the calling task (just like
    // the ThreadExitTramp fallback) without disturbing the rest
    // of the process.
    0x48, 0x89, 0xCF, // 0x8AC mov rdi, rcx ; exit code
    0x31, 0xC0,       // 0x8AF xor eax, eax ; SYS_EXIT
    0xCD, 0x80,       // 0x8B1 int 0x80
    0x0F, 0x0B,       // 0x8B3 ud2 ; [[noreturn]]

    // --- OutputDebugStringA (offset 0x8B5, 13 bytes) ----------
    // Win32: void OutputDebugStringA(LPCSTR lpOutputString).
    // rcx = NUL-terminated ASCII string. Maps to SYS_DEBUG_PRINT
    // which does the strlen + bounce + serial emit kernel-side.
    // Win64 ABI: rdi is callee-saved — push/pop around the
    // syscall to preserve the caller's rdi.
    0x57,                         // 0x8B5 push rdi
    0x48, 0x89, 0xCF,             // 0x8B6 mov rdi, rcx ; str
    0xB8, 0x2E, 0x00, 0x00, 0x00, // 0x8B9 mov eax, 46 ; SYS_DEBUG_PRINT
    0xCD, 0x80,                   // 0x8BE int 0x80
    0x5F,                         // 0x8C0 pop rdi
    0xC3,                         // 0x8C1 ret

    // --- GetProcessTimes (offset 0x8C2, 44 bytes) -------------
    // Win32:
    // BOOL GetProcessTimes(HANDLE hProcess, // rcx ignored
    // LPFILETIME CreationTime, // rdx
    // LPFILETIME ExitTime, // r8
    // LPFILETIME KernelTime, // r9
    // LPFILETIME UserTime); // [rsp+0x28]
    // Aliased by GetThreadTimes (same shape). v0 just zeros all
    // four FILETIMEs and returns BOOL TRUE — callers that only
    // want to detect "API exists" proceed cleanly, callers that
    // divide-by-zero get the same garbage they'd get from a real
    // machine that hadn't run long enough.
    // Assumes each output pointer is non-NULL (Win32 doesn't spec
    // NULL-tolerance on these args); real callers always pass
    // valid FILETIMEs.
    0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x8C2 mov qword [rdx], 0
    0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x8C9 mov qword [r8], 0
    0x49, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x8D0 mov qword [r9], 0
    0x48, 0x8B, 0x4C, 0x24, 0x28,             // 0x8D7 mov rcx, [rsp+0x28]
    0x48, 0x85, 0xC9,                         // 0x8DC test rcx, rcx
    0x74, 0x07,                               // 0x8DF je +7 -> 0x8E8
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x8E1 mov qword [rcx], 0
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x8E8 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x8ED ret

    // --- GetSystemTimes (offset 0x8EE, 30 bytes) --------------
    // Win32:
    // BOOL GetSystemTimes(PFILETIME IdleTime, // rcx
    // PFILETIME KernelTime, // rdx
    // PFILETIME UserTime); // r8
    // v0 zeros rcx and rdx pointers when non-null, returns BOOL
    // TRUE. r8 (UserTime) is left untouched — stub-size budget,
    // and UserTime is less commonly consulted than Idle/Kernel.
    0x48, 0x85, 0xC9,                         // 0x8EE test rcx, rcx
    0x74, 0x07,                               // 0x8F1 je +7 -> 0x8FA
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0x8F3 mov qword [rcx], 0
    0x48, 0x85, 0xD2,                         // 0x8FA test rdx, rdx
    0x74, 0x07,                               // 0x8FD je +7 -> 0x906
    0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, // 0x8FF mov qword [rdx], 0
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x906 mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x90B ret

    // --- GlobalMemoryStatusEx (offset 0x90C, 16 bytes) --------
    // Win32: BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer).
    // rcx = user pointer. Maps to SYS_MEM_STATUS which does the
    // struct validation + populate server-side. Returns BOOL
    // TRUE on syscall success (rax=0), FALSE on failure (rax=-1).
    // The `inc rax` flips 0↔1 and -1↔0, which is exactly the
    // Win32 BOOL mapping we want. Saves rdi across the syscall
    // (callee-saved in Win64 ABI).
    0x57,                         // 0x90C push rdi
    0x48, 0x89, 0xCF,             // 0x90D mov rdi, rcx
    0xB8, 0x2F, 0x00, 0x00, 0x00, // 0x910 mov eax, 47 ; SYS_MEM_STATUS
    0xCD, 0x80,                   // 0x915 int 0x80
    0x48, 0xFF, 0xC0,             // 0x917 inc rax ; 0→1, -1→0
    0x5F,                         // 0x91A pop rdi
    0xC3,                         // 0x91B ret

    // --- WaitForMultipleObjects (offset 0x91C, 24 bytes) ------
    // Win32:
    // DWORD WaitForMultipleObjects(DWORD nCount, // rcx
    // const HANDLE *, // rdx
    // BOOL bWaitAll, // r8
    // DWORD dwMs); // r9
    // DuetOS: SYS_WAIT_MULTI with count=rdi, arr=rsi,
    // waitAll=rdx, timeout_ms=r10. Saves rdi+rsi across the
    // syscall (both callee-saved in Win64 ABI).
    0x57,                         // 0x91C push rdi
    0x56,                         // 0x91D push rsi
    0x48, 0x89, 0xCF,             // 0x91E mov rdi, rcx ; count
    0x48, 0x89, 0xD6,             // 0x921 mov rsi, rdx ; handle array
    0x4C, 0x89, 0xC2,             // 0x924 mov rdx, r8 ; waitAll
    0x4D, 0x89, 0xCA,             // 0x927 mov r10, r9 ; timeout
    0xB8, 0x30, 0x00, 0x00, 0x00, // 0x92A mov eax, 48 ; SYS_WAIT_MULTI
    0xCD, 0x80,                   // 0x92F int 0x80
    0x5E,                         // 0x931 pop rsi
    0x5F,                         // 0x932 pop rdi
    0xC3,                         // 0x933 ret

    // === =============================================

    // --- GetSystemInfo (offset 0x934, 13 bytes) ---------------
    // Win32: void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo).
    // rcx = user ptr. Maps to SYS_SYSTEM_INFO. Aliased by
    // GetNativeSystemInfo (same shape; WoW64 distinction doesn't
    // apply — we're native x86_64 already).
    0x57,                         // 0x934 push rdi
    0x48, 0x89, 0xCF,             // 0x935 mov rdi, rcx
    0xB8, 0x31, 0x00, 0x00, 0x00, // 0x938 mov eax, 49 ; SYS_SYSTEM_INFO
    0xCD, 0x80,                   // 0x93D int 0x80
    0x5F,                         // 0x93F pop rdi
    0xC3,                         // 0x940 ret

    // --- OutputDebugStringW (offset 0x941, 13 bytes) ---------
    // Win32: void OutputDebugStringW(LPCWSTR lpOutputString).
    // rcx = NUL-terminated UTF-16LE string. Maps to
    // SYS_DEBUG_PRINTW (kernel strips to ASCII + emits).
    0x57,                         // 0x941 push rdi
    0x48, 0x89, 0xCF,             // 0x942 mov rdi, rcx
    0xB8, 0x32, 0x00, 0x00, 0x00, // 0x945 mov eax, 50 ; SYS_DEBUG_PRINTW
    0xCD, 0x80,                   // 0x94A int 0x80
    0x5F,                         // 0x94C pop rdi
    0xC3,                         // 0x94D ret

    // --- FormatMessageA (offset 0x94E, 32 bytes) --------------
    // Win32:
    // DWORD FormatMessageA(DWORD flags, LPCVOID src, DWORD msgId,
    // DWORD lang, LPSTR buf, DWORD nSize,
    // va_list *args);
    // v0: writes "Error.\n\0" (7 chars + NUL) into lpBuffer if
    // non-NULL, returns 7. If lpBuffer is NULL, returns 0.
    // This lets callers that print the buffer see a stable
    // placeholder instead of random memory, and callers that
    // gate on "non-zero return means message decoded" take the
    // happy path. No flag handling — a follow-up can add
    // FORMAT_MESSAGE_ALLOCATE_BUFFER + hex-formatting of msgId.
    0x48, 0x8B, 0x44, 0x24, 0x28, // 0x94E mov rax, [rsp+0x28] ; lpBuffer
    0x48, 0x85, 0xC0,             // 0x953 test rax, rax
    0x74, 0x13,                   // 0x956 je +19 -> 0x96B (null_buf)
    // Write "Erro" (0x6F727245) then "r.\n\0" (0x000A2E72) at [rax+4]
    0xC7, 0x00, 0x45, 0x72, 0x72, 0x6F,       // 0x958 mov dword [rax], 0x6F727245
    0xC7, 0x40, 0x04, 0x72, 0x2E, 0x0A, 0x00, // 0x95E mov dword [rax+4], 0x000A2E72
    0xB8, 0x07, 0x00, 0x00, 0x00,             // 0x965 mov eax, 7 (chars written)
    0xC3,                                     // 0x96A ret
    // null_buf path
    0x31, 0xC0, // 0x96B xor eax, eax
    0xC3,       // 0x96D ret

    // --- GetConsoleScreenBufferInfo (offset 0x96E, 54 bytes) --
    // Win32:
    // BOOL GetConsoleScreenBufferInfo(HANDLE hOut,
    // PCONSOLE_SCREEN_BUFFER_INFO p);
    // rdx = buffer. 22-byte layout:
    // 0x00 COORD dwSize (80, 25)
    // 0x04 COORD dwCursorPosition (0, 0)
    // 0x08 WORD wAttributes (0x07 white-on-black)
    // 0x0A SMALL_RECT srWindow (L=0, T=0, R=79, B=24)
    // 0x12 COORD dwMaximumWindowSize (80, 25)
    // Returns TRUE unless rdx is NULL.
    0x48, 0x85, 0xD2, // 0x96E test rdx, rdx
    0x74, 0x2E,       // 0x971 je +46 -> 0x9A1 (fail)
    // dwSize at [rdx] = (X=80, Y=25) -> 0x00190050
    0xC7, 0x02, 0x50, 0x00, 0x19, 0x00, // 0x973 mov dword [rdx], 0x00190050
    // dwCursorPosition at [rdx+4] = 0
    0xC7, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, // 0x979 mov dword [rdx+4], 0
    // wAttributes at [rdx+8] = 0x0007
    0x66, 0xC7, 0x42, 0x08, 0x07, 0x00, // 0x980 mov word [rdx+8], 7
    // srWindow L,T at [rdx+10] = 0
    0xC7, 0x42, 0x0A, 0x00, 0x00, 0x00, 0x00, // 0x986 mov dword [rdx+10], 0
    // srWindow R,B at [rdx+14] = (79, 24) -> 0x0018004F
    0xC7, 0x42, 0x0E, 0x4F, 0x00, 0x18, 0x00, // 0x98D mov dword [rdx+14], 0x0018004F
    // dwMaximumWindowSize at [rdx+18] = (80, 25) -> 0x00190050
    0xC7, 0x42, 0x12, 0x50, 0x00, 0x19, 0x00, // 0x994 mov dword [rdx+18], 0x00190050
    0xB8, 0x01, 0x00, 0x00, 0x00,             // 0x99B mov eax, 1 (BOOL TRUE)
    0xC3,                                     // 0x9A0 ret
    0x31, 0xC0,                               // 0x9A1 xor eax, eax
    0xC3,                                     // 0x9A3 ret

    // === =============================================

    // --- RaiseException (offset 0x9A4, 9 bytes) ---------------
    // Win32:
    // void RaiseException(DWORD dwExceptionCode, DWORD flags,
    // DWORD nArgs, const ULONG_PTR *args);
    // v0 has no SEH, so any RaiseException is fatal — route to
    // SYS_EXIT with rcx (exception code) as the exit code.
    0x48, 0x89, 0xCF, // 0x9A4 mov rdi, rcx
    0x31, 0xC0,       // 0x9A7 xor eax, eax
    0xCD, 0x80,       // 0x9A9 int 0x80
    0x0F, 0x0B,       // 0x9AB ud2 ; [[noreturn]]

    // --- DecodePointer / EncodePointer (offset 0x9AD, 4 bytes) --
    // Win32: PVOID DecodePointer(PVOID Ptr); EncodePointer same.
    // Windows uses these for process-wide XOR-with-a-secret
    // obfuscation of function pointers (ASLR defense-in-depth).
    // v0 has no process-wide secret → identity preserves the
    // Encode/Decode round-trip used by MSVC's CRT.
    0x48, 0x89, 0xC8, // 0x9AD mov rax, rcx
    0xC3,             // 0x9B0 ret

    // === =============================================

    // --- CreateSemaphoreW (offset 0x9B1, 27 bytes) ------------
    // Win32:
    // HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES, // rcx (ignored)
    // LONG lInitial, // rdx
    // LONG lMaximum, // r8
    // LPCWSTR lpName); // r9 (ignored)
    // Maps to SYS_SEM_CREATE(initial, max). Translates kernel
    // -1 to Win32 NULL handle. CreateSemaphoreA + CreateSemaphoreExW
    // are wired to the same stub.
    0x57,                         // 0x9B1 push rdi
    0x56,                         // 0x9B2 push rsi
    0x48, 0x89, 0xD7,             // 0x9B3 mov rdi, rdx ; initial
    0x4C, 0x89, 0xC6,             // 0x9B6 mov rsi, r8 ; max
    0xB8, 0x33, 0x00, 0x00, 0x00, // 0x9B9 mov eax, 51 ; SYS_SEM_CREATE
    0xCD, 0x80,                   // 0x9BE int 0x80
    0x48, 0x83, 0xF8, 0xFF,       // 0x9C0 cmp rax, -1
    0x75, 0x03,                   // 0x9C4 jne +3 -> 0x9C9 (pop rsi)
    0x31, 0xC0,                   // 0x9C6 xor eax, eax
    0x90,                         // 0x9C8 nop (padding so jne target lands at 0x9C9)
    0x5E,                         // 0x9C9 pop rsi
    0x5F,                         // 0x9CA pop rdi
    0xC3,                         // 0x9CB ret

    // --- ReleaseSemaphore (offset 0x9CC, 29 bytes) ------------
    // Win32:
    // BOOL ReleaseSemaphore(HANDLE hSem, // rcx
    // LONG lReleaseCount, // rdx
    // LPLONG lpPreviousCount // r8 (optional)
    // );
    // int 0x80 preserves r8 (isr_common pushes/pops all GPRs)
    // so we can still read it after the syscall without a save.
    0x57,                         // 0x9CC push rdi
    0x56,                         // 0x9CD push rsi
    0x48, 0x89, 0xCF,             // 0x9CE mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x9D1 mov rsi, rdx
    0xB8, 0x34, 0x00, 0x00, 0x00, // 0x9D4 mov eax, 52 ; SYS_SEM_RELEASE
    0xCD, 0x80,                   // 0x9D9 int 0x80
    0x4D, 0x85, 0xC0,             // 0x9DB test r8, r8 ; lpPreviousCount != NULL?
    0x74, 0x03,                   // 0x9DE je +3 -> 0x9E3 (inc rax)
    0x41, 0x89, 0x00,             // 0x9E0 mov [r8], eax
    0x48, 0xFF, 0xC0,             // 0x9E3 inc rax ; -1 -> 0 FALSE; prev -> prev+1 TRUE
    0x5E,                         // 0x9E6 pop rsi
    0x5F,                         // 0x9E7 pop rdi
    0xC3,                         // 0x9E8 ret

    // --- WaitForSingleObject v3 (offset 0x9E9, 94 bytes) ------
    // v2 + semaphore range (0x500..0x507 → SYS_SEM_WAIT).
    // Bumps the `kOffWaitForObj2` aliases over to v3 via the
    // import table so every caller gets semaphore-aware wait.
    0x57,                               // 0x9E9 push rdi
    0x56,                               // 0x9EA push rsi
    0x48, 0x89, 0xC8,                   // 0x9EB mov rax, rcx
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0x9EE sub rax, 0x200
    0x48, 0x83, 0xF8, 0x08,             // 0x9F4 cmp rax, 8
    0x72, 0x1D,                         // 0x9F8 jb .mutex (+29 -> 0xA17)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0x9FA sub rax, 0x100 (total 0x300 relative)
    0x48, 0x83, 0xF8, 0x08,             // 0xA00 cmp rax, 8
    0x72, 0x21,                         // 0xA04 jb .event (+33 -> 0xA27)
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0xA06 sub rax, 0x200 (total 0x500 relative)
    0x48, 0x83, 0xF8, 0x08,             // 0xA0C cmp rax, 8
    0x72, 0x25,                         // 0xA10 jb .sem (+37 -> 0xA37)
    // .pseudo path (handle not in any known range)
    0x31, 0xC0, // 0xA12 xor eax, eax ; WAIT_OBJECT_0 for unknown
    0x5E,       // 0xA14 pop rsi
    0x5F,       // 0xA15 pop rdi
    0xC3,       // 0xA16 ret
    // .mutex (offset 0xA17)
    0x48, 0x89, 0xCF,             // 0xA17 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA1A mov rsi, rdx
    0xB8, 0x1A, 0x00, 0x00, 0x00, // 0xA1D mov eax, 26 (SYS_MUTEX_WAIT)
    0xCD, 0x80,                   // 0xA22 int 0x80
    0x5E,                         // 0xA24 pop rsi
    0x5F,                         // 0xA25 pop rdi
    0xC3,                         // 0xA26 ret
    // .event (offset 0xA27)
    0x48, 0x89, 0xCF,             // 0xA27 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA2A mov rsi, rdx
    0xB8, 0x21, 0x00, 0x00, 0x00, // 0xA2D mov eax, 33 (SYS_EVENT_WAIT)
    0xCD, 0x80,                   // 0xA32 int 0x80
    0x5E,                         // 0xA34 pop rsi
    0x5F,                         // 0xA35 pop rdi
    0xC3,                         // 0xA36 ret
    // .sem (offset 0xA37)
    0x48, 0x89, 0xCF,             // 0xA37 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA3A mov rsi, rdx
    0xB8, 0x35, 0x00, 0x00, 0x00, // 0xA3D mov eax, 53 (SYS_SEM_WAIT)
    0xCD, 0x80,                   // 0xA42 int 0x80
    0x5E,                         // 0xA44 pop rsi
    0x5F,                         // 0xA45 pop rdi
    0xC3,                         // 0xA46 ret

    // === =============================================

    // --- WaitForSingleObject v4 (offset 0xA47, 122 bytes) -----
    // v3 + a fourth range (0x400..0x407, thread handles) that
    // dispatches to SYS_THREAD_WAIT. Now WaitForSingleObject on
    // a CreateThread handle actually blocks until the thread
    // exits rather than the v3 pseudo-signaled fast path.
    //
    // Dispatch order is still "cheapest first": mutex, event,
    // thread, semaphore. Unknown handles fall through to the
    // pseudo-signaled path for backward compatibility.
    0x57,                               // 0xA47 push rdi
    0x56,                               // 0xA48 push rsi
    0x48, 0x89, 0xC8,                   // 0xA49 mov rax, rcx
    0x48, 0x2D, 0x00, 0x02, 0x00, 0x00, // 0xA4C sub rax, 0x200
    0x48, 0x83, 0xF8, 0x08,             // 0xA52 cmp rax, 8
    0x72, 0x29,                         // 0xA56 jb .mutex (+41 -> 0xA81)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0xA58 sub rax, 0x100 (H - 0x300)
    0x48, 0x83, 0xF8, 0x08,             // 0xA5E cmp rax, 8
    0x72, 0x2D,                         // 0xA62 jb .event (+45 -> 0xA91)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0xA64 sub rax, 0x100 (H - 0x400)
    0x48, 0x83, 0xF8, 0x08,             // 0xA6A cmp rax, 8
    0x72, 0x31,                         // 0xA6E jb .thread (+49 -> 0xAA1)
    0x48, 0x2D, 0x00, 0x01, 0x00, 0x00, // 0xA70 sub rax, 0x100 (H - 0x500)
    0x48, 0x83, 0xF8, 0x08,             // 0xA76 cmp rax, 8
    0x72, 0x35,                         // 0xA7A jb .sem (+53 -> 0xAB1)
    // .pseudo: unknown handle -> WAIT_OBJECT_0
    0x31, 0xC0, // 0xA7C xor eax, eax
    0x5E,       // 0xA7E pop rsi
    0x5F,       // 0xA7F pop rdi
    0xC3,       // 0xA80 ret
    // .mutex (offset 0xA81)
    0x48, 0x89, 0xCF,             // 0xA81 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA84 mov rsi, rdx
    0xB8, 0x1A, 0x00, 0x00, 0x00, // 0xA87 mov eax, 26 (SYS_MUTEX_WAIT)
    0xCD, 0x80,                   // 0xA8C int 0x80
    0x5E,                         // 0xA8E pop rsi
    0x5F,                         // 0xA8F pop rdi
    0xC3,                         // 0xA90 ret
    // .event (offset 0xA91)
    0x48, 0x89, 0xCF,             // 0xA91 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xA94 mov rsi, rdx
    0xB8, 0x21, 0x00, 0x00, 0x00, // 0xA97 mov eax, 33 (SYS_EVENT_WAIT)
    0xCD, 0x80,                   // 0xA9C int 0x80
    0x5E,                         // 0xA9E pop rsi
    0x5F,                         // 0xA9F pop rdi
    0xC3,                         // 0xAA0 ret
    // .thread (offset 0xAA1)
    0x48, 0x89, 0xCF,             // 0xAA1 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xAA4 mov rsi, rdx
    0xB8, 0x36, 0x00, 0x00, 0x00, // 0xAA7 mov eax, 54 (SYS_THREAD_WAIT)
    0xCD, 0x80,                   // 0xAAC int 0x80
    0x5E,                         // 0xAAE pop rsi
    0x5F,                         // 0xAAF pop rdi
    0xC3,                         // 0xAB0 ret
    // .sem (offset 0xAB1)
    0x48, 0x89, 0xCF,             // 0xAB1 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xAB4 mov rsi, rdx
    0xB8, 0x35, 0x00, 0x00, 0x00, // 0xAB7 mov eax, 53 (SYS_SEM_WAIT)
    0xCD, 0x80,                   // 0xABC int 0x80
    0x5E,                         // 0xABE pop rsi
    0x5F,                         // 0xABF pop rdi
    0xC3,                         // 0xAC0 ret

    // === =============================================

    // --- GetStartupInfo{W,A} (offset 0xAC1, 24 bytes) ---------
    // Win32: void GetStartupInfo{A,W}(LPSTARTUPINFO{A,W} p).
    // STARTUPINFO is 104 bytes (both A and W) with cb at offset
    // 0. v0 populates a zero-filled struct with cb = 104 and
    // leaves every other field zero — programs that gate reads
    // on dwFlags (= 0 → no STARTF_USESTDHANDLES, etc.) see a
    // consistent "no startup info" state and don't read stale
    // stack memory. Previously aliased to kOffCritSecNop which
    // left the caller's buffer uninitialised — real Windows
    // code crashes reading lpDesktop / hStdInput as a wild
    // pointer.
    //
    // Win64: rdi is callee-saved; saved + restored around the
    // rep stosq. rcx is caller-saved, but we pop it back into
    // rcx after the rep stosq so [rcx] can write cb — cheaper
    // than holding it in rsi.
    0x57,                               // 0xAC1 push rdi
    0x48, 0x89, 0xCF,                   // 0xAC2 mov rdi, rcx
    0x51,                               // 0xAC5 push rcx
    0x31, 0xC0,                         // 0xAC6 xor eax, eax
    0xB9, 0x0D, 0x00, 0x00, 0x00,       // 0xAC8 mov ecx, 13 ; 104/8 qwords
    0xF3, 0x48, 0xAB,                   // 0xACD rep stosq
    0x59,                               // 0xAD0 pop rcx
    0xC7, 0x01, 0x68, 0x00, 0x00, 0x00, // 0xAD1 mov dword [rcx], 104 (cb)
    0x5F,                               // 0xAD7 pop rdi
    0xC3,                               // 0xAD8 ret

    // === =============================================

    // --- GetExitCodeThread real (offset 0xAD9, 20 bytes) ------
    // Win32: BOOL GetExitCodeThread(HANDLE=rcx, LPDWORD Exit=rdx).
    // Supersedes the stub at kOffGetExitCodeThread which
    // hard-coded STILL_ACTIVE. Routes to SYS_THREAD_EXIT_CODE
    // which reads Process.win32_threads[slot].exit_code — kept
    // at STILL_ACTIVE (0x103) until the task's SYS_EXIT path
    // stashes the real rdi value there.
    //
    // Returns BOOL TRUE always. If the handle is invalid the
    // syscall returns -1 and we write -1 into *Exit — callers
    // that interpret the BOOL will succeed, callers that look at
    // the numeric exit code will see 0xFFFFFFFF (bogus but
    // non-fatal).
    0x57,                         // 0xAD9 push rdi
    0x48, 0x89, 0xCF,             // 0xADA mov rdi, rcx
    0xB8, 0x37, 0x00, 0x00, 0x00, // 0xADD mov eax, 55 (SYS_THREAD_EXIT_CODE)
    0xCD, 0x80,                   // 0xAE2 int 0x80
    0x89, 0x02,                   // 0xAE4 mov [rdx], eax
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xAE6 mov eax, 1 (BOOL TRUE)
    0x5F,                         // 0xAEB pop rdi
    0xC3,                         // 0xAEC ret

    // === =============================================

    // --- InterlockedAnd (offset 0xAED, 16 bytes) --------------
    // Win32: LONG InterlockedAnd(LONG volatile *Target=rcx,
    // LONG Value=edx).
    // Returns the ORIGINAL value of *Target. Standard CAS loop:
    // do { old = *t; new = old & v; } while (!cas(t, old, new));
    // LOCK CMPXCHG is serialised across CPUs and acts as a full
    // barrier — correct under both SMP and single-CPU with a
    // preemptive timer interrupt.
    0x8B, 0x01,                   // 0xAED mov eax, [rcx] ; old
    0x41, 0x89, 0xC0,             // 0xAEF mov r8d, eax ; new = old
    0x41, 0x21, 0xD0,             // 0xAF2 and r8d, edx ; new &= value
    0xF0, 0x44, 0x0F, 0xB1, 0x01, // 0xAF5 lock cmpxchg [rcx], r8d
    0x75, 0xF1,                   // 0xAFA jne -15 -> 0xAED (retry)
    0xC3,                         // 0xAFC ret

    // --- InterlockedOr (offset 0xAFD, 16 bytes) ---------------
    0x8B, 0x01,                   // 0xAFD mov eax, [rcx]
    0x41, 0x89, 0xC0,             // 0xAFF mov r8d, eax
    0x41, 0x09, 0xD0,             // 0xB02 or r8d, edx
    0xF0, 0x44, 0x0F, 0xB1, 0x01, // 0xB05 lock cmpxchg [rcx], r8d
    0x75, 0xF1,                   // 0xB0A jne -15 -> 0xAFD
    0xC3,                         // 0xB0C ret

    // --- InterlockedXor (offset 0xB0D, 16 bytes) --------------
    0x8B, 0x01,                   // 0xB0D mov eax, [rcx]
    0x41, 0x89, 0xC0,             // 0xB0F mov r8d, eax
    0x41, 0x31, 0xD0,             // 0xB12 xor r8d, edx
    0xF0, 0x44, 0x0F, 0xB1, 0x01, // 0xB15 lock cmpxchg [rcx], r8d
    0x75, 0xF1,                   // 0xB1A jne -15 -> 0xB0D
    0xC3,                         // 0xB1C ret

    // --- InterlockedAnd64 (offset 0xB1D, 17 bytes) ------------
    // 64-bit operand — REX.W on all four instructions.
    0x48, 0x8B, 0x01,             // 0xB1D mov rax, [rcx]
    0x49, 0x89, 0xC0,             // 0xB20 mov r8, rax
    0x49, 0x21, 0xD0,             // 0xB23 and r8, rdx
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xB26 lock cmpxchg [rcx], r8
    0x75, 0xF0,                   // 0xB2B jne -16 -> 0xB1D
    0xC3,                         // 0xB2D ret

    // --- InterlockedOr64 (offset 0xB2E, 17 bytes) -------------
    0x48, 0x8B, 0x01,             // 0xB2E mov rax, [rcx]
    0x49, 0x89, 0xC0,             // 0xB31 mov r8, rax
    0x49, 0x09, 0xD0,             // 0xB34 or r8, rdx
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xB37 lock cmpxchg [rcx], r8
    0x75, 0xF0,                   // 0xB3C jne -16 -> 0xB2E
    0xC3,                         // 0xB3E ret

    // --- InterlockedXor64 (offset 0xB3F, 17 bytes) ------------
    0x48, 0x8B, 0x01,             // 0xB3F mov rax, [rcx]
    0x49, 0x89, 0xC0,             // 0xB42 mov r8, rax
    0x49, 0x31, 0xD0,             // 0xB45 xor r8, rdx
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xB48 lock cmpxchg [rcx], r8
    0x75, 0xF0,                   // 0xB4D jne -16 -> 0xB3F
    0xC3,                         // 0xB4F ret

    // === ==============================================

    // --- EnterCriticalSection (offset 0xB50, 50 bytes) --------
    // Win32: void EnterCriticalSection(LPCRITICAL_SECTION = rcx).
    //
    // CRITICAL_SECTION layout we impose on the caller's 40-byte
    // struct (InitializeCriticalSection already zero-fills it):
    // [rcx+0x00] u64 owner_tid (0 = unheld)
    // [rcx+0x08] u64 recursion
    // [rcx+0x10..0x28] unused
    //
    // Algorithm:
    // 1. rbx <- rcx (rbx is callee-saved in Win64; we need a
    // register that survives int 0x80).
    // 2. r8 <- our task id via SYS_GETPID.
    // 3. lock cmpxchg: if owner == 0, owner := r8. ZF=1 -> took.
    // 4. If not, check owner == r8 (recursive acquire).
    // 5. Otherwise SYS_YIELD and retry.
    //
    // Win64 ABI: rbx and rsi/rdi are callee-saved; the int 0x80
    // syscall path preserves all but rax. We push/pop rbx around
    // the body.
    0x53,             // 0xB50 push rbx
    0x48, 0x89, 0xCB, // 0xB51 mov rbx, rcx ; save lpcs
    0x6A, 0x01,       // 0xB54 push 1
    0x58,             // 0xB56 pop rax ; rax = SYS_GETPID
    0xCD, 0x80,       // 0xB57 int 0x80 ; rax = TID
    0x49, 0x89, 0xC0, // 0xB59 mov r8, rax ; r8 = our TID
    // .retry (abs 0xB5C):
    0x31, 0xC0,                   // 0xB5C xor eax, eax ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x03, // 0xB5E lock cmpxchg [rbx], r8
    0x74, 0x0C,                   // 0xB63 je .took (+0x0C -> 0xB71)
    0x4C, 0x39, 0x03,             // 0xB65 cmp [rbx], r8 ; owner == us?
    0x74, 0x11,                   // 0xB68 je .recursive (+0x11 -> 0xB7B)
    0x6A, 0x03,                   // 0xB6A push 3
    0x58,                         // 0xB6C pop rax ; rax = SYS_YIELD
    0xCD, 0x80,                   // 0xB6D int 0x80
    0xEB, 0xEB,                   // 0xB6F jmp .retry (-0x15 -> 0xB5C)
    // .took (abs 0xB71): first acquire — recursion := 1.
    0x48, 0xC7, 0x43, 0x08, 0x01, 0x00, 0x00, 0x00, // 0xB71 mov qword [rbx+8], 1
    0x5B,                                           // 0xB79 pop rbx
    0xC3,                                           // 0xB7A ret
    // .recursive (abs 0xB7B): already held by us — bump.
    0x48, 0xFF, 0x43, 0x08, // 0xB7B inc qword [rbx+8]
    0x5B,                   // 0xB7F pop rbx
    0xC3,                   // 0xB80 ret

    // --- LeaveCriticalSection (offset 0xB81, 14 bytes) --------
    // Win32: void LeaveCriticalSection(LPCRITICAL_SECTION = rcx).
    // Decrement recursion; on zero, clear owner so the next
    // acquire wins the cmpxchg. Caller is assumed to hold — a
    // bogus caller underflows recursion and never re-zeroes
    // owner (matches Windows: "bad things happen").
    0x48, 0xFF, 0x49, 0x08,                   // 0xB81 dec qword [rcx+8]
    0x75, 0x07,                               // 0xB85 jnz .done (+7 -> 0xB8E)
    0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, // 0xB87 mov qword [rcx], 0
    // .done (abs 0xB8E):
    0xC3, // 0xB8E ret

    // === ==============================================

    // --- InitializeSRWLock (offset 0xB8F, 6 bytes) ------------
    // Win32: void InitializeSRWLock(PSRWLOCK = rcx). Zero the
    // 8-byte slot. Critical even though SRWLOCKs are sometimes
    // static-init'd to zero — stack-allocated SRWLOCKs hold
    // garbage until explicitly initialised.
    0x31, 0xC0,       // 0xB8F xor eax, eax
    0x48, 0x89, 0x01, // 0xB91 mov qword [rcx], rax
    0xC3,             // 0xB94 ret

    // --- AcquireSRWLockExclusive (offset 0xB95, 30 bytes) -----
    // Win32: void AcquireSRWLockExclusive(PSRWLOCK = rcx). Same
    // spin-yield pattern as EnterCriticalSection but no
    // recursion tracking — SRW locks are NOT reentrant. If a
    // thread tries to acquire the same SRWLOCK twice the second
    // call deadlocks. That's the documented Win32 contract.
    0x53,             // 0xB95 push rbx
    0x48, 0x89, 0xCB, // 0xB96 mov rbx, rcx
    0x6A, 0x01,       // 0xB99 push 1
    0x58,             // 0xB9B pop rax ; SYS_GETPID
    0xCD, 0x80,       // 0xB9C int 0x80 ; rax = TID
    0x49, 0x89, 0xC0, // 0xB9E mov r8, rax ; r8 = our TID
    // .retry (abs 0xBA1):
    0x31, 0xC0,                   // 0xBA1 xor eax, eax ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x03, // 0xBA3 lock cmpxchg [rbx], r8
    0x74, 0x07,                   // 0xBA8 je .done (+7 -> 0xBB1)
    0x6A, 0x03,                   // 0xBAA push 3
    0x58,                         // 0xBAC pop rax ; SYS_YIELD
    0xCD, 0x80,                   // 0xBAD int 0x80
    0xEB, 0xF0,                   // 0xBAF jmp .retry (-16 -> 0xBA1)
    // .done (abs 0xBB1):
    0x5B, // 0xBB1 pop rbx
    0xC3, // 0xBB2 ret

    // --- ReleaseSRWLockExclusive (offset 0xBB3, 6 bytes) ------
    // Win32: void ReleaseSRWLockExclusive(PSRWLOCK = rcx). Zero
    // the slot so the next acquirer wins the cmpxchg. `mov` is
    // atomic on aligned 8-byte stores on x86_64; no `lock`
    // prefix needed.
    0x31, 0xC0,       // 0xBB3 xor eax, eax
    0x48, 0x89, 0x01, // 0xBB5 mov qword [rcx], rax
    0xC3,             // 0xBB8 ret

    // --- TryAcquireSRWLockExclusive (offset 0xBB9, 22 bytes) --
    // Win32: BOOLEAN TryAcquireSRWLockExclusive(PSRWLOCK = rcx).
    // Single cmpxchg; no spin. Returns 1 on success, 0 on
    // contention. Uses setz to materialise ZF as the low byte of
    // rax; the existing binding to kOffReturnOne (always 1) was
    // dishonest and masked real contention.
    0x6A, 0x01,                   // 0xBB9 push 1
    0x58,                         // 0xBBB pop rax ; SYS_GETPID
    0xCD, 0x80,                   // 0xBBC int 0x80 ; rax = TID
    0x49, 0x89, 0xC0,             // 0xBBE mov r8, rax ; r8 = our TID
    0x31, 0xC0,                   // 0xBC1 xor eax, eax ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x01, // 0xBC3 lock cmpxchg [rcx], r8
    0x0F, 0x94, 0xC0,             // 0xBC8 setz al ; al = ZF
    0x0F, 0xB6, 0xC0,             // 0xBCB movzx eax, al ; eax = BOOL
    0xC3,                         // 0xBCE ret

    // === ==============================================

    // --- RtlTryEnterCriticalSection (offset 0xBCF, 56 bytes) --
    // Win32: BOOL TryEnterCriticalSection(LPCRITICAL_SECTION = rcx).
    // Same CRITICAL_SECTION layout as EnterCriticalSection. Try
    // acquire once; on success (including recursive re-acquire)
    // return 1, otherwise return 0 WITHOUT blocking. Previously
    // bound to kOffReturnOne which always claimed success.
    0x53,                         // 0xBCF push rbx
    0x48, 0x89, 0xCB,             // 0xBD0 mov rbx, rcx
    0x6A, 0x01,                   // 0xBD3 push 1
    0x58,                         // 0xBD5 pop rax ; SYS_GETPID
    0xCD, 0x80,                   // 0xBD6 int 0x80 ; rax = TID
    0x49, 0x89, 0xC0,             // 0xBD8 mov r8, rax ; r8 = TID
    0x31, 0xC0,                   // 0xBDB xor eax, eax ; expected = 0
    0xF0, 0x4C, 0x0F, 0xB1, 0x03, // 0xBDD lock cmpxchg [rbx], r8
    0x74, 0x09,                   // 0xBE2 je .took (+9 -> 0xBED)
    0x4C, 0x39, 0x03,             // 0xBE4 cmp [rbx], r8
    0x74, 0x13,                   // 0xBE7 je .recursive (+0x13 -> 0xBFC)
    0x31, 0xC0,                   // 0xBE9 xor eax, eax ; not-taken: return 0
    0x5B,                         // 0xBEB pop rbx
    0xC3,                         // 0xBEC ret
    // .took (abs 0xBED):
    0x48, 0xC7, 0x43, 0x08, 0x01, 0x00, 0x00, 0x00, // 0xBED mov qword [rbx+8], 1
    0xB8, 0x01, 0x00, 0x00, 0x00,                   // 0xBF5 mov eax, 1
    0x5B,                                           // 0xBFA pop rbx
    0xC3,                                           // 0xBFB ret
    // .recursive (abs 0xBFC):
    0x48, 0xFF, 0x43, 0x08,       // 0xBFC inc qword [rbx+8]
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC00 mov eax, 1
    0x5B,                         // 0xC05 pop rbx
    0xC3,                         // 0xC06 ret

    // === ==============================================

    // --- SetUnhandledExceptionFilter (offset 0xC07, 12 bytes) -
    // Win32: LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
    // LPTOP_LEVEL_EXCEPTION_FILTER newFilter = rcx);
    // Returns the previous filter. xchg on a memory operand is
    // implicitly `lock`ed on x86, so this is a single atomic swap:
    // caller's rcx lands in the proc-env slot; the previous value
    // ends up in rcx, which we copy into rax to return.
    //
    // The imm32 0x65000600 fits in 32 bits and `mov eax, imm32`
    // zero-extends to rax — saves 5 bytes vs `mov rax, imm64`.
    0xB8, 0x00, 0x06, 0x00, 0x65, // 0xC07 mov eax, 0x65000600 ; &proc_env.unhandled
    0x48, 0x87, 0x08,             // 0xC0C xchg qword [rax], rcx
    0x48, 0x89, 0xC8,             // 0xC0F mov rax, rcx ; return old
    0xC3,                         // 0xC12 ret

    // --- UnhandledExceptionFilter (offset 0xC13, 21 bytes) ----
    // Win32: LONG UnhandledExceptionFilter(EXCEPTION_POINTERS* = rcx).
    // Load the stored filter; if non-null, TAIL-call it (the
    // filter's signature matches ours exactly, and tail-call
    // inherits our caller's shadow space + doesn't grow the
    // stack). If null, return EXCEPTION_EXECUTE_HANDLER (= 1),
    // Windows's documented "no top-level filter" default — the
    // caller (CRT's _seh_filter_exe or similar) then proceeds
    // to terminate the process via the standard SEH path.
    0xB8, 0x00, 0x06, 0x00, 0x65, // 0xC13 mov eax, 0x65000600
    0x48, 0x8B, 0x00,             // 0xC18 mov rax, [rax] ; load filter
    0x48, 0x85, 0xC0,             // 0xC1B test rax, rax
    0x74, 0x02,                   // 0xC1E jz .default (+2 -> 0xC22)
    0xFF, 0xE0,                   // 0xC20 jmp rax ; tail-call filter
    // .default (abs 0xC22):
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC22 mov eax, 1 ; EXCEPTION_EXECUTE_HANDLER
    0xC3,                         // 0xC27 ret

    // === ==============================================

    // --- InitOnceExecuteOnce (offset 0xC28, 87 bytes) ---------
    // Win32: BOOL InitOnceExecuteOnce(
    // PINIT_ONCE InitOnce = rcx,
    // PINIT_ONCE_FN InitFn = rdx,
    // PVOID Parameter = r8,
    // LPVOID *Context = r9);
    //
    // INIT_ONCE is an 8-byte slot we interpret as:
    // 0 = untouched
    // 1 = initialiser running
    // 2 = done
    //
    // Single atomic CAS 0->1 picks exactly one thread as the
    // initialiser. Losers spin-yield on the slot until it reaches
    // 2. The InitFn signature matches the arg-shifted version of
    // ours: BOOL InitFn(PINIT_ONCE=rcx, PVOID Parameter=rdx,
    // PVOID* Context=r8). Our rdx/r8/r9 shift one slot left into
    // rcx/rdx/r8 before the call. We hold InitOnce in rbx, InitFn
    // in rdi (both callee-saved) so the shuffle doesn't lose
    // state.
    //
    // Null-InitFn fast path: legitimately used as "mark this
    // INIT_ONCE complete without running anything." Skipping the
    // call also avoids CALL-to-0 #PF-killing the task, which is
    // how syscall-stress's `InitOnceExecuteOnce(&io, 0, 0, 0)`
    // test uses it.
    0x53,                         // 0xC28 push rbx
    0x57,                         // 0xC29 push rdi
    0x48, 0x89, 0xCB,             // 0xC2A mov rbx, rcx ; rbx = InitOnce
    0x48, 0x89, 0xD7,             // 0xC2D mov rdi, rdx ; rdi = InitFn
    0x31, 0xC0,                   // 0xC30 xor eax, eax ; expected = 0
    0xBA, 0x01, 0x00, 0x00, 0x00, // 0xC32 mov edx, 1 ; new = 1
    0xF0, 0x48, 0x0F, 0xB1, 0x13, // 0xC37 lock cmpxchg [rbx], rdx
    0x75, 0x29,                   // 0xC3C jnz .wait (+0x29 -> 0xC67)
    // We won the CAS.
    0x48, 0x85, 0xFF,       // 0xC3E test rdi, rdi ; null InitFn?
    0x74, 0x15,             // 0xC41 jz .null (+0x15 -> 0xC58)
    0x48, 0x89, 0xD9,       // 0xC43 mov rcx, rbx ; arg1 = InitOnce
    0x4C, 0x89, 0xC2,       // 0xC46 mov rdx, r8 ; arg2 = Parameter
    0x4D, 0x89, 0xC8,       // 0xC49 mov r8, r9 ; arg3 = Context
    0x48, 0x83, 0xEC, 0x20, // 0xC4C sub rsp, 32 ; shadow space
    0xFF, 0xD7,             // 0xC50 call rdi ; InitFn(...)
    0x48, 0x83, 0xC4, 0x20, // 0xC52 add rsp, 32
    0xEB, 0x05,             // 0xC56 jmp .finish (+5 -> 0xC5D)
    // .null (abs 0xC58): skipped InitFn — return TRUE.
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC58 mov eax, 1
    // .finish (abs 0xC5D):
    0x48, 0xC7, 0x03, 0x02, 0x00, 0x00, 0x00, // 0xC5D mov qword [rbx], 2 ; done
    0x5F,                                     // 0xC64 pop rdi
    0x5B,                                     // 0xC65 pop rbx
    0xC3,                                     // 0xC66 ret ; eax = call result or 1
    // .wait (abs 0xC67): CAS lost; slot is 1 or 2. Spin-yield
    // until it reaches 2 (done).
    0x48, 0x8B, 0x03,       // 0xC67 mov rax, [rbx]
    0x48, 0x83, 0xF8, 0x02, // 0xC6A cmp rax, 2
    0x74, 0x07,             // 0xC6E je .wait_done (+7 -> 0xC77)
    0x6A, 0x03,             // 0xC70 push 3
    0x58,                   // 0xC72 pop rax ; SYS_YIELD
    0xCD, 0x80,             // 0xC73 int 0x80
    0xEB, 0xF0,             // 0xC75 jmp .wait (-0x10 -> 0xC67)
    // .wait_done (abs 0xC77): the initialiser finished. Return 1
    // (pretend success — we don't track the initialiser's BOOL
    // across threads).
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xC77 mov eax, 1
    0x5F,                         // 0xC7C pop rdi
    0x5B,                         // 0xC7D pop rbx
    0xC3,                         // 0xC7E ret

    // === real GetProcAddress =====================

    // --- GetProcAddress (offset 0xC7F, 18 bytes) ------------------
    // Win32: FARPROC GetProcAddress(HMODULE hModule=rcx, LPCSTR name=rdx).
    // DuetOS: SYS_DLL_PROC_ADDRESS (57) with rdi=hmod, rsi=name.
    // Returns the exported VA or 0 on miss — same miss contract as
    // the old kOffReturnZero stub. rdi + rsi are callee-saved in the
    // Win32 x64 ABI; save/restore across the syscall.
    0x57,                         // 0xC7F push rdi
    0x56,                         // 0xC80 push rsi
    0x48, 0x89, 0xCF,             // 0xC81 mov rdi, rcx ; hModule
    0x48, 0x89, 0xD6,             // 0xC84 mov rsi, rdx ; name ptr
    0xB8, 0x39, 0x00, 0x00, 0x00, // 0xC87 mov eax, 57 ; SYS_DLL_PROC_ADDRESS
    0xCD, 0x80,                   // 0xC8C int 0x80
    0x5E,                         // 0xC8E pop rsi
    0x5F,                         // 0xC8F pop rdi
    0xC3,                         // 0xC90 ret

    // === Render/drivers: D3D11 / D3D12 / DXGI IAT landing pads ===

    // --- D3D11CreateDevice (offset 0xC91, 13 bytes) --------------
    // rax = HRESULT E_FAIL (returned by the syscall). Kind=1.
    0xBF, 0x01, 0x00, 0x00, 0x00, // 0xC91 mov edi, 1 ; kind = D3D11
    0xB8, 0x65, 0x00, 0x00, 0x00, // 0xC96 mov eax, 101 ; SYS_GFX_D3D_STUB
    0xCD, 0x80,                   // 0xC9B int 0x80
    0xC3,                         // 0xC9D ret

    // --- D3D12CreateDevice (offset 0xC9E, 13 bytes) --------------
    0xBF, 0x02, 0x00, 0x00, 0x00, // 0xC9E mov edi, 2 ; kind = D3D12
    0xB8, 0x65, 0x00, 0x00, 0x00, // 0xCA3 mov eax, 101 ; SYS_GFX_D3D_STUB
    0xCD, 0x80,                   // 0xCA8 int 0x80
    0xC3,                         // 0xCAA ret

    // --- CreateDXGIFactory (offset 0xCAB, 13 bytes) --------------
    0xBF, 0x03, 0x00, 0x00, 0x00, // 0xCAB mov edi, 3 ; kind = DXGI
    0xB8, 0x65, 0x00, 0x00, 0x00, // 0xCB0 mov eax, 101 ; SYS_GFX_D3D_STUB
    0xCD, 0x80,                   // 0xCB5 int 0x80
    0xC3,                         // 0xCB7 ret

    // === Render/drivers: real paint-lifecycle + FillRect =========

    // --- BeginPaint (offset 0xCB8, 14 bytes) ---------------------
    // Win32: HDC BeginPaint(HWND hwnd=rcx, LPPAINTSTRUCT lpPaint=rdx).
    // DuetOS: SYS_WIN_BEGIN_PAINT (103) with rdi=hwnd, rsi=ps ptr.
    // Kernel fills the 72-B PAINTSTRUCT + validates dirty.
    0x48, 0x89, 0xCF,             // 0xCB8 mov rdi, rcx ; hwnd
    0x48, 0x89, 0xD6,             // 0xCBB mov rsi, rdx ; PAINTSTRUCT*
    0xB8, 0x67, 0x00, 0x00, 0x00, // 0xCBE mov eax, 103 ; SYS_WIN_BEGIN_PAINT
    0xCD, 0x80,                   // 0xCC3 int 0x80
    0xC3,                         // 0xCC5 ret

    // --- EndPaint (offset 0xCC6, 11 bytes) -----------------------
    // Win32: BOOL EndPaint(HWND=rcx, const PAINTSTRUCT*=rdx).
    // DuetOS: SYS_WIN_END_PAINT (104). No-op + returns 1.
    0x48, 0x89, 0xCF,             // 0xCC6 mov rdi, rcx ; hwnd
    0xB8, 0x68, 0x00, 0x00, 0x00, // 0xCC9 mov eax, 104 ; SYS_WIN_END_PAINT
    0xCD, 0x80,                   // 0xCCE int 0x80
    0xC3,                         // 0xCD0 ret

    // --- InvalidateRect (offset 0xCD1, 14 bytes) -----------------
    // Win32: BOOL InvalidateRect(HWND=rcx, RECT*=rdx, BOOL bErase=r8).
    // DuetOS: SYS_WIN_INVALIDATE (87). lpRect is ignored in v1 —
    // the whole client repaints on every compose.
    0x48, 0x89, 0xCF,             // 0xCD1 mov rdi, rcx ; hwnd
    0x4C, 0x89, 0xC6,             // 0xCD4 mov rsi, r8 ; bErase
    0xB8, 0x57, 0x00, 0x00, 0x00, // 0xCD7 mov eax, 87 ; SYS_WIN_INVALIDATE
    0xCD, 0x80,                   // 0xCDC int 0x80
    0xC3,                         // 0xCDE ret

    // --- UpdateWindow (offset 0xCDF, 13 bytes) -------------------
    // Win32: BOOL UpdateWindow(HWND=rcx). Posts WM_PAINT if dirty.
    // DuetOS: SYS_WIN_INVALIDATE (87) with bErase=0 — same drain
    // path as InvalidateRect.
    0x48, 0x89, 0xCF,             // 0xCDF mov rdi, rcx ; hwnd
    0x31, 0xF6,                   // 0xCE2 xor esi, esi ; bErase = 0
    0xB8, 0x57, 0x00, 0x00, 0x00, // 0xCE4 mov eax, 87 ; SYS_WIN_INVALIDATE
    0xCD, 0x80,                   // 0xCE9 int 0x80
    0xC3,                         // 0xCEB ret

    // --- GetDC (offset 0xCEC, 4 bytes) ---------------------------
    // Win32: HDC GetDC(HWND=rcx). We alias HDC to HWND — the only
    // GDI entry points we route through syscalls take the hwnd
    // back, so a pass-through return is semantically correct.
    0x48, 0x89, 0xC8, // 0xCEC mov rax, rcx ; HDC = HWND
    0xC3,             // 0xCEF ret

    // --- ReleaseDC (offset 0xCF0, 6 bytes) -----------------------
    // Win32: int ReleaseDC(HWND, HDC). No state to release — always
    // returns 1 (success).
    0xB8, 0x01, 0x00, 0x00, 0x00, // 0xCF0 mov eax, 1
    0xC3,                         // 0xCF5 ret

    // --- FillRect (offset 0xCF6, 17 bytes) -----------------------
    // Win32: int FillRect(HDC hdc=rcx, const RECT*=rdx, HBRUSH=r8).
    // DuetOS: SYS_GDI_FILL_RECT_USER (105) — rdi=hwnd/hdc,
    // rsi=user RECT*, rdx=brush (treated as COLORREF).
    0x48, 0x89, 0xCF,             // 0xCF6 mov rdi, rcx ; hdc/hwnd
    0x48, 0x89, 0xD6,             // 0xCF9 mov rsi, rdx ; RECT*
    0x4C, 0x89, 0xC2,             // 0xCFC mov rdx, r8 ; brush → colour
    0xB8, 0x69, 0x00, 0x00, 0x00, // 0xCFF mov eax, 105 ; SYS_GDI_FILL_RECT_USER
    0xCD, 0x80,                   // 0xD04 int 0x80
    0xC3,                         // 0xD06 ret

    // --- TextOutA (offset 0xD07, 31 bytes) -----------------------
    // Win32: BOOL TextOutA(HDC hdc=rcx, int x=edx, int y=r8d,
    // LPCSTR=r9, int cchString=[rsp+0x28]).
    // 5th arg is on the stack (above the 32 B shadow space + 8 B
    // return address = [rsp+0x28]).
    // DuetOS: SYS_GDI_TEXT_OUT (66) — rdi=hwnd, rsi=x, rdx=y,
    // r10=text ptr, r8=len, r9=colour. We default the colour to
    // white (0xFFFFFF) because TextOutA doesn't carry one in its
    // signature (real Windows uses SetTextColor on the DC, which
    // we don't track yet).
    0x48, 0x89, 0xCF,             // 0xD07 mov rdi, rcx ; hwnd
    0x48, 0x89, 0xD6,             // 0xD0A mov rsi, rdx ; x
    0x4C, 0x89, 0xC2,             // 0xD0D mov rdx, r8 ; y
    0x4D, 0x89, 0xCA,             // 0xD10 mov r10, r9 ; text ptr
    0x44, 0x8B, 0x44, 0x24, 0x28, // 0xD13 mov r8d, [rsp+40]; cchString
    0x41, 0xB9, 0xFF, 0xFF, 0xFF, // 0xD18 mov r9d, 0xFFFFFF; default colour
    0x00,                         // (imm32 continuation)
    0xB8, 0x42, 0x00, 0x00, 0x00, // 0xD1E mov eax, 66 ; SYS_GDI_TEXT_OUT
    0xCD, 0x80,                   // 0xD23 int 0x80
    0xC3,                         // 0xD25 ret

    // === GDI object handle-table stubs ===========================

    // --- CreateCompatibleDC (offset 0xD26, 11 bytes) -------------
    0x48, 0x89, 0xCF,             // 0xD26 mov rdi, rcx ; hdc_src
    0xB8, 0x6A, 0x00, 0x00, 0x00, // 0xD29 mov eax, 106
    0xCD, 0x80,                   // 0xD2E int 0x80
    0xC3,                         // 0xD30 ret

    // --- CreateCompatibleBitmap (offset 0xD31, 17 bytes) ---------
    0x48, 0x89, 0xCF,             // 0xD31 mov rdi, rcx ; hdc
    0x48, 0x89, 0xD6,             // 0xD34 mov rsi, rdx ; width
    0x4C, 0x89, 0xC2,             // 0xD37 mov rdx, r8 ; height
    0xB8, 0x6B, 0x00, 0x00, 0x00, // 0xD3A mov eax, 107
    0xCD, 0x80,                   // 0xD3F int 0x80
    0xC3,                         // 0xD41 ret

    // --- CreateSolidBrush (offset 0xD42, 11 bytes) ---------------
    0x48, 0x89, 0xCF,             // 0xD42 mov rdi, rcx ; COLORREF
    0xB8, 0x6C, 0x00, 0x00, 0x00, // 0xD45 mov eax, 108
    0xCD, 0x80,                   // 0xD4A int 0x80
    0xC3,                         // 0xD4C ret

    // --- GetStockObject (offset 0xD4D, 11 bytes) -----------------
    0x48, 0x89, 0xCF,             // 0xD4D mov rdi, rcx ; index
    0xB8, 0x6D, 0x00, 0x00, 0x00, // 0xD50 mov eax, 109
    0xCD, 0x80,                   // 0xD55 int 0x80
    0xC3,                         // 0xD57 ret

    // --- SelectObject (offset 0xD58, 14 bytes) -------------------
    0x48, 0x89, 0xCF,             // 0xD58 mov rdi, rcx ; hdc
    0x48, 0x89, 0xD6,             // 0xD5B mov rsi, rdx ; hobj
    0xB8, 0x6E, 0x00, 0x00, 0x00, // 0xD5E mov eax, 110
    0xCD, 0x80,                   // 0xD63 int 0x80
    0xC3,                         // 0xD65 ret

    // --- DeleteDC (offset 0xD66, 11 bytes) -----------------------
    0x48, 0x89, 0xCF,             // 0xD66 mov rdi, rcx ; hdc
    0xB8, 0x6F, 0x00, 0x00, 0x00, // 0xD69 mov eax, 111
    0xCD, 0x80,                   // 0xD6E int 0x80
    0xC3,                         // 0xD70 ret

    // --- DeleteObject (offset 0xD71, 11 bytes) -------------------
    0x48, 0x89, 0xCF,             // 0xD71 mov rdi, rcx ; hobj
    0xB8, 0x70, 0x00, 0x00, 0x00, // 0xD74 mov eax, 112
    0xCD, 0x80,                   // 0xD79 int 0x80
    0xC3,                         // 0xD7B ret

    // --- BitBlt (offset 0xD7C, 103 bytes) ------------------------
    // Win32: BOOL BitBlt(HDC hdcDest=rcx, int x=edx, int y=r8d,
    // int cx=r9d, int cy=[rsp+40],
    // HDC hdcSrc=[rsp+48], int x1=[rsp+56],
    // int y1=[rsp+64], DWORD rop=[rsp+72]).
    // Build a 9 * u64 args struct on our own stack (pre-sub 72
    // bytes), pass the pointer via rdi into SYS_GDI_BITBLT_DC (113).
    // Only the low 32 bits of each int slot are meaningful; the
    // kernel ignores the upper 32.
    //
    // After `sub rsp, 72`:
    // [rsp+0..71] = our 9-slot struct
    // [rsp+72] = return address
    // [rsp+80..111]= caller's 32 B shadow space
    // [rsp+112] = cy
    // [rsp+120] = hdcSrc
    // [rsp+128] = x1
    // [rsp+136] = y1
    // [rsp+144] = rop
    0x48, 0x83, 0xEC, 0x48,             // 0xD7C sub rsp, 72
    0x48, 0x89, 0x0C, 0x24,             // 0xD80 mov [rsp+0], rcx ; hdcDst
    0x48, 0x89, 0x54, 0x24, 0x08,       // 0xD84 mov [rsp+8], rdx ; x
    0x4C, 0x89, 0x44, 0x24, 0x10,       // 0xD89 mov [rsp+16], r8 ; y
    0x4C, 0x89, 0x4C, 0x24, 0x18,       // 0xD8E mov [rsp+24], r9 ; cx
    0x48, 0x8B, 0x84, 0x24, 0x70, 0x00, // 0xD93 mov rax, [rsp+112] ; cy
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x20,       // 0xD9B mov [rsp+32], rax
    0x48, 0x8B, 0x84, 0x24, 0x78, 0x00, // 0xDA0 mov rax, [rsp+120] ; hdcSrc
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x28,       // 0xDA8 mov [rsp+40], rax
    0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, // 0xDAD mov rax, [rsp+128] ; x1
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x30,       // 0xDB5 mov [rsp+48], rax
    0x48, 0x8B, 0x84, 0x24, 0x88, 0x00, // 0xDBA mov rax, [rsp+136] ; y1
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x38,       // 0xDC2 mov [rsp+56], rax
    0x48, 0x8B, 0x84, 0x24, 0x90, 0x00, // 0xDC7 mov rax, [rsp+144] ; rop
    0x00, 0x00,                         //
    0x48, 0x89, 0x44, 0x24, 0x40,       // 0xDCF mov [rsp+64], rax
    0x48, 0x89, 0xE7,                   // 0xDD4 mov rdi, rsp
    0xB8, 0x71, 0x00, 0x00, 0x00,       // 0xDD7 mov eax, 113 ; SYS_GDI_BITBLT_DC
    0xCD, 0x80,                         // 0xDDC int 0x80
    0x48, 0x83, 0xC4, 0x48,             // 0xDDE add rsp, 72
    0xC3,                               // 0xDE2 ret

    // === DC colour state setters ================================

    // --- SetTextColor (offset 0xDE3, 14 bytes) ------------------
    // Win32: COLORREF SetTextColor(HDC=rcx, COLORREF=rdx).
    // DuetOS: SYS_GDI_SET_TEXT_COLOR (114). rax = previous colour.
    0x48, 0x89, 0xCF,             // 0xDE3 mov rdi, rcx ; HDC
    0x48, 0x89, 0xD6,             // 0xDE6 mov rsi, rdx ; COLORREF
    0xB8, 0x72, 0x00, 0x00, 0x00, // 0xDE9 mov eax, 114 ; SYS_GDI_SET_TEXT_COLOR
    0xCD, 0x80,                   // 0xDEE int 0x80
    0xC3,                         // 0xDF0 ret

    // --- SetBkColor (offset 0xDF1, 14 bytes) --------------------
    0x48, 0x89, 0xCF,             // 0xDF1 mov rdi, rcx ; HDC
    0x48, 0x89, 0xD6,             // 0xDF4 mov rsi, rdx ; COLORREF
    0xB8, 0x73, 0x00, 0x00, 0x00, // 0xDF7 mov eax, 115 ; SYS_GDI_SET_BK_COLOR
    0xCD, 0x80,                   // 0xDFC int 0x80
    0xC3,                         // 0xDFE ret

    // --- SetBkMode (offset 0xDFF, 14 bytes) ---------------------
    // Win32: int SetBkMode(HDC=rcx, int mode=edx). OPAQUE=2, TRANSPARENT=1.
    0x48, 0x89, 0xCF,             // 0xDFF mov rdi, rcx ; HDC
    0x48, 0x89, 0xD6,             // 0xE02 mov rsi, rdx ; mode
    0xB8, 0x74, 0x00, 0x00, 0x00, // 0xE05 mov eax, 116 ; SYS_GDI_SET_BK_MODE
    0xCD, 0x80,                   // 0xE0A int 0x80
    0xC3,                         // 0xE0C ret

    // --- StretchBlt (offset 0xE0D, 129 bytes) -------------------
    // Win32: BOOL StretchBlt(HDC hdcDst=rcx, int xDst=edx,
    // int yDst=r8d, int wDst=r9d,
    // int hDst=[rsp+40], HDC hdcSrc=[rsp+48],
    // int xSrc=[rsp+56], int ySrc=[rsp+64],
    // int wSrc=[rsp+72], int hSrc=[rsp+80],
    // DWORD rop=[rsp+88]).
    // Pack 11 u64s into a stack-resident struct (88 B), pass
    // pointer via rdi to SYS_GDI_STRETCH_BLT_DC (117). Stack args
    // are read from [rsp+88+40 .. rsp+88+88] after the sub.
    0x48, 0x83, 0xEC, 0x58,                         // 0xE0D sub rsp, 88
    0x48, 0x89, 0x0C, 0x24,                         // 0xE11 mov [rsp+0], rcx ; hdcDst
    0x48, 0x89, 0x54, 0x24, 0x08,                   // 0xE15 mov [rsp+8], rdx ; xDst
    0x4C, 0x89, 0x44, 0x24, 0x10,                   // 0xE1A mov [rsp+16], r8 ; yDst
    0x4C, 0x89, 0x4C, 0x24, 0x18,                   // 0xE1F mov [rsp+24], r9 ; wDst
    0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, // 0xE24 mov rax, [rsp+128] ; hDst
    0x48, 0x89, 0x44, 0x24, 0x20,                   // 0xE2C mov [rsp+32], rax
    0x48, 0x8B, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, // 0xE31 mov rax, [rsp+136] ; hdcSrc
    0x48, 0x89, 0x44, 0x24, 0x28,                   // 0xE39 mov [rsp+40], rax
    0x48, 0x8B, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, // 0xE3E mov rax, [rsp+144] ; xSrc
    0x48, 0x89, 0x44, 0x24, 0x30,                   // 0xE46 mov [rsp+48], rax
    0x48, 0x8B, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, // 0xE4B mov rax, [rsp+152] ; ySrc
    0x48, 0x89, 0x44, 0x24, 0x38,                   // 0xE53 mov [rsp+56], rax
    0x48, 0x8B, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, // 0xE58 mov rax, [rsp+160] ; wSrc
    0x48, 0x89, 0x44, 0x24, 0x40,                   // 0xE60 mov [rsp+64], rax
    0x48, 0x8B, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00, // 0xE65 mov rax, [rsp+168] ; hSrc
    0x48, 0x89, 0x44, 0x24, 0x48,                   // 0xE6D mov [rsp+72], rax
    0x48, 0x8B, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, // 0xE72 mov rax, [rsp+176] ; rop
    0x48, 0x89, 0x44, 0x24, 0x50,                   // 0xE7A mov [rsp+80], rax
    0x48, 0x89, 0xE7,                               // 0xE7F mov rdi, rsp
    0xB8, 0x75, 0x00, 0x00, 0x00,                   // 0xE82 mov eax, 117 ; SYS_GDI_STRETCH_BLT_DC
    0xCD, 0x80,                                     // 0xE87 int 0x80
    0x48, 0x83, 0xC4, 0x58,                         // 0xE89 add rsp, 88
    0xC3,                                           // 0xE8D ret

    // === GDI outline primitives — real IAT routes ===============

    // --- Rectangle (offset 0xE8E, 40 bytes) ---------------------
    // Win32: BOOL Rectangle(HDC=rcx, int left=edx, int top=r8d,
    // int right=r9d, int bottom=[rsp+40]).
    // DuetOS: SYS_GDI_RECTANGLE (67) — rdi=hwnd, rsi=x, rdx=y,
    // r10=w, r8=h, r9=colour. Convert LTRB → (L, T, R-L, B-T).
    // Uses r11 (caller-saved in Win64) as a scratch for B.
    0x4C, 0x8B, 0x5C, 0x24, 0x28, // 0xE8E mov r11, [rsp+40] ; bottom
    0x4D, 0x29, 0xC3,             // 0xE93 sub r11, r8 ; h = bottom - top
    0x4D, 0x89, 0xCA,             // 0xE96 mov r10, r9 ; R
    0x49, 0x29, 0xD2,             // 0xE99 sub r10, rdx ; w = R - L
    0x48, 0x89, 0xCF,             // 0xE9C mov rdi, rcx ; hwnd
    0x48, 0x89, 0xD6,             // 0xE9F mov rsi, rdx ; x = L
    0x4C, 0x89, 0xC2,             // 0xEA2 mov rdx, r8 ; y = T
    0x4D, 0x89, 0xD8,             // 0xEA5 mov r8, r11 ; h
    0x41, 0xB9, 0xFF, 0xFF, 0xFF, // 0xEA8 mov r9d, 0xFFFFFF ; colour = white
    0x00,                         //
    0xB8, 0x43, 0x00, 0x00, 0x00, // 0xEAE mov eax, 67 ; SYS_GDI_RECTANGLE
    0xCD, 0x80,                   // 0xEB3 int 0x80
    0xC3,                         // 0xEB5 ret

    // --- Ellipse (offset 0xEB6, 40 bytes) -----------------------
    // Same shape as Rectangle; different syscall number.
    0x4C, 0x8B, 0x5C, 0x24, 0x28, // 0xEB6 mov r11, [rsp+40]
    0x4D, 0x29, 0xC3,             // 0xEBB sub r11, r8
    0x4D, 0x89, 0xCA,             // 0xEBE mov r10, r9
    0x49, 0x29, 0xD2,             // 0xEC1 sub r10, rdx
    0x48, 0x89, 0xCF,             // 0xEC4 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xEC7 mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0xECA mov rdx, r8
    0x4D, 0x89, 0xD8,             // 0xECD mov r8, r11
    0x41, 0xB9, 0xFF, 0xFF, 0xFF, // 0xED0 mov r9d, 0xFFFFFF
    0x00,                         //
    0xB8, 0x4B, 0x00, 0x00, 0x00, // 0xED6 mov eax, 75 ; SYS_GDI_ELLIPSE
    0xCD, 0x80,                   // 0xEDB int 0x80
    0xC3,                         // 0xEDD ret

    // --- SetPixel / SetPixelV (offset 0xEDE, 20 bytes) ----------
    // Win32: COLORREF SetPixel(HDC=rcx, int x=edx, int y=r8d,
    // COLORREF=r9d).
    // DuetOS: SYS_GDI_SET_PIXEL (76) — rdi=hwnd, rsi=x, rdx=y,
    // r10=colour. Also serves SetPixelV (BOOL return — 1 is a
    // valid non-zero return for SetPixel's caller too).
    0x48, 0x89, 0xCF,             // 0xEDE mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xEE1 mov rsi, rdx ; x
    0x4C, 0x89, 0xC2,             // 0xEE4 mov rdx, r8 ; y
    0x4D, 0x89, 0xCA,             // 0xEE7 mov r10, r9 ; colour
    0xB8, 0x4C, 0x00, 0x00, 0x00, // 0xEEA mov eax, 76 ; SYS_GDI_SET_PIXEL
    0xCD, 0x80,                   // 0xEEF int 0x80
    0xC3,                         // 0xEF1 ret

    // --- CreatePen (offset 0xEF2, 17 bytes) ---------------------
    // Win32: HPEN CreatePen(int style=rcx, int width=edx,
    // COLORREF=r8d).
    // DuetOS: SYS_GDI_CREATE_PEN (118) — rdi=style, rsi=width,
    // rdx=COLORREF.
    0x48, 0x89, 0xCF,             // 0xEF2 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xEF5 mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0xEF8 mov rdx, r8
    0xB8, 0x76, 0x00, 0x00, 0x00, // 0xEFB mov eax, 118
    0xCD, 0x80,                   // 0xF00 int 0x80
    0xC3,                         // 0xF02 ret

    // --- MoveToEx (offset 0xF03, 20 bytes) ----------------------
    // Win32: BOOL MoveToEx(HDC=rcx, int x=edx, int y=r8d,
    // LPPOINT lpPoint=r9).
    // DuetOS: SYS_GDI_MOVE_TO_EX (119) — rdi=HDC, rsi=x, rdx=y,
    // r10=out LPPOINT.
    0x48, 0x89, 0xCF,             // 0xF03 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xF06 mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0xF09 mov rdx, r8
    0x4D, 0x89, 0xCA,             // 0xF0C mov r10, r9
    0xB8, 0x77, 0x00, 0x00, 0x00, // 0xF0F mov eax, 119
    0xCD, 0x80,                   // 0xF14 int 0x80
    0xC3,                         // 0xF16 ret

    // --- LineTo (offset 0xF17, 17 bytes) ------------------------
    // Win32: BOOL LineTo(HDC=rcx, int x=edx, int y=r8d).
    // DuetOS: SYS_GDI_LINE_TO (120) — rdi=HDC, rsi=x, rdx=y.
    0x48, 0x89, 0xCF,             // 0xF17 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xF1A mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0xF1D mov rdx, r8
    0xB8, 0x78, 0x00, 0x00, 0x00, // 0xF20 mov eax, 120
    0xCD, 0x80,                   // 0xF25 int 0x80
    0xC3,                         // 0xF27 ret

    // --- DrawTextA (offset 0xF28, 25 bytes) ---------------------
    // Win32: int DrawTextA(HDC=rcx, LPCSTR=rdx, int cchText=r8d,
    // LPRECT=r9, UINT format=[rsp+40]).
    // DuetOS: SYS_GDI_DRAW_TEXT_USER (121) — rdi=HDC, rsi=text,
    // rdx=len, r10=RECT*, r8=format.
    0x48, 0x89, 0xCF,             // 0xF28 mov rdi, rcx ; HDC
    0x48, 0x89, 0xD6,             // 0xF2B mov rsi, rdx ; text
    0x4C, 0x89, 0xC2,             // 0xF2E mov rdx, r8 ; len
    0x4D, 0x89, 0xCA,             // 0xF31 mov r10, r9 ; RECT*
    0x44, 0x8B, 0x44, 0x24, 0x28, // 0xF34 mov r8d, [rsp+40] ; format
    0xB8, 0x79, 0x00, 0x00, 0x00, // 0xF39 mov eax, 121
    0xCD, 0x80,                   // 0xF3E int 0x80
    0xC3,                         // 0xF40 ret

    // === Message loop — GetMessage / PeekMessage / DispatchMessage

    // --- GetMessageA/W (offset 0xF41, 14 bytes) -----------------
    // Win32: BOOL GetMessage(LPMSG=rcx, HWND filter=rdx,
    // UINT fMin=r8d, UINT fMax=r9d).
    // Filter-min/max ignored in v0 (our queues don't carry enough
    // message granularity for range filtering yet).
    // DuetOS: SYS_WIN_GET_MSG (63) — rdi=out ptr, rsi=hwnd filter.
    // Returns 1 for a normal message, 0 for WM_QUIT, -1 on fault.
    // The Win32 MSG struct's first 32 bytes — hwnd/message/wparam/
    // lparam — are exactly what our kernel writes out; the trailing
    // time/pt/lPrivate are left uninitialised (Win32 apps that
    // read them get indeterminate but non-crashing data).
    0x48, 0x89, 0xCF,             // 0xF41 mov rdi, rcx ; LPMSG
    0x48, 0x89, 0xD6,             // 0xF44 mov rsi, rdx ; HWND filter
    0xB8, 0x3F, 0x00, 0x00, 0x00, // 0xF47 mov eax, 63 ; SYS_WIN_GET_MSG
    0xCD, 0x80,                   // 0xF4C int 0x80
    0xC3,                         // 0xF4E ret

    // --- PeekMessageA/W (offset 0xF4F, 18 bytes) ----------------
    // Win32: BOOL PeekMessageA(LPMSG=rcx, HWND=rdx, UINT fMin=r8d,
    // UINT fMax=r9d, UINT wRemove=[rsp+40]).
    // DuetOS: SYS_WIN_PEEK_MSG (62) — rdi=out, rsi=hwnd, rdx=bRemove.
    0x48, 0x89, 0xCF,             // 0xF4F mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xF52 mov rsi, rdx
    0x8B, 0x54, 0x24, 0x28,       // 0xF55 mov edx, [rsp+40] ; wRemove
    0xB8, 0x3E, 0x00, 0x00, 0x00, // 0xF59 mov eax, 62 ; SYS_WIN_PEEK_MSG
    0xCD, 0x80,                   // 0xF5E int 0x80
    0xC3,                         // 0xF60 ret

    // --- DispatchMessageA/W (offset 0xF61, 60 bytes) ------------
    // Win32: LRESULT DispatchMessage(const MSG* lpMsg=rcx).
    // The message's hwnd holds its WndProc in per-window slot 0
    // (set by SetWindowLongPtrA + RegisterClass at CreateWindow
    // time). Look it up via SYS_WIN_GET_LONG, then synthesise the
    // Win32 WndProc call:
    // wndproc(hwnd, msg, wparam, lparam)
    // If the WndProc slot is 0 we just return 0 — the app's
    // default handler never wired.
    //
    // rbx + r12 are callee-saved in Win64, so save them; we use
    // rbx = lpMsg and r12 = hwnd across the syscall.
    //
    // Stack alignment: ret-addr puts rsp @ +8; `push rbx; push r12`
    // brings it back to +0; `sub rsp, 40` (32 shadow + 8 align) =
    // +8 before the call, canonical Win64 pre-call alignment.
    0x53,                         // 0xF61 push rbx
    0x41, 0x54,                   // 0xF62 push r12
    0x48, 0x89, 0xCB,             // 0xF64 mov rbx, rcx ; lpMsg
    0x4C, 0x8B, 0x23,             // 0xF67 mov r12, [rbx] ; hwnd_biased
    0x4C, 0x89, 0xE7,             // 0xF6A mov rdi, r12
    0x31, 0xF6,                   // 0xF6D xor esi, esi ; index = 0 (GWLP_WNDPROC)
    0xB8, 0x55, 0x00, 0x00, 0x00, // 0xF6F mov eax, 85 ; SYS_WIN_GET_LONG
    0xCD, 0x80,                   // 0xF74 int 0x80
    0x48, 0x85, 0xC0,             // 0xF76 test rax, rax
    0x74, 0x1C,                   // 0xF79 jz .default (+28 to 0xF97)
    0x48, 0x83, 0xEC, 0x28,       // 0xF7B sub rsp, 40
    0x4C, 0x89, 0xE1,             // 0xF7F mov rcx, r12 ; hwnd
    0x8B, 0x53, 0x08,             // 0xF82 mov edx, [rbx+8] ; message
    0x4C, 0x8B, 0x43, 0x10,       // 0xF85 mov r8, [rbx+16] ; wparam
    0x4C, 0x8B, 0x4B, 0x18,       // 0xF89 mov r9, [rbx+24] ; lparam
    0xFF, 0xD0,                   // 0xF8D call rax ; WndProc
    0x48, 0x83, 0xC4, 0x28,       // 0xF8F add rsp, 40
    0x41, 0x5C,                   // 0xF93 pop r12
    0x5B,                         // 0xF95 pop rbx
    0xC3,                         // 0xF96 ret
    // .default (offset 0xF97):
    0x31, 0xC0, // 0xF97 xor eax, eax
    0x41, 0x5C, // 0xF99 pop r12
    0x5B,       // 0xF9B pop rbx
    0xC3,       // 0xF9C ret

    // === Filled primitives — brush/pen from DC =================

    // --- Rectangle filled (offset 0xF9D, 34 bytes) --------------
    // Win32: BOOL Rectangle(HDC=rcx, int L=edx, int T=r8d,
    // int R=r9d, int B=[rsp+40]).
    // DuetOS: SYS_GDI_RECTANGLE_FILLED (122) — rdi=HDC, rsi=x,
    // rdx=y, r10=w, r8=h. Convert LTRB→xywh. Colour is fetched
    // from DC state (selected_brush + selected_pen), not from args.
    0x4C, 0x8B, 0x5C, 0x24, 0x28, // 0xF9D mov r11, [rsp+40] ; B
    0x4D, 0x29, 0xC3,             // 0xFA2 sub r11, r8 ; h
    0x4D, 0x89, 0xCA,             // 0xFA5 mov r10, r9 ; R
    0x49, 0x29, 0xD2,             // 0xFA8 sub r10, rdx ; w
    0x48, 0x89, 0xCF,             // 0xFAB mov rdi, rcx ; HDC
    0x48, 0x89, 0xD6,             // 0xFAE mov rsi, rdx ; x = L
    0x4C, 0x89, 0xC2,             // 0xFB1 mov rdx, r8 ; y = T
    0x4D, 0x89, 0xD8,             // 0xFB4 mov r8, r11 ; h
    0xB8, 0x7A, 0x00, 0x00, 0x00, // 0xFB7 mov eax, 122
    0xCD, 0x80,                   // 0xFBC int 0x80
    0xC3,                         // 0xFBE ret

    // --- Ellipse filled (offset 0xFBF, 34 bytes) ----------------
    // Same shape as filled-Rectangle; different syscall.
    0x4C, 0x8B, 0x5C, 0x24, 0x28, // 0xFBF mov r11, [rsp+40]
    0x4D, 0x29, 0xC3,             // 0xFC4 sub r11, r8
    0x4D, 0x89, 0xCA,             // 0xFC7 mov r10, r9
    0x49, 0x29, 0xD2,             // 0xFCA sub r10, rdx
    0x48, 0x89, 0xCF,             // 0xFCD mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xFD0 mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0xFD3 mov rdx, r8
    0x4D, 0x89, 0xD8,             // 0xFD6 mov r8, r11
    0xB8, 0x7B, 0x00, 0x00, 0x00, // 0xFD9 mov eax, 123
    0xCD, 0x80,                   // 0xFDE int 0x80
    0xC3,                         // 0xFE0 ret

    // --- PatBlt (offset 0xFE1, 25 bytes) -----------------------
    // Win32: BOOL PatBlt(HDC=rcx, int x=edx, int y=r8d,
    // int w=r9d, int h=[rsp+40],
    // DWORD rop=[rsp+48]).
    // DuetOS: SYS_GDI_PAT_BLT (124) — rdi=HDC, rsi=x, rdx=y,
    // r10=w, r8=h. ROP ignored (always PATCOPY).
    0x48, 0x89, 0xCF,             // 0xFE1 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xFE4 mov rsi, rdx ; x
    0x4C, 0x89, 0xC2,             // 0xFE7 mov rdx, r8 ; y
    0x4D, 0x89, 0xCA,             // 0xFEA mov r10, r9 ; w
    0x44, 0x8B, 0x44, 0x24, 0x28, // 0xFED mov r8d, [rsp+40] ; h
    0xB8, 0x7C, 0x00, 0x00, 0x00, // 0xFF2 mov eax, 124
    0xCD, 0x80,                   // 0xFF7 int 0x80
    0xC3,                         // 0xFF9 ret

    // === UTF-16 text entry points ===============================

    // --- TextOutW (offset 0xFFA, 31 bytes) ----------------------
    // Win32: BOOL TextOutW(HDC=rcx, int x=edx, int y=r8d,
    // LPCWSTR=r9, int cchString=[rsp+40]).
    // Same shape as TextOutA; different syscall. Kernel strips
    // each u16 to ASCII ('?' for non-ASCII) then shares the
    // memDC / window-DC dispatch with DoGdiTextOut.
    0x48, 0x89, 0xCF,             // 0xFFA mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0xFFD mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0x1000 mov rdx, r8
    0x4D, 0x89, 0xCA,             // 0x1003 mov r10, r9
    0x44, 0x8B, 0x44, 0x24, 0x28, // 0x1006 mov r8d, [rsp+40] ; cchString
    0x41, 0xB9, 0xFF, 0xFF, 0xFF, // 0x100B mov r9d, 0xFFFFFF ; fallback colour
    0x00,                         //
    0xB8, 0x7D, 0x00, 0x00, 0x00, // 0x1011 mov eax, 125 ; SYS_GDI_TEXT_OUT_W
    0xCD, 0x80,                   // 0x1016 int 0x80
    0xC3,                         // 0x1018 ret

    // --- DrawTextW (offset 0x1019, 25 bytes) --------------------
    // Win32: int DrawTextW(HDC=rcx, LPCWSTR=rdx, int cchText=r8d,
    // LPRECT=r9, UINT format=[rsp+40]).
    // Same shape as DrawTextA.
    0x48, 0x89, 0xCF,             // 0x1019 mov rdi, rcx
    0x48, 0x89, 0xD6,             // 0x101C mov rsi, rdx
    0x4C, 0x89, 0xC2,             // 0x101F mov rdx, r8
    0x4D, 0x89, 0xCA,             // 0x1022 mov r10, r9
    0x44, 0x8B, 0x44, 0x24, 0x28, // 0x1025 mov r8d, [rsp+40] ; format
    0xB8, 0x7E, 0x00, 0x00, 0x00, // 0x102A mov eax, 126 ; SYS_GDI_DRAW_TEXT_W
    0xCD, 0x80,                   // 0x102F int 0x80
    0xC3,                         // 0x1031 ret

    // === System palette ========================================

    // --- GetSysColor (offset 0x1032, 11 bytes) ------------------
    // Win32: DWORD GetSysColor(int nIndex=ecx).
    0x48, 0x89, 0xCF,             // 0x1032 mov rdi, rcx
    0xB8, 0x7F, 0x00, 0x00, 0x00, // 0x1035 mov eax, 127 ; SYS_GDI_GET_SYS_COLOR
    0xCD, 0x80,                   // 0x103A int 0x80
    0xC3,                         // 0x103C ret

    // --- GetSysColorBrush (offset 0x103D, 11 bytes) -------------
    // Win32: HBRUSH GetSysColorBrush(int nIndex=ecx).
    0x48, 0x89, 0xCF,             // 0x103D mov rdi, rcx
    0xB8, 0x80, 0x00, 0x00, 0x00, // 0x1040 mov eax, 128 ; SYS_GDI_GET_SYS_COLOR_BRUSH
    0xCD, 0x80,                   // 0x1045 int 0x80
    0xC3,                         // 0x1047 ret
