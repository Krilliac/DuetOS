/*
 * userland/libs/kernel32/kernel32.c
 *
 * Freestanding CustomOS kernel32.dll — ring-3 code that
 * implements Win32 entry points by issuing native int 0x80
 * syscalls + returning sentinel constants where appropriate.
 * This is the live userland replacement for the matching
 * entries in kernel/subsystems/win32/stubs.cpp.
 *
 * Every function exported here retires the corresponding
 * `{"kernel32.dll", "<name>", kOff<name>}` row in
 * kStubsTable. The flat stub stays compiled as a fallback
 * (slice-6's via-DLL path runs first; the stub is only
 * reached if preload fails). A later sweep-slice deletes
 * the dead rows.
 *
 * Build: tools/build-kernel32-dll.sh
 *   clang --target=x86_64-pc-windows-msvc + lld-link /dll
 *   /noentry /nodefaultlib /base:0x10020000 + one /export:
 *   line per function. No CRT, no imports.
 *
 * Native syscall ABI (all exports below rely on this):
 *     int 0x80
 *     rax = syscall number, rdi/rsi/rdx/r10/r8/r9 = args
 *     rax = return value on exit
 *
 * The kernel's SYS_* handlers preserve every register except
 * rax, so "int 0x80" in an inline asm with only `"=a"(rv)`
 * output and `"a"(num)` / `"D"(arg)` / ... inputs is safe —
 * the compiler tracks rdi / rsi / rdx as clobbered only when
 * we use them as input operands, and those are the exact
 * registers the syscall reads.
 */

typedef unsigned int       DWORD;
typedef unsigned int       UINT;
typedef int                BOOL;
typedef void*              HANDLE;
typedef unsigned long      ULONG;
typedef unsigned long long UINT_PTR; /* 64-bit on x64 windows-msvc; DWORD is 32 */

#define WIN32_NORETURN __attribute__((noreturn))

/* ------------------------------------------------------------------
 * Process / thread identity (syscall-backed)
 * ------------------------------------------------------------------ */

/* SYS_GETPROCID = 8 — kernel returns CurrentProcess()->pid. */
__declspec(dllexport) DWORD GetCurrentProcessId(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long) 8) : "memory");
    return (DWORD) rv;
}

/* SYS_GETPID = 1 — kernel returns the scheduler task id.
 * This is "thread id" in the Win32 sense: per-thread, distinct
 * from the process id. Matches what the existing flat stub
 * (kOffGetCurrentThreadId) does. */
__declspec(dllexport) DWORD GetCurrentThreadId(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long) 1) : "memory");
    return (DWORD) rv;
}

/* ------------------------------------------------------------------
 * Pseudo-handles (constant returns)
 * Real Windows also returns these literal values; any receiver
 * checks for the sentinel rather than going through the handle
 * table.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE GetCurrentProcess(void)
{
    return (HANDLE) (long) -1;
}

__declspec(dllexport) HANDLE GetCurrentThread(void)
{
    return (HANDLE) (long) -2;
}

/* ------------------------------------------------------------------
 * Last-error slot (syscall-backed)
 * Per-process u32 stored in Process.win32_last_error.
 * ------------------------------------------------------------------ */

/* SYS_GETLASTERROR = 9 */
__declspec(dllexport) DWORD GetLastError(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long) 9) : "memory");
    return (DWORD) rv;
}

/* SYS_SETLASTERROR = 10 — rdi = new error code. */
__declspec(dllexport) void SetLastError(DWORD err)
{
    long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long) 10), "D"((long) err) : "memory");
}

/* ------------------------------------------------------------------
 * Noreturn terminators (SYS_EXIT = 0, rdi = exit code)
 * ------------------------------------------------------------------ */

__declspec(dllexport) WIN32_NORETURN void ExitProcess(UINT uExitCode)
{
    __asm__ volatile("int $0x80" : : "a"((long) 0), "D"((long) uExitCode));
    __builtin_unreachable();
}

/* TerminateProcess(hProcess, uExitCode) — hProcess is ignored
 * (single-process semantics match the existing stub). uExitCode
 * goes to SYS_EXIT same as ExitProcess. */
__declspec(dllexport) WIN32_NORETURN BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    (void) hProcess;
    __asm__ volatile("int $0x80" : : "a"((long) 0), "D"((long) uExitCode));
    __builtin_unreachable();
}

/* ------------------------------------------------------------------
 * "Safe-ignore" return-constant shims
 * Semantically equivalent to the flat-stubs kOffReturnZero /
 * kOffReturnOne family for these specific Win32 contracts.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL IsDebuggerPresent(void)
{
    return 0; /* No debugger attached (this OS has no debug API yet). */
}

__declspec(dllexport) BOOL IsProcessorFeaturePresent(DWORD feature)
{
    (void) feature;
    /* Optimistically claim every queried feature is present —
     * x86_64 universally has SSE / SSE2 / CMPXCHG16B / NX, and
     * AES / AVX / RDRAND are all visible in our CPU probe log.
     * Returning 0 forced every caller onto scalar-only fallback
     * paths; returning 1 matches modern hardware. */
    return 1;
}

__declspec(dllexport) BOOL SetConsoleCtrlHandler(void* handler, BOOL add)
{
    (void) handler;
    (void) add;
    /* We have no console Ctrl-C dispatcher yet — pretend we
     * registered. Matches the flat stub's kOffReturnOne
     * behaviour. */
    return 1;
}

/* ------------------------------------------------------------------
 * Stdio handle
 * Win32: HANDLE GetStdHandle(DWORD nStdHandle).
 * The downstream WriteFile path ignores the handle and always
 * uses fd=1 (stdout). Pass-through is faithful enough for every
 * "hello world" caller today.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE GetStdHandle(DWORD nStdHandle)
{
    /* Zero-extend DWORD to HANDLE (pointer-sized on x64).
     * STD_OUTPUT_HANDLE = -11 as DWORD = 0xFFFFFFF5 becomes
     * 0x00000000FFFFFFF5 as a HANDLE — same as the flat stub's
     * `mov eax, ecx; ret`. UINT_PTR is 64-bit so the cast-
     * chain stays warning-clean under MSVC's LLP64 layout. */
    return (HANDLE) (UINT_PTR) nStdHandle;
}

/* ------------------------------------------------------------------
 * Scheduler interaction (Sleep, SwitchToThread, GetTickCount)
 *
 * Sleep(0) specifically yields (SYS_SLEEP_MS with rdi=0 behaves
 * like SYS_YIELD per syscall.h:176-189), so a single trampoline
 * covers both "drop the timeslice" and "sleep N ms" semantics.
 * ------------------------------------------------------------------ */

typedef unsigned long long ULONGLONG;
typedef long               LONG;

__declspec(dllexport) void Sleep(DWORD ms)
{
    long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long) 19), "D"((long) ms) : "memory");
}

__declspec(dllexport) BOOL SwitchToThread(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long) 3) : "memory");
    /* SYS_YIELD returns 0 on success — match Win32
     * SwitchToThread's "TRUE if yielded" semantic. */
    return 1;
}

/* SYS_PERF_COUNTER (13) returns raw 100 Hz tick count. Scale
 * by 10 to convert to ms. Both GetTickCount (DWORD) and
 * GetTickCount64 (ULONGLONG) share this impl — GetTickCount
 * is just a truncation of GetTickCount64. */
__declspec(dllexport) ULONGLONG GetTickCount64(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long) 13) : "memory");
    return (ULONGLONG) rv * 10ULL;
}

__declspec(dllexport) DWORD GetTickCount(void)
{
    return (DWORD) GetTickCount64();
}

/* ------------------------------------------------------------------
 * Interlocked* family — atomic read/modify/write primitives.
 *
 * All of these are pure-CPU (no syscall). The Win32 semantics
 * are well-defined against x86 atomics:
 *   - Increment/Decrement return the NEW value.
 *   - Exchange returns the OLD value.
 *   - CompareExchange returns the OLD value (regardless of
 *     whether the swap succeeded).
 *   - ExchangeAdd returns the OLD value.
 *   - And / Or / Xor return the OLD value.
 *
 * Clang's __atomic_* intrinsics on x86-64 emit a single
 * `lock xadd` / `lock cmpxchg` / `xchg` instruction inline —
 * no libcall — so -nodefaultlib links cleanly.
 * ------------------------------------------------------------------ */

__declspec(dllexport) LONG InterlockedIncrement(LONG volatile* addend)
{
    return __atomic_add_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedDecrement(LONG volatile* addend)
{
    return __atomic_sub_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedExchange(LONG volatile* target, LONG value)
{
    return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedCompareExchange(LONG volatile* dest, LONG exch, LONG comp)
{
    __atomic_compare_exchange_n(dest, &comp, exch,
                                /*weak=*/0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    /* comp is updated in place to the actual pre-CAS value —
     * which is exactly what Win32 InterlockedCompareExchange
     * returns. */
    return comp;
}

__declspec(dllexport) LONG InterlockedExchangeAdd(LONG volatile* addend, LONG value)
{
    return __atomic_fetch_add(addend, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedAnd(LONG volatile* dest, LONG value)
{
    return __atomic_fetch_and(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedOr(LONG volatile* dest, LONG value)
{
    return __atomic_fetch_or(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedXor(LONG volatile* dest, LONG value)
{
    return __atomic_fetch_xor(dest, value, __ATOMIC_SEQ_CST);
}

typedef long long LONG64;

__declspec(dllexport) LONG64 InterlockedIncrement64(LONG64 volatile* addend)
{
    return __atomic_add_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedDecrement64(LONG64 volatile* addend)
{
    return __atomic_sub_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedExchange64(LONG64 volatile* target, LONG64 value)
{
    return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedCompareExchange64(LONG64 volatile* dest, LONG64 exch, LONG64 comp)
{
    __atomic_compare_exchange_n(dest, &comp, exch, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return comp;
}

__declspec(dllexport) LONG64 InterlockedExchangeAdd64(LONG64 volatile* addend, LONG64 value)
{
    return __atomic_fetch_add(addend, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedAnd64(LONG64 volatile* dest, LONG64 value)
{
    return __atomic_fetch_and(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedOr64(LONG64 volatile* dest, LONG64 value)
{
    return __atomic_fetch_or(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedXor64(LONG64 volatile* dest, LONG64 value)
{
    return __atomic_fetch_xor(dest, value, __ATOMIC_SEQ_CST);
}

/* ------------------------------------------------------------------
 * Console / system introspection (slice 16)
 *
 * Most of these are constant-returning shims that report sane
 * "you're on x86_64 Windows 10, code page 437, no Wow64" values
 * so CRT startup + typical console programs proceed without
 * branching onto obscure alt paths.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL GetConsoleMode(HANDLE hConsole, DWORD* lpMode)
{
    (void) hConsole;
    if (lpMode != (DWORD*) 0)
        *lpMode = 3; /* ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT */
    return 1;
}

__declspec(dllexport) UINT GetConsoleCP(void)
{
    return 437; /* OEM code page — what cmd.exe uses by default. */
}

__declspec(dllexport) UINT GetConsoleOutputCP(void)
{
    return 437;
}

__declspec(dllexport) DWORD GetLogicalDrives(void)
{
    /* Bit 23 set = X: — same sentinel the flat stub returns. */
    return 0x00800000u;
}

__declspec(dllexport) UINT GetDriveTypeA(const char* root)
{
    (void) root;
    return 3; /* DRIVE_FIXED */
}

__declspec(dllexport) UINT GetDriveTypeW(const void* root)
{
    (void) root;
    return 3; /* DRIVE_FIXED */
}

__declspec(dllexport) BOOL IsWow64Process(HANDLE hProc, BOOL* Wow64Process)
{
    (void) hProc;
    if (Wow64Process != (BOOL*) 0)
        *Wow64Process = 0; /* Native x64, not Wow64. */
    return 1;
}

__declspec(dllexport) BOOL IsWow64Process2(HANDLE hProc, unsigned short* proc_machine, unsigned short* native_machine)
{
    (void) hProc;
    if (proc_machine != (unsigned short*) 0)
        *proc_machine = 0; /* IMAGE_FILE_MACHINE_UNKNOWN — not Wow64. */
    if (native_machine != (unsigned short*) 0)
        *native_machine = 0x8664; /* IMAGE_FILE_MACHINE_AMD64 */
    return 1;
}

/* HMODULE GetModuleHandleExW/A — v0 always returns "not found"
 * for non-null names, matching the flat stub. The NULL-arg
 * path (which should return the EXE base) goes through
 * GetModuleHandleW in real Windows, so this HMODULE-by-name
 * variant's flat stub also returned 0. */
__declspec(dllexport) BOOL GetModuleHandleExW(DWORD flags, const void* name, void** phmodule)
{
    (void) flags;
    (void) name;
    if (phmodule != (void**) 0)
        *phmodule = (void*) 0;
    return 0;
}

__declspec(dllexport) BOOL GetModuleHandleExA(DWORD flags, const char* name, void** phmodule)
{
    (void) flags;
    (void) name;
    if (phmodule != (void**) 0)
        *phmodule = (void*) 0;
    return 0;
}

__declspec(dllexport) BOOL FreeLibrary(void* hModule)
{
    (void) hModule;
    return 1; /* Pretend success — we don't refcount mapped DLLs yet. */
}

/* ------------------------------------------------------------------
 * SList family — slim-list intrusive stack. v0 returns NULL /
 * 0, matching the flat kOffReturnZero registration for these.
 * Any non-null use would panic with a null pointer today; real
 * callers all have a "what if SList isn't supported" fallback.
 * ------------------------------------------------------------------ */

typedef struct SLIST_ENTRY
{
    struct SLIST_ENTRY* Next;
} SLIST_ENTRY;

__declspec(dllexport) void InterlockedPushEntrySList(void* head, SLIST_ENTRY* entry)
{
    (void) head;
    (void) entry;
}

__declspec(dllexport) SLIST_ENTRY* InterlockedPopEntrySList(void* head)
{
    (void) head;
    return (SLIST_ENTRY*) 0;
}

__declspec(dllexport) SLIST_ENTRY* InterlockedFlushSList(void* head)
{
    (void) head;
    return (SLIST_ENTRY*) 0;
}

__declspec(dllexport) void InitializeSListHead(void* head)
{
    /* Zero the 16-byte SLIST_HEADER (one pointer + one u64
     * aligned pair on x64). Byte loop keeps this independent
     * of memset. */
    if (head != (void*) 0)
    {
        unsigned char* b = (unsigned char*) head;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
}

/* ------------------------------------------------------------------
 * Virtual memory (slice 18)
 *
 * SYS_VMAP   = 28 — bump-allocate `size` bytes (page-rounded)
 *              from the per-process vmap arena, return VA.
 * SYS_VUNMAP = 29 — release a (va, size) range; returns 0 on
 *              hit, -1 if outside the arena.
 *
 * Both ignore Win32's lpAddress / flAllocationType / flProtect
 * args today. v0 vmap pages are always RW+NX (W^X), so
 * VirtualProtect is a no-op that just round-trips the previous
 * protection value to keep CRT-startup probe round-trips happy.
 * ------------------------------------------------------------------ */

typedef unsigned long long SIZE_T;
typedef unsigned int       PROT;

__declspec(dllexport) void* VirtualAlloc(void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    (void) lpAddress;
    (void) flAllocationType;
    (void) flProtect;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 28), "D"((long long) dwSize) : "memory");
    return (void*) rv;
}

/* VirtualAllocEx ignores the extra HANDLE arg in v0 (the flat
 * stub aliases this to VirtualAlloc — same here). */
__declspec(dllexport) void* VirtualAllocEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD flAllocationType,
                                           DWORD flProtect)
{
    (void) hProcess;
    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) BOOL VirtualFree(void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    (void) dwFreeType;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 29), "D"((long long) lpAddress), "S"((long long) dwSize)
                     : "memory");
    /* SYS_VUNMAP returns 0 on hit, -1 on miss; Win32 wants
     * BOOL TRUE on hit. */
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL VirtualFreeEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    (void) hProcess;
    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

__declspec(dllexport) BOOL VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
    (void) lpAddress;
    (void) dwSize;
    (void) flNewProtect;
    /* Every vmap page is RW+NX by construction (W^X). Round-
     * trip PAGE_READWRITE (= 0x04) as the "previous" protection
     * so MSVC CRT's probe path sees a plausible value. */
    if (lpflOldProtect != (DWORD*) 0)
        *lpflOldProtect = 0x04;
    return 1;
}

__declspec(dllexport) BOOL VirtualProtectEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD flNewProtect,
                                            DWORD* lpflOldProtect)
{
    (void) hProcess;
    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

/* ------------------------------------------------------------------
 * lstr* family (slice 18) — Windows' historic string helpers,
 * still imported by older / port-compat code paths in real
 * MSVC PEs. Same semantics as str / wcs intrinsics without
 * the SEH wrappers real Windows applies on top.
 * ------------------------------------------------------------------ */

#define NO_BUILTIN_LSTR __attribute__((no_builtin("strlen", "strcmp", "strcpy")))

__declspec(dllexport) NO_BUILTIN_LSTR int lstrlenA(const char* s)
{
    if (s == (const char*) 0)
        return 0; /* lstrlenA NUL-input returns 0, not crash */
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) NO_BUILTIN_LSTR int lstrcmpA(const char* a, const char* b)
{
    if (a == (const char*) 0 || b == (const char*) 0)
        return (a == b) ? 0 : (a == (const char*) 0 ? -1 : 1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int) (unsigned char) *a - (int) (unsigned char) *b;
}

__declspec(dllexport) NO_BUILTIN_LSTR int lstrcmpiA(const char* a, const char* b)
{
    if (a == (const char*) 0 || b == (const char*) 0)
        return (a == b) ? 0 : (a == (const char*) 0 ? -1 : 1);
    for (;; ++a, ++b)
    {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char) (ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char) (cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int) (unsigned char) ca - (int) (unsigned char) cb;
    }
}

__declspec(dllexport) NO_BUILTIN_LSTR char* lstrcpyA(char* dst, const char* src)
{
    if (dst == (char*) 0 || src == (const char*) 0)
        return dst;
    char* d = dst;
    while ((*d++ = *src++) != 0) { }
    return dst;
}

typedef unsigned short wchar_t16; /* Win32 wchar_t is UTF-16 */

__declspec(dllexport) int lstrlenW(const wchar_t16* s)
{
    if (s == (const wchar_t16*) 0)
        return 0;
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) int lstrcmpW(const wchar_t16* a, const wchar_t16* b)
{
    if (a == (const wchar_t16*) 0 || b == (const wchar_t16*) 0)
        return (a == b) ? 0 : (a == (const wchar_t16*) 0 ? -1 : 1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int) *a - (int) *b;
}

__declspec(dllexport) int lstrcmpiW(const wchar_t16* a, const wchar_t16* b)
{
    if (a == (const wchar_t16*) 0 || b == (const wchar_t16*) 0)
        return (a == b) ? 0 : (a == (const wchar_t16*) 0 ? -1 : 1);
    for (;; ++a, ++b)
    {
        wchar_t16 ca = *a;
        wchar_t16 cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16) (ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16) (cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int) ca - (int) cb;
    }
}

__declspec(dllexport) wchar_t16* lstrcpyW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*) 0 || src == (const wchar_t16*) 0)
        return dst;
    wchar_t16* d = dst;
    while ((*d++ = *src++) != 0) { }
    return dst;
}

/* ------------------------------------------------------------------
 * File / console I/O (slice 19)
 *
 * Backed by the file syscall family:
 *   SYS_WRITE      = 2  — fd-based write (fd=1 → stdout)
 *   SYS_FILE_OPEN  = 20 — open (rdi=ASCII path, rsi=len)
 *   SYS_FILE_READ  = 21 — read (rdi=handle, rsi=buf, rdx=count)
 *   SYS_FILE_CLOSE = 22 — close (rdi=handle, no-op for unknown)
 *   SYS_FILE_SEEK  = 23 — seek (rdi=handle, rsi=offset, rdx=whence)
 *   SYS_FILE_FSTAT = 24 — fstat-style size (rdi=handle, rsi=outptr)
 *
 * The Win32 contract: handle goes in rcx, then rdx, r8, r9 for
 * args 2-4, with arg 5+ on the stack. Our SYS_* take args in
 * rdi, rsi, rdx, r10, r8, r9 — so the trampolines mostly just
 * shuffle the calling convention.
 *
 * WriteFile / WriteConsole* ignore the handle and route to
 * SYS_WRITE(fd=1) — same simplification as the existing flat
 * stubs. Real handle-aware writes need a richer dispatch
 * (file vs console vs pipe); deferred.
 * ------------------------------------------------------------------ */

typedef void* LPDWORD_t; /* DWORD* via opaque pointer to avoid C-warning chains */

__declspec(dllexport) BOOL WriteFile(HANDLE hFile, const void* buf, DWORD n, DWORD* lpWritten, void* lpOverlapped)
{
    (void) hFile;
    (void) lpOverlapped;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 2),       /* SYS_WRITE */
                       "D"((long long) 1),       /* fd=1 (stdout) */
                       "S"((long long) buf),     /* buf */
                       "d"((long long) n)        /* count */
                     : "memory");
    if (lpWritten != (DWORD*) 0)
        *lpWritten = rv >= 0 ? (DWORD) rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL WriteConsoleA(HANDLE hConsole, const void* buf, DWORD n, DWORD* lpWritten, void* lpReserved)
{
    /* Same shape as WriteFile — alias the impl. */
    return WriteFile(hConsole, buf, n, lpWritten, lpReserved);
}

/* WriteConsoleW — n is wide-char count. Emit each wchar's low
 * byte to stdout (UTF-16 → ASCII strip; fine for ASCII and
 * Latin-1 codepoints, garbles the rest. Same approximation as
 * the flat stub at kOffWriteConsoleW). */
__declspec(dllexport) BOOL WriteConsoleW(HANDLE hConsole, const wchar_t16* buf, DWORD n, DWORD* lpWritten,
                                         void* lpReserved)
{
    (void) hConsole;
    (void) lpReserved;
    if (buf == (const wchar_t16*) 0 || n == 0)
    {
        if (lpWritten != (DWORD*) 0)
            *lpWritten = 0;
        return 1;
    }
    /* Strip into a stack-local ASCII buffer up to 256 bytes
     * per call. CRT writes typically come a line at a time so
     * this is rarely a real cap. */
    char ascii[256];
    DWORD cap = n > 256 ? 256 : n;
    for (DWORD i = 0; i < cap; ++i)
        ascii[i] = (char) (buf[i] & 0xFF);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 2),       /* SYS_WRITE */
                       "D"((long long) 1),       /* fd=1 */
                       "S"((long long) ascii),
                       "d"((long long) cap)
                     : "memory");
    if (lpWritten != (DWORD*) 0)
        *lpWritten = rv >= 0 ? (DWORD) rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL CloseHandle(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long) 22),     /* SYS_FILE_CLOSE */
                       "D"((long long) h)
                     : "memory");
    return 1; /* Match flat-stub: always TRUE — kernel side
               * handles unknown handles as a no-op. */
}

/* CreateFileW — wide path in rcx (lpFileName), other args
 * ignored. UTF-16 → ASCII strip on a stack-local buffer, then
 * SYS_FILE_OPEN(rdi=path, rsi=len). Returns the kernel handle
 * (Win32-shaped 0x100..0x10F) or -1 on failure. */
__declspec(dllexport) HANDLE CreateFileW(const wchar_t16* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                         void* lpSecurityAttributes, DWORD dwCreationDisposition,
                                         DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    (void) dwDesiredAccess;
    (void) dwShareMode;
    (void) lpSecurityAttributes;
    (void) dwCreationDisposition;
    (void) dwFlagsAndAttributes;
    (void) hTemplateFile;
    if (lpFileName == (const wchar_t16*) 0)
        return (HANDLE) (long long) -1; /* INVALID_HANDLE_VALUE */
    char ascii[256];
    int  i = 0;
    while (i < 255 && lpFileName[i] != 0)
    {
        ascii[i] = (char) (lpFileName[i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 20),     /* SYS_FILE_OPEN */
                       "D"((long long) ascii),
                       "S"((long long) i)
                     : "memory");
    return (HANDLE) rv;
}

__declspec(dllexport) BOOL ReadFile(HANDLE h, void* buf, DWORD count, DWORD* lpRead, void* lpOverlapped)
{
    (void) lpOverlapped;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 21),     /* SYS_FILE_READ */
                       "D"((long long) h),
                       "S"((long long) buf),
                       "d"((long long) count)
                     : "memory");
    if (lpRead != (DWORD*) 0)
        *lpRead = rv >= 0 ? (DWORD) rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL SetFilePointerEx(HANDLE h, long long liDistance, long long* lpNewPosition,
                                            DWORD dwMoveMethod)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 23),     /* SYS_FILE_SEEK */
                       "D"((long long) h),
                       "S"((long long) liDistance),
                       "d"((long long) dwMoveMethod)
                     : "memory");
    if (lpNewPosition != (long long*) 0)
        *lpNewPosition = rv;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL GetFileSizeEx(HANDLE h, long long* lpFileSize)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 24),     /* SYS_FILE_FSTAT */
                       "D"((long long) h),
                       "S"((long long) lpFileSize)
                     : "memory");
    /* SYS_FILE_FSTAT returns 0 on success and writes to the
     * out pointer; non-zero is failure. */
    return rv == 0 ? 1 : 0;
}

/* GetFileSize — DWORD version. Same semantics as GetFileSizeEx
 * but returns the size in rax (low 32 bits) and writes the
 * high 32 bits via lpFileSizeHigh if non-null. */
__declspec(dllexport) DWORD GetFileSize(HANDLE h, DWORD* lpFileSizeHigh)
{
    long long size = 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 24),
                       "D"((long long) h),
                       "S"((long long) &size)
                     : "memory");
    if (rv != 0)
        return 0xFFFFFFFFu; /* INVALID_FILE_SIZE */
    if (lpFileSizeHigh != (DWORD*) 0)
        *lpFileSizeHigh = (DWORD) (size >> 32);
    return (DWORD) (size & 0xFFFFFFFFu);
}
