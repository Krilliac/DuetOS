/*
 * userland/libs/kernel32/kernel32.c
 *
 * Freestanding DuetOS kernel32.dll — ring-3 code that
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

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned long ULONG;
typedef unsigned long long UINT_PTR; /* 64-bit on x64 windows-msvc; DWORD is 32 */

#define WIN32_NORETURN __attribute__((noreturn))

/* ------------------------------------------------------------------
 * Process / thread identity (syscall-backed)
 * ------------------------------------------------------------------ */

/* SYS_GETPROCID = 8 — kernel returns CurrentProcess()->pid. */
__declspec(dllexport) DWORD GetCurrentProcessId(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)8) : "memory");
    return (DWORD)rv;
}

/* SYS_GETPID = 1 — kernel returns the scheduler task id.
 * This is "thread id" in the Win32 sense: per-thread, distinct
 * from the process id. Matches what the existing flat stub
 * (kOffGetCurrentThreadId) does. */
__declspec(dllexport) DWORD GetCurrentThreadId(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)1) : "memory");
    return (DWORD)rv;
}

/* ------------------------------------------------------------------
 * Pseudo-handles (constant returns)
 * Real Windows also returns these literal values; any receiver
 * checks for the sentinel rather than going through the handle
 * table.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE GetCurrentProcess(void)
{
    return (HANDLE)(long)-1;
}

__declspec(dllexport) HANDLE GetCurrentThread(void)
{
    return (HANDLE)(long)-2;
}

/* ------------------------------------------------------------------
 * Last-error slot (syscall-backed)
 * Per-process u32 stored in Process.win32_last_error.
 * ------------------------------------------------------------------ */

/* SYS_GETLASTERROR = 9 */
__declspec(dllexport) DWORD GetLastError(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)9) : "memory");
    return (DWORD)rv;
}

/* SYS_SETLASTERROR = 10 — rdi = new error code. */
__declspec(dllexport) void SetLastError(DWORD err)
{
    long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long)10), "D"((long)err) : "memory");
}

/* ------------------------------------------------------------------
 * Noreturn terminators (SYS_EXIT = 0, rdi = exit code)
 * ------------------------------------------------------------------ */

__declspec(dllexport) WIN32_NORETURN void ExitProcess(UINT uExitCode)
{
    __asm__ volatile("int $0x80" : : "a"((long)0), "D"((long)uExitCode));
    __builtin_unreachable();
}

/* TerminateProcess(hProcess, uExitCode) — hProcess is ignored
 * (single-process semantics match the existing stub). uExitCode
 * goes to SYS_EXIT same as ExitProcess. */
__declspec(dllexport) WIN32_NORETURN BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    (void)hProcess;
    __asm__ volatile("int $0x80" : : "a"((long)0), "D"((long)uExitCode));
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
    (void)feature;
    /* Optimistically claim every queried feature is present —
     * x86_64 universally has SSE / SSE2 / CMPXCHG16B / NX, and
     * AES / AVX / RDRAND are all visible in our CPU probe log.
     * Returning 0 forced every caller onto scalar-only fallback
     * paths; returning 1 matches modern hardware. */
    return 1;
}

__declspec(dllexport) BOOL SetConsoleCtrlHandler(void* handler, BOOL add)
{
    (void)handler;
    (void)add;
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
    return (HANDLE)(UINT_PTR)nStdHandle;
}

/* ------------------------------------------------------------------
 * Scheduler interaction (Sleep, SwitchToThread, GetTickCount)
 *
 * Sleep(0) specifically yields (SYS_SLEEP_MS with rdi=0 behaves
 * like SYS_YIELD per syscall.h:176-189), so a single trampoline
 * covers both "drop the timeslice" and "sleep N ms" semantics.
 * ------------------------------------------------------------------ */

typedef unsigned long long ULONGLONG;
typedef long LONG;

__declspec(dllexport) void Sleep(DWORD ms)
{
    long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long)19), "D"((long)ms) : "memory");
}

__declspec(dllexport) BOOL SwitchToThread(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)3) : "memory");
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
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)13) : "memory");
    return (ULONGLONG)rv * 10ULL;
}

__declspec(dllexport) DWORD GetTickCount(void)
{
    return (DWORD)GetTickCount64();
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
    (void)hConsole;
    if (lpMode != (DWORD*)0)
        *lpMode = 3; /* ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT */
    return 1;
}

/* Code pages: report CP_UTF8 (65001). Callers that serialise
 * via WriteConsoleW don't actually care; callers that ASK
 * expect a sane answer, and UTF-8 is closer to our actual
 * "pass through" stdout than OEM 437. batch27 of
 * hello_winapi.exe pins this at 65001. */
__declspec(dllexport) UINT GetConsoleCP(void)
{
    return 65001;
}

__declspec(dllexport) UINT GetConsoleOutputCP(void)
{
    return 65001;
}

__declspec(dllexport) BOOL SetConsoleMode(HANDLE hConsole, DWORD mode)
{
    (void)hConsole;
    (void)mode;
    return 1;
}

__declspec(dllexport) BOOL SetConsoleOutputCP(UINT cp)
{
    (void)cp;
    return 1;
}

/* OutputDebugStringA/W — route to SYS_DEBUG_PRINT (46) which
 * emits `[odbg] <text>` to COM1. Silently tolerates NULL. */
__declspec(dllexport) void OutputDebugStringA(const char* str)
{
    if (!str)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)46), "D"((long long)str) : "memory");
}

typedef unsigned short WCHAR_t;
__declspec(dllexport) void OutputDebugStringW(const WCHAR_t* wstr)
{
    if (!wstr)
        return;
    /* Strip to ASCII into a 256-byte stack buffer. */
    char buf[256];
    size_t i = 0;
    while (i < 255 && wstr[i])
    {
        buf[i] = (char)(wstr[i] & 0xFF);
        ++i;
    }
    buf[i] = 0;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)46), "D"((long long)buf) : "memory");
}

__declspec(dllexport) DWORD GetLogicalDrives(void)
{
    /* Bit 23 set = X: — same sentinel the flat stub returns. */
    return 0x00800000u;
}

__declspec(dllexport) UINT GetDriveTypeA(const char* root)
{
    (void)root;
    return 3; /* DRIVE_FIXED */
}

__declspec(dllexport) UINT GetDriveTypeW(const void* root)
{
    (void)root;
    return 3; /* DRIVE_FIXED */
}

__declspec(dllexport) BOOL IsWow64Process(HANDLE hProc, BOOL* Wow64Process)
{
    (void)hProc;
    if (Wow64Process != (BOOL*)0)
        *Wow64Process = 0; /* Native x64, not Wow64. */
    return 1;
}

__declspec(dllexport) BOOL IsWow64Process2(HANDLE hProc, unsigned short* proc_machine, unsigned short* native_machine)
{
    (void)hProc;
    if (proc_machine != (unsigned short*)0)
        *proc_machine = 0; /* IMAGE_FILE_MACHINE_UNKNOWN — not Wow64. */
    if (native_machine != (unsigned short*)0)
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
    (void)flags;
    (void)name;
    if (phmodule != (void**)0)
        *phmodule = (void*)0;
    return 0;
}

__declspec(dllexport) BOOL GetModuleHandleExA(DWORD flags, const char* name, void** phmodule)
{
    (void)flags;
    (void)name;
    if (phmodule != (void**)0)
        *phmodule = (void*)0;
    return 0;
}

__declspec(dllexport) BOOL FreeLibrary(void* hModule)
{
    (void)hModule;
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
    (void)head;
    (void)entry;
}

__declspec(dllexport) SLIST_ENTRY* InterlockedPopEntrySList(void* head)
{
    (void)head;
    return (SLIST_ENTRY*)0;
}

__declspec(dllexport) SLIST_ENTRY* InterlockedFlushSList(void* head)
{
    (void)head;
    return (SLIST_ENTRY*)0;
}

__declspec(dllexport) void InitializeSListHead(void* head)
{
    /* Zero the 16-byte SLIST_HEADER (one pointer + one u64
     * aligned pair on x64). Byte loop keeps this independent
     * of memset. */
    if (head != (void*)0)
    {
        unsigned char* b = (unsigned char*)head;
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
typedef unsigned int PROT;

__declspec(dllexport) void* VirtualAlloc(void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    (void)lpAddress;
    (void)flAllocationType;
    (void)flProtect;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)28), "D"((long long)dwSize) : "memory");
    return (void*)rv;
}

/* VirtualAllocEx ignores the extra HANDLE arg in v0 (the flat
 * stub aliases this to VirtualAlloc — same here). */
__declspec(dllexport) void* VirtualAllocEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD flAllocationType,
                                           DWORD flProtect)
{
    (void)hProcess;
    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) BOOL VirtualFree(void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    (void)dwFreeType;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)29), "D"((long long)lpAddress), "S"((long long)dwSize)
                     : "memory");
    /* SYS_VUNMAP returns 0 on hit, -1 on miss; Win32 wants
     * BOOL TRUE on hit. */
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL VirtualFreeEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    (void)hProcess;
    return VirtualFree(lpAddress, dwSize, dwFreeType);
}

__declspec(dllexport) BOOL VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
    (void)lpAddress;
    (void)dwSize;
    (void)flNewProtect;
    /* Every vmap page is RW+NX by construction (W^X). Round-
     * trip PAGE_READWRITE (= 0x04) as the "previous" protection
     * so MSVC CRT's probe path sees a plausible value. */
    if (lpflOldProtect != (DWORD*)0)
        *lpflOldProtect = 0x04;
    return 1;
}

__declspec(dllexport) BOOL VirtualProtectEx(HANDLE hProcess, void* lpAddress, SIZE_T dwSize, DWORD flNewProtect,
                                            DWORD* lpflOldProtect)
{
    (void)hProcess;
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
    if (s == (const char*)0)
        return 0; /* lstrlenA NUL-input returns 0, not crash */
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) NO_BUILTIN_LSTR int lstrcmpA(const char* a, const char* b)
{
    if (a == (const char*)0 || b == (const char*)0)
        return (a == b) ? 0 : (a == (const char*)0 ? -1 : 1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

__declspec(dllexport) NO_BUILTIN_LSTR int lstrcmpiA(const char* a, const char* b)
{
    if (a == (const char*)0 || b == (const char*)0)
        return (a == b) ? 0 : (a == (const char*)0 ? -1 : 1);
    for (;; ++a, ++b)
    {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
    }
}

__declspec(dllexport) NO_BUILTIN_LSTR char* lstrcpyA(char* dst, const char* src)
{
    if (dst == (char*)0 || src == (const char*)0)
        return dst;
    char* d = dst;
    while ((*d++ = *src++) != 0)
    {
    }
    return dst;
}

typedef unsigned short wchar_t16; /* Win32 wchar_t is UTF-16 */

__declspec(dllexport) int lstrlenW(const wchar_t16* s)
{
    if (s == (const wchar_t16*)0)
        return 0;
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

__declspec(dllexport) int lstrcmpW(const wchar_t16* a, const wchar_t16* b)
{
    if (a == (const wchar_t16*)0 || b == (const wchar_t16*)0)
        return (a == b) ? 0 : (a == (const wchar_t16*)0 ? -1 : 1);
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return (int)*a - (int)*b;
}

__declspec(dllexport) int lstrcmpiW(const wchar_t16* a, const wchar_t16* b)
{
    if (a == (const wchar_t16*)0 || b == (const wchar_t16*)0)
        return (a == b) ? 0 : (a == (const wchar_t16*)0 ? -1 : 1);
    for (;; ++a, ++b)
    {
        wchar_t16 ca = *a;
        wchar_t16 cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16)(cb + ('a' - 'A'));
        if (!ca || ca != cb)
            return (int)ca - (int)cb;
    }
}

__declspec(dllexport) wchar_t16* lstrcpyW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*)0 || src == (const wchar_t16*)0)
        return dst;
    wchar_t16* d = dst;
    while ((*d++ = *src++) != 0)
    {
    }
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
    (void)hFile;
    (void)lpOverlapped;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)2),   /* SYS_WRITE */
                       "D"((long long)1),   /* fd=1 (stdout) */
                       "S"((long long)buf), /* buf */
                       "d"((long long)n)    /* count */
                     : "memory");
    if (lpWritten != (DWORD*)0)
        *lpWritten = rv >= 0 ? (DWORD)rv : 0;
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
    (void)hConsole;
    (void)lpReserved;
    if (buf == (const wchar_t16*)0 || n == 0)
    {
        if (lpWritten != (DWORD*)0)
            *lpWritten = 0;
        return 1;
    }
    /* Strip into a stack-local ASCII buffer up to 256 bytes
     * per call. CRT writes typically come a line at a time so
     * this is rarely a real cap. */
    char ascii[256];
    DWORD cap = n > 256 ? 256 : n;
    for (DWORD i = 0; i < cap; ++i)
        ascii[i] = (char)(buf[i] & 0xFF);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)2), /* SYS_WRITE */
                       "D"((long long)1), /* fd=1 */
                       "S"((long long)ascii), "d"((long long)cap)
                     : "memory");
    if (lpWritten != (DWORD*)0)
        *lpWritten = rv >= 0 ? (DWORD)rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL CloseHandle(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)22), /* SYS_FILE_CLOSE */
                       "D"((long long)h)
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
    (void)dwDesiredAccess;
    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)dwCreationDisposition;
    (void)dwFlagsAndAttributes;
    (void)hTemplateFile;
    if (lpFileName == (const wchar_t16*)0)
        return (HANDLE)(long long)-1; /* INVALID_HANDLE_VALUE */
    char ascii[256];
    int i = 0;
    while (i < 255 && lpFileName[i] != 0)
    {
        ascii[i] = (char)(lpFileName[i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)20), /* SYS_FILE_OPEN */
                       "D"((long long)ascii), "S"((long long)i)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) BOOL ReadFile(HANDLE h, void* buf, DWORD count, DWORD* lpRead, void* lpOverlapped)
{
    (void)lpOverlapped;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)21), /* SYS_FILE_READ */
                       "D"((long long)h), "S"((long long)buf), "d"((long long)count)
                     : "memory");
    if (lpRead != (DWORD*)0)
        *lpRead = rv >= 0 ? (DWORD)rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL SetFilePointerEx(HANDLE h, long long liDistance, long long* lpNewPosition,
                                            DWORD dwMoveMethod)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)23), /* SYS_FILE_SEEK */
                       "D"((long long)h), "S"((long long)liDistance), "d"((long long)dwMoveMethod)
                     : "memory");
    if (lpNewPosition != (long long*)0)
        *lpNewPosition = rv;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL GetFileSizeEx(HANDLE h, long long* lpFileSize)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)24), /* SYS_FILE_FSTAT */
                       "D"((long long)h), "S"((long long)lpFileSize)
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
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)24), "D"((long long)h), "S"((long long)&size) : "memory");
    if (rv != 0)
        return 0xFFFFFFFFu; /* INVALID_FILE_SIZE */
    if (lpFileSizeHigh != (DWORD*)0)
        *lpFileSizeHigh = (DWORD)(size >> 32);
    return (DWORD)(size & 0xFFFFFFFFu);
}

/* ------------------------------------------------------------------
 * Time queries (slice 20)
 *
 * SYS_GETTIME_FT = 17 — Windows FILETIME (100 ns ticks since 1601).
 * SYS_NOW_NS     = 18 — nanoseconds since boot (HPET-backed).
 *
 * QueryPerformanceFrequency reports 1 GHz so QPC/QPF division
 * yields seconds with ~70 ns granularity.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void GetSystemTimeAsFileTime(long long* lpFileTime)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)17) : "memory");
    if (lpFileTime != (long long*)0)
        *lpFileTime = rv;
}

__declspec(dllexport) BOOL QueryPerformanceCounter(long long* lpPerformanceCount)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)18) : "memory");
    if (lpPerformanceCount != (long long*)0)
        *lpPerformanceCount = rv;
    return 1;
}

__declspec(dllexport) BOOL QueryPerformanceFrequency(long long* lpFrequency)
{
    /* 1 GHz — pairs with QPC's nanosecond return so subtraction
     * + division yields seconds. */
    if (lpFrequency != (long long*)0)
        *lpFrequency = 1000000000LL;
    return 1;
}

/* ------------------------------------------------------------------
 * Heap aliases (slice 20)
 *
 * These all alias to the per-process heap via SYS_HEAP_*.
 * GetProcessHeap returns a sentinel; HeapAlloc/Free/Size/ReAlloc
 * ignore the heap handle (single-heap-per-process v0). HeapCreate /
 * HeapDestroy pretend to succeed.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE GetProcessHeap(void)
{
    /* Sentinel — same value as the flat stub returned, matching
     * the per-process heap base. */
    return (HANDLE)0x50000000ULL;
}

__declspec(dllexport) void* HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    (void)hHeap;
    (void)dwFlags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)dwBytes) : "memory");
    return (void*)rv;
}

__declspec(dllexport) BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem)
{
    (void)hHeap;
    (void)dwFlags;
    if (lpMem == (void*)0)
        return 1;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)lpMem) : "memory");
    return 1;
}

__declspec(dllexport) SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem)
{
    (void)hHeap;
    (void)dwFlags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)14), "D"((long long)lpMem) : "memory");
    return (SIZE_T)rv;
}

__declspec(dllexport) void* HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, SIZE_T dwBytes)
{
    (void)hHeap;
    (void)dwFlags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)15), "D"((long long)lpMem), "S"((long long)dwBytes)
                     : "memory");
    return (void*)rv;
}

__declspec(dllexport) HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    (void)flOptions;
    (void)dwInitialSize;
    (void)dwMaximumSize;
    /* All heaps collapse to the per-process default. Return the
     * sentinel from GetProcessHeap. */
    return (HANDLE)0x50000000ULL;
}

__declspec(dllexport) BOOL HeapDestroy(HANDLE hHeap)
{
    (void)hHeap;
    return 1; /* Pretend success — we don't refcount heaps. */
}

/* ------------------------------------------------------------------
 * Locale / code page (slice 20)
 *
 * v0 reports a US-English / Latin-1 locale across the board.
 * Programs that branch on these mostly just want a sane default.
 * ------------------------------------------------------------------ */

__declspec(dllexport) UINT GetACP(void)
{
    return 1252; /* Western European Latin-1 ANSI code page. */
}

__declspec(dllexport) UINT GetOEMCP(void)
{
    return 437; /* Same as GetConsoleCP. */
}

__declspec(dllexport) BOOL IsValidCodePage(UINT codepage)
{
    /* Accept 437 / 1252 (the two we report) and 65001 (UTF-8). */
    return (codepage == 437 || codepage == 1252 || codepage == 65001) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * MultiByteToWideChar / WideCharToMultiByte (slice 20)
 *
 * v0 only supports a 1:1 byte-to-wchar conversion (low byte of
 * the wchar = the source byte). Sufficient for ASCII and
 * passable for Latin-1; ignores codepage entirely. The flat
 * stubs at kOffMBtoWC / kOffWCtoMB do the same.
 * ------------------------------------------------------------------ */

__declspec(dllexport) int MultiByteToWideChar(UINT codepage, DWORD dwFlags, const char* lpMultiByteStr, int cbMultiByte,
                                              wchar_t16* lpWideCharStr, int cchWideChar)
{
    (void)codepage;
    (void)dwFlags;
    if (lpMultiByteStr == (const char*)0)
        return 0;
    /* cbMultiByte == -1 means "input is NUL-terminated; include
     * the terminator in the output". Compute length first. */
    int in_len;
    if (cbMultiByte < 0)
    {
        int n = 0;
        while (lpMultiByteStr[n] != 0)
            ++n;
        in_len = n + 1; /* include the NUL */
    }
    else
        in_len = cbMultiByte;
    if (cchWideChar == 0 || lpWideCharStr == (wchar_t16*)0)
        return in_len; /* Caller is asking for required size. */
    int copy = in_len < cchWideChar ? in_len : cchWideChar;
    for (int i = 0; i < copy; ++i)
        lpWideCharStr[i] = (wchar_t16)(unsigned char)lpMultiByteStr[i];
    return copy;
}

__declspec(dllexport) int WideCharToMultiByte(UINT codepage, DWORD dwFlags, const wchar_t16* lpWideCharStr,
                                              int cchWideChar, char* lpMultiByteStr, int cbMultiByte,
                                              const char* lpDefaultChar, BOOL* lpUsedDefaultChar)
{
    (void)codepage;
    (void)dwFlags;
    (void)lpDefaultChar;
    if (lpUsedDefaultChar != (BOOL*)0)
        *lpUsedDefaultChar = 0;
    if (lpWideCharStr == (const wchar_t16*)0)
        return 0;
    int in_len;
    if (cchWideChar < 0)
    {
        int n = 0;
        while (lpWideCharStr[n] != 0)
            ++n;
        in_len = n + 1;
    }
    else
        in_len = cchWideChar;
    if (cbMultiByte == 0 || lpMultiByteStr == (char*)0)
        return in_len;
    int copy = in_len < cbMultiByte ? in_len : cbMultiByte;
    for (int i = 0; i < copy; ++i)
        lpMultiByteStr[i] = (char)(lpWideCharStr[i] & 0xFF);
    return copy;
}

/* ------------------------------------------------------------------
 * TLS slots (slice 21)
 *
 * SYS_TLS_ALLOC = 34 / FREE = 35 / GET = 36 / SET = 37.
 * Per-process TLS table backs all four. TLS_OUT_OF_INDEXES =
 * 0xFFFFFFFF returned on alloc failure / invalid slot.
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD TlsAlloc(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)34) : "memory");
    /* Kernel returns u32(-1) on failure; pass through. */
    return (DWORD)rv;
}

__declspec(dllexport) BOOL TlsFree(DWORD slot)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)35), "D"((long long)slot) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) void* TlsGetValue(DWORD slot)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)36), "D"((long long)slot) : "memory");
    return (void*)rv;
}

__declspec(dllexport) BOOL TlsSetValue(DWORD slot, void* value)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)37), "D"((long long)slot), "S"((long long)value)
                     : "memory");
    return rv == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Win32 sync primitives — handle-based (slice 21)
 *
 * Kernel state lives in Process tables (mutex, event,
 * semaphore, thread). Handles are kWin32{Mutex,Event,Sem,Thread}
 * Base + slot index. Each Create/Release/Wait routes to the
 * matching SYS_* call.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE CreateMutexW(void* sec, BOOL bInitialOwner, const wchar_t16* name)
{
    (void)sec;
    (void)name;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)25), "D"((long long)bInitialOwner) : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE CreateMutexA(void* sec, BOOL bInitialOwner, const char* name)
{
    (void)name;
    return CreateMutexW(sec, bInitialOwner, (const wchar_t16*)0);
}

__declspec(dllexport) BOOL ReleaseMutex(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)27), "D"((long long)h) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) HANDLE CreateEventW(void* sec, BOOL bManualReset, BOOL bInitialState, const wchar_t16* name)
{
    (void)sec;
    (void)name;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)30), "D"((long long)bManualReset), "S"((long long)bInitialState)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE CreateEventA(void* sec, BOOL bManualReset, BOOL bInitialState, const char* name)
{
    (void)name;
    return CreateEventW(sec, bManualReset, bInitialState, (const wchar_t16*)0);
}

__declspec(dllexport) BOOL SetEvent(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)31), "D"((long long)h) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL ResetEvent(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)32), "D"((long long)h) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) HANDLE CreateSemaphoreW(void* sec, long initial, long maximum, const wchar_t16* name)
{
    (void)sec;
    (void)name;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)51), "D"((long long)initial), "S"((long long)maximum)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE CreateSemaphoreA(void* sec, long initial, long maximum, const char* name)
{
    (void)name;
    return CreateSemaphoreW(sec, initial, maximum, (const wchar_t16*)0);
}

__declspec(dllexport) BOOL ReleaseSemaphore(HANDLE h, long releaseCount, long* lpPreviousCount)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)52), "D"((long long)h), "S"((long long)releaseCount)
                     : "memory");
    if (lpPreviousCount != (long*)0)
        *lpPreviousCount = 0; /* v0 doesn't track previous count. */
    return rv == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * WaitForSingleObject — dispatch by handle range
 *
 * Mutex (0x200..0x207)    -> SYS_MUTEX_WAIT (26)
 * Event (0x300..0x307)    -> SYS_EVENT_WAIT (33)
 * Semaphore (0x500..0x507) -> SYS_SEM_WAIT (53)
 * Thread (0x400..0x407)   -> SYS_THREAD_WAIT (54)
 * Anything else            -> WAIT_OBJECT_0 (0) — pseudo-signal
 *                             (matches the flat-stub fallback)
 * ------------------------------------------------------------------ */

#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 0x102u

__declspec(dllexport) DWORD WaitForSingleObject(HANDLE h, DWORD timeout_ms)
{
    unsigned long long handle = (unsigned long long)h;
    long long rv;
    long long syscall_num;
    if (handle >= 0x200 && handle < 0x208)
        syscall_num = 26; /* SYS_MUTEX_WAIT */
    else if (handle >= 0x300 && handle < 0x308)
        syscall_num = 33; /* SYS_EVENT_WAIT */
    else if (handle >= 0x500 && handle < 0x508)
        syscall_num = 53; /* SYS_SEM_WAIT */
    else if (handle >= 0x400 && handle < 0x408)
        syscall_num = 54; /* SYS_THREAD_WAIT */
    else
        return WAIT_OBJECT_0; /* Unknown handle — pseudo-signal. */
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(syscall_num), "D"((long long)h), "S"((long long)timeout_ms)
                     : "memory");
    return (DWORD)rv;
}

__declspec(dllexport) DWORD WaitForSingleObjectEx(HANDLE h, DWORD timeout_ms, BOOL bAlertable)
{
    (void)bAlertable; /* APCs not supported in v0. */
    return WaitForSingleObject(h, timeout_ms);
}

/* ------------------------------------------------------------------
 * CriticalSection (slice 22)
 *
 * CRITICAL_SECTION is a 40-byte caller-owned struct. v0 uses the
 * first 16 bytes as:
 *   [cs + 0]: owner TID (0 = unowned)
 *   [cs + 8]: recursion count
 *
 * Same TID = SYS_GETPID (1). Spin-CAS with SYS_YIELD on
 * contention. Recursive re-entry just bumps the count.
 * Matches the flat-stub semantics at kOffEnterCritSecReal.
 * ------------------------------------------------------------------ */

typedef long long volatile* CritSecPtr;

static long long syscall_get_tid(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)1) : "memory");
    return rv;
}

static void syscall_yield(void)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)3) : "memory");
}

__declspec(dllexport) BOOL InitializeCriticalSection(void* cs)
{
    /* Zero the 40-byte CRITICAL_SECTION. Byte loop keeps this
     * independent of memset. */
    if (cs != (void*)0)
    {
        unsigned char* b = (unsigned char*)cs;
        for (int i = 0; i < 40; ++i)
            b[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL InitializeCriticalSectionEx(void* cs, DWORD spin, DWORD flags)
{
    (void)spin;
    (void)flags;
    return InitializeCriticalSection(cs);
}

__declspec(dllexport) BOOL InitializeCriticalSectionAndSpinCount(void* cs, DWORD spin)
{
    (void)spin;
    return InitializeCriticalSection(cs);
}

__declspec(dllexport) void DeleteCriticalSection(void* cs)
{
    (void)cs;
    /* No allocations to free; flat stub is also a no-op. */
}

__declspec(dllexport) void EnterCriticalSection(void* cs)
{
    long long tid = syscall_get_tid();
    CritSecPtr owner = (CritSecPtr)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    for (;;)
    {
        long long expected = 0;
        if (__atomic_compare_exchange_n(owner, &expected, tid, /*weak=*/0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        {
            /* First acquire: recursion := 1. */
            *recur = 1;
            return;
        }
        if (expected == tid)
        {
            /* Already held by us — bump recursion. */
            *recur = *recur + 1;
            return;
        }
        /* Contended — yield and retry. */
        syscall_yield();
    }
}

__declspec(dllexport) void LeaveCriticalSection(void* cs)
{
    CritSecPtr owner = (CritSecPtr)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    long long next = *recur - 1;
    *recur = next;
    if (next == 0)
        *owner = 0; /* Release: next acquirer's CAS wins. */
}

__declspec(dllexport) BOOL TryEnterCriticalSection(void* cs)
{
    long long tid = syscall_get_tid();
    CritSecPtr owner = (CritSecPtr)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    long long expected = 0;
    if (__atomic_compare_exchange_n(owner, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        *recur = 1;
        return 1;
    }
    if (expected == tid)
    {
        *recur = *recur + 1;
        return 1;
    }
    return 0; /* Contended; do NOT spin. */
}

/* ------------------------------------------------------------------
 * SRWLock — single 8-byte slot, exclusive only (slice 22)
 *
 * v0 collapses shared/exclusive to exclusive. Real Win32 SRW
 * locks are NOT reentrant — second acquire from the same thread
 * deadlocks. We preserve that contract.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void InitializeSRWLock(void* lock)
{
    if (lock != (void*)0)
        *(long long volatile*)lock = 0;
}

__declspec(dllexport) void AcquireSRWLockExclusive(void* lock)
{
    long long tid = syscall_get_tid();
    long long volatile* p = (long long volatile*)lock;
    for (;;)
    {
        long long expected = 0;
        if (__atomic_compare_exchange_n(p, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            return;
        syscall_yield();
    }
}

__declspec(dllexport) void ReleaseSRWLockExclusive(void* lock)
{
    if (lock != (void*)0)
        *(long long volatile*)lock = 0;
}

__declspec(dllexport) BOOL TryAcquireSRWLockExclusive(void* lock)
{
    long long tid = syscall_get_tid();
    long long volatile* p = (long long volatile*)lock;
    long long expected = 0;
    if (__atomic_compare_exchange_n(p, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return 1;
    return 0;
}

/* SRW shared aliases collapse to exclusive in v0. */
__declspec(dllexport) void AcquireSRWLockShared(void* lock)
{
    AcquireSRWLockExclusive(lock);
}

__declspec(dllexport) void ReleaseSRWLockShared(void* lock)
{
    ReleaseSRWLockExclusive(lock);
}

__declspec(dllexport) BOOL TryAcquireSRWLockShared(void* lock)
{
    return TryAcquireSRWLockExclusive(lock);
}

/* ------------------------------------------------------------------
 * InitOnceExecuteOnce (slice 22)
 *
 * INIT_ONCE is an 8-byte slot we interpret as:
 *     0 = untouched
 *     1 = initialiser running
 *     2 = done
 *
 * Single CAS 0->1 picks the initialiser; losers spin-yield
 * until the slot reaches 2. Null InitFn legitimately marks
 * "complete without running anything".
 * ------------------------------------------------------------------ */

typedef BOOL (*InitOnceFn)(void* InitOnce, void* Parameter, void** Context);

__declspec(dllexport) BOOL InitOnceExecuteOnce(void* InitOnce, InitOnceFn InitFn, void* Parameter, void** Context)
{
    long long volatile* slot = (long long volatile*)InitOnce;
    long long expected = 0;
    if (__atomic_compare_exchange_n(slot, &expected, 1LL, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        /* We won the CAS — run the initialiser (if any). */
        if (InitFn != (InitOnceFn)0)
            InitFn(InitOnce, Parameter, Context);
        *slot = 2; /* Mark done. */
        return 1;
    }
    /* Lost the CAS — wait for the winner to mark it done. */
    while (__atomic_load_n(slot, __ATOMIC_SEQ_CST) != 2)
        syscall_yield();
    return 1;
}

/* ------------------------------------------------------------------
 * Thread management (slice 23)
 *
 * SYS_THREAD_CREATE = 45 (rdi=start_va, rsi=param) -> handle
 * SYS_THREAD_EXIT_CODE = 55 (rdi=handle) -> exit code
 * SYS_EXIT = 0 (rdi=code, [[noreturn]])
 *
 * ResumeThread is registered as kOffReturnZero in the flat
 * stubs (we don't pause threads at create time today, so
 * Resume is a no-op). Same here.
 * ------------------------------------------------------------------ */

typedef DWORD (*ThreadStartFn)(void*);

__declspec(dllexport) HANDLE CreateThread(void* lpThreadAttributes, SIZE_T dwStackSize, ThreadStartFn lpStartAddress,
                                          void* lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId)
{
    (void)lpThreadAttributes;
    (void)dwStackSize;
    (void)dwCreationFlags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)45), "D"((long long)lpStartAddress), "S"((long long)lpParameter)
                     : "memory");
    /* Win32 contract: NULL on failure. The kernel returns -1
     * (cast as u64 = 0xFF..F) on failure; translate. */
    if (rv == -1)
    {
        if (lpThreadId != (DWORD*)0)
            *lpThreadId = 0;
        return (HANDLE)0;
    }
    if (lpThreadId != (DWORD*)0)
        *lpThreadId = (DWORD)rv;
    return (HANDLE)rv;
}

__declspec(dllexport) DWORD ResumeThread(HANDLE hThread)
{
    (void)hThread;
    /* No suspended-thread state in v0 — every CreateThread runs
     * immediately. Return 0 (= "thread was not previously
     * suspended"), matching the flat stub's behaviour. */
    return 0;
}

__declspec(dllexport) BOOL GetExitCodeThread(HANDLE hThread, DWORD* lpExitCode)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)55), "D"((long long)hThread) : "memory");
    /* SYS_THREAD_EXIT_CODE returns u64(-1) on bad handle and
     * the actual exit code (or STILL_ACTIVE = 0x103) otherwise.
     * Win32 contract: BOOL TRUE on success regardless of
     * STILL_ACTIVE; we always claim success (matches flat
     * stub's optimism). */
    if (lpExitCode != (DWORD*)0)
        *lpExitCode = (rv == -1) ? 0x103 : (DWORD)rv;
    return 1;
}

__declspec(dllexport) WIN32_NORETURN void ExitThread(DWORD dwExitCode)
{
    /* For our single-thread-per-process model ExitThread ==
     * ExitProcess. Match the flat stub's behaviour. */
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)dwExitCode));
    __builtin_unreachable();
}

__declspec(dllexport) BOOL GetExitCodeProcess(HANDLE hProcess, DWORD* lpExitCode)
{
    /* No cross-process query in v0 — pretend the queried
     * process is still running. Matches the flat stub's
     * STILL_ACTIVE behaviour. */
    (void)hProcess;
    if (lpExitCode != (DWORD*)0)
        *lpExitCode = 0x103; /* STILL_ACTIVE */
    return 1;
}

/* ------------------------------------------------------------------
 * File system (slice 30) — Find*, Copy/Move/Delete, dir ops.
 * All report "not found" / ACCESS_DENIED to keep real programs
 * on their graceful-failure paths.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE FindFirstFileA(const char* path, void* find_data)
{
    (void)path;
    (void)find_data;
    return (HANDLE)(long long)-1; /* INVALID_HANDLE_VALUE — "no files" */
}

__declspec(dllexport) HANDLE FindFirstFileW(const wchar_t16* path, void* find_data)
{
    (void)path;
    (void)find_data;
    return (HANDLE)(long long)-1;
}

__declspec(dllexport) BOOL FindNextFileA(HANDLE h, void* find_data)
{
    (void)h;
    (void)find_data;
    return 0; /* No more files */
}

__declspec(dllexport) BOOL FindNextFileW(HANDLE h, void* find_data)
{
    (void)h;
    (void)find_data;
    return 0;
}

__declspec(dllexport) BOOL FindClose(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL CopyFileA(const char* src, const char* dst, BOOL fail_if_exists)
{
    (void)src;
    (void)dst;
    (void)fail_if_exists;
    return 0;
}

__declspec(dllexport) BOOL CopyFileW(const wchar_t16* src, const wchar_t16* dst, BOOL fail_if_exists)
{
    (void)src;
    (void)dst;
    (void)fail_if_exists;
    return 0;
}

__declspec(dllexport) BOOL MoveFileA(const char* src, const char* dst)
{
    (void)src;
    (void)dst;
    return 0;
}

__declspec(dllexport) BOOL MoveFileW(const wchar_t16* src, const wchar_t16* dst)
{
    (void)src;
    (void)dst;
    return 0;
}

__declspec(dllexport) BOOL DeleteFileA(const char* path)
{
    (void)path;
    return 0;
}

__declspec(dllexport) BOOL DeleteFileW(const wchar_t16* path)
{
    (void)path;
    return 0;
}

__declspec(dllexport) DWORD GetFileAttributesA(const char* path)
{
    (void)path;
    return 0xFFFFFFFFu; /* INVALID_FILE_ATTRIBUTES — "not found" */
}

__declspec(dllexport) DWORD GetFileAttributesW(const wchar_t16* path)
{
    (void)path;
    return 0xFFFFFFFFu;
}

/* SetFileAttributes — v0 has no writable FS backend; pretend
 * success (TRUE). Callers that care check GetFileAttributes
 * afterward and see the attributes unchanged — they proceed
 * on the assumption we lost the write; same observable as
 * "read-only FS". batch37 of hello_winapi pins TRUE. */
__declspec(dllexport) BOOL SetFileAttributesA(const char* path, DWORD attrs)
{
    (void)path;
    (void)attrs;
    return 1;
}

__declspec(dllexport) BOOL SetFileAttributesW(const wchar_t16* path, DWORD attrs)
{
    (void)path;
    (void)attrs;
    return 1;
}

__declspec(dllexport) BOOL CreateDirectoryA(const char* path, void* sec)
{
    (void)path;
    (void)sec;
    return 0;
}

__declspec(dllexport) BOOL CreateDirectoryW(const wchar_t16* path, void* sec)
{
    (void)path;
    (void)sec;
    return 0;
}

__declspec(dllexport) BOOL RemoveDirectoryA(const char* path)
{
    (void)path;
    return 0;
}

__declspec(dllexport) BOOL RemoveDirectoryW(const wchar_t16* path)
{
    (void)path;
    return 0;
}

__declspec(dllexport) BOOL FlushFileBuffers(HANDLE h)
{
    (void)h;
    return 1;
}

/* System-directory queries — all report L"X:\\" (4 chars incl
 * NUL, 3 chars excl NUL). Matches the flat-stub semantics that
 * hello_winapi's batch35 pins.
 *
 * Signatures:
 *   DWORD  GetTempPathW(DWORD size, LPWSTR buf);      size-first
 *   UINT   GetWindowsDirectoryW(LPWSTR buf, UINT sz); buffer-first
 *   UINT   GetSystemDirectoryW(LPWSTR buf, UINT sz);  buffer-first
 *
 * All return 3 on success (chars written excl NUL) or 4 if
 * the buffer is too small (chars required incl NUL). */

static DWORD write_xcolon_backslash_w(wchar_t16* out, DWORD cap)
{
    if (!out || cap < 4)
        return 4; /* required incl NUL */
    out[0] = 'X';
    out[1] = ':';
    out[2] = '\\';
    out[3] = 0;
    return 3; /* chars excl NUL */
}

static DWORD write_xcolon_backslash_a(char* out, DWORD cap)
{
    if (!out || cap < 4)
        return 4;
    out[0] = 'X';
    out[1] = ':';
    out[2] = '\\';
    out[3] = 0;
    return 3;
}

__declspec(dllexport) DWORD GetTempPathA(DWORD cb, char* out)
{
    return write_xcolon_backslash_a(out, cb);
}

__declspec(dllexport) DWORD GetTempPathW(DWORD cb, wchar_t16* out)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetWindowsDirectoryA(char* out, UINT cb)
{
    return write_xcolon_backslash_a(out, cb);
}

__declspec(dllexport) UINT GetWindowsDirectoryW(wchar_t16* out, UINT cb)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetSystemDirectoryA(char* out, UINT cb)
{
    return write_xcolon_backslash_a(out, cb);
}

__declspec(dllexport) UINT GetSystemDirectoryW(wchar_t16* out, UINT cb)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetSystemWindowsDirectoryW(wchar_t16* out, UINT cb)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetTempFileNameA(const char* dir, const char* prefix, UINT unique, char* out)
{
    (void)dir;
    (void)prefix;
    (void)unique;
    if (out)
        out[0] = 0;
    return 0;
}

__declspec(dllexport) UINT GetTempFileNameW(const wchar_t16* dir, const wchar_t16* prefix, UINT unique, wchar_t16* out)
{
    (void)dir;
    (void)prefix;
    (void)unique;
    if (out)
        out[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD GetCurrentDirectoryA(DWORD cb, char* out)
{
    static const char dir[] = "C:\\";
    DWORD want = sizeof(dir);
    if (!out || cb < want)
        return want;
    for (DWORD i = 0; i < want; ++i)
        out[i] = dir[i];
    return want - 1;
}

__declspec(dllexport) BOOL SetCurrentDirectoryA(const char* path)
{
    (void)path;
    return 1;
}

__declspec(dllexport) BOOL SetCurrentDirectoryW(const wchar_t16* path)
{
    (void)path;
    return 1;
}

/* Process32First/Next — report empty process list. The
 * existing flat stubs are registered under ntdll's NOT_IMPL
 * tier; for completeness let's add these so PE startup
 * snapshots don't error. */
__declspec(dllexport) HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD pid)
{
    (void)flags;
    (void)pid;
    /* Return a non-INVALID sentinel so callers Close it later
     * (CloseHandle on an unknown handle is already a no-op). */
    return (HANDLE)0x1001;
}

__declspec(dllexport) BOOL Process32FirstW(HANDLE h, void* entry)
{
    (void)h;
    (void)entry;
    return 0; /* Empty snapshot */
}

__declspec(dllexport) BOOL Process32NextW(HANDLE h, void* entry)
{
    (void)h;
    (void)entry;
    return 0;
}

__declspec(dllexport) BOOL Process32First(HANDLE h, void* entry)
{
    return Process32FirstW(h, entry);
}

__declspec(dllexport) BOOL Process32Next(HANDLE h, void* entry)
{
    return Process32NextW(h, entry);
}

__declspec(dllexport) HANDLE OpenProcess(DWORD access, BOOL inherit, DWORD pid)
{
    (void)access;
    (void)inherit;
    (void)pid;
    return (HANDLE)0; /* Access denied — keep callers on fallback */
}

__declspec(dllexport) BOOL GenerateConsoleCtrlEvent(DWORD event, DWORD group)
{
    (void)event;
    (void)group;
    return 0;
}

/* GlobalAlloc / LocalAlloc family. Deprecated Win32 heap APIs
 * still used by old clipboard / OLE code. v0 routes both through
 * SYS_HEAP_ALLOC (=11) and SYS_HEAP_FREE (=12). Flags ignored;
 * every block behaves like GMEM_FIXED so Lock/Unlock are
 * pass-through. GMEM_ZEROINIT (0x0040) is honoured — zeros the
 * buffer before returning. */
#define GMEM_ZEROINIT 0x0040u

__declspec(dllexport) HANDLE GlobalAlloc(UINT flags, SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)cb) : "memory");
    if (rv != 0 && (flags & GMEM_ZEROINIT))
    {
        unsigned char* p = (unsigned char*)rv;
        for (SIZE_T i = 0; i < cb; ++i)
            p[i] = 0;
    }
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE GlobalReAlloc(HANDLE h, SIZE_T cb, UINT flags)
{
    (void)flags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)15), /* SYS_HEAP_REALLOC */
                       "D"((long long)(unsigned long long)h), "S"((long long)cb)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE GlobalFree(HANDLE h)
{
    if (h == (HANDLE)0)
        return (HANDLE)0;
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)12), "D"((long long)(unsigned long long)h)
                     : "memory");
    return (HANDLE)0; /* GlobalFree returns NULL on success. */
}

__declspec(dllexport) void* GlobalLock(HANDLE h)
{
    /* GMEM_FIXED → handle == pointer. */
    return (void*)h;
}

__declspec(dllexport) BOOL GlobalUnlock(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) SIZE_T GlobalSize(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)14), /* SYS_HEAP_SIZE */
                       "D"((long long)(unsigned long long)h)
                     : "memory");
    return (SIZE_T)rv;
}

__declspec(dllexport) UINT GlobalFlags(HANDLE h)
{
    (void)h;
    return 0;
}

/* Local* — same shape as Global*. */
__declspec(dllexport) HANDLE LocalAlloc(UINT flags, SIZE_T cb)
{
    return GlobalAlloc(flags, cb);
}

__declspec(dllexport) HANDLE LocalReAlloc(HANDLE h, SIZE_T cb, UINT flags)
{
    return GlobalReAlloc(h, cb, flags);
}

__declspec(dllexport) HANDLE LocalFree(HANDLE h)
{
    return GlobalFree(h);
}

__declspec(dllexport) void* LocalLock(HANDLE h)
{
    return GlobalLock(h);
}

__declspec(dllexport) BOOL LocalUnlock(HANDLE h)
{
    return GlobalUnlock(h);
}

__declspec(dllexport) SIZE_T LocalSize(HANDLE h)
{
    return GlobalSize(h);
}

__declspec(dllexport) UINT LocalFlags(HANDLE h)
{
    return GlobalFlags(h);
}

/* Affinity / CPU info — single-CPU; both masks are 1. */
__declspec(dllexport) BOOL GetProcessAffinityMask(HANDLE proc, unsigned long long* proc_mask,
                                                  unsigned long long* sys_mask)
{
    (void)proc;
    if (proc_mask)
        *proc_mask = 1;
    if (sys_mask)
        *sys_mask = 1;
    return 1;
}

__declspec(dllexport) BOOL SetProcessAffinityMask(HANDLE proc, unsigned long long mask)
{
    (void)proc;
    (void)mask;
    return 1;
}

__declspec(dllexport) unsigned long long SetThreadAffinityMask(HANDLE thread, unsigned long long mask)
{
    (void)thread;
    (void)mask;
    return 1;
}

__declspec(dllexport) DWORD GetActiveProcessorCount(unsigned short group)
{
    (void)group;
    return 1;
}

__declspec(dllexport) unsigned short GetActiveProcessorGroupCount(void)
{
    return 1;
}

/* GetSystemInfo / GetNativeSystemInfo — populate SYSTEM_INFO
 * (48 bytes). Apps query this for page size + processor count. */
__declspec(dllexport) void GetSystemInfo(void* info)
{
    if (!info)
        return;
    unsigned char* p = (unsigned char*)info;
    for (int i = 0; i < 48; ++i)
        p[i] = 0;
    *((unsigned short*)&p[0]) = 9; /* PROCESSOR_ARCHITECTURE_AMD64 */
    *((DWORD*)&p[4]) = 4096;
    *((unsigned long long*)&p[8]) = 0x10000ULL;
    *((unsigned long long*)&p[16]) = 0x7FFFFFFEFFFFULL;
    *((unsigned long long*)&p[24]) = 1;
    *((DWORD*)&p[32]) = 1;
    *((DWORD*)&p[36]) = 8664; /* PROCESSOR_AMD_X8664 */
    *((DWORD*)&p[40]) = 65536;
}

__declspec(dllexport) void GetNativeSystemInfo(void* info)
{
    GetSystemInfo(info);
}

/* Windows version reporting — claim Windows 10 build 19041
 * (matches the registry stub in advapi32). */
__declspec(dllexport) DWORD GetVersion(void)
{
    /* Layout: low 8 bits major (10), bits 8..15 minor (0),
     * high 16 bits build (19041) — but the high bit is set on
     * NT-based versions, so flip bit 31. */
    return 0x4A6100AAu;
}

__declspec(dllexport) BOOL GetVersionExA(void* info)
{
    if (!info)
        return 0;
    DWORD* p = (DWORD*)info;
    if (p[0] < 148)
        return 0;
    p[1] = 10;
    p[2] = 0;
    p[3] = 19041;
    p[4] = 2; /* VER_PLATFORM_WIN32_NT */
    /* szCSDVersion left untouched — matches the kernel32 thunk
       fast-path. Caller is expected to zero-init the struct. */
    return 1;
}

__declspec(dllexport) BOOL GetVersionExW(void* info)
{
    if (!info)
        return 0;
    DWORD* p = (DWORD*)info;
    if (p[0] < 276)
        return 0;
    p[1] = 10;
    p[2] = 0;
    p[3] = 19041;
    p[4] = 2;
    /* szCSDVersion left untouched — matches the kernel32 thunk
       fast-path. Caller is expected to zero-init the struct. */
    return 1;
}

__declspec(dllexport) BOOL VerifyVersionInfoW(void* info, DWORD type_mask, unsigned long long cond_mask)
{
    (void)info;
    (void)type_mask;
    (void)cond_mask;
    return 1;
}
