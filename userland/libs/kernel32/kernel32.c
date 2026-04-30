/*
 * userland/libs/kernel32/kernel32.c
 *
 * Freestanding DuetOS kernel32.dll — ring-3 code that
 * implements Win32 entry points by issuing native int 0x80
 * syscalls + returning sentinel constants where appropriate.
 * This is the live userland replacement for the matching
 * entries in kernel/subsystems/win32/thunks.cpp.
 *
 * Every function exported here retires the corresponding
 * `{"kernel32.dll", "<name>", kOff<name>}` row in
 * kStubsTable. The flat stub stays compiled as a fallback
 * (the via-DLL path runs first; the stub is only reached
 * if preload fails). A later sweep deletes the dead rows.
 *
 * Build: tools/build/build-kernel32-dll.sh
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
 * Console / system introspection
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
 * "pass through" stdout than OEM 437. The console-API
 * smoke test in hello_winapi.exe pins this at 65001. */
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
 * Virtual memory
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
 * lstr* family — Windows' historic string helpers,
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

__declspec(dllexport) NO_BUILTIN_LSTR char* lstrcatA(char* dst, const char* src)
{
    if (dst == (char*)0 || src == (const char*)0)
        return dst;
    char* d = dst;
    while (*d != 0)
        ++d;
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
 * Environment variables — per-process userland table.
 *
 * The kernel-hosted env block (GetEnvironmentStringsW via stubs page)
 * gives the fixed boot-time environment. Get/Set/Expand on top of it
 * are kept entirely in user space here so a Set is visible to the
 * matching Get inside the same process. STUB-grade: no inheritance
 * across CreateProcess (we don't have CreateProcess yet anyway).
 * ------------------------------------------------------------------ */

#define DUETOS_ENV_MAX 16
#define DUETOS_ENV_NAME 32
#define DUETOS_ENV_VAL 96

typedef struct
{
    wchar_t16 name[DUETOS_ENV_NAME];
    wchar_t16 val[DUETOS_ENV_VAL];
    int in_use;
} DuetosEnvSlot;

static DuetosEnvSlot g_env_table[DUETOS_ENV_MAX];

static int wstr_eq_ci(const wchar_t16* a, const wchar_t16* b)
{
    int i = 0;
    for (;;)
    {
        wchar_t16 ca = a[i];
        wchar_t16 cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16)(cb + ('a' - 'A'));
        if (ca != cb)
            return 0;
        if (ca == 0)
            return 1;
        ++i;
    }
}

static int wstr_len(const wchar_t16* s)
{
    int n = 0;
    while (s[n] != 0)
        ++n;
    return n;
}

static void wstr_copy(wchar_t16* dst, const wchar_t16* src, int max)
{
    int i;
    for (i = 0; i < max - 1 && src[i] != 0; ++i)
        dst[i] = src[i];
    dst[i] = 0;
}

__declspec(dllexport) DWORD GetEnvironmentVariableW(const wchar_t16* name, wchar_t16* buf, DWORD size)
{
    if (name == (const wchar_t16*)0)
        return 0;
    for (int i = 0; i < DUETOS_ENV_MAX; ++i)
    {
        if (!g_env_table[i].in_use)
            continue;
        if (!wstr_eq_ci(g_env_table[i].name, name))
            continue;
        int n = wstr_len(g_env_table[i].val);
        if (buf == (wchar_t16*)0 || size == 0)
            return (DWORD)(n + 1);
        if ((DWORD)n + 1 > size)
        {
            buf[0] = 0;
            return (DWORD)(n + 1);
        }
        wstr_copy(buf, g_env_table[i].val, (int)size);
        return (DWORD)n;
    }
    return 0;
}

__declspec(dllexport) BOOL SetEnvironmentVariableW(const wchar_t16* name, const wchar_t16* val)
{
    if (name == (const wchar_t16*)0)
        return 0;
    /* val == NULL means "delete" the variable. */
    /* First, find an existing entry to update or delete. */
    for (int i = 0; i < DUETOS_ENV_MAX; ++i)
    {
        if (!g_env_table[i].in_use)
            continue;
        if (!wstr_eq_ci(g_env_table[i].name, name))
            continue;
        if (val == (const wchar_t16*)0)
        {
            g_env_table[i].in_use = 0;
            return 1;
        }
        wstr_copy(g_env_table[i].val, val, DUETOS_ENV_VAL);
        return 1;
    }
    if (val == (const wchar_t16*)0)
        return 1; /* Delete of non-existent == success per docs. */
    /* Allocate a free slot. */
    for (int i = 0; i < DUETOS_ENV_MAX; ++i)
    {
        if (g_env_table[i].in_use)
            continue;
        wstr_copy(g_env_table[i].name, name, DUETOS_ENV_NAME);
        wstr_copy(g_env_table[i].val, val, DUETOS_ENV_VAL);
        g_env_table[i].in_use = 1;
        return 1;
    }
    return 0;
}

__declspec(dllexport) DWORD GetEnvironmentVariableA(const char* name, char* buf, DWORD size)
{
    if (name == (const char*)0)
        return 0;
    /* Translate name to wchar_t16, look up, then translate back. */
    wchar_t16 wname[DUETOS_ENV_NAME];
    int i;
    for (i = 0; i < DUETOS_ENV_NAME - 1 && name[i] != 0; ++i)
        wname[i] = (wchar_t16)(unsigned char)name[i];
    wname[i] = 0;
    wchar_t16 wval[DUETOS_ENV_VAL];
    DWORD n = GetEnvironmentVariableW(wname, wval, DUETOS_ENV_VAL);
    if (n == 0)
        return 0;
    /* n is wchar count without NUL when buf-fit, with NUL otherwise. */
    if (buf == (char*)0 || size == 0)
        return n;
    DWORD j;
    for (j = 0; j < size - 1 && wval[j] != 0; ++j)
        buf[j] = (char)(unsigned char)wval[j];
    buf[j] = 0;
    return j;
}

__declspec(dllexport) BOOL SetEnvironmentVariableA(const char* name, const char* val)
{
    if (name == (const char*)0)
        return 0;
    wchar_t16 wname[DUETOS_ENV_NAME];
    wchar_t16 wval[DUETOS_ENV_VAL];
    int i;
    for (i = 0; i < DUETOS_ENV_NAME - 1 && name[i] != 0; ++i)
        wname[i] = (wchar_t16)(unsigned char)name[i];
    wname[i] = 0;
    if (val == (const char*)0)
        return SetEnvironmentVariableW(wname, (const wchar_t16*)0);
    for (i = 0; i < DUETOS_ENV_VAL - 1 && val[i] != 0; ++i)
        wval[i] = (wchar_t16)(unsigned char)val[i];
    wval[i] = 0;
    return SetEnvironmentVariableW(wname, wval);
}

__declspec(dllexport) DWORD ExpandEnvironmentStringsW(const wchar_t16* src, wchar_t16* dst, DWORD size)
{
    /* v0: copy literal text only; %VAR% expansion is unimplemented. */
    if (src == (const wchar_t16*)0)
        return 0;
    int n = wstr_len(src) + 1; /* including NUL */
    if (dst == (wchar_t16*)0 || size == 0)
        return (DWORD)n;
    if ((DWORD)n > size)
    {
        wstr_copy(dst, src, (int)size);
        return (DWORD)n;
    }
    wstr_copy(dst, src, (int)size);
    return (DWORD)n;
}

/* ------------------------------------------------------------------
 * Locale APIs — fixed en-US (LCID 0x0409). DuetOS has no real
 * locale tables yet; these return canned strings keyed off the
 * common LCType selectors that real apps query.
 * ------------------------------------------------------------------ */

#define DUETOS_LCID_EN_US 0x0409UL
#define DUETOS_LANGID_EN_US 0x0409U

__declspec(dllexport) unsigned long GetUserDefaultLCID(void)
{
    return DUETOS_LCID_EN_US;
}
__declspec(dllexport) unsigned long GetSystemDefaultLCID(void)
{
    return DUETOS_LCID_EN_US;
}
__declspec(dllexport) unsigned long GetThreadLocale(void)
{
    return DUETOS_LCID_EN_US;
}
__declspec(dllexport) unsigned short GetUserDefaultLangID(void)
{
    return DUETOS_LANGID_EN_US;
}
__declspec(dllexport) unsigned short GetSystemDefaultLangID(void)
{
    return DUETOS_LANGID_EN_US;
}
__declspec(dllexport) BOOL SetThreadLocale(unsigned long lcid)
{
    (void)lcid;
    return 1;
}

__declspec(dllexport) BOOL IsValidLocale(unsigned long lcid, DWORD flags)
{
    (void)flags;
    return (lcid == DUETOS_LCID_EN_US || lcid == 0x0800 || lcid == 0x0400) ? 1 : 0;
}

__declspec(dllexport) int GetLocaleInfoW(unsigned long lcid, unsigned long lctype, wchar_t16* buf, int cchData)
{
    (void)lcid;
    lctype &= 0x0FFFFFFF;
    static const wchar_t16 sLang[] = {'e', 'n', 0};
    static const wchar_t16 sCountry[] = {'U', 'n', 'i', 't', 'e', 'd', ' ', 'S', 't', 'a', 't', 'e', 's', 0};
    static const wchar_t16 sCountryAbbrev[] = {'U', 'S', 'A', 0};
    static const wchar_t16 sLangName[] = {'E', 'n', 'g', 'l', 'i', 's', 'h', 0};
    static const wchar_t16 sIso3166[] = {'U', 'S', 0};
    static const wchar_t16 sIso639[] = {'e', 'n', 0};
    static const wchar_t16 sDecimal[] = {'.', 0};
    static const wchar_t16 sThousand[] = {',', 0};
    const wchar_t16* msg;
    switch (lctype)
    {
    case 0x0002:
        msg = sLangName;
        break;
    case 0x0006:
        msg = sCountry;
        break;
    case 0x0007:
        msg = sCountryAbbrev;
        break;
    case 0x000E:
        msg = sDecimal;
        break;
    case 0x000F:
        msg = sThousand;
        break;
    case 0x0059:
        msg = sIso639;
        break;
    case 0x005A:
        msg = sIso3166;
        break;
    default:
        msg = sLang;
        break;
    }
    int needed = 0;
    while (msg[needed] != 0)
        ++needed;
    ++needed;
    if (cchData == 0)
        return needed;
    if (buf == (wchar_t16*)0 || cchData < needed)
        return 0;
    int j = 0;
    while (msg[j] != 0)
    {
        buf[j] = msg[j];
        ++j;
    }
    buf[j] = 0;
    return needed;
}

/* ------------------------------------------------------------------
 * Userland atom table — 32 slots, shared between local + global
 * (matches older Windows). Atoms in [0xC000, 0xC020).
 * ------------------------------------------------------------------ */

#define DUETOS_ATOM_MAX 32
#define DUETOS_ATOM_BASE 0xC000U

typedef struct
{
    char name[64];
    int in_use;
    unsigned int refcnt;
} DuetosAtomSlot;

static DuetosAtomSlot g_atoms[DUETOS_ATOM_MAX];

static int astr_eq_ci(const char* a, const char* b)
{
    int i = 0;
    for (;;)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return 0;
        if (ca == 0)
            return 1;
        ++i;
    }
}

static unsigned short atom_add_internal(const char* name)
{
    if (name == (const char*)0)
        return 0;
    for (int i = 0; i < DUETOS_ATOM_MAX; ++i)
        if (g_atoms[i].in_use && astr_eq_ci(g_atoms[i].name, name))
        {
            g_atoms[i].refcnt++;
            return (unsigned short)(DUETOS_ATOM_BASE + i);
        }
    for (int i = 0; i < DUETOS_ATOM_MAX; ++i)
        if (!g_atoms[i].in_use)
        {
            int j = 0;
            while (j < 63 && name[j] != 0)
            {
                g_atoms[i].name[j] = name[j];
                ++j;
            }
            g_atoms[i].name[j] = 0;
            g_atoms[i].in_use = 1;
            g_atoms[i].refcnt = 1;
            return (unsigned short)(DUETOS_ATOM_BASE + i);
        }
    return 0;
}

__declspec(dllexport) unsigned short AddAtomA(const char* name)
{
    return atom_add_internal(name);
}
__declspec(dllexport) unsigned short GlobalAddAtomA(const char* name)
{
    return atom_add_internal(name);
}

__declspec(dllexport) unsigned short FindAtomA(const char* name)
{
    if (name == (const char*)0)
        return 0;
    for (int i = 0; i < DUETOS_ATOM_MAX; ++i)
        if (g_atoms[i].in_use && astr_eq_ci(g_atoms[i].name, name))
            return (unsigned short)(DUETOS_ATOM_BASE + i);
    return 0;
}
__declspec(dllexport) unsigned short GlobalFindAtomA(const char* name)
{
    return FindAtomA(name);
}

__declspec(dllexport) unsigned int GlobalGetAtomNameA(unsigned short atom, char* buf, int cch)
{
    if (atom < DUETOS_ATOM_BASE || buf == (char*)0 || cch == 0)
        return 0;
    int idx = atom - DUETOS_ATOM_BASE;
    if (idx < 0 || idx >= DUETOS_ATOM_MAX || !g_atoms[idx].in_use)
        return 0;
    int j = 0;
    while (j < cch - 1 && g_atoms[idx].name[j] != 0)
    {
        buf[j] = g_atoms[idx].name[j];
        ++j;
    }
    buf[j] = 0;
    return (unsigned int)j;
}
__declspec(dllexport) unsigned int GetAtomNameA(unsigned short atom, char* buf, int cch)
{
    return GlobalGetAtomNameA(atom, buf, cch);
}

__declspec(dllexport) unsigned short GlobalDeleteAtom(unsigned short atom)
{
    if (atom < DUETOS_ATOM_BASE)
        return atom;
    int idx = atom - DUETOS_ATOM_BASE;
    if (idx < 0 || idx >= DUETOS_ATOM_MAX || !g_atoms[idx].in_use)
        return atom;
    if (--g_atoms[idx].refcnt == 0)
        g_atoms[idx].in_use = 0;
    return 0;
}
__declspec(dllexport) unsigned short DeleteAtom(unsigned short atom)
{
    return GlobalDeleteAtom(atom);
}

/* GetTimeZoneInformation — return UTC-0 with no DST. */
typedef struct
{
    long Bias;
    wchar_t16 StandardName[32];
    unsigned short StandardDateY, StandardDateM, StandardDateDayOfWeek, StandardDateDay;
    unsigned short StandardDateH, StandardDateMin, StandardDateS, StandardDateMs;
    long StandardBias;
    wchar_t16 DaylightName[32];
    unsigned short DaylightDateY, DaylightDateM, DaylightDateDayOfWeek, DaylightDateDay;
    unsigned short DaylightDateH, DaylightDateMin, DaylightDateS, DaylightDateMs;
    long DaylightBias;
} DUETOS_TZ_INFORMATION;

__declspec(dllexport) DWORD GetTimeZoneInformation(DUETOS_TZ_INFORMATION* tzi)
{
    if (tzi == (DUETOS_TZ_INFORMATION*)0)
        return 0xFFFFFFFFUL;
    unsigned char* b = (unsigned char*)tzi;
    for (unsigned long i = 0; i < sizeof(*tzi); ++i)
        b[i] = 0;
    static const wchar_t16 utc[] = {'U', 'T', 'C', 0};
    for (int i = 0; utc[i] != 0; ++i)
        tzi->StandardName[i] = utc[i];
    return 1;
}

typedef struct
{
    short cols, rows;
    short cur_x, cur_y;
    unsigned short attrs;
    short win_left, win_top, win_right, win_bot;
    short max_cols, max_rows;
} DUETOS_CONSOLE_SBI;

/* In-memory cursor + attribute state. */
static short g_console_cur_x = 0, g_console_cur_y = 0;
static unsigned short g_console_attrs = 0x07;
static int g_console_cursor_visible = 1;
static int g_console_cursor_size = 25; /* pct of cell */

__declspec(dllexport) BOOL GetConsoleScreenBufferInfo(HANDLE h, DUETOS_CONSOLE_SBI* info)
{
    (void)h;
    if (info == (DUETOS_CONSOLE_SBI*)0)
        return 0;
    info->cols = 80;
    info->rows = 25;
    info->cur_x = g_console_cur_x;
    info->cur_y = g_console_cur_y;
    info->attrs = g_console_attrs;
    info->win_left = 0;
    info->win_top = 0;
    info->win_right = 79;
    info->win_bot = 24;
    info->max_cols = 80;
    info->max_rows = 25;
    return 1;
}

typedef struct
{
    short x, y;
} DUETOS_COORD;
typedef struct
{
    DWORD size;
    BOOL visible;
} DUETOS_CONSOLE_CURSOR_INFO;

__declspec(dllexport) BOOL SetConsoleCursorPosition(HANDLE h, DUETOS_COORD pos)
{
    (void)h;
    g_console_cur_x = pos.x;
    g_console_cur_y = pos.y;
    return 1;
}

__declspec(dllexport) BOOL GetConsoleCursorInfo(HANDLE h, DUETOS_CONSOLE_CURSOR_INFO* ci)
{
    (void)h;
    if (ci == (DUETOS_CONSOLE_CURSOR_INFO*)0)
        return 0;
    ci->size = (DWORD)g_console_cursor_size;
    ci->visible = g_console_cursor_visible;
    return 1;
}

__declspec(dllexport) BOOL SetConsoleCursorInfo(HANDLE h, const DUETOS_CONSOLE_CURSOR_INFO* ci)
{
    (void)h;
    if (ci == (const DUETOS_CONSOLE_CURSOR_INFO*)0)
        return 0;
    g_console_cursor_size = (int)ci->size;
    g_console_cursor_visible = ci->visible ? 1 : 0;
    return 1;
}

__declspec(dllexport) BOOL SetConsoleTextAttribute(HANDLE h, unsigned short attrs)
{
    (void)h;
    g_console_attrs = attrs;
    return 1;
}

__declspec(dllexport) BOOL FillConsoleOutputAttribute(HANDLE h, unsigned short attr, DWORD count, DUETOS_COORD origin,
                                                      DWORD* written)
{
    (void)h;
    (void)attr;
    (void)origin;
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

__declspec(dllexport) BOOL FillConsoleOutputCharacterA(HANDLE h, char ch, DWORD count, DUETOS_COORD origin,
                                                       DWORD* written)
{
    (void)h;
    (void)ch;
    (void)origin;
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

__declspec(dllexport) BOOL FillConsoleOutputCharacterW(HANDLE h, wchar_t16 ch, DWORD count, DUETOS_COORD origin,
                                                       DWORD* written)
{
    (void)h;
    (void)ch;
    (void)origin;
    if (written != (DWORD*)0)
        *written = count;
    return 1;
}

__declspec(dllexport) BOOL GetNumberOfConsoleInputEvents(HANDLE h, DWORD* count)
{
    (void)h;
    if (count != (DWORD*)0)
        *count = 0; /* No queued console input under emulator. */
    return 1;
}

/* GetFileAttributesA/W live further down — they use SYS_FILE_QUERY_ATTRIBUTES
 * directly. Skipping our placeholder definitions here avoids duplicates. */

/* CreateFileMappingW — for v0 we treat unnamed file mappings
 * backed by the system pagefile (INVALID_HANDLE_VALUE handle)
 * as a heap allocation. The returned "mapping handle" is the
 * heap pointer with the low bit set as a sentinel; MapViewOfFile
 * just returns the same pointer (size 0 → use stored size).
 *
 * Named mappings still STUB. ipc_smoke uses the unnamed path.
 */
typedef struct
{
    DWORD size;
    DWORD protect;
    void* base;
} DUETOS_FILEMAPPING;

#define DUETOS_FILEMAPPING_MAX 8
static DUETOS_FILEMAPPING g_filemappings[DUETOS_FILEMAPPING_MAX];
static int g_filemapping_count = 0;

__declspec(dllexport) HANDLE CreateFileMappingW(HANDLE hFile, void* sec, DWORD protect, DWORD sizeHigh, DWORD sizeLow,
                                                const wchar_t16* name)
{
    (void)hFile;
    (void)sec;
    (void)name;
    /* Allocate via SYS_HEAP_ALLOC. */
    if (g_filemapping_count >= DUETOS_FILEMAPPING_MAX)
        return (HANDLE)0;
    DWORD total = ((unsigned long long)sizeHigh << 32) | sizeLow;
    if (total == 0)
        total = 0x10000; /* default 64K if caller passed 0 */
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)total) : "memory");
    if (rv == 0)
        return (HANDLE)0;
    int slot = g_filemapping_count++;
    g_filemappings[slot].size = total;
    g_filemappings[slot].protect = protect;
    g_filemappings[slot].base = (void*)rv;
    /* Sentinel handle: 0x6000 + slot. */
    return (HANDLE)(unsigned long long)(0x6000 + slot);
}

__declspec(dllexport) HANDLE OpenFileMappingW(DWORD desired, BOOL inherit, const wchar_t16* name)
{
    (void)desired;
    (void)inherit;
    (void)name;
    /* Named mappings not yet supported — return NULL. */
    return (HANDLE)0;
}

__declspec(dllexport) void* MapViewOfFile(HANDLE h, DWORD desired, DWORD offHigh, DWORD offLow,
                                          unsigned long long bytes)
{
    (void)desired;
    (void)offHigh;
    (void)offLow;
    (void)bytes;
    unsigned long long handle_v = (unsigned long long)h;
    if (handle_v < 0x6000 || handle_v >= 0x6000 + DUETOS_FILEMAPPING_MAX)
        return (void*)0;
    int slot = (int)(handle_v - 0x6000);
    return g_filemappings[slot].base;
}

__declspec(dllexport) BOOL UnmapViewOfFile(const void* base)
{
    (void)base;
    /* Page is freed when CloseHandle of the mapping is called. */
    return 1;
}

/* CreateJobObjectW — opaque sentinel handle. AssignProcessToJobObject
 * accepts and returns success. IsProcessInJob reports FALSE before
 * any assignment in this v0 model. */
__declspec(dllexport) HANDLE CreateJobObjectW(void* sec, const wchar_t16* name)
{
    (void)sec;
    (void)name;
    return (HANDLE)0x7001ULL;
}

__declspec(dllexport) BOOL AssignProcessToJobObject(HANDLE job, HANDLE proc)
{
    (void)job;
    (void)proc;
    return 1;
}

__declspec(dllexport) BOOL IsProcessInJob(HANDLE proc, HANDLE job, BOOL* in_job)
{
    (void)proc;
    (void)job;
    if (in_job != (BOOL*)0)
        *in_job = 0;
    return 1;
}

/* CreateIoCompletionPort — for v0 we keep an in-memory ring of
 * up to 32 pending completions per port. Single-threaded scope
 * matches the rest of the v0 kernel32 surface; matches the
 * smoke-test usage pattern of "post N, get N within the same
 * thread".
 */
#define DUETOS_IOCP_RING 32
typedef struct
{
    DWORD bytes;
    unsigned long long key;
    void* ov;
} DuetosIocpEntry;
typedef struct
{
    DuetosIocpEntry ring[DUETOS_IOCP_RING];
    int head, tail;
    int in_use;
} DuetosIocp;

#define DUETOS_IOCP_MAX 4
static DuetosIocp g_iocp[DUETOS_IOCP_MAX];

__declspec(dllexport) HANDLE CreateIoCompletionPort(HANDLE fileHandle, HANDLE existing, unsigned long long key,
                                                    DWORD numThreads)
{
    (void)fileHandle;
    (void)key;
    (void)numThreads;
    if (existing != (HANDLE)0)
        return existing; /* Associate fileHandle with existing port — STUB. */
    for (int i = 0; i < DUETOS_IOCP_MAX; ++i)
        if (!g_iocp[i].in_use)
        {
            g_iocp[i].head = 0;
            g_iocp[i].tail = 0;
            g_iocp[i].in_use = 1;
            return (HANDLE)(unsigned long long)(0x8000 + i);
        }
    return (HANDLE)0;
}

__declspec(dllexport) BOOL PostQueuedCompletionStatus(HANDLE iocp, DWORD bytes, unsigned long long key, void* ov)
{
    unsigned long long h = (unsigned long long)iocp;
    if (h < 0x8000 || h >= 0x8000 + DUETOS_IOCP_MAX)
        return 0;
    int slot = (int)(h - 0x8000);
    if (!g_iocp[slot].in_use)
        return 0;
    int next = (g_iocp[slot].tail + 1) % DUETOS_IOCP_RING;
    if (next == g_iocp[slot].head)
        return 0; /* full */
    g_iocp[slot].ring[g_iocp[slot].tail].bytes = bytes;
    g_iocp[slot].ring[g_iocp[slot].tail].key = key;
    g_iocp[slot].ring[g_iocp[slot].tail].ov = ov;
    g_iocp[slot].tail = next;
    return 1;
}

__declspec(dllexport) BOOL GetQueuedCompletionStatus(HANDLE iocp, DWORD* bytes, unsigned long long* key, void** ov,
                                                     DWORD timeout)
{
    (void)timeout;
    unsigned long long h = (unsigned long long)iocp;
    if (h < 0x8000 || h >= 0x8000 + DUETOS_IOCP_MAX)
        return 0;
    int slot = (int)(h - 0x8000);
    if (!g_iocp[slot].in_use)
        return 0;
    if (g_iocp[slot].head == g_iocp[slot].tail)
        return 0; /* empty — could also block, but v0 is non-blocking. */
    if (bytes != (DWORD*)0)
        *bytes = g_iocp[slot].ring[g_iocp[slot].head].bytes;
    if (key != (unsigned long long*)0)
        *key = g_iocp[slot].ring[g_iocp[slot].head].key;
    if (ov != (void**)0)
        *ov = g_iocp[slot].ring[g_iocp[slot].head].ov;
    g_iocp[slot].head = (g_iocp[slot].head + 1) % DUETOS_IOCP_RING;
    return 1;
}

/* CreateTimerQueue / DeleteTimerQueue — sentinel handle. */
__declspec(dllexport) HANDLE CreateTimerQueue(void)
{
    return (HANDLE)0x8801ULL;
}

__declspec(dllexport) BOOL DeleteTimerQueue(HANDLE q)
{
    (void)q;
    return 1;
}

/* CreateWaitableTimerW — sentinel; immediate signal on wait if the
 * relative due-time is "very soon". The smoke test uses 100 ms
 * which is short enough that returning a pre-signaled event-style
 * handle works in single-thread tests. We reuse the manual-reset
 * Event slot machinery via an actual SYS_HANDLE_CREATE_EVENT call. */
__declspec(dllexport) HANDLE CreateWaitableTimerW(void* sa, BOOL manualReset, const wchar_t16* name)
{
    (void)sa;
    (void)name;
    /* Allocate via SYS_HANDLE_CREATE_EVENT (manual, signaled). */
    long long h;
    __asm__ volatile("int $0x80"
                     : "=a"(h)
                     : "a"((long long)33),                                      /* SYS_HANDLE_CREATE_EVENT */
                       "D"((long long)(manualReset ? 1 : 0)), "S"((long long)1) /* initially signaled */
                     : "memory");
    return (HANDLE)h;
}

__declspec(dllexport) BOOL SetWaitableTimer(HANDLE t, void* due, long period, void* completion, void* arg, BOOL resume)
{
    (void)t;
    (void)due;
    (void)period;
    (void)completion;
    (void)arg;
    (void)resume;
    return 1;
}

__declspec(dllexport) BOOL CancelWaitableTimer(HANDLE t)
{
    (void)t;
    return 1;
}

/* WTSGetActiveConsoleSessionId stub — return 1. */
__declspec(dllexport) DWORD WTSGetActiveConsoleSessionId(void)
{
    return 1;
}

__declspec(dllexport) BOOL ProcessIdToSessionId(DWORD pid, DWORD* session)
{
    (void)pid;
    if (session != (DWORD*)0)
        *session = 1;
    return 1;
}

/* GetSystemPowerStatus — return canned "AC plugged, full battery". */
typedef struct
{
    unsigned char ACLineStatus;
    unsigned char BatteryFlag;
    unsigned char BatteryLifePercent;
    unsigned char Reserved1;
    DWORD BatteryLifeTime;
    DWORD BatteryFullLifeTime;
} DUETOS_SYSTEM_POWER_STATUS;

__declspec(dllexport) BOOL GetSystemPowerStatus(DUETOS_SYSTEM_POWER_STATUS* sps)
{
    if (sps == (DUETOS_SYSTEM_POWER_STATUS*)0)
        return 0;
    sps->ACLineStatus = 1;          /* AC online */
    sps->BatteryFlag = 0x80;        /* no system battery */
    sps->BatteryLifePercent = 0xFF; /* unknown */
    sps->Reserved1 = 0;
    sps->BatteryLifeTime = 0xFFFFFFFFu;
    sps->BatteryFullLifeTime = 0xFFFFFFFFu;
    return 1;
}

__declspec(dllexport) DWORD SetThreadExecutionState(DWORD esFlags)
{
    /* Return previous state (just echo input). */
    return esFlags;
}

__declspec(dllexport) BOOL IsSystemResumeAutomatic(void)
{
    return 0;
}

/* GeoID family — return USA = 244. */
__declspec(dllexport) int GetUserGeoID(int geoclass)
{
    (void)geoclass;
    return 244;
}

__declspec(dllexport) int GetSystemGeoID(int geoclass)
{
    (void)geoclass;
    return 244;
}

__declspec(dllexport) int GetGeoInfoW(int geoid, int gtype, wchar_t16* buf, int cchData, unsigned short langid)
{
    (void)geoid;
    (void)langid;
    static const wchar_t16 sIso2[] = {'U', 'S', 0};
    static const wchar_t16 sIso3[] = {'U', 'S', 'A', 0};
    static const wchar_t16 sName[] = {'U', 'n', 'i', 't', 'e', 'd', ' ', 'S', 't', 'a', 't', 'e', 's', 0};
    const wchar_t16* msg;
    /* gtype: GEO_ISO2=4, GEO_ISO3=5, GEO_FRIENDLYNAME=8 */
    if (gtype == 4)
        msg = sIso2;
    else if (gtype == 5)
        msg = sIso3;
    else
        msg = sName;
    int needed = 0;
    while (msg[needed] != 0)
        ++needed;
    ++needed;
    if (cchData == 0)
        return needed;
    if (buf == (wchar_t16*)0 || cchData < needed)
        return 0;
    int j = 0;
    while (msg[j] != 0)
    {
        buf[j] = msg[j];
        ++j;
    }
    buf[j] = 0;
    return needed;
}

/* GetCalendarInfoEx — return canned strings for common selectors. */
__declspec(dllexport) int GetCalendarInfoEx(const wchar_t16* locale, unsigned int cal, const wchar_t16* reserved,
                                            unsigned int caltype, wchar_t16* buf, int cchData, unsigned int* val)
{
    (void)locale;
    (void)cal;
    (void)reserved;
    (void)val;
    static const wchar_t16 sName[] = {'G', 'r', 'e', 'g', 'o', 'r', 'i', 'a', 'n', 0};
    /* CAL_SCALNAME = 2, others mostly canned. */
    if (caltype != 2 && caltype != 0x1000) /* CAL_SCALNAME or NOUSEROVERRIDE | CAL_SCALNAME */
        return 0;
    int needed = 10;
    if (cchData == 0)
        return needed;
    if (buf == (wchar_t16*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < 9; ++i)
        buf[i] = sName[i];
    buf[9] = 0;
    return needed;
}

__declspec(dllexport) int GetCalendarInfoA(unsigned int locale, unsigned int cal, unsigned int caltype, char* buf,
                                           int cchData, unsigned int* val)
{
    (void)locale;
    (void)cal;
    (void)val;
    if (caltype != 2)
        return 0;
    static const char sName[] = "Gregorian";
    int needed = 10;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < 9; ++i)
        buf[i] = sName[i];
    buf[9] = 0;
    return needed;
}

/* GetDpiForSystem — assume 96 dpi (default 100% scale). */
__declspec(dllexport) unsigned int GetDpiForSystem(void)
{
    return 96;
}

/* Date/time/number format APIs — canned MM/DD/YYYY, HH:MM:SS, pass-through. */
static int duetos_u32_to_dec(unsigned int v, char* out)
{
    if (v == 0)
    {
        out[0] = '0';
        return 1;
    }
    char tmp[16];
    int n = 0;
    while (v != 0)
    {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (int i = 0; i < n; ++i)
        out[i] = tmp[n - 1 - i];
    return n;
}

typedef struct
{
    unsigned short y, m, dow, d, h, min, s, ms;
} DUETOS_SYSTEMTIME;

__declspec(dllexport) int GetDateFormatA(unsigned long lcid, DWORD flags, const DUETOS_SYSTEMTIME* st, const char* fmt,
                                         char* buf, int cchData)
{
    (void)lcid;
    (void)flags;
    (void)fmt;
    if (st == (const DUETOS_SYSTEMTIME*)0)
        return 0;
    char tmp[32];
    int len = 0;
    if (st->m < 10)
        tmp[len++] = '0';
    len += duetos_u32_to_dec(st->m, tmp + len);
    tmp[len++] = '/';
    if (st->d < 10)
        tmp[len++] = '0';
    len += duetos_u32_to_dec(st->d, tmp + len);
    tmp[len++] = '/';
    len += duetos_u32_to_dec(st->y, tmp + len);
    tmp[len] = 0;
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = tmp[i];
    buf[len] = 0;
    return needed;
}

__declspec(dllexport) int GetTimeFormatA(unsigned long lcid, DWORD flags, const DUETOS_SYSTEMTIME* st, const char* fmt,
                                         char* buf, int cchData)
{
    (void)lcid;
    (void)flags;
    (void)fmt;
    if (st == (const DUETOS_SYSTEMTIME*)0)
        return 0;
    char tmp[32];
    int len = 0;
    if (st->h < 10)
        tmp[len++] = '0';
    len += duetos_u32_to_dec(st->h, tmp + len);
    tmp[len++] = ':';
    if (st->min < 10)
        tmp[len++] = '0';
    len += duetos_u32_to_dec(st->min, tmp + len);
    tmp[len++] = ':';
    if (st->s < 10)
        tmp[len++] = '0';
    len += duetos_u32_to_dec(st->s, tmp + len);
    tmp[len] = 0;
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = tmp[i];
    buf[len] = 0;
    return needed;
}

__declspec(dllexport) int GetNumberFormatA(unsigned long lcid, DWORD flags, const char* num, void* fmt, char* buf,
                                           int cchData)
{
    (void)lcid;
    (void)flags;
    (void)fmt;
    if (num == (const char*)0)
        return 0;
    int n = 0;
    while (num[n] != 0)
        ++n;
    int needed = n + 1;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < n; ++i)
        buf[i] = num[i];
    buf[n] = 0;
    return needed;
}

__declspec(dllexport) BOOL EnumSystemLocalesA(BOOL(__stdcall* cb)(char*), DWORD flags)
{
    (void)flags;
    if (cb == (BOOL(__stdcall*)(char*))0)
        return 0;
    char id[] = "00000409";
    cb(id);
    return 1;
}

__declspec(dllexport) BOOL GetVolumeInformationW(const wchar_t16* root, wchar_t16* vol_name, DWORD vol_name_len,
                                                 DWORD* serial, DWORD* max_comp, DWORD* fs_flags, wchar_t16* fs_name,
                                                 DWORD fs_name_len)
{
    (void)root;
    if (vol_name != (wchar_t16*)0 && vol_name_len > 0)
    {
        static const wchar_t16 vn[] = {'D', 'u', 'e', 't', 'O', 'S', 0};
        DWORD i = 0;
        while (i < vol_name_len - 1 && vn[i] != 0)
        {
            vol_name[i] = vn[i];
            ++i;
        }
        vol_name[i] = 0;
    }
    if (serial != (DWORD*)0)
        *serial = 0xCAFEBABE;
    if (max_comp != (DWORD*)0)
        *max_comp = 255;
    if (fs_flags != (DWORD*)0)
        *fs_flags = 0;
    if (fs_name != (wchar_t16*)0 && fs_name_len > 0)
    {
        static const wchar_t16 fn[] = {'D', 'U', 'E', 'T', 'F', 'S', 0};
        DWORD i = 0;
        while (i < fs_name_len - 1 && fn[i] != 0)
        {
            fs_name[i] = fn[i];
            ++i;
        }
        fs_name[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL GetDiskFreeSpaceExW(const wchar_t16* dir, void* avail, void* total, void* free_)
{
    (void)dir;
    unsigned long long free_b = 1ULL * 1024 * 1024 * 1024;
    unsigned long long total_b = 8ULL * 1024 * 1024 * 1024;
    if (avail != (void*)0)
        *(unsigned long long*)avail = free_b;
    if (total != (void*)0)
        *(unsigned long long*)total = total_b;
    if (free_ != (void*)0)
        *(unsigned long long*)free_ = free_b;
    return 1;
}

__declspec(dllexport) BOOL GetThreadIOPendingFlag(HANDLE thread, BOOL* pending)
{
    (void)thread;
    if (pending != (BOOL*)0)
        *pending = 0;
    return 1;
}

__declspec(dllexport) DWORD GetPrivateProfileStringA(const char* section, const char* key, const char* def_val,
                                                     char* buf, DWORD size, const char* file)
{
    (void)section;
    (void)key;
    (void)file;
    if (buf == (char*)0 || size == 0)
        return 0;
    if (def_val == (const char*)0)
    {
        buf[0] = 0;
        return 0;
    }
    DWORD i = 0;
    while (i < size - 1 && def_val[i] != 0)
    {
        buf[i] = def_val[i];
        ++i;
    }
    buf[i] = 0;
    return i;
}

__declspec(dllexport) UINT GetPrivateProfileIntA(const char* section, const char* key, int def_val, const char* file)
{
    (void)section;
    (void)key;
    (void)file;
    return (UINT)def_val;
}

__declspec(dllexport) DWORD GetProfileStringA(const char* section, const char* key, const char* def_val, char* buf,
                                              DWORD size)
{
    return GetPrivateProfileStringA(section, key, def_val, buf, size, "");
}

__declspec(dllexport) DWORD GetFullPathNameW(const wchar_t16* lpFileName, DWORD nBufferLength, wchar_t16* lpBuffer,
                                             wchar_t16** lpFilePart)
{
    (void)lpFilePart;
    if (lpFileName == (const wchar_t16*)0 || lpBuffer == (wchar_t16*)0)
        return 0;
    int srclen = 0;
    while (lpFileName[srclen] != 0)
        ++srclen;
    int add_drive = (srclen > 0 && (lpFileName[0] == '\\' || lpFileName[0] == '/')) ? 2 : 0;
    DWORD needed = (DWORD)(srclen + 1 + add_drive);
    if (needed > nBufferLength)
        return needed;
    int j = 0;
    if (add_drive)
    {
        lpBuffer[j++] = 'C';
        lpBuffer[j++] = ':';
    }
    for (int i = 0; i < srclen; ++i)
        lpBuffer[j++] = lpFileName[i];
    lpBuffer[j] = 0;
    return (DWORD)j;
}

/* GetCPInfo — fill a CPINFO so callers checking MaxCharSize > 0
 * pass. We only support CP_ACP / CP_OEMCP / CP_UTF8 / CP_THREAD_ACP
 * out-of-the-box; anything else still gets a generic single-byte
 * code page. The DefaultChar is "?" for fidelity with ANSI Windows. */
typedef struct
{
    unsigned int MaxCharSize;
    unsigned char DefaultChar[2];
    unsigned char LeadByte[12];
} DUETOS_CPINFO;

__declspec(dllexport) BOOL GetCPInfo(unsigned int CodePage, DUETOS_CPINFO* lpCPInfo)
{
    if (lpCPInfo == (DUETOS_CPINFO*)0)
        return 0;
    for (int i = 0; i < 12; ++i)
        lpCPInfo->LeadByte[i] = 0;
    lpCPInfo->DefaultChar[0] = '?';
    lpCPInfo->DefaultChar[1] = 0;
    if (CodePage == 65001) /* CP_UTF8 */
        lpCPInfo->MaxCharSize = 4;
    else
        lpCPInfo->MaxCharSize = 1; /* single-byte ANSI / OEM */
    return 1;
}

__declspec(dllexport) int LCMapStringW(unsigned long Locale, DWORD dwMapFlags, const wchar_t16* lpSrcStr, int cchSrc,
                                       wchar_t16* lpDestStr, int cchDest)
{
    (void)Locale;
    if (lpSrcStr == (const wchar_t16*)0)
        return 0;
    /* Compute source length. */
    int src_len = cchSrc;
    if (src_len < 0)
    {
        src_len = 0;
        while (lpSrcStr[src_len] != 0)
            ++src_len;
        ++src_len; /* include NUL */
    }
    /* Sizing call — return required dest length. */
    if (cchDest == 0 || lpDestStr == (wchar_t16*)0)
        return src_len;
    if (cchDest < src_len)
        return 0;
    /* Apply the requested transformation, byte-by-byte. */
    const unsigned long LCMAP_LOWERCASE = 0x00000100;
    const unsigned long LCMAP_UPPERCASE = 0x00000200;
    for (int i = 0; i < src_len; ++i)
    {
        wchar_t16 c = lpSrcStr[i];
        if ((dwMapFlags & LCMAP_LOWERCASE) && c >= 'A' && c <= 'Z')
            c = (wchar_t16)(c + ('a' - 'A'));
        else if ((dwMapFlags & LCMAP_UPPERCASE) && c >= 'a' && c <= 'z')
            c = (wchar_t16)(c - ('a' - 'A'));
        lpDestStr[i] = c;
    }
    return src_len;
}

/* FormatMessageW — canned messages for FORMAT_MESSAGE_FROM_SYSTEM
 * with a few common error codes. Fully real localisation /
 * inserts deferred until we have a real ntdll error table. */
__declspec(dllexport) DWORD FormatMessageW(DWORD dwFlags, const void* lpSource, DWORD dwMessageId, DWORD dwLanguageId,
                                           wchar_t16* lpBuffer, DWORD nSize, void* Arguments)
{
    (void)dwFlags;
    (void)lpSource;
    (void)dwLanguageId;
    (void)Arguments;
    if (lpBuffer == (wchar_t16*)0 || nSize == 0)
        return 0;
    static const wchar_t16 kOk[] = {'T', 'h', 'e', ' ', 'o', 'p', 'e', 'r', 'a', 't', 'i', 'o', 'n',
                                    ' ', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'e', 'd', ' ', 's', 'u',
                                    'c', 'c', 'e', 's', 's', 'f', 'u', 'l', 'l', 'y', '.', 0};
    static const wchar_t16 kGen[] = {'G', 'e', 'n', 'e', 'r', 'i', 'c', ' ', 'f', 'a', 'i', 'l', 'u', 'r', 'e', '.', 0};
    static const wchar_t16 kNotFound[] = {'T', 'h', 'e', ' ', 's', 'y', 's', 't', 'e', 'm', ' ',
                                          'c', 'a', 'n', 'n', 'o', 't', ' ', 'f', 'i', 'n', 'd',
                                          ' ', 't', 'h', 'e', ' ', 'p', 'a', 't', 'h', '.', 0};
    const wchar_t16* msg;
    if (dwMessageId == 0)
        msg = kOk;
    else if (dwMessageId == 3)
        msg = kNotFound; /* ERROR_PATH_NOT_FOUND */
    else
        msg = kGen;
    DWORD i = 0;
    while (msg[i] != 0 && i < nSize - 1)
    {
        lpBuffer[i] = msg[i];
        ++i;
    }
    lpBuffer[i] = 0;
    return i;
}

__declspec(dllexport) DWORD ExpandEnvironmentStringsA(const char* src, char* dst, DWORD size)
{
    if (src == (const char*)0)
        return 0;
    int i = 0;
    while (src[i] != 0)
        ++i;
    int total = i + 1;
    if (dst == (char*)0 || size == 0)
        return (DWORD)total;
    DWORD j;
    for (j = 0; j < size - 1 && src[j] != 0; ++j)
        dst[j] = src[j];
    dst[j] = 0;
    return (DWORD)total;
}

__declspec(dllexport) wchar_t16* lstrcatW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*)0 || src == (const wchar_t16*)0)
        return dst;
    wchar_t16* d = dst;
    while (*d != 0)
        ++d;
    while ((*d++ = *src++) != 0)
    {
    }
    return dst;
}

/* ------------------------------------------------------------------
 * File / console I/O
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
    /* UTF-16 → ASCII; normalise '\\' → '/' so Windows-style paths
     * match the kernel ramfs's POSIX-style lookup. Optional drive
     * prefix "C:" / "c:" is stripped — DuetOS has one logical
     * volume; drive letters are vestigial from the Win32 ABI. */
    char ascii[256];
    int i = 0;
    int j = 0;
    /* Skip drive letter prefix if present. */
    if (lpFileName[0] != 0 && lpFileName[1] == ':' &&
        ((lpFileName[0] >= 'A' && lpFileName[0] <= 'Z') || (lpFileName[0] >= 'a' && lpFileName[0] <= 'z')))
        i = 2;
    while (j < 255 && lpFileName[i] != 0)
    {
        char c = (char)(lpFileName[i] & 0xFF);
        ascii[j++] = (c == '\\') ? '/' : c;
        ++i;
    }
    ascii[j] = '\0';
    i = j;
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
 * Time queries
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
 * Heap aliases
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
 * Locale / code page
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
 * MultiByteToWideChar / WideCharToMultiByte
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
 * TLS slots
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
 * Win32 sync primitives — handle-based
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
 * CriticalSection
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
 * SRWLock — single 8-byte slot, exclusive only
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
 * InitOnceExecuteOnce
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
 * Thread management
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
 * File system — Find*, Copy/Move/Delete, dir ops.
 * All report "not found" / ACCESS_DENIED to keep real programs
 * on their graceful-failure paths.
 * ------------------------------------------------------------------ */

/* SYS_DIR_OPEN  = 154,  rdi = const char* path. Returns handle on
 *                       success, -1 on miss / pool full.
 * SYS_DIR_NEXT  = 155,  rdi = HANDLE, rsi = struct
 *                       Win32DirEntryReport*. Returns 1 on success,
 *                       0 at end-of-iteration, -1 on bad handle.
 *
 * The Win32DirEntryReport struct is the kernel-side stable ABI:
 *   char name[64]; u32 attributes; u32 _pad; u64 size_bytes; u8 _r[16];
 * = 96 bytes total. The kernel32 thunks marshal this into the
 * caller's WIN32_FIND_DATA[A|W] (Win32 layout: 320-byte block
 * starting with FILETIME * 3 + DWORD * 4 + name fields).
 *
 * FindFirstFile* + FindNextFile* both hand a 320-byte WIN32_FIND_DATA
 * to user code — we zero-fill the leading FILETIME / size DWORDs we
 * don't have data for, then fill cFileName from report.name. The
 * caller's `void*` is treated as opaque storage; we never read it.
 *
 * Path filter (e.g. "C:\\dir\\*.txt") is NOT honoured — we walk
 * every entry the kernel returns. Sub-GAP: glob filtering. The
 * Win32 enumeration habit is to walk every entry then match
 * cFileName client-side anyway, so most callers don't notice.
 *
 * Path translation: strip a trailing "\\*" / "\\*.*" wildcard, then
 * convert backslashes to forward slashes so the kernel's "/disk/<idx>"
 * routing recognises the path.
 */
struct Win32DirEntryReport_t
{
    char name[64];
    unsigned int attributes;
    unsigned int _pad;
    unsigned long long size_bytes;
    unsigned char _reserved[16];
};

/* WIN32_FIND_DATA shape — 320 bytes total. We only ever populate
 * the few fields that matter (attributes + size + name). */
struct Win32FindDataW_t
{
    DWORD dwFileAttributes;
    long long ftCreationTime;
    long long ftLastAccessTime;
    long long ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    wchar_t16 cFileName[260];
    wchar_t16 cAlternateFileName[14];
    DWORD dwFileType;
    DWORD dwCreatorType;
    unsigned short wFinderFlags;
};

struct Win32FindDataA_t
{
    DWORD dwFileAttributes;
    long long ftCreationTime;
    long long ftLastAccessTime;
    long long ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    char cFileName[260];
    char cAlternateFileName[14];
};

static long long DirOpenSyscall(const char* path)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)154), "D"((long long)path) : "memory");
    return rv;
}

static long long DirNextSyscall(long long handle, void* report)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)155), "D"(handle), "S"((long long)report) : "memory");
    return rv;
}

/* True iff `s` contains '*' or '?' before NUL — i.e. a Win32
 * filename glob pattern as opposed to a literal leaf. */
static int LeafIsGlob(const char* s)
{
    while (*s)
    {
        if (*s == '*' || *s == '?')
            return 1;
        ++s;
    }
    return 0;
}

/* Translate a Win32-shaped path prefix into the kernel's
 * "/disk/N" form.
 *
 *   - "\\?\" extended-length prefix is stripped (any depth of
 *     these is collapsed to plain).
 *   - "<letter>:" drive prefix is converted to /disk/<idx> where
 *     idx = uppercase(letter) - 'C' (so C: -> /disk/0, D: -> 1,
 *     E: -> 2, ...). Drive letters before C ('A' / 'B' — the
 *     classic floppy slots on real Windows) map to /disk/0 too;
 *     v0 doesn't expose floppies but the path still has to land
 *     somewhere usable.
 *   - Pure-relative paths and bare-leading-'\\' paths pass
 *     through with the backslash-to-slash conversion only.
 *
 * Returns the number of bytes consumed from `in` (always advances
 * past the drive-prefix if one was present) and writes the
 * canonicalised prefix (or "") to `out`. The caller continues
 * appending the remainder. */
static unsigned long Win32PathPrefixA(const char* in, char* out, unsigned long out_cap, unsigned long* out_written)
{
    *out_written = 0;
    if (out_cap == 0)
        return 0;
    out[0] = '\0';

    unsigned long ci = 0;

    /* Strip any number of repeated "\\?\" / "//?/" extended-
     * length prefixes (case-insensitive, separator-agnostic). */
    for (;;)
    {
        const char a = in[ci];
        const char b = in[ci + 1];
        const char c = in[ci + 2];
        const char d = in[ci + 3];
        if ((a == '\\' || a == '/') && (b == '\\' || b == '/') && c == '?' && (d == '\\' || d == '/'))
            ci += 4;
        else
            break;
    }

    /* Drive-letter prefix? */
    char letter = in[ci];
    if (((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')) && in[ci + 1] == ':')
    {
        char upper = (letter >= 'a' && letter <= 'z') ? (char)(letter - 'a' + 'A') : letter;
        int idx = (upper < 'C') ? 0 : (upper - 'C');
        /* "/disk/<idx>" — single-digit suffices for our sane cap. */
        const char* prefix = "/disk/";
        unsigned long pi = 0;
        while (prefix[pi] && pi + 1 < out_cap)
        {
            out[pi] = prefix[pi];
            ++pi;
        }
        if (pi + 1 < out_cap)
        {
            if (idx >= 10)
            {
                /* 2-digit fallback for theoretical ZZ disks. */
                out[pi++] = (char)('0' + (idx / 10));
            }
            if (pi + 1 < out_cap)
                out[pi++] = (char)('0' + (idx % 10));
        }
        out[pi] = '\0';
        *out_written = pi;
        ci += 2; /* past the ':' — the next char is the separator
                  * that introduces the rest of the path. */
    }
    return ci;
}

/* Normalize a Win32 path to the kernel's "/disk/N/..." form:
 *   - translate Win32 drive prefixes ("C:\\...", "\\?\C:\\..."),
 *   - translate '\\' to '/',
 *   - if the leaf component is a glob (contains '*' or '?'),
 *     strip it from `out` and copy it to `pattern_out` (capped).
 *
 * `pattern_out` may be NULL — caller doesn't care about the
 * pattern (no glob filtering). Cap at 63 bytes so the kernel's
 * path-copy buffer doesn't truncate the leaf. */
static void NormalizePathA(const char* in, char* out, unsigned long out_cap, char* pattern_out, unsigned long pat_cap)
{
    if (out_cap == 0)
        return;

    unsigned long prefix_len = 0;
    unsigned long consumed = Win32PathPrefixA(in, out, out_cap, &prefix_len);
    in += consumed;

    unsigned long ci = prefix_len;
    unsigned long last_sep = ci;
    int has_sep = (prefix_len > 0); /* "/disk/N" is itself a separator-bearing prefix. */
    while (in[0] != '\0' && ci + 1 < out_cap)
    {
        char c = (in[0] == '\\') ? '/' : in[0];
        out[ci] = c;
        if (c == '/')
        {
            last_sep = ci;
            has_sep = 1;
        }
        ++ci;
        ++in;
    }
    out[ci] = '\0';
    if (pattern_out && pat_cap > 0)
        pattern_out[0] = '\0';
    if (has_sep)
    {
        const char* tail = out + last_sep + 1;
        if (LeafIsGlob(tail))
        {
            if (pattern_out && pat_cap > 0)
            {
                unsigned long pi = 0;
                for (; tail[pi] != '\0' && pi + 1 < pat_cap; ++pi)
                    pattern_out[pi] = tail[pi];
                pattern_out[pi] = '\0';
            }
            out[last_sep] = '\0';
        }
    }
}

static void NormalizePathW(const wchar_t16* in, char* out, unsigned long out_cap, char* pattern_out,
                           unsigned long pat_cap)
{
    if (out_cap == 0)
        return;
    unsigned long ci = 0;
    while (in[ci] != 0 && ci + 1 < out_cap)
    {
        char c = in[ci] == L'\\' ? '/' : (char)(in[ci] & 0xFF);
        out[ci] = c;
        ++ci;
    }
    out[ci] = '\0';
    /* Reuse the A-variant glob extract by copying through. */
    char tmp[64];
    for (unsigned long i = 0; i < sizeof(tmp); ++i)
        tmp[i] = 0;
    NormalizePathA(out, tmp, sizeof(tmp), pattern_out, pat_cap);
    for (unsigned long i = 0; i < sizeof(tmp); ++i)
        out[i] = tmp[i];
}

/* Case-insensitive Win32 glob matcher. Honours '*' (match any
 * run, including empty) and '?' (match exactly one char).
 * Recursion is bounded by `*` count + pattern length; with the
 * 63-byte pattern cap from NormalizePath* this is safe.
 *
 * Empty pattern means "match anything" (no filter set). */
static int FindGlobLowerA(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return (int)(unsigned char)c;
}
static int FindGlobMatch(const char* pattern, const char* name)
{
    if (pattern == 0 || pattern[0] == '\0')
        return 1;
    while (*pattern)
    {
        if (*pattern == '*')
        {
            ++pattern;
            if (*pattern == '\0')
                return 1;
            while (*name)
            {
                if (FindGlobMatch(pattern, name))
                    return 1;
                ++name;
            }
            return 0;
        }
        if (*name == '\0')
            return 0;
        if (*pattern != '?' && FindGlobLowerA(*pattern) != FindGlobLowerA(*name))
            return 0;
        ++pattern;
        ++name;
    }
    return *name == '\0';
}

/* Per-handle pattern table — FindFirstFile installs a slot,
 * FindNextFile looks it up, FindClose retires it. 8 slots cover
 * a typical Win32 PE's nested enumerations (most PEs have one
 * outer + one inner enumerate at a time). */
struct FindHandleSlot
{
    long long handle;
    int in_use;
    char pattern[64];
};
static struct FindHandleSlot g_find_slots[8];

static void FindSlotInstall(long long h, const char* pattern)
{
    /* Reuse-or-allocate. A previous handle with the same number
     * (impossible in practice — kernel issues fresh handles) is
     * overwritten cleanly. */
    int free_idx = -1;
    for (int i = 0; i < (int)(sizeof(g_find_slots) / sizeof(g_find_slots[0])); ++i)
    {
        if (g_find_slots[i].in_use && g_find_slots[i].handle == h)
        {
            free_idx = i;
            break;
        }
        if (!g_find_slots[i].in_use && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0)
        return; /* table full — fallback to no-filter */
    g_find_slots[free_idx].handle = h;
    g_find_slots[free_idx].in_use = 1;
    unsigned long pi = 0;
    if (pattern)
    {
        for (; pattern[pi] != '\0' && pi + 1 < sizeof(g_find_slots[free_idx].pattern); ++pi)
            g_find_slots[free_idx].pattern[pi] = pattern[pi];
    }
    g_find_slots[free_idx].pattern[pi] = '\0';
}

static const char* FindSlotPattern(long long h)
{
    for (int i = 0; i < (int)(sizeof(g_find_slots) / sizeof(g_find_slots[0])); ++i)
    {
        if (g_find_slots[i].in_use && g_find_slots[i].handle == h)
            return g_find_slots[i].pattern;
    }
    return ""; /* no slot = no filter */
}

static void FindSlotRelease(long long h)
{
    for (int i = 0; i < (int)(sizeof(g_find_slots) / sizeof(g_find_slots[0])); ++i)
    {
        if (g_find_slots[i].in_use && g_find_slots[i].handle == h)
        {
            g_find_slots[i].in_use = 0;
            g_find_slots[i].handle = 0;
            g_find_slots[i].pattern[0] = '\0';
            return;
        }
    }
}

static void FillFindDataA(const struct Win32DirEntryReport_t* r, struct Win32FindDataA_t* fd)
{
    fd->dwFileAttributes = r->attributes;
    fd->ftCreationTime = 0;
    fd->ftLastAccessTime = 0;
    fd->ftLastWriteTime = 0;
    fd->nFileSizeLow = (DWORD)(r->size_bytes & 0xFFFFFFFFULL);
    fd->nFileSizeHigh = (DWORD)((r->size_bytes >> 32) & 0xFFFFFFFFULL);
    fd->dwReserved0 = 0;
    fd->dwReserved1 = 0;
    for (unsigned long i = 0; i < 260; ++i)
        fd->cFileName[i] = (i < 64) ? r->name[i] : 0;
    for (unsigned long i = 0; i < 14; ++i)
        fd->cAlternateFileName[i] = 0;
}

static void FillFindDataW(const struct Win32DirEntryReport_t* r, struct Win32FindDataW_t* fd)
{
    fd->dwFileAttributes = r->attributes;
    fd->ftCreationTime = 0;
    fd->ftLastAccessTime = 0;
    fd->ftLastWriteTime = 0;
    fd->nFileSizeLow = (DWORD)(r->size_bytes & 0xFFFFFFFFULL);
    fd->nFileSizeHigh = (DWORD)((r->size_bytes >> 32) & 0xFFFFFFFFULL);
    fd->dwReserved0 = 0;
    fd->dwReserved1 = 0;
    for (unsigned long i = 0; i < 260; ++i)
        fd->cFileName[i] = (i < 64) ? (wchar_t16)(unsigned char)r->name[i] : 0;
    for (unsigned long i = 0; i < 14; ++i)
        fd->cAlternateFileName[i] = 0;
    fd->dwFileType = 0;
    fd->dwCreatorType = 0;
    fd->wFinderFlags = 0;
}

/* Walk past kernel-returned entries until one matches `pattern` or
 * the iteration ends. Empty pattern means "no filter". Returns the
 * raw DirNextSyscall return code (1=hit, 0=end, <0=error) for the
 * first matching entry. */
static long long FindWalkUntilMatch(long long h, const char* pattern, struct Win32DirEntryReport_t* r)
{
    for (;;)
    {
        long long rc = DirNextSyscall(h, r);
        if (rc != 1)
            return rc;
        if (FindGlobMatch(pattern, r->name))
            return 1;
    }
}

__declspec(dllexport) HANDLE FindFirstFileA(const char* path, void* find_data)
{
    if (path == (const char*)0 || find_data == (void*)0)
        return (HANDLE)(long long)-1;
    char kpath[64];
    char pattern[64];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathA(path, kpath, sizeof(kpath), pattern, sizeof(pattern));
    long long h = DirOpenSyscall(kpath);
    if (h < 0)
        return (HANDLE)(long long)-1;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch(h, pattern, &r);
    if (rc != 1)
        return (HANDLE)(long long)-1;
    FillFindDataA(&r, (struct Win32FindDataA_t*)find_data);
    FindSlotInstall(h, pattern);
    return (HANDLE)h;
}

__declspec(dllexport) HANDLE FindFirstFileW(const wchar_t16* path, void* find_data)
{
    if (path == (const wchar_t16*)0 || find_data == (void*)0)
        return (HANDLE)(long long)-1;
    char kpath[64];
    char pattern[64];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathW(path, kpath, sizeof(kpath), pattern, sizeof(pattern));
    long long h = DirOpenSyscall(kpath);
    if (h < 0)
        return (HANDLE)(long long)-1;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch(h, pattern, &r);
    if (rc != 1)
        return (HANDLE)(long long)-1;
    FillFindDataW(&r, (struct Win32FindDataW_t*)find_data);
    FindSlotInstall(h, pattern);
    return (HANDLE)h;
}

__declspec(dllexport) BOOL FindNextFileA(HANDLE h, void* find_data)
{
    if (find_data == (void*)0)
        return 0;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch((long long)h, FindSlotPattern((long long)h), &r);
    if (rc != 1)
        return 0;
    FillFindDataA(&r, (struct Win32FindDataA_t*)find_data);
    return 1;
}

__declspec(dllexport) BOOL FindNextFileW(HANDLE h, void* find_data)
{
    if (find_data == (void*)0)
        return 0;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch((long long)h, FindSlotPattern((long long)h), &r);
    if (rc != 1)
        return 0;
    FillFindDataW(&r, (struct Win32FindDataW_t*)find_data);
    return 1;
}

/* FindClose — calls SYS_FILE_CLOSE (= 9), which already routes the
 * kWin32DirBase range to the directory snapshot teardown. Releases
 * the per-handle pattern slot regardless of the kernel return. */
__declspec(dllexport) BOOL FindClose(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)9), "D"((long long)h) : "memory");
    FindSlotRelease((long long)h);
    return 1;
}

/* CreateProcessA / CreateProcessW — subprocess spawn via the new
 * SYS_PROCESS_SPAWN (= 158). v0 ignores most CreateProcess
 * parameters; only the application path is honoured (via
 * lpApplicationName, or extracted from the first token of
 * lpCommandLine if lpApplicationName is NULL).
 *
 * Path translation: forward slashes pass through verbatim. The
 * kernel-side helper accepts only "/disk/<idx>/<rest>" paths;
 * Windows-native "C:\\..." paths need Windows→Unix translation
 * which is its own slice.
 *
 * On success, fills lpProcessInformation->hProcess /
 * dwProcessId / hThread / dwThreadId. hThread is collapsed to 0
 * (no separate Win32 thread handle for the new process's primary
 * thread; callers that need it can NtOpenThread the tid).
 */
struct ProcessInformation_t
{
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

__declspec(dllexport) BOOL CreateProcessA(const char* lpApplicationName, char* lpCommandLine, void* lpProcessAttributes,
                                          void* lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                                          void* lpEnvironment, const char* lpCurrentDirectory, void* lpStartupInfo,
                                          void* lpProcessInformation)
{
    (void)lpProcessAttributes;
    (void)lpThreadAttributes;
    (void)bInheritHandles;
    (void)dwCreationFlags;
    (void)lpEnvironment;
    (void)lpCurrentDirectory;
    (void)lpStartupInfo;
    const char* path = lpApplicationName;
    if (path == (const char*)0)
        path = lpCommandLine; // first arg of cmdline ≈ executable
    if (path == (const char*)0)
        return 0;
    long long pid;
    __asm__ volatile("int $0x80"
                     : "=a"(pid)
                     : "a"((long long)158), /* SYS_PROCESS_SPAWN */
                       "D"((long long)path), "S"((long long)0)
                     : "memory");
    if (pid < 0)
        return 0;
    if (lpProcessInformation != (void*)0)
    {
        struct ProcessInformation_t* pi = (struct ProcessInformation_t*)lpProcessInformation;
        pi->hProcess = (HANDLE)(long long)pid;
        pi->hThread = (HANDLE)0;
        pi->dwProcessId = (DWORD)pid;
        pi->dwThreadId = (DWORD)pid; // single-thread process; tid == pid
    }
    return 1;
}

__declspec(dllexport) BOOL CreateProcessW(const wchar_t16* lpApplicationName, wchar_t16* lpCommandLine,
                                          void* lpProcessAttributes, void* lpThreadAttributes, BOOL bInheritHandles,
                                          DWORD dwCreationFlags, void* lpEnvironment,
                                          const wchar_t16* lpCurrentDirectory, void* lpStartupInfo,
                                          void* lpProcessInformation)
{
    /* Strip wide → ASCII (low byte). 128-byte cap matches the
     * kernel-side path buffer. */
    char path[128];
    for (unsigned i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    const wchar_t16* src = lpApplicationName;
    if (src == (const wchar_t16*)0)
        src = lpCommandLine;
    if (src == (const wchar_t16*)0)
        return 0;
    unsigned i = 0;
    while (i + 1 < sizeof(path) && src[i] != 0)
    {
        path[i] = (char)(src[i] & 0xFF);
        ++i;
    }
    path[i] = '\0';
    return CreateProcessA(path, (char*)0, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
                          lpEnvironment, (const char*)0, lpStartupInfo, lpProcessInformation);
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

__declspec(dllexport) BOOL DeleteFileA(const char* path)
{
    if (path == (const char*)0)
        return 0;
    /* Run through the same Win32 path translator the Find* /
     * CreateProcess paths use so a "C:\\..." path resolves
     * through the kernel's "/disk/N" routing. NormalizePathA
     * with no glob-pattern out parameter is a pure translator. */
    char kpath[256];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathA(path, kpath, sizeof(kpath), (char*)0, 0);
    int len = 0;
    while (kpath[len] != '\0' && len < 255)
        ++len;
    long long status;
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)143), /* SYS_FILE_UNLINK */
                       "D"((long long)kpath), "S"((long long)len)
                     : "memory");
    return status == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL DeleteFileW(const wchar_t16* path)
{
    if (path == (const wchar_t16*)0)
        return 0;
    char ascii[256];
    int i = 0;
    while (i < 255 && path[i] != 0)
    {
        ascii[i] = (char)(path[i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    return DeleteFileA(ascii);
}

__declspec(dllexport) BOOL MoveFileA(const char* src, const char* dst)
{
    if (src == (const char*)0 || dst == (const char*)0)
        return 0;
    char ksrc[256];
    char kdst[256];
    for (unsigned long i = 0; i < sizeof(ksrc); ++i)
        ksrc[i] = 0;
    for (unsigned long i = 0; i < sizeof(kdst); ++i)
        kdst[i] = 0;
    NormalizePathA(src, ksrc, sizeof(ksrc), (char*)0, 0);
    NormalizePathA(dst, kdst, sizeof(kdst), (char*)0, 0);
    int slen = 0;
    while (ksrc[slen] != '\0' && slen < 255)
        ++slen;
    int dlen = 0;
    while (kdst[dlen] != '\0' && dlen < 255)
        ++dlen;
    long long status;
    register long long r10 __asm__("r10") = (long long)dlen;
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)144), /* SYS_FILE_RENAME */
                       "D"((long long)ksrc), "S"((long long)slen), "d"((long long)kdst), "r"(r10)
                     : "memory");
    return status == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL MoveFileW(const wchar_t16* src, const wchar_t16* dst)
{
    if (src == (const wchar_t16*)0 || dst == (const wchar_t16*)0)
        return 0;
    char ascii_src[256];
    char ascii_dst[256];
    int i = 0;
    while (i < 255 && src[i] != 0)
    {
        ascii_src[i] = (char)(src[i] & 0xFF);
        ++i;
    }
    ascii_src[i] = '\0';
    int j = 0;
    while (j < 255 && dst[j] != 0)
    {
        ascii_dst[j] = (char)(dst[j] & 0xFF);
        ++j;
    }
    ascii_dst[j] = '\0';
    return MoveFileA(ascii_src, ascii_dst);
}

__declspec(dllexport) DWORD GetFileAttributesA(const char* path)
{
    if (path == (const char*)0)
        return 0xFFFFFFFFu;
    char kpath[256];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathA(path, kpath, sizeof(kpath), (char*)0, 0);
    int len = 0;
    while (kpath[len] != '\0' && len < 255)
        ++len;
    if (len == 0)
        return 0xFFFFFFFFu;
    /* SYS_FILE_QUERY_ATTRIBUTES = 151. Out buffer is the
     * FILE_NETWORK_OPEN_INFORMATION layout — 56 bytes; we only
     * read the FileAttributes DWORD at offset 48. */
    unsigned char info[56];
    for (unsigned long i = 0; i < sizeof(info); ++i)
        info[i] = 0;
    long long status;
    register long long r10 __asm__("r10") = (long long)sizeof(info);
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)kpath), "S"((long long)len), "d"((long long)info), "r"(r10)
                     : "memory");
    if (status != 0)
        return 0xFFFFFFFFu; /* not found / no read permission */
    return *(unsigned*)(info + 48);
}

__declspec(dllexport) DWORD GetFileAttributesW(const wchar_t16* path)
{
    if (path == (const wchar_t16*)0)
        return 0xFFFFFFFFu;
    char ascii[256];
    int i = 0;
    while (i < 255 && path[i] != 0)
    {
        ascii[i] = (char)(path[i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    return GetFileAttributesA(ascii);
}

/* SetFileAttributes — v0 has no writable FS backend; pretend
 * success (TRUE). Callers that care check GetFileAttributes
 * afterward and see the attributes unchanged — they proceed
 * on the assumption we lost the write; same observable as
 * "read-only FS". The reg-fattr smoke test in hello_winapi
 * pins this at TRUE. */
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
 * NUL, 3 chars excl NUL). Matches the flat-stub semantics
 * that hello_winapi's sysdir smoke test pins.
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
