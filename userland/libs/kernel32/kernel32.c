#include "kernel32_internal.h"

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
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

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
 * Thread-local in kernel Task state until the full TEB surface lands.
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
    DUET_USER_TRAP_UNREACHABLE();
}

/* TerminateProcess(hProcess, uExitCode) — hProcess is ignored
 * (single-process semantics match the existing stub). uExitCode
 * goes to SYS_EXIT same as ExitProcess. */
__declspec(dllexport) WIN32_NORETURN BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    (void)hProcess;
    __asm__ volatile("int $0x80" : : "a"((long)0), "D"((long)uExitCode));
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * Per-process app-compat policy cache
 *
 * `SYS_COMPAT_QUERY = 206` returns the packed CompatPolicyBits the
 * PE loader baked in at spawn time (sidecar `<exe>.duetcompat`).
 * The policy never mutates for a process's lifetime, so we read it
 * once on first consultation and serve every subsequent call from
 * cache — see the pattern note in
 * `wiki/reference/Roadmap.md#app-compat--per-win32-api-hooks`.
 *
 * Bit layout MUST match `enum CompatPolicyBits` in
 * kernel/syscall/syscall.h. A breaking change there breaks every
 * shim below.
 * ------------------------------------------------------------------ */
#define DUETOS_COMPAT_BIT_IGNORE_DEBUGGER (1ull << 0)
#define DUETOS_COMPAT_BIT_IGNORE_ETW (1ull << 1)
#define DUETOS_COMPAT_BIT_FAKE_OK_STACK_GUARANTEE (1ull << 2)
#define DUETOS_COMPAT_BIT_APPLIED (1ull << 3)
/* Top bit marks the cache primed. Reserved high so the kernel
 * never sets it on its own. Multiple threads can race the syscall
 * — every call returns the same answer, so the worst case is two
 * trips on first use. */
#define DUETOS_COMPAT_CACHE_PRIMED (1ull << 63)

static unsigned long long g_duet_compat_cache = 0;

unsigned long long duet_compat_query(void)
{
    unsigned long long cached = g_duet_compat_cache;
    if ((cached & DUETOS_COMPAT_CACHE_PRIMED) != 0)
        return cached;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)206) /* SYS_COMPAT_QUERY */
                     : "memory");
    unsigned long long bits = (unsigned long long)rv | DUETOS_COMPAT_CACHE_PRIMED;
    g_duet_compat_cache = bits;
    return bits;
}

/* ------------------------------------------------------------------
 * "Safe-ignore" return-constant shims
 * Semantically equivalent to the flat-stubs kOffReturnZero /
 * kOffReturnOne family for these specific Win32 contracts.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL IsDebuggerPresent(void)
{
    /* DuetOS has no debugger surface in v0 — the production-build
     * answer is FALSE either way. We still consult the compat
     * policy to wire the documented contract: when a future
     * release lights up a real debugger and an `ignore_debugger`
     * sidecar is present, the call returns FALSE without exposing
     * the live attach state. */
    if ((duet_compat_query() & DUETOS_COMPAT_BIT_IGNORE_DEBUGGER) != 0)
        return 0;
    return 0;
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

/* Per-process inherited stdio handles. The kernel writes them
 * into Process::std_handles[] at spawn (SYS_PROCESS_SPAWN_EX);
 * SYS_GET_INHERITED_STD reads them back. PEs that weren't started
 * with STARTF_USESTDHANDLES see 0 here and fall through to the
 * legacy pseudo-handle return.
 */
typedef long long ll_;
static HANDLE win32_get_inherited_std_handle(DWORD nStdHandle)
{
    /* STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12 */
    int idx;
    if (nStdHandle == 0xFFFFFFF6u) /* -10 stdin */
        idx = 0;
    else if (nStdHandle == 0xFFFFFFF5u) /* -11 stdout */
        idx = 1;
    else if (nStdHandle == 0xFFFFFFF4u) /* -12 stderr */
        idx = 2;
    else
        return (HANDLE)0;
    ll_ rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((ll_)191), /* SYS_GET_INHERITED_STD */
                       "D"((ll_)idx)
                     : "memory");
    if (rv <= 0 || rv == (ll_)~0ULL)
        return (HANDLE)0;
    return (HANDLE)(UINT_PTR)rv;
}

__declspec(dllexport) HANDLE GetStdHandle(DWORD nStdHandle)
{
    /* If the parent supplied an inheritable handle for this
     * stream via CreateProcess(STARTF_USESTDHANDLES), return
     * that real handle so WriteFile / ReadFile route through
     * the kernel handle path (pipe / file). Otherwise fall
     * back to the legacy zero-extended pseudo-handle. */
    HANDLE inherited = win32_get_inherited_std_handle(nStdHandle);
    if (inherited != (HANDLE)0)
        return inherited;

    /* Zero-extend DWORD to HANDLE (pointer-sized on x64).
     * STD_OUTPUT_HANDLE = -11 as DWORD = 0xFFFFFFF5 becomes
     * 0x00000000FFFFFFF5 as a HANDLE — same as the flat stub's
     * `mov eax, ecx; ret`. UINT_PTR is 64-bit so the cast-
     * chain stays warning-clean under MSVC's LLP64 layout. */
    return (HANDLE)(UINT_PTR)nStdHandle;
}

/* SetPriorityClass / GetPriorityClass — store the Win32 priority
 * class on the calling Process. The scheduler is single-band
 * today, so the value is purely advisory; round-trips through
 * SYS_PRIORITY_CLASS for fidelity. Returns the (post-op) class
 * code; 0 = unsupported. */
__declspec(dllexport) BOOL SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass)
{
    (void)hProcess; /* v0: caller's process only. */
    ll_ rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((ll_)189), /* SYS_PRIORITY_CLASS */
                       "D"((ll_)1),   /* op = set */
                       "S"((ll_)dwPriorityClass)
                     : "memory");
    return rv != 0;
}

__declspec(dllexport) DWORD GetPriorityClass(HANDLE hProcess)
{
    (void)hProcess;
    ll_ rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((ll_)189), /* SYS_PRIORITY_CLASS */
                       "D"((ll_)0),   /* op = get */
                       "S"((ll_)0)
                     : "memory");
    /* Default to NORMAL_PRIORITY_CLASS when the kernel reports 0
     * (process freshly spawned without an explicit Set). */
    if (rv == 0)
        return 0x20u; /* NORMAL_PRIORITY_CLASS */
    return (DWORD)rv;
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
 * Cross-slice syscall helpers (promoted out of the sync slice so
 * kernel32_sync.c and kernel32_fs.c can both link them).
 * ------------------------------------------------------------------ */

long long syscall_get_tid(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)1) : "memory");
    return rv;
}

void syscall_yield(void)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)3) : "memory");
}
