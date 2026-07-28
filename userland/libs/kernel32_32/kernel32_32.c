/*
 * userland/libs/kernel32_32/kernel32_32.c
 *
 * Freestanding DuetOS kernel32.dll (i386 / PE32 variant) — ring-3
 * 32-bit code that implements the minimum Win32 entry surface a
 * PE32 image is likely to import.
 *
 * Companion to userland/libs/kernel32/kernel32.c (the PE32+ x86_64
 * variant). Both share the kernel-side syscall table (SYS_EXIT=0,
 * SYS_GETPID=1, SYS_GETPROCID=8, SYS_GETLASTERROR=9,
 * SYS_SETLASTERROR=10, ...) but use different ABIs to invoke it.
 *
 * Native 32-bit syscall ABI (mirrors Linux i386 because that's the
 * register set the i386 architecture exposes):
 *     int $0x80
 *     eax = syscall number
 *     ebx = arg1, ecx = arg2, edx = arg3, esi = arg4, edi = arg5, ebp = arg6
 *     eax = return value on exit
 *
 * The kernel's isr_common detects a 32-bit caller via CS=0x3B in the
 * trap frame and remaps these into the SysV AMD64 slots the C++
 * SyscallDispatch expects — see kernel/arch/x86_64/exceptions.S.
 *
 * Build target: i686-pc-windows-msvc (clang --target plus lld-link
 * /machine:x86 /dll /noentry /nodefaultlib). Result is a PE32 (i386)
 * DLL with Machine=0x014C, OptHdrMagic=0x10B.
 *
 * Layer-4 minimum surface: just the calls pe32_smoke uses. Future
 * slices grow this to the full ~150-export kernel32 footprint.
 *
 * File I/O (CreateFile / ReadFile / SetFilePointer / GetFileSize /
 * GetFileAttributes) lives in the sibling TU kernel32_32_fs.c; the
 * typedefs and syscall trampolines both TUs use live in
 * kernel32_32_internal.h.
 */

#include "kernel32_32_internal.h"

/* ------------------------------------------------------------------
 * Noreturn terminators (SYS_EXIT = 0, ebx = exit code)
 * ------------------------------------------------------------------ */

__declspec(dllexport) WIN32_NORETURN void __stdcall ExitProcess(UINT uExitCode)
{
    /* SYS_EXIT does not return; the kernel destroys the task and
     * never resumes user mode. The ud2 is unreachable but keeps
     * the compiler from inserting a fallthrough into whatever
     * follows in .text. */
    duet_syscall1(0 /* SYS_EXIT */, uExitCode);
    __asm__ volatile("ud2" ::: "memory");
    __builtin_unreachable();
}

__declspec(dllexport) WIN32_NORETURN BOOL __stdcall TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    (void)hProcess;
    duet_syscall1(0 /* SYS_EXIT */, uExitCode);
    __asm__ volatile("ud2" ::: "memory");
    __builtin_unreachable();
}

/* ------------------------------------------------------------------
 * Process / thread identity (syscall-backed)
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD __stdcall GetCurrentProcessId(void)
{
    return (DWORD)duet_syscall0(8 /* SYS_GETPROCID */);
}

__declspec(dllexport) DWORD __stdcall GetCurrentThreadId(void)
{
    return (DWORD)duet_syscall0(1 /* SYS_GETPID */);
}

/* ------------------------------------------------------------------
 * Pseudo-handles (constant returns)
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall GetCurrentProcess(void)
{
    return (HANDLE)(unsigned)-1;
}

__declspec(dllexport) HANDLE __stdcall GetCurrentThread(void)
{
    return (HANDLE)(unsigned)-2;
}

/* ------------------------------------------------------------------
 * Last-error slot (syscall-backed)
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD __stdcall GetLastError(void)
{
    return (DWORD)duet_syscall0(9 /* SYS_GETLASTERROR */);
}

__declspec(dllexport) void __stdcall SetLastError(DWORD err)
{
    duet_syscall1(10 /* SYS_SETLASTERROR */, err);
}

/* ------------------------------------------------------------------
 * Standard-handle + console output
 *
 * GetStdHandle returns the magic sentinel values Windows itself
 * returns: STD_OUTPUT_HANDLE = (HANDLE)-11, STD_INPUT_HANDLE =
 * (HANDLE)-10, STD_ERROR_HANDLE = (HANDLE)-12. WriteFile recognises
 * those exact values and routes to SYS_WRITE(fd=1).
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle)
{
    /* (DWORD)-11 = 0xFFFFFFF5 → STD_OUTPUT_HANDLE
     * (DWORD)-12 = 0xFFFFFFF4 → STD_ERROR_HANDLE
     * (DWORD)-10 = 0xFFFFFFF6 → STD_INPUT_HANDLE */
    return (HANDLE)(unsigned)nStdHandle;
}

/* WriteFile dispatches by handle range, mirroring the 64-bit
 * kernel32:
 *   - kernel file handles (0x100..0x10F, planted by CreateFile* via
 *     SYS_FILE_OPEN / SYS_FILE_CREATE) → SYS_FILE_WRITE, which walks
 *     the per-handle cursor under the kCapFsWrite gate.
 *   - the three std handles → SYS_WRITE(fd=1).
 *   - anything else → FALSE. No "dump it to stdout anyway" fallback:
 *     that masks stale-handle bugs in the caller.
 *
 * GAP: lpOverlapped is not honoured — the 32-bit set has no IOCP
 * surface, so an overlapped write would silently behave
 * synchronously at the current cursor. Rejected rather than faked;
 * see the matching note in kernel32_32_fs.c::ReadFile. */
__declspec(dllexport) BOOL __stdcall WriteFile(HANDLE h, const void* buf, DWORD n, DWORD* lpWritten, void* lpOverlapped)
{
    const unsigned h_low = (unsigned)(unsigned long)h;
    if (lpWritten != (DWORD*)0)
        *lpWritten = 0;

    if (Duet32IsFileHandle(h))
    {
        if (lpOverlapped != (void*)0)
            return 0;
        const int frv = duet_syscall3(43 /* SYS_FILE_WRITE */, h_low, (unsigned)(unsigned long)buf, n);
        if (frv < 0)
            return 0;
        if (lpWritten != (DWORD*)0)
            *lpWritten = (DWORD)frv;
        return 1;
    }

    if (h_low != 0xFFFFFFF5u && h_low != 0xFFFFFFF4u && h_low != 0xFFFFFFF6u)
        return 0;

    const int rv = duet_syscall3(2 /* SYS_WRITE */, 1 /* fd=stdout */, (unsigned)(unsigned long)buf, n);
    if (lpWritten != (DWORD*)0)
        *lpWritten = rv >= 0 ? (DWORD)rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall WriteConsoleA(HANDLE hConsole, const void* buf, DWORD n, DWORD* lpWritten,
                                                   void* lpReserved)
{
    return WriteFile(hConsole, buf, n, lpWritten, lpReserved);
}

/* WriteConsoleW: same as A but each input char is a wchar_t16. Strip
 * to ASCII by taking the low byte; fine for ASCII/Latin-1 codepoints,
 * approximates the rest. (wchar_t16 comes from the internal header.) */
__declspec(dllexport) BOOL __stdcall WriteConsoleW(HANDLE hConsole, const wchar_t16* buf, DWORD n, DWORD* lpWritten,
                                                   void* lpReserved)
{
    (void)lpReserved;
    if (buf == (const wchar_t16*)0 || n == 0)
    {
        if (lpWritten != (DWORD*)0)
            *lpWritten = 0;
        return 1;
    }
    /* Stack-local 256-byte ASCII bounce. CRT writes are typically
     * line-at-a-time so a small cap suffices. */
    char ascii[256];
    DWORD cap = n > 256 ? 256 : n;
    for (DWORD i = 0; i < cap; ++i)
        ascii[i] = (char)(buf[i] & 0xFF);
    return WriteFile(hConsole, ascii, cap, lpWritten, (void*)0);
}

/* ------------------------------------------------------------------
 * Module-handle pseudo-API. Real Windows tracks LoadLibrary'd DLLs
 * per process; v0 returns sentinels:
 *   GetModuleHandleA(NULL)  -> the PE's ImageBase via SYS_DLL_BASE
 *   GetModuleHandleA(name)  -> the named DLL's load base, or NULL
 * Concrete callers (MSVC CRT, ntdll thunks) rely on these for the
 * "where am I" / "where's kernel32" boot-time queries.
 * ------------------------------------------------------------------ */

/* SYS_DLL_BASE_BY_NAME = 172 — kernel returns the loaded DLL's
 * post-ASLR base VA for the named module, or 0 if not loaded.
 * (This header said "= 79" until 2026-07-26 — stale residue from the
 * 2026-06-17 fix, which corrected the call below but not the comment
 * above it. 79 is SYS_WIN_SET_CURSOR.) */
__declspec(dllexport) HANDLE __stdcall GetModuleHandleA(const char* lpModuleName)
{
    /* SYS_DLL_BASE_BY_NAME (172): rdi = name ptr, rsi = name length.
     * A NULL/empty name returns the EXE image base, matching
     * GetModuleHandle(NULL) semantics and the 64-bit kernel32. (This
     * previously called syscall 79 — SYS_WIN_SET_CURSOR — with the name
     * pointer and no length, returning a garbage value the caller's CRT
     * then dereferenced as a module base.) */
    unsigned len = 0;
    if (lpModuleName != (const char*)0)
        while (len < 63 && lpModuleName[len] != 0)
            ++len;
    return (HANDLE)(unsigned long)(unsigned)duet_syscall3(172 /* SYS_DLL_BASE_BY_NAME */,
                                                          (unsigned)(unsigned long)lpModuleName, len, 0);
}

__declspec(dllexport) HANDLE __stdcall GetModuleHandleW(const wchar_t16* lpModuleName)
{
    /* Flatten to ASCII for the syscall. The kernel's
     * SYS_DLL_BASE_BY_NAME takes an A-string. */
    if (lpModuleName == (const wchar_t16*)0)
        return GetModuleHandleA((const char*)0);
    char ascii[256];
    DWORD i = 0;
    for (; i + 1 < sizeof(ascii) && lpModuleName[i] != 0; ++i)
        ascii[i] = (char)(lpModuleName[i] & 0xFF);
    ascii[i] = 0;
    return GetModuleHandleA(ascii);
}

/* GetProcAddress(hModule, lpProcName) - kernel asks the DLL loader
 * to look up `lpProcName` in `hModule`'s export table. Returns 0 on
 * miss; v0 callers (mostly LoadLibrary chasers) check for NULL.
 *
 * SYS_DLL_PROC_ADDRESS = 57: rdi = HMODULE (DLL base VA), rsi = user
 * VA of the NUL-terminated ASCII name. (This previously called
 * syscall 80, which is SYS_WIN_SET_CAPTURE, under a made-up name
 * "SYS_DLL_PROC_ADDR" that no enum entry ever had: every
 * GetProcAddress grabbed mouse capture for whatever HWND the module
 * base's bit pattern resembled, then returned the captured-HWND value
 * cast to FARPROC, so any dynamically-resolved call jumped to
 * garbage.) */
typedef void* FARPROC;
__declspec(dllexport) FARPROC __stdcall GetProcAddress(HANDLE hModule, const char* lpProcName)
{
    const int rv = duet_syscall2(57 /* SYS_DLL_PROC_ADDRESS */, (unsigned)(unsigned long)hModule,
                                 (unsigned)(unsigned long)lpProcName);
    return (FARPROC)(unsigned long)(unsigned)rv;
}

__declspec(dllexport) HANDLE __stdcall LoadLibraryA(const char* lpLibFileName)
{
    /* v0: defer to GetModuleHandleA — i.e., only DLLs that the
     * kernel preloaded are visible. Real LoadLibrary would chase
     * the named file via the FS. Acceptable v0 because every PE32
     * the kernel spawns has its preload set picked at spawn time. */
    return GetModuleHandleA(lpLibFileName);
}

__declspec(dllexport) HANDLE __stdcall LoadLibraryW(const wchar_t16* lpLibFileName)
{
    return GetModuleHandleW(lpLibFileName);
}

__declspec(dllexport) BOOL __stdcall FreeLibrary(HANDLE hLibModule)
{
    /* v0: no-op success. Preloaded DLLs live for the process
     * lifetime; releasing them mid-flight is a follow-up slice. */
    (void)hLibModule;
    return 1;
}

/* ------------------------------------------------------------------
 * Sleep / timing
 * ------------------------------------------------------------------ */

/* SYS_SLEEP_MS = 19 — rdi = milliseconds; the caller is moved to the
 * sleep queue and woken by the timer tick. rdi == 0 behaves like
 * SYS_YIELD.
 *
 * (This previously called syscall 11 under a made-up name "SYS_SLEEP"
 * that no enum entry ever had. 11 is SYS_HEAP_ALLOC, whose rdi is a
 * byte count — so every Sleep(ms) returned immediately without ever
 * blocking AND leaked an `ms`-byte heap allocation. A guest spin-loop
 * that paced itself with Sleep therefore burned its whole tick budget
 * while slowly exhausting its heap.) */
__declspec(dllexport) void __stdcall Sleep(DWORD dwMilliseconds)
{
    duet_syscall1(19 /* SYS_SLEEP_MS */, dwMilliseconds);
}

/* SYS_PERF_COUNTER = 13 — no args; returns the kernel tick counter,
 * which advances at 100 Hz. Win32 GetTickCount is milliseconds, so
 * scale by 10, exactly as the 64-bit GetTickCount64 does. Truncating
 * to DWORD is correct: Win32 documents GetTickCount as wrapping every
 * ~49.7 days.
 *
 * (This previously called syscall 70 under a made-up name
 * "SYS_GETTICKCOUNT" that no enum entry ever had. 70 is
 * SYS_WIN_GET_RECT, which expects rdi=HWND, rsi=selector, rdx=RECT* —
 * none of which were supplied, so the call returned a status flag
 * rather than a time and left the kernel reading a stale register as
 * the out-pointer.) */
__declspec(dllexport) DWORD __stdcall GetTickCount(void)
{
    return (DWORD)((unsigned)duet_syscall0(13 /* SYS_PERF_COUNTER */) * 10u);
}

/* ------------------------------------------------------------------
 * Heap — the handle-aware HEAPEX family, matching the 64-bit
 * kernel32 (userland/libs/kernel32/kernel32_sync.c) exactly:
 *
 *   SYS_HEAPEX_ALLOC   = 194 — rdi = heap handle (0 = default),
 *                              rsi = size.        Returns VA or 0.
 *   SYS_HEAPEX_FREE    = 195 — rdi = heap handle, rsi = ptr.
 *   SYS_HEAPEX_SIZE    = 196 — rdi = heap handle, rsi = ptr.
 *                              Returns payload bytes, 0 on bad ptr.
 *   SYS_HEAPEX_REALLOC = 197 — rdi = heap handle, rsi = ptr
 *                              (0 = alloc), rdx = new size
 *                              (0 = free). Returns new VA or 0.
 *
 * This whole block previously called syscalls 71 and 72 under the
 * names "SYS_HEAP_ALLOC" / "SYS_HEAP_FREE". Those numbers are
 * SYS_WIN_SET_TEXT and SYS_WIN_TIMER_SET: every HeapAlloc tried to
 * retitle a window using the byte count as a string pointer, and
 * every HeapFree tried to arm a window timer. Allocation always
 * failed and nothing was ever freed.
 *
 * The legacy 2-arg SYS_HEAP_ALLOC(11)/SYS_HEAP_FREE(12) pair would
 * also have been wrong here: it takes rdi = size with no heap
 * handle, so it cannot honour the HeapCreate handle the static MSVC
 * CRT allocates through. The 64-bit sibling uses HEAPEX for exactly
 * that reason.
 * ------------------------------------------------------------------ */

#define HEAP_ZERO_MEMORY 0x00000008u

/* The heap handle is the heap's base VA, not an opaque cookie:
 * Win32HeapResolveHandle (kernel/subsystems/win32/heap.cpp) accepts
 * proc->heap_base, 0, or kWin32HeapVa, and otherwise matches a
 * HeapCreate'd secondary heap by base_va.
 *
 * This used to return a made-up 0x12340000 sentinel, on the stated
 * assumption that "the kernel doesn't key on this value" — it does.
 * 0x50000000 is kWin32HeapVa, the value the 64-bit GetProcessHeap
 * returns, so every HEAPEX call now resolves instead of being
 * rejected. */
#define DUET32_PROCESS_HEAP_VA 0x50000000u

__declspec(dllexport) HANDLE __stdcall GetProcessHeap(void)
{
    return (HANDLE)DUET32_PROCESS_HEAP_VA;
}

__declspec(dllexport) void* __stdcall HeapAlloc(HANDLE hHeap, DWORD dwFlags, unsigned dwBytes)
{
    const unsigned rv = (unsigned)duet_syscall2(194 /* SYS_HEAPEX_ALLOC */, (unsigned)(unsigned long)hHeap, dwBytes);
    /* HEAP_ZERO_MEMORY is honoured in the DLL, as on 64-bit — the
     * kernel hands back uninitialised heap bytes. */
    if (rv != 0 && (dwFlags & HEAP_ZERO_MEMORY) != 0)
    {
        unsigned char* dst = (unsigned char*)(unsigned long)rv;
        for (unsigned i = 0; i < dwBytes; ++i)
            dst[i] = 0;
    }
    return (void*)(unsigned long)rv;
}

__declspec(dllexport) BOOL __stdcall HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem)
{
    (void)dwFlags;
    /* Win32 treats HeapFree(NULL) as success; the kernel would
     * reject it as a bad pointer. Same guard as the 64-bit sibling. */
    if (lpMem == (void*)0)
        return 1;
    duet_syscall2(195 /* SYS_HEAPEX_FREE */, (unsigned)(unsigned long)hHeap, (unsigned)(unsigned long)lpMem);
    return 1;
}

__declspec(dllexport) unsigned __stdcall HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem)
{
    (void)dwFlags;
    if (lpMem == (const void*)0)
        return 0;
    return (unsigned)duet_syscall2(196 /* SYS_HEAPEX_SIZE */, (unsigned)(unsigned long)hHeap,
                                   (unsigned)(unsigned long)lpMem);
}

/* HeapReAlloc(hHeap, flags, lpMem, dwBytes) — the kernel owns the
 * grow/shrink and the payload copy.
 *
 * The previous implementation allocated a fresh block and returned it
 * WITHOUT copying the old contents and without freeing the old block,
 * because no size oracle existed. Every CRT realloc therefore silently
 * lost the caller's data. HEAPEX_REALLOC has been available all along. */
__declspec(dllexport) void* __stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, unsigned dwBytes)
{
    const unsigned rv = (unsigned)duet_syscall3(197 /* SYS_HEAPEX_REALLOC */, (unsigned)(unsigned long)hHeap,
                                                (unsigned)(unsigned long)lpMem, dwBytes);
    if (rv != 0 && (dwFlags & HEAP_ZERO_MEMORY) != 0 && lpMem == (void*)0)
    {
        unsigned char* dst = (unsigned char*)(unsigned long)rv;
        for (unsigned i = 0; i < dwBytes; ++i)
            dst[i] = 0;
    }
    return (void*)(unsigned long)rv;
}

/* ------------------------------------------------------------------
 * CRT-startup helpers
 * ------------------------------------------------------------------ */

/* GetCommandLineA returns a pointer to the process's command line.
 * v0 returns a fixed "a.exe" string until the spawn path plumbs a
 * real command line through. */
__declspec(dllexport) const char* __stdcall GetCommandLineA(void)
{
    static const char kCmdline[] = "a.exe";
    return kCmdline;
}

__declspec(dllexport) const wchar_t16* __stdcall GetCommandLineW(void)
{
    static const wchar_t16 kCmdlineW[] = {'a', '.', 'e', 'x', 'e', 0};
    return kCmdlineW;
}

/* GetStartupInfoA/W — populate a STARTUPINFO struct. v0 zero-fills
 * the caller-provided struct except for cb (its size) so the CRT
 * sees "no console redirection, no special handles". */
__declspec(dllexport) void __stdcall GetStartupInfoA(void* lpStartupInfo)
{
    if (lpStartupInfo == (void*)0)
        return;
    /* STARTUPINFOA is 68 bytes; zero everything then set cb at +0. */
    unsigned char* p = (unsigned char*)lpStartupInfo;
    for (int i = 0; i < 68; ++i)
        p[i] = 0;
    /* cb (DWORD at offset 0) — caller usually pre-fills this; if not,
     * leave 0 (real Windows tolerates either). */
}

__declspec(dllexport) void __stdcall GetStartupInfoW(void* lpStartupInfo)
{
    GetStartupInfoA(lpStartupInfo);
}

/* GetFileType — type of the named file handle:
 *   FILE_TYPE_CHAR (0x2) for the three std handles — what MSVC CRT's
 *     "is stdout a console?" check wants.
 *   FILE_TYPE_DISK (0x1) for kernel file handles, so a caller that
 *     gates seeking on "is this seekable?" gets the right answer for
 *     a CreateFile* handle.
 *   FILE_TYPE_UNKNOWN (0x0) otherwise. */
__declspec(dllexport) DWORD __stdcall GetFileType(HANDLE hFile)
{
    const unsigned h = (unsigned)(unsigned long)hFile;
    if (h == 0xFFFFFFF5u || h == 0xFFFFFFF4u || h == 0xFFFFFFF6u)
        return 0x2; /* FILE_TYPE_CHAR */
    if (Duet32IsFileHandle(hFile))
        return 0x1; /* FILE_TYPE_DISK */
    return 0x0;     /* FILE_TYPE_UNKNOWN */
}

/* Critical sections, SRW locks, mutexes/events/semaphores, waits and
 * CreateThread live in the sibling TU kernel32_32_sync.c — including
 * the i386 struct-layout note that governs every caller-owned lock
 * struct in this DLL. */

/* ------------------------------------------------------------------
 * Per-process app-compat policy cache (mirrors kernel32.c)
 *
 * `SYS_COMPAT_QUERY = 206` returns the packed CompatPolicyBits
 * the PE loader baked in at spawn time. The policy never mutates,
 * so we read it once and cache the result. Bit layout matches
 * `enum CompatPolicyBits` in kernel/syscall/syscall.h — every
 * relevant bit fits in the low byte, so the 32-bit syscall
 * trampoline's eax return is wide enough.
 * ------------------------------------------------------------------ */
#define DUETOS_COMPAT_BIT_IGNORE_DEBUGGER (1u << 0)
#define DUETOS_COMPAT_BIT_IGNORE_ETW (1u << 1)
#define DUETOS_COMPAT_BIT_FAKE_OK_STACK_GUARANTEE (1u << 2)
#define DUETOS_COMPAT_BIT_APPLIED (1u << 3)
/* Top bit (within a u32) marks the cache primed; reserved high
 * so the kernel never sets it on its own. */
#define DUETOS_COMPAT_CACHE_PRIMED (1u << 31)

static unsigned g_duet_compat_cache = 0;

static unsigned duet_compat_query(void)
{
    unsigned cached = g_duet_compat_cache;
    if ((cached & DUETOS_COMPAT_CACHE_PRIMED) != 0)
        return cached;
    unsigned bits = (unsigned)duet_syscall0(206) | DUETOS_COMPAT_CACHE_PRIMED;
    g_duet_compat_cache = bits;
    return bits;
}

/* ------------------------------------------------------------------
 * IsDebuggerPresent / safe-ignore shims
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL __stdcall IsDebuggerPresent(void)
{
    /* See kernel32.c::IsDebuggerPresent for the rationale: in v0
     * the production-build answer is FALSE either way; the policy
     * consultation wires the contract for a future debugger. */
    if ((duet_compat_query() & DUETOS_COMPAT_BIT_IGNORE_DEBUGGER) != 0)
        return 0;
    return 0;
}

__declspec(dllexport) BOOL __stdcall IsProcessorFeaturePresent(DWORD ProcessorFeature)
{
    (void)ProcessorFeature;
    return 0;
}

__declspec(dllexport) void __stdcall SetUnhandledExceptionFilter(void* filter)
{
    (void)filter;
}

__declspec(dllexport) void __stdcall UnhandledExceptionFilter(void* info)
{
    (void)info;
}

/* CloseHandle: kernel handles are per-process; the kernel32 path is a
 * thin wrapper around SYS_FILE_CLOSE = 22, which frees the handle
 * slot and treats an unknown handle as a documented no-op.
 *
 * (This previously called syscall 4 — SYS_STAT, not SYS_CLOSE; there
 * is no SYS_CLOSE. Every close therefore issued a path-stat with the
 * handle value reinterpreted as a user path pointer, leaked a
 * kCapFsRead denial on sandboxed callers, returned FALSE, and left
 * the file slot allocated until process exit. Same wrong-syscall-
 * number class as the GetModuleHandleA bug fixed 2026-06-17; the
 * 64-bit kernel32 has always used 22.) */
__declspec(dllexport) BOOL __stdcall CloseHandle(HANDLE hObject)
{
    duet_syscall1(22 /* SYS_FILE_CLOSE */, (unsigned)(unsigned long)hObject);
    /* Match the 64-bit kernel32 and the flat-stub contract: always
     * TRUE. The kernel handles unknown handles as a no-op, and Win32
     * callers routinely close pseudo-handles. */
    return 1;
}

/* GetVersion / GetVersionExA — version pretend. v0 reports a fixed
 * Windows-5.1 (XP SP3) tuple, the lowest common denominator Win32
 * SDK build target. Real Windows queries this all over the place. */
__declspec(dllexport) DWORD __stdcall GetVersion(void)
{
    /* Low word = major + minor (5,1), high word = build number
     * (0xA28 = 2600, XP SP3). */
    return 0x0A280005u;
}

/* InterlockedXxx — atomic ops. v0 uses single-CPU non-atomic; the
 * compat note says SMP support lands with the lock prefix slice. */
__declspec(dllexport) long __stdcall InterlockedIncrement(long volatile* p)
{
    if (p == (long volatile*)0)
        return 0;
    long v = *p + 1;
    *p = v;
    return v;
}

__declspec(dllexport) long __stdcall InterlockedDecrement(long volatile* p)
{
    if (p == (long volatile*)0)
        return 0;
    long v = *p - 1;
    *p = v;
    return v;
}

__declspec(dllexport) long __stdcall InterlockedExchange(long volatile* p, long val)
{
    if (p == (long volatile*)0)
        return 0;
    long old = *p;
    *p = val;
    return old;
}

__declspec(dllexport) long __stdcall InterlockedCompareExchange(long volatile* p, long val, long cmp)
{
    if (p == (long volatile*)0)
        return 0;
    long old = *p;
    if (old == cmp)
        *p = val;
    return old;
}

/* ------------------------------------------------------------------
 * Debug output
 * ------------------------------------------------------------------ */

/* OutputDebugStringA — route the NUL-terminated string to the kernel
 * debug sink via SYS_WRITE(fd=1), the same channel WriteFile uses for
 * stdout. On Windows with no debugger attached the string is simply
 * discarded; surfacing it on the serial console (the DuetOS debug
 * sink) is the more useful behaviour and is consistent with
 * IsDebuggerPresent returning the "no debugger" answer. A guest PE32's
 * static CRT may call this through an OutputDebugStringf-style wrapper
 * on its startup/diagnostics path, so a real implementation (not the
 * unresolved-import stub that SYS_EXITs) is required to clear CRT
 * init. */
__declspec(dllexport) void __stdcall OutputDebugStringA(const char* lpOutputString)
{
    if (lpOutputString == (const char*)0)
        return;
    unsigned n = 0;
    while (lpOutputString[n] != 0)
        ++n;
    if (n != 0)
        duet_syscall3(2 /* SYS_WRITE */, 1 /* fd = stdout/debug sink */, (unsigned)(unsigned long)lpOutputString, n);
}

/* ------------------------------------------------------------------
 * OS version
 * ------------------------------------------------------------------ */

/* GetVersionExA — fill the caller's OSVERSIONINFO(EX)A. Reports
 * Windows XP (5.1 build 2600, VER_PLATFORM_WIN32_NT), consistent with
 * the GetVersion export above and period-appropriate for the
 * early-2000s PE32 binaries this layer targets. The caller pre-sets
 * dwOSVersionInfoSize (offset 0) to 148 (OSVERSIONINFOA) or 156 (EX);
 * we reject anything smaller, then fill the five base DWORDs, zero
 * szCSDVersion[128], and zero the EX tail when present. A guest that
 * reads dwPlatformId after the call branches to its NT path on ==2. */
__declspec(dllexport) BOOL __stdcall GetVersionExA(void* lpVersionInformation)
{
    if (lpVersionInformation == (void*)0)
        return 0;
    DWORD* p = (DWORD*)lpVersionInformation;
    if (p[0] < 148) /* smaller than sizeof(OSVERSIONINFOA) — invalid */
        return 0;
    p[1] = 5;                                     /* dwMajorVersion */
    p[2] = 1;                                     /* dwMinorVersion */
    p[3] = 2600;                                  /* dwBuildNumber */
    p[4] = 2;                                     /* dwPlatformId = VER_PLATFORM_WIN32_NT */
    char* csd = (char*)lpVersionInformation + 20; /* szCSDVersion[128] */
    for (int i = 0; i < 128; ++i)
        csd[i] = 0;
    if (p[0] >= 156) /* OSVERSIONINFOEXA — zero the SP/suite/product tail */
    {
        unsigned char* ex = (unsigned char*)lpVersionInformation + 148;
        for (int i = 0; i < 8; ++i)
            ex[i] = 0;
    }
    return 1;
}

/* ------------------------------------------------------------------
 * Thread-local storage — SYS_TLS_ALLOC=34 / FREE=35 / GET=36 / SET=37.
 * The static CRT uses these for its per-thread errno / FPU-state and
 * its _onexit table. TLS_OUT_OF_INDEXES (0xFFFFFFFF) signals alloc
 * failure.
 * ------------------------------------------------------------------ */
__declspec(dllexport) DWORD __stdcall TlsAlloc(void)
{
    return (DWORD)duet_syscall0(34 /* SYS_TLS_ALLOC */);
}

__declspec(dllexport) BOOL __stdcall TlsFree(DWORD slot)
{
    return duet_syscall1(35 /* SYS_TLS_FREE */, slot) == 0 ? 1 : 0;
}

__declspec(dllexport) void* __stdcall TlsGetValue(DWORD slot)
{
    const int rv = duet_syscall1(36 /* SYS_TLS_GET */, slot);
    return (void*)(unsigned long)(unsigned)rv;
}

__declspec(dllexport) BOOL __stdcall TlsSetValue(DWORD slot, void* value)
{
    return duet_syscall3(37 /* SYS_TLS_SET */, slot, (unsigned)(unsigned long)value, 0) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Locale / code page — fixed en-US / Latin-1. Pure userland, no
 * syscalls. The static CRT queries the ANSI/OEM code pages during
 * startup to size its mbtowc tables.
 * ------------------------------------------------------------------ */
__declspec(dllexport) UINT __stdcall GetACP(void)
{
    return 1252; /* Western European (Latin-1) ANSI code page. */
}

__declspec(dllexport) UINT __stdcall GetOEMCP(void)
{
    return 437; /* OEM US. */
}

__declspec(dllexport) BOOL __stdcall IsValidCodePage(UINT codepage)
{
    return (codepage == 437 || codepage == 1252 || codepage == 65001) ? 1 : 0;
}

/* CPINFO: 32-bit layout is identical (no pointers). MaxCharSize=1 for
 * the SBCS code pages we report, 4 for UTF-8. */
typedef struct
{
    UINT MaxCharSize;
    unsigned char DefaultChar[2];
    unsigned char LeadByte[12];
} DUETOS_CPINFO32;

__declspec(dllexport) BOOL __stdcall GetCPInfo(UINT CodePage, DUETOS_CPINFO32* lpCPInfo)
{
    if (lpCPInfo == (DUETOS_CPINFO32*)0)
        return 0;
    for (int i = 0; i < 12; ++i)
        lpCPInfo->LeadByte[i] = 0; /* no DBCS lead-byte ranges */
    lpCPInfo->DefaultChar[0] = '?';
    lpCPInfo->DefaultChar[1] = 0;
    lpCPInfo->MaxCharSize = (CodePage == 65001) ? 4u : 1u;
    return 1;
}

/* ------------------------------------------------------------------
 * Heap creation / teardown
 * ------------------------------------------------------------------ */

/* HeapCreate — the static CRT creates its main heap here and then
 * routes every subsequent HeapAlloc/HeapFree through the returned
 * handle. We alias it to the per-process heap: the CRT's "private"
 * heap IS the process heap. Returning NULL would send the CRT down
 * its abort path.
 *
 * GAP: no private arena — a HeapDestroy on this handle cannot
 * actually reclaim the CRT's allocations because they live in the
 * shared process heap, and two HeapCreate callers share one arena
 * rather than being isolated. SYS_HEAPEX_CREATE (192) exists and
 * would give a real secondary heap; wiring it is a follow-on slice
 * because it also needs HeapDestroy (193) and the CRT's teardown
 * ordering checked. The handle value matters either way — it must be
 * one Win32HeapResolveHandle accepts, which the previous 0x12340000
 * sentinel was not. */
__declspec(dllexport) HANDLE __stdcall HeapCreate(DWORD flOptions, unsigned dwInitialSize, unsigned dwMaximumSize)
{
    (void)flOptions;
    (void)dwInitialSize;
    (void)dwMaximumSize;
    return (HANDLE)DUET32_PROCESS_HEAP_VA; /* alias of GetProcessHeap */
}

/* HeapDestroy — the per-process heap is never torn down; succeed.
 * Only reached on the CRT's error/teardown path. */
__declspec(dllexport) BOOL __stdcall HeapDestroy(HANDLE hHeap)
{
    (void)hHeap;
    return 1;
}

/* ------------------------------------------------------------------
 * Environment / module path
 * ------------------------------------------------------------------ */

/* GetEnvironmentVariableA — v0 has no per-process environment table,
 * so every variable reports "not found". The CRT's getenv tolerates a
 * 0 (variable absent) return. */
// STUB: empty environment — every variable reports not-found.
__declspec(dllexport) DWORD __stdcall GetEnvironmentVariableA(const char* lpName, char* lpBuffer, DWORD nSize)
{
    (void)lpName;
    (void)lpBuffer;
    (void)nSize;
    return 0;
}

/* GetModuleFileNameA — v0 returns a fixed sentinel path, consistent
 * with the "X:\" drive and "a.exe" program-name sentinels the
 * GetCurrentDirectoryA / GetCommandLineA exports already use. A guest
 * CRT uses the result for _pgmptr and to derive its own directory. */
// GAP: fixed sentinel module path — the real staged path needs the PE32
// proc-env page (not yet wired); revisit when a guest derives a data
// directory from its module path.
__declspec(dllexport) DWORD __stdcall GetModuleFileNameA(HANDLE hModule, char* lpFilename, DWORD nSize)
{
    (void)hModule;
    if (lpFilename == (char*)0 || nSize == 0)
        return 0;
    static const char path[] = "X:\\a.exe";
    DWORD i = 0;
    for (; i < nSize - 1 && path[i] != 0; ++i)
        lpFilename[i] = path[i];
    lpFilename[i] = 0;
    return i;
}

/* ------------------------------------------------------------------
 * Virtual-memory query / instruction cache
 * ------------------------------------------------------------------ */

/* MEMORY_BASIC_INFORMATION, classic pre-Win10 28-byte layout (no
 * PartitionId) — the shape a period PE32 passes (dwLength == 0x1c). */
typedef struct
{
    void* BaseAddress;
    void* AllocationBase;
    DWORD AllocationProtect;
    unsigned RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} DUETOS_MBI32;

/* VirtualQuery — fill a MEMORY_BASIC_INFORMATION for the queried
 * address. v0 reports a synthetic single committed page, mirroring the
 * 64-bit kernel32 VirtualQuery: enough for callers that probe a
 * region's state. */
// GAP: synthetic region info (single committed page), not backed by the
// kernel's region ledger — AllocationBase is the page-aligned query
// address, not the true allocation/module base; revisit with a
// region-query syscall if a guest relies on the real base.
__declspec(dllexport) unsigned __stdcall VirtualQuery(const void* lpAddress, DUETOS_MBI32* lpBuffer, unsigned dwLength)
{
    if (lpBuffer == (DUETOS_MBI32*)0 || dwLength < sizeof(*lpBuffer))
        return 0;
    void* base = (void*)((unsigned long)lpAddress & ~0xFFFUL);
    lpBuffer->BaseAddress = base;
    lpBuffer->AllocationBase = base;
    lpBuffer->AllocationProtect = 0x04; /* PAGE_READWRITE */
    lpBuffer->RegionSize = 0x1000;
    lpBuffer->State = 0x1000; /* MEM_COMMIT */
    lpBuffer->Protect = 0x04; /* PAGE_READWRITE */
    lpBuffer->Type = 0x20000; /* MEM_PRIVATE */
    return sizeof(*lpBuffer);
}

/* FlushInstructionCache — x86 keeps the I-cache coherent with normal
 * D-cache stores, so a self-modifying / JIT caller needs no explicit
 * flush; succeed. */
__declspec(dllexport) BOOL __stdcall FlushInstructionCache(HANDLE hProcess, const void* lpBaseAddress, unsigned dwSize)
{
    (void)hProcess;
    (void)lpBaseAddress;
    (void)dwSize;
    return 1;
}
