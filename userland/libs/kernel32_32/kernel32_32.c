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
 */

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;

#define WIN32_NORETURN __attribute__((noreturn))

/* No-arg syscall trampoline: eax = nr. */
static inline int duet_syscall0(int nr)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr) : "memory");
    return rv;
}

/* Single-arg syscall trampoline: eax = nr, ebx = arg1. */
static inline int duet_syscall1(int nr, unsigned a1)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1) : "memory");
    return rv;
}

/* Three-arg syscall trampoline: eax = nr, ebx = arg1, ecx = arg2,
 * edx = arg3. Linux i386 ABI; the kernel's isr_common remaps
 * (ebx,ecx,edx) -> (rdi,rsi,rdx) for the C++ dispatcher. */
static inline int duet_syscall3(int nr, unsigned a1, unsigned a2, unsigned a3)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(nr), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return rv;
}

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

__declspec(dllexport) BOOL __stdcall WriteFile(HANDLE h, const void* buf, DWORD n, DWORD* lpWritten, void* lpOverlapped)
{
    (void)lpOverlapped;
    const unsigned h_low = (unsigned)(unsigned long)h;
    /* Std handles only — no file I/O in the 32-bit kernel32 v0. */
    if (h_low != 0xFFFFFFF5u && h_low != 0xFFFFFFF4u && h_low != 0xFFFFFFF6u)
    {
        if (lpWritten != (DWORD*)0)
            *lpWritten = 0;
        return 0;
    }
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
 * approximates the rest. */
typedef unsigned short wchar_t16;
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

/* SYS_DLL_BASE_BY_NAME = 79 — kernel returns the loaded DLL's
 * post-ASLR base VA for the named module, or 0 if not loaded. */
__declspec(dllexport) HANDLE __stdcall GetModuleHandleA(const char* lpModuleName)
{
    return (HANDLE)(unsigned long)(unsigned)duet_syscall1(79, (unsigned)(unsigned long)lpModuleName);
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
 * SYS_DLL_PROC_ADDR = 80. */
typedef void* FARPROC;
__declspec(dllexport) FARPROC __stdcall GetProcAddress(HANDLE hModule, const char* lpProcName)
{
    const int rv = duet_syscall3(80, (unsigned)(unsigned long)hModule, (unsigned)(unsigned long)lpProcName, 0);
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

/* SYS_SLEEP = 11 — caller blocks for the specified number of
 * milliseconds. v0 accepts INFINITE (-1) as "sleep forever". */
__declspec(dllexport) void __stdcall Sleep(DWORD dwMilliseconds)
{
    duet_syscall1(11 /* SYS_SLEEP */, dwMilliseconds);
}

/* SYS_GETTICKCOUNT = 70 — uptime in ms since boot, low 32 bits. */
__declspec(dllexport) DWORD __stdcall GetTickCount(void)
{
    return (DWORD)duet_syscall0(70 /* SYS_GETTICKCOUNT */);
}

/* ------------------------------------------------------------------
 * Heap (v0: forward to the process win32-heap region the kernel
 * sets up at spawn time. Kernel side handles the actual allocation
 * via the SYS_HEAP_ALLOC / SYS_HEAP_FREE syscalls.)
 * ------------------------------------------------------------------ */

/* SYS_HEAP_ALLOC = 71 — args: process_heap_handle (ignored), size,
 * flags. Returns user VA of the allocated block, 0 on OOM. */
__declspec(dllexport) HANDLE __stdcall GetProcessHeap(void)
{
    /* Sentinel handle. The kernel doesn't keyed on this value;
     * any non-NULL HANDLE routes to the per-process heap. */
    return (HANDLE)0x12340000u;
}

__declspec(dllexport) void* __stdcall HeapAlloc(HANDLE hHeap, DWORD dwFlags, unsigned dwBytes)
{
    const int rv = duet_syscall3(71 /* SYS_HEAP_ALLOC */, (unsigned)(unsigned long)hHeap, dwBytes, dwFlags);
    return (void*)(unsigned long)(unsigned)rv;
}

__declspec(dllexport) BOOL __stdcall HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem)
{
    const int rv =
        duet_syscall3(72 /* SYS_HEAP_FREE */, (unsigned)(unsigned long)hHeap, (unsigned)(unsigned long)lpMem, dwFlags);
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) unsigned __stdcall HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem)
{
    (void)hHeap;
    (void)dwFlags;
    (void)lpMem;
    return 0; /* v0: unknown — caller fallback path expected. */
}

/* HeapReAlloc(hHeap, flags, lpMem, dwBytes): v0 fallback that
 * allocates a fresh block and copies. Doesn't free the old one
 * (no size oracle yet); the caller's pattern is "realloc then
 * stash both" for resilience. */
__declspec(dllexport) void* __stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, unsigned dwBytes)
{
    void* nb = HeapAlloc(hHeap, dwFlags, dwBytes);
    (void)lpMem;
    /* TODO: copy min(old_size, dwBytes) bytes once HeapSize works. */
    return nb;
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

/* GetFileType — type of the named file handle. v0 returns
 *   FILE_TYPE_CHAR (0x2) for the three std handles
 *   FILE_TYPE_UNKNOWN (0x0) otherwise
 * which is enough for MSVC CRT's "is stdout a console?" check. */
__declspec(dllexport) DWORD __stdcall GetFileType(HANDLE hFile)
{
    const unsigned h = (unsigned)(unsigned long)hFile;
    if (h == 0xFFFFFFF5u || h == 0xFFFFFFF4u || h == 0xFFFFFFF6u)
        return 0x2; /* FILE_TYPE_CHAR */
    return 0x0;     /* FILE_TYPE_UNKNOWN */
}

/* ------------------------------------------------------------------
 * Critical sections (v0: lockless on single-threaded entry; CS struct
 * is opaque + 24 bytes for x86, populated by InitializeCriticalSection).
 * MSVC CRT initialises a handful of these before main() and the v0
 * implementation needs to at least accept them.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void __stdcall InitializeCriticalSection(void* lpCriticalSection)
{
    if (lpCriticalSection == (void*)0)
        return;
    unsigned char* p = (unsigned char*)lpCriticalSection;
    for (int i = 0; i < 24; ++i)
        p[i] = 0;
}

__declspec(dllexport) void __stdcall EnterCriticalSection(void* lpCriticalSection)
{
    (void)lpCriticalSection;
}

__declspec(dllexport) void __stdcall LeaveCriticalSection(void* lpCriticalSection)
{
    (void)lpCriticalSection;
}

__declspec(dllexport) void __stdcall DeleteCriticalSection(void* lpCriticalSection)
{
    (void)lpCriticalSection;
}

__declspec(dllexport) BOOL __stdcall InitializeCriticalSectionAndSpinCount(void* lpCriticalSection, DWORD dwSpinCount)
{
    (void)dwSpinCount;
    InitializeCriticalSection(lpCriticalSection);
    return 1;
}

/* ------------------------------------------------------------------
 * IsDebuggerPresent / safe-ignore shims
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL __stdcall IsDebuggerPresent(void)
{
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

/* CloseHandle: kernel handles are per-process; the kernel32 path is
 * a thin wrapper around SYS_CLOSE = 4. */
__declspec(dllexport) BOOL __stdcall CloseHandle(HANDLE hObject)
{
    const int rv = duet_syscall1(4 /* SYS_CLOSE */, (unsigned)(unsigned long)hObject);
    return rv >= 0 ? 1 : 0;
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
