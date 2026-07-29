/*
 * userland/libs/kernel32_32/kernel32_32_misc.c
 *
 * The remaining high-demand i386 (PE32) kernel32 exports that do not
 * belong to the file, time or synchronisation TUs: the Local* heap
 * aliases, debug output, module-name queries, and the small set of
 * "accept and report failure honestly" calls a period PE32 reaches
 * for during startup.
 *
 * Why an honest failing export beats no export: an import the loader
 * cannot resolve is bound to a stub that SYS_EXITs the process on
 * first call. A guest that calls LoadResource and gets NULL takes its
 * own documented error path; a guest that calls an unresolved
 * LoadResource dies. Every STUB below is therefore deliberate — it
 * buys the caller its error branch.
 *
 * Contracts mirror userland/libs/kernel32/ (the x86_64 sibling)
 * except where a divergence is called out inline.
 */

#include "kernel32_32_internal.h"

/* ------------------------------------------------------------------
 * Local* heap aliases — SYS_HEAP_ALLOC 11 / SYS_HEAP_FREE 12
 *
 * These are the deprecated Win32 heap APIs. The x86_64 sibling routes
 * Local* through Global*, which route through SYS_HEAP_ALLOC /
 * SYS_HEAP_FREE; the same pair is used directly here. Every block
 * behaves like LMEM_FIXED, so the handle IS the pointer and
 * LocalLock/LocalUnlock would be pass-throughs (not exported — no
 * demand).
 * ------------------------------------------------------------------ */

#define LMEM_ZEROINIT 0x0040u

__declspec(dllexport) HANDLE __stdcall LocalAlloc(UINT uFlags, unsigned uBytes)
{
    const unsigned rv = (unsigned)duet_syscall1(11 /* SYS_HEAP_ALLOC */, uBytes);
    if (rv != 0 && (uFlags & LMEM_ZEROINIT) != 0)
    {
        unsigned char* p = (unsigned char*)(unsigned long)rv;
        for (unsigned i = 0; i < uBytes; ++i)
            p[i] = 0;
    }
    return (HANDLE)(unsigned long)rv;
}

__declspec(dllexport) HANDLE __stdcall LocalFree(HANDLE hMem)
{
    /* LocalFree returns NULL on success and the original handle on
     * failure. The kernel treats an unknown pointer as a no-op, so
     * success is the only outcome we can report. */
    if (hMem == (HANDLE)0)
        return (HANDLE)0;
    duet_syscall1(12 /* SYS_HEAP_FREE */, (unsigned)(unsigned long)hMem);
    return (HANDLE)0;
}

/* ------------------------------------------------------------------
 * Debug output
 * ------------------------------------------------------------------ */

/* OutputDebugStringW narrows to ASCII and reuses OutputDebugStringA
 * so both spellings travel one channel under one capability. The
 * kernel does have SYS_DEBUG_PRINTW (50), but it is gated on
 * kCapSerialConsole while the A path this DLL already ships uses
 * SYS_WRITE(fd=1); routing W differently would give the same API two
 * different failure modes depending on the letter suffix. */
__declspec(dllexport) void __stdcall OutputDebugStringW(const wchar_t16* lpOutputString)
{
    if (lpOutputString == (const wchar_t16*)0)
        return;
    char ascii[256];
    unsigned i = 0;
    for (; i + 1 < sizeof(ascii) && lpOutputString[i] != 0; ++i)
        ascii[i] = (char)(lpOutputString[i] & 0xFF);
    ascii[i] = 0;
    OutputDebugStringA(ascii);
}

/* DebugBreak deliberately does NOT execute int3. DuetOS has no
 * ring-3 debugger attached during a normal boot, so the trap would be
 * unhandled and terminate the guest — turning a diagnostic hint into
 * a kill. The x86_64 thunk table makes the identical choice
 * (kOffPinVoidNop, "void — no int3 (would kill us)"). */
// GAP: no breakpoint is raised - a debugger, once one exists, will not
// stop here. Revisit when a ring-3 debugger can catch #BP.
__declspec(dllexport) void __stdcall DebugBreak(void) {}

/* RaiseException(code, flags, nargs, args) — Win32 raises a
 * structured exception and lets the SEH dispatcher decide. The i386
 * companion has no SEH dispatch (see msvcrt_32's
 * _except_handler4_common), so the only faithful outcome for an
 * unhandled raise is process termination carrying the exception code.
 *
 * The x86_64 side no longer does this: kernel32.dll!RaiseException
 * builds a real EXCEPTION_RECORD and enters ntdll's two-pass engine
 * (userland/libs/kernel32/kernel32_seh.c). Closing the gap here needs
 * the kernel to deliver faults into a 32-bit dispatcher with an i386
 * CONTEXT and the fs:[0] handler chain, which does not exist yet. */
// STUB: no SEH dispatch - every RaiseException terminates the process
// instead of searching for a handler, so a guest that raises an
// exception it intended to catch dies instead.
__declspec(dllexport) WIN32_NORETURN void __stdcall RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags,
                                                                   DWORD nNumberOfArguments, const void* lpArguments)
{
    (void)dwExceptionFlags;
    (void)nNumberOfArguments;
    (void)lpArguments;
    duet_syscall1(0 /* SYS_EXIT */, dwExceptionCode);
    __asm__ volatile("ud2" ::: "memory");
    __builtin_unreachable();
}

/* ------------------------------------------------------------------
 * Heap policy
 * ------------------------------------------------------------------ */

/* HeapSetInformation selects a heap policy — the low-fragmentation
 * heap, or terminate-on-corruption. Neither is a property a caller
 * can observe through this API; both are advisory. Reporting success
 * is what Windows does for every policy it already satisfies, and a
 * FALSE return would send a hardened CRT down an abort path over a
 * hint it does not actually need. */
// GAP: the requested heap policy is not applied - the kernel heap has
// one implementation and no LFH / terminate-on-corruption modes.
__declspec(dllexport) BOOL __stdcall HeapSetInformation(HANDLE HeapHandle, int HeapInformationClass,
                                                        void* HeapInformation, unsigned HeapInformationLength)
{
    (void)HeapHandle;
    (void)HeapInformationClass;
    (void)HeapInformation;
    (void)HeapInformationLength;
    return 1;
}

/* ------------------------------------------------------------------
 * Module queries
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL __stdcall GetModuleHandleExW(DWORD dwFlags, const wchar_t16* lpModuleName, void** phModule)
{
    /* The flags select a pin / unchanged-refcount tier. Every module
     * this loader knows about is preloaded and lives for the process
     * lifetime, so all three tiers behave identically. */
    (void)dwFlags;
    if (phModule == (void**)0)
        return 0;
    void* h = (void*)GetModuleHandleW(lpModuleName);
    *phModule = h;
    return h != (void*)0 ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall GetModuleHandleExA(DWORD dwFlags, const char* lpModuleName, void** phModule)
{
    (void)dwFlags;
    if (phModule == (void**)0)
        return 0;
    void* h = (void*)GetModuleHandleA(lpModuleName);
    *phModule = h;
    return h != (void*)0 ? 1 : 0;
}

/* GetModuleFileNameW — widen whatever GetModuleFileNameA produces so
 * the sentinel path stays in one place (kernel32_32.c) rather than
 * being spelled twice and drifting. */
__declspec(dllexport) DWORD __stdcall GetModuleFileNameW(HANDLE hModule, wchar_t16* lpFilename, DWORD nSize)
{
    if (lpFilename == (wchar_t16*)0 || nSize == 0)
        return 0;
    char ascii[260];
    DWORD cap = nSize < (DWORD)sizeof(ascii) ? nSize : (DWORD)sizeof(ascii);
    const DWORD n = GetModuleFileNameA(hModule, ascii, cap);
    DWORD i = 0;
    for (; i < n && i + 1 < nSize; ++i)
        lpFilename[i] = (wchar_t16)(unsigned char)ascii[i];
    lpFilename[i] = 0;
    return i;
}

__declspec(dllexport) HANDLE __stdcall LoadLibraryExW(const wchar_t16* lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    /* LOAD_LIBRARY_AS_DATAFILE and friends select a mapping mode that
     * only matters once resources are readable; the preload set is
     * mapped as an image either way. */
    (void)hFile;
    (void)dwFlags;
    return LoadLibraryW(lpLibFileName);
}

__declspec(dllexport) HANDLE __stdcall LoadLibraryExA(const char* lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    (void)hFile;
    (void)dwFlags;
    return LoadLibraryA(lpLibFileName);
}

/* ------------------------------------------------------------------
 * Directory enumeration teardown
 * ------------------------------------------------------------------ */

/* FindClose releases a FindFirstFile* snapshot. SYS_FILE_CLOSE (22)
 * routes the directory-handle range to the snapshot teardown and
 * treats an unknown handle as a documented no-op, so this is safe for
 * any handle a confused caller passes.
 *
 * NOTE for whoever audits the x86_64 sibling: kernel32_fs.c's
 * FindClose issues syscall 9, which is SYS_GETLASTERROR, not
 * SYS_FILE_CLOSE — its comment says "SYS_FILE_CLOSE (= 9)" but the
 * enum has been 22 for as long as the range has existed. That path
 * leaks the snapshot. Fixed here; the 64-bit file is owned by
 * another lane. */
__declspec(dllexport) BOOL __stdcall FindClose(HANDLE hFindFile)
{
    duet_syscall1(22 /* SYS_FILE_CLOSE */, (unsigned)(unsigned long)hFindFile);
    return 1;
}

/* Resources moved to kernel32_32_resource.c when the shared `.rsrc`
 * walker landed. LoadResource used to be a return-NULL STUB here. */

/* ------------------------------------------------------------------
 * Error-message formatting
 * ------------------------------------------------------------------ */

/* FormatMessageW — canned FORMAT_MESSAGE_FROM_SYSTEM text for the
 * codes a startup path is most likely to render. Same three messages
 * the x86_64 sibling carries (kernel32_io.c), so a guest sees the
 * same string whichever bitness it runs at. */
// GAP: only three system messages and no insert (%1) expansion -
// FORMAT_MESSAGE_FROM_STRING / _ARGUMENT_ARRAY are ignored. Revisit
// when a real ntdll message table exists.
__declspec(dllexport) DWORD __stdcall FormatMessageW(DWORD dwFlags, const void* lpSource, DWORD dwMessageId,
                                                     DWORD dwLanguageId, wchar_t16* lpBuffer, DWORD nSize,
                                                     void* Arguments)
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
    else if (dwMessageId == 3) /* ERROR_PATH_NOT_FOUND */
        msg = kNotFound;
    else
        msg = kGen;
    DWORD i = 0;
    while (msg[i] != 0 && i + 1 < nSize)
    {
        lpBuffer[i] = msg[i];
        ++i;
    }
    lpBuffer[i] = 0;
    return i;
}

/* FormatMessageA — the narrow spelling routes through the wide one so
 * the message table is not duplicated. */
__declspec(dllexport) DWORD __stdcall FormatMessageA(DWORD dwFlags, const void* lpSource, DWORD dwMessageId,
                                                     DWORD dwLanguageId, char* lpBuffer, DWORD nSize, void* Arguments)
{
    if (lpBuffer == (char*)0 || nSize == 0)
        return 0;
    wchar_t16 wide[128];
    DWORD cap = nSize < 128u ? nSize : 128u;
    const DWORD n = FormatMessageW(dwFlags, lpSource, dwMessageId, dwLanguageId, wide, cap, Arguments);
    DWORD i = 0;
    for (; i < n && i + 1 < nSize; ++i)
        lpBuffer[i] = (char)(wide[i] & 0xFF);
    lpBuffer[i] = 0;
    return i;
}
