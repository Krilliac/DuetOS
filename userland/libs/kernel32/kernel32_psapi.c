#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * K32* psapi entry points — duplicated into kernel32.
 *
 * Modern Windows (Vista+) duplicates the entire psapi process /
 * module enumeration API into kernel32 with a `K32` prefix so a
 * binary built against an updated psapi.h imports from kernel32
 * directly. mingw-w64's `psapi.h` does the same thing under the
 * hood. Without these in kernel32, `EnumProcesses` etc. in a
 * smoke-test PE compile to imports of
 * `kernel32.dll!K32EnumProcesses` and fall through to the catch-
 * all NO-OP — the userland psapi.dll's K32* exports are
 * unreachable because the import-hint DLL is wrong.
 *
 * The implementations here are tiny mirrors of psapi.c: report
 * the calling process / EXE in fixed-size single-element form.
 * Real cross-process enumeration needs a kernel-side process-
 * snapshot syscall; deferred. */
__declspec(dllexport) BOOL K32EnumProcesses(DWORD* pids, DWORD cb, DWORD* cb_needed)
{
    if (cb_needed)
        *cb_needed = sizeof(DWORD);
    if (pids != (DWORD*)0 && cb >= sizeof(DWORD))
    {
        long rv;
        __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)8) : "memory"); /* SYS_GETPROCID */
        pids[0] = (DWORD)rv;
    }
    return 1;
}

__declspec(dllexport) BOOL K32EnumProcessModules(HANDLE hProcess, HANDLE* modules, DWORD cb, DWORD* cb_needed)
{
    (void)hProcess;
    if (cb_needed)
        *cb_needed = sizeof(HANDLE);
    if (modules != (HANDLE*)0 && cb >= sizeof(HANDLE))
        modules[0] = (HANDLE)0x140000000ULL; /* synthetic EXE base */
    return 1;
}

__declspec(dllexport) BOOL K32EnumProcessModulesEx(HANDLE hProcess, HANDLE* modules, DWORD cb, DWORD* cb_needed,
                                                   DWORD filter)
{
    (void)filter;
    return K32EnumProcessModules(hProcess, modules, cb, cb_needed);
}

__declspec(dllexport) DWORD K32GetMappedFileNameW(HANDLE hProcess, void* addr, wchar_t16* path, DWORD cch)
{
    (void)hProcess;
    (void)addr;
    if (path != (wchar_t16*)0 && cch > 0)
        path[0] = 0;
    return 0;
}

/* The image-path family below used to hand back three different
 * canned strings — "C:\bin\ring3.exe" from the W form,
 * "X:\bin\ring3.exe" from the A form, and the bare base name
 * "ring3" — none of which matched the running EXE or each other.
 * GetModuleFileName[AW] already derives the real path from argv[0]
 * in the proc-env page, so every one of these now routes through
 * it and they agree by construction. */

/* Owned by kernel32_env.c. */
__declspec(dllexport) DWORD GetModuleFileNameW(HANDLE hModule, wchar_t16* buf, DWORD nSize);
__declspec(dllexport) DWORD GetModuleFileNameA(HANDLE hModule, char* buf, DWORD nSize);

__declspec(dllexport) DWORD K32GetModuleBaseNameW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    (void)hProcess;
    (void)mod;
    if (name == (wchar_t16*)0 || cch == 0)
        return 0;
    wchar_t16 full[260];
    const DWORD len = GetModuleFileNameW((HANDLE)0, full, (DWORD)(sizeof(full) / sizeof(full[0])));
    if (len == 0 || len >= (DWORD)(sizeof(full) / sizeof(full[0])))
    {
        name[0] = 0;
        return 0;
    }
    /* Base name = everything past the last separator. */
    DWORD start = 0;
    for (DWORD i = len; i > 0; --i)
    {
        if (full[i - 1] == '\\' || full[i - 1] == '/')
        {
            start = i;
            break;
        }
    }
    DWORD i = 0;
    while (i < cch - 1 && start + i < len)
    {
        name[i] = full[start + i];
        ++i;
    }
    name[i] = 0;
    return i;
}

// GAP: only the calling process is modelled — hProcess and the module
// handle are ignored, so a cross-process query answers with the caller's
// own image. Revisit when a process-snapshot syscall lands.
__declspec(dllexport) DWORD K32GetModuleFileNameExW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    (void)hProcess;
    (void)mod;
    return GetModuleFileNameW((HANDLE)0, name, cch);
}

__declspec(dllexport) DWORD K32GetProcessImageFileNameW(HANDLE hProcess, wchar_t16* name, DWORD cch)
{
    return K32GetModuleFileNameExW(hProcess, (HANDLE)0, name, cch);
}

__declspec(dllexport) DWORD K32GetProcessImageFileNameA(HANDLE hProcess, char* name, DWORD cch)
{
    (void)hProcess;
    return GetModuleFileNameA((HANDLE)0, name, cch);
}

/* QueryFullProcessImageNameW — the Vista+ replacement for
 * GetProcessImageFileNameW. Same answer, different out-param
 * convention: *pdwSize is in/out (capacity in, length-written out)
 * and the return value is a BOOL.
 *
 * dwFlags PROCESS_NAME_NATIVE (1) asks for the \Device\Harddisk...
 * form; DuetOS has no NT device namespace, so we answer the
 * drive-letter path for both flag values. */
// GAP: only the calling process is modelled (hProcess is ignored) and
// PROCESS_NAME_NATIVE returns the Win32 drive-letter path because DuetOS
// has no \Device object namespace to name.
__declspec(dllexport) BOOL QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, wchar_t16* lpExeName,
                                                      DWORD* pdwSize)
{
    (void)hProcess;
    (void)dwFlags;
    if (lpExeName == (wchar_t16*)0 || pdwSize == (DWORD*)0 || *pdwSize == 0)
    {
        SetLastError(87 /* ERROR_INVALID_PARAMETER */);
        return 0;
    }
    const DWORD cap = *pdwSize;
    const DWORD len = GetModuleFileNameW((HANDLE)0, lpExeName, cap);
    if (len == 0)
    {
        SetLastError(3 /* ERROR_PATH_NOT_FOUND */);
        return 0;
    }
    if (len >= cap)
    {
        /* GetModuleFileNameW returns nSize on truncation. */
        SetLastError(122 /* ERROR_INSUFFICIENT_BUFFER */);
        return 0;
    }
    *pdwSize = len;
    return 1;
}

__declspec(dllexport) BOOL K32GetProcessMemoryInfo(HANDLE hProcess, void* info, DWORD cb)
{
    (void)hProcess;
    if (info == (void*)0 || cb == 0)
        return 0;
    unsigned int* p = (unsigned int*)info;
    unsigned char* b = (unsigned char*)info;
    for (DWORD i = 0; i < cb; ++i)
        b[i] = 0;
    /* PROCESS_MEMORY_COUNTERS layout: { cb, PageFaultCount,
     * PeakWorkingSetSize, WorkingSetSize, ... }. Echo the cb in
     * slot 0 so callers that print it get a plausible header. */
    if (cb >= 4)
        p[0] = cb;
    return 1;
}

__declspec(dllexport) BOOL K32QueryWorkingSet(HANDLE hProcess, void* buf, DWORD cb)
{
    (void)hProcess;
    if (buf)
    {
        unsigned char* b = (unsigned char*)buf;
        for (DWORD i = 0; i < cb; ++i)
            b[i] = 0;
    }
    return 1;
}

typedef struct DUET_K32_PERFORMANCE_INFORMATION
{
    DWORD cb;
    SIZE_T CommitTotal;
    SIZE_T CommitLimit;
    SIZE_T CommitPeak;
    SIZE_T PhysicalTotal;
    SIZE_T PhysicalAvailable;
    SIZE_T SystemCache;
    SIZE_T KernelTotal;
    SIZE_T KernelPaged;
    SIZE_T KernelNonpaged;
    SIZE_T PageSize;
    DWORD HandleCount;
    DWORD ProcessCount;
    DWORD ThreadCount;
} DUET_K32_PERFORMANCE_INFORMATION;

#define SYS_SYSTEM_PERFORMANCE_INFO 184LL

__declspec(dllexport) BOOL K32GetPerformanceInfo(void* info, DWORD cb)
{
    if (info == (void*)0 || cb < sizeof(DUET_K32_PERFORMANCE_INFORMATION))
        return 0;

    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(SYS_SYSTEM_PERFORMANCE_INFO), "D"(info), "S"((unsigned long long)cb)
                     : "memory");
    return rv == 0 ? 1 : 0;
}
