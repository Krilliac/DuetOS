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

__declspec(dllexport) DWORD K32GetModuleBaseNameW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    (void)hProcess;
    (void)mod;
    static const wchar_t16 base[] = {'r', 'i', 'n', 'g', '3', 0};
    if (name == (wchar_t16*)0 || cch == 0)
        return 0;
    int i = 0;
    while (i < (int)cch - 1 && base[i] != 0)
    {
        name[i] = base[i];
        ++i;
    }
    name[i] = 0;
    return (DWORD)i;
}

__declspec(dllexport) DWORD K32GetModuleFileNameExW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    (void)hProcess;
    (void)mod;
    static const wchar_t16 path[] = {'C', ':', '\\', 'b', 'i', 'n', '\\', 'r', 'i',
                                     'n', 'g', '3',  '.', 'e', 'x', 'e',  0};
    if (name == (wchar_t16*)0 || cch == 0)
        return 0;
    int i = 0;
    while (i < (int)cch - 1 && path[i] != 0)
    {
        name[i] = path[i];
        ++i;
    }
    name[i] = 0;
    return (DWORD)i;
}

__declspec(dllexport) DWORD K32GetProcessImageFileNameW(HANDLE hProcess, wchar_t16* name, DWORD cch)
{
    return K32GetModuleFileNameExW(hProcess, (HANDLE)0, name, cch);
}

__declspec(dllexport) DWORD K32GetProcessImageFileNameA(HANDLE hProcess, char* name, DWORD cch)
{
    (void)hProcess;
    static const char path[] = "X:\\bin\\ring3.exe";
    if (name == (char*)0 || cch == 0)
        return 0;
    int i = 0;
    while (i < (int)cch - 1 && path[i] != 0)
    {
        name[i] = path[i];
        ++i;
    }
    name[i] = 0;
    return (DWORD)i;
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
