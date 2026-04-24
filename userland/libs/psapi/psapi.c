/*
 * userland/libs/psapi/psapi.c — 7 process-snapshot stubs. All
 * report "nothing here" — no foreign-process info in v0.
 */

typedef int            BOOL;
typedef unsigned int   DWORD;
typedef unsigned short wchar_t16;
typedef void*          HANDLE;

__declspec(dllexport) BOOL EnumProcesses(DWORD* pids, DWORD cb, DWORD* cb_needed)
{
    (void) pids;
    (void) cb;
    if (cb_needed)
        *cb_needed = 0;
    return 1; /* TRUE with 0 pids — no processes visible. */
}

__declspec(dllexport) BOOL EnumProcessModules(HANDLE hProcess, HANDLE* modules, DWORD cb, DWORD* cb_needed)
{
    (void) hProcess;
    (void) modules;
    (void) cb;
    if (cb_needed)
        *cb_needed = 0;
    return 0; /* FALSE — process not accessible. */
}

__declspec(dllexport) DWORD GetMappedFileNameW(HANDLE hProcess, void* addr, wchar_t16* path, DWORD cch)
{
    (void) hProcess;
    (void) addr;
    (void) cch;
    if (path)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD GetModuleBaseNameW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    (void) hProcess;
    (void) mod;
    (void) cch;
    if (name)
        name[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD GetModuleFileNameExW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    (void) hProcess;
    (void) mod;
    (void) cch;
    if (name)
        name[0] = 0;
    return 0;
}

__declspec(dllexport) BOOL GetProcessMemoryInfo(HANDLE hProcess, void* info, DWORD cb)
{
    (void) hProcess;
    /* Zero whatever struct the caller handed us — they always
     * check the WorkingSetSize etc. fields, which start at 0. */
    if (info)
    {
        unsigned char* b = (unsigned char*) info;
        for (DWORD i = 0; i < cb; ++i)
            b[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL QueryWorkingSet(HANDLE hProcess, void* buf, DWORD cb)
{
    (void) hProcess;
    if (buf)
    {
        unsigned char* b = (unsigned char*) buf;
        for (DWORD i = 0; i < cb; ++i)
            b[i] = 0;
    }
    return 1;
}
