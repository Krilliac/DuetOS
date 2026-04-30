/*
 * userland/libs/psapi/psapi.c — process-snapshot stubs.
 * v0 returns the current process / first module so tools that
 * iterate "for this PID, list modules / get path / get memory"
 * have at least something to work with.
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned short wchar_t16;
typedef void* HANDLE;

__declspec(dllexport) BOOL EnumProcesses(DWORD* pids, DWORD cb, DWORD* cb_needed)
{
    /* Report at least the current process so callers that filter
     * "is this PID alive" find something. The kernel-real PID is
     * fetched via GetCurrentProcessId — but that lives in
     * kernel32; we approximate with PID 1 (the init class). */
    if (cb_needed)
        *cb_needed = sizeof(DWORD);
    if (pids != (DWORD*)0 && cb >= sizeof(DWORD))
    {
        pids[0] = 1; /* sentinel current-process PID */
        return 1;
    }
    return 1;
}

__declspec(dllexport) BOOL EnumProcessModules(HANDLE hProcess, HANDLE* modules, DWORD cb, DWORD* cb_needed)
{
    (void)hProcess;
    /* Report the EXE module — synthetic 0x140000000 (the typical
     * default PE base under DuetOS ASLR). Real callers usually
     * just need a non-NULL handle to feed back into
     * GetModuleFileNameExW. */
    if (cb_needed)
        *cb_needed = sizeof(HANDLE);
    if (modules != (HANDLE*)0 && cb >= sizeof(HANDLE))
    {
        modules[0] = (HANDLE)0x140000000ULL;
        return 1;
    }
    return 1;
}

__declspec(dllexport) DWORD GetMappedFileNameW(HANDLE hProcess, void* addr, wchar_t16* path, DWORD cch)
{
    (void)hProcess;
    (void)addr;
    if (path != (wchar_t16*)0 && cch > 0)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD GetModuleBaseNameW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
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

__declspec(dllexport) DWORD GetModuleFileNameExW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
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

__declspec(dllexport) DWORD GetProcessImageFileNameW(HANDLE hProcess, wchar_t16* name, DWORD cch)
{
    return GetModuleFileNameExW(hProcess, (HANDLE)0, name, cch);
}

__declspec(dllexport) DWORD GetProcessImageFileNameA(HANDLE hProcess, char* name, DWORD cch)
{
    (void)hProcess;
    static const char path[] = "C:\\bin\\ring3.exe";
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

/* PROCESS_MEMORY_COUNTERS layout (cb-prefixed). Fill canned
 * values so callers that print them get plausible numbers. */
__declspec(dllexport) BOOL GetProcessMemoryInfo(HANDLE hProcess, void* info, DWORD cb)
{
    (void)hProcess;
    if (info == (void*)0 || cb == 0)
        return 0;
    unsigned int* p = (unsigned int*)info;
    /* Zero everything first. */
    unsigned char* b = (unsigned char*)info;
    for (DWORD i = 0; i < cb; ++i)
        b[i] = 0;
    /* PROCESS_MEMORY_COUNTERS: cb, PageFaultCount, PeakWorkingSetSize, WorkingSetSize, ... */
    if (cb >= 4)
        p[0] = cb;
    if (cb >= 8)
        p[1] = 0; /* PageFaultCount */
    /* WorkingSetSize / PeakWorkingSetSize at offset 8 / 16; SIZE_T sized. */
    return 1;
}

__declspec(dllexport) BOOL QueryWorkingSet(HANDLE hProcess, void* buf, DWORD cb)
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
