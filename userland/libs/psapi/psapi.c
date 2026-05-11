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

/* K32* aliases — mingw-w64's psapi.h transparently rewrites
 * `EnumProcesses` etc. to `K32EnumProcesses` etc. on Vista+, so a
 * binary built against modern headers imports the K32 form
 * directly even when the source spells the legacy name. Without
 * these re-exports every modern Win32 PE that probes psapi falls
 * through to the catch-all NO-OP stub and the smoke tests FAIL.
 *
 * Each forwards 1:1 — same ABI, same return convention. */
__declspec(dllexport) BOOL K32EnumProcesses(DWORD* pids, DWORD cb, DWORD* cb_needed)
{
    return EnumProcesses(pids, cb, cb_needed);
}

__declspec(dllexport) BOOL K32EnumProcessModules(HANDLE hProcess, HANDLE* modules, DWORD cb, DWORD* cb_needed)
{
    return EnumProcessModules(hProcess, modules, cb, cb_needed);
}

__declspec(dllexport) BOOL K32EnumProcessModulesEx(HANDLE hProcess, HANDLE* modules, DWORD cb, DWORD* cb_needed,
                                                   DWORD filter)
{
    (void)filter; /* LIST_MODULES_DEFAULT is the only meaningful tier in v0. */
    return EnumProcessModules(hProcess, modules, cb, cb_needed);
}

__declspec(dllexport) DWORD K32GetMappedFileNameW(HANDLE hProcess, void* addr, wchar_t16* path, DWORD cch)
{
    return GetMappedFileNameW(hProcess, addr, path, cch);
}

__declspec(dllexport) DWORD K32GetModuleBaseNameW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    return GetModuleBaseNameW(hProcess, mod, name, cch);
}

__declspec(dllexport) DWORD K32GetModuleFileNameExW(HANDLE hProcess, HANDLE mod, wchar_t16* name, DWORD cch)
{
    return GetModuleFileNameExW(hProcess, mod, name, cch);
}

__declspec(dllexport) DWORD K32GetProcessImageFileNameW(HANDLE hProcess, wchar_t16* name, DWORD cch)
{
    return GetProcessImageFileNameW(hProcess, name, cch);
}

__declspec(dllexport) DWORD K32GetProcessImageFileNameA(HANDLE hProcess, char* name, DWORD cch)
{
    return GetProcessImageFileNameA(hProcess, name, cch);
}

__declspec(dllexport) BOOL K32GetProcessMemoryInfo(HANDLE hProcess, void* info, DWORD cb)
{
    return GetProcessMemoryInfo(hProcess, info, cb);
}

__declspec(dllexport) BOOL K32QueryWorkingSet(HANDLE hProcess, void* buf, DWORD cb)
{
    return QueryWorkingSet(hProcess, buf, cb);
}

typedef unsigned long long SIZE_T;

typedef struct DUET_PERFORMANCE_INFORMATION
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
} DUET_PERFORMANCE_INFORMATION;

#define SYS_SYSTEM_PERFORMANCE_INFO 184LL

static BOOL QueryPerformanceSnapshot(void* info, DWORD cb)
{
    if (info == (void*)0 || cb < sizeof(DUET_PERFORMANCE_INFORMATION))
        return 0;

    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(SYS_SYSTEM_PERFORMANCE_INFO), "D"(info), "S"((unsigned long long)cb)
                     : "memory");
    return rv == 0 ? 1 : 0;
}

/* GetPerformanceInfo / K32GetPerformanceInfo — system-wide
 * performance snapshot. The kernel fills the Win32-compatible
 * PERFORMANCE_INFORMATION shape from scheduler and frame-allocator
 * counters; memory counters are page counts except PageSize. */
__declspec(dllexport) BOOL GetPerformanceInfo(void* info, DWORD cb)
{
    return QueryPerformanceSnapshot(info, cb);
}

__declspec(dllexport) BOOL K32GetPerformanceInfo(void* info, DWORD cb)
{
    return QueryPerformanceSnapshot(info, cb);
}

/* EmptyWorkingSet / K32EmptyWorkingSet — flush physical pages
 * back to swap. v0 has no swap, so success-no-op. */
__declspec(dllexport) BOOL EmptyWorkingSet(HANDLE hProcess)
{
    (void)hProcess;
    return 1;
}

__declspec(dllexport) BOOL K32EmptyWorkingSet(HANDLE hProcess)
{
    (void)hProcess;
    return 1;
}

/* GetWsChanges / K32GetWsChanges — working-set delta. Returns
 * empty + success. */
__declspec(dllexport) BOOL GetWsChanges(HANDLE hProcess, void* watch_info, DWORD cb)
{
    (void)hProcess;
    if (watch_info)
    {
        unsigned char* b = (unsigned char*)watch_info;
        for (DWORD i = 0; i < cb; ++i)
            b[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL K32GetWsChanges(HANDLE hProcess, void* watch_info, DWORD cb)
{
    return GetWsChanges(hProcess, watch_info, cb);
}

/* InitializeProcessForWsWatch / K32InitializeProcessForWsWatch —
 * arm working-set tracking. v0 success-no-op. */
__declspec(dllexport) BOOL InitializeProcessForWsWatch(HANDLE hProcess)
{
    (void)hProcess;
    return 1;
}

__declspec(dllexport) BOOL K32InitializeProcessForWsWatch(HANDLE hProcess)
{
    (void)hProcess;
    return 1;
}

/* GetModuleInformation / K32GetModuleInformation — module
 * load address + size. Synthesise a 1 MB region centred on
 * the typical default base (0x140000000). */
__declspec(dllexport) BOOL GetModuleInformation(HANDLE hProcess, HANDLE mod, void* info, DWORD cb)
{
    (void)hProcess;
    (void)mod;
    if (info == (void*)0 || cb == 0)
        return 0;
    /* MODULEINFO = { LPVOID lpBaseOfDll; DWORD SizeOfImage; LPVOID EntryPoint; }
     * Layout on x64: 8 + 4 + (4 pad) + 8 = 24 bytes. */
    unsigned long long* p64 = (unsigned long long*)info;
    if (cb >= 24)
    {
        p64[0] = 0x140000000ULL;
        unsigned int* p32 = (unsigned int*)(p64 + 1);
        p32[0] = 0x100000;
        p32[1] = 0;
        p64[2] = 0x140000000ULL;
    }
    return 1;
}

__declspec(dllexport) BOOL K32GetModuleInformation(HANDLE hProcess, HANDLE mod, void* info, DWORD cb)
{
    return GetModuleInformation(hProcess, mod, info, cb);
}

/* EnumDeviceDrivers / K32EnumDeviceDrivers — kernel-driver
 * enumeration (kCapDebug-equivalent). v0 reports 0 drivers. */
__declspec(dllexport) BOOL EnumDeviceDrivers(void** image_base, DWORD cb, DWORD* cb_needed)
{
    (void)image_base;
    (void)cb;
    if (cb_needed)
        *cb_needed = 0;
    return 1;
}

__declspec(dllexport) BOOL K32EnumDeviceDrivers(void** image_base, DWORD cb, DWORD* cb_needed)
{
    return EnumDeviceDrivers(image_base, cb, cb_needed);
}

__declspec(dllexport) DWORD GetDeviceDriverBaseNameA(void* image_base, char* name, DWORD cch)
{
    (void)image_base;
    if (name && cch > 0)
        name[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD GetDeviceDriverBaseNameW(void* image_base, wchar_t16* name, DWORD cch)
{
    (void)image_base;
    if (name && cch > 0)
        name[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD K32GetDeviceDriverBaseNameA(void* image_base, char* name, DWORD cch)
{
    return GetDeviceDriverBaseNameA(image_base, name, cch);
}

__declspec(dllexport) DWORD K32GetDeviceDriverBaseNameW(void* image_base, wchar_t16* name, DWORD cch)
{
    return GetDeviceDriverBaseNameW(image_base, name, cch);
}

__declspec(dllexport) DWORD GetDeviceDriverFileNameA(void* image_base, char* file, DWORD cch)
{
    (void)image_base;
    if (file && cch > 0)
        file[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD GetDeviceDriverFileNameW(void* image_base, wchar_t16* file, DWORD cch)
{
    (void)image_base;
    if (file && cch > 0)
        file[0] = 0;
    return 0;
}

/* QueryFullProcessImageNameA / W — modern (Vista+) image-path
 * query. Forward to GetProcessImageFileName / W. */
__declspec(dllexport) BOOL QueryFullProcessImageNameA(HANDLE hProcess, DWORD flags, char* exe_name, DWORD* size)
{
    (void)flags;
    DWORD cch = (size != (DWORD*)0) ? *size : 0;
    DWORD wrote = GetProcessImageFileNameA(hProcess, exe_name, cch);
    if (size)
        *size = wrote;
    return wrote != 0;
}

__declspec(dllexport) BOOL QueryFullProcessImageNameW(HANDLE hProcess, DWORD flags, wchar_t16* exe_name, DWORD* size)
{
    (void)flags;
    DWORD cch = (size != (DWORD*)0) ? *size : 0;
    DWORD wrote = GetProcessImageFileNameW(hProcess, exe_name, cch);
    if (size)
        *size = wrote;
    return wrote != 0;
}

__declspec(dllexport) DWORD GetMappedFileNameA(HANDLE hProcess, void* addr, char* path, DWORD cch)
{
    (void)hProcess;
    (void)addr;
    if (path && cch > 0)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) DWORD K32GetMappedFileNameA(HANDLE hProcess, void* addr, char* path, DWORD cch)
{
    return GetMappedFileNameA(hProcess, addr, path, cch);
}

__declspec(dllexport) DWORD GetModuleBaseNameA(HANDLE hProcess, HANDLE mod, char* name, DWORD cch)
{
    (void)hProcess;
    (void)mod;
    static const char base[] = "ring3";
    if (name == (char*)0 || cch == 0)
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

__declspec(dllexport) DWORD K32GetModuleBaseNameA(HANDLE hProcess, HANDLE mod, char* name, DWORD cch)
{
    return GetModuleBaseNameA(hProcess, mod, name, cch);
}

__declspec(dllexport) DWORD GetModuleFileNameExA(HANDLE hProcess, HANDLE mod, char* name, DWORD cch)
{
    (void)hProcess;
    (void)mod;
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

__declspec(dllexport) DWORD K32GetModuleFileNameExA(HANDLE hProcess, HANDLE mod, char* name, DWORD cch)
{
    return GetModuleFileNameExA(hProcess, mod, name, cch);
}
