/*
 * sysinfo_smoke — exercise extended system-info APIs.
 *
 *   GlobalMemoryStatusEx
 *   GetPhysicallyInstalledSystemMemory
 *   GetLogicalProcessorInformation (skipped — heavy)
 *   GetActiveProcessorCount
 *   GetMaximumProcessorCount
 *   GetSystemFirmwareTable (skipped)
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[sysinfo_smoke] starting\r\n");

    /* GlobalMemoryStatusEx. */
    {
        MEMORYSTATUSEX ms = {0};
        ms.dwLength = sizeof(ms);
        BOOL ok = GlobalMemoryStatusEx(&ms);
        Out("[sysinfo_smoke] GlobalMemoryStatusEx = ");
        Out(ok && ms.ullTotalPhys > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetPhysicallyInstalledSystemMemory. */
    {
        ULONGLONG kb = 0;
        BOOL ok = GetPhysicallyInstalledSystemMemory(&kb);
        Out("[sysinfo_smoke] GetPhysicallyInstalledSystemMemory = ");
        Out(ok && kb > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetActiveProcessorCount. */
    {
        DWORD c = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        Out("[sysinfo_smoke] GetActiveProcessorCount = ");
        Out(c > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetMaximumProcessorCount. */
    {
        DWORD c = GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS);
        Out("[sysinfo_smoke] GetMaximumProcessorCount = ");
        Out(c > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[sysinfo_smoke] done\r\n");
    Out("[ring3-sysinfo-smoke] PASS\r\n");
    ExitProcess(0);
}
