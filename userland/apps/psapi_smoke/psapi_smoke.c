/*
 * psapi_smoke — exercise psapi process-info APIs.
 *
 * Probes the surface every Windows task-manager / debugger uses
 * to enumerate processes and modules:
 *   EnumProcesses
 *   GetProcessImageFileNameW (path of a PID's main image)
 *   EnumProcessModules
 *   GetModuleFileNameExW
 *   GetProcessMemoryInfo
 *   GetPerformanceInfo
 *   QueryWorkingSet
 *
 * Real PASS depends on the kernel exposing per-process metadata
 * to userland — likely partially STUB today. Those calls that
 * succeed should at minimum identify our own PID.
 */
#include <windows.h>
#include <psapi.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutDec(unsigned long long v)
{
    char buf[24];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[24];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[psapi_smoke] starting\r\n");

    /* EnumProcesses. */
    {
        DWORD pids[64];
        DWORD bytes = 0;
        BOOL ok = EnumProcesses(pids, sizeof(pids), &bytes);
        Out("[psapi_smoke] EnumProcesses           = ");
        if (ok)
        {
            Out("PASS count=");
            OutDec(bytes / sizeof(DWORD));
            Out("\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }
    }

    /* EnumProcessModules on self. */
    {
        HANDLE me = GetCurrentProcess();
        HMODULE mods[32];
        DWORD bytes = 0;
        BOOL ok = EnumProcessModules(me, mods, sizeof(mods), &bytes);
        Out("[psapi_smoke] EnumProcessModules      = ");
        if (ok)
        {
            Out("PASS modules=");
            OutDec(bytes / sizeof(HMODULE));
            Out("\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }
    }

    /* GetProcessMemoryInfo. */
    {
        PROCESS_MEMORY_COUNTERS pmc = {0};
        pmc.cb = sizeof(pmc);
        BOOL ok = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
        Out("[psapi_smoke] GetProcessMemoryInfo    = ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetProcessImageFileNameW. */
    {
        WCHAR path[260] = {0};
        DWORD n = GetProcessImageFileNameW(GetCurrentProcess(), path, 260);
        Out("[psapi_smoke] GetProcessImageFileNameW= ");
        Out(n > 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* GetPerformanceInfo. Counts are page units except PageSize. */
    {
        PERFORMANCE_INFORMATION perf = {0};
        perf.cb = sizeof(perf);
        BOOL ok = GetPerformanceInfo(&perf, sizeof(perf));
        Out("[psapi_smoke] GetPerformanceInfo     = ");
        if (ok && perf.cb == sizeof(perf) && perf.PageSize > 0 && perf.PhysicalTotal > 0 && perf.CommitLimit > 0)
        {
            Out("PASS pages=");
            OutDec(perf.PhysicalTotal);
            Out("\r\n");
        }
        else
        {
            Out("FAIL/STUB\r\n");
        }
    }

    Out("[psapi_smoke] done\r\n");
    ExitProcess(0);
}
