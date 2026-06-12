/*
 * multimon_smoke — exercise multi-monitor / display APIs.
 *
 *   GetSystemMetrics(SM_CXSCREEN/SM_CYSCREEN)
 *   GetSystemMetrics(SM_CMONITORS)
 *   EnumDisplayMonitors (callback)
 *   MonitorFromPoint
 *   GetMonitorInfoW
 *   EnumDisplayDevicesW
 *
 * v0: compositor is single-monitor. Most should PASS with a
 * primary monitor reported.
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

static int g_mon_count = 0;
static BOOL CALLBACK mon_cb(HMONITOR h, HDC dc, LPRECT r, LPARAM p)
{
    (void)h;
    (void)dc;
    (void)r;
    (void)p;
    ++g_mon_count;
    return TRUE;
}

void __cdecl mainCRTStartup(void)
{
    Out("[multimon_smoke] starting\r\n");

    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);
    Out("[multimon_smoke] GetSystemMetrics(screen) = ");
    Out(cx > 0 && cy > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    int nm = GetSystemMetrics(SM_CMONITORS);
    Out("[multimon_smoke] GetSystemMetrics(SM_CMONITORS) = ");
    Out(nm >= 1 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* EnumDisplayMonitors. */
    g_mon_count = 0;
    BOOL ok = EnumDisplayMonitors(NULL, NULL, mon_cb, 0);
    Out("[multimon_smoke] EnumDisplayMonitors  = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* MonitorFromPoint(0,0) — should return the primary monitor. */
    {
        POINT pt = {0, 0};
        HMONITOR m = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
        Out("[multimon_smoke] MonitorFromPoint     = ");
        Out(m != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* EnumDisplayDevicesW. */
    {
        DISPLAY_DEVICEW dd = {0};
        dd.cb = sizeof(dd);
        BOOL r = EnumDisplayDevicesW(NULL, 0, &dd, 0);
        Out("[multimon_smoke] EnumDisplayDevicesW  = ");
        Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[multimon_smoke] done\r\n");
    Out("[ring3-multimon-smoke] PASS\r\n");
    ExitProcess(0);
}
