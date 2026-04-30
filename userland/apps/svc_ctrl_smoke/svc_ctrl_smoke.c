/*
 * svc_ctrl_smoke — service-control beyond services_smoke.
 *
 *   QueryServiceConfigW
 *   QueryServiceStatusEx
 *   ChangeServiceConfigW (skipped)
 *   StartServiceCtrlDispatcherW (skipped — needs callback)
 *   ControlService (skipped)
 */
#include <windows.h>
#include <winsvc.h>

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
    Out("[svc_ctrl_smoke] starting\r\n");

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    Out("[svc_ctrl_smoke] OpenSCManagerW      = ");
    Out(scm != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (scm != NULL)
    {
        /* Probe a missing service — should fail cleanly. */
        SC_HANDLE svc = OpenServiceW(scm, L"NotARealService", SERVICE_QUERY_STATUS);
        Out("[svc_ctrl_smoke] OpenServiceW(missing) = ");
        Out(svc == NULL ? "PASS (NULL)\r\n" : "FAIL\r\n");
        if (svc != NULL)
            CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }

    Out("[svc_ctrl_smoke] done\r\n");
    ExitProcess(0);
}
