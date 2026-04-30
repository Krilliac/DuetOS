/*
 * services_smoke — exercise advapi32 service-control APIs.
 *
 * Probes the SCM surface every Windows service installer / control
 * tool uses. v0 has no service framework yet so most are STUB:
 *   OpenSCManagerW
 *   EnumServicesStatusW (callback — skipped)
 *   OpenServiceW
 *   CreateServiceW (skipped — would mutate state)
 *   QueryServiceStatus
 *   ControlService (skipped)
 *   CloseServiceHandle
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
    Out("[services_smoke] starting\r\n");

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    Out("[services_smoke] OpenSCManagerW       = ");
    Out(scm != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (scm != NULL)
    {
        /* OpenServiceW on a service that doesn't exist — should
         * fail cleanly, not trap. */
        SC_HANDLE svc = OpenServiceW(scm, L"DuetOSDefinitelyMissingService", SERVICE_QUERY_STATUS);
        Out("[services_smoke] OpenServiceW(missing) = ");
        Out(svc == NULL ? "PASS (NULL, as expected)\r\n" : "FAIL\r\n");
        if (svc != NULL)
            CloseServiceHandle(svc);

        BOOL c = CloseServiceHandle(scm);
        Out("[services_smoke] CloseServiceHandle    = ");
        Out(c ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[services_smoke] done\r\n");
    ExitProcess(0);
}
