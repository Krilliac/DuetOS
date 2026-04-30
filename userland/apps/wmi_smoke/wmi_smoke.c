/*
 * wmi_smoke — exercise the COM/WMI startup surface.
 *
 *   CoInitializeSecurity
 *   CoInitializeEx (already in com_smoke)
 *
 * v0: WMI is not available. Smoke = "doesn't trap when an
 * installer probes WMI".
 */
#include <windows.h>
#include <objbase.h>

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
    Out("[wmi_smoke] starting\r\n");

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    Out("[wmi_smoke] CoInitializeEx        = ");
    Out(SUCCEEDED(hr) ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* CoInitializeSecurity. */
    {
        HRESULT s = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                                         NULL, EOAC_NONE, NULL);
        Out("[wmi_smoke] CoInitializeSecurity  = ");
        Out(SUCCEEDED(s) || s == RPC_E_TOO_LATE ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    CoUninitialize();
    Out("[wmi_smoke] done\r\n");
    ExitProcess(0);
}
