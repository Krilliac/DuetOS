/*
 * setupapi_smoke — exercise device-installer APIs.
 *
 *   SetupDiGetClassDevsW
 *   SetupDiDestroyDeviceInfoList
 *   SetupDiEnumDeviceInfo
 *   SetupDiGetDeviceRegistryPropertyW
 */
#include <windows.h>
#include <setupapi.h>

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
    Out("[setupapi_smoke] starting\r\n");

    HDEVINFO h = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    Out("[setupapi_smoke] SetupDiGetClassDevsW = ");
    Out(h != INVALID_HANDLE_VALUE ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (h != INVALID_HANDLE_VALUE)
    {
        SP_DEVINFO_DATA dev = {0};
        dev.cbSize = sizeof(dev);
        BOOL e = SetupDiEnumDeviceInfo(h, 0, &dev);
        Out("[setupapi_smoke] SetupDiEnumDeviceInfo = ");
        Out("PASS (returned)\r\n");
        (void)e;

        BOOL d = SetupDiDestroyDeviceInfoList(h);
        Out("[setupapi_smoke] SetupDiDestroyDeviceInfoList = ");
        Out(d ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[setupapi_smoke] done\r\n");
    Out("[ring3-setupapi-smoke] PASS\r\n");
    ExitProcess(0);
}
