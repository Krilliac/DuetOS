/*
 * xinput_smoke — exercise xinput1_4.dll's flat C API.
 * v0 reports zero connected controllers; we PASS if the call returned
 * (any DWORD code is fine — we just need the entry point to exist).
 */
#include <windows.h>

extern DWORD XInputGetState(DWORD idx, void* state);
extern DWORD XInputSetState(DWORD idx, void* vibration);
extern DWORD XInputGetCapabilities(DWORD idx, DWORD flags, void* caps);
extern DWORD XInputGetBatteryInformation(DWORD idx, BYTE type, void* battery);
extern void XInputEnable(BOOL enable);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[xinput_smoke] starting\r\n");

    BYTE state[16] = {0};
    DWORD r = XInputGetState(0, state);
    Out("[xinput_smoke] XInputGetState(0)         = ");
    Out((r == 1167) ? "PASS\r\n" : "FAIL\r\n"); /* ERROR_DEVICE_NOT_CONNECTED */

    BYTE vib[4] = {0};
    r = XInputSetState(0, vib);
    Out("[xinput_smoke] XInputSetState(0)         = ");
    Out((r == 1167) ? "PASS\r\n" : "FAIL\r\n");

    BYTE caps[20] = {0};
    r = XInputGetCapabilities(0, 0, caps);
    Out("[xinput_smoke] XInputGetCapabilities(0)  = ");
    Out((r == 1167) ? "PASS\r\n" : "FAIL\r\n");

    BYTE battery[2] = {0};
    r = XInputGetBatteryInformation(0, 0, battery);
    Out("[xinput_smoke] XInputGetBatteryInformation = ");
    Out((r == 1167) ? "PASS\r\n" : "FAIL\r\n");

    XInputEnable(TRUE);
    Out("[xinput_smoke] XInputEnable(TRUE)        = PASS (returned)\r\n");

    /* Verify all 4 slots return the not-connected sentinel. */
    int connected_or_invalid = 0;
    for (DWORD i = 0; i < 4; ++i)
    {
        r = XInputGetState(i, state);
        if (r != 1167)
            connected_or_invalid = 1;
    }
    Out("[xinput_smoke] All 4 slots not-connected = ");
    Out(connected_or_invalid ? "FAIL\r\n" : "PASS\r\n");

    Out("[xinput_smoke] done\r\n");
    ExitProcess(0);
}
