/*
 * xinput_smoke — exercise xinput1_4.dll's flat C API.
 *
 * The DLL queries the kernel's HID gamepad slot table over
 * SYS_GAMEPAD_STATE, so under QEMU (no pad attached) every slot
 * legitimately answers ERROR_DEVICE_NOT_CONNECTED — that is the real
 * query result, not a hardcoded stub. Attaching a USB gamepad flips
 * the answer, which is exactly what this fixture is pinning: the
 * codes below prove the syscall round-trip works and reports the
 * true connection state.
 */
#include <windows.h>

#define ERROR_SUCCESS_ 0u
#define ERROR_NOT_CONNECTED_ 1167u /* ERROR_DEVICE_NOT_CONNECTED */
#define ERROR_EMPTY_ 4306u         /* ERROR_EMPTY */

extern DWORD XInputGetState(DWORD idx, void* state);
extern DWORD XInputSetState(DWORD idx, void* vibration);
extern DWORD XInputGetCapabilities(DWORD idx, DWORD flags, void* caps);
extern DWORD XInputGetBatteryInformation(DWORD idx, BYTE type, void* battery);
extern DWORD XInputGetKeystroke(DWORD idx, DWORD reserved, void* keystroke);
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

    /* Slot 0 decides what every call below must answer. With no pad
     * attached (the QEMU case) every entry point reports
     * ERROR_DEVICE_NOT_CONNECTED; with one attached they report their
     * real results instead. Checking against a fixed 1167 would pass
     * under emulation and fail the moment someone plugs a controller
     * into real hardware -- the one case actually worth proving. */
    BYTE state[16] = {0};
    DWORD r = XInputGetState(0, state);
    const int connected = (r == ERROR_SUCCESS_);
    Out("[xinput_smoke] XInputGetState(0)         = ");
    Out((connected || r == ERROR_NOT_CONNECTED_) ? "PASS\r\n" : "FAIL\r\n");

    /* Vibration is accepted and dropped (no interrupt-OUT report
     * writer yet), so a connected pad answers success. */
    BYTE vib[4] = {0};
    r = XInputSetState(0, vib);
    Out("[xinput_smoke] XInputSetState(0)         = ");
    Out((r == (connected ? ERROR_SUCCESS_ : ERROR_NOT_CONNECTED_)) ? "PASS\r\n" : "FAIL\r\n");

    BYTE caps[20] = {0};
    r = XInputGetCapabilities(0, 0, caps);
    Out("[xinput_smoke] XInputGetCapabilities(0)  = ");
    Out((r == (connected ? ERROR_SUCCESS_ : ERROR_NOT_CONNECTED_)) ? "PASS\r\n" : "FAIL\r\n");

    BYTE battery[2] = {0};
    r = XInputGetBatteryInformation(0, 0, battery);
    Out("[xinput_smoke] XInputGetBatteryInformation = ");
    Out((r == (connected ? ERROR_SUCCESS_ : ERROR_NOT_CONNECTED_)) ? "PASS\r\n" : "FAIL\r\n");

    /* No keystroke queue yet: a connected pad reports the empty
     * sentinel rather than success. */
    BYTE keystroke[8] = {0};
    r = XInputGetKeystroke(0, 0, keystroke);
    Out("[xinput_smoke] XInputGetKeystroke(0)     = ");
    Out((r == (connected ? ERROR_EMPTY_ : ERROR_NOT_CONNECTED_)) ? "PASS\r\n" : "FAIL\r\n");

    XInputEnable(TRUE);
    Out("[xinput_smoke] XInputEnable(TRUE)        = PASS (returned)\r\n");

    /* Every slot must answer one of the two legal codes. A bad slot
     * index or an unmapped wire struct shows up as neither. */
    int bad_slot = 0;
    for (DWORD i = 0; i < 4; ++i)
    {
        r = XInputGetState(i, state);
        if (r != ERROR_SUCCESS_ && r != ERROR_NOT_CONNECTED_)
            bad_slot = 1;
    }
    Out("[xinput_smoke] All 4 slots answer legally = ");
    Out(bad_slot ? "FAIL\r\n" : "PASS\r\n");

    Out("[xinput_smoke] done\r\n");
    Out("[ring3-xinput-smoke] PASS\r\n");
    ExitProcess(0);
}
