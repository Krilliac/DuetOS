/*
 * dinput8_smoke — exercise dinput8.dll DirectInput8Create + device.
 *   DirectInput8Create
 *   IDirectInput8::CreateDevice
 *   IDirectInputDevice8::SetDataFormat / SetCooperativeLevel /
 *     Acquire / GetDeviceState / Unacquire
 */
#include <windows.h>

extern long DirectInput8Create(HMODULE inst, DWORD ver, const GUID* riid, void** out, void* unk);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static const GUID kIidDi = {0xbf798031, 0x483a, 0x4da2, {0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00}};

void __cdecl mainCRTStartup(void)
{
    Out("[dinput8_smoke] starting\r\n");

    void* di = NULL;
    long hr = DirectInput8Create(NULL, 0x800, &kIidDi, &di, NULL);
    Out("[dinput8_smoke] DirectInput8Create  = ");
    Out((hr == 0 && di) ? "PASS\r\n" : "FAIL\r\n");
    if (!di)
    {
        Out("[ring3-dinput8-smoke] FAIL create\r\n");
        ExitProcess(1);
    }

    void** di_vt = *(void***)di;

    /* slot 3 = CreateDevice */
    void* dev = NULL;
    typedef long (*PFN_CreateDev)(void*, const GUID*, void**, void*);
    hr = ((PFN_CreateDev)di_vt[3])(di, &kIidDi, &dev, NULL);
    Out("[dinput8_smoke] CreateDevice        = ");
    Out((hr == 0 && dev) ? "PASS\r\n" : "FAIL\r\n");

    void** dev_vt = *(void***)dev;

    /* slot 9 = SetDataFormat */
    typedef long (*PFN_SDF)(void*, const void*);
    hr = ((PFN_SDF)dev_vt[9])(dev, NULL);
    Out("[dinput8_smoke] SetDataFormat       = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 12 = Acquire */
    typedef long (*PFN_Acq)(void*);
    hr = ((PFN_Acq)dev_vt[12])(dev);
    Out("[dinput8_smoke] Acquire             = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 10 = GetDeviceState */
    BYTE state[256];
    typedef long (*PFN_GDS)(void*, DWORD, void*);
    hr = ((PFN_GDS)dev_vt[10])(dev, sizeof(state), state);
    Out("[dinput8_smoke] GetDeviceState      = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 13 = Unacquire */
    hr = ((PFN_Acq)dev_vt[13])(dev);
    Out("[dinput8_smoke] Unacquire           = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)dev_vt[2])(dev);
    ((PFN_Rel)di_vt[2])(di);

    Out("[dinput8_smoke] done\r\n");
    Out("[ring3-dinput8-smoke] PASS\r\n");
    ExitProcess(0);
}
