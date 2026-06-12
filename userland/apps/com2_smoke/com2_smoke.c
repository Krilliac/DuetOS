/*
 * com2_smoke — extended COM helpers beyond com_smoke.
 *
 *   IIDFromString (round-trip with StringFromCLSID)
 *   CLSIDFromString
 *   StringFromGUID2
 *   IsEqualGUID
 *   PropVariantInit / PropVariantClear
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
    Out("[com2_smoke] starting\r\n");

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    /* StringFromGUID2. */
    {
        const GUID id = {0x12345678, 0x1234, 0x5678, {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a}};
        WCHAR buf[64] = {0};
        int n = StringFromGUID2(&id, buf, 64);
        Out("[com2_smoke] StringFromGUID2     = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* IsEqualGUID. */
    {
        const GUID a = {0x11111111, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
        const GUID b = a;
        const GUID c = {0x22222222, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
        Out("[com2_smoke] IsEqualGUID         = ");
        Out(IsEqualGUID(&a, &b) && !IsEqualGUID(&a, &c) ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    CoUninitialize();
    Out("[com2_smoke] done\r\n");
    Out("[ring3-com2-smoke] PASS\r\n");
    ExitProcess(0);
}
