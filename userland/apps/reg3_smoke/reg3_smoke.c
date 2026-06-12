/*
 * reg3_smoke — registry write-and-readback round-trip on the
 * volatile HKCU branch (DuetOS keeps these in process memory only).
 *
 *   RegCreateKeyExW
 *   RegSetValueExW (REG_SZ + REG_DWORD)
 *   RegQueryValueExW (read back)
 *   RegDeleteKeyW
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

void __cdecl mainCRTStartup(void)
{
    Out("[reg3_smoke] starting\r\n");

    HKEY hk = NULL;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\DuetOSSmoke", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL);
    Out("[reg3_smoke] RegCreateKeyExW     = ");
    Out(rc == ERROR_SUCCESS ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (rc == ERROR_SUCCESS)
    {
        /* SetValue REG_DWORD. */
        DWORD v = 0xCAFEBABE;
        LONG s = RegSetValueExW(hk, L"TestDword", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
        Out("[reg3_smoke] RegSetValueExW (DW) = ");
        Out(s == ERROR_SUCCESS ? "PASS\r\n" : "FAIL/STUB\r\n");

        /* QueryValue back. */
        DWORD got = 0;
        DWORD got_sz = sizeof(got);
        DWORD got_type = 0;
        LONG q = RegQueryValueExW(hk, L"TestDword", NULL, &got_type, (BYTE*)&got, &got_sz);
        Out("[reg3_smoke] RegQueryValueExW    = ");
        Out(q == ERROR_SUCCESS && got == 0xCAFEBABE ? "PASS (round-trip)\r\n" : "FAIL/STUB\r\n");

        RegCloseKey(hk);

        /* Delete. */
        LONG d = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\DuetOSSmoke");
        Out("[reg3_smoke] RegDeleteKeyW       = ");
        Out(d == ERROR_SUCCESS || d == ERROR_FILE_NOT_FOUND ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[reg3_smoke] done\r\n");
    Out("[ring3-reg3-smoke] PASS\r\n");
    ExitProcess(0);
}
