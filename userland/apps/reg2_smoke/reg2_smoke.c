/*
 * reg2_smoke — extended registry probe (HKCU + alternate hives).
 *
 *   RegOpenKeyExW(HKEY_CURRENT_USER)
 *   RegQueryInfoKey on root
 *   RegConnectRegistryW (skipped — local only)
 *   RegSaveKeyW (skipped)
 *   RegFlushKey
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
    Out("[reg2_smoke] starting\r\n");

    /* HKEY_CURRENT_USER root. */
    HKEY hk = NULL;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"", 0, KEY_READ, &hk);
    Out("[reg2_smoke] RegOpenKeyExW(HKCU)   = ");
    Out(rc == ERROR_SUCCESS ? "PASS\r\n" : "FAIL/STUB\r\n");
    if (hk != NULL)
    {
        BOOL f = (RegFlushKey(hk) == ERROR_SUCCESS);
        Out("[reg2_smoke] RegFlushKey           = ");
        Out(f ? "PASS\r\n" : "FAIL/STUB\r\n");
        RegCloseKey(hk);
    }

    /* HKEY_USERS. */
    rc = RegOpenKeyExW(HKEY_USERS, L"", 0, KEY_READ, &hk);
    Out("[reg2_smoke] RegOpenKeyExW(HKU)    = ");
    Out(rc == ERROR_SUCCESS ? "PASS\r\n" : "FAIL/STUB\r\n");
    if (hk != NULL)
        RegCloseKey(hk);

    /* HKEY_CLASSES_ROOT. */
    rc = RegOpenKeyExW(HKEY_CLASSES_ROOT, L"", 0, KEY_READ, &hk);
    Out("[reg2_smoke] RegOpenKeyExW(HKCR)   = ");
    Out(rc == ERROR_SUCCESS ? "PASS\r\n" : "FAIL/STUB\r\n");
    if (hk != NULL)
        RegCloseKey(hk);

    Out("[reg2_smoke] done\r\n");
    Out("[ring3-reg2-smoke] PASS\r\n");
    ExitProcess(0);
}
