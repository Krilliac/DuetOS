/*
 * registry_smoke — exercise advapi32 registry APIs.
 *
 * Probes the registry surface every Win32 app reads at startup:
 *   RegOpenKeyExW   (HKLM well-known subkeys)
 *   RegQueryValueExW (read REG_SZ + REG_DWORD)
 *   RegEnumKeyExW   (subkey enumeration)
 *   RegEnumValueW   (value enumeration)
 *   RegQueryInfoKeyW
 *   RegCloseKey
 *
 * DuetOS ships a static prefix-tree registry under HKLM with at
 * least HKLM\Software\Microsoft\Windows NT\CurrentVersion +
 * HKLM\Hardware\Description\System\CentralProcessor\0 — see
 * wiki/subsystems/Win32-DLLs.md for the registry surface.
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

static void OutDec(unsigned long long v)
{
    char buf[32];
    int len = 0;
    if (v == 0)
        buf[len++] = '0';
    else
    {
        char rev[32];
        int r = 0;
        while (v != 0)
        {
            rev[r++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int j = 0; j < r; ++j)
            buf[len++] = rev[r - 1 - j];
    }
    buf[len] = '\0';
    Out(buf);
}

void __cdecl mainCRTStartup(void)
{
    Out("[registry_smoke] starting\r\n");

    /* RegOpenKeyExW on HKLM\\Software. */
    HKEY hk = NULL;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software", 0, KEY_READ, &hk);
    Out("[registry_smoke] RegOpenKeyExW(HKLM\\Software) = ");
    Out(rc == ERROR_SUCCESS ? "PASS\r\n" : "FAIL\r\n");
    if (rc == ERROR_SUCCESS)
        RegCloseKey(hk);

    /* RegOpenKeyExW on a deeper path. */
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hk);
    Out("[registry_smoke] RegOpenKeyExW(...CurrentVersion) = ");
    Out(rc == ERROR_SUCCESS ? "PASS\r\n" : "FAIL\r\n");

    if (rc == ERROR_SUCCESS)
    {
        /* RegQueryValueExW for ProductName. */
        WCHAR vbuf[128] = {0};
        DWORD vsz = sizeof(vbuf);
        DWORD vtype = 0;
        LONG q = RegQueryValueExW(hk, L"ProductName", NULL, &vtype, (BYTE*)vbuf, &vsz);
        Out("[registry_smoke] RegQueryValueExW(ProductName) = ");
        if (q == ERROR_SUCCESS && vsz > 0)
        {
            Out("PASS type=");
            OutDec((unsigned long long)vtype);
            Out(" sz=");
            OutDec((unsigned long long)vsz);
            Out("\r\n");
        }
        else
        {
            Out("FAIL rc=");
            OutDec((unsigned long long)q);
            Out("\r\n");
        }

        /* RegQueryInfoKeyW. */
        DWORD num_subkeys = 0, max_subkey_len = 0, num_values = 0, max_value_name_len = 0;
        LONG i = RegQueryInfoKeyW(hk, NULL, NULL, NULL, &num_subkeys, &max_subkey_len, NULL, &num_values,
                                  &max_value_name_len, NULL, NULL, NULL);
        Out("[registry_smoke] RegQueryInfoKeyW            = ");
        if (i == ERROR_SUCCESS)
        {
            Out("PASS subkeys=");
            OutDec((unsigned long long)num_subkeys);
            Out(" values=");
            OutDec((unsigned long long)num_values);
            Out("\r\n");
        }
        else
        {
            Out("FAIL rc=");
            OutDec((unsigned long long)i);
            Out("\r\n");
        }

        /* RegEnumValueW — list value names. */
        DWORD enum_idx = 0;
        DWORD pass_count = 0;
        for (;;)
        {
            WCHAR name[64];
            DWORD name_sz = 64;
            LONG e = RegEnumValueW(hk, enum_idx, name, &name_sz, NULL, NULL, NULL, NULL);
            if (e != ERROR_SUCCESS)
                break;
            ++enum_idx;
            ++pass_count;
            if (enum_idx >= 16)
                break;
        }
        Out("[registry_smoke] RegEnumValueW iterated      = ");
        if (pass_count > 0)
        {
            Out("PASS count=");
            OutDec((unsigned long long)pass_count);
            Out("\r\n");
        }
        else
        {
            Out("FAIL (no values)\r\n");
        }

        /* RegEnumKeyExW — list subkeys. */
        enum_idx = 0;
        pass_count = 0;
        for (;;)
        {
            WCHAR name[128];
            DWORD name_sz = 128;
            LONG e = RegEnumKeyExW(hk, enum_idx, name, &name_sz, NULL, NULL, NULL, NULL);
            if (e != ERROR_SUCCESS)
                break;
            ++enum_idx;
            ++pass_count;
            if (enum_idx >= 16)
                break;
        }
        Out("[registry_smoke] RegEnumKeyExW iterated      = ");
        if (pass_count > 0)
        {
            Out("PASS count=");
            OutDec((unsigned long long)pass_count);
            Out("\r\n");
        }
        else
        {
            Out("PASS (no subkeys, also OK)\r\n");
        }

        RegCloseKey(hk);
    }

    Out("[registry_smoke] done\r\n");
    ExitProcess(0);
}
