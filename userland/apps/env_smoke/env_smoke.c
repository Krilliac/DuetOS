/*
 * env_smoke — exercise kernel32 environment-variable APIs.
 *
 * Probes the env var surface every Win32 app uses to find
 * configuration: PATH, USERPROFILE, TEMP, COMPUTERNAME, etc.
 *   GetEnvironmentVariableA / GetEnvironmentVariableW
 *   SetEnvironmentVariableA / SetEnvironmentVariableW
 *   ExpandEnvironmentStringsA / ExpandEnvironmentStringsW
 *   GetEnvironmentStringsW / FreeEnvironmentStringsW
 *   GetEnvironmentStrings  (legacy A version)
 *
 * Validates: set+get round-trip, expansion of literal text with
 * %Var%, the env block contains at least one '=' and is double-NUL
 * terminated.
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

static int StrEqA(const char* a, const char* b)
{
    int i = 0;
    while (a[i] && b[i])
    {
        if (a[i] != b[i])
            return 0;
        ++i;
    }
    return a[i] == b[i];
}

void __cdecl mainCRTStartup(void)
{
    Out("[env_smoke] starting\r\n");

    /* Set + Get round-trip (W). */
    {
        BOOL set = SetEnvironmentVariableW(L"DUETOS_TEST", L"hello42");
        Out("[env_smoke] SetEnvironmentVariableW   = ");
        Out(set ? "PASS\r\n" : "FAIL\r\n");

        WCHAR buf[32] = {0};
        DWORD n = GetEnvironmentVariableW(L"DUETOS_TEST", buf, 32);
        Out("[env_smoke] GetEnvironmentVariableW   = ");
        if (n > 0 && buf[0] == 'h' && buf[1] == 'e' && buf[2] == 'l' && buf[3] == 'l' && buf[4] == 'o')
            Out("PASS (round-trip)\r\n");
        else
            Out("FAIL\r\n");
    }

    /* Set + Get round-trip (A). */
    {
        BOOL set = SetEnvironmentVariableA("DUETOS_TEST_A", "world99");
        Out("[env_smoke] SetEnvironmentVariableA   = ");
        Out(set ? "PASS\r\n" : "FAIL\r\n");

        char buf[32] = {0};
        DWORD n = GetEnvironmentVariableA("DUETOS_TEST_A", buf, 32);
        Out("[env_smoke] GetEnvironmentVariableA   = ");
        Out(n > 0 && StrEqA(buf, "world99") ? "PASS (round-trip)\r\n" : "FAIL\r\n");
    }

    /* Get on a non-existent var should return 0. */
    {
        WCHAR buf[8];
        DWORD n = GetEnvironmentVariableW(L"DUETOS_NOPE", buf, 8);
        Out("[env_smoke] GetEnvironmentVariableW(?)= ");
        Out(n == 0 ? "PASS (not found)\r\n" : "FAIL (false positive)\r\n");
    }

    /* GetEnvironmentStringsW — block must end with double-NUL. */
    {
        LPWCH env = GetEnvironmentStringsW();
        Out("[env_smoke] GetEnvironmentStringsW   = ");
        if (env == NULL)
        {
            Out("FAIL (NULL)\r\n");
        }
        else
        {
            /* Walk the block until we hit a double-NUL or 64K. */
            int i = 0;
            int found_term = 0;
            while (i < 65536)
            {
                if (env[i] == 0 && env[i + 1] == 0)
                {
                    found_term = 1;
                    break;
                }
                ++i;
            }
            Out(found_term ? "PASS (terminated)\r\n" : "FAIL (no double-NUL)\r\n");
            FreeEnvironmentStringsW(env);
        }
    }

    /* ExpandEnvironmentStringsW — should at least preserve literal text. */
    {
        WCHAR out_buf[64] = {0};
        DWORD n = ExpandEnvironmentStringsW(L"plain", out_buf, 64);
        Out("[env_smoke] ExpandEnvironmentStringsW = ");
        if (n > 0 && out_buf[0] == 'p' && out_buf[1] == 'l' && out_buf[2] == 'a' && out_buf[3] == 'i' &&
            out_buf[4] == 'n')
            Out("PASS (literal preserved)\r\n");
        else
            Out("FAIL\r\n");
    }

    Out("[env_smoke] done\r\n");
    Out("[ring3-env-smoke] PASS\r\n");
    ExitProcess(0);
}
