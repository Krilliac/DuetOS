/*
 * token_smoke — exercise advapi32 access-token APIs.
 *
 *   OpenProcessToken
 *   GetTokenInformation
 *   DuplicateTokenEx (skipped — heavy)
 *   GetUserNameA
 *   LookupAccountSidW (skipped)
 *   AdjustTokenPrivileges (skipped)
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
    Out("[token_smoke] starting\r\n");

    HANDLE token = NULL;
    BOOL ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    Out("[token_smoke] OpenProcessToken     = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (ok && token != NULL)
    {
        /* GetTokenInformation TokenUser. */
        char buf[256];
        DWORD got = 0;
        BOOL g = GetTokenInformation(token, TokenUser, buf, sizeof(buf), &got);
        Out("[token_smoke] GetTokenInformation = ");
        Out(g || got > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(token);
    }

    /* GetUserNameA. */
    {
        char buf[64] = {0};
        DWORD sz = 64;
        BOOL u = GetUserNameA(buf, &sz);
        Out("[token_smoke] GetUserNameA        = ");
        Out(u && sz > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[token_smoke] done\r\n");
    ExitProcess(0);
}
