/*
 * cap_smoke — capability / token-info APIs.
 *
 *   GetCurrentProcessToken (pseudo-handle)
 *   PrivilegeCheck (skipped — needs LUID)
 *   CheckTokenMembership (skipped)
 *   ImpersonateSelf
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
    Out("[cap_smoke] starting\r\n");

    BOOL ok = ImpersonateSelf(SecurityImpersonation);
    Out("[cap_smoke] ImpersonateSelf      = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    BOOL r = RevertToSelf();
    Out("[cap_smoke] RevertToSelf         = ");
    Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[cap_smoke] done\r\n");
    ExitProcess(0);
}
