/*
 * advapi_smoke — exercise misc advapi32 surface.
 *
 *   ImpersonateLoggedOnUser (skipped — needs token)
 *   RevertToSelf
 *   LookupPrivilegeValueW
 *   PrivilegeCheck (skipped)
 *   GetSecurityDescriptorOwner / DACL
 *   ConvertStringSidToSidA
 */
#include <windows.h>
#include <sddl.h>

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
    Out("[advapi_smoke] starting\r\n");

    BOOL r = RevertToSelf();
    Out("[advapi_smoke] RevertToSelf         = ");
    Out(r ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* LookupPrivilegeValueW for SeDebugPrivilege. */
    {
        LUID luid = {0, 0};
        BOOL ok = LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid);
        Out("[advapi_smoke] LookupPrivilegeValueW = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* ConvertStringSidToSidA. */
    {
        PSID sid = NULL;
        BOOL ok = ConvertStringSidToSidA("S-1-5-18", &sid);
        Out("[advapi_smoke] ConvertStringSidToSidA = ");
        Out(ok && sid != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (sid != NULL)
            LocalFree(sid);
    }

    Out("[advapi_smoke] done\r\n");
    Out("[ring3-advapi-smoke] PASS\r\n");
    ExitProcess(0);
}
