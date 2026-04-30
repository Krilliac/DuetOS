/*
 * security_smoke — exercise security-descriptor / SID APIs.
 *
 *   InitializeSecurityDescriptor
 *   IsValidSecurityDescriptor
 *   AllocateAndInitializeSid
 *   IsValidSid
 *   FreeSid
 *   InitializeAcl
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
    Out("[security_smoke] starting\r\n");

    SECURITY_DESCRIPTOR sd = {0};
    BOOL ok = InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    Out("[security_smoke] InitializeSecurityDescriptor = ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    BOOL valid = IsValidSecurityDescriptor(&sd);
    Out("[security_smoke] IsValidSecurityDescriptor = ");
    Out(valid ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* AllocateAndInitializeSid + IsValidSid + FreeSid. */
    {
        SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
        PSID sid = NULL;
        BOOL a = AllocateAndInitializeSid(&auth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sid);
        Out("[security_smoke] AllocateAndInitializeSid = ");
        Out(a && sid != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (sid != NULL)
        {
            BOOL v = IsValidSid(sid);
            Out("[security_smoke] IsValidSid             = ");
            Out(v ? "PASS\r\n" : "FAIL/STUB\r\n");
            FreeSid(sid);
        }
    }

    /* InitializeAcl. */
    {
        unsigned char acl_buf[64] = {0};
        BOOL ok = InitializeAcl((PACL)acl_buf, sizeof(acl_buf), ACL_REVISION);
        Out("[security_smoke] InitializeAcl         = ");
        Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[security_smoke] done\r\n");
    ExitProcess(0);
}
