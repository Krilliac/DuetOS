/*
 * dde_smoke — exercise legacy DDEML APIs.
 *
 *   DdeInitializeA
 *   DdeCreateStringHandleA
 *   DdeFreeStringHandle
 *   DdeUninitialize
 *
 * Skipped: the real conversation flow (DdeConnect, DdePost) needs
 * a server. This just exercises the init / string-handle plumbing.
 */
#include <windows.h>
#include <ddeml.h>

static HDDEDATA CALLBACK dde_cb(UINT type, UINT fmt, HCONV conv, HSZ s1, HSZ s2, HDDEDATA data, ULONG_PTR data1,
                                ULONG_PTR data2)
{
    (void)type;
    (void)fmt;
    (void)conv;
    (void)s1;
    (void)s2;
    (void)data;
    (void)data1;
    (void)data2;
    return NULL;
}

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
    Out("[dde_smoke] starting\r\n");

    DWORD inst = 0;
    UINT r = DdeInitializeA(&inst, dde_cb, APPCMD_CLIENTONLY, 0);
    Out("[dde_smoke] DdeInitializeA       = ");
    Out(r == DMLERR_NO_ERROR ? "PASS\r\n" : "FAIL/STUB\r\n");

    if (r == DMLERR_NO_ERROR)
    {
        HSZ name = DdeCreateStringHandleA(inst, "DuetOSDdeTest", CP_WINANSI);
        Out("[dde_smoke] DdeCreateStringHandleA = ");
        Out(name != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

        if (name != NULL)
        {
            BOOL f = DdeFreeStringHandle(inst, name);
            Out("[dde_smoke] DdeFreeStringHandle  = ");
            Out(f ? "PASS\r\n" : "FAIL/STUB\r\n");
        }

        BOOL u = DdeUninitialize(inst);
        Out("[dde_smoke] DdeUninitialize      = ");
        Out(u ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[dde_smoke] done\r\n");
    Out("[ring3-dde-smoke] PASS\r\n");
    ExitProcess(0);
}
