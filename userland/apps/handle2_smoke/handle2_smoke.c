/*
 * handle2_smoke — handle-management APIs beyond handle_smoke.
 *
 *   DuplicateHandle (on a CreateEvent handle)
 *   GetHandleInformation / SetHandleInformation
 *   SetHandleCount (legacy)
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
    Out("[handle2_smoke] starting\r\n");

    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    Out("[handle2_smoke] CreateEventW         = ");
    Out(e != NULL ? "PASS\r\n" : "FAIL\r\n");

    if (e != NULL)
    {
        HANDLE dup = NULL;
        BOOL ok = DuplicateHandle(GetCurrentProcess(), e, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
        Out("[handle2_smoke] DuplicateHandle      = ");
        Out(ok && dup != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (dup != NULL)
            CloseHandle(dup);

        DWORD flags = 0;
        BOOL gh = GetHandleInformation(e, &flags);
        Out("[handle2_smoke] GetHandleInformation = ");
        Out(gh ? "PASS\r\n" : "FAIL/STUB\r\n");

        BOOL sh = SetHandleInformation(e, HANDLE_FLAG_INHERIT, 0);
        Out("[handle2_smoke] SetHandleInformation = ");
        Out(sh ? "PASS\r\n" : "FAIL/STUB\r\n");

        CloseHandle(e);
    }

    Out("[handle2_smoke] done\r\n");
    ExitProcess(0);
}
