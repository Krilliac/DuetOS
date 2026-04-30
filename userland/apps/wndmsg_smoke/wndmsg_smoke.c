/*
 * wndmsg_smoke — exercise SendMessage / wndproc lookup APIs.
 *
 *   SendMessageA / SendMessageW (to NULL → broadcast, returns 0)
 *   GetWindowThreadProcessId (skipped — needs HWND)
 *   GetSystemMenu (skipped)
 *   IsWindowVisible / IsWindowEnabled (probe NULL behavior)
 *   IsDialogMessage (skipped)
 *   GetParent on NULL
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
    Out("[wndmsg_smoke] starting\r\n");

    /* IsWindowVisible(NULL) — should return FALSE. */
    BOOL v = IsWindowVisible(NULL);
    Out("[wndmsg_smoke] IsWindowVisible(NULL)= ");
    Out(!v ? "PASS (FALSE, as expected)\r\n" : "FAIL\r\n");

    /* IsWindowEnabled(NULL) — should return FALSE. */
    BOOL e = IsWindowEnabled(NULL);
    Out("[wndmsg_smoke] IsWindowEnabled(NULL)= ");
    Out(!e ? "PASS (FALSE, as expected)\r\n" : "FAIL\r\n");

    /* GetParent(NULL) — should return NULL. */
    HWND p = GetParent(NULL);
    Out("[wndmsg_smoke] GetParent(NULL)      = ");
    Out(p == NULL ? "PASS (NULL)\r\n" : "FAIL\r\n");

    /* IsWindow(NULL) — FALSE. */
    BOOL iw = IsWindow(NULL);
    Out("[wndmsg_smoke] IsWindow(NULL)       = ");
    Out(!iw ? "PASS (FALSE)\r\n" : "FAIL\r\n");

    /* SendMessageA on NULL hwnd — broadcasts. Just verify it
     * doesn't trap. */
    LRESULT r = SendMessageA(NULL, WM_NULL, 0, 0);
    Out("[wndmsg_smoke] SendMessageA(NULL)   = ");
    Out("PASS (returned)\r\n");
    (void)r;

    /* GetSystemMenu(NULL,FALSE) — NULL or sentinel. */
    HMENU m = GetSystemMenu(NULL, FALSE);
    Out("[wndmsg_smoke] GetSystemMenu(NULL)  = ");
    Out("PASS (returned)\r\n");
    (void)m;

    Out("[wndmsg_smoke] done\r\n");
    ExitProcess(0);
}
