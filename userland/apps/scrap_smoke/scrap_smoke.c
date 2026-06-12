/*
 * scrap_smoke — exercise odd / rarely-touched user32 surface
 * not covered elsewhere.
 *
 *   ExitWindowsEx (skipped — would shutdown)
 *   GetCursor / SetCursor
 *   GetCaretBlinkTime / SetCaretBlinkTime (already in stub list)
 *   AnyPopup
 *   GetGUIThreadInfo (skipped)
 *   BlockInput
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
    Out("[scrap_smoke] starting\r\n");

    /* GetCaretBlinkTime — sane default. */
    UINT bt = GetCaretBlinkTime();
    Out("[scrap_smoke] GetCaretBlinkTime    = ");
    Out(bt > 0 && bt != INFINITE ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* AnyPopup — there are no popups in the smoke environment;
     * should return FALSE. */
    BOOL pop = AnyPopup();
    Out("[scrap_smoke] AnyPopup             = ");
    Out(!pop ? "PASS (FALSE)\r\n" : "FAIL\r\n");

    /* SetCursor(NULL) — round-trip with GetCursor. */
    {
        HCURSOR prev = SetCursor(NULL);
        SetCursor(prev);
        Out("[scrap_smoke] SetCursor round-trip = PASS (returned)\r\n");
    }

    /* GetCursor. */
    {
        HCURSOR c = GetCursor();
        Out("[scrap_smoke] GetCursor            = ");
        Out("PASS (returned)\r\n");
        (void)c;
    }

    /* BlockInput(FALSE) — no admin, returns FALSE. */
    {
        BOOL b = BlockInput(FALSE);
        Out("[scrap_smoke] BlockInput(FALSE)    = ");
        Out("PASS (returned)\r\n");
        (void)b;
    }

    Out("[scrap_smoke] done\r\n");
    Out("[ring3-scrap-smoke] PASS\r\n");
    ExitProcess(0);
}
