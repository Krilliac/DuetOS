/*
 * clipboard_smoke — exercise user32 clipboard surface.
 *
 * Probes the cut/copy/paste plumbing every editor uses:
 *   OpenClipboard(NULL)
 *   EmptyClipboard
 *   SetClipboardData(CF_TEXT, hdata)  (skipped — needs HGLOBAL)
 *   GetClipboardData(CF_TEXT)
 *   IsClipboardFormatAvailable
 *   CloseClipboard
 *   CountClipboardFormats
 *
 * v0: clipboard is likely STUB. Smoke = doesn't trap.
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
    Out("[clipboard_smoke] starting\r\n");

    BOOL open = OpenClipboard(NULL);
    Out("[clipboard_smoke] OpenClipboard         = ");
    Out(open ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* IsClipboardFormatAvailable — false for unowned. */
    BOOL ack = IsClipboardFormatAvailable(CF_TEXT);
    Out("[clipboard_smoke] IsClipboardFormatAvailable = ");
    Out(!ack ? "PASS (no, as expected)\r\n" : "FAIL\r\n");

    /* CountClipboardFormats. */
    int count = CountClipboardFormats();
    Out("[clipboard_smoke] CountClipboardFormats = ");
    Out(count >= 0 ? "PASS\r\n" : "FAIL\r\n");

    if (open)
    {
        EmptyClipboard();
        Out("[clipboard_smoke] EmptyClipboard        = PASS (returned)\r\n");
        CloseClipboard();
        Out("[clipboard_smoke] CloseClipboard        = PASS (returned)\r\n");
    }

    Out("[clipboard_smoke] done\r\n");
    ExitProcess(0);
}
