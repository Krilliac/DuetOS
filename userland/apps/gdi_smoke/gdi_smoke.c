/*
 * gdi_smoke — exercise GDI device-context / object surface.
 *
 * Probes the basic GDI surface every drawing app uses. We
 * don't actually paint pixels (no window) — just exercise the
 * object-creation / selection / deletion ABI:
 *   CreateCompatibleDC
 *   CreateCompatibleBitmap
 *   GetStockObject
 *   SelectObject
 *   DeleteObject
 *   GetDeviceCaps
 *   GetDC / ReleaseDC (on desktop window)
 *
 * Most of these are likely STUB today; the value is the boot
 * transcript showing exactly which return real handles vs. NULL.
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
    Out("[gdi_smoke] starting\r\n");

    /* GetDC(NULL) — desktop DC. */
    HDC hdc_screen = GetDC(NULL);
    Out("[gdi_smoke] GetDC(NULL)         = ");
    Out(hdc_screen != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* CreateCompatibleDC. */
    HDC mem_dc = CreateCompatibleDC(hdc_screen);
    Out("[gdi_smoke] CreateCompatibleDC  = ");
    Out(mem_dc != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* CreateCompatibleBitmap 32x32. */
    HBITMAP bmp = CreateCompatibleBitmap(hdc_screen, 32, 32);
    Out("[gdi_smoke] CreateCompatibleBitmap = ");
    Out(bmp != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* SelectObject. */
    if (mem_dc != NULL && bmp != NULL)
    {
        HBITMAP prev = (HBITMAP)SelectObject(mem_dc, bmp);
        Out("[gdi_smoke] SelectObject(bitmap)= ");
        Out(prev != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetStockObject. */
    {
        HBRUSH br = (HBRUSH)GetStockObject(WHITE_BRUSH);
        Out("[gdi_smoke] GetStockObject(WHITE_BRUSH) = ");
        Out(br != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* GetDeviceCaps. */
    if (hdc_screen != NULL)
    {
        int w = GetDeviceCaps(hdc_screen, HORZRES);
        int h = GetDeviceCaps(hdc_screen, VERTRES);
        Out("[gdi_smoke] GetDeviceCaps HORZRES/VERTRES = ");
        Out(w > 0 && h > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* DeleteObject + DeleteDC + ReleaseDC. */
    if (bmp != NULL)
    {
        BOOL d = DeleteObject(bmp);
        Out("[gdi_smoke] DeleteObject        = ");
        Out(d ? "PASS\r\n" : "FAIL\r\n");
    }
    if (mem_dc != NULL)
    {
        BOOL d = DeleteDC(mem_dc);
        Out("[gdi_smoke] DeleteDC            = ");
        Out(d ? "PASS\r\n" : "FAIL\r\n");
    }
    if (hdc_screen != NULL)
    {
        int r = ReleaseDC(NULL, hdc_screen);
        Out("[gdi_smoke] ReleaseDC           = ");
        Out(r != 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    Out("[gdi_smoke] done\r\n");
    ExitProcess(0);
}
