/*
 * gdiplus_smoke — exercise GDI+ startup / shutdown.
 *
 *   GdiplusStartup
 *   GdiplusShutdown
 *
 * v0: GDI+ is not available; expect FAIL/STUB. Smoke value =
 * "doesn't trap when image-loading code initialises GDI+".
 */
#include <windows.h>

/* Manually declare GdiplusStartup / Shutdown — GdiPlus.h is C++. */
typedef ULONG_PTR ULONG_PTR;
typedef int Status;
typedef struct
{
    UINT32 GdiplusVersion;
    void* DebugEventCallback;
    BOOL SuppressBackgroundThread;
    BOOL SuppressExternalCodecs;
} GdiplusStartupInput;

extern Status __stdcall GdiplusStartup(ULONG_PTR* token, const GdiplusStartupInput* in, void* out);
extern void __stdcall GdiplusShutdown(ULONG_PTR token);

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
    Out("[gdiplus_smoke] starting\r\n");

    GdiplusStartupInput input = {1, NULL, FALSE, FALSE};
    ULONG_PTR token = 0;
    Status s = GdiplusStartup(&token, &input, NULL);
    Out("[gdiplus_smoke] GdiplusStartup       = ");
    Out("PASS (returned)\r\n");
    (void)s;

    if (token != 0)
    {
        GdiplusShutdown(token);
        Out("[gdiplus_smoke] GdiplusShutdown      = PASS (returned)\r\n");
    }

    Out("[gdiplus_smoke] done\r\n");
    ExitProcess(0);
}
