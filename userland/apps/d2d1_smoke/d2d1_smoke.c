/*
 * d2d1_smoke — exercise d2d1.dll D2D1Factory + HwndRenderTarget.
 *   D2D1CreateFactory
 *   ID2D1Factory::CreateHwndRenderTarget
 *   ID2D1HwndRenderTarget::CreateSolidColorBrush
 *   ID2D1HwndRenderTarget::BeginDraw / Clear / FillRectangle / EndDraw
 */
#include <windows.h>

extern long D2D1CreateFactory(UINT type, const GUID* riid, const void* options, void** out);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static const GUID kIidFactory = {0x06152247, 0x6f50, 0x465a, {0x92, 0x45, 0x11, 0x8b, 0xfd, 0x3b, 0x60, 0x07}};

void __cdecl mainCRTStartup(void)
{
    Out("[d2d1_smoke] starting\r\n");

    void* factory = NULL;
    long hr = D2D1CreateFactory(0 /*SINGLE_THREADED*/, &kIidFactory, NULL, &factory);
    Out("[d2d1_smoke] D2D1CreateFactory       = ");
    Out((hr == 0 && factory) ? "PASS\r\n" : "FAIL\r\n");
    if (!factory)
    {
        Out("[ring3-d2d1-smoke] FAIL createfactory\r\n");
        ExitProcess(1);
    }

    void** f_vt = *(void***)factory;

    /* D2D1_RENDER_TARGET_PROPERTIES (24B): Type(0,4) PixelFormat(4,8)
     * dpiX(12,4) dpiY(16,4) Usage(20,4) MinLevel(24,4). For NULL caller,
     * use a zero buffer. */
    BYTE rt_props[28];
    for (UINT i = 0; i < sizeof(rt_props); ++i)
        rt_props[i] = 0;

    /* D2D1_HWND_RENDER_TARGET_PROPERTIES: hwnd(0,8) width(8,4) height(12,4) presentOpts(16,4) */
    BYTE hwnd_props[24];
    for (UINT i = 0; i < sizeof(hwnd_props); ++i)
        hwnd_props[i] = 0;
    *(HWND*)(hwnd_props + 0) = NULL; /* offscreen */
    /* 32x32 BGRA8 = 4 KiB — fits in 64 KiB Win32 heap. */
    *(UINT*)(hwnd_props + 8) = 32;
    *(UINT*)(hwnd_props + 12) = 32;

    /* slot 14 = CreateHwndRenderTarget */
    void* rt = NULL;
    typedef long (*PFN_CRT)(void*, const void*, const void*, void**);
    hr = ((PFN_CRT)f_vt[14])(factory, rt_props, hwnd_props, &rt);
    Out("[d2d1_smoke] CreateHwndRenderTarget = ");
    Out((hr == 0 && rt) ? "PASS\r\n" : "FAIL\r\n");

    if (rt)
    {
        void** rt_vt = *(void***)rt;

        /* slot 8 = CreateSolidColorBrush(color, props, **out)
         * D2D1_COLOR_F = {r, g, b, a} = 16B */
        float color[4] = {1.0f, 0.0f, 1.0f, 1.0f}; /* magenta */
        void* brush = NULL;
        typedef long (*PFN_CSB)(void*, const void*, const void*, void**);
        hr = ((PFN_CSB)rt_vt[8])(rt, color, NULL, &brush);
        Out("[d2d1_smoke] CreateSolidColorBrush  = ");
        Out((hr == 0 && brush) ? "PASS\r\n" : "FAIL\r\n");

        /* slot 27 = BeginDraw */
        typedef void (*PFN_BD)(void*);
        ((PFN_BD)rt_vt[27])(rt);
        Out("[d2d1_smoke] BeginDraw              = PASS (returned)\r\n");

        /* slot 26 = Clear(color) */
        float bg[4] = {0.0f, 0.0f, 0.5f, 1.0f}; /* dark blue */
        typedef void (*PFN_Clr)(void*, const void*);
        ((PFN_Clr)rt_vt[26])(rt, bg);
        Out("[d2d1_smoke] Clear(dark blue)       = PASS (returned)\r\n");

        /* slot 17 = FillRectangle(rect, brush)  rect = 4x float */
        float rect[4] = {10.0f, 10.0f, 100.0f, 100.0f};
        typedef void (*PFN_FR)(void*, const void*, void*);
        ((PFN_FR)rt_vt[17])(rt, rect, brush);
        Out("[d2d1_smoke] FillRectangle          = PASS (returned)\r\n");

        /* slot 28 = EndDraw(tag1, tag2) */
        typedef long (*PFN_ED)(void*, void*, void*);
        hr = ((PFN_ED)rt_vt[28])(rt, NULL, NULL);
        Out("[d2d1_smoke] EndDraw                = ");
        Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

        if (brush)
        {
            typedef unsigned long (*PFN_Rel)(void*);
            ((PFN_Rel)((void**)(*(void***)brush))[2])(brush);
        }
        typedef unsigned long (*PFN_Rel2)(void*);
        ((PFN_Rel2)rt_vt[2])(rt);
    }

    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)f_vt[2])(factory);
    Out("[d2d1_smoke] done\r\n");
    Out("[ring3-d2d1-smoke] PASS\r\n");
    ExitProcess(0);
}
