/*
 * dwrite_smoke — exercise dwrite.dll DWriteFactory + format + layout.
 *   DWriteCreateFactory
 *   IDWriteFactory::CreateTextFormat
 *   IDWriteFactory::CreateTextLayout
 *   IDWriteTextFormat::GetFontSize
 */
#include <windows.h>

extern long DWriteCreateFactory(UINT type, const GUID* riid, void** out);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static const GUID kIidDw = {0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};

void __cdecl mainCRTStartup(void)
{
    Out("[dwrite_smoke] starting\r\n");

    void* factory = NULL;
    long hr = DWriteCreateFactory(0, &kIidDw, &factory);
    Out("[dwrite_smoke] DWriteCreateFactory  = ");
    Out((hr == 0 && factory) ? "PASS\r\n" : "FAIL\r\n");
    if (!factory)
        ExitProcess(1);

    void** f_vt = *(void***)factory;

    /* slot 15 = CreateTextFormat */
    void* fmt = NULL;
    typedef long (*PFN_CTF)(void*, const void*, void*, UINT, UINT, UINT, float, const void*, void**);
    static const WCHAR family[] = L"Segoe UI";
    static const WCHAR locale[] = L"en-us";
    hr = ((PFN_CTF)f_vt[15])(factory, family, NULL, 400, 0, 5, 14.0f, locale, &fmt);
    Out("[dwrite_smoke] CreateTextFormat     = ");
    Out((hr == 0 && fmt) ? "PASS\r\n" : "FAIL\r\n");

    if (fmt)
    {
        void** fmt_vt = *(void***)fmt;
        /* slot 18 = GetFontSize → returns float */
        typedef float (*PFN_GFS)(void*);
        float sz = ((PFN_GFS)fmt_vt[18])(fmt);
        Out("[dwrite_smoke] Format::GetFontSize  = ");
        Out((sz > 13.5f && sz < 14.5f) ? "PASS\r\n" : "FAIL\r\n");
    }

    /* slot 18 = CreateTextLayout */
    void* layout = NULL;
    typedef long (*PFN_CTL)(void*, const void*, UINT, void*, float, float, void**);
    static const WCHAR text[] = L"Hello DuetOS";
    hr = ((PFN_CTL)f_vt[18])(factory, text, 12, fmt, 200.0f, 50.0f, &layout);
    Out("[dwrite_smoke] CreateTextLayout     = ");
    Out((hr == 0 && layout) ? "PASS\r\n" : "FAIL\r\n");

    if (layout)
    {
        void** layout_vt = *(void***)layout;
        /* slot 60 = GetMetrics (canonical Win SDK position). */
        unsigned char tm[36] = {0};
        typedef long (*PFN_GM)(void*, void*);
        ((PFN_GM)layout_vt[60])(layout, tm);
        const float layout_w = *(const float*)(tm + 8);
        Out("[dwrite_smoke] Layout::GetMetrics  = ");
        Out((layout_w > 0.0f) ? "PASS (width>0)\r\n" : "FAIL\r\n");

        /* slot 64 = HitTestPoint. Probe four points across the text:
         *   (0, 0)        → first column, leading
         *   (cell_w*1.5)  → column 1, trailing half
         *   (large x)     → past the end, isInside=FALSE
         *   (negative y)  → above text, isInside=FALSE                */
        typedef long (*PFN_HTP)(void*, float, float, int*, int*, void*);
        const float fs = 14.0f;
        const float cell_w = fs * 0.6f;
        unsigned char htm[36] = {0};
        int trailing = 99, inside = 99;
        long hr2 = ((PFN_HTP)layout_vt[64])(layout, 0.0f, 0.0f, &trailing, &inside, htm);
        const UINT pos0 = *(const UINT*)(htm + 0);
        Out("[dwrite_smoke] Layout::HitTestPoint(0,0) = ");
        Out((hr2 == 0 && pos0 == 0u && trailing == 0 && inside == 1) ? "PASS\r\n" : "FAIL\r\n");

        trailing = 99;
        inside = 99;
        hr2 = ((PFN_HTP)layout_vt[64])(layout, cell_w * 1.5f, 5.0f, &trailing, &inside, htm);
        const UINT pos1 = *(const UINT*)(htm + 0);
        Out("[dwrite_smoke] Layout::HitTestPoint(1.5*cw,5) = ");
        Out((hr2 == 0 && pos1 == 1u && trailing == 1 && inside == 1) ? "PASS\r\n" : "FAIL\r\n");

        trailing = 99;
        inside = 99;
        hr2 = ((PFN_HTP)layout_vt[64])(layout, cell_w * 100.0f, 5.0f, &trailing, &inside, htm);
        Out("[dwrite_smoke] Layout::HitTestPoint(past-end) = ");
        Out((hr2 == 0 && inside == 0) ? "PASS\r\n" : "FAIL\r\n");
    }

    typedef unsigned long (*PFN_Rel)(void*);
    if (layout)
        ((PFN_Rel)((void**)(*(void***)layout))[2])(layout);
    if (fmt)
        ((PFN_Rel)((void**)(*(void***)fmt))[2])(fmt);
    ((PFN_Rel)f_vt[2])(factory);

    Out("[dwrite_smoke] done\r\n");
    ExitProcess(0);
}
