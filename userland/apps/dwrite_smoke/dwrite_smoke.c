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

    typedef unsigned long (*PFN_Rel)(void*);
    if (layout)
        ((PFN_Rel)((void**)(*(void***)layout))[2])(layout);
    if (fmt)
        ((PFN_Rel)((void**)(*(void***)fmt))[2])(fmt);
    ((PFN_Rel)f_vt[2])(factory);

    Out("[dwrite_smoke] done\r\n");
    ExitProcess(0);
}
