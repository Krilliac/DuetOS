/*
 * userland/libs/gdi32_32/gdi32_32.c
 *
 * Freestanding DuetOS gdi32.dll (i386 / PE32 variant). v0 contains
 * safe-ignore stubs for the most-imported gdi32 exports.
 */

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int INT;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HDC;
typedef HANDLE HGDIOBJ;
typedef HANDLE HBITMAP;
typedef HANDLE HBRUSH;
typedef HANDLE HFONT;
typedef HANDLE HPEN;
typedef HANDLE HRGN;
typedef HANDLE HPALETTE;
typedef unsigned long COLORREF;
typedef unsigned short wchar_t16;

/* GDI object stubs — return non-null sentinel handles so caller
 * doesn't trip its NULL-on-fail path. */
__declspec(dllexport) HBITMAP __stdcall CreateBitmap(int w, int h, UINT planes, UINT bpp, const void* bits)
{
    (void)w;
    (void)h;
    (void)planes;
    (void)bpp;
    (void)bits;
    return (HBITMAP)0x10001;
}

__declspec(dllexport) HBITMAP __stdcall CreateCompatibleBitmap(HDC dc, int w, int h)
{
    (void)dc;
    (void)w;
    (void)h;
    return (HBITMAP)0x10002;
}

__declspec(dllexport) HDC __stdcall CreateCompatibleDC(HDC dc)
{
    (void)dc;
    return (HDC)0x10003;
}

__declspec(dllexport) BOOL __stdcall DeleteDC(HDC dc)
{
    (void)dc;
    return 1;
}

__declspec(dllexport) BOOL __stdcall DeleteObject(HGDIOBJ h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ obj)
{
    (void)dc;
    (void)obj;
    return (HGDIOBJ)0;
}

__declspec(dllexport) HGDIOBJ __stdcall GetStockObject(int idx)
{
    (void)idx;
    return (HGDIOBJ)0x10004;
}

/* Pen / Brush / Font creation. All return non-null sentinels. */
__declspec(dllexport) HPEN __stdcall CreatePen(int style, int w, COLORREF col)
{
    (void)style;
    (void)w;
    (void)col;
    return (HPEN)0x10005;
}

__declspec(dllexport) HBRUSH __stdcall CreateSolidBrush(COLORREF col)
{
    (void)col;
    return (HBRUSH)0x10006;
}

__declspec(dllexport) HBRUSH __stdcall CreateBrushIndirect(const void* lb)
{
    (void)lb;
    return (HBRUSH)0x10007;
}

__declspec(dllexport) HFONT __stdcall CreateFontA(int h, int w, int e, int o, int wt, DWORD i, DWORD u, DWORD s,
                                                  DWORD ch, DWORD op, DWORD cl, DWORD q, DWORD p, const char* face)
{
    (void)h;
    (void)w;
    (void)e;
    (void)o;
    (void)wt;
    (void)i;
    (void)u;
    (void)s;
    (void)ch;
    (void)op;
    (void)cl;
    (void)q;
    (void)p;
    (void)face;
    return (HFONT)0x10008;
}

__declspec(dllexport) HFONT __stdcall CreateFontW(int h, int w, int e, int o, int wt, DWORD i, DWORD u, DWORD s,
                                                  DWORD ch, DWORD op, DWORD cl, DWORD q, DWORD p, const wchar_t16* face)
{
    (void)face;
    return CreateFontA(h, w, e, o, wt, i, u, s, ch, op, cl, q, p, (const char*)0);
}

__declspec(dllexport) HFONT __stdcall CreateFontIndirectA(const void* lf)
{
    (void)lf;
    return (HFONT)0x10009;
}

__declspec(dllexport) HFONT __stdcall CreateFontIndirectW(const void* lf)
{
    (void)lf;
    return (HFONT)0x1000A;
}

/* Drawing primitives. v0 no-ops. */
__declspec(dllexport) BOOL __stdcall BitBlt(HDC dst, int x, int y, int w, int h, HDC src, int sx, int sy, DWORD rop)
{
    (void)dst;
    (void)x;
    (void)y;
    (void)w;
    (void)h;
    (void)src;
    (void)sx;
    (void)sy;
    (void)rop;
    return 1;
}

__declspec(dllexport) BOOL __stdcall StretchBlt(HDC dst, int x, int y, int w, int h, HDC src, int sx, int sy, int sw,
                                                int sh, DWORD rop)
{
    (void)dst;
    (void)x;
    (void)y;
    (void)w;
    (void)h;
    (void)src;
    (void)sx;
    (void)sy;
    (void)sw;
    (void)sh;
    (void)rop;
    return 1;
}

__declspec(dllexport) BOOL __stdcall MoveToEx(HDC dc, int x, int y, void* lpPoint)
{
    (void)dc;
    (void)x;
    (void)y;
    (void)lpPoint;
    return 1;
}

__declspec(dllexport) BOOL __stdcall LineTo(HDC dc, int x, int y)
{
    (void)dc;
    (void)x;
    (void)y;
    return 1;
}

__declspec(dllexport) BOOL __stdcall Rectangle(HDC dc, int l, int t, int r, int b)
{
    (void)dc;
    (void)l;
    (void)t;
    (void)r;
    (void)b;
    return 1;
}

__declspec(dllexport) BOOL __stdcall Ellipse(HDC dc, int l, int t, int r, int b)
{
    (void)dc;
    (void)l;
    (void)t;
    (void)r;
    (void)b;
    return 1;
}

__declspec(dllexport) BOOL __stdcall Polygon(HDC dc, const void* lpPoints, int cnt)
{
    (void)dc;
    (void)lpPoints;
    (void)cnt;
    return 1;
}

__declspec(dllexport) BOOL __stdcall Polyline(HDC dc, const void* lpPoints, int cnt)
{
    (void)dc;
    (void)lpPoints;
    (void)cnt;
    return 1;
}

__declspec(dllexport) BOOL __stdcall Arc(HDC dc, int a, int b, int c, int d, int e, int f, int g, int h)
{
    (void)dc;
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    (void)g;
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL __stdcall TextOutA(HDC dc, int x, int y, const char* s, int n)
{
    (void)dc;
    (void)x;
    (void)y;
    (void)s;
    (void)n;
    return 1;
}

__declspec(dllexport) BOOL __stdcall TextOutW(HDC dc, int x, int y, const wchar_t16* s, int n)
{
    (void)dc;
    (void)x;
    (void)y;
    (void)s;
    (void)n;
    return 1;
}

__declspec(dllexport) int __stdcall DrawTextA(HDC dc, const char* s, int n, void* rect, UINT fmt)
{
    (void)dc;
    (void)s;
    (void)n;
    (void)rect;
    (void)fmt;
    return 0;
}

__declspec(dllexport) int __stdcall DrawTextW(HDC dc, const wchar_t16* s, int n, void* rect, UINT fmt)
{
    return DrawTextA(dc, (const char*)0, n, rect, fmt);
}

__declspec(dllexport) COLORREF __stdcall SetPixel(HDC dc, int x, int y, COLORREF col)
{
    (void)dc;
    (void)x;
    (void)y;
    (void)col;
    return 0;
}

__declspec(dllexport) COLORREF __stdcall GetPixel(HDC dc, int x, int y)
{
    (void)dc;
    (void)x;
    (void)y;
    return 0;
}

__declspec(dllexport) int __stdcall FillRect(HDC dc, const void* lprc, HBRUSH br)
{
    (void)dc;
    (void)lprc;
    (void)br;
    return 1;
}

__declspec(dllexport) int __stdcall FrameRect(HDC dc, const void* lprc, HBRUSH br)
{
    return FillRect(dc, lprc, br);
}

/* GDI state stubs. */
__declspec(dllexport) COLORREF __stdcall SetBkColor(HDC dc, COLORREF c)
{
    (void)dc;
    (void)c;
    return 0;
}

__declspec(dllexport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF c)
{
    (void)dc;
    (void)c;
    return 0;
}

__declspec(dllexport) int __stdcall SetBkMode(HDC dc, int mode)
{
    (void)dc;
    (void)mode;
    return 0;
}

__declspec(dllexport) UINT __stdcall SetTextAlign(HDC dc, UINT mode)
{
    (void)dc;
    (void)mode;
    return 0;
}

__declspec(dllexport) int __stdcall SetMapMode(HDC dc, int mode)
{
    (void)dc;
    (void)mode;
    return 0;
}

__declspec(dllexport) int __stdcall GetDeviceCaps(HDC dc, int idx)
{
    (void)dc;
    (void)idx;
    return 0;
}

__declspec(dllexport) int __stdcall GetObjectA(HGDIOBJ h, int cb, void* lpv)
{
    (void)h;
    (void)cb;
    (void)lpv;
    return 0;
}

__declspec(dllexport) int __stdcall GetObjectW(HGDIOBJ h, int cb, void* lpv)
{
    return GetObjectA(h, cb, lpv);
}

__declspec(dllexport) HBITMAP __stdcall CreateDIBSection(HDC dc, const void* bmi, UINT usage, void** ppvBits,
                                                         HANDLE hSection, DWORD off)
{
    (void)dc;
    (void)bmi;
    (void)usage;
    (void)hSection;
    (void)off;
    if (ppvBits)
        *ppvBits = (void*)0;
    return 0;
}

__declspec(dllexport) HBITMAP __stdcall CreateDIBitmap(HDC dc, const void* hdr, DWORD init, const void* bits,
                                                       const void* bmi, UINT usage)
{
    (void)dc;
    (void)hdr;
    (void)init;
    (void)bits;
    (void)bmi;
    (void)usage;
    return 0;
}

__declspec(dllexport) int __stdcall GetDIBits(HDC dc, HBITMAP bmp, UINT start, UINT scans, void* bits, void* bi,
                                              UINT usage)
{
    (void)dc;
    (void)bmp;
    (void)start;
    (void)scans;
    (void)bits;
    (void)bi;
    (void)usage;
    return 0;
}

__declspec(dllexport) HPEN __stdcall ExtCreatePen(DWORD style, DWORD w, const void* lb, DWORD style_cnt,
                                                  const DWORD* style_array)
{
    (void)style;
    (void)w;
    (void)lb;
    (void)style_cnt;
    (void)style_array;
    return (HPEN)0x1000B;
}

__declspec(dllexport) HRGN __stdcall CreateRectRgnIndirect(const void* lprc)
{
    (void)lprc;
    return (HRGN)0x1000C;
}

/* DC save / restore. */
__declspec(dllexport) int __stdcall SaveDC(HDC dc)
{
    (void)dc;
    return 1;
}

__declspec(dllexport) BOOL __stdcall RestoreDC(HDC dc, int n)
{
    (void)dc;
    (void)n;
    return 1;
}
