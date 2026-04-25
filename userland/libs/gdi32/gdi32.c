/*
 * userland/libs/gdi32/gdi32.c — 44 GDI stubs, with FillRect +
 * TextOutA/W + Rectangle + ExtTextOutA/W bridged to the kernel
 * compositor's per-window display list via SYS_GDI_* (65..68).
 *
 * GetDC(hWnd) collapses the HWND into the HDC slot so later GDI
 * calls recover the window handle directly — we don't yet have a
 * DC table, a DC doesn't select into a bitmap, and CreateCompatibleDC
 * returns a sentinel that paints into nothing. The common idiom
 * `HDC hdc = GetDC(hwnd); FillRect(hdc, ...); ReleaseDC(hwnd, hdc);`
 * therefore works even without a real device context.
 *
 * COLORREF on the Win32 side is 0x00BBGGRR; the kernel repacks to
 * 0x00RRGGBB before framebuffer writes, so we pass the user's value
 * through verbatim.
 */

typedef int BOOL;
typedef unsigned int UINT;
typedef int INT;
typedef unsigned int DWORD;
typedef unsigned int COLORREF;
typedef void* HDC;
typedef void* HGDIOBJ;
typedef void* HBITMAP;
typedef void* HBRUSH;
typedef void* HFONT;
typedef void* HPEN;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

typedef struct
{
    INT left, top, right, bottom;
} RECT;

#define SYS_GDI_FILL_RECT 65
#define SYS_GDI_TEXT_OUT 66
#define SYS_GDI_RECTANGLE 67
#define SYS_GDI_CLEAR 68
#define SYS_GDI_SET_TEXT_COLOR 114
#define SYS_GDI_SET_BK_COLOR 115
#define SYS_GDI_SET_BK_MODE 116
#define SYS_GDI_LINE 74
#define SYS_GDI_ELLIPSE 75
#define SYS_GDI_SET_PIXEL 76
#define SYS_GDI_DRAW_TEXT_W 126

/* Encode the HWND inside the HDC pointer so later GDI calls can
 * recover it. Bit layout: HDC == (HWND | GDI_TAG). GDI_TAG keeps
 * the pointer obviously-non-null (Win32 callers null-check HDCs)
 * and distinguishable from a real memory address. */
#define GDI_TAG 0xDC00000000ULL

static HDC gdi32_hdc_from_hwnd(HANDLE hWnd)
{
    return (HDC)((unsigned long long)hWnd | GDI_TAG);
}

static HANDLE gdi32_hwnd_from_hdc(HDC dc)
{
    unsigned long long v = (unsigned long long)dc;
    if ((v & GDI_TAG) != GDI_TAG)
        return (HANDLE)0;
    return (HANDLE)(v & ~GDI_TAG);
}

/* --- DC management --- */
__declspec(dllexport) HDC GetDC(HANDLE hWnd)
{
    return gdi32_hdc_from_hwnd(hWnd);
}
__declspec(dllexport) HDC GetWindowDC(HANDLE hWnd)
{
    return gdi32_hdc_from_hwnd(hWnd);
}
__declspec(dllexport) INT ReleaseDC(HANDLE hWnd, HDC dc)
{
    (void)hWnd;
    (void)dc;
    return 1;
}
/* CreateCompatibleDC has no HWND — stays a no-op sentinel; any
 * draw routed through it is silently dropped (the HWND recovered
 * from the sentinel is 0, which the kernel rejects). */
__declspec(dllexport) HDC CreateCompatibleDC(HDC dc)
{
    (void)dc;
    return (HDC)GDI_TAG;
}
__declspec(dllexport) BOOL DeleteDC(HDC dc)
{
    (void)dc;
    return 1;
}
__declspec(dllexport) INT SaveDC(HDC dc)
{
    (void)dc;
    return 1;
}
__declspec(dllexport) BOOL RestoreDC(HDC dc, INT saved)
{
    (void)dc;
    (void)saved;
    return 1;
}

/* --- Object creation --- */
/* Brushes in v0 carry the colour in the bottom 24 bits; the stub
 * sets the top bit to distinguish "real brush" from NULL. */
__declspec(dllexport) HBITMAP CreateBitmap(INT w, INT h, UINT planes, UINT bits_per_pel, const void* bits)
{
    (void)w;
    (void)h;
    (void)planes;
    (void)bits_per_pel;
    (void)bits;
    return (HBITMAP)0;
}
__declspec(dllexport) HBITMAP CreateCompatibleBitmap(HDC dc, INT w, INT h)
{
    (void)dc;
    (void)w;
    (void)h;
    return (HBITMAP)0;
}
__declspec(dllexport) HBITMAP CreateDIBSection(HDC dc, const void* bi, UINT usage, void** bits, HANDLE section,
                                               DWORD offset)
{
    (void)dc;
    (void)bi;
    (void)usage;
    (void)section;
    (void)offset;
    if (bits)
        *bits = (void*)0;
    return (HBITMAP)0;
}
__declspec(dllexport) HBITMAP CreateDIBitmap(HDC dc, const void* header, DWORD init, const void* bits, const void* bi,
                                             UINT usage)
{
    (void)dc;
    (void)header;
    (void)init;
    (void)bits;
    (void)bi;
    (void)usage;
    return (HBITMAP)0;
}
__declspec(dllexport) HBRUSH CreateBrushIndirect(const void* lb)
{
    if (!lb)
        return (HBRUSH)0;
    /* LOGBRUSH = { UINT style; COLORREF color; ULONG_PTR hatch; } */
    const unsigned* b = (const unsigned*)lb;
    unsigned long long tag = 0xB0000000ULL | (unsigned long long)b[1];
    return (HBRUSH)tag;
}
__declspec(dllexport) HBRUSH CreateSolidBrush(COLORREF clr)
{
    unsigned long long tag = 0xB0000000ULL | (unsigned long long)clr;
    return (HBRUSH)tag;
}
__declspec(dllexport) HPEN CreatePen(INT style, INT width, COLORREF clr)
{
    (void)style;
    (void)width;
    (void)clr;
    return (HPEN)0;
}
__declspec(dllexport) HFONT CreateFontA(INT h, INT w, INT esc, INT orient, INT weight, DWORD italic, DWORD underline,
                                        DWORD strikeout, DWORD charset, DWORD out_prec, DWORD clip_prec, DWORD quality,
                                        DWORD pitch, const char* face)
{
    (void)h;
    (void)w;
    (void)esc;
    (void)orient;
    (void)weight;
    (void)italic;
    (void)underline;
    (void)strikeout;
    (void)charset;
    (void)out_prec;
    (void)clip_prec;
    (void)quality;
    (void)pitch;
    (void)face;
    return (HFONT)0;
}
__declspec(dllexport) HFONT CreateFontW(INT h, INT w, INT esc, INT orient, INT weight, DWORD italic, DWORD underline,
                                        DWORD strikeout, DWORD charset, DWORD out_prec, DWORD clip_prec, DWORD quality,
                                        DWORD pitch, const wchar_t16* face)
{
    (void)h;
    (void)w;
    (void)esc;
    (void)orient;
    (void)weight;
    (void)italic;
    (void)underline;
    (void)strikeout;
    (void)charset;
    (void)out_prec;
    (void)clip_prec;
    (void)quality;
    (void)pitch;
    (void)face;
    return (HFONT)0;
}
__declspec(dllexport) HFONT CreateFontIndirectA(const void* lf)
{
    (void)lf;
    return (HFONT)0;
}
__declspec(dllexport) HFONT CreateFontIndirectW(const void* lf)
{
    (void)lf;
    return (HFONT)0;
}

__declspec(dllexport) HGDIOBJ GetStockObject(INT idx)
{
    (void)idx;
    return (HGDIOBJ)0;
}
__declspec(dllexport) HGDIOBJ SelectObject(HDC dc, HGDIOBJ obj)
{
    (void)dc;
    (void)obj;
    return (HGDIOBJ)0;
}
__declspec(dllexport) BOOL DeleteObject(HGDIOBJ obj)
{
    (void)obj;
    return 1;
}
__declspec(dllexport) INT GetObjectA(HGDIOBJ obj, INT cb, void* buf)
{
    (void)obj;
    (void)cb;
    (void)buf;
    return 0;
}
__declspec(dllexport) INT GetObjectW(HGDIOBJ obj, INT cb, void* buf)
{
    (void)obj;
    (void)cb;
    (void)buf;
    return 0;
}

/* Recover brush colour from the stub's tag. Returns 0 if the
 * brush is NULL or not our tagged format. */
static COLORREF gdi32_brush_colour(HBRUSH br)
{
    unsigned long long v = (unsigned long long)br;
    if ((v & 0xF0000000ULL) != 0xB0000000ULL)
        return 0;
    return (COLORREF)(v & 0x00FFFFFFULL);
}

/* Call SYS_GDI_FILL_RECT / SYS_GDI_RECTANGLE. Six args: hwnd, x,
 * y, w, h, colour. r8 / r9 via register vars. */
static BOOL gdi32_rect_core(unsigned num, HANDLE hwnd, INT x, INT y, INT w, INT h, COLORREF colour)
{
    register long long r10_w asm("r10") = (long long)w;
    register long long r8_h asm("r8") = (long long)h;
    register long long r9_c asm("r9") = (long long)(unsigned long long)colour;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)num), "D"((long long)(unsigned long long)hwnd), "S"((long long)x),
                       "d"((long long)y), "r"(r10_w), "r"(r8_h), "r"(r9_c)
                     : "memory");
    return rv ? 1 : 0;
}

static BOOL gdi32_text_core(HANDLE hwnd, INT x, INT y, const char* text, UINT len, COLORREF colour)
{
    register long long r10_t asm("r10") = (long long)(unsigned long long)text;
    register long long r8_l asm("r8") = (long long)len;
    register long long r9_c asm("r9") = (long long)(unsigned long long)colour;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_TEXT_OUT), "D"((long long)(unsigned long long)hwnd), "S"((long long)x),
                       "d"((long long)y), "r"(r10_t), "r"(r8_l), "r"(r9_c)
                     : "memory");
    return rv ? 1 : 0;
}

/* --- Draw calls --- */
__declspec(dllexport) BOOL BitBlt(HDC dst, INT x, INT y, INT w, INT h, HDC src, INT sx, INT sy, DWORD rop)
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
__declspec(dllexport) BOOL StretchBlt(HDC dst, INT x, INT y, INT w, INT h, HDC src, INT sx, INT sy, INT sw, INT sh,
                                      DWORD rop)
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

/* DrawText — trivial one-line implementation: treats the rect's
 * top-left as the anchor and paints the (NUL-terminated or `len`-
 * bounded) text with the DC's HWND. Ignores alignment flags for
 * v0; callers that want centered text will see left-aligned. */
static unsigned gdi32_strnlen(const char* s, INT len)
{
    unsigned n = 0;
    if (!s)
        return 0;
    while ((len < 0 || (INT)n < len) && s[n] != 0 && n < 4096)
        ++n;
    return n;
}
__declspec(dllexport) INT DrawTextA(HDC dc, const char* text, INT len, void* r, UINT fmt)
{
    (void)fmt;
    if (!r || !text)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    RECT* rc = (RECT*)r;
    unsigned n = gdi32_strnlen(text, len);
    /* Default text colour is black — real GDI uses the DC's
     * stored text colour; v0 ignores SetTextColor. */
    gdi32_text_core(hwnd, rc->left, rc->top, text, n, 0);
    return 8; /* "glyph height" best-effort — callers use this as a row height */
}
__declspec(dllexport) INT DrawTextW(HDC dc, const wchar_t16* text, INT len, void* r, UINT fmt)
{
    if (!r || !text)
        return 0;
    /* The kernel handler accepts the HDC directly (memDC tag or
     * window-DC raw handle), copies in `rdx` wchar_ts, downcodes
     * non-ASCII to '?', and applies DT_CENTER / DT_VCENTER /
     * DT_RIGHT / DT_LEFT / DT_TOP / DT_SINGLELINE. Returns the
     * drawn-text pixel height in eax. */
    register long long r10_r asm("r10") = (long long)(unsigned long long)r;
    register long long r8_f asm("r8") = (long long)fmt;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_DRAW_TEXT_W), "D"((long long)(unsigned long long)dc),
                       "S"((long long)(unsigned long long)text), "d"((long long)len), "r"(r10_r), "r"(r8_f)
                     : "memory");
    return (INT)(rv > 0 ? rv : 0);
}

static unsigned gdi32_ascii_len(const wchar_t16* s, INT len)
{
    unsigned n = 0;
    if (!s)
        return 0;
    while ((len < 0 || (INT)n < len) && s[n] != 0 && n < 4096)
        ++n;
    return n;
}

__declspec(dllexport) BOOL ExtTextOutA(HDC dc, INT x, INT y, UINT opts, const void* r, const char* text, UINT len,
                                       const INT* dx)
{
    (void)opts;
    (void)r;
    (void)dx;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    return gdi32_text_core(hwnd, x, y, text, len, 0);
}
__declspec(dllexport) BOOL ExtTextOutW(HDC dc, INT x, INT y, UINT opts, const void* r, const wchar_t16* text, UINT len,
                                       const INT* dx)
{
    (void)opts;
    (void)r;
    (void)dx;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text)
        return 0;
    /* Best-effort UTF-16 → ASCII flatten into a 256-char buffer.
     * Long strings are truncated; non-ASCII becomes '?'. */
    char buf[256];
    unsigned n = 0;
    unsigned cap = sizeof(buf) - 1;
    unsigned limit = (len == 0xFFFFFFFFu) ? cap : (len < cap ? len : cap);
    for (; n < limit && text[n] != 0; ++n)
    {
        wchar_t16 c = text[n];
        buf[n] = (c > 0 && c < 0x7F) ? (char)c : '?';
    }
    buf[n] = 0;
    return gdi32_text_core(hwnd, x, y, buf, n, 0);
}
__declspec(dllexport) BOOL TextOutA(HDC dc, INT x, INT y, const char* text, INT len)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    unsigned n = gdi32_strnlen(text, len);
    return gdi32_text_core(hwnd, x, y, text, n, 0);
}
__declspec(dllexport) BOOL TextOutW(HDC dc, INT x, INT y, const wchar_t16* text, INT len)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text)
        return 0;
    char buf[256];
    unsigned cap = sizeof(buf) - 1;
    unsigned limit = (len < 0) ? cap : ((unsigned)len < cap ? (unsigned)len : cap);
    unsigned n = 0;
    for (; n < limit && text[n] != 0; ++n)
    {
        wchar_t16 c = text[n];
        buf[n] = (c > 0 && c < 0x7F) ? (char)c : '?';
    }
    buf[n] = 0;
    return gdi32_text_core(hwnd, x, y, buf, n, 0);
}
__declspec(dllexport) INT FillRect(HDC dc, const void* r, HBRUSH br)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !r)
        return 0;
    const RECT* rc = (const RECT*)r;
    INT w = rc->right - rc->left;
    INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    COLORREF col = gdi32_brush_colour(br);
    return gdi32_rect_core(SYS_GDI_FILL_RECT, hwnd, rc->left, rc->top, w, h, col) ? 1 : 0;
}
__declspec(dllexport) INT FrameRect(HDC dc, const void* r, HBRUSH br)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !r)
        return 0;
    const RECT* rc = (const RECT*)r;
    INT w = rc->right - rc->left;
    INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    COLORREF col = gdi32_brush_colour(br);
    return gdi32_rect_core(SYS_GDI_RECTANGLE, hwnd, rc->left, rc->top, w, h, col) ? 1 : 0;
}
/* DC current-point state. Real GDI stores (x, y) per DC; v1
 * uses a single module-global — good enough when programs only
 * paint on one DC at a time. Concurrent DCs share the cursor;
 * documented limitation. */
static INT g_cur_x = 0;
static INT g_cur_y = 0;

typedef struct
{
    INT x;
    INT y;
} POINT;

static BOOL gdi32_line_core(HANDLE hwnd, INT x0, INT y0, INT x1, INT y1, COLORREF col)
{
    register long long r10_x1 asm("r10") = (long long)x1;
    register long long r8_y1 asm("r8") = (long long)y1;
    register long long r9_c asm("r9") = (long long)(unsigned long long)col;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_LINE), "D"((long long)(unsigned long long)hwnd), "S"((long long)x0),
                       "d"((long long)y0), "r"(r10_x1), "r"(r8_y1), "r"(r9_c)
                     : "memory");
    return rv ? 1 : 0;
}

__declspec(dllexport) BOOL MoveToEx(HDC dc, INT x, INT y, void* prev)
{
    (void)dc;
    if (prev)
    {
        POINT* p = (POINT*)prev;
        p->x = g_cur_x;
        p->y = g_cur_y;
    }
    g_cur_x = x;
    g_cur_y = y;
    return 1;
}
__declspec(dllexport) BOOL LineTo(HDC dc, INT x, INT y)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    BOOL rv = gdi32_line_core(hwnd, g_cur_x, g_cur_y, x, y, 0);
    g_cur_x = x;
    g_cur_y = y;
    return rv;
}
__declspec(dllexport) BOOL Polyline(HDC dc, const void* pts, INT n)
{
    if (!pts || n < 2)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    const POINT* p = (const POINT*)pts;
    for (INT i = 0; i + 1 < n; ++i)
    {
        (void)gdi32_line_core(hwnd, p[i].x, p[i].y, p[i + 1].x, p[i + 1].y, 0);
    }
    return 1;
}
__declspec(dllexport) BOOL Polygon(HDC dc, const void* pts, INT n)
{
    if (!pts || n < 2)
        return 0;
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    const POINT* p = (const POINT*)pts;
    Polyline(dc, pts, n);
    (void)gdi32_line_core(hwnd, p[n - 1].x, p[n - 1].y, p[0].x, p[0].y, 0);
    return 1;
}
/* Win32 Rectangle paints a bordered outline + fills the interior
 * with the currently-selected brush. v0 has no selected-object
 * tracking, so the fill is black and the outline is black. */
__declspec(dllexport) BOOL Rectangle(HDC dc, INT l, INT t, INT r, INT b)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    INT w = r - l;
    INT h = b - t;
    if (w <= 0 || h <= 0)
        return 1;
    return gdi32_rect_core(SYS_GDI_RECTANGLE, hwnd, l, t, w, h, 0);
}
__declspec(dllexport) BOOL Ellipse(HDC dc, INT l, INT t, INT r, INT b)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    INT w = r - l;
    INT h = b - t;
    if (w <= 0 || h <= 0)
        return 1;
    return gdi32_rect_core(SYS_GDI_ELLIPSE, hwnd, l, t, w, h, 0);
}

__declspec(dllexport) COLORREF SetPixel(HDC dc, INT x, INT y, COLORREF col)
{
    HANDLE hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return (COLORREF)-1;
    register long long r10_c asm("r10") = (long long)(unsigned long long)col;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_PIXEL), "D"((long long)(unsigned long long)hwnd), "S"((long long)x),
                       "d"((long long)y), "r"(r10_c)
                     : "memory");
    return rv ? col : (COLORREF)-1;
}
__declspec(dllexport) BOOL SetPixelV(HDC dc, INT x, INT y, COLORREF col)
{
    return SetPixel(dc, x, y, col) != (COLORREF)-1;
}
__declspec(dllexport) COLORREF GetPixel(HDC dc, INT x, INT y)
{
    (void)dc;
    (void)x;
    (void)y;
    /* No framebuffer read-back syscall in v1 — return CLR_INVALID
     * so callers that check for it take the "couldn't query"
     * path. Most programs use GetPixel for hit-testing which
     * has other paths. */
    return (COLORREF)-1;
}

/* --- DC state setters (route to kernel where the syscall exists) --- */
__declspec(dllexport) COLORREF SetBkColor(HDC dc, COLORREF clr)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_BK_COLOR), "D"((long long)(unsigned long long)dc), "S"((long long)clr)
                     : "memory");
    return (COLORREF)rv;
}
__declspec(dllexport) INT SetBkMode(HDC dc, INT mode)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_BK_MODE), "D"((long long)(unsigned long long)dc), "S"((long long)mode)
                     : "memory");
    return (INT)rv;
}
__declspec(dllexport) INT SetMapMode(HDC dc, INT mode)
{
    (void)dc;
    (void)mode;
    return 0;
}
__declspec(dllexport) UINT SetTextAlign(HDC dc, UINT align)
{
    (void)dc;
    (void)align;
    return 0;
}
__declspec(dllexport) COLORREF SetTextColor(HDC dc, COLORREF clr)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)SYS_GDI_SET_TEXT_COLOR), "D"((long long)(unsigned long long)dc),
                       "S"((long long)clr)
                     : "memory");
    return (COLORREF)rv;
}

/* GetDeviceCaps — report device capability ints. The kernel's
 * default framebuffer is 32-bpp; hardcode the constants apps
 * routinely query. Index list:
 *   8  = HORZRES        (pixels)
 *   10 = VERTRES        (pixels)
 *   12 = BITSPIXEL      (32)
 *   14 = PLANES         (1)
 *   88 = LOGPIXELSX     (96 — standard DPI)
 *   90 = LOGPIXELSY     (96)
 *   24 = NUMCOLORS      (-1 = "more than 256")
 *   26 = ASPECTX        (36 — square pixels)
 *   40 = ASPECTY        (36)
 *   38 = TECHNOLOGY     (0 = DT_PLOTTER, but 1 = DT_RASDISPLAY is canonical)
 * Anything else returns 0.
 */
__declspec(dllexport) INT GetDeviceCaps(HDC dc, INT index)
{
    (void)dc;
    switch (index)
    {
    case 8:
        return 1024; /* HORZRES — matches the default framebuffer */
    case 10:
        return 768; /* VERTRES */
    case 12:
        return 32; /* BITSPIXEL */
    case 14:
        return 1; /* PLANES */
    case 88:
    case 90:
        return 96; /* LOGPIXELSX/Y */
    case 24:
        return -1; /* NUMCOLORS — "true colour" sentinel */
    case 26:
    case 40:
        return 36; /* ASPECTX/Y — square pixels */
    case 38:
        return 1; /* TECHNOLOGY = DT_RASDISPLAY */
    case 22:
        return 8; /* HORZSIZE — millimetres (ballpark) */
    case 6:
        return 8; /* VERTSIZE */
    default:
        return 0;
    }
}

/* GetTextExtentPoint32A/W — measure text. With 8x8 bitmap font,
 * width = chars * 8, height = 8. Caller's SIZE struct is two
 * INT fields (cx, cy). */
typedef struct
{
    INT cx;
    INT cy;
} SIZE_GDI;
__declspec(dllexport) BOOL GetTextExtentPoint32A(HDC dc, const char* str, INT cnt, SIZE_GDI* sz)
{
    (void)dc;
    (void)str;
    if (sz)
    {
        sz->cx = (cnt < 0 ? 0 : cnt) * 8;
        sz->cy = 8;
    }
    return 1;
}
__declspec(dllexport) BOOL GetTextExtentPoint32W(HDC dc, const wchar_t16* str, INT cnt, SIZE_GDI* sz)
{
    (void)dc;
    (void)str;
    if (sz)
    {
        sz->cx = (cnt < 0 ? 0 : cnt) * 8;
        sz->cy = 8;
    }
    return 1;
}
__declspec(dllexport) BOOL GetTextExtentExPointW(HDC dc, const wchar_t16* str, INT cnt, INT max_extent, INT* fit,
                                                 INT* dx, SIZE_GDI* sz)
{
    (void)dc;
    (void)str;
    (void)max_extent;
    (void)dx;
    if (fit)
        *fit = cnt;
    if (sz)
    {
        sz->cx = (cnt < 0 ? 0 : cnt) * 8;
        sz->cy = 8;
    }
    return 1;
}

/* GetTextMetricsA/W — fill a TEXTMETRIC. Real struct is 56 bytes
 * for ANSI. We zero-fill and write the few fields apps actually
 * read: tmHeight=8, tmAveCharWidth=8, tmMaxCharWidth=8. */
__declspec(dllexport) BOOL GetTextMetricsA(HDC dc, void* tm)
{
    (void)dc;
    if (!tm)
        return 0;
    unsigned char* p = (unsigned char*)tm;
    for (int i = 0; i < 56; ++i)
        p[i] = 0;
    INT* fields = (INT*)tm;
    fields[0] = 8; /* tmHeight */
    fields[1] = 8; /* tmAscent */
    fields[2] = 0; /* tmDescent */
    fields[5] = 8; /* tmAveCharWidth */
    fields[6] = 8; /* tmMaxCharWidth */
    fields[7] = 1; /* tmWeight (FW_NORMAL = 400 actually but doesn't matter for v0) */
    return 1;
}
__declspec(dllexport) BOOL GetTextMetricsW(HDC dc, void* tm)
{
    return GetTextMetricsA(dc, tm);
}

/* GetCharWidth32A/W — width of each character in the range. With
 * a fixed-width font, every cell is 8 pixels. */
__declspec(dllexport) BOOL GetCharWidth32A(HDC dc, UINT first, UINT last, INT* widths)
{
    (void)dc;
    if (!widths || last < first)
        return 0;
    UINT n = last - first + 1;
    for (UINT i = 0; i < n; ++i)
        widths[i] = 8;
    return 1;
}
__declspec(dllexport) BOOL GetCharWidth32W(HDC dc, UINT first, UINT last, INT* widths)
{
    return GetCharWidth32A(dc, first, last, widths);
}

/* SetROP2 / GetROP2 — drawing-mode setter. R2_COPYPEN (13) is
 * the universal default; accept any set, return previous. */
__declspec(dllexport) INT SetROP2(HDC dc, INT mode)
{
    (void)dc;
    (void)mode;
    return 13;
}
__declspec(dllexport) INT GetROP2(HDC dc)
{
    (void)dc;
    return 13;
}

/* GetClipBox — fill the RECT with a "cover everything" extent.
 * Returns SIMPLEREGION (2). */
__declspec(dllexport) INT GetClipBox(HDC dc, RECT* r)
{
    (void)dc;
    if (r)
    {
        r->left = 0;
        r->top = 0;
        r->right = 1024;
        r->bottom = 768;
    }
    return 2;
}

__declspec(dllexport) INT IntersectClipRect(HDC dc, INT l, INT t, INT r, INT b)
{
    (void)dc;
    (void)l;
    (void)t;
    (void)r;
    (void)b;
    return 2; /* SIMPLEREGION */
}

__declspec(dllexport) INT ExcludeClipRect(HDC dc, INT l, INT t, INT r, INT b)
{
    (void)dc;
    (void)l;
    (void)t;
    (void)r;
    (void)b;
    return 2;
}

__declspec(dllexport) INT SetStretchBltMode(HDC dc, INT mode)
{
    (void)dc;
    (void)mode;
    return 1;
}

__declspec(dllexport) INT GetStretchBltMode(HDC dc)
{
    (void)dc;
    return 1;
}
