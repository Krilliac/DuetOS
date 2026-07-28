/*
 * userland/libs/gdi32_32/gdi32_32.c
 *
 * Freestanding DuetOS gdi32.dll (i386 / PE32 variant) — the drawing
 * surface, bridged to the compositor's per-window display list over
 * SYS_GDI_* the same way the 64-bit userland/libs/gdi32/gdi32.c is.
 *
 * Before this slice every export returned a constant and the file
 * issued no syscalls at all, so a PE32 that painted its window saw
 * every draw call "succeed" and nothing appear. Object creation
 * (pens, brushes) now encodes the colour into the handle, so
 * SelectObject needs no allocation table and a FillRect / TextOut /
 * LineTo actually reaches the framebuffer.
 *
 * Only window DCs render. A memory DC from CreateCompatibleDC has no
 * kernel-side backing here (the 64-bit sibling's DC-object syscalls
 * are not in this port), so draw calls against one are refused
 * rather than silently dropped — see the STUB markers.
 *
 * The typedefs, syscall numbers, handle encodings and draw cores are
 * in gdi32_32_internal.h.
 */

#include "gdi32_32_internal.h"

/* ------------------------------------------------------------------
 * Objects
 *
 * Pens and brushes are self-describing handles: type nibble + BGR
 * colour. Nothing is allocated, so nothing leaks and DeleteObject is
 * genuinely a no-op rather than a deferred bug.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HPEN __stdcall CreatePen(int style, int width, COLORREF colour)
{
    /* GAP: dash/dot styles and widths above 1 px are not modelled —
     * the compositor's line primitive is a 1-px Bresenham run.
     * Revisit when the display list grows a stroke width. */
    (void)style;
    (void)width;
    return (HPEN)(unsigned long)(GDI32_PEN_TAG | (colour & GDI32_COLOUR_MASK));
}

__declspec(dllexport) HBRUSH __stdcall CreateSolidBrush(COLORREF colour)
{
    return (HBRUSH)(unsigned long)(GDI32_BRUSH_TAG | (colour & GDI32_COLOUR_MASK));
}

/* LOGBRUSH on i386: { UINT lbStyle; COLORREF lbColor; ULONG_PTR
 * lbHatch; } — 12 bytes. Only the solid style carries a colour we
 * can honour. */
__declspec(dllexport) HBRUSH __stdcall CreateBrushIndirect(const void* lb)
{
    if (!lb)
        return (HBRUSH)0;
    const unsigned* fields = (const unsigned*)lb;
    /* GAP: hatch and pattern brushes fall back to their solid
     * colour — the display list has no hatch primitive. */
    return CreateSolidBrush((COLORREF)fields[1]);
}

/* STUB: there is no font pipeline — the compositor draws text in one
 * built-in bitmap face at a fixed size, so every font handle is the
 * same object and no metric of the requested face is honoured. */
__declspec(dllexport) HFONT __stdcall CreateFontA(int h, int w, int esc, int orient, int weight, DWORD italic,
                                                  DWORD underline, DWORD strikeout, DWORD charset, DWORD out_prec,
                                                  DWORD clip_prec, DWORD quality, DWORD pitch, const char* face)
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
    return (HFONT)0x10004;
}

__declspec(dllexport) HFONT __stdcall CreateFontW(int h, int w, int esc, int orient, int weight, DWORD italic,
                                                  DWORD underline, DWORD strikeout, DWORD charset, DWORD out_prec,
                                                  DWORD clip_prec, DWORD quality, DWORD pitch, const wchar_t16* face)
{
    (void)face;
    return CreateFontA(h, w, esc, orient, weight, italic, underline, strikeout, charset, out_prec, clip_prec, quality,
                       pitch, 0);
}

__declspec(dllexport) HFONT __stdcall CreateFontIndirectA(const void* lf)
{
    (void)lf;
    return (HFONT)0x10004;
}

__declspec(dllexport) HFONT __stdcall CreateFontIndirectW(const void* lf)
{
    (void)lf;
    return (HFONT)0x10004;
}

/* Stock objects. The colour-bearing ones become real brush / pen
 * handles so a caller that fills with GetStockObject(WHITE_BRUSH)
 * paints white rather than black. */
#define WHITE_BRUSH 0
#define LTGRAY_BRUSH 1
#define GRAY_BRUSH 2
#define DKGRAY_BRUSH 3
#define BLACK_BRUSH 4
#define NULL_BRUSH 5
#define WHITE_PEN 6
#define BLACK_PEN 7
#define NULL_PEN 8
#define SYSTEM_FONT 13

__declspec(dllexport) HGDIOBJ __stdcall GetStockObject(int index)
{
    switch (index)
    {
    case WHITE_BRUSH:
        return (HGDIOBJ)(unsigned long)(GDI32_BRUSH_TAG | 0x00FFFFFFu);
    case LTGRAY_BRUSH:
        return (HGDIOBJ)(unsigned long)(GDI32_BRUSH_TAG | 0x00C0C0C0u);
    case GRAY_BRUSH:
        return (HGDIOBJ)(unsigned long)(GDI32_BRUSH_TAG | 0x00808080u);
    case DKGRAY_BRUSH:
        return (HGDIOBJ)(unsigned long)(GDI32_BRUSH_TAG | 0x00404040u);
    case BLACK_BRUSH:
        return (HGDIOBJ)(unsigned long)GDI32_BRUSH_TAG;
    case WHITE_PEN:
        return (HGDIOBJ)(unsigned long)(GDI32_PEN_TAG | 0x00FFFFFFu);
    case BLACK_PEN:
        return (HGDIOBJ)(unsigned long)GDI32_PEN_TAG;
    case NULL_BRUSH:
    case NULL_PEN:
        /* A NULL brush/pen means "draw nothing"; an untagged
         * sentinel is what the draw calls below skip on. */
        return (HGDIOBJ)0x10005;
    case SYSTEM_FONT:
    default:
        return (HGDIOBJ)0x10004;
    }
}

/* Currently-selected pen / brush. Real GDI keeps these per-DC; one
 * set is enough while programs paint one window at a time — the same
 * documented single-DC limitation the 64-bit sibling carries for its
 * current point. */
static HGDIOBJ s_cur_pen = 0;
static HGDIOBJ s_cur_brush = 0;

__declspec(dllexport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ obj)
{
    (void)dc;
    const unsigned v = (unsigned)(unsigned long)obj;
    if ((v & GDI32_TYPE_MASK) == GDI32_PEN_TAG)
    {
        HGDIOBJ prev = s_cur_pen;
        s_cur_pen = obj;
        return prev;
    }
    if ((v & GDI32_TYPE_MASK) == GDI32_BRUSH_TAG)
    {
        HGDIOBJ prev = s_cur_brush;
        s_cur_brush = obj;
        return prev;
    }
    /* Fonts, bitmaps and regions have no selectable state here. */
    return (HGDIOBJ)0;
}

__declspec(dllexport) BOOL __stdcall DeleteObject(HGDIOBJ obj)
{
    /* Self-describing handles own no memory. */
    (void)obj;
    return 1;
}

static COLORREF gdi32_pen_colour(void)
{
    return gdi32_object_colour(s_cur_pen, GDI32_PEN_TAG);
}

static COLORREF gdi32_brush_colour(void)
{
    return gdi32_object_colour(s_cur_brush, GDI32_BRUSH_TAG);
}

/* ------------------------------------------------------------------
 * Device contexts
 * ------------------------------------------------------------------ */

/* STUB: an off-screen DC needs a kernel-backed surface to render
 * into, which this port does not carry. The sentinel is non-null so
 * the caller's failure path stays quiet, but it is not tagged as a
 * window DC, so every draw call against it is refused. */
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

/* STUB: bitmaps have no backing store here, so CreateBitmap and its
 * relatives hand back sentinels that nothing can be blitted from. */
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

/* ------------------------------------------------------------------
 * Draw calls
 * ------------------------------------------------------------------ */

__declspec(dllexport) INT __stdcall FillRect(HDC dc, const void* lprc, HBRUSH brush)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !lprc)
        return 0;
    const RECT* rc = (const RECT*)lprc;
    const INT w = rc->right - rc->left;
    const INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    return gdi32_rect_core(SYS_GDI_FILL_RECT, hwnd, rc->left, rc->top, w, h,
                           gdi32_object_colour(brush, GDI32_BRUSH_TAG))
               ? 1
               : 0;
}

__declspec(dllexport) INT __stdcall FrameRect(HDC dc, const void* lprc, HBRUSH brush)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !lprc)
        return 0;
    const RECT* rc = (const RECT*)lprc;
    const INT w = rc->right - rc->left;
    const INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    return gdi32_rect_core(SYS_GDI_RECTANGLE, hwnd, rc->left, rc->top, w, h,
                           gdi32_object_colour(brush, GDI32_BRUSH_TAG))
               ? 1
               : 0;
}

__declspec(dllexport) BOOL __stdcall Rectangle(HDC dc, int left, int top, int right, int bottom)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    const INT w = right - left;
    const INT h = bottom - top;
    if (w <= 0 || h <= 0)
        return 1;
    /* Win32 Rectangle fills with the current brush, then outlines
     * with the current pen. Both primitives are recorded in that
     * order so the display-list replay reproduces it. */
    if (s_cur_brush)
    {
        (void)gdi32_rect_core(SYS_GDI_FILL_RECT, hwnd, left, top, w, h, gdi32_brush_colour());
    }
    return gdi32_rect_core(SYS_GDI_RECTANGLE, hwnd, left, top, w, h, gdi32_pen_colour()) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall Ellipse(HDC dc, int left, int top, int right, int bottom)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    const INT w = right - left;
    const INT h = bottom - top;
    if (w <= 0 || h <= 0)
        return 1;
    return gdi32_rect_core(SYS_GDI_ELLIPSE, hwnd, left, top, w, h, gdi32_pen_colour()) ? 1 : 0;
}

/* Current point. Shared across DCs for the same reason the pen and
 * brush are. */
static INT s_cur_x = 0;
static INT s_cur_y = 0;

__declspec(dllexport) BOOL __stdcall MoveToEx(HDC dc, int x, int y, void* prev)
{
    (void)dc;
    if (prev)
    {
        POINT* p = (POINT*)prev;
        p->x = s_cur_x;
        p->y = s_cur_y;
    }
    s_cur_x = x;
    s_cur_y = y;
    return 1;
}

static BOOL gdi32_line_core(HWND hwnd, INT x0, INT y0, INT x1, INT y1, COLORREF colour)
{
    return duet_syscall6(SYS_GDI_LINE, (unsigned)(unsigned long)hwnd, (unsigned)x0, (unsigned)y0, (unsigned)x1,
                         (unsigned)y1, (unsigned)colour)
               ? 1
               : 0;
}

__declspec(dllexport) BOOL __stdcall LineTo(HDC dc, int x, int y)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return 0;
    const BOOL ok = gdi32_line_core(hwnd, s_cur_x, s_cur_y, x, y, gdi32_pen_colour());
    /* Win32 advances the current point even when the stroke draws
     * nothing, so the update is unconditional. */
    s_cur_x = x;
    s_cur_y = y;
    return ok;
}

__declspec(dllexport) BOOL __stdcall Polyline(HDC dc, const void* points, int count)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !points || count < 2)
        return 0;
    const POINT* p = (const POINT*)points;
    const COLORREF colour = gdi32_pen_colour();
    for (int i = 1; i < count; ++i)
    {
        (void)gdi32_line_core(hwnd, p[i - 1].x, p[i - 1].y, p[i].x, p[i].y, colour);
    }
    return 1;
}

__declspec(dllexport) BOOL __stdcall Polygon(HDC dc, const void* points, int count)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !points || count < 2)
        return 0;
    /* GAP: the outline is drawn but the interior is not filled —
     * the display list has no scanline-fill primitive. Revisit
     * alongside compositor polygon support. */
    (void)Polyline(dc, points, count);
    const POINT* p = (const POINT*)points;
    return gdi32_line_core(hwnd, p[count - 1].x, p[count - 1].y, p[0].x, p[0].y, gdi32_pen_colour());
}

/* STUB: no arc primitive exists in the display list; the call is
 * accepted so a caller's error path stays quiet and nothing draws. */
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

__declspec(dllexport) COLORREF __stdcall SetPixel(HDC dc, int x, int y, COLORREF colour)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd)
        return (COLORREF)-1;
    if (!duet_syscall4(SYS_GDI_SET_PIXEL, (unsigned)(unsigned long)hwnd, (unsigned)x, (unsigned)y, (unsigned)colour))
        return (COLORREF)-1;
    return colour;
}

/* STUB: the display list records primitives rather than a readable
 * pixel buffer, so there is nothing to sample. CLR_INVALID is the
 * Win32 failure value, which is the honest answer. */
__declspec(dllexport) COLORREF __stdcall GetPixel(HDC dc, int x, int y)
{
    (void)dc;
    (void)x;
    (void)y;
    return (COLORREF)-1;
}

/* ------------------------------------------------------------------
 * Text
 * ------------------------------------------------------------------ */

/* Text colour is DC state in Win32, so it lives here rather than in
 * a handle. Same single-DC caveat as the pen / brush. */
static COLORREF s_text_colour = 0x00FFFFFFu; /* white on the dark client */
static COLORREF s_bk_colour = 0;

static unsigned gdi32_strnlen(const char* s, int len)
{
    if (!s)
        return 0;
    if (len >= 0)
        return (unsigned)len;
    unsigned n = 0;
    while (s[n])
        ++n;
    return n;
}

static BOOL gdi32_text_core(HWND hwnd, INT x, INT y, const char* text, unsigned len)
{
    return duet_syscall6(SYS_GDI_TEXT_OUT, (unsigned)(unsigned long)hwnd, (unsigned)x, (unsigned)y,
                         (unsigned)(unsigned long)text, len, (unsigned)s_text_colour)
               ? 1
               : 0;
}

__declspec(dllexport) BOOL __stdcall TextOutA(HDC dc, int x, int y, const char* text, int len)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text)
        return 0;
    return gdi32_text_core(hwnd, x, y, text, gdi32_strnlen(text, len));
}

__declspec(dllexport) BOOL __stdcall TextOutW(HDC dc, int x, int y, const wchar_t16* text, int len)
{
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text)
        return 0;
    char buf[256];
    const unsigned cap = sizeof(buf) - 1;
    const unsigned limit = (len < 0) ? cap : ((unsigned)len < cap ? (unsigned)len : cap);
    unsigned n = 0;
    for (; n < limit && text[n] != 0; ++n)
    {
        wchar_t16 c = text[n];
        buf[n] = (c > 0 && c < 0x7F) ? (char)c : '?';
    }
    buf[n] = '\0';
    return gdi32_text_core(hwnd, x, y, buf, n);
}

/* DrawText anchors at the rect's top-left. GAP: no word wrap, no
 * alignment flags, no multi-line layout — revisit when a PE needs
 * DT_CENTER / DT_WORDBREAK to read correctly. */
__declspec(dllexport) INT __stdcall DrawTextA(HDC dc, const char* text, int len, void* rect, UINT format)
{
    (void)format;
    HWND hwnd = gdi32_hwnd_from_hdc(dc);
    if (!hwnd || !text || !rect)
        return 0;
    const RECT* rc = (const RECT*)rect;
    return gdi32_text_core(hwnd, rc->left, rc->top, text, gdi32_strnlen(text, len)) ? 1 : 0;
}

__declspec(dllexport) INT __stdcall DrawTextW(HDC dc, const wchar_t16* text, int len, void* rect, UINT format)
{
    (void)format;
    if (!rect)
        return 0;
    const RECT* rc = (const RECT*)rect;
    return TextOutW(dc, rc->left, rc->top, text, len) ? 1 : 0;
}

__declspec(dllexport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF colour)
{
    (void)dc;
    COLORREF prev = s_text_colour;
    s_text_colour = colour;
    return prev;
}

__declspec(dllexport) COLORREF __stdcall SetBkColor(HDC dc, COLORREF colour)
{
    /* GAP: opaque text backgrounds are not painted — the text
     * primitive draws glyphs only. The value round-trips so a
     * caller that saves and restores it sees what it set. */
    (void)dc;
    COLORREF prev = s_bk_colour;
    s_bk_colour = colour;
    return prev;
}

/* STUB: background mode, text alignment and mapping mode have no
 * effect on the display list's fixed top-left, transparent,
 * device-units text primitive. Each returns the Win32 default so a
 * save/restore pair is not misled. */
#define TRANSPARENT 1
#define TA_LEFT 0
#define MM_TEXT 1

__declspec(dllexport) INT __stdcall SetBkMode(HDC dc, int mode)
{
    (void)dc;
    (void)mode;
    return TRANSPARENT;
}

__declspec(dllexport) UINT __stdcall SetTextAlign(HDC dc, UINT mode)
{
    (void)dc;
    (void)mode;
    return TA_LEFT;
}

__declspec(dllexport) INT __stdcall SetMapMode(HDC dc, int mode)
{
    (void)dc;
    (void)mode;
    return MM_TEXT;
}

/* ------------------------------------------------------------------
 * Queries + the blit / DIB family
 * ------------------------------------------------------------------ */

#define HORZRES 8
#define VERTRES 10
#define BITSPIXEL 12
#define PLANES 14
#define NUMCOLORS 24

/* SM_CXSCREEN / SM_CYSCREEN selectors for SYS_WIN_GET_METRIC. */
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1

__declspec(dllexport) INT __stdcall GetDeviceCaps(HDC dc, int index)
{
    (void)dc;
    switch (index)
    {
    case HORZRES:
        /* Ask the window manager rather than baking in a guess, so
         * this stays honest against the real framebuffer. */
        return duet_syscall1(91 /* SYS_WIN_GET_METRIC */, SM_CXSCREEN);
    case VERTRES:
        return duet_syscall1(91 /* SYS_WIN_GET_METRIC */, SM_CYSCREEN);
    case BITSPIXEL:
        return 32;
    case PLANES:
        return 1;
    case NUMCOLORS:
        return -1; /* true colour */
    default:
        return 0;
    }
}

/* STUB: object introspection needs the allocation table this port
 * does not keep, so GetObject reports "no data written". */
__declspec(dllexport) INT __stdcall GetObjectA(HGDIOBJ obj, int cb, void* out)
{
    (void)obj;
    (void)cb;
    (void)out;
    return 0;
}

__declspec(dllexport) INT __stdcall GetObjectW(HGDIOBJ obj, int cb, void* out)
{
    (void)obj;
    (void)cb;
    (void)out;
    return 0;
}

/* STUB: blitting needs a source surface. Memory DCs and bitmaps are
 * sentinels here, so there is nothing to copy from and the call
 * reports failure rather than pretending a copy happened. */
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
    return 0;
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
    return 0;
}

/* STUB: no DIB surface allocation. ppvBits is cleared so a caller
 * that checks it before writing pixels sees the failure instead of
 * scribbling through a stale pointer. */
__declspec(dllexport) HBITMAP __stdcall CreateDIBSection(HDC dc, const void* bmi, UINT usage, void** bits,
                                                         HANDLE section, DWORD offset)
{
    (void)dc;
    (void)bmi;
    (void)usage;
    (void)section;
    (void)offset;
    if (bits)
        *bits = 0;
    return (HBITMAP)0;
}

__declspec(dllexport) HBITMAP __stdcall CreateDIBitmap(HDC dc, const void* header, DWORD init, const void* bits,
                                                       const void* bmi, UINT usage)
{
    (void)dc;
    (void)header;
    (void)init;
    (void)bits;
    (void)bmi;
    (void)usage;
    return (HBITMAP)0;
}

__declspec(dllexport) INT __stdcall GetDIBits(HDC dc, HBITMAP bmp, UINT start, UINT scans, void* bits, void* bi,
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

__declspec(dllexport) HPEN __stdcall ExtCreatePen(DWORD style, DWORD width, const void* lb, DWORD style_count,
                                                  const DWORD* style_array)
{
    (void)style_count;
    (void)style_array;
    if (!lb)
        return (HPEN)0;
    /* LOGBRUSH again: { lbStyle, lbColor, lbHatch }. */
    const unsigned* fields = (const unsigned*)lb;
    return CreatePen((int)style, (int)width, (COLORREF)fields[1]);
}

/* STUB: clipping regions are not modelled — the compositor clips
 * every primitive to the client rect and nothing finer. */
__declspec(dllexport) HRGN __stdcall CreateRectRgnIndirect(const void* rect)
{
    (void)rect;
    return (HRGN)0x10006;
}

/* SaveDC / RestoreDC snapshot the DC state this port actually keeps:
 * pen, brush, text and background colour, and the current point.
 * That covers the save-draw-restore idiom around a WM_PAINT
 * handler, which is the only use these see. */
static struct
{
    HGDIOBJ pen;
    HGDIOBJ brush;
    COLORREF text_colour;
    COLORREF bk_colour;
    INT cur_x;
    INT cur_y;
    int valid;
} s_dc_saved;

__declspec(dllexport) INT __stdcall SaveDC(HDC dc)
{
    (void)dc;
    s_dc_saved.pen = s_cur_pen;
    s_dc_saved.brush = s_cur_brush;
    s_dc_saved.text_colour = s_text_colour;
    s_dc_saved.bk_colour = s_bk_colour;
    s_dc_saved.cur_x = s_cur_x;
    s_dc_saved.cur_y = s_cur_y;
    s_dc_saved.valid = 1;
    /* GAP: one save slot, so nested SaveDC calls collapse onto each
     * other and only depth 1 restores correctly. Revisit if a PE is
     * seen nesting them. */
    return 1;
}

__declspec(dllexport) BOOL __stdcall RestoreDC(HDC dc, int saved)
{
    (void)dc;
    (void)saved;
    if (!s_dc_saved.valid)
        return 0;
    s_cur_pen = s_dc_saved.pen;
    s_cur_brush = s_dc_saved.brush;
    s_text_colour = s_dc_saved.text_colour;
    s_bk_colour = s_dc_saved.bk_colour;
    s_cur_x = s_dc_saved.cur_x;
    s_cur_y = s_dc_saved.cur_y;
    s_dc_saved.valid = 0;
    return 1;
}
