/*
 * userland/libs/gdi32/gdi32.c — 44 GDI stubs.
 * No drawing in v0. All Create* / Get* / Select* return NULL
 * handles or pass-through. Draw calls do nothing. GetDC returns
 * a sentinel so callers don't null-check fail immediately.
 */

typedef int            BOOL;
typedef unsigned int   UINT;
typedef int            INT;
typedef unsigned int   DWORD;
typedef unsigned int   COLORREF;
typedef void*          HDC;
typedef void*          HGDIOBJ;
typedef void*          HBITMAP;
typedef void*          HBRUSH;
typedef void*          HFONT;
typedef void*          HPEN;
typedef void*          HANDLE;
typedef unsigned short wchar_t16;

/* --- DC management --- */
/* GetDC returns non-NULL so "HDC dc = GetDC(...)" succeeds; we
 * don't draw on it but subsequent GDI calls are no-ops anyway. */
__declspec(dllexport) HDC GetDC(HANDLE hWnd) { (void) hWnd; return (HDC) 0x10000; }
__declspec(dllexport) HDC GetWindowDC(HANDLE hWnd) { (void) hWnd; return (HDC) 0x10000; }
__declspec(dllexport) INT ReleaseDC(HANDLE hWnd, HDC dc) { (void) hWnd; (void) dc; return 1; }
__declspec(dllexport) HDC CreateCompatibleDC(HDC dc) { (void) dc; return (HDC) 0x10000; }
__declspec(dllexport) BOOL DeleteDC(HDC dc) { (void) dc; return 1; }
__declspec(dllexport) INT SaveDC(HDC dc) { (void) dc; return 1; }
__declspec(dllexport) BOOL RestoreDC(HDC dc, INT saved) { (void) dc; (void) saved; return 1; }

/* --- Object creation --- */
__declspec(dllexport) HBITMAP CreateBitmap(INT w, INT h, UINT planes, UINT bits_per_pel, const void* bits)
{ (void) w; (void) h; (void) planes; (void) bits_per_pel; (void) bits; return (HBITMAP) 0; }
__declspec(dllexport) HBITMAP CreateCompatibleBitmap(HDC dc, INT w, INT h) { (void) dc; (void) w; (void) h; return (HBITMAP) 0; }
__declspec(dllexport) HBITMAP CreateDIBSection(HDC dc, const void* bi, UINT usage, void** bits, HANDLE section, DWORD offset)
{ (void) dc; (void) bi; (void) usage; (void) section; (void) offset; if (bits) *bits = (void*) 0; return (HBITMAP) 0; }
__declspec(dllexport) HBITMAP CreateDIBitmap(HDC dc, const void* header, DWORD init, const void* bits, const void* bi, UINT usage)
{ (void) dc; (void) header; (void) init; (void) bits; (void) bi; (void) usage; return (HBITMAP) 0; }
__declspec(dllexport) HBRUSH CreateBrushIndirect(const void* lb) { (void) lb; return (HBRUSH) 0; }
__declspec(dllexport) HBRUSH CreateSolidBrush(COLORREF clr) { (void) clr; return (HBRUSH) 0; }
__declspec(dllexport) HPEN CreatePen(INT style, INT width, COLORREF clr) { (void) style; (void) width; (void) clr; return (HPEN) 0; }
__declspec(dllexport) HFONT CreateFontA(INT h, INT w, INT esc, INT orient, INT weight, DWORD italic, DWORD underline,
                                       DWORD strikeout, DWORD charset, DWORD out_prec, DWORD clip_prec,
                                       DWORD quality, DWORD pitch, const char* face)
{ (void) h; (void) w; (void) esc; (void) orient; (void) weight; (void) italic; (void) underline;
  (void) strikeout; (void) charset; (void) out_prec; (void) clip_prec; (void) quality; (void) pitch; (void) face;
  return (HFONT) 0; }
__declspec(dllexport) HFONT CreateFontW(INT h, INT w, INT esc, INT orient, INT weight, DWORD italic, DWORD underline,
                                       DWORD strikeout, DWORD charset, DWORD out_prec, DWORD clip_prec,
                                       DWORD quality, DWORD pitch, const wchar_t16* face)
{ (void) h; (void) w; (void) esc; (void) orient; (void) weight; (void) italic; (void) underline;
  (void) strikeout; (void) charset; (void) out_prec; (void) clip_prec; (void) quality; (void) pitch; (void) face;
  return (HFONT) 0; }
__declspec(dllexport) HFONT CreateFontIndirectA(const void* lf) { (void) lf; return (HFONT) 0; }
__declspec(dllexport) HFONT CreateFontIndirectW(const void* lf) { (void) lf; return (HFONT) 0; }

__declspec(dllexport) HGDIOBJ GetStockObject(INT idx) { (void) idx; return (HGDIOBJ) 0; }
__declspec(dllexport) HGDIOBJ SelectObject(HDC dc, HGDIOBJ obj) { (void) dc; (void) obj; return (HGDIOBJ) 0; }
__declspec(dllexport) BOOL DeleteObject(HGDIOBJ obj) { (void) obj; return 1; }
__declspec(dllexport) INT GetObjectA(HGDIOBJ obj, INT cb, void* buf) { (void) obj; (void) cb; (void) buf; return 0; }
__declspec(dllexport) INT GetObjectW(HGDIOBJ obj, INT cb, void* buf) { (void) obj; (void) cb; (void) buf; return 0; }

/* --- Draw calls (all silent no-ops) --- */
__declspec(dllexport) BOOL BitBlt(HDC dst, INT x, INT y, INT w, INT h, HDC src, INT sx, INT sy, DWORD rop)
{ (void) dst; (void) x; (void) y; (void) w; (void) h; (void) src; (void) sx; (void) sy; (void) rop; return 1; }
__declspec(dllexport) BOOL StretchBlt(HDC dst, INT x, INT y, INT w, INT h, HDC src, INT sx, INT sy, INT sw, INT sh, DWORD rop)
{ (void) dst; (void) x; (void) y; (void) w; (void) h; (void) src; (void) sx; (void) sy; (void) sw; (void) sh; (void) rop; return 1; }
__declspec(dllexport) INT DrawTextA(HDC dc, const char* text, INT len, void* r, UINT fmt)
{ (void) dc; (void) text; (void) len; (void) r; (void) fmt; return 0; }
__declspec(dllexport) INT DrawTextW(HDC dc, const wchar_t16* text, INT len, void* r, UINT fmt)
{ (void) dc; (void) text; (void) len; (void) r; (void) fmt; return 0; }
__declspec(dllexport) BOOL ExtTextOutA(HDC dc, INT x, INT y, UINT opts, const void* r, const char* text, UINT len, const INT* dx)
{ (void) dc; (void) x; (void) y; (void) opts; (void) r; (void) text; (void) len; (void) dx; return 1; }
__declspec(dllexport) BOOL ExtTextOutW(HDC dc, INT x, INT y, UINT opts, const void* r, const wchar_t16* text, UINT len, const INT* dx)
{ (void) dc; (void) x; (void) y; (void) opts; (void) r; (void) text; (void) len; (void) dx; return 1; }
__declspec(dllexport) BOOL TextOutA(HDC dc, INT x, INT y, const char* text, INT len)
{ (void) dc; (void) x; (void) y; (void) text; (void) len; return 1; }
__declspec(dllexport) BOOL TextOutW(HDC dc, INT x, INT y, const wchar_t16* text, INT len)
{ (void) dc; (void) x; (void) y; (void) text; (void) len; return 1; }
__declspec(dllexport) INT FillRect(HDC dc, const void* r, HBRUSH br) { (void) dc; (void) r; (void) br; return 1; }
__declspec(dllexport) INT FrameRect(HDC dc, const void* r, HBRUSH br) { (void) dc; (void) r; (void) br; return 1; }
__declspec(dllexport) BOOL LineTo(HDC dc, INT x, INT y) { (void) dc; (void) x; (void) y; return 1; }
__declspec(dllexport) BOOL MoveToEx(HDC dc, INT x, INT y, void* prev) { (void) dc; (void) x; (void) y; (void) prev; return 1; }
__declspec(dllexport) BOOL Polygon(HDC dc, const void* pts, INT n) { (void) dc; (void) pts; (void) n; return 1; }
__declspec(dllexport) BOOL Polyline(HDC dc, const void* pts, INT n) { (void) dc; (void) pts; (void) n; return 1; }
__declspec(dllexport) BOOL Rectangle(HDC dc, INT l, INT t, INT r, INT b) { (void) dc; (void) l; (void) t; (void) r; (void) b; return 1; }
__declspec(dllexport) BOOL Ellipse(HDC dc, INT l, INT t, INT r, INT b) { (void) dc; (void) l; (void) t; (void) r; (void) b; return 1; }

/* --- DC state setters (return "previous value", all 0) --- */
__declspec(dllexport) COLORREF SetBkColor(HDC dc, COLORREF clr) { (void) dc; (void) clr; return 0; }
__declspec(dllexport) INT SetBkMode(HDC dc, INT mode) { (void) dc; (void) mode; return 0; }
__declspec(dllexport) INT SetMapMode(HDC dc, INT mode) { (void) dc; (void) mode; return 0; }
__declspec(dllexport) UINT SetTextAlign(HDC dc, UINT align) { (void) dc; (void) align; return 0; }
__declspec(dllexport) COLORREF SetTextColor(HDC dc, COLORREF clr) { (void) dc; (void) clr; return 0; }
