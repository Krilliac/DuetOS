/*
 * userland/libs/user32_32/user32_32_misc.c
 *
 * The WM-adjacent half of the i386 (PE32) user32 companion DLL:
 * geometry, metrics, paint, focus/activation, input state, caret,
 * clipboard, timers and the resource-loader shims. The window
 * lifecycle, class table and message pump live in user32_32.c.
 *
 * Everything here that a SYS_WIN_* handler backs is a real call.
 * The handful of exports with no kernel surface behind them
 * (icons, cursors, coordinate mapping for child windows) carry a
 * STUB or GAP marker naming what is missing.
 */

#include "user32_32_internal.h"

/* ------------------------------------------------------------------
 * Geometry + metrics
 * ------------------------------------------------------------------ */

/* struct user32_rect lives in user32_32_internal.h — both this TU and
 * user32_32_util.c decode the kernel's rect writes. */

static BOOL user32_get_rect(HWND h, unsigned selector, void* rect)
{
    if (!rect)
        return 0;
    return duet_syscall3(SYS_WIN_GET_RECT, (unsigned)(unsigned long)h, selector, (unsigned)(unsigned long)rect) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall GetClientRect(HWND h, void* rect)
{
    return user32_get_rect(h, 1 /* client */, rect);
}

__declspec(dllexport) BOOL __stdcall GetWindowRect(HWND h, void* rect)
{
    return user32_get_rect(h, 0 /* window */, rect);
}

__declspec(dllexport) INT __stdcall GetSystemMetrics(int index)
{
    return duet_syscall1(SYS_WIN_GET_METRIC, (unsigned)index);
}

/* SYS_WIN_MOVE flags — bit 0 = SWP_NOMOVE, bit 1 = SWP_NOSIZE. */
#define WIN_MOVE_NOMOVE 0x1
#define WIN_MOVE_NOSIZE 0x2

__declspec(dllexport) BOOL __stdcall MoveWindow(HWND h, int x, int y, int w, int ht, BOOL repaint)
{
    const int rv =
        duet_syscall6(SYS_WIN_MOVE, (unsigned)(unsigned long)h, (unsigned)x, (unsigned)y, (unsigned)w, (unsigned)ht, 0);
    if (rv && repaint)
    {
        (void)duet_syscall2(SYS_WIN_INVALIDATE, (unsigned)(unsigned long)h, 0);
    }
    return rv ? 1 : 0;
}

/* Win32 SWP_* bits, in the caller's flag word. */
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002

__declspec(dllexport) BOOL __stdcall SetWindowPos(HWND h, HWND after, int x, int y, int w, int ht, UINT flags)
{
    /* Z-order (`after`) is the compositor's to decide; the only
     * ordering control ring 3 has is SetActiveWindow, which
     * SetForegroundWindow already exposes. */
    (void)after;
    unsigned kflags = 0;
    if (flags & SWP_NOMOVE)
        kflags |= WIN_MOVE_NOMOVE;
    if (flags & SWP_NOSIZE)
        kflags |= WIN_MOVE_NOSIZE;
    return duet_syscall6(SYS_WIN_MOVE, (unsigned)(unsigned long)h, (unsigned)x, (unsigned)y, (unsigned)w, (unsigned)ht,
                         kflags)
               ? 1
               : 0;
}

__declspec(dllexport) BOOL __stdcall SetWindowTextA(HWND h, const char* text)
{
    user32_record_set_title(h, text);
    return duet_syscall2(SYS_WIN_SET_TEXT, (unsigned)(unsigned long)h, (unsigned)(unsigned long)text) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall SetWindowTextW(HWND h, const wchar_t16* text)
{
    char flat[WIN_TITLE_MAX];
    user32_w_to_ascii(text, flat, WIN_TITLE_MAX);
    return SetWindowTextA(h, flat);
}

__declspec(dllexport) HWND __stdcall GetParent(HWND h)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall1(SYS_WIN_GET_PARENT, (unsigned)(unsigned long)h);
}

/* The compositor's client area is the window rect inset by the
 * chrome, and SYS_WIN_GET_RECT reports both, so the two coordinate
 * spaces differ by the window origin plus the title bar. */
static BOOL user32_map_point(HWND h, void* pt, int to_client)
{
    if (!pt)
        return 0;
    struct user32_rect wr = {0, 0, 0, 0};
    struct user32_rect cr = {0, 0, 0, 0};
    if (!user32_get_rect(h, 0, &wr) || !user32_get_rect(h, 1, &cr))
        return 0;
    /* Client height is smaller than window height by exactly the
     * chrome; the horizontal border is the residual width. */
    const INT border = ((wr.right - wr.left) - (cr.right - cr.left)) / 2;
    const INT origin_x = wr.left + border;
    const INT origin_y = wr.bottom - (cr.bottom - cr.top);
    INT* p = (INT*)pt;
    if (to_client)
    {
        p[0] -= origin_x;
        p[1] -= origin_y;
    }
    else
    {
        p[0] += origin_x;
        p[1] += origin_y;
    }
    return 1;
}

__declspec(dllexport) BOOL __stdcall ScreenToClient(HWND h, void* pt)
{
    return user32_map_point(h, pt, 1);
}

__declspec(dllexport) BOOL __stdcall ClientToScreen(HWND h, void* pt)
{
    return user32_map_point(h, pt, 0);
}

/* STUB: the compositor has no desktop-window registration, so there
 * is no HWND that names the root surface. Callers get a non-zero
 * sentinel so "did it succeed?" probes pass, but every SYS_WIN_*
 * call against it is rejected as a foreign handle. */
__declspec(dllexport) HWND __stdcall GetDesktopWindow(void)
{
    return (HWND)0x10001;
}

/* ------------------------------------------------------------------
 * Paint
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL __stdcall InvalidateRect(HWND h, const void* rect, BOOL erase)
{
    /* GAP: the kernel invalidates the whole client area; a partial
     * rect is widened to the full window — revisit when the
     * compositor grows per-rect damage tracking for PE windows. */
    (void)rect;
    return duet_syscall2(SYS_WIN_INVALIDATE, (unsigned)(unsigned long)h, (unsigned)erase) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall ValidateRect(HWND h, const void* rect)
{
    (void)rect;
    return duet_syscall1(SYS_WIN_VALIDATE, (unsigned)(unsigned long)h) ? 1 : 0;
}

/* PAINTSTRUCT on i386: { HDC hdc; BOOL fErase; RECT rcPaint;
 * BOOL fRestore; BOOL fIncUpdate; BYTE rgbReserved[32]; } — 64
 * bytes, versus 72 on x86_64. Only the first three fields carry
 * meaning; rgbReserved is left untouched. */
struct user32_paintstruct32
{
    HDC hdc;
    BOOL fErase;
    struct user32_rect rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
};

__declspec(dllexport) HDC __stdcall GetDC(HWND h)
{
    /* The HDC is the HWND with the GDI tag folded in, so a later
     * draw call can recover the target window from the DC alone.
     * Mirrors the 64-bit pair's encoding, narrowed to fit a 32-bit
     * handle. */
    return (HDC)(unsigned long)((unsigned)(unsigned long)h | DUET32_GDI_HDC_TAG);
}

__declspec(dllexport) HDC __stdcall GetWindowDC(HWND h)
{
    return GetDC(h);
}

__declspec(dllexport) INT __stdcall ReleaseDC(HWND h, HDC dc)
{
    /* Window DCs are pure handle arithmetic — nothing to release. */
    (void)h;
    (void)dc;
    return 1;
}

__declspec(dllexport) HDC __stdcall BeginPaint(HWND h, void* ps)
{
    HDC hdc = GetDC(h);
    if (ps)
    {
        struct user32_paintstruct32* p = (struct user32_paintstruct32*)ps;
        p->hdc = hdc;
        p->fErase = 1;
        p->rcPaint.left = 0;
        p->rcPaint.top = 0;
        p->rcPaint.right = 0;
        p->rcPaint.bottom = 0;
        (void)user32_get_rect(h, 1 /* client */, &p->rcPaint);
        p->fRestore = 0;
        p->fIncUpdate = 0;
    }
    /* The caller has promised to paint, so drop the dirty bit now —
     * otherwise the next pump drain posts a second WM_PAINT and the
     * app repaints forever. */
    (void)duet_syscall1(SYS_WIN_VALIDATE, (unsigned)(unsigned long)h);
    return hdc;
}

__declspec(dllexport) BOOL __stdcall EndPaint(HWND h, const void* ps)
{
    /* BeginPaint already validated; the display list the paint
     * recorded is replayed by the compositor on its own schedule. */
    (void)h;
    (void)ps;
    return 1;
}

/* ------------------------------------------------------------------
 * The drawing calls Windows homes in USER32
 *
 * FillRect / FrameRect / DrawText are USER32 exports, so an importer
 * resolves them here and never reaches gdi32. They record the same
 * display-list primitives gdi32_32 does, decoding the shared brush
 * and HDC encodings from duet32_gdi_abi.h.
 * ------------------------------------------------------------------ */

static BOOL user32_rect_primitive(int nr, HDC dc, const struct user32_rect* rc, unsigned colour)
{
    const unsigned hwnd = Duet32HwndFromHdc(dc);
    if (!hwnd || !rc)
        return 0;
    const INT w = rc->right - rc->left;
    const INT h = rc->bottom - rc->top;
    if (w <= 0 || h <= 0)
        return 1;
    return duet_syscall6(nr, hwnd, (unsigned)rc->left, (unsigned)rc->top, (unsigned)w, (unsigned)h, colour) ? 1 : 0;
}

__declspec(dllexport) INT __stdcall FillRect(HDC dc, const void* rect, HANDLE brush)
{
    return user32_rect_primitive(SYS_GDI_FILL_RECT, dc, (const struct user32_rect*)rect,
                                 Duet32GdiObjectColour(brush, DUET32_GDI_BRUSH_TAG));
}

__declspec(dllexport) INT __stdcall FrameRect(HDC dc, const void* rect, HANDLE brush)
{
    return user32_rect_primitive(SYS_GDI_RECTANGLE, dc, (const struct user32_rect*)rect,
                                 Duet32GdiObjectColour(brush, DUET32_GDI_BRUSH_TAG));
}

/* DrawText anchors at the rect's top-left. GAP: no word wrap, no
 * alignment flags, no multi-line layout — mirrors gdi32_32's
 * DrawText and lifts when the display list grows a text layout
 * primitive. */
static BOOL user32_draw_text(HDC dc, const char* text, unsigned len, const struct user32_rect* rc)
{
    const unsigned hwnd = Duet32HwndFromHdc(dc);
    if (!hwnd || !text || !rc)
        return 0;
    return duet_syscall6(SYS_GDI_TEXT_OUT, hwnd, (unsigned)rc->left, (unsigned)rc->top, (unsigned)(unsigned long)text,
                         len, 0x00FFFFFFu)
               ? 1
               : 0;
}

__declspec(dllexport) INT __stdcall DrawTextA(HDC dc, const char* text, int len, void* rect, UINT format)
{
    (void)format;
    if (!text)
        return 0;
    unsigned n = 0;
    if (len >= 0)
    {
        n = (unsigned)len;
    }
    else
    {
        while (text[n])
            ++n;
    }
    return user32_draw_text(dc, text, n, (const struct user32_rect*)rect) ? 1 : 0;
}

__declspec(dllexport) INT __stdcall DrawTextW(HDC dc, const wchar_t16* text, int len, void* rect, UINT format)
{
    (void)format;
    char flat[256];
    const unsigned cap = sizeof(flat) - 1;
    const unsigned limit = (len < 0) ? cap : ((unsigned)len < cap ? (unsigned)len : cap);
    unsigned n = 0;
    if (text)
    {
        for (; n < limit && text[n] != 0; ++n)
        {
            wchar_t16 c = text[n];
            flat[n] = (c > 0 && c < 0x7F) ? (char)c : '?';
        }
    }
    flat[n] = '\0';
    return user32_draw_text(dc, flat, n, (const struct user32_rect*)rect) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Focus / activation
 * ------------------------------------------------------------------ */

__declspec(dllexport) HWND __stdcall GetFocus(void)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall0(SYS_WIN_GET_FOCUS);
}

__declspec(dllexport) HWND __stdcall SetFocus(HWND h)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall1(SYS_WIN_SET_FOCUS, (unsigned)(unsigned long)h);
}

__declspec(dllexport) HWND __stdcall GetActiveWindow(void)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall0(SYS_WIN_GET_ACTIVE);
}

__declspec(dllexport) HWND __stdcall SetActiveWindow(HWND h)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall1(SYS_WIN_SET_ACTIVE, (unsigned)(unsigned long)h);
}

__declspec(dllexport) HWND __stdcall GetForegroundWindow(void)
{
    return GetActiveWindow();
}

__declspec(dllexport) BOOL __stdcall SetForegroundWindow(HWND h)
{
    (void)SetActiveWindow(h);
    return 1;
}

/* ------------------------------------------------------------------
 * Input state
 * ------------------------------------------------------------------ */

__declspec(dllexport) SHORT __stdcall GetKeyState(int vk)
{
    return (SHORT)duet_syscall1(SYS_WIN_GET_KEYSTATE, (unsigned)vk);
}

__declspec(dllexport) SHORT __stdcall GetAsyncKeyState(int vk)
{
    return GetKeyState(vk);
}

__declspec(dllexport) BOOL __stdcall GetCursorPos(void* pt)
{
    if (!pt)
        return 0;
    return duet_syscall1(SYS_WIN_GET_CURSOR, (unsigned)(unsigned long)pt) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall SetCursorPos(int x, int y)
{
    return duet_syscall2(SYS_WIN_SET_CURSOR, (unsigned)x, (unsigned)y) ? 1 : 0;
}

__declspec(dllexport) HWND __stdcall SetCapture(HWND h)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall1(SYS_WIN_SET_CAPTURE, (unsigned)(unsigned long)h);
}

__declspec(dllexport) BOOL __stdcall ReleaseCapture(void)
{
    return duet_syscall0(SYS_WIN_RELEASE_CAPTURE) ? 1 : 0;
}

__declspec(dllexport) HWND __stdcall GetCapture(void)
{
    return (HWND)(unsigned long)(unsigned)duet_syscall0(SYS_WIN_GET_CAPTURE);
}

/* STUB: cursor shapes are the compositor's, not the app's — there
 * is no per-window cursor selection to set, so the previous cursor
 * reported back is always NULL. */
__declspec(dllexport) HCURSOR __stdcall SetCursor(HCURSOR cursor)
{
    (void)cursor;
    return (HCURSOR)0;
}

/* ------------------------------------------------------------------
 * Timers
 * ------------------------------------------------------------------ */

__declspec(dllexport) UINT __stdcall SetTimer(HWND h, UINT id, UINT interval_ms, void* proc)
{
    /* GAP: a non-null TIMERPROC is ignored — WM_TIMER is posted to
     * the window queue and the pump dispatches it through the
     * WNDPROC instead. Revisit if a PE is seen relying on the
     * callback form. */
    (void)proc;
    return (UINT)duet_syscall3(SYS_WIN_TIMER_SET, (unsigned)(unsigned long)h, id, interval_ms);
}

__declspec(dllexport) BOOL __stdcall KillTimer(HWND h, UINT id)
{
    return duet_syscall2(SYS_WIN_TIMER_KILL, (unsigned)(unsigned long)h, id) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Caret
 * ------------------------------------------------------------------ */

static BOOL user32_caret_op(unsigned op, unsigned a1, unsigned a2, unsigned a3)
{
    return duet_syscall4(SYS_WIN_CARET, op, a1, a2, a3) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall CreateCaret(HWND h, HANDLE bitmap, int w, int ht)
{
    /* A bitmap caret would need a GDI object the compositor can
     * blit; the kernel draws a solid block instead. */
    (void)bitmap;
    return user32_caret_op(0, (unsigned)w, (unsigned)ht, (unsigned)(unsigned long)h);
}

__declspec(dllexport) BOOL __stdcall DestroyCaret(void)
{
    return user32_caret_op(1, 0, 0, 0);
}

__declspec(dllexport) BOOL __stdcall SetCaretPos(int x, int y)
{
    return user32_caret_op(2, (unsigned)x, (unsigned)y, 0);
}

__declspec(dllexport) BOOL __stdcall ShowCaret(HWND h)
{
    (void)h;
    return user32_caret_op(3, 0, 0, 0);
}

__declspec(dllexport) BOOL __stdcall HideCaret(HWND h)
{
    (void)h;
    return user32_caret_op(4, 0, 0, 0);
}

/* The caret blink rate is a fixed compositor property; there is no
 * per-process setting to read back or change. */
__declspec(dllexport) UINT __stdcall GetCaretBlinkTime(void)
{
    return 500;
}

__declspec(dllexport) BOOL __stdcall SetCaretBlinkTime(UINT msec)
{
    // STUB: the compositor's blink period is fixed; the request is
    // accepted and discarded.
    (void)msec;
    return 1;
}

/* ------------------------------------------------------------------
 * Clipboard
 *
 * The kernel owns one system-wide text clipboard. Open/Close/Empty
 * exist only to satisfy the Win32 protocol — there is no ownership
 * to arbitrate with a single clipboard and no other claimant.
 * ------------------------------------------------------------------ */

#define CF_TEXT 1

__declspec(dllexport) BOOL __stdcall OpenClipboard(HWND owner)
{
    (void)owner;
    return 1;
}

__declspec(dllexport) BOOL __stdcall CloseClipboard(void)
{
    return 1;
}

__declspec(dllexport) BOOL __stdcall EmptyClipboard(void)
{
    static const char empty[1] = {'\0'};
    return duet_syscall1(SYS_WIN_CLIP_SET_TEXT, (unsigned)(unsigned long)empty) ? 1 : 0;
}

/* GetClipboardData hands back an HGLOBAL the caller may read. The
 * shadow buffer is refilled on every call, matching Win32's
 * "copy it out before the next call, do not free it" convention. */
static char s_clipboard_shadow[1024];

__declspec(dllexport) HANDLE __stdcall GetClipboardData(UINT fmt)
{
    if (fmt != CF_TEXT)
        return (HANDLE)0;
    s_clipboard_shadow[0] = '\0';
    (void)duet_syscall2(SYS_WIN_CLIP_GET_TEXT, (unsigned)(unsigned long)s_clipboard_shadow,
                        (unsigned)sizeof(s_clipboard_shadow));
    /* An empty clipboard reads back as an empty C string, which is
     * what a strlen-style caller expects. */
    return (HANDLE)s_clipboard_shadow;
}

__declspec(dllexport) HANDLE __stdcall SetClipboardData(UINT fmt, HANDLE data)
{
    if (fmt != CF_TEXT || !data)
        return (HANDLE)0;
    (void)duet_syscall1(SYS_WIN_CLIP_SET_TEXT, (unsigned)(unsigned long)data);
    return data;
}

/* ------------------------------------------------------------------
 * Message box + resources
 * ------------------------------------------------------------------ */

__declspec(dllexport) INT __stdcall MessageBoxA(HWND owner, const char* text, const char* caption, UINT type)
{
    (void)owner;
    (void)type;
    /* No modal dialog is drawn: the kernel records the text as a
     * [msgbox] serial line and reports IDOK so the caller continues
     * down its "user clicked OK" path. */
    (void)duet_syscall2(SYS_WIN_MSGBOX, (unsigned)(unsigned long)text, (unsigned)(unsigned long)caption);
    return 1; /* IDOK */
}

__declspec(dllexport) INT __stdcall MessageBoxW(HWND owner, const wchar_t16* text, const wchar_t16* caption, UINT type)
{
    char flat_text[256];
    char flat_caption[WIN_TITLE_MAX];
    user32_w_to_ascii(text, flat_text, sizeof(flat_text));
    user32_w_to_ascii(caption, flat_caption, sizeof(flat_caption));
    return MessageBoxA(owner, flat_text, flat_caption, type);
}

/* LoadIcon/LoadCursor — REAL for system resources (NULL hInstance
 * returns sentinel); REAL for PE resources (decode .rsrc, register
 * icon as GDI bitmap or cursor via SYS_GDI_CREATE_CURSOR_RGBA).
 * See userland/libs/user32/user32.c for the matching 64-bit impl. */

#define IDC_ARROW_32 32512

/* Forward-declare — pe_resources.h is included below for LoadString. */
#include "../common/pe_resources.h"

#define SYS_GDI_CREATE_COMPAT_BITMAP 107
#define SYS_GDI_SET_DIBITS 214
#define SYS_GDI_CREATE_CURSOR_RGBA 224

static HICON __stdcall user32_32_load_icon_impl(HINSTANCE inst, unsigned long name_id)
{
    if (inst == (HINSTANCE)0)
        return (HICON)1; /* system icon sentinel */
    if (name_id == 0 || name_id > 0xFFFF)
        return (HICON)1;
    {
        DUET_RES_VIEW view;
        unsigned int icon_id = 0;
        unsigned int iw = 0, ih = 0;
        const void* base = (const void*)inst;
        if (!duet_res_init(base, &view))
            return (HICON)1;
        if (!duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, name_id, 32, 32, &icon_id, &iw, &ih))
            return (HICON)1;
        if (iw == 0 || ih == 0 || iw > 64 || ih > 64)
            return (HICON)1;
        {
            static unsigned char bgra[64 * 64 * 4];
            if (!duet_res_decode_icon(&view, DUET_RES_TYPE_ICON, icon_id, iw, ih, bgra, 64 * 64, (unsigned int*)0,
                                      (unsigned int*)0))
                return (HICON)1;
            {
                int bmp_h = duet_syscall3(SYS_GDI_CREATE_COMPAT_BITMAP, 0, iw, ih);
                if (bmp_h == 0)
                    return (HICON)1;
                duet_syscall6(SYS_GDI_SET_DIBITS, (unsigned)bmp_h, (unsigned)(unsigned long)bgra, iw, ih, 32, iw * 4);
                return (HICON)(unsigned long)bmp_h;
            }
        }
    }
}

__declspec(dllexport) HICON __stdcall LoadIconA(HINSTANCE inst, const char* name)
{
    return user32_32_load_icon_impl(inst, (unsigned long)(unsigned long)name);
}

__declspec(dllexport) HICON __stdcall LoadIconW(HINSTANCE inst, const wchar_t16* name)
{
    return user32_32_load_icon_impl(inst, (unsigned long)(unsigned long)name);
}

static HCURSOR __stdcall user32_32_load_cursor_impl(HINSTANCE inst, unsigned long name_id)
{
    if (inst == (HINSTANCE)0)
    {
        if (name_id == 0 || name_id > 0xFFFF)
            return (HCURSOR)IDC_ARROW_32;
        return (HCURSOR)name_id;
    }
    if (name_id == 0 || name_id > 0xFFFF)
        return (HCURSOR)IDC_ARROW_32;
    {
        DUET_RES_VIEW view;
        unsigned int cursor_id = 0;
        unsigned int cw = 0, ch = 0;
        const void* base = (const void*)inst;
        if (!duet_res_init(base, &view))
            return (HCURSOR)IDC_ARROW_32;
        if (!duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_CURSOR, name_id, 32, 32, &cursor_id, &cw, &ch))
            return (HCURSOR)IDC_ARROW_32;
        if (cw == 0 || ch == 0 || cw > 64 || ch > 64)
            return (HCURSOR)IDC_ARROW_32;
        {
            static unsigned char bgra[64 * 64 * 4];
            unsigned int x_hot = 0, y_hot = 0;
            if (!duet_res_decode_icon(&view, DUET_RES_TYPE_CURSOR, cursor_id, cw, ch, bgra, 64 * 64, &x_hot, &y_hot))
                return (HCURSOR)IDC_ARROW_32;
            {
                unsigned packed_dim = cw | (ch << 16);
                unsigned packed_hot = (x_hot & 0xFF) | ((y_hot & 0xFF) << 8);
                int result =
                    duet_syscall3(SYS_GDI_CREATE_CURSOR_RGBA, (unsigned)(unsigned long)bgra, packed_dim, packed_hot);
                if (result > 0)
                    return (HCURSOR)(unsigned long)result;
            }
        }
    }
    return (HCURSOR)IDC_ARROW_32;
}

__declspec(dllexport) HCURSOR __stdcall LoadCursorA(HINSTANCE inst, const char* name)
{
    return user32_32_load_cursor_impl(inst, (unsigned long)(unsigned long)name);
}

__declspec(dllexport) HCURSOR __stdcall LoadCursorW(HINSTANCE inst, const wchar_t16* name)
{
    return user32_32_load_cursor_impl(inst, (unsigned long)(unsigned long)name);
}

/* LoadImage — unified loader for IMAGE_ICON, IMAGE_CURSOR, IMAGE_BITMAP. */
#define IMAGE_BITMAP_32 0
#define IMAGE_ICON_32 1
#define IMAGE_CURSOR_32 2

/* LoadBitmap — decode RT_BITMAP (a packed DIB with no BITMAPFILEHEADER)
 * from the module's .rsrc into BGRA and create a GDI bitmap via the same
 * SYS_GDI_CREATE_COMPAT_BITMAP + SET_DIBITS pair user32_32_load_icon_impl
 * uses. NULL on any failure: Win32 has no system-bitmap fallback the way
 * LoadIcon/LoadCursor have system shapes, so failing closed with NULL is
 * the documented contract. See userland/libs/user32/user32.c for the
 * matching 64-bit impl. */
static HANDLE __stdcall user32_32_load_bitmap_impl(HINSTANCE inst, unsigned long name_id)
{
    if (inst == (HINSTANCE)0)
        return (HANDLE)0; /* no module -> no .rsrc to decode */
    /* GAP: named (string) RT_BITMAP resources unimplemented — integer
     * ordinals only, same as LoadIcon/LoadCursor — revisit when a
     * by-name caller appears. */
    if (name_id == 0 || name_id > 0xFFFF)
        return (HANDLE)0;
    {
        DUET_RES_VIEW view;
        unsigned int bw = 0, bh = 0, bpp = 0;
        const void* base = (const void*)inst;
        if (!duet_res_init(base, &view))
            return (HANDLE)0;
        if (!duet_res_bitmap_info(&view, (unsigned int)name_id, &bw, &bh, &bpp))
            return (HANDLE)0;
        /* GAP: bitmaps larger than 128x128 rejected (static decode
         * buffer, 64 KiB) — revisit when a caller ships bigger art. */
        if (bw == 0 || bh == 0 || bw > 128 || bh > 128)
            return (HANDLE)0;
        {
            static unsigned char bgra[128 * 128 * 4];
            if (!duet_res_decode_bitmap(&view, (unsigned int)name_id, bgra, 128 * 128, (unsigned int*)0,
                                        (unsigned int*)0))
                return (HANDLE)0;
            /* Create a GDI bitmap and upload the decoded pixels — the
             * same two syscalls user32_32_load_icon_impl uses. */
            {
                int bmp_h = duet_syscall3(SYS_GDI_CREATE_COMPAT_BITMAP, 0, bw, bh);
                if (bmp_h == 0)
                    return (HANDLE)0;
                duet_syscall6(SYS_GDI_SET_DIBITS, (unsigned)bmp_h, (unsigned)(unsigned long)bgra, bw, bh, 32, bw * 4);
                return (HANDLE)(unsigned long)bmp_h;
            }
        }
    }
}

__declspec(dllexport) HANDLE __stdcall LoadBitmapA(HINSTANCE inst, const char* name)
{
    return user32_32_load_bitmap_impl(inst, (unsigned long)(unsigned long)name);
}
__declspec(dllexport) HANDLE __stdcall LoadBitmapW(HINSTANCE inst, const wchar_t16* name)
{
    return user32_32_load_bitmap_impl(inst, (unsigned long)(unsigned long)name);
}
// STUB: returns NULL - RT_ACCELERATOR needs KeyCode->VK translation.
__declspec(dllexport) HANDLE __stdcall LoadAcceleratorsA(HINSTANCE inst, const char* name)
{
    (void)inst;
    (void)name;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE __stdcall LoadAcceleratorsW(HINSTANCE inst, const wchar_t16* name)
{
    (void)inst;
    (void)name;
    return (HANDLE)0;
}

__declspec(dllexport) HANDLE __stdcall LoadImageA(HINSTANCE inst, const char* name, unsigned type, int w, int h,
                                                  unsigned flags)
{
    (void)w;
    (void)h;
    (void)flags;
    /* GAP: LR_DEFAULTSIZE, LR_SHARED, LR_LOADFROMFILE not implemented — revisit when file-load is needed. */
    if (type == IMAGE_ICON_32)
        return (HANDLE)LoadIconA(inst, name);
    if (type == IMAGE_CURSOR_32)
        return (HANDLE)LoadCursorA(inst, name);
    return (HANDLE)LoadBitmapA(inst, name);
}

__declspec(dllexport) HANDLE __stdcall LoadImageW(HINSTANCE inst, const wchar_t16* name, unsigned type, int w, int h,
                                                  unsigned flags)
{
    (void)w;
    (void)h;
    (void)flags;
    /* GAP: LR_DEFAULTSIZE, LR_SHARED, LR_LOADFROMFILE not implemented — revisit when file-load is needed. */
    if (type == IMAGE_ICON_32)
        return (HANDLE)LoadIconW(inst, name);
    if (type == IMAGE_CURSOR_32)
        return (HANDLE)LoadCursorW(inst, name);
    return (HANDLE)LoadBitmapW(inst, name);
}

/* ------------------------------------------------------------------
 * String resources
 *
 * The i386 half of LoadString, over the shared `.rsrc` walker. See
 * userland/libs/user32/user32.c for why user32 resolves the module
 * base itself rather than importing kernel32!GetModuleHandleW: these
 * DLLs link with /nodefaultlib and import nothing.
 * ------------------------------------------------------------------ */

/* pe_resources.h already included above for LoadIcon/LoadCursor. */

#define SYS_DLL_BASE_BY_NAME 172

static const void* user32_exe_base(void)
{
    static const char kEmpty[1] = {0};
    const unsigned rv = (unsigned)duet_syscall2(SYS_DLL_BASE_BY_NAME, (unsigned)(unsigned long)kEmpty, 0u);
    return (const void*)(unsigned long)rv;
}

static int user32_string_view(HINSTANCE inst, DUET_RES_VIEW* view)
{
    const void* base = (const void*)inst;
    if (base == (const void*)0)
        base = user32_exe_base();
    if (base == (const void*)0)
        return 0;
    return duet_res_init(base, view);
}

/* LoadStringW. cchBufferMax == 0 is the documented pointer-return
 * form: lpBuffer is treated as an LPWSTR* and receives the address of
 * the (unterminated) resource string. */
__declspec(dllexport) INT __stdcall LoadStringW(HINSTANCE inst, UINT id, wchar_t16* buf, INT len)
{
    DUET_RES_VIEW view;
    const unsigned short* chars;
    unsigned int chars_len;
    INT i;

    if (!buf || len < 0)
        return 0;
    if (!user32_string_view(inst, &view))
        return 0;
    if (!duet_res_find_string(&view, id, 0, 0, &chars, &chars_len))
        return 0;

    if (len == 0)
    {
        *(const wchar_t16**)(void*)buf = (const wchar_t16*)chars;
        return (INT)chars_len;
    }
    for (i = 0; i < len - 1 && (unsigned int)i < chars_len; ++i)
        buf[i] = (wchar_t16)chars[i];
    buf[i] = 0;
    return i;
}

/* GAP: narrowing is Latin-1 truncation, not a codepage conversion — a
 * code unit above 0xFF becomes '?'. Revisit when the NLS layer grows a
 * shared WideCharToMultiByte. */
__declspec(dllexport) INT __stdcall LoadStringA(HINSTANCE inst, UINT id, char* buf, INT len)
{
    DUET_RES_VIEW view;
    const unsigned short* chars;
    unsigned int chars_len;
    INT i;

    if (!buf || len <= 0)
        return 0;
    if (!user32_string_view(inst, &view))
        return 0;
    if (!duet_res_find_string(&view, id, 0, 0, &chars, &chars_len))
        return 0;

    for (i = 0; i < len - 1 && (unsigned int)i < chars_len; ++i)
        buf[i] = (chars[i] < 0x100u) ? (char)(unsigned char)chars[i] : '?';
    buf[i] = 0;
    return i;
}
