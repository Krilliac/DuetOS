#include "gdi_objects.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/process.h"
#include "../../drivers/video/font8x8.h"
#include "../../drivers/video/framebuffer.h"
#include "../../drivers/video/theme.h"
#include "../../drivers/video/widget.h"
#include "../../mm/kheap.h"
#include "../../mm/paging.h"
#include "window_syscall.h"

namespace duetos::subsystems::win32
{

namespace
{

constinit MemDC g_mem_dcs[kMaxMemDcs] = {};
constinit Bitmap g_bitmaps[kMaxBitmaps] = {};
constinit Brush g_brushes[kMaxBrushes] = {};
constinit Pen g_pens[kMaxPens] = {};
constinit WindowDcState g_win_dcs[kMaxWindowDcSlots] = {};

// First six brush slots are pre-allocated for stock brushes. Their
// indices (0..5) match the Win32 GetStockObject codes so the
// mapping is trivial.
constinit bool g_init_done = false;

u32 HandleIndex(u64 h)
{
    return static_cast<u32>(h & 0xFFFFu);
}

u64 MakeHandle(u64 tag, u32 index)
{
    return tag | static_cast<u64>(index);
}

} // namespace

u64 GdiHandleType(u64 h)
{
    const u64 tag = h & kGdiTagMask;
    if (tag == kGdiTagMemDC || tag == kGdiTagBitmap || tag == kGdiTagBrush)
        return tag;
    return 0;
}

MemDC* GdiLookupMemDC(u64 h)
{
    if ((h & kGdiTagMask) != kGdiTagMemDC)
        return nullptr;
    const u32 idx = HandleIndex(h);
    if (idx >= kMaxMemDcs || !g_mem_dcs[idx].alive)
        return nullptr;
    return &g_mem_dcs[idx];
}

Bitmap* GdiLookupBitmap(u64 h)
{
    if ((h & kGdiTagMask) != kGdiTagBitmap)
        return nullptr;
    const u32 idx = HandleIndex(h);
    if (idx >= kMaxBitmaps || !g_bitmaps[idx].alive)
        return nullptr;
    return &g_bitmaps[idx];
}

Brush* GdiLookupBrush(u64 h)
{
    if ((h & kGdiTagMask) != kGdiTagBrush)
        return nullptr;
    const u32 idx = HandleIndex(h);
    if (idx >= kMaxBrushes || !g_brushes[idx].alive)
        return nullptr;
    return &g_brushes[idx];
}

Pen* GdiLookupPen(u64 h)
{
    if ((h & kGdiTagMask) != kGdiTagPen)
        return nullptr;
    const u32 idx = HandleIndex(h);
    if (idx >= kMaxPens || !g_pens[idx].alive)
        return nullptr;
    return &g_pens[idx];
}

WindowDcState* GdiWindowDcState(u32 window_handle)
{
    if (window_handle >= kMaxWindowDcSlots)
        return nullptr;
    WindowDcState* s = &g_win_dcs[window_handle];
    if (!s->init)
    {
        s->init = true;
        s->text_color = 0x00000000;
        s->bk_color = 0x00FFFFFF;
        s->bk_mode = kBkModeOpaque;
        s->selected_pen = 0;
        s->selected_brush = 0;
        s->cur_x = 0;
        s->cur_y = 0;
    }
    return s;
}

namespace
{

// Win32 Classic-theme palette. 31 slots covers COLOR_SCROLLBAR..
// COLOR_MENUBAR. COLORREF layout: (R) | (G<<8) | (B<<16), Win32
// 0x00BBGGRR byte order in memory. Values lifted from a Windows
// XP Classic theme reference — close enough for PEs that want
// "system-looking" colours without a theming engine.
constexpr u32 kSysColorCount = 31;
constexpr u32 kSysColorMap[kSysColorCount] = {
    0x00D4D0C8, // 0  COLOR_SCROLLBAR
    0x00000000, // 1  COLOR_BACKGROUND / DESKTOP
    0x00000099, // 2  COLOR_ACTIVECAPTION (classic blue title)
    0x00808080, // 3  COLOR_INACTIVECAPTION
    0x00FFFFFF, // 4  COLOR_MENU
    0x00FFFFFF, // 5  COLOR_WINDOW
    0x00000000, // 6  COLOR_WINDOWFRAME
    0x00000000, // 7  COLOR_MENUTEXT
    0x00000000, // 8  COLOR_WINDOWTEXT
    0x00FFFFFF, // 9  COLOR_CAPTIONTEXT
    0x00B4B4B4, // 10 COLOR_ACTIVEBORDER
    0x00B4B4B4, // 11 COLOR_INACTIVEBORDER
    0x00ABABAB, // 12 COLOR_APPWORKSPACE
    0x00C56A31, // 13 COLOR_HIGHLIGHT (classic XP blue selection)
    0x00FFFFFF, // 14 COLOR_HIGHLIGHTTEXT
    0x00F0F0F0, // 15 COLOR_BTNFACE
    0x00A0A0A0, // 16 COLOR_BTNSHADOW
    0x006D6D6D, // 17 COLOR_GRAYTEXT
    0x00000000, // 18 COLOR_BTNTEXT
    0x00000000, // 19 COLOR_INACTIVECAPTIONTEXT
    0x00FFFFFF, // 20 COLOR_BTNHIGHLIGHT
    0x00696969, // 21 COLOR_3DDKSHADOW
    0x00E3E3E3, // 22 COLOR_3DLIGHT
    0x00000000, // 23 COLOR_INFOTEXT
    0x00E1FFFF, // 24 COLOR_INFOBK
    0x00C0C0C0, // 25 (reserved)
    0x0000CC66, // 26 COLOR_HOTLIGHT
    0x00D7E4F2, // 27 COLOR_GRADIENTACTIVECAPTION
    0x00C5C5C5, // 28 COLOR_GRADIENTINACTIVECAPTION
    0x00C56A31, // 29 COLOR_MENUHILIGHT
    0x00F0F0F0, // 30 COLOR_MENUBAR
};

// HBRUSH handle per sys-colour slot, filled lazily the first time
// `GdiSysColorBrush` is queried for that index. Shared system-wide
// and DeleteObject'd as a no-op (the brush slots are ordinary
// non-stock entries in the brush table, so we mark them `.stock =
// true` when we allocate them so DeleteObject ignores them — same
// trick the real stock brushes use).
constinit u64 g_sys_color_brushes[kSysColorCount] = {};

} // namespace

u32 GdiSysColor(u32 index)
{
    if (index >= kSysColorCount)
        return 0x00C0C0C0;
    return kSysColorMap[index];
}

u64 GdiSysColorBrush(u32 index)
{
    if (index >= kSysColorCount)
        return 0;
    if (g_sys_color_brushes[index] != 0)
        return g_sys_color_brushes[index];
    const u64 h = GdiCreateSolidBrush(kSysColorMap[index]);
    if (h == 0)
        return 0;
    // Mark it stock so DeleteObject is a no-op.
    Brush* b = GdiLookupBrush(h);
    if (b != nullptr)
        b->stock = true;
    g_sys_color_brushes[index] = h;
    return h;
}

void GdiInit()
{
    if (g_init_done)
        return;
    g_init_done = true;

    // Stock brushes. Indices 0..5 reserved — later CreateSolidBrush
    // allocations start at 6.
    auto stock = [](u32 slot, u32 rgb, bool present)
    {
        g_brushes[slot].alive = present;
        g_brushes[slot].rgb = rgb;
        g_brushes[slot].stock = true;
    };
    stock(kStockWhiteBrush, 0x00FFFFFF, true);
    stock(kStockLtGrayBrush, 0x00C0C0C0, true);
    stock(kStockGrayBrush, 0x00808080, true);
    stock(kStockDkGrayBrush, 0x00404040, true);
    stock(kStockBlackBrush, 0x00000000, true);
    stock(kStockNullBrush, 0x00000000, true); // NULL brush — no-op fill

    auto stock_pen = [](u32 slot, u32 rgb, bool present)
    {
        // Stock pen slots live in the pen table at indices matching
        // their GetStockObject codes (6..8). Non-stock CreatePen
        // calls start from slot 9.
        g_pens[slot].alive = present;
        g_pens[slot].rgb = rgb;
        g_pens[slot].width = 1;
        g_pens[slot].stock = true;
    };
    stock_pen(kStockWhitePen, 0x00FFFFFF, true);
    stock_pen(kStockBlackPen, 0x00000000, true);
    stock_pen(kStockNullPen, 0x00000000, true); // NULL pen — skip draw

    arch::SerialWrite("[gdi] stock objects registered (6 brushes, 3 pens)\n");
}

u64 GdiCreateCompatibleDC()
{
    for (u32 i = 0; i < kMaxMemDcs; ++i)
    {
        if (!g_mem_dcs[i].alive)
        {
            g_mem_dcs[i].alive = true;
            g_mem_dcs[i].selected_bitmap = 0;
            // Win32 DC defaults: text = black, bk = white, bk_mode =
            // OPAQUE. (Our boot-time compositor paints glyphs white
            // on transparent, but the real Win32 default is the
            // opposite — black on white opaque. Match Win32 so PEs
            // that skip SetTextColor still render readably.)
            g_mem_dcs[i].text_color = 0x00000000;
            g_mem_dcs[i].bk_color = 0x00FFFFFF;
            g_mem_dcs[i].bk_mode = kBkModeOpaque;
            g_mem_dcs[i].selected_pen = 0;   // implicit BLACK_PEN
            g_mem_dcs[i].selected_brush = 0; // implicit WHITE_BRUSH
            g_mem_dcs[i].cur_x = 0;
            g_mem_dcs[i].cur_y = 0;
            return MakeHandle(kGdiTagMemDC, i);
        }
    }
    return 0;
}

u64 GdiCreateCompatibleBitmap(u32 width, u32 height)
{
    if (width == 0 || height == 0)
        return 0;
    const u64 pixels = static_cast<u64>(width) * static_cast<u64>(height);
    if (pixels > kMaxBitmapPixels)
        return 0;
    const u64 bytes = pixels * 4;
    u32* buf = static_cast<u32*>(duetos::mm::KMalloc(bytes));
    if (buf == nullptr)
        return 0;
    // Zero-init so new bitmaps start fully black/transparent; avoids
    // leaking kernel heap bytes.
    for (u64 i = 0; i < pixels; ++i)
        buf[i] = 0;

    for (u32 i = 0; i < kMaxBitmaps; ++i)
    {
        if (!g_bitmaps[i].alive)
        {
            g_bitmaps[i].alive = true;
            g_bitmaps[i].width = width;
            g_bitmaps[i].height = height;
            g_bitmaps[i].pitch = width * 4;
            g_bitmaps[i].pixels = buf;
            return MakeHandle(kGdiTagBitmap, i);
        }
    }
    duetos::mm::KFree(buf);
    return 0;
}

u64 GdiCreateSolidBrush(u32 rgb)
{
    // Search from slot 6 — 0..5 are reserved for stock brushes.
    for (u32 i = 6; i < kMaxBrushes; ++i)
    {
        if (!g_brushes[i].alive)
        {
            g_brushes[i].alive = true;
            g_brushes[i].rgb = rgb;
            g_brushes[i].stock = false;
            return MakeHandle(kGdiTagBrush, i);
        }
    }
    return 0;
}

u64 GdiGetStockObject(u32 index)
{
    // Brush slots 0..5 live in the brush table; pen slots 6..8 in
    // the pen table. The handle tag lets SelectObject discriminate
    // without a branch here.
    if (index <= kStockNullBrush)
    {
        if (!g_brushes[index].alive)
            return 0;
        return MakeHandle(kGdiTagBrush, index);
    }
    if (index <= kStockNullPen)
    {
        if (!g_pens[index].alive)
            return 0;
        return MakeHandle(kGdiTagPen, index);
    }
    return 0;
}

u64 GdiCreatePen(u32 style, u32 width, u32 rgb)
{
    (void)style; // styles (PS_DASH / PS_DOT / etc.) ignored in v0
    for (u32 i = 9; i < kMaxPens; ++i)
    {
        if (!g_pens[i].alive)
        {
            g_pens[i].alive = true;
            g_pens[i].rgb = rgb;
            g_pens[i].width = (width == 0) ? 1 : width;
            g_pens[i].stock = false;
            return MakeHandle(kGdiTagPen, i);
        }
    }
    return 0;
}

u32 GdiSetTextColor(u64 hdc, u32 rgb)
{
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc != nullptr)
    {
        const u32 prev = dc->text_color;
        dc->text_color = rgb;
        return prev;
    }
    if ((hdc & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr)
        {
            const u32 prev = s->text_color;
            s->text_color = rgb;
            return prev;
        }
    }
    return rgb;
}

u32 GdiSetBkColor(u64 hdc, u32 rgb)
{
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc != nullptr)
    {
        const u32 prev = dc->bk_color;
        dc->bk_color = rgb;
        return prev;
    }
    if ((hdc & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr)
        {
            const u32 prev = s->bk_color;
            s->bk_color = rgb;
            return prev;
        }
    }
    return rgb;
}

u8 GdiSetBkMode(u64 hdc, u8 mode)
{
    if (mode != kBkModeTransparent && mode != kBkModeOpaque)
        return 0;
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc != nullptr)
    {
        const u8 prev = dc->bk_mode;
        dc->bk_mode = mode;
        return prev;
    }
    if ((hdc & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr)
        {
            const u8 prev = s->bk_mode;
            s->bk_mode = mode;
            return prev;
        }
    }
    return mode;
}

u64 GdiSelectObject(u64 hdc, u64 hobj)
{
    const u64 obj_tag = hobj & kGdiTagMask;
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc != nullptr)
    {
        if (obj_tag == kGdiTagBitmap && GdiLookupBitmap(hobj) != nullptr)
        {
            const u64 prev = dc->selected_bitmap;
            dc->selected_bitmap = hobj;
            return prev;
        }
        if (obj_tag == kGdiTagPen && GdiLookupPen(hobj) != nullptr)
        {
            const u64 prev = dc->selected_pen;
            dc->selected_pen = hobj;
            return prev;
        }
        if (obj_tag == kGdiTagBrush && GdiLookupBrush(hobj) != nullptr)
        {
            const u64 prev = dc->selected_brush;
            dc->selected_brush = hobj;
            return prev;
        }
        return hobj;
    }
    // Window-HDC path — look up / lazily init the per-window DC
    // state. Both pen and brush selections now land in the side
    // table so Rectangle / Ellipse / PatBlt can consult them.
    if ((hdc & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr)
        {
            if (obj_tag == kGdiTagPen && GdiLookupPen(hobj) != nullptr)
            {
                const u64 prev = s->selected_pen;
                s->selected_pen = hobj;
                return prev;
            }
            if (obj_tag == kGdiTagBrush && GdiLookupBrush(hobj) != nullptr)
            {
                const u64 prev = s->selected_brush;
                s->selected_brush = hobj;
                return prev;
            }
        }
    }
    return hobj;
}

bool GdiDeleteDC(u64 hdc)
{
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc == nullptr)
        return false;
    dc->alive = false;
    dc->selected_bitmap = 0;
    return true;
}

bool GdiDeleteObject(u64 hobj)
{
    const u64 tag = hobj & kGdiTagMask;
    if (tag == kGdiTagBitmap)
    {
        Bitmap* b = GdiLookupBitmap(hobj);
        if (b == nullptr)
            return false;
        if (b->pixels != nullptr)
        {
            duetos::mm::KFree(b->pixels);
            b->pixels = nullptr;
        }
        b->alive = false;
        return true;
    }
    if (tag == kGdiTagBrush)
    {
        Brush* b = GdiLookupBrush(hobj);
        if (b == nullptr)
            return false;
        if (b->stock)
            return true; // no-op on stock per Win32 spec
        b->alive = false;
        return true;
    }
    if (tag == kGdiTagPen)
    {
        Pen* p = GdiLookupPen(hobj);
        if (p == nullptr)
            return false;
        if (p->stock)
            return true;
        p->alive = false;
        return true;
    }
    return false;
}

// --- Bitmap paint helpers ----------------------------------------
//
// These routines write raw pixels into a bitmap's BGRA8888 buffer.
// They're the "memDC" equivalent of the compositor's display-list
// replay — same output, just landing in a guest-owned off-screen
// buffer rather than the framebuffer.

void GdiPaintRectOnBitmap(Bitmap* bmp, i32 x, i32 y, i32 w, i32 h, u32 rgb)
{
    if (bmp == nullptr || bmp->pixels == nullptr || w <= 0 || h <= 0)
        return;
    // Clip against bitmap extents. Use i64 math so `x + w` can't
    // wrap for bad inputs. Negative starts are advanced to 0.
    i64 x0 = x;
    i64 y0 = y;
    i64 x1 = static_cast<i64>(x) + w;
    i64 y1 = static_cast<i64>(y) + h;
    if (x0 < 0)
        x0 = 0;
    if (y0 < 0)
        y0 = 0;
    if (x1 > static_cast<i64>(bmp->width))
        x1 = bmp->width;
    if (y1 > static_cast<i64>(bmp->height))
        y1 = bmp->height;
    if (x1 <= x0 || y1 <= y0)
        return;

    const u32 stride = bmp->pitch / 4;
    for (i64 yy = y0; yy < y1; ++yy)
    {
        u32* row = bmp->pixels + static_cast<u64>(yy) * stride;
        for (i64 xx = x0; xx < x1; ++xx)
            row[xx] = rgb;
    }
}

void GdiPaintTextOnBitmap(Bitmap* bmp, i32 x, i32 y, const char* text, u32 fg, u32 bg, bool opaque)
{
    if (bmp == nullptr || bmp->pixels == nullptr || text == nullptr)
        return;
    using namespace duetos::drivers::video;
    const u32 stride = bmp->pitch / 4;
    i32 cur_x = x;
    for (u32 i = 0; text[i] != '\0'; ++i)
    {
        if (cur_x + static_cast<i32>(kGlyphWidth) <= 0 || cur_x >= static_cast<i32>(bmp->width))
            break;
        const u8* glyph = Font8x8Lookup(text[i]);
        for (u32 row = 0; row < kGlyphHeight; ++row)
        {
            const i32 py = y + static_cast<i32>(row);
            if (py < 0 || py >= static_cast<i32>(bmp->height))
                continue;
            const u8 bits = glyph[row];
            u32* dst_row = bmp->pixels + static_cast<u64>(py) * stride;
            for (u32 col = 0; col < kGlyphWidth; ++col)
            {
                const i32 px = cur_x + static_cast<i32>(col);
                if (px < 0 || px >= static_cast<i32>(bmp->width))
                    continue;
                const bool on = (bits & (0x80u >> col)) != 0;
                if (on)
                    dst_row[px] = fg;
                else if (opaque)
                    dst_row[px] = bg;
            }
        }
        cur_x += static_cast<i32>(kGlyphWidth);
    }
}

void GdiDrawLineOnBitmap(Bitmap* bmp, i32 x0, i32 y0, i32 x1, i32 y1, u32 rgb)
{
    if (bmp == nullptr || bmp->pixels == nullptr)
        return;
    // Standard Bresenham with a per-pixel surface clip — no
    // Cohen-Sutherland pre-clip because single-pixel plots here
    // are so cheap that the clip-test dwarfs the plot.
    const i32 dx = (x1 > x0) ? x1 - x0 : x0 - x1;
    const i32 dy = (y1 > y0) ? -(y1 - y0) : -(y0 - y1);
    const i32 sx = (x0 < x1) ? 1 : -1;
    const i32 sy = (y0 < y1) ? 1 : -1;
    i32 err = dx + dy;
    i32 x = x0;
    i32 y = y0;
    const u32 stride = bmp->pitch / 4;
    for (;;)
    {
        if (x >= 0 && y >= 0 && static_cast<u32>(x) < bmp->width && static_cast<u32>(y) < bmp->height)
        {
            bmp->pixels[static_cast<u64>(y) * stride + static_cast<u64>(x)] = rgb;
        }
        if (x == x1 && y == y1)
            break;
        const i32 e2 = 2 * err;
        if (e2 >= dy)
        {
            err += dy;
            x += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y += sy;
        }
    }
}

void GdiBlitIntoBitmap(Bitmap* bmp, i32 dst_x, i32 dst_y, const u32* src, u32 src_w, u32 src_h, u32 src_pitch_px)
{
    if (bmp == nullptr || bmp->pixels == nullptr || src == nullptr || src_w == 0 || src_h == 0)
        return;
    i64 dx0 = dst_x;
    i64 dy0 = dst_y;
    i64 dx1 = static_cast<i64>(dst_x) + src_w;
    i64 dy1 = static_cast<i64>(dst_y) + src_h;
    // Track the src offset implied by left/top clipping so we walk
    // the correct source row even when dst_x/dst_y are negative.
    i64 sx_off = 0;
    i64 sy_off = 0;
    if (dx0 < 0)
    {
        sx_off = -dx0;
        dx0 = 0;
    }
    if (dy0 < 0)
    {
        sy_off = -dy0;
        dy0 = 0;
    }
    if (dx1 > static_cast<i64>(bmp->width))
        dx1 = bmp->width;
    if (dy1 > static_cast<i64>(bmp->height))
        dy1 = bmp->height;
    if (dx1 <= dx0 || dy1 <= dy0)
        return;

    const u32 stride = bmp->pitch / 4;
    for (i64 yy = dy0; yy < dy1; ++yy)
    {
        const u32* src_row = src + static_cast<u64>(yy - dy0 + sy_off) * src_pitch_px + static_cast<u64>(sx_off);
        u32* dst_row = bmp->pixels + static_cast<u64>(yy) * stride;
        for (i64 xx = dx0; xx < dx1; ++xx)
            dst_row[xx] = src_row[xx - dx0];
    }
}

// --- Syscall dispatchers -----------------------------------------

void DoGdiCreateCompatibleDC(arch::TrapFrame* frame)
{
    // rdi = hdc_src (ignored in v0; we don't copy DC colour state)
    (void)frame->rdi;
    frame->rax = GdiCreateCompatibleDC();
}

void DoGdiCreateCompatibleBitmap(arch::TrapFrame* frame)
{
    // rdi = hdc (ignored), rsi = width, rdx = height
    const u32 w = static_cast<u32>(frame->rsi);
    const u32 h = static_cast<u32>(frame->rdx);
    frame->rax = GdiCreateCompatibleBitmap(w, h);
}

void DoGdiCreateSolidBrush(arch::TrapFrame* frame)
{
    // rdi = COLORREF (Win32 layout 0x00BBGGRR)
    const u32 cr = static_cast<u32>(frame->rdi);
    const u32 rgb = ((cr & 0xFF) << 16) | (((cr >> 8) & 0xFF) << 8) | ((cr >> 16) & 0xFF);
    frame->rax = GdiCreateSolidBrush(rgb);
}

void DoGdiGetStockObject(arch::TrapFrame* frame)
{
    frame->rax = GdiGetStockObject(static_cast<u32>(frame->rdi));
}

void DoGdiSelectObject(arch::TrapFrame* frame)
{
    frame->rax = GdiSelectObject(frame->rdi, frame->rsi);
}

void DoGdiDeleteDC(arch::TrapFrame* frame)
{
    frame->rax = GdiDeleteDC(frame->rdi) ? 1 : 0;
}

void DoGdiDeleteObject(arch::TrapFrame* frame)
{
    frame->rax = GdiDeleteObject(frame->rdi) ? 1 : 0;
}

// Packed 9-arg BitBlt struct the user stub builds on its stack.
// Field widths are u64 for every slot; the low 32 bits of each
// integer arg carry the meaningful value (Win64 int passes in
// 32-bit registers, upper 32 bits of the argument register are
// undefined — we tolerate garbage there).
struct BitBltArgs
{
    u64 hdc_dst;
    u64 x;
    u64 y;
    u64 cx;
    u64 cy;
    u64 hdc_src;
    u64 x1;
    u64 y1;
    u64 rop;
};

void DoGdiSetTextColor(arch::TrapFrame* frame)
{
    // rdi = HDC, rsi = COLORREF
    const u32 cr = static_cast<u32>(frame->rsi);
    const u32 rgb = ((cr & 0xFF) << 16) | (((cr >> 8) & 0xFF) << 8) | ((cr >> 16) & 0xFF);
    const u32 prev_rgb = GdiSetTextColor(frame->rdi, rgb);
    // Return value is a COLORREF (Win32 layout). Re-pack.
    const u32 prev_cr = ((prev_rgb & 0xFF) << 16) | (((prev_rgb >> 8) & 0xFF) << 8) | ((prev_rgb >> 16) & 0xFF);
    frame->rax = prev_cr;
}

void DoGdiSetBkColor(arch::TrapFrame* frame)
{
    const u32 cr = static_cast<u32>(frame->rsi);
    const u32 rgb = ((cr & 0xFF) << 16) | (((cr >> 8) & 0xFF) << 8) | ((cr >> 16) & 0xFF);
    const u32 prev_rgb = GdiSetBkColor(frame->rdi, rgb);
    const u32 prev_cr = ((prev_rgb & 0xFF) << 16) | (((prev_rgb >> 8) & 0xFF) << 8) | ((prev_rgb >> 16) & 0xFF);
    frame->rax = prev_cr;
}

void DoGdiSetBkMode(arch::TrapFrame* frame)
{
    frame->rax = GdiSetBkMode(frame->rdi, static_cast<u8>(frame->rsi));
}

void DoGdiBitBltDC(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 user_args = frame->rdi;
    if (user_args == 0)
    {
        frame->rax = 0;
        return;
    }
    BitBltArgs args{};
    if (!duetos::mm::CopyFromUser(&args, reinterpret_cast<const void*>(user_args), sizeof(args)))
    {
        frame->rax = 0;
        return;
    }

    // Pull + range-check every dimension.
    const i32 dst_x = static_cast<i32>(static_cast<u32>(args.x));
    const i32 dst_y = static_cast<i32>(static_cast<u32>(args.y));
    const i32 cx = static_cast<i32>(static_cast<u32>(args.cx));
    const i32 cy = static_cast<i32>(static_cast<u32>(args.cy));
    const i32 src_x = static_cast<i32>(static_cast<u32>(args.x1));
    const i32 src_y = static_cast<i32>(static_cast<u32>(args.y1));

    if (cx <= 0 || cy <= 0)
    {
        frame->rax = 0;
        return;
    }
    // Cap by the per-window pool so we don't ever allocate a
    // staging buffer larger than the pool can accept.
    if (static_cast<u64>(cx) * static_cast<u64>(cy) > kWinBlitMaxPx)
    {
        frame->rax = 0;
        return;
    }

    // Source: a memory DC with a selected compatible bitmap. v0
    // doesn't support window-to-window or screen-to-window blits.
    MemDC* src_dc = GdiLookupMemDC(args.hdc_src);
    if (src_dc == nullptr || src_dc->selected_bitmap == 0)
    {
        frame->rax = 0;
        return;
    }
    Bitmap* src_bmp = GdiLookupBitmap(src_dc->selected_bitmap);
    if (src_bmp == nullptr || src_bmp->pixels == nullptr)
    {
        frame->rax = 0;
        return;
    }
    if (src_x < 0 || src_y < 0 || static_cast<u32>(src_x) + static_cast<u32>(cx) > src_bmp->width ||
        static_cast<u32>(src_y) + static_cast<u32>(cy) > src_bmp->height)
    {
        frame->rax = 0;
        return;
    }

    // Extract the source subrect into a contiguous staging buffer.
    // The per-window blit-pool writer `WindowClientBitBlt` expects
    // row-major tight-packed BGRA pixels (pitch = width*4).
    const u32 bytes = static_cast<u32>(cx) * static_cast<u32>(cy) * 4;
    u32* staging = static_cast<u32*>(duetos::mm::KMalloc(bytes));
    if (staging == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u32* src_rows = src_bmp->pixels;
    const u32 src_stride_px = src_bmp->pitch / 4;
    for (u32 row = 0; row < static_cast<u32>(cy); ++row)
    {
        const u32* src_row = src_rows + (static_cast<u32>(src_y) + row) * src_stride_px + static_cast<u32>(src_x);
        u32* dst_row = staging + row * static_cast<u32>(cx);
        for (u32 col = 0; col < static_cast<u32>(cx); ++col)
            dst_row[col] = src_row[col];
    }
    (void)args.rop; // SRCCOPY assumed in v0

    // Destination can be either a window HWND (display-list Blit
    // prim + compose) or a memDC with a selected bitmap (direct
    // write into the bitmap buffer). Dispatch by handle tag.
    const u64 dst_tag = args.hdc_dst & kGdiTagMask;
    bool ok = false;
    if (dst_tag == kGdiTagMemDC)
    {
        MemDC* dst_dc = GdiLookupMemDC(args.hdc_dst);
        if (dst_dc != nullptr && dst_dc->selected_bitmap != 0)
        {
            Bitmap* dst_bmp = GdiLookupBitmap(dst_dc->selected_bitmap);
            if (dst_bmp != nullptr)
            {
                GdiBlitIntoBitmap(dst_bmp, dst_x, dst_y, staging, static_cast<u32>(cx), static_cast<u32>(cy),
                                  static_cast<u32>(cx));
                ok = true;
            }
        }
    }
    else if (dst_tag == 0)
    {
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(args.hdc_dst, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientBitBlt(h_comp, dst_x, dst_y, staging, static_cast<u32>(cx), static_cast<u32>(cy));
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            ok = true;
        }
        CompositorUnlock();
    }

    duetos::mm::KFree(staging);
    frame->rax = ok ? 1 : 0;
}

// Packed 11-arg StretchBlt struct — same convention as BitBltArgs.
struct StretchBltArgs
{
    u64 hdc_dst;
    u64 dst_x;
    u64 dst_y;
    u64 dst_w;
    u64 dst_h;
    u64 hdc_src;
    u64 src_x;
    u64 src_y;
    u64 src_w;
    u64 src_h;
    u64 rop;
};

void DoGdiStretchBltDC(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;

    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 user_args = frame->rdi;
    if (user_args == 0)
    {
        frame->rax = 0;
        return;
    }
    StretchBltArgs args{};
    if (!duetos::mm::CopyFromUser(&args, reinterpret_cast<const void*>(user_args), sizeof(args)))
    {
        frame->rax = 0;
        return;
    }

    const i32 dst_x = static_cast<i32>(static_cast<u32>(args.dst_x));
    const i32 dst_y = static_cast<i32>(static_cast<u32>(args.dst_y));
    const i32 dst_w = static_cast<i32>(static_cast<u32>(args.dst_w));
    const i32 dst_h = static_cast<i32>(static_cast<u32>(args.dst_h));
    const i32 src_x = static_cast<i32>(static_cast<u32>(args.src_x));
    const i32 src_y = static_cast<i32>(static_cast<u32>(args.src_y));
    const i32 src_w = static_cast<i32>(static_cast<u32>(args.src_w));
    const i32 src_h = static_cast<i32>(static_cast<u32>(args.src_h));

    if (dst_w <= 0 || dst_h <= 0 || src_w <= 0 || src_h <= 0)
    {
        frame->rax = 0;
        return;
    }
    if (static_cast<u64>(dst_w) * static_cast<u64>(dst_h) > kWinBlitMaxPx)
    {
        frame->rax = 0;
        return;
    }

    // Source must be a memDC + selected bitmap.
    MemDC* src_dc = GdiLookupMemDC(args.hdc_src);
    if (src_dc == nullptr || src_dc->selected_bitmap == 0)
    {
        frame->rax = 0;
        return;
    }
    Bitmap* src_bmp = GdiLookupBitmap(src_dc->selected_bitmap);
    if (src_bmp == nullptr || src_bmp->pixels == nullptr)
    {
        frame->rax = 0;
        return;
    }
    if (src_x < 0 || src_y < 0 || static_cast<u32>(src_x) + static_cast<u32>(src_w) > src_bmp->width ||
        static_cast<u32>(src_y) + static_cast<u32>(src_h) > src_bmp->height)
    {
        frame->rax = 0;
        return;
    }

    const u32 bytes = static_cast<u32>(dst_w) * static_cast<u32>(dst_h) * 4;
    u32* staging = static_cast<u32*>(duetos::mm::KMalloc(bytes));
    if (staging == nullptr)
    {
        frame->rax = 0;
        return;
    }

    // Nearest-neighbor scale: for each dst pixel (ox, oy), sample
    // src at `(src_x + ox * src_w / dst_w, src_y + oy * src_h /
    // dst_h)`. Using u64 intermediates keeps the multiplication
    // from overflowing for large src dimensions.
    const u32 src_stride = src_bmp->pitch / 4;
    const u32* src_rows = src_bmp->pixels;
    for (i32 oy = 0; oy < dst_h; ++oy)
    {
        const u32 sy = static_cast<u32>(src_y) +
                       static_cast<u32>((static_cast<u64>(oy) * static_cast<u64>(src_h)) / static_cast<u64>(dst_h));
        const u32* src_row = src_rows + sy * src_stride;
        u32* dst_row = staging + static_cast<u32>(oy) * static_cast<u32>(dst_w);
        for (i32 ox = 0; ox < dst_w; ++ox)
        {
            const u32 sx = static_cast<u32>(src_x) +
                           static_cast<u32>((static_cast<u64>(ox) * static_cast<u64>(src_w)) / static_cast<u64>(dst_w));
            dst_row[ox] = src_row[sx];
        }
    }
    (void)args.rop;

    // Dispatch by dst handle tag — same shape as BitBlt.
    const u64 dst_tag = args.hdc_dst & kGdiTagMask;
    bool ok = false;
    if (dst_tag == kGdiTagMemDC)
    {
        MemDC* dst_dc = GdiLookupMemDC(args.hdc_dst);
        if (dst_dc != nullptr && dst_dc->selected_bitmap != 0)
        {
            Bitmap* dst_bmp = GdiLookupBitmap(dst_dc->selected_bitmap);
            if (dst_bmp != nullptr)
            {
                GdiBlitIntoBitmap(dst_bmp, dst_x, dst_y, staging, static_cast<u32>(dst_w), static_cast<u32>(dst_h),
                                  static_cast<u32>(dst_w));
                ok = true;
            }
        }
    }
    else if (dst_tag == 0)
    {
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(args.hdc_dst, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientBitBlt(h_comp, dst_x, dst_y, staging, static_cast<u32>(dst_w), static_cast<u32>(dst_h));
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            ok = true;
        }
        CompositorUnlock();
    }

    duetos::mm::KFree(staging);
    frame->rax = ok ? 1 : 0;
}

void DoGdiCreatePen(arch::TrapFrame* frame)
{
    // rdi = style, rsi = width, rdx = COLORREF (Win32 0x00BBGGRR).
    const u32 style = static_cast<u32>(frame->rdi);
    const u32 width = static_cast<u32>(frame->rsi);
    const u32 cr = static_cast<u32>(frame->rdx);
    const u32 rgb = ((cr & 0xFF) << 16) | (((cr >> 8) & 0xFF) << 8) | ((cr >> 16) & 0xFF);
    frame->rax = GdiCreatePen(style, width, rgb);
}

// Helper: resolve the current "pen colour" for an HDC. memDC uses
// `selected_pen` on the MemDC; window HDC uses the per-window DC
// state's `selected_pen`; either 0 = implicit BLACK_PEN.
u32 ResolvePenColor(u64 hdc)
{
    u64 pen = 0;
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc != nullptr)
    {
        pen = dc->selected_pen;
    }
    else if ((hdc & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr)
            pen = s->selected_pen;
    }
    if (pen == 0)
        return 0x00000000; // BLACK_PEN implicit default
    Pen* p = GdiLookupPen(pen);
    if (p == nullptr)
        return 0x00000000;
    return p->rgb;
}

void DoGdiMoveToEx(arch::TrapFrame* frame)
{
    // rdi = HDC, rsi = x, rdx = y, r10 = optional user LPPOINT out.
    const i32 x = static_cast<i32>(static_cast<u32>(frame->rsi));
    const i32 y = static_cast<i32>(static_cast<u32>(frame->rdx));
    const u64 user_out = frame->r10;

    i32 old_x = 0, old_y = 0;
    bool ok = false;
    MemDC* dc = GdiLookupMemDC(frame->rdi);
    if (dc != nullptr)
    {
        old_x = dc->cur_x;
        old_y = dc->cur_y;
        dc->cur_x = x;
        dc->cur_y = y;
        ok = true;
    }
    else if ((frame->rdi & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(frame->rdi));
        if (s != nullptr)
        {
            old_x = s->cur_x;
            old_y = s->cur_y;
            s->cur_x = x;
            s->cur_y = y;
            ok = true;
        }
    }
    if (!ok)
    {
        frame->rax = 0;
        return;
    }
    if (user_out != 0)
    {
        // Win32 POINT is { LONG x; LONG y; } — 8 bytes, two i32s.
        i32 pt[2] = {old_x, old_y};
        if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(user_out), pt, sizeof(pt)))
        {
            frame->rax = 0;
            return;
        }
    }
    frame->rax = 1;
}

// Resolve the DC's current brush colour. Mirrors ResolvePenColor
// — memDC + WindowDcState both feed into a single brush lookup,
// fallback WHITE_BRUSH if none selected.
u32 ResolveBrushColor(u64 hdc)
{
    u64 brush = 0;
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc != nullptr)
    {
        brush = dc->selected_brush;
    }
    else if ((hdc & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(hdc));
        if (s != nullptr)
            brush = s->selected_brush;
    }
    if (brush == 0)
        return 0x00FFFFFF; // implicit WHITE_BRUSH
    Brush* b = GdiLookupBrush(brush);
    if (b == nullptr)
        return 0x00FFFFFF;
    return b->rgb;
}

// Paint a filled ellipse into a bitmap via bounding-box scan.
// Ellipse equation: (x-cx)^2 / a^2 + (y-cy)^2 / b^2 <= 1, equivalent
// to `(x-cx)^2 * b^2 + (y-cy)^2 * a^2 <= a^2 * b^2` — integer math,
// no sqrt, no floats. Surface-clipped. Degenerate (zero-axis)
// rects are a no-op.
void PaintFilledEllipseOnBitmap(Bitmap* bmp, i32 x, i32 y, i32 w, i32 h, u32 rgb)
{
    if (bmp == nullptr || bmp->pixels == nullptr || w <= 0 || h <= 0)
        return;
    const i64 a = w / 2;
    const i64 b = h / 2;
    if (a == 0 || b == 0)
        return;
    const i64 cx = x + a;
    const i64 cy = y + b;
    const i64 a2 = a * a;
    const i64 b2 = b * b;
    const i64 a2b2 = a2 * b2;

    i64 x0 = x;
    i64 y0 = y;
    i64 x1 = static_cast<i64>(x) + w;
    i64 y1 = static_cast<i64>(y) + h;
    if (x0 < 0)
        x0 = 0;
    if (y0 < 0)
        y0 = 0;
    if (x1 > static_cast<i64>(bmp->width))
        x1 = bmp->width;
    if (y1 > static_cast<i64>(bmp->height))
        y1 = bmp->height;

    const u32 stride = bmp->pitch / 4;
    for (i64 yy = y0; yy < y1; ++yy)
    {
        u32* row = bmp->pixels + static_cast<u64>(yy) * stride;
        const i64 dy = yy - cy;
        const i64 dy2 = dy * dy;
        for (i64 xx = x0; xx < x1; ++xx)
        {
            const i64 dx = xx - cx;
            if (dx * dx * b2 + dy2 * a2 <= a2b2)
                row[xx] = rgb;
        }
    }
}

void DoGdiLineTo(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    // rdi = HDC, rsi = x1 (end), rdx = y1.
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const i32 x1 = static_cast<i32>(static_cast<u32>(frame->rsi));
    const i32 y1 = static_cast<i32>(static_cast<u32>(frame->rdx));
    const u32 rgb = ResolvePenColor(frame->rdi);

    bool ok = false;
    MemDC* dc = GdiLookupMemDC(frame->rdi);
    if (dc != nullptr)
    {
        if (dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                GdiDrawLineOnBitmap(bmp, dc->cur_x, dc->cur_y, x1, y1, rgb);
                dc->cur_x = x1;
                dc->cur_y = y1;
                ok = true;
            }
        }
        else
        {
            // No selected bitmap — still advance the current pos so
            // a follow-up SelectObject + LineTo loop behaves.
            dc->cur_x = x1;
            dc->cur_y = y1;
            ok = true;
        }
    }
    else if ((frame->rdi & kGdiTagMask) == 0)
    {
        WindowDcState* s = GdiWindowDcState(static_cast<u32>(frame->rdi));
        if (s != nullptr)
        {
            const i32 x0 = s->cur_x;
            const i32 y0 = s->cur_y;
            CompositorLock();
            const u32 h_comp = HwndToCompositorHandleForCaller(frame->rdi, proc->pid);
            if (h_comp != kWindowInvalid)
            {
                WindowClientLine(h_comp, x0, y0, x1, y1, rgb);
                const Theme& theme = ThemeCurrent();
                DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
                ok = true;
            }
            CompositorUnlock();
            s->cur_x = x1;
            s->cur_y = y1;
        }
    }
    frame->rax = ok ? 1 : 0;
}

void DoGdiGetSysColor(arch::TrapFrame* frame)
{
    const u32 rgb = GdiSysColor(static_cast<u32>(frame->rdi));
    // COLORREF is 0x00BBGGRR in Win32; our internal RGB is already
    // in that same layout (the map was populated in COLORREF form),
    // so we can return directly.
    frame->rax = rgb;
}

void DoGdiGetSysColorBrush(arch::TrapFrame* frame)
{
    frame->rax = GdiSysColorBrush(static_cast<u32>(frame->rdi));
}

void DoGdiPatBlt(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 hdc = frame->rdi;
    const i32 x = static_cast<i32>(static_cast<u32>(frame->rsi));
    const i32 y = static_cast<i32>(static_cast<u32>(frame->rdx));
    const i32 w = static_cast<i32>(static_cast<u32>(frame->r10));
    const i32 h = static_cast<i32>(static_cast<u32>(frame->r8));
    if (w <= 0 || h <= 0)
    {
        frame->rax = 0;
        return;
    }
    const u32 brush_rgb = ResolveBrushColor(hdc);

    bool ok = false;
    const u64 tag = hdc & kGdiTagMask;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                GdiPaintRectOnBitmap(bmp, x, y, w, h, brush_rgb);
                ok = true;
            }
        }
    }
    else if (tag == 0)
    {
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            WindowClientFillRect(h_comp, x, y, w, h, brush_rgb);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            ok = true;
        }
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

void DoGdiRectangleFilled(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 hdc = frame->rdi;
    const i32 x = static_cast<i32>(static_cast<u32>(frame->rsi));
    const i32 y = static_cast<i32>(static_cast<u32>(frame->rdx));
    const i32 w = static_cast<i32>(static_cast<u32>(frame->r10));
    const i32 h = static_cast<i32>(static_cast<u32>(frame->r8));
    if (w <= 0 || h <= 0)
    {
        frame->rax = 0;
        return;
    }
    const u32 brush_rgb = ResolveBrushColor(hdc);
    const u32 pen_rgb = ResolvePenColor(hdc);

    bool ok = false;
    const u64 tag = hdc & kGdiTagMask;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                GdiPaintRectOnBitmap(bmp, x, y, w, h, brush_rgb);
                // 1-px outline via four Bresenham edges.
                GdiDrawLineOnBitmap(bmp, x, y, x + w - 1, y, pen_rgb);
                GdiDrawLineOnBitmap(bmp, x + w - 1, y, x + w - 1, y + h - 1, pen_rgb);
                GdiDrawLineOnBitmap(bmp, x + w - 1, y + h - 1, x, y + h - 1, pen_rgb);
                GdiDrawLineOnBitmap(bmp, x, y + h - 1, x, y, pen_rgb);
                ok = true;
            }
        }
    }
    else if (tag == 0)
    {
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            // Record fill + outline as two separate display-list
            // primitives — the replay order (fill then outline)
            // matches Win32 Rectangle semantics.
            WindowClientFillRect(h_comp, x, y, w, h, brush_rgb);
            WindowClientRectangle(h_comp, x, y, w, h, pen_rgb);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            ok = true;
        }
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

void DoGdiEllipseFilled(arch::TrapFrame* frame)
{
    using namespace duetos::drivers::video;
    duetos::core::Process* proc = duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 hdc = frame->rdi;
    const i32 x = static_cast<i32>(static_cast<u32>(frame->rsi));
    const i32 y = static_cast<i32>(static_cast<u32>(frame->rdx));
    const i32 w = static_cast<i32>(static_cast<u32>(frame->r10));
    const i32 h = static_cast<i32>(static_cast<u32>(frame->r8));
    if (w <= 0 || h <= 0)
    {
        frame->rax = 0;
        return;
    }
    const u32 brush_rgb = ResolveBrushColor(hdc);
    const u32 pen_rgb = ResolvePenColor(hdc);

    bool ok = false;
    const u64 tag = hdc & kGdiTagMask;
    if (tag == kGdiTagMemDC)
    {
        MemDC* dc = GdiLookupMemDC(hdc);
        if (dc != nullptr && dc->selected_bitmap != 0)
        {
            Bitmap* bmp = GdiLookupBitmap(dc->selected_bitmap);
            if (bmp != nullptr)
            {
                PaintFilledEllipseOnBitmap(bmp, x, y, w, h, brush_rgb);
                // Outline via the window-path midpoint algorithm
                // isn't available as a bitmap helper; for v0 we
                // paint a slightly-smaller ellipse in pen colour
                // over the fill's border ring, which approximates
                // the outline for small + medium ellipses.
                (void)pen_rgb; // outline-on-bitmap deferred
                ok = true;
            }
        }
    }
    else if (tag == 0)
    {
        CompositorLock();
        const u32 h_comp = HwndToCompositorHandleForCaller(hdc, proc->pid);
        if (h_comp != kWindowInvalid)
        {
            // Window path: the compositor doesn't yet have a
            // filled-ellipse prim. Record the outline via the
            // existing Ellipse prim; the area is technically
            // unfilled but the shape is on screen. Filled-ellipse
            // on window HDC is a documented v0 gap.
            (void)brush_rgb;
            WindowClientEllipse(h_comp, x, y, w, h, pen_rgb);
            const Theme& theme = ThemeCurrent();
            DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            ok = true;
        }
        CompositorUnlock();
    }
    frame->rax = ok ? 1 : 0;
}

} // namespace duetos::subsystems::win32
