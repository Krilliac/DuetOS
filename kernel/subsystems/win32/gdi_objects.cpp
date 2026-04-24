#include "gdi_objects.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/process.h"
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

    arch::SerialWrite("[gdi] stock objects registered (6 brushes)\n");
}

u64 GdiCreateCompatibleDC()
{
    for (u32 i = 0; i < kMaxMemDcs; ++i)
    {
        if (!g_mem_dcs[i].alive)
        {
            g_mem_dcs[i].alive = true;
            g_mem_dcs[i].selected_bitmap = 0;
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
    if (index > kStockNullBrush)
        return 0;
    if (!g_brushes[index].alive)
        return 0;
    return MakeHandle(kGdiTagBrush, index);
}

u64 GdiSelectObject(u64 hdc, u64 hobj)
{
    MemDC* dc = GdiLookupMemDC(hdc);
    if (dc == nullptr)
        return 0; // window DCs + invalid HDCs don't track selections
    const u64 tag = hobj & kGdiTagMask;
    if (tag == kGdiTagBitmap && GdiLookupBitmap(hobj) != nullptr)
    {
        const u64 prev = dc->selected_bitmap;
        dc->selected_bitmap = hobj;
        return prev;
    }
    // Other object kinds (brush/pen) aren't tracked on the DC
    // in v0; return the handle unchanged (Win32 Select* returns the
    // previous selection) so paired Select+Restore idioms don't
    // trip over a zero.
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
    return false;
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

    // Destination must be a window HWND — in v0 a memory-DC-to-
    // memory-DC blit would need us to also track the dest bitmap
    // and write pixels back into it, which isn't plumbed yet.
    const u64 dst_tag = args.hdc_dst & kGdiTagMask;
    bool ok = false;
    if (dst_tag == 0)
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

} // namespace duetos::subsystems::win32
