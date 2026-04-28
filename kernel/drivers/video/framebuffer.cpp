#include "drivers/video/framebuffer.h"

#include "arch/x86_64/serial.h"
#include "mm/multiboot2.h"
#include "mm/paging.h"
#include "drivers/video/font8x8.h"

namespace duetos::drivers::video
{

namespace
{

using arch::SerialWrite;
using arch::SerialWriteHex;
using mm::MultibootFramebufferTag;
using mm::MultibootInfoHeader;
using mm::MultibootTagHeader;

constinit bool g_available = false;
constinit bool g_init_called = false;
constinit FramebufferInfo g_info{};

// Walk the Multiboot2 tag list for tag 8. Returns a pointer into the
// live info struct (no copy) so fields can be read directly, or
// nullptr if the tag is absent.
const MultibootFramebufferTag* FindFramebufferTag(uptr info_phys)
{
    const auto* info = reinterpret_cast<const MultibootInfoHeader*>(info_phys);
    uptr cursor = info_phys + sizeof(MultibootInfoHeader);
    const uptr end = info_phys + info->total_size;

    while (cursor < end)
    {
        const auto* tag = reinterpret_cast<const MultibootTagHeader*>(cursor);
        if (tag->type == mm::kMultibootTagEnd)
        {
            break;
        }
        if (tag->type == mm::kMultibootTagFramebuffer)
        {
            return reinterpret_cast<const MultibootFramebufferTag*>(cursor);
        }
        cursor += (tag->size + 7u) & ~uptr{7};
    }
    return nullptr;
}

} // namespace

void FramebufferInit(uptr multiboot_info_phys)
{
    if (g_init_called)
    {
        return; // idempotent
    }
    g_init_called = true;

    if (multiboot_info_phys == 0)
    {
        SerialWrite("[video/fb] no Multiboot2 info — framebuffer disabled\n");
        return;
    }

    const MultibootFramebufferTag* tag = FindFramebufferTag(multiboot_info_phys);
    if (tag == nullptr)
    {
        SerialWrite("[video/fb] no framebuffer tag from loader — staying on serial\n");
        return;
    }

    // Only direct-RGB mode is useful today. Indexed (palette) mode
    // would need a DAC-programming helper we don't have; EGA-text
    // mode is an 80x25 character cell buffer at 0xB8000, a totally
    // different code path.
    if (tag->framebuffer_type != mm::kFramebufferTypeRgb)
    {
        SerialWrite("[video/fb] unsupported framebuffer type=");
        SerialWriteHex(tag->framebuffer_type);
        SerialWrite(" — disabled\n");
        return;
    }

    // 32-bpp only for v0. 24-bpp packed RGB would need a different
    // pixel-store inner loop; 15/16-bpp need channel packing. Land
    // those when a real machine reports them.
    if (tag->bpp != 32)
    {
        SerialWrite("[video/fb] unsupported bpp=");
        SerialWriteHex(tag->bpp);
        SerialWrite(" (need 32) — disabled\n");
        return;
    }

    // Sanity check pitch. A sane pitch is >= width * 4 and a multiple
    // of 4 (since we write 32-bit pixels). Firmware has been known
    // to lie here — better a boot-time refuse than garbled output.
    if (tag->pitch < tag->width * 4 || (tag->pitch & 3) != 0)
    {
        SerialWrite("[video/fb] insane pitch=");
        SerialWriteHex(tag->pitch);
        SerialWrite(" for width=");
        SerialWriteHex(tag->width);
        SerialWrite(" — disabled\n");
        return;
    }

    // MapMmio the whole surface. Cache-disabled is the right posture
    // for framebuffer MMIO — write-combining is better but needs PAT
    // programming we don't have yet; uncached works universally and
    // 1024x768x32 @ 60 Hz is well under the bandwidth budget.
    const u64 bytes = static_cast<u64>(tag->pitch) * tag->height;
    void* virt = mm::MapMmio(tag->addr, bytes);
    if (virt == nullptr)
    {
        SerialWrite("[video/fb] MapMmio failed for framebuffer — disabled\n");
        return;
    }

    g_info.virt = virt;
    g_info.phys = tag->addr;
    g_info.width = tag->width;
    g_info.height = tag->height;
    g_info.pitch = tag->pitch;
    g_info.bpp = tag->bpp;
    g_available = true;

    SerialWrite("[video/fb] online phys=");
    SerialWriteHex(tag->addr);
    SerialWrite(" virt=");
    SerialWriteHex(reinterpret_cast<u64>(virt));
    SerialWrite(" ");
    SerialWriteHex(tag->width);
    SerialWrite("x");
    SerialWriteHex(tag->height);
    SerialWrite(" pitch=");
    SerialWriteHex(tag->pitch);
    SerialWrite("\n");
}

bool FramebufferAvailable()
{
    return g_available;
}

bool FramebufferRebind(u64 phys, u32 width, u32 height, u32 pitch, u8 bpp)
{
    if (bpp != 32)
    {
        SerialWrite("[video/fb] rebind rejected: unsupported bpp=");
        SerialWriteHex(bpp);
        SerialWrite("\n");
        return false;
    }
    if (pitch < width * 4 || (pitch & 3) != 0 || width == 0 || height == 0)
    {
        SerialWrite("[video/fb] rebind rejected: invalid pitch/width/height\n");
        return false;
    }
    const u64 bytes = static_cast<u64>(pitch) * height;
    void* virt = mm::MapMmio(phys, bytes);
    if (virt == nullptr)
    {
        SerialWrite("[video/fb] rebind MapMmio failed — MMIO arena exhausted?\n");
        return false;
    }
    g_info.virt = virt;
    g_info.phys = phys;
    g_info.width = width;
    g_info.height = height;
    g_info.pitch = pitch;
    g_info.bpp = bpp;
    g_available = true;
    SerialWrite("[video/fb] rebound phys=");
    SerialWriteHex(phys);
    SerialWrite(" virt=");
    SerialWriteHex(reinterpret_cast<u64>(virt));
    SerialWrite(" ");
    SerialWriteHex(width);
    SerialWrite("x");
    SerialWriteHex(height);
    SerialWrite(" pitch=");
    SerialWriteHex(pitch);
    SerialWrite("\n");
    return true;
}

bool FramebufferRebindExternal(void* virt, u64 phys, u32 width, u32 height, u32 pitch, u8 bpp)
{
    if (bpp != 32 || virt == nullptr || pitch < width * 4 || (pitch & 3) != 0 || width == 0 || height == 0)
    {
        SerialWrite("[video/fb] rebind-ext rejected (bad geometry or null virt)\n");
        return false;
    }
    g_info.virt = virt;
    g_info.phys = phys;
    g_info.width = width;
    g_info.height = height;
    g_info.pitch = pitch;
    g_info.bpp = bpp;
    g_available = true;
    SerialWrite("[video/fb] rebound-ext virt=");
    SerialWriteHex(reinterpret_cast<u64>(virt));
    SerialWrite(" phys=");
    SerialWriteHex(phys);
    SerialWrite(" ");
    SerialWriteHex(width);
    SerialWrite("x");
    SerialWriteHex(height);
    SerialWrite(" pitch=");
    SerialWriteHex(pitch);
    SerialWrite("\n");
    return true;
}

namespace
{
constinit FramebufferPresentFn g_present_hook = nullptr;
} // namespace

void FramebufferSetPresentHook(FramebufferPresentFn fn)
{
    g_present_hook = fn;
}

void FramebufferPresent()
{
    if (g_present_hook != nullptr)
        g_present_hook();
}

FramebufferInfo FramebufferGet()
{
    return g_info;
}

void FramebufferPutPixel(u32 x, u32 y, u32 rgb)
{
    if (!g_available)
    {
        return;
    }
    if (x >= g_info.width || y >= g_info.height)
    {
        return;
    }
    auto* row =
        reinterpret_cast<volatile u32*>(reinterpret_cast<u8*>(g_info.virt) + static_cast<u64>(y) * g_info.pitch);
    row[x] = rgb;
}

void FramebufferFillRect(u32 x, u32 y, u32 w, u32 h, u32 rgb)
{
    if (!g_available || w == 0 || h == 0)
    {
        return;
    }
    if (x >= g_info.width || y >= g_info.height)
    {
        return;
    }
    // Clip to the surface. Overflow-safe: x + w can't exceed u32::max
    // because width is already bounded by the surface dimensions.
    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;

    auto* fb_bytes = reinterpret_cast<u8*>(g_info.virt);
    for (u32 yi = y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(fb_bytes + static_cast<u64>(yi) * g_info.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            row[xi] = rgb;
        }
    }
}

void FramebufferBlit(u32 dst_x, u32 dst_y, const u32* src, u32 src_w, u32 src_h, u32 src_pitch_px)
{
    if (!g_available || src == nullptr || src_w == 0 || src_h == 0)
    {
        return;
    }
    if (dst_x >= g_info.width || dst_y >= g_info.height)
    {
        return;
    }
    const u32 x_end = (dst_x + src_w > g_info.width) ? g_info.width : dst_x + src_w;
    const u32 y_end = (dst_y + src_h > g_info.height) ? g_info.height : dst_y + src_h;

    auto* fb_bytes = reinterpret_cast<u8*>(g_info.virt);
    for (u32 yi = dst_y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(fb_bytes + static_cast<u64>(yi) * g_info.pitch);
        const u32* src_row = src + static_cast<u64>(yi - dst_y) * src_pitch_px;
        for (u32 xi = dst_x; xi < x_end; ++xi)
        {
            row[xi] = src_row[xi - dst_x];
        }
    }
}

void FramebufferClear(u32 rgb)
{
    if (!g_available)
    {
        return;
    }
    FramebufferFillRect(0, 0, g_info.width, g_info.height, rgb);
}

void FramebufferDrawChar(u32 x, u32 y, char ch, u32 fg, u32 bg)
{
    if (!g_available)
    {
        return;
    }
    const u8* glyph = Font8x8Lookup(ch);
    for (u32 row = 0; row < kGlyphHeight; ++row)
    {
        const u8 bits = glyph[row];
        for (u32 col = 0; col < kGlyphWidth; ++col)
        {
            const bool on = (bits & (0x80U >> col)) != 0;
            FramebufferPutPixel(x + col, y + row, on ? fg : bg);
        }
    }
}

void FramebufferDrawString(u32 x, u32 y, const char* text, u32 fg, u32 bg)
{
    if (!g_available || text == nullptr)
    {
        return;
    }
    u32 cx = x;
    while (*text != '\0')
    {
        if (cx + kGlyphWidth > g_info.width)
        {
            break;
        }
        FramebufferDrawChar(cx, y, *text, fg, bg);
        cx += kGlyphWidth;
        ++text;
    }
}

void FramebufferDrawRect(u32 x, u32 y, u32 w, u32 h, u32 rgb, u32 thickness)
{
    if (!g_available || w == 0 || h == 0 || thickness == 0)
    {
        return;
    }
    // Clamp thickness so the four bands don't overlap into the
    // interior in a way that changes the outlined-rect semantics
    // (e.g. a 2-pixel outline on a 3-pixel-tall rect should fill
    // the whole thing, not double-write the middle row).
    const u32 cap = (w < h ? w : h) / 2;
    if (thickness > cap)
    {
        thickness = (cap == 0) ? 1 : cap;
    }
    FramebufferFillRect(x, y, w, thickness, rgb);                 // top
    FramebufferFillRect(x, y + h - thickness, w, thickness, rgb); // bottom
    FramebufferFillRect(x, y, thickness, h, rgb);                 // left
    FramebufferFillRect(x + w - thickness, y, thickness, h, rgb); // right
}

void FramebufferFillRectAlpha(u32 x, u32 y, u32 w, u32 h, u32 argb)
{
    if (!g_available || w == 0 || h == 0)
    {
        return;
    }
    if (x >= g_info.width || y >= g_info.height)
    {
        return;
    }

    const u32 alpha = (argb >> 24) & 0xFFU;
    if (alpha == 0)
    {
        return;
    }
    if (alpha == 0xFF)
    {
        FramebufferFillRect(x, y, w, h, argb & 0x00FFFFFFU);
        return;
    }

    // Pre-multiply the source channels by alpha once so the inner
    // loop is dst * inv + src_premul plus a /255 round.
    const u32 src_r = (argb >> 16) & 0xFFU;
    const u32 src_g = (argb >> 8) & 0xFFU;
    const u32 src_b = argb & 0xFFU;
    const u32 sr_a = src_r * alpha;
    const u32 sg_a = src_g * alpha;
    const u32 sb_a = src_b * alpha;
    const u32 inv = 255U - alpha;

    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;

    auto* fb_bytes = reinterpret_cast<u8*>(g_info.virt);
    for (u32 yi = y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(fb_bytes + static_cast<u64>(yi) * g_info.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            const u32 dst = row[xi];
            const u32 dr = (dst >> 16) & 0xFFU;
            const u32 dg = (dst >> 8) & 0xFFU;
            const u32 db = dst & 0xFFU;
            // /255 rounding via the (n + 127) / 255 form. Equivalent
            // to ((n + 128) + ((n + 128) >> 8)) >> 8 in the cheap
            // 16-bit-mul approximation; we use the explicit divide
            // for clarity (compiler folds it into a multiply).
            const u32 r = (sr_a + dr * inv + 127U) / 255U;
            const u32 g = (sg_a + dg * inv + 127U) / 255U;
            const u32 b = (sb_a + db * inv + 127U) / 255U;
            row[xi] = (r << 16) | (g << 8) | b;
        }
    }
}

void FramebufferFillRectGradient(u32 x, u32 y, u32 w, u32 h, u32 top_rgb, u32 bot_rgb)
{
    if (!g_available || w == 0 || h == 0)
    {
        return;
    }
    if (x >= g_info.width || y >= g_info.height)
    {
        return;
    }
    if (h == 1 || top_rgb == bot_rgb)
    {
        FramebufferFillRect(x, y, w, h, top_rgb);
        return;
    }

    const i32 tr = static_cast<i32>((top_rgb >> 16) & 0xFFU);
    const i32 tg = static_cast<i32>((top_rgb >> 8) & 0xFFU);
    const i32 tb = static_cast<i32>(top_rgb & 0xFFU);
    const i32 br = static_cast<i32>((bot_rgb >> 16) & 0xFFU);
    const i32 bg = static_cast<i32>((bot_rgb >> 8) & 0xFFU);
    const i32 bb = static_cast<i32>(bot_rgb & 0xFFU);

    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;
    const u32 span = h - 1U; // we know h >= 2 here

    auto* fb_bytes = reinterpret_cast<u8*>(g_info.virt);
    for (u32 yi = y; yi < y_end; ++yi)
    {
        // 8.8 fixed-point row position in [0, 256]. Use the
        // unclipped `span`, not `y_end - y`, so a gradient
        // clipped at the bottom of the screen still extrapolates
        // each visible row to its correct shade.
        const u32 t = ((yi - y) * 256U) / span;
        const i32 r = tr + ((br - tr) * static_cast<i32>(t)) / 256;
        const i32 g = tg + ((bg - tg) * static_cast<i32>(t)) / 256;
        const i32 b = tb + ((bb - tb) * static_cast<i32>(t)) / 256;
        const u32 c = (static_cast<u32>(r) << 16) | (static_cast<u32>(g) << 8) | static_cast<u32>(b);
        auto* row = reinterpret_cast<volatile u32*>(fb_bytes + static_cast<u64>(yi) * g_info.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            row[xi] = c;
        }
    }
}

void FramebufferFillRoundRect(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 rgb)
{
    if (!g_available || w == 0 || h == 0)
    {
        return;
    }
    // Clamp radius to half the shorter side. A radius bigger than
    // that would paint corner curves that overlap each other; the
    // clamp turns "absurd" radii into a stadium / circle, which is
    // still a sensible thing to ask for.
    const u32 max_r = (w < h ? w : h) / 2U;
    if (radius > max_r)
    {
        radius = max_r;
    }
    if (radius == 0)
    {
        FramebufferFillRect(x, y, w, h, rgb);
        return;
    }

    // Middle band: full width across the rows that aren't in a
    // corner zone. Note h - 2*radius can be 0 if radius == h/2 and
    // h is even — FramebufferFillRect short-circuits on h == 0.
    FramebufferFillRect(x, y + radius, w, h - 2U * radius, rgb);

    // Per-row "indent" for the corner zones. The arc passes
    // through the four pixels closest to (radius-1, 0), (0,
    // radius-1) etc. of each radius-square. For each row at
    // distance dy from the outer corner, the smallest x-indent
    // dx is the smallest dx for which (r1 - dx)² + (r1 - dy)²
    // ≤ r1² where r1 = radius - 1.
    const u32 r1 = radius - 1U;
    const u32 r1_sq = r1 * r1;
    for (u32 dy = 0; dy < radius; ++dy)
    {
        const u32 vy = r1 - dy;
        const u32 vy_sq = vy * vy;
        u32 dx = 0;
        while (dx < radius)
        {
            const u32 vx = r1 - dx;
            if (vx * vx + vy_sq <= r1_sq)
            {
                break;
            }
            ++dx;
        }
        // Rows are inset by `dx` on each side; if `dx` equals or
        // exceeds w/2 the row is empty (would happen for very
        // small rects with the radius clamp; FillRect handles 0).
        const u32 row_w = (2U * dx >= w) ? 0U : (w - 2U * dx);
        if (row_w == 0)
        {
            continue;
        }
        // Top corner row: y + dy.
        FramebufferFillRect(x + dx, y + dy, row_w, 1U, rgb);
        // Bottom corner row: y + h - 1 - dy. Distinct from the
        // top row whenever h > 2*radius, but the clamp makes
        // 2*radius ≤ h, so y+h-1-dy ≥ y+radius for all dy in the
        // loop and the rows never collide with the middle band.
        FramebufferFillRect(x + dx, y + h - 1U - dy, row_w, 1U, rgb);
    }
}

void FramebufferSelfTest()
{
    if (!g_available)
    {
        SerialWrite("[video/fb] self-test skipped (no framebuffer)\n");
        return;
    }

    SerialWrite("[video/fb] self-test\n");

    // Clear to a dark slate so the swatches stand out. Also proves
    // the whole-surface fill path works — any MapMmio / pitch error
    // shows up as stripes or a partial clear.
    FramebufferClear(0x00101828);

    // Corner swatches — 64x64 each. Colour choice: unambiguous hue
    // per corner so a human looking at the screen can verify the
    // channel order (R top-left, G top-right, B bottom-left, white
    // bottom-right).
    constexpr u32 kSwatch = 64;
    FramebufferFillRect(0, 0, kSwatch, kSwatch, 0x00FF0000);                                            // red
    FramebufferFillRect(g_info.width - kSwatch, 0, kSwatch, kSwatch, 0x0000FF00);                       // green
    FramebufferFillRect(0, g_info.height - kSwatch, kSwatch, kSwatch, 0x000000FF);                      // blue
    FramebufferFillRect(g_info.width - kSwatch, g_info.height - kSwatch, kSwatch, kSwatch, 0x00FFFFFF); // white

    // 2-pixel framing rectangle along the outer edge. Top + bottom
    // bands cover the corners of the side bands, which is fine —
    // the colour is the same.
    constexpr u32 kFrame = 2;
    FramebufferFillRect(0, 0, g_info.width, kFrame, 0x0080A0FF);                      // top
    FramebufferFillRect(0, g_info.height - kFrame, g_info.width, kFrame, 0x0080A0FF); // bottom
    FramebufferFillRect(0, 0, kFrame, g_info.height, 0x0080A0FF);                     // left
    FramebufferFillRect(g_info.width - kFrame, 0, kFrame, g_info.height, 0x0080A0FF); // right

    SerialWrite("[video/fb] self-test OK\n");
}

} // namespace duetos::drivers::video
