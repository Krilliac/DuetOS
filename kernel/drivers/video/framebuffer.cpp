#include "framebuffer.h"

#include "../../arch/x86_64/serial.h"
#include "../../mm/multiboot2.h"
#include "../../mm/paging.h"
#include "font8x8.h"

namespace customos::drivers::video
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
    auto* row = reinterpret_cast<volatile u32*>(reinterpret_cast<u8*>(g_info.virt) + static_cast<u64>(y) * g_info.pitch);
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
    FramebufferFillRect(x, y, w, thickness, rgb);                        // top
    FramebufferFillRect(x, y + h - thickness, w, thickness, rgb);        // bottom
    FramebufferFillRect(x, y, thickness, h, rgb);                        // left
    FramebufferFillRect(x + w - thickness, y, thickness, h, rgb);        // right
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
    FramebufferFillRect(0, 0, kSwatch, kSwatch, 0x00FF0000);                                                // red
    FramebufferFillRect(g_info.width - kSwatch, 0, kSwatch, kSwatch, 0x0000FF00);                           // green
    FramebufferFillRect(0, g_info.height - kSwatch, kSwatch, kSwatch, 0x000000FF);                          // blue
    FramebufferFillRect(g_info.width - kSwatch, g_info.height - kSwatch, kSwatch, kSwatch, 0x00FFFFFF);     // white

    // 2-pixel framing rectangle along the outer edge. Top + bottom
    // bands cover the corners of the side bands, which is fine —
    // the colour is the same.
    constexpr u32 kFrame = 2;
    FramebufferFillRect(0, 0, g_info.width, kFrame, 0x0080A0FF);                             // top
    FramebufferFillRect(0, g_info.height - kFrame, g_info.width, kFrame, 0x0080A0FF);        // bottom
    FramebufferFillRect(0, 0, kFrame, g_info.height, 0x0080A0FF);                            // left
    FramebufferFillRect(g_info.width - kFrame, 0, kFrame, g_info.height, 0x0080A0FF);        // right

    SerialWrite("[video/fb] self-test OK\n");
}

} // namespace customos::drivers::video
