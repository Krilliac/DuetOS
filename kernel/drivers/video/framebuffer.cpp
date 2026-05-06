#include "drivers/video/framebuffer.h"

#include "arch/x86_64/serial.h"
#include "mm/frame_allocator.h"
#include "mm/multiboot2.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "drivers/video/font8x8.h"
#include "drivers/video/render_stats.h"

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
// Multiboot2 info physical address captured by the first call to
// FramebufferInit. Re-used by FramebufferReinit so a driver fault-
// domain restart can find the framebuffer tag again without
// thread-ing the address through every call site.
constinit uptr g_saved_mb_info = 0;
// Forward decl — the storage lives further down the TU next to the
// hook accessor pair, but FramebufferTeardown needs to clear it.
extern FramebufferPresentFn g_present_hook;

// Offscreen shadow surface — see `FramebufferBeginCompose`. Sized to
// the live framebuffer (`g_info.width * g_info.height * 4` bytes,
// tightly packed) and allocated lazily from the physical frame
// allocator the first time compose is requested. Pitch is always
// `g_info.width * 4` so the inner loop's row stride is a single
// multiplication; the live framebuffer's pitch padding is handled
// only at the End-of-compose memcpy.
constinit void* g_shadow_base = nullptr;
constinit u32 g_shadow_pitch = 0;
constinit bool g_compose_active = false;

// Damage union. Every pixel-write primitive routes its post-clip
// rect through `MarkDamage` so the compose-end blit and the present
// hook can flush only the dirty region. The math lives on
// `DamageRect::Extend` — see framebuffer.h. `valid == false` means
// "no writes yet this frame" so the End-of-compose path can skip
// the row copy entirely. The union is reset by
// `FramebufferResetDamage`, which `FramebufferPresent` calls after
// the hook has consumed it.
constinit DamageRect g_damage = {};

// Mark `(x, y, w, h)` as dirty. Caller is responsible for already
// having clipped the rect to the surface; passing zero width or
// height is a silent no-op (Extend short-circuits on either) so
// primitives that early-out on empty clip rects don't have to add
// a second branch.
inline void MarkDamage(u32 x, u32 y, u32 w, u32 h)
{
    g_damage.Extend(x, y, w, h);
}

// Single source of truth for "where do pixel writes go". Called by
// every primitive's inner loop; the cost is one dependent load +
// branch per primitive call (NOT per pixel — primitives hoist the
// result out of the loop). Returning by value avoids any aliasing
// concerns the compiler might otherwise have to defend against.
struct WriteTarget
{
    u8* base;
    u32 pitch;
};

inline WriteTarget GetWriteTarget()
{
    if (g_compose_active && g_shadow_base != nullptr)
    {
        return {reinterpret_cast<u8*>(g_shadow_base), g_shadow_pitch};
    }
    return {reinterpret_cast<u8*>(g_info.virt), g_info.pitch};
}

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
    // Stash for FramebufferReinit. Done before any early-return so
    // a re-init after teardown still has the multiboot pointer
    // even if the first call ended up disabled (no tag, etc.).
    g_saved_mb_info = multiboot_info_phys;

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

void FramebufferTeardown()
{
    // Mark the surface unavailable first so any draw call racing
    // with the teardown bails out at the !Available() guard.
    g_available = false;
    // Drop every cached parameter. The MMIO arena is a bump
    // allocator so the previous mapping leaks — documented as
    // "cheap" (a 1024x768x32 buffer is 3 MiB out of a 512 MiB
    // arena). A future slice that adds an actual unmap path can
    // wire it in here.
    g_info = FramebufferInfo{};
    // Compose state — drop the shadow buffer reference. The
    // backing pages stay allocated (we don't free here either)
    // but the next BeginCompose/EndCompose pair runs through the
    // lazy-allocate path and re-creates the shadow at the new
    // dimensions if Reinit picked a different mode.
    g_shadow_base = nullptr;
    g_shadow_pitch = 0;
    g_compose_active = false;
    // Damage union — reset so a Reinit at different geometry
    // doesn't carry forward a rect that's now off-surface.
    g_damage.Reset();
    // Present hook + the init guard. Re-init re-arms the hook
    // through whatever backend (virtio-gpu, etc.) registers
    // again on its own restart path.
    g_present_hook = nullptr;
    g_init_called = false;
    SerialWrite("[video/fb] teardown — surface offline\n");
}

void FramebufferReinit()
{
    // Driver fault-domain init lambdas take no args, so the saved
    // multiboot info phys (captured on the first FramebufferInit)
    // gets threaded through here. If the first init never ran
    // (boot took a path that disabled the framebuffer entirely),
    // g_saved_mb_info stays 0 and FramebufferInit handles that
    // case the same way it does at boot — log + leave disabled.
    FramebufferInit(g_saved_mb_info);
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
    const DamageRect d = FramebufferReadDamage();
    if (g_present_hook != nullptr)
    {
        g_present_hook(d);
    }
    // Stats track every present pass — including the no-hook case
    // (firmware framebuffer, Bochs VBE) — so the partial vs. full
    // ratio reflects the compositor's behaviour rather than the
    // backend's. Recorded BEFORE damage reset so the snapshot is
    // accurate.
    RenderStatsOnPresent(d, g_info.width, g_info.height);
    // Either way, the damage union belongs to the just-presented
    // frame — the next compose pass starts clean. Hooks that need
    // the rect take a snapshot above; running this unconditionally
    // means callers without a hook (firmware framebuffer, Bochs
    // VBE) also start each frame from a clean union.
    FramebufferResetDamage();
}

void FramebufferAddDamage(u32 x, u32 y, u32 w, u32 h)
{
    if (!g_available || w == 0 || h == 0)
        return;
    if (x >= g_info.width || y >= g_info.height)
        return;
    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;
    MarkDamage(x, y, x_end - x, y_end - y);
}

DamageRect FramebufferReadDamage()
{
    return g_damage;
}

void FramebufferResetDamage()
{
    g_damage.Reset();
}

void FramebufferBeginCompose()
{
    if (!g_available || g_compose_active)
        return;

    if (g_shadow_base == nullptr)
    {
        // Tightly packed: width * 4 bytes per row, no padding.
        const u64 bytes = static_cast<u64>(g_info.width) * 4ULL * g_info.height;
        const u64 frames = (bytes + (mm::kPageSize - 1ULL)) >> mm::kPageSizeLog2;
        const auto phys = mm::AllocateContiguousFrames(frames);
        if (phys == mm::kNullFrame)
        {
            // Allocator exhausted — fall back to direct-to-MMIO mode.
            // `g_compose_active` stays false so `GetWriteTarget` keeps
            // pointing at the live framebuffer.
            SerialWrite("[video/fb] shadow alloc failed (frames=");
            SerialWriteHex(frames);
            SerialWrite(") — staying direct\n");
            return;
        }
        g_shadow_base = mm::PhysToVirt(phys);
        g_shadow_pitch = g_info.width * 4U;
        SerialWrite("[video/fb] shadow online bytes=");
        SerialWriteHex(bytes);
        SerialWrite(" virt=");
        SerialWriteHex(reinterpret_cast<u64>(g_shadow_base));
        SerialWrite("\n");
    }
    g_compose_active = true;
}

void FramebufferEndCompose()
{
    if (!g_compose_active)
        return;
    // Flush the shadow surface to the live framebuffer. Pitches
    // differ in general (live may have padding), so the copy is
    // row-by-row rather than a single memcpy.
    //
    // If the compose pass accumulated a damage union, copy only
    // those rows + columns. The compose buffer holds last frame's
    // pixels outside the damage rect, so a partial copy preserves
    // unchanged regions on screen (which is exactly what we want
    // — they were already correct). When `g_damage.valid` is false
    // the frame painted nothing, and the copy below short-circuits
    // before touching the live framebuffer at all.
    if (!g_damage.valid)
    {
        g_compose_active = false;
        RenderStatsOnComposeEnd();
        return;
    }
    const u32 cx = g_damage.x;
    const u32 cy = g_damage.y;
    const u32 cx_end = g_damage.x + g_damage.w;
    const u32 cy_end = g_damage.y + g_damage.h;
    auto* src_bytes = reinterpret_cast<const u8*>(g_shadow_base);
    auto* dst_bytes = reinterpret_cast<u8*>(g_info.virt);
    for (u32 yi = cy; yi < cy_end; ++yi)
    {
        const auto* src_row = reinterpret_cast<const u32*>(src_bytes + static_cast<u64>(yi) * g_shadow_pitch);
        auto* dst_row = reinterpret_cast<volatile u32*>(dst_bytes + static_cast<u64>(yi) * g_info.pitch);
        for (u32 xi = cx; xi < cx_end; ++xi)
        {
            dst_row[xi] = src_row[xi];
        }
    }
    g_compose_active = false;
    RenderStatsOnComposeEnd();
}

bool FramebufferComposeActive()
{
    return g_compose_active;
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
    const WriteTarget wt = GetWriteTarget();
    auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(y) * wt.pitch);
    row[x] = rgb;
    MarkDamage(x, y, 1, 1);
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

    const WriteTarget wt = GetWriteTarget();
    for (u32 yi = y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(yi) * wt.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            row[xi] = rgb;
        }
    }
    MarkDamage(x, y, x_end - x, y_end - y);
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

    const WriteTarget wt = GetWriteTarget();
    for (u32 yi = dst_y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(yi) * wt.pitch);
        const u32* src_row = src + static_cast<u64>(yi - dst_y) * src_pitch_px;
        for (u32 xi = dst_x; xi < x_end; ++xi)
        {
            row[xi] = src_row[xi - dst_x];
        }
    }
    MarkDamage(dst_x, dst_y, x_end - dst_x, y_end - dst_y);
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

namespace
{
// Render one 8x8 glyph at (x, y) with each source pixel as a
// `scale x scale` filled rect. A 0-scale or out-of-range
// scale collapses to scale=1 to keep the call defensive.
void DrawCharScaled(u32 x, u32 y, char ch, u32 fg, u32 bg, u32 scale)
{
    if (scale == 0)
        scale = 1;
    if (scale > 8)
        scale = 8;
    const u8* glyph = Font8x8Lookup(ch);
    for (u32 row = 0; row < kGlyphHeight; ++row)
    {
        const u8 bits = glyph[row];
        for (u32 col = 0; col < kGlyphWidth; ++col)
        {
            const bool on = (bits & (0x80U >> col)) != 0;
            FramebufferFillRect(x + col * scale, y + row * scale, scale, scale, on ? fg : bg);
        }
    }
}
} // namespace

void FramebufferDrawStringScaled(u32 x, u32 y, const char* text, u32 fg, u32 bg, u32 scale)
{
    if (!g_available || text == nullptr)
        return;
    if (scale == 0)
        scale = 1;
    if (scale > 8)
        scale = 8;
    const u32 cell = kGlyphWidth * scale;
    u32 cx = x;
    while (*text != '\0')
    {
        if (cx + cell > g_info.width)
            break;
        DrawCharScaled(cx, y, *text, fg, bg, scale);
        cx += cell;
        ++text;
    }
}

u32 StringPixelWidthScaled(const char* text, u32 scale)
{
    if (text == nullptr)
        return 0;
    if (scale == 0)
        scale = 1;
    if (scale > 8)
        scale = 8;
    u32 n = 0;
    while (text[n] != '\0')
        ++n;
    return n * kGlyphWidth * scale;
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

    const WriteTarget wt = GetWriteTarget();
    for (u32 yi = y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(yi) * wt.pitch);
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
    MarkDamage(x, y, x_end - x, y_end - y);
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

    const WriteTarget wt = GetWriteTarget();
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
        auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(yi) * wt.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            row[xi] = c;
        }
    }
    MarkDamage(x, y, x_end - x, y_end - y);
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

// Safety cap on the per-line iteration count so a malicious caller
// passing absurd endpoints can't spin the compositor. 8K covers any
// plausible diagonal at 4K resolution; anything larger is a bug.
constexpr u32 kFbMaxLinePixels = 8192;

void FramebufferDrawLine(i32 x0, i32 y0, i32 x1, i32 y1, u32 rgb)
{
    if (!g_available)
    {
        return;
    }
    // Standard Bresenham, all-octant. The signed deltas keep the
    // four-quadrant logic out of the inner loop.
    const i32 dx = (x1 >= x0) ? (x1 - x0) : (x0 - x1);
    const i32 sx = (x1 >= x0) ? 1 : -1;
    const i32 dy = -((y1 >= y0) ? (y1 - y0) : (y0 - y1));
    const i32 sy = (y1 >= y0) ? 1 : -1;
    i32 err = dx + dy;
    i32 x = x0;
    i32 y = y0;
    for (u32 step = 0; step < kFbMaxLinePixels; ++step)
    {
        if (x >= 0 && y >= 0 && static_cast<u32>(x) < g_info.width && static_cast<u32>(y) < g_info.height)
        {
            FramebufferPutPixel(static_cast<u32>(x), static_cast<u32>(y), rgb);
        }
        if (x == x1 && y == y1)
        {
            break;
        }
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

namespace
{

// Plot the eight symmetric points around `(cx, cy)` for one
// midpoint-circle iteration step. Each plot is independently
// surface-clipped — a circle that hangs off the framebuffer
// only loses the off-screen octants.
void Plot8(i32 cx, i32 cy, i32 dx, i32 dy, u32 rgb)
{
    const i32 pts_x[8] = {cx + dx, cx - dx, cx + dx, cx - dx, cx + dy, cx - dy, cx + dy, cx - dy};
    const i32 pts_y[8] = {cy + dy, cy + dy, cy - dy, cy - dy, cy + dx, cy + dx, cy - dx, cy - dx};
    for (u32 k = 0; k < 8; ++k)
    {
        if (pts_x[k] >= 0 && pts_y[k] >= 0 && static_cast<u32>(pts_x[k]) < g_info.width &&
            static_cast<u32>(pts_y[k]) < g_info.height)
        {
            FramebufferPutPixel(static_cast<u32>(pts_x[k]), static_cast<u32>(pts_y[k]), rgb);
        }
    }
}

} // namespace

void FramebufferDrawCircle(i32 cx, i32 cy, u32 radius, u32 rgb)
{
    if (!g_available)
    {
        return;
    }
    if (radius == 0)
    {
        if (cx >= 0 && cy >= 0 && static_cast<u32>(cx) < g_info.width && static_cast<u32>(cy) < g_info.height)
        {
            FramebufferPutPixel(static_cast<u32>(cx), static_cast<u32>(cy), rgb);
        }
        return;
    }
    // Midpoint algorithm. Iterate dx from 0 outward; dy starts at
    // r and walks inward. Decision variable `d` tracks the signed
    // distance from the true arc.
    i32 dx = 0;
    i32 dy = static_cast<i32>(radius);
    i32 d = 1 - dy;
    while (dx <= dy)
    {
        Plot8(cx, cy, dx, dy, rgb);
        ++dx;
        if (d < 0)
        {
            d += 2 * dx + 1;
        }
        else
        {
            --dy;
            d += 2 * (dx - dy) + 1;
        }
    }
}

void FramebufferFillCircle(i32 cx, i32 cy, u32 radius, u32 rgb)
{
    if (!g_available)
    {
        return;
    }
    if (radius == 0)
    {
        if (cx >= 0 && cy >= 0 && static_cast<u32>(cx) < g_info.width && static_cast<u32>(cy) < g_info.height)
        {
            FramebufferPutPixel(static_cast<u32>(cx), static_cast<u32>(cy), rgb);
        }
        return;
    }
    // Per-row span: for each y in [cy-r, cy+r], the row's half-
    // width is floor(sqrt(r² - dy²)). Computed via integer test
    // so we don't pull in libm. Walk an outer pointer right-ward
    // until the squared distance crosses r² — bounded by r so
    // the cost is O(r²) total writes, which is exactly the
    // number of painted pixels.
    const i32 r = static_cast<i32>(radius);
    const i64 r2 = static_cast<i64>(r) * r;
    for (i32 dy = -r; dy <= r; ++dy)
    {
        const i64 dy2 = static_cast<i64>(dy) * dy;
        // Walk dx outward from 0 until the test fails — gives
        // the largest dx with dx² + dy² ≤ r².
        i32 dx = 0;
        while (dx <= r && static_cast<i64>(dx) * dx + dy2 <= r2)
        {
            ++dx;
        }
        --dx;
        if (dx < 0)
            continue;
        const i32 row_y = cy + dy;
        const i32 row_x = cx - dx;
        const u32 row_w = static_cast<u32>(2 * dx + 1);
        if (row_y < 0 || static_cast<u32>(row_y) >= g_info.height)
            continue;
        // Clip the span to the surface; FramebufferFillRect is
        // already coordinate-clipped but skipping the row when
        // it's entirely off-screen avoids a no-op call.
        i32 left = row_x;
        i32 right = row_x + static_cast<i32>(row_w);
        if (left < 0)
            left = 0;
        if (right > static_cast<i32>(g_info.width))
            right = static_cast<i32>(g_info.width);
        if (right <= left)
            continue;
        FramebufferFillRect(static_cast<u32>(left), static_cast<u32>(row_y), static_cast<u32>(right - left), 1U, rgb);
    }
}

void FramebufferDrawRoundRect(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 rgb)
{
    if (!g_available || w == 0 || h == 0)
    {
        return;
    }
    const u32 max_r = (w < h ? w : h) / 2U;
    if (radius > max_r)
    {
        radius = max_r;
    }
    if (radius == 0)
    {
        // Fall through to a 1-pixel rectangular outline.
        FramebufferDrawRect(x, y, w, h, rgb, 1);
        return;
    }
    // Straight edges between the corner arcs. Top + bottom run
    // from x+radius to x+w-radius; left + right run from y+radius
    // to y+h-radius.
    if (w > 2 * radius)
    {
        FramebufferFillRect(x + radius, y, w - 2 * radius, 1U, rgb);          // top edge
        FramebufferFillRect(x + radius, y + h - 1U, w - 2 * radius, 1U, rgb); // bottom edge
    }
    if (h > 2 * radius)
    {
        FramebufferFillRect(x, y + radius, 1U, h - 2 * radius, rgb);          // left edge
        FramebufferFillRect(x + w - 1U, y + radius, 1U, h - 2 * radius, rgb); // right edge
    }
    // Four corner arcs. Each arc lives inside a `radius × radius`
    // square at the corresponding corner; iterate the same
    // midpoint-style indent the fill primitive uses but plot only
    // the boundary pixel (the smallest dx for each dy).
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
        if (dx >= radius)
            continue;
        // Top-left corner pixel: (x + dx, y + dy).
        FramebufferPutPixel(x + dx, y + dy, rgb);
        // Top-right corner pixel.
        FramebufferPutPixel(x + w - 1U - dx, y + dy, rgb);
        // Bottom-left corner pixel.
        FramebufferPutPixel(x + dx, y + h - 1U - dy, rgb);
        // Bottom-right corner pixel.
        FramebufferPutPixel(x + w - 1U - dx, y + h - 1U - dy, rgb);
    }
}

void FramebufferPunchCorners(u32 x, u32 y, u32 w, u32 h, u32 radius, u32 punch_rgb)
{
    if (!g_available || w == 0 || h == 0 || radius == 0)
    {
        return;
    }
    const u32 max_r = (w < h ? w : h) / 2U;
    if (radius > max_r)
    {
        radius = max_r;
    }
    if (radius == 0)
    {
        return;
    }
    // Walk the (radius × radius) corner square. For each row
    // (dy), find the smallest `dx` for which the pixel lies
    // INSIDE the rounded curve — every column to the left of
    // that dx is outside the curve and gets the punch colour.
    // Mirror the result to all four corners.
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
        if (dx == 0)
            continue; // entire row is inside the curve — no punch
        // Top-left: paint columns [0, dx) at row dy.
        FramebufferFillRect(x, y + dy, dx, 1U, punch_rgb);
        // Top-right: paint the mirrored span at row dy.
        FramebufferFillRect(x + w - dx, y + dy, dx, 1U, punch_rgb);
        // Bottom-left.
        FramebufferFillRect(x, y + h - 1U - dy, dx, 1U, punch_rgb);
        // Bottom-right.
        FramebufferFillRect(x + w - dx, y + h - 1U - dy, dx, 1U, punch_rgb);
    }
}

namespace
{

// Q16.16 sin values for [0°, 90°]. Generated offline from
// `sin(d * π / 180) * 65536`, rounded to nearest. 91 entries
// is enough for full-circle work via quadrant mirroring.
constexpr i32 kSinDegQ16[91] = {
    0,     1144,  2287,  3430,  4572,  5712,  6850,  7987,  9121,  10252, 11380, 12505, 13626, 14742, 15855, 16962,
    18064, 19161, 20252, 21336, 22415, 23486, 24550, 25607, 26656, 27697, 28729, 29753, 30767, 31772, 32768, 33754,
    34729, 35693, 36647, 37590, 38521, 39441, 40348, 41243, 42126, 42995, 43852, 44695, 45525, 46341, 47143, 47930,
    48703, 49461, 50203, 50931, 51643, 52339, 53020, 53684, 54332, 54963, 55578, 56175, 56756, 57319, 57865, 58393,
    58903, 59396, 59870, 60326, 60764, 61183, 61584, 61966, 62328, 62672, 62997, 63303, 63589, 63856, 64104, 64332,
    64540, 64729, 64898, 65048, 65177, 65287, 65376, 65446, 65496, 65526, 65536,
};

// Reduce `deg` to the canonical range [0, 360).
i32 NormalizeDeg(i32 deg)
{
    deg %= 360;
    if (deg < 0)
        deg += 360;
    return deg;
}

// Q16.16 sin / cos via quadrant mirroring of the [0, 90°] table.
// Inputs are integer degrees; results are i32 in Q16.16.
i32 SinDegQ16(i32 deg)
{
    deg = NormalizeDeg(deg);
    if (deg <= 90)
        return kSinDegQ16[deg];
    if (deg <= 180)
        return kSinDegQ16[180 - deg];
    if (deg <= 270)
        return -kSinDegQ16[deg - 180];
    return -kSinDegQ16[360 - deg];
}

i32 CosDegQ16(i32 deg)
{
    return SinDegQ16(deg + 90);
}

} // namespace

void FramebufferStrokeArc(i32 cx, i32 cy, i32 radius, i32 start_deg, i32 sweep_deg, u32 thickness, u32 rgb)
{
    if (!g_available || radius <= 0 || thickness == 0)
    {
        return;
    }
    // Normalize the sweep direction to a positive walk so the
    // inner loop is monotonic. A negative sweep flips the start
    // and direction.
    i32 walk_steps = sweep_deg;
    i32 step_sign = 1;
    if (walk_steps < 0)
    {
        walk_steps = -walk_steps;
        step_sign = -1;
    }
    // Sweeps > 360° just paint the full circle (idempotent
    // pixels are no problem); cap so the inner loop is bounded.
    if (walk_steps > 360)
    {
        walk_steps = 360;
    }
    // Thickness: walk concentric arcs at radii in
    // [r - half, r - half + thickness). Half-step asymmetry
    // gives a 2-px stroke at radii (r, r+1), 3-px at (r-1, r,
    // r+1), 4-px at (r-1, r, r+1, r+2), etc.
    const i32 half = static_cast<i32>(thickness / 2);
    for (i32 d = 0; d <= walk_steps; ++d)
    {
        const i32 angle = start_deg + step_sign * d;
        const i32 c = CosDegQ16(angle);
        const i32 s = SinDegQ16(angle);
        for (u32 t = 0; t < thickness; ++t)
        {
            const i32 r = radius - half + static_cast<i32>(t);
            if (r <= 0)
                continue;
            // (cx + cos*r, cy + sin*r), rounded.
            const i32 dx = static_cast<i32>((static_cast<i64>(c) * r) >> 16);
            const i32 dy = static_cast<i32>((static_cast<i64>(s) * r) >> 16);
            const i32 px = cx + dx;
            const i32 py = cy + dy;
            if (px >= 0 && py >= 0 && static_cast<u32>(px) < g_info.width && static_cast<u32>(py) < g_info.height)
            {
                FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py), rgb);
            }
        }
    }
}

namespace
{

// Stamp a `thickness x thickness` square centred on (x, y).
// Pixels outside the framebuffer are clipped per-pixel because
// `FramebufferFillRect` takes unsigned coords; we test before
// computing top-left.
void StampThick(i32 x, i32 y, u32 thickness, u32 rgb)
{
    if (thickness == 0)
        return;
    if (thickness == 1)
    {
        if (x >= 0 && y >= 0 && static_cast<u32>(x) < g_info.width && static_cast<u32>(y) < g_info.height)
        {
            FramebufferPutPixel(static_cast<u32>(x), static_cast<u32>(y), rgb);
        }
        return;
    }
    const i32 half = static_cast<i32>(thickness / 2);
    const i32 left = x - half;
    const i32 top = y - half;
    // Clamp to fb bounds without dropping the entire stamp.
    i32 x0 = (left < 0) ? 0 : left;
    i32 y0 = (top < 0) ? 0 : top;
    i32 x1 = left + static_cast<i32>(thickness);
    i32 y1 = top + static_cast<i32>(thickness);
    if (x1 > static_cast<i32>(g_info.width))
        x1 = static_cast<i32>(g_info.width);
    if (y1 > static_cast<i32>(g_info.height))
        y1 = static_cast<i32>(g_info.height);
    if (x0 >= x1 || y0 >= y1)
        return;
    FramebufferFillRect(static_cast<u32>(x0), static_cast<u32>(y0), static_cast<u32>(x1 - x0),
                        static_cast<u32>(y1 - y0), rgb);
}

// Bresenham line walk with a thickness stamp at each pixel.
// Adjacent stamps overlap by (thickness - 1) so the visual is a
// continuous thick line. For thickness 1, falls through to the
// existing Bresenham primitive.
void StrokeThickLine(i32 x0, i32 y0, i32 x1, i32 y1, u32 thickness, u32 rgb)
{
    if (thickness <= 1)
    {
        FramebufferDrawLine(x0, y0, x1, y1, rgb);
        return;
    }
    const i32 dx = (x1 > x0) ? (x1 - x0) : (x0 - x1);
    const i32 dy = (y1 > y0) ? (y1 - y0) : (y0 - y1);
    const i32 sx = (x0 < x1) ? 1 : -1;
    const i32 sy = (y0 < y1) ? 1 : -1;
    i32 err = (dx > dy ? dx : -dy) / 2;
    i32 x = x0;
    i32 y = y0;
    // Hard cap to mirror DrawLine's `kFbMaxLinePixels` runaway-input guard.
    constexpr i32 kMaxSteps = 8192;
    for (i32 step = 0; step <= kMaxSteps; ++step)
    {
        StampThick(x, y, thickness, rgb);
        if (x == x1 && y == y1)
            return;
        const i32 e2 = err;
        if (e2 > -dx)
        {
            err -= dy;
            x += sx;
        }
        if (e2 < dy)
        {
            err += dx;
            y += sy;
        }
    }
}

// Adaptive de Casteljau cubic Bézier flattener. Subdivides at
// t=0.5 until both control points are within 1 pixel of the
// chord (squared-distance test) or recursion depth hits 8.
// Each leaf segment is stroked as a thick line.
void FlattenCubic(i32 x0, i32 y0, i32 x1, i32 y1, i32 x2, i32 y2, i32 x3, i32 y3, u32 thickness, u32 rgb, u32 depth)
{
    auto chord_dist_sq = [](i32 px, i32 py, i32 ax, i32 ay, i32 bx, i32 by) -> i64
    {
        // |2A| of triangle (A, B, P) = |(bx-ax)(ay-py) - (ax-px)(by-ay)|
        const i64 num = static_cast<i64>(bx - ax) * (ay - py) - static_cast<i64>(ax - px) * (by - ay);
        const i64 abs_num = (num < 0) ? -num : num;
        const i64 denom = static_cast<i64>(bx - ax) * (bx - ax) + static_cast<i64>(by - ay) * (by - ay);
        if (denom == 0)
        {
            // Degenerate chord — distance is just |P - A|².
            const i64 ddx = px - ax;
            const i64 ddy = py - ay;
            return ddx * ddx + ddy * ddy;
        }
        return (abs_num * abs_num) / denom;
    };

    if (depth >= 8 || (chord_dist_sq(x1, y1, x0, y0, x3, y3) <= 1 && chord_dist_sq(x2, y2, x0, y0, x3, y3) <= 1))
    {
        StrokeThickLine(x0, y0, x3, y3, thickness, rgb);
        return;
    }
    // Single-step de Casteljau midpoint subdivision.
    const i32 m01x = (x0 + x1) / 2;
    const i32 m01y = (y0 + y1) / 2;
    const i32 m12x = (x1 + x2) / 2;
    const i32 m12y = (y1 + y2) / 2;
    const i32 m23x = (x2 + x3) / 2;
    const i32 m23y = (y2 + y3) / 2;
    const i32 m012x = (m01x + m12x) / 2;
    const i32 m012y = (m01y + m12y) / 2;
    const i32 m123x = (m12x + m23x) / 2;
    const i32 m123y = (m12y + m23y) / 2;
    const i32 m0123x = (m012x + m123x) / 2;
    const i32 m0123y = (m012y + m123y) / 2;

    FlattenCubic(x0, y0, m01x, m01y, m012x, m012y, m0123x, m0123y, thickness, rgb, depth + 1);
    FlattenCubic(m0123x, m0123y, m123x, m123y, m23x, m23y, x3, y3, thickness, rgb, depth + 1);
}

} // namespace

void FramebufferStrokePath(const PathSegment* segments, u32 count, u32 thickness, u32 rgb)
{
    if (!g_available || segments == nullptr || count == 0 || thickness == 0)
    {
        return;
    }
    // Pen state: `pen_*` is the current position, `start_*` is
    // the most recent Move (target of `Close`). A bare op without
    // a Move implicitly anchors at (0, 0).
    i32 pen_x = 0;
    i32 pen_y = 0;
    i32 start_x = 0;
    i32 start_y = 0;
    for (u32 i = 0; i < count; ++i)
    {
        const PathSegment& s = segments[i];
        switch (s.op)
        {
        case PathOp::Move:
            pen_x = s.pts[0].x;
            pen_y = s.pts[0].y;
            start_x = pen_x;
            start_y = pen_y;
            break;
        case PathOp::Line:
            StrokeThickLine(pen_x, pen_y, s.pts[0].x, s.pts[0].y, thickness, rgb);
            pen_x = s.pts[0].x;
            pen_y = s.pts[0].y;
            break;
        case PathOp::Cubic:
            FlattenCubic(pen_x, pen_y, s.pts[0].x, s.pts[0].y, s.pts[1].x, s.pts[1].y, s.pts[2].x, s.pts[2].y,
                         thickness, rgb, 0);
            pen_x = s.pts[2].x;
            pen_y = s.pts[2].y;
            break;
        case PathOp::Close:
            StrokeThickLine(pen_x, pen_y, start_x, start_y, thickness, rgb);
            pen_x = start_x;
            pen_y = start_y;
            break;
        }
    }
}

void FramebufferDropShadow(u32 x, u32 y, u32 w, u32 h, u32 depth, u8 start_alpha)
{
    if (!g_available || w == 0 || h == 0 || depth == 0 || start_alpha == 0)
    {
        return;
    }
    // Each shadow band is one pixel inset further from the
    // source rect; alpha decreases linearly from `start_alpha` to
    // zero at the outermost band, so the shadow fades out into
    // the desktop. `depth+1` divisions to avoid alpha hitting 0
    // before the last band (which would be a wasted pass).
    for (u32 d = 0; d < depth; ++d)
    {
        // Linear ramp: alpha at band d is start_alpha * (depth - d) / depth.
        const u32 a = (static_cast<u32>(start_alpha) * (depth - d)) / depth;
        if (a == 0)
            continue;
        const u32 argb = (a << 24); // black tint
        // Right band: 1px column from (x+w+d, y+d+1) down to
        // (x+w+d, y+h+d). The +d+1 vertical offset offsets the
        // shadow downward so it reads as cast from a light from
        // top-left, matching the chrome convention.
        FramebufferFillRectAlpha(x + w + d, y + 1U + d, 1U, h, argb);
        // Bottom band: 1px row from (x+d+1, y+h+d) across to
        // (x+w+d, y+h+d). Includes the corner pixel that the
        // right band already touched at (x+w+d, y+h+d) — the
        // double-blend is harmless (alpha blending is idempotent
        // at the same source colour for a single-pixel overlap).
        FramebufferFillRectAlpha(x + 1U + d, y + h + d, w, 1U, argb);
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
