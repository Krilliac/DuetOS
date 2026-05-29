#include "drivers/video/framebuffer.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "drivers/video/blend_math.h"
#include "drivers/video/font8x8.h"
#include "drivers/video/render_stats.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/multiboot2.h"
#include "mm/page.h"
#include "mm/paging.h"

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

// Presented-frame snapshot — the pixels currently on the live
// framebuffer (== frame N-1's composite), kept in normal RAM with
// the same tightly-packed `width * 4` layout as the shadow. Allocated
// lazily alongside the shadow.
//
// `FramebufferEndCompose` diffs the freshly-composed shadow against
// this snapshot to derive the *exact* changed bounding box, then
// blits / presents only that. An idle desktop recomposes the whole
// surface into the shadow (DesktopCompose is unconditional by
// design — gating it on a hand-set dirty bit froze PE apps that
// repaint via the periodic tick; see #286/#288), but if the result
// is byte-identical to what's already on screen the diff is empty,
// the blit + present are skipped, and the virtio-gpu host round-trip
// (the visible 1 Hz VBox flicker + the mouse-lag lock contention)
// never happens. The decision is content-derived, so no paint path
// can "forget" to mark itself dirty — a pixel that genuinely changed
// is found by the compare; one that didn't is correctly skipped.
//
// `g_presented_valid` is false until the first full sync (snapshot
// pages are not guaranteed zeroed, and the very first frame must
// reach the screen in full regardless of their contents).
constinit void* g_presented_base = nullptr;
constinit bool g_presented_valid = false;

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

// --- Snapshot invalidation (direct-FB-writer hook) -----------------
//
// Pass A's compose elision diffs offscreen vs presented-snapshot and
// only blits divergent pixels. That's blind to writes that bypass the
// offscreen surface (the cursor sprite is the primary case — see
// drivers/video/cursor.cpp). When such a writer touches live FB, it
// must call `FramebufferInvalidateSnapshot` to tell the next EndCompose
// "the snapshot at this rect is no longer trustworthy — force a blit
// from the offscreen here regardless of pixel-level equality." The
// blit then writes offscreen contents (which lack the cursor sprite)
// to live FB, cleanly erasing the cursor pixels left behind by direct
// writes. The cursor is then re-painted into the next offscreen via
// `CursorOverlayInCompose` so the blit lands the cursor at the
// CURRENT position atomically.
//
// Bounded to 8 rects per compose cycle; on overflow new entries are
// merged into the nearest existing rect (degrading toward a single
// bounding box). Cursor sprite movement at PS/2 rate (~60 Hz) over a
// ~70 ms compose cycle produces at most ~4-8 invalidations — well
// within the cap before merging kicks in.
constexpr u32 kMaxInvalidations = 8;
constinit DamageRect g_invalidations[kMaxInvalidations] = {};
constinit u32 g_invalidation_count = 0;

// --- Multi-rect (banded) damage for the present path ---------------
//
// D1 fix. The content diff (FramebufferEndCompose) used to collapse
// every changed pixel into ONE bounding box. Spatially-separated
// changes — the taskbar clock (bottom-right) and a live widget
// (centre), say — fused into a near-fullscreen rect, so the
// virtio-gpu TRANSFER_TO_HOST_2D + RESOURCE_FLUSH still touched ~half
// the surface every compose (the residual VBox flicker). Instead we
// split the surface into horizontal bands and emit one tight rect
// per band that actually changed: vertically-separated widgets land
// in different bands and flush as small independent rects. A genuine
// large repaint dirties many contiguous bands; past `kCoalesceBands`
// we fall back to the single union bbox so we don't trade one big
// flush for dozens of virtio round-trips. `g_damage` still carries
// the union for render-stats + no-present-hook backends, so their
// behaviour is unchanged.
constexpr u32 kBandH = 64;
constexpr u32 kMaxDamageRects = 64; // covers surfaces up to 4096 px tall
constexpr u32 kCoalesceBands = 6;   // > this many dirty bands -> one union flush
constinit DamageRect g_damage_rects[kMaxDamageRects] = {};
constinit u32 g_damage_rect_count = 0;

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
    // Multiplication-overflow invariant. `pitch` and `height` are
    // firmware-supplied u32 fields; a malicious/buggy bootloader
    // that reports pitch=0xFFFFFFFF + height=0xFFFFFFFF wraps `bytes`
    // to a tiny value, MapMmio succeeds for the truncated range, and
    // FramebufferPresent below scribbles past the mapped region into
    // adjacent MMIO arena (or kernel memory if the arena is exhausted).
    // The sanity checks above bound `pitch >= width*4` but don't cap
    // either dimension — the multiplication itself is the only place
    // the wraparound is observable. KASSERT, not silent: a corrupt
    // bytes here means EVERY later pixel write is a wild store.
    KASSERT_WITH_VALUE(tag->height == 0 || bytes / tag->height == tag->pitch, "video/fb", "pitch * height overflow",
                       bytes);
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
    // Presented-frame snapshot — drop it too. Its backing pages
    // leak with the shadow's (same documented "cheap" tradeoff);
    // the next BeginCompose re-allocates at the new geometry, and
    // g_presented_valid=false forces a full first present so the
    // content-diff invariant rebuilds from scratch.
    g_presented_base = nullptr;
    g_presented_valid = false;
    // Damage union + banded rect list — reset so a Reinit at
    // different geometry doesn't carry forward a rect that's now
    // off-surface.
    g_damage.Reset();
    g_damage_rect_count = 0;
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
        // MMIO arena (the kernel's MapMmio reservation pool) is
        // saturated — typically means a driver leaked a region or
        // we reserved smaller than the framebuffer needs. Klog
        // captures the byte count so a post-mortem can sanity-
        // check against the arena cap.
        KLOG_ERROR_V("drivers/video/fb", "rebind MapMmio failed — MMIO arena exhausted? (bytes)", bytes);
        return false;
    }
    g_info.virt = virt;
    g_info.phys = phys;
    g_info.width = width;
    g_info.height = height;
    g_info.pitch = pitch;
    g_info.bpp = bpp;
    g_available = true;
    // Match FramebufferRebindExternal: a fresh live FB target moves
    // the snapshot out of sync with reality, so force the next
    // EndCompose to do a full first-frame blit instead of relying
    // on its content-diff (which would compare against a snapshot
    // that no longer reflects what's on the new screen).
    g_presented_valid = false;
    g_damage.Reset();
    g_damage_rect_count = 0;
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
    // The new live buffer (e.g. virtio-gpu's host-side scanout backing
    // populated by the driver's boot-proof test pattern) is OUT OF SYNC
    // with both the prior live FB and the EndCompose snapshot. If we
    // don't invalidate, the next compose's content-diff scan compares
    // shadow against the stale snapshot, finds them identical (the
    // compose paints the same scene), elides the blit, and the new
    // live FB keeps whatever the driver left there — typically the
    // host-side RGB diagonal+corner test pattern, with only the SVG-
    // bearing parts of the wallpaper overwritten on subsequent
    // partial-diff blits. Symptom: Classic + Amber themes (no SVG
    // wallpaper backdrop) showed the GPU test pattern at boot
    // instead of the themed desktop. Slate10 + Duet looked "ok"
    // only because their full-screen SVG wallpaper masked it.
    // Force a full first-frame blit on the next EndCompose by
    // dropping the snapshot's valid bit + the damage union.
    g_presented_valid = false;
    g_damage.Reset();
    g_damage_rect_count = 0;
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
    // True dirty pixel count + rect count for RenderStats. The
    // banded path's per-rect sum is what the GPU actually uploads;
    // the union bbox area overstates by `bbox - sum(rects)` when
    // bands are spatially separated. Computed regardless of whether
    // a present hook is registered so firmware-FB / Bochs-VBE
    // boots (no hook) still see accurate dirty-pixel stats.
    u64 dirty_pixels = 0;
    u32 rect_count = 0;
    if (d.valid)
    {
        if (g_damage_rect_count > 0)
        {
            rect_count = g_damage_rect_count;
            for (u32 i = 0; i < g_damage_rect_count; ++i)
            {
                dirty_pixels += static_cast<u64>(g_damage_rects[i].w) * g_damage_rects[i].h;
            }
        }
        else
        {
            rect_count = 1;
            dirty_pixels = static_cast<u64>(d.w) * d.h;
        }
    }
    if (g_present_hook != nullptr)
    {
        if (g_damage_rect_count > 0)
        {
            // Banded path: flush each disjoint dirty rect on its own
            // so spatially-separated changes don't fuse into one
            // near-fullscreen host transfer (the D1 flicker).
            for (u32 i = 0; i < g_damage_rect_count; ++i)
            {
                g_present_hook(g_damage_rects[i]);
            }
        }
        else
        {
            // Single-rect path: first frame, coalesced large repaint,
            // or a clean frame (d.valid == false -> hook skips).
            g_present_hook(d);
        }
    }
    // Stats track every present pass — including the no-hook case
    // (firmware framebuffer, Bochs VBE) — so the partial vs. full
    // ratio reflects the compositor's behaviour rather than the
    // backend's. Recorded BEFORE damage reset so the snapshot is
    // accurate.
    RenderStatsOnPresent(d, dirty_pixels, rect_count, g_info.width, g_info.height);
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
    g_damage_rect_count = 0;
}

void FramebufferDropSnapshot()
{
    g_presented_valid = false;
}

void FramebufferInvalidateSnapshot(u32 x, u32 y, u32 w, u32 h)
{
    if (!g_available || w == 0 || h == 0)
        return;
    if (x >= g_info.width || y >= g_info.height)
        return;
    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;
    const u32 cw = x_end - x;
    const u32 ch = y_end - y;

    // Try to merge into an existing rect that overlaps or touches the
    // new one — keeps the count small for cursor movements that pass
    // over (or near) the same region multiple times.
    for (u32 i = 0; i < g_invalidation_count; ++i)
    {
        const auto& r = g_invalidations[i];
        // Touch / overlap test: one rect's right edge >= the other's
        // left, AND vice versa, for both axes.
        if (x <= r.x + r.w && r.x <= x + cw && y <= r.y + r.h && r.y <= y + ch)
        {
            g_invalidations[i].Extend(x, y, cw, ch);
            return;
        }
    }

    if (g_invalidation_count < kMaxInvalidations)
    {
        g_invalidations[g_invalidation_count].Reset();
        g_invalidations[g_invalidation_count].Extend(x, y, cw, ch);
        ++g_invalidation_count;
        return;
    }

    // Overflow: merge into the smallest existing rect (degrades toward
    // a single bounding box over time but keeps coverage complete).
    u32 smallest = 0;
    u64 smallest_area = static_cast<u64>(g_invalidations[0].w) * g_invalidations[0].h;
    for (u32 i = 1; i < kMaxInvalidations; ++i)
    {
        const u64 a = static_cast<u64>(g_invalidations[i].w) * g_invalidations[i].h;
        if (a < smallest_area)
        {
            smallest = i;
            smallest_area = a;
        }
    }
    g_invalidations[smallest].Extend(x, y, cw, ch);
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
        auto phys_r = mm::AllocateContiguousFrames(frames);
        if (!phys_r)
        {
            // Allocator exhausted — fall back to direct-to-MMIO mode.
            // `g_compose_active` stays false so `GetWriteTarget` keeps
            // pointing at the live framebuffer.
            SerialWrite("[video/fb] shadow alloc failed (frames=");
            SerialWriteHex(frames);
            SerialWrite(") — staying direct\n");
            return;
        }
        const auto phys = phys_r.value();
        g_shadow_base = mm::PhysToVirt(phys);
        g_shadow_pitch = g_info.width * 4U;
        SerialWrite("[video/fb] shadow online bytes=");
        SerialWriteHex(bytes);
        SerialWrite(" virt=");
        SerialWriteHex(reinterpret_cast<u64>(g_shadow_base));
        SerialWrite("\n");

        // Presented-frame snapshot — same size + layout as the
        // shadow. Failure here is non-fatal: the compositor still
        // works, it just can't elide unchanged frames, so every
        // present goes full (g_presented_valid stays false and the
        // EndCompose full-sync path runs each frame). Don't fail
        // the whole compose for it.
        const auto snap_phys = mm::AllocateContiguousFrames(frames).value_or(mm::kNullFrame);
        if (snap_phys == mm::kNullFrame)
        {
            SerialWrite("[video/fb] presented-snapshot alloc failed (frames=");
            SerialWriteHex(frames);
            SerialWrite(") — diff-elision disabled, full present each frame\n");
        }
        else
        {
            g_presented_base = mm::PhysToVirt(snap_phys);
            g_presented_valid = false; // not yet synced to the screen
            SerialWrite("[video/fb] presented-snapshot online virt=");
            SerialWriteHex(reinterpret_cast<u64>(g_presented_base));
            SerialWrite("\n");
        }
    }
    g_compose_active = true;
}

namespace
{

// Copy the inclusive-exclusive rect [bx, bx_end) x [by, by_end) from
// the shadow surface to the live framebuffer. Pitches differ in
// general (live may have padding); the shadow is tightly packed.
inline void BlitShadowRectToLive(u32 bx, u32 by, u32 bx_end, u32 by_end)
{
    const auto* src_bytes = reinterpret_cast<const u8*>(g_shadow_base);
    auto* dst_bytes = reinterpret_cast<u8*>(g_info.virt);
    for (u32 yi = by; yi < by_end; ++yi)
    {
        const auto* src_row = reinterpret_cast<const u32*>(src_bytes + static_cast<u64>(yi) * g_shadow_pitch);
        auto* dst_row = reinterpret_cast<volatile u32*>(dst_bytes + static_cast<u64>(yi) * g_info.pitch);
        for (u32 xi = bx; xi < bx_end; ++xi)
        {
            dst_row[xi] = src_row[xi];
        }
    }
}

// Copy the same rect from the shadow to the presented-frame snapshot.
// Both buffers use the tightly-packed `g_shadow_pitch` layout, so the
// snapshot stays a faithful mirror of what is on screen.
inline void SyncShadowRectToSnapshot(u32 bx, u32 by, u32 bx_end, u32 by_end)
{
    const auto* src_bytes = reinterpret_cast<const u8*>(g_shadow_base);
    auto* snap_bytes = reinterpret_cast<u8*>(g_presented_base);
    for (u32 yi = by; yi < by_end; ++yi)
    {
        const u64 off = static_cast<u64>(yi) * g_shadow_pitch;
        const auto* src_row = reinterpret_cast<const u32*>(src_bytes + off);
        auto* snap_row = reinterpret_cast<u32*>(snap_bytes + off);
        for (u32 xi = bx; xi < bx_end; ++xi)
        {
            snap_row[xi] = src_row[xi];
        }
    }
}

} // namespace

void FramebufferEndCompose()
{
    if (!g_compose_active)
        return;

    // Snapshot-invalidation pass: external direct-FB writers (cursor)
    // accumulate rects via FramebufferInvalidateSnapshot. The diff
    // scan below would elide these regions because offscreen and
    // snapshot match (the writer's pixels live on LIVE FB and are
    // invisible to both). Force a blit from offscreen → live and
    // sync snapshot at each invalidated rect. This erases the
    // writer's pixels (e.g. cursor at an old position) by writing
    // the compose-rendered content over them. Cheap: ~16x16 per
    // cursor invalidation, up to 8 rects per compose.
    if (g_invalidation_count > 0 && g_presented_base != nullptr && g_presented_valid)
    {
        for (u32 i = 0; i < g_invalidation_count; ++i)
        {
            const auto& r = g_invalidations[i];
            if (!r.valid || r.w == 0 || r.h == 0)
                continue;
            const u32 bx = r.x;
            const u32 by = r.y;
            const u32 bx_end = (r.x + r.w > g_info.width) ? g_info.width : r.x + r.w;
            const u32 by_end = (r.y + r.h > g_info.height) ? g_info.height : r.y + r.h;
            if (bx >= bx_end || by >= by_end)
                continue;
            BlitShadowRectToLive(bx, by, bx_end, by_end);
            SyncShadowRectToSnapshot(bx, by, bx_end, by_end);
            // Also extend g_damage so the present hook flushes these
            // pixels to the backend (virtio-gpu TRANSFER_TO_HOST_2D).
            g_damage.Extend(bx, by, bx_end - bx, by_end - by);
        }
        g_invalidation_count = 0;
    }

    // Nothing was painted at all this pass — leave the screen as-is.
    // `g_damage.valid == false` also makes FramebufferPresent skip
    // the backend round-trip, so an idle tick costs nothing.
    if (!g_damage.valid)
    {
        g_compose_active = false;
        RenderStatsOnComposeEnd();
        return;
    }

    // The primitive-accumulated `g_damage` bounds where pixels COULD
    // have changed: everything outside it was untouched this pass and
    // is, by induction, already identical between the shadow, the
    // live screen, and the snapshot. We never need to look past it.
    const u32 cx = g_damage.x;
    const u32 cy = g_damage.y;
    const u32 cx_end = g_damage.x + g_damage.w;
    const u32 cy_end = g_damage.y + g_damage.h;

    // No snapshot (alloc failed) or snapshot not yet representative of
    // the whole screen: take the conservative full path — blit the
    // entire primitive-damage rect, then make the snapshot mirror the
    // ENTIRE surface so the content-diff invariant ("snapshot == live
    // screen everywhere") holds for every subsequent frame regardless
    // of what this first pass painted. `g_damage` is left as the full
    // primitive rect so FramebufferPresent flushes it in full — the
    // first real frame must reach the display unconditionally.
    if (g_presented_base == nullptr || !g_presented_valid)
    {
        BlitShadowRectToLive(cx, cy, cx_end, cy_end);
        if (g_presented_base != nullptr)
        {
            SyncShadowRectToSnapshot(0, 0, g_info.width, g_info.height);
            g_presented_valid = true;
        }
        g_damage_rect_count = 0; // single-rect path: full first frame
        g_compose_active = false;
        RenderStatsOnComposeEnd();
        return;
    }

    // Content diff: within the primitive-damage rect, compare the
    // freshly-composed shadow against the snapshot of what's on
    // screen. CPU-only linear scan, no host round-trip — far cheaper
    // than the virtio-gpu TRANSFER_TO_HOST_2D + RESOURCE_FLUSH it
    // elides. A recompose that lands the same pixels produces an
    // empty diff and presents nothing.
    //
    // Per changed scanline we already know its tight [first,last] x
    // span; we fold that into (a) the per-band rect it falls in and
    // (b) the overall union `d`. Bands keep spatially-separated
    // changes from fusing into one near-fullscreen flush (D1).
    const auto* shadow_bytes = reinterpret_cast<const u8*>(g_shadow_base);
    const auto* snap_bytes = reinterpret_cast<const u8*>(g_presented_base);

    const u32 band_count = (g_info.height + kBandH - 1U) / kBandH;
    const u32 nbands = (band_count < kMaxDamageRects) ? band_count : kMaxDamageRects;
    for (u32 b = 0; b < nbands; ++b)
        g_damage_rects[b].Reset();

    DamageRect d = {};
    bool band_overflow = false; // a change landed past the rect array
    for (u32 yi = cy; yi < cy_end; ++yi)
    {
        const u64 off = static_cast<u64>(yi) * g_shadow_pitch;
        const auto* srow = reinterpret_cast<const u32*>(shadow_bytes + off);
        const auto* prow = reinterpret_cast<const u32*>(snap_bytes + off);
        u32 first = cx_end;
        u32 last = cx;
        for (u32 xi = cx; xi < cx_end; ++xi)
        {
            if (srow[xi] != prow[xi])
            {
                if (xi < first)
                    first = xi;
                last = xi;
            }
        }
        if (first <= last)
        {
            const u32 w = (last - first) + 1U;
            d.Extend(first, yi, w, 1U);
            const u32 band = yi / kBandH;
            if (band < nbands)
                g_damage_rects[band].Extend(first, yi, w, 1U);
            else
                band_overflow = true;
        }
    }

    if (!d.valid)
    {
        // Pixel-identical recompose — screen + snapshot already
        // correct. Drop the damage so FramebufferPresent skips the
        // backend flush (RenderStats counts this as `frames_clean`).
        g_damage.Reset();
        g_damage_rect_count = 0;
        g_compose_active = false;
        RenderStatsOnComposeEnd();
        return;
    }

    // Compact the dirty bands to the front of the array, counting
    // them (empty bands stayed valid==false after Reset()).
    u32 dirty = 0;
    for (u32 b = 0; b < nbands; ++b)
    {
        if (g_damage_rects[b].valid)
        {
            if (b != dirty)
                g_damage_rects[dirty] = g_damage_rects[b];
            ++dirty;
        }
    }

    if (band_overflow || dirty > kCoalesceBands)
    {
        // Either a change fell past the rect array (huge surface) or
        // many bands changed (a real large repaint). One union flush
        // beats `dirty` virtio round-trips — fall back to single-rect.
        const u32 dx_end = d.x + d.w;
        const u32 dy_end = d.y + d.h;
        BlitShadowRectToLive(d.x, d.y, dx_end, dy_end);
        SyncShadowRectToSnapshot(d.x, d.y, dx_end, dy_end);
        g_damage = d;
        g_damage_rect_count = 0;
        g_compose_active = false;
        RenderStatsOnComposeEnd();
        return;
    }

    // Push each changed band as its own tight rect, keeping the
    // snapshot in lock-step per band. `g_damage` carries the union
    // so RenderStats + no-present-hook backends (firmware FB, Bochs
    // VBE — they already saw the per-band blits land on the live
    // surface) behave exactly as before.
    for (u32 i = 0; i < dirty; ++i)
    {
        const DamageRect& r = g_damage_rects[i];
        BlitShadowRectToLive(r.x, r.y, r.x + r.w, r.y + r.h);
        SyncShadowRectToSnapshot(r.x, r.y, r.x + r.w, r.y + r.h);
    }
    g_damage_rect_count = dirty;
    g_damage = d;
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

u32 FramebufferReadPixel(u32 x, u32 y)
{
    // Always sample from the LIVE framebuffer, not the compose
    // shadow buffer — callers that need "what was just written this
    // compose pass" have to issue an EndCompose first. The cursor
    // backing-store sampler is the primary client and that's the
    // semantic it has always relied on (it ran a private copy of
    // this routine before chrome-tactility consolidated the API).
    if (!g_available || x >= g_info.width || y >= g_info.height || g_info.virt == nullptr)
    {
        return 0;
    }
    const auto* row = reinterpret_cast<const volatile u32*>(reinterpret_cast<const u8*>(g_info.virt) +
                                                            static_cast<u64>(y) * g_info.pitch);
    return row[x];
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

void FramebufferBlendPixel(u32 x, u32 y, u32 argb)
{
    if (!g_available)
    {
        return;
    }
    if (x >= g_info.width || y >= g_info.height)
    {
        return;
    }
    const u32 alpha = (argb >> 24) & 0xFFU;
    if (alpha == 0U)
    {
        return;
    }
    const WriteTarget wt = GetWriteTarget();
    auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(y) * wt.pitch);
    if (alpha == 0xFFU)
    {
        row[x] = argb & 0x00FFFFFFU;
        MarkDamage(x, y, 1, 1);
        return;
    }
    row[x] = BlendOver(row[x], argb & 0x00FFFFFFU, static_cast<u8>(alpha));
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

void FramebufferBlendFill(u32 x, u32 y, u32 w, u32 h, u32 argb)
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

    // Inner loop delegates to BlendOver (kernel/drivers/video/blend_math.h)
    // so the rounding + channel layout match the hosted unit test
    // exactly. The alpha == 0 / alpha == 0xFF fast paths are short-
    // circuited above so the per-pixel call never re-tests them.
    const u32 src_rgb = argb & 0x00FFFFFFU;
    const u8 src_a = static_cast<u8>(alpha);
    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;

    const WriteTarget wt = GetWriteTarget();
    for (u32 yi = y; yi < y_end; ++yi)
    {
        auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(yi) * wt.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            row[xi] = BlendOver(row[xi], src_rgb, src_a);
        }
    }
    MarkDamage(x, y, x_end - x, y_end - y);
}

usize FramebufferBlendRgba(u32 x, u32 y, u32 w, u32 h, const u32* src_rgba, u32 src_pitch_px)
{
    if (!g_available || src_rgba == nullptr || w == 0 || h == 0)
    {
        return 0;
    }
    if (x >= g_info.width || y >= g_info.height)
    {
        // Caller handed us a rect entirely off the surface — every
        // chrome paint path should have clipped to the on-screen
        // window first. Fire a probe so a regression in a paint
        // path's clip arithmetic shows up in the boot log instead
        // of as a silent missing-shadow.
        KBP_PROBE_V(debug::ProbeId::kBlendRangeOob, (static_cast<u64>(x) << 16) | y);
        return 0;
    }

    const u32 x_end = (x + w > g_info.width) ? g_info.width : x + w;
    const u32 y_end = (y + h > g_info.height) ? g_info.height : y + h;
    const WriteTarget wt = GetWriteTarget();
    usize dirty = 0;
    for (u32 yi = y; yi < y_end; ++yi)
    {
        const u32 src_row = yi - y;
        const u32* src = src_rgba + static_cast<u64>(src_row) * src_pitch_px;
        auto* row = reinterpret_cast<volatile u32*>(wt.base + static_cast<u64>(yi) * wt.pitch);
        for (u32 xi = x; xi < x_end; ++xi)
        {
            const u32 s = src[xi - x];
            const u8 a = static_cast<u8>((s >> 24) & 0xFFU);
            if (a == 0)
            {
                continue; // sparse-atlas fast path
            }
            if (a == 0xFFU)
            {
                row[xi] = s & 0x00FFFFFFU;
            }
            else
            {
                row[xi] = BlendOver(row[xi], s & 0x00FFFFFFU, a);
            }
            ++dirty;
        }
    }
    if (dirty != 0)
    {
        MarkDamage(x, y, x_end - x, y_end - y);
    }
    return dirty;
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

// Fractional-degree sin/cos using linear interpolation of the existing
// Q16.16 integer table. Input is any double in degrees; output is a
// double in [-1, +1]. Error vs true sin/cos < 0.5 LSB of the table
// (< 0.0015 rad), well below any visible arc-rotation artefact at the
// ±5° sweep range PaintDuetArcs uses.
//
// File-scope static — not in the anonymous namespace so
// FramebufferStrokeArcFloat (a public function) can call it without an
// internal-linkage violation. Does not pull in any math library header.
static double SinDegF(double deg)
{
    // Reduce to [0, 360).
    while (deg < 0.0)
        deg += 360.0;
    while (deg >= 360.0)
        deg -= 360.0;
    // Lerp between the two nearest integer-degree entries.
    const i32 d0 = static_cast<i32>(deg);
    const i32 d1 = (d0 + 1) % 360;
    const double frac = deg - static_cast<double>(d0);
    const double s0 = static_cast<double>(SinDegQ16(d0)) / 65536.0;
    const double s1 = static_cast<double>(SinDegQ16(d1)) / 65536.0;
    return s0 + frac * (s1 - s0);
}

static double CosDegF(double deg)
{
    return SinDegF(deg + 90.0);
}

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

void FramebufferStrokeArcFloat(i32 cx, i32 cy, i32 radius, double start_deg, double sweep_deg, u32 thickness, u32 rgb)
{
    if (!g_available || radius <= 0 || thickness == 0)
        return;
    // Step size: ~1 pixel of arc length at this radius.
    // `step = 180 / (π * r)` degrees ≈ `57.3 / r`. Clamped to [0.1°, 1.0°]
    // so tiny radii don't explode the loop and huge radii stay gapless.
    double step = 57.3 / static_cast<double>(radius);
    if (step > 1.0)
        step = 1.0;
    if (step < 0.1)
        step = 0.1;

    // Walk the sweep in fractional-degree steps. A negative sweep
    // walks backward; cap magnitude at 360° so a full revolution is
    // the maximum.
    double walk = sweep_deg;
    double sign = 1.0;
    if (walk < 0.0)
    {
        walk = -walk;
        sign = -1.0;
    }
    if (walk > 360.0)
        walk = 360.0;

    const i32 half = static_cast<i32>(thickness / 2);
    double d = 0.0;
    while (d <= walk)
    {
        const double angle = start_deg + sign * d;
        const double c = CosDegF(angle);
        const double s = SinDegF(angle);
        for (u32 t = 0; t < thickness; ++t)
        {
            const i32 r = radius - half + static_cast<i32>(t);
            if (r <= 0)
                continue;
            const i32 px = cx + static_cast<i32>(c * static_cast<double>(r) + 0.5);
            const i32 py = cy + static_cast<i32>(s * static_cast<double>(r) + 0.5);
            if (px >= 0 && py >= 0 && static_cast<u32>(px) < g_info.width && static_cast<u32>(py) < g_info.height)
            {
                FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py), rgb);
            }
        }
        d += step;
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
        FramebufferBlendFill(x + w + d, y + 1U + d, 1U, h, argb);
        // Bottom band: 1px row from (x+d+1, y+h+d) across to
        // (x+w+d, y+h+d). Includes the corner pixel that the
        // right band already touched at (x+w+d, y+h+d) — the
        // double-blend is harmless (alpha blending is idempotent
        // at the same source colour for a single-pixel overlap).
        FramebufferBlendFill(x + 1U + d, y + h + d, w, 1U, argb);
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

// File-scope PASS tracker for the boot umbrella aggregator. Set
// by the success branch of BlendSelfTest; read by
// BlendSelfTestPassed(). Initially false so an absent or
// FAILed self-test never lights up the umbrella line.
namespace
{
bool s_blend_passed = false;
} // namespace

void BlendSelfTest()
{
    s_blend_passed = false;

    if (!g_available)
    {
        SerialWrite("[blend-selftest] SKIP (framebuffer not available)\n");
        return;
    }
    if (g_compose_active)
    {
        // Read-back goes through FramebufferReadPixel which always
        // hits the LIVE framebuffer; with compose active the writes
        // would land in the shadow buffer instead, so the test
        // would falsely report mismatch. Boot ordering guarantees
        // BlendSelfTest runs before compose ever engages — flag if
        // that ever changes.
        SerialWrite("[blend-selftest] SKIP (compose active)\n");
        return;
    }

    // ----- alpha=0xFF must REPLACE -----
    const u32 saved = FramebufferReadPixel(0, 0);
    FramebufferPutPixel(0, 0, 0x000000U);
    FramebufferBlendFill(0, 0, 1, 1, 0xFFFFFFFFU);
    const u32 opaque = FramebufferReadPixel(0, 0) & 0x00FFFFFFU;
    if (opaque != 0x00FFFFFFU)
    {
        SerialWrite("[blend-selftest] FAIL (alpha=255 did not replace)\n");
        KBP_PROBE_V(debug::ProbeId::kBlendRangeOob, opaque);
        FramebufferPutPixel(0, 0, saved);
        return;
    }

    // ----- alpha=0x80 must land ~50% -----
    FramebufferPutPixel(0, 0, 0x000000U);
    FramebufferBlendFill(0, 0, 1, 1, 0x80FFFFFFU);
    const u32 mid_b = FramebufferReadPixel(0, 0) & 0xFFU;
    if (mid_b < 126U || mid_b > 130U)
    {
        SerialWrite("[blend-selftest] FAIL (alpha=128 not midpoint)\n");
        KBP_PROBE_V(debug::ProbeId::kBlendRangeOob, mid_b);
        FramebufferPutPixel(0, 0, saved);
        return;
    }

    FramebufferPutPixel(0, 0, saved);
    SerialWrite("[blend-selftest] PASS (blendrgba, blendfill, alpha-zero-skip)\n");
    s_blend_passed = true;
}

bool BlendSelfTestPassed()
{
    return s_blend_passed;
}

} // namespace duetos::drivers::video
