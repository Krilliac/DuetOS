#pragma once

#include "../../core/types.h"

/*
 * DuetOS — linear framebuffer driver, v0.
 *
 * First direct-to-pixel graphics primitive in the tree. Consumes the
 * Multiboot2 framebuffer tag (type 8) GRUB hands over on boot, maps
 * the linear framebuffer into the kernel MMIO arena, and exposes the
 * minimum ops every higher-level surface (console font rasterizer,
 * splash screen, compositor later) will need:
 *
 *   - `FramebufferInit(multiboot_info_phys)` — parses tag, validates
 *     "direct RGB" shape, MapMmios the pixel buffer. Safe to call
 *     when no tag is present: leaves the driver `Available() == false`
 *     and returns silently.
 *   - `FramebufferClear(rgb)` / `FramebufferFillRect(x, y, w, h, rgb)` /
 *     `FramebufferPutPixel(x, y, rgb)` — the classic trio; all
 *     coordinate-clipped, no panics on out-of-range.
 *   - Accessors for info the console layer needs (width in pixels,
 *     height in pixels, pitch in bytes).
 *
 * Scope limits that will be fixed in later commits:
 *   - Assumes BPP = 32 (8:8:8:8 with one reserved byte). Some real
 *     VBE modes hand back 24-bit packed, and EFI GOP sometimes
 *     reports 15 or 16 bit. Unsupported depths log + disable the
 *     driver rather than guessing.
 *   - Assumes the firmware placed red/green/blue in the classic
 *     A=24 / R=16 / G=8 / B=0 arrangement (QEMU std-vga, BGA, most
 *     Intel iGPUs). Different masks will render with swapped colour
 *     channels — visible but functional, and fixable by reading the
 *     colour-info trailer once a real machine forces the issue.
 *   - No back buffer / no double buffering. Every draw lands in the
 *     live framebuffer. Fine for boot splash + kernel panic display;
 *     the compositor will install its own off-screen buffer chain.
 *   - No dirty-rect tracking. Redraws are full-rect. The cost is
 *     a handful of MB/s at 1024x768x32, well inside the PCIe budget
 *     for the devices we care about.
 *   - No cursor / blinking text / scrolling. Those land with the
 *     framebuffer console on top of this driver.
 *
 * Context: kernel. Init runs once AFTER `PagingInit` (uses MapMmio)
 * and BEFORE any subsystem wants to draw. Drawing is IRQ-safe in
 * principle (writes to MMIO), but drawing from an IRQ handler on
 * a slow framebuffer will cause visible scheduling jitter; keep
 * draw calls in task context unless the panic path specifically
 * needs them.
 */

namespace duetos::drivers::video
{

struct FramebufferInfo
{
    void* virt; // kernel-virtual pointer into the MMIO arena
    u64 phys;   // physical base the firmware handed us
    u32 width;  // pixels
    u32 height; // pixels
    u32 pitch;  // bytes per scanline (>= width * bytes_per_pixel)
    u8 bpp;     // bits per pixel (we only support 32 today)
    u8 _pad[3];
};

/// Parse the Multiboot2 framebuffer tag from the info struct at
/// `multiboot_info_phys`, validate that it's a direct-RGB 32-bpp
/// linear framebuffer, and MapMmio the pixel buffer. Idempotent:
/// second call is a no-op. If GRUB didn't provide a tag or the tag
/// describes an unsupported mode, logs the reason to the serial
/// console and leaves the driver `Available() == false`.
void FramebufferInit(uptr multiboot_info_phys);

/// True if init found a usable framebuffer and drawing is permitted.
bool FramebufferAvailable();

/// Snapshot of the live framebuffer parameters. Valid for the whole
/// uptime once Init has returned; framebuffer parameters don't
/// change after boot.
FramebufferInfo FramebufferGet();

/// Fill the entire surface with `rgb` (0x00RRGGBB). No-op if
/// !Available().
void FramebufferClear(u32 rgb);

/// Write one pixel. Out-of-range coordinates silently drop — callers
/// that care are expected to clip up front. No-op if !Available().
void FramebufferPutPixel(u32 x, u32 y, u32 rgb);

/// Fill the axis-aligned rect [x, x+w) x [y, y+h) with `rgb`.
/// Clipped to the surface; passing a rect that's entirely off-screen
/// is a silent no-op. No-op if !Available().
void FramebufferFillRect(u32 x, u32 y, u32 w, u32 h, u32 rgb);

/// Draw the OUTLINE of the rect [x, x+w) x [y, y+h) with
/// `thickness` pixels of border in `rgb`. Interior is untouched.
/// Clipped; no-op on empty dimensions or !Available().
void FramebufferDrawRect(u32 x, u32 y, u32 w, u32 h, u32 rgb, u32 thickness);

/// Copy `src_w × src_h` BGRA8888 pixels into the framebuffer at
/// `(dst_x, dst_y)`. `src` is a kernel-side pointer to a row-major
/// pixel buffer with `src_pitch_px` u32-pixels per row (allowing a
/// clipped subrect of a larger source). Out-of-range destination
/// coordinates are clipped; an entirely off-screen blit is a silent
/// no-op. No-op if `!Available()` or `src == nullptr`. The
/// compositor uses this to replay a window's recorded BitBlt
/// primitives; user code reaches it via SYS_GDI_BITBLT.
void FramebufferBlit(u32 dst_x, u32 dst_y, const u32* src, u32 src_w, u32 src_h, u32 src_pitch_px);

/// Draw one 8x8 glyph at (x, y) using the built-in bitmap font.
/// `fg` is the ink colour; `bg` is painted behind the glyph cell
/// so text appears on a clean background rather than alpha-blended.
/// Unmapped characters render as a placeholder box (see font8x8.h).
void FramebufferDrawChar(u32 x, u32 y, char ch, u32 fg, u32 bg);

/// Draw a NUL-terminated string at (x, y). Cell advance is 8 px
/// per glyph. No wrapping, no newline handling — the caller
/// controls layout. Stops at the first NUL or when the next cell
/// would exceed the framebuffer width.
void FramebufferDrawString(u32 x, u32 y, const char* text, u32 fg, u32 bg);

/// Exercise the draw path at boot: clear to black, draw coloured
/// corner swatches + a framing rectangle. Visible proof that the
/// firmware handoff + Mmio map + pixel store all work end-to-end.
/// No-op if !Available().
void FramebufferSelfTest();

/// Re-bind the framebuffer driver to a new physical base +
/// dimensions. Called after a GPU-side mode-set (Bochs VBE,
/// future Intel/AMD/NVIDIA modeset) so the compositor paints at
/// the new resolution. MapMmios a fresh virtual alias — the old
/// mapping is leaked (arena is a bump allocator, 512 MiB wide,
/// cheap). Rejects non-32-bpp modes + insane pitches. Returns
/// false on validation failure or MMIO-arena exhaustion.
///
/// Does NOT re-initialize overlay widgets (taskbar Y position,
/// cursor/clock placement) — they stay at their boot-time
/// coordinates. Callers that care about chrome alignment need
/// to rebuild it explicitly after this call succeeds.
bool FramebufferRebind(u64 phys, u32 width, u32 height, u32 pitch, u8 bpp);

} // namespace duetos::drivers::video
