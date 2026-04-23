#pragma once

#include "../../core/types.h"

/*
 * CustomOS — Bochs VBE (VESA BIOS Extensions) display driver, v0.
 *
 * First real GPU driver: programs QEMU's std-vga / bochs-display
 * (vendor 0x1234 device 0x1111) via the classic Bochs VBE register
 * bank. The interface is identical on every BGA-compatible device
 * (VMware SVGA-II falls back to it, KVM's default stdvga uses it,
 * and the original Bochs emulator pioneered it). MMIO register
 * access exists too but legacy port-IO via 0x1CE (index) / 0x1CF
 * (data) is universally available and doesn't require BAR2
 * mapping — we use port IO exclusively in v0.
 *
 * Scope (v0):
 *   - Detect the device via its VBE ID register (0xB0C0 | version
 *     nibble). ID read through the classic port pair works even
 *     before any mode-set.
 *   - Query the controller's maximum supported dimensions + BPP
 *     via VBE_DISPI_GETCAPS. Reports whatever the hypervisor's
 *     build was compiled with — typically 2560×1600 or higher.
 *   - Program a new mode (width × height × 32 bpp linear
 *     framebuffer). The sequence is: disable → write width +
 *     height + bpp → enable with LFB + NO-CLEAR flags.
 *   - Log current + requested mode on every transition so the
 *     boot log documents every mode-set.
 *
 * Scope (future):
 *   - Re-bind the video::Framebuffer driver to the new linear FB
 *     base so the existing compositor paints at the new
 *     resolution. Today the set-mode call happens but the
 *     framebuffer driver keeps pointing at the original
 *     firmware-handoff buffer.
 *   - Virtual scrolling via VIRT_WIDTH / Y_OFFSET (for
 *     hardware-accelerated scroll without redrawing every pixel).
 *   - Bank-switching for pre-VBE3 devices (we don't boot on
 *     those).
 *
 * Context: kernel. Callable from task context (port IO is fine
 * from anywhere, but other callers of the framebuffer shouldn't
 * race a mode change — arrange externally).
 */

namespace customos::drivers::gpu
{

struct VbeCaps
{
    bool present; // true iff the VBE ID register reads a 0xB0Cx value
    u16 version;  // low byte of VBE ID (0, 1, 2, 3, 4, 5)
    u16 max_xres; // maximum supported horizontal pixels
    u16 max_yres; // maximum supported vertical pixels
    u16 max_bpp;  // maximum supported bits per pixel
    u16 cur_xres; // current horizontal resolution (read back after any set)
    u16 cur_yres; // current vertical resolution
    u16 cur_bpp;  // current bits per pixel
    bool enabled; // current ENABLE register LFB bit state
};

/// Query the VBE controller. Safe to call at any time after boot.
/// Returns `present == false` when the register pair reads a value
/// that doesn't match the Bochs VBE ID signature (0xB0Cx).
VbeCaps VbeQuery();

/// Program a new display mode. `width` × `height` in pixels,
/// `bpp` is 8 / 15 / 16 / 24 / 32 (32 is what every compositor in
/// this tree assumes). Returns true if the controller accepted
/// the write AND read back the requested dimensions. Does NOT
/// rebind the kernel framebuffer driver — caller is responsible
/// for re-running the paint path against the new dimensions.
bool VbeSetMode(u16 width, u16 height, u16 bpp);

/// Boot-time self-test: query the controller, log its
/// capabilities + the current mode, confirm the VBE ID register
/// reads as expected. No-op (silent return) when the hypervisor
/// doesn't expose a Bochs VBE device.
void VbeSelfTest();

} // namespace customos::drivers::gpu
