#pragma once

#include "util/types.h"

/*
 * DuetOS — display info aggregator, v0.
 *
 * One-stop "what's the display look like?" query that bundles the
 * three sources of truth a higher layer would otherwise have to
 * splice together by hand:
 *
 *   1. The active framebuffer (`drivers/video/framebuffer.h`):
 *      width, height, pitch, bpp, kernel VA + physical address.
 *   2. The owning GPU (`drivers/gpu/gpu.h`): vendor, family tag,
 *      tier classification, MMIO BAR, architecture decode.
 *   3. The present backend (firmware passthrough, Bochs VBE,
 *      virtio-gpu): which one is driving the framebuffer right
 *      now, and is its scanout backing live.
 *
 * Used by the `gfx` shell command, the future Vulkan ICD's
 * physical-device enumeration (so a `vkGetPhysicalDeviceProperties`
 * query has a coherent place to read the active display from), and
 * future runtime-mode-change paths that need to know "what's the
 * current resolution before I ask the firmware to set a new one?"
 *
 * This is a strictly READ surface — it never mutates state. Each
 * `Query()` walks the upstream APIs and returns a snapshot. No
 * locking; the upstream APIs are themselves boot-stable read-only
 * accessors today, so the snapshot is internally consistent.
 *
 * Context: kernel. Cheap to call (single-digit upstream lookups +
 * one struct fill).
 */

namespace duetos::drivers::video
{

enum class PresentBackend : u8
{
    None = 0,      // no framebuffer available
    Direct = 1,    // firmware framebuffer / Bochs VBE — write-and-it-shows
    VirtioGpu = 2, // virtio-gpu present hook (transfer + flush)
    Unknown = 3,   // hook is set but doesn't match a known backend
};

struct DisplayInfo
{
    bool available; // false = no framebuffer / no display
    u32 width;      // pixels
    u32 height;     // pixels
    u32 pitch;      // bytes per row
    u8 bpp;         // 32 today
    u64 fb_phys;    // framebuffer physical base
    u64 fb_virt;    // framebuffer kernel-virtual base (as u64 to keep
                    // the struct trivially copyable / printable)

    // Owning GPU — the first display-class PCI device discovered.
    // `gpu_present == false` when no display-class device was
    // found (headless boot) but the framebuffer might still be
    // live via firmware passthrough.
    bool gpu_present;
    const char* gpu_vendor; // "Intel" / "AMD" / "NVIDIA" / "QEMU-Bochs" / ...
    const char* gpu_family; // family tag from the vendor probe, or nullptr
    const char* gpu_tier;   // "tier1-intel-igpu" / "tier3-vm" / ...
    const char* gpu_arch;   // NVIDIA-only architecture tag, or nullptr
    u64 gpu_mmio_phys;      // GPU BAR0 physical, 0 if unmapped
    u64 gpu_mmio_size;
    u64 gpu_count; // total display-class PCI devices

    // Present backend.
    PresentBackend backend;
    bool compose_active; // true between BeginCompose / EndCompose
};

/// Snapshot the active display + owning GPU + present backend.
DisplayInfo Query();

/// Short string for `PresentBackend` (for shell + log output).
const char* PresentBackendName(PresentBackend b);

} // namespace duetos::drivers::video
