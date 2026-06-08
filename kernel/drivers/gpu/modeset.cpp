/*
 * DuetOS — runtime display modeset coordinator: implementation.
 *
 * Companion to modeset.h. The only backend wired today is virtio-gpu
 * (the autologin desktop boots `-vga virtio`); a Bochs-VBE direct
 * path could slot in behind the same DisplaySetMode facade later by
 * calling VbeSetMode + FramebufferRebind, but std-vga is not the
 * desktop's boot device so it stays out of scope.
 */

#include "drivers/gpu/modeset.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/virtio_gpu.h"
#include "drivers/video/framebuffer.h"

namespace duetos::drivers::gpu
{

namespace
{

// The selectable mode list. Kept short + bounded: every entry's
// BGRA backing is a modest contiguous allocation (the largest,
// 1280x1024, is 5 MiB / 1280 frames) and each is a resolution the
// virtio-gpu host accepts. Ordered small→large so the panel reads
// top-to-bottom as "more pixels".
constexpr DisplayMode kModes[] = {
    {800, 600, "800 x 600"},
    {1024, 768, "1024 x 768"},
    {1280, 720, "1280 x 720"},
    {1280, 1024, "1280 x 1024"},
};

constexpr u32 kModeCount = static_cast<u32>(sizeof(kModes) / sizeof(kModes[0]));

} // namespace

const DisplayMode& DisplayModeAt(u32 index)
{
    if (index >= kModeCount)
        index = 0;
    return kModes[index];
}

u32 DisplayModeCount()
{
    return kModeCount;
}

u32 DisplayCurrentModeIndex()
{
    const auto fb = ::duetos::drivers::video::FramebufferGet();
    for (u32 i = 0; i < kModeCount; ++i)
    {
        if (kModes[i].width == fb.width && kModes[i].height == fb.height)
            return i;
    }
    return kModeCount; // current geometry not in our list (e.g. boot default)
}

bool DisplayModesetAvailable()
{
    // A live virtio-gpu scanout owns the framebuffer backing, so we
    // can tear it down + rebuild at a new size. On any other backend
    // the framebuffer is a fixed firmware / BGA aperture we can't
    // re-program through this path.
    return VirtioGpuScanoutInfo().ready;
}

bool DisplaySetMode(u32 width, u32 height)
{
    if (!DisplayModesetAvailable())
    {
        arch::SerialWrite("[modeset] no re-programmable backend (virtio-gpu scanout not live)\n");
        return false;
    }

    const auto& cur = VirtioGpuScanoutInfo();
    if (cur.width == width && cur.height == height)
        return true; // already there

    // 1) virtio-gpu: tear the old resource + backing down, build a new
    //    resource/backing/scanout at the requested geometry. The reset
    //    path feasibility-probes the new backing before touching the
    //    live resource (so an allocation shortfall is safe), and if the
    //    post-teardown device-command setup fails it rebuilds the
    //    PREVIOUS mode from scratch. Either way, the freed-and-rebuilt
    //    backing lives at a NEW address, so step 2 must rebind whenever
    //    a scanout is live — not only on the requested-mode success.
    const bool applied = VirtioGpuResetScanout(width, height);
    const auto& sc = VirtioGpuScanoutInfo();

    if (!sc.ready)
    {
        // Catastrophic: the requested mode failed AND the previous-mode
        // recovery also failed. Nothing to rebind to. The framebuffer
        // still points at the freed old backing, but there is no live
        // scanout to repoint it at — surface the failure.
        arch::SerialWrite("[modeset] scanout down after reset (no live mode to bind)\n");
        return false;
    }

    // 2) Rebind the framebuffer to the live backing (new mode on
    //    success, or the recovered previous mode on failure). This
    //    resets the presented-snapshot validity so the next compose
    //    does a full first-frame blit.
    if (!::duetos::drivers::video::FramebufferRebindExternal(sc.backing_va, sc.backing_phys, sc.width, sc.height,
                                                             sc.pitch, 32))
    {
        arch::SerialWrite("[modeset] framebuffer rebind failed after scanout reset\n");
        return false;
    }

    // 3) Drop the compose shadow + snapshot — they were sized to the
    //    OLD geometry. The next FramebufferBeginCompose re-allocates
    //    them at the live width/height. Safe here: we hold the
    //    compositor lock (caller is the settings key handler), so no
    //    compose is mid-flight.
    ::duetos::drivers::video::FramebufferDropComposeBuffers();

    if (!applied)
    {
        // Display is alive at the recovered previous geometry, but the
        // mode the user asked for was not applied.
        arch::SerialWrite("[modeset] requested mode not applied; display recovered at prior geometry\n");
        return false;
    }

    // The window manager reads FramebufferGet() fresh on every
    // DesktopCompose pass, so the ui-ticker's next frame relays out
    // the taskbar / wallpaper / window clamps at the new geometry and
    // repaints in full (snapshot was invalidated). No explicit
    // recompose call needed — the periodic compose handles it.
    arch::SerialWrite("[modeset] resolution changed to ");
    arch::SerialWriteHex(width);
    arch::SerialWrite("x");
    arch::SerialWriteHex(height);
    arch::SerialWrite("\n");
    return true;
}

} // namespace duetos::drivers::gpu
