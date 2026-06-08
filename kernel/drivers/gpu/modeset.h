#pragma once

#include "util/types.h"

/*
 * DuetOS — runtime display modeset coordinator.
 *
 * The boot path elects a framebuffer geometry once (virtio-gpu
 * scanout sized to the GET_DISPLAY_INFO default, capped to
 * 1024x768) and the compositor paints into it forever. This module
 * lets a user change resolution at runtime from the Settings ▸
 * Display panel.
 *
 * Backend: the autologin desktop boots under QEMU `-vga virtio`, so
 * the modeset path drives virtio-gpu — tear the old 2D resource +
 * backing down, build a new one at the requested size, rebind the
 * framebuffer to the new backing, drop the (old-sized) compose
 * shadow so the compositor re-allocates at the new geometry, and
 * force a full recompose. The window manager reads `FramebufferGet()`
 * fresh on every compose pass, so the desktop re-lays-out (taskbar
 * Y, wallpaper extent, window clamps) automatically once the new
 * geometry is live.
 *
 * On a non-virtio backend (Bochs VBE direct, firmware passthrough)
 * `DisplayModesetAvailable()` returns false and `DisplaySetMode`
 * is a no-op returning false — the Settings panel then shows the
 * read-only info it always did.
 *
 * Context: kernel. `DisplaySetMode` must be called from the
 * compositor-owning thread (the ui-ticker / settings key handler)
 * so it doesn't race an in-flight compose.
 */

namespace duetos::drivers::gpu
{

struct DisplayMode
{
    u32 width;
    u32 height;
    const char* label; // e.g. "1024 x 768"
};

/// The short, safe list of selectable modes. Bounded to sizes whose
/// BGRA backing is a reasonable contiguous allocation and that the
/// virtio-gpu host accepts. Index 0..DisplayModeCount()-1.
const DisplayMode& DisplayModeAt(u32 index);
u32 DisplayModeCount();

/// Index of the mode matching the live framebuffer geometry, or
/// DisplayModeCount() if the current geometry isn't in the list
/// (e.g. a boot default like 1280x800 that we don't offer to set).
u32 DisplayCurrentModeIndex();

/// True iff a runtime resolution change is possible on this boot —
/// i.e. a live virtio-gpu scanout owns the framebuffer.
bool DisplayModesetAvailable();

/// Change the live display resolution to (width, height).
///   1. virtio-gpu reset-scanout (new resource + backing)
///   2. rebind the framebuffer to the new backing
///   3. drop the old-sized compose shadow + snapshot
///   4. force a full recompose so the desktop relayouts + repaints
/// Returns true on success; false (with the OLD mode left fully
/// live and on screen) if the backend can't modeset, the size is
/// out of range, or the new backing can't be allocated.
bool DisplaySetMode(u32 width, u32 height);

} // namespace duetos::drivers::gpu
