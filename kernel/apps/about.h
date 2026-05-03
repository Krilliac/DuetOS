#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS About / System Info — v0.
 *
 * Replaces the two-line "ABOUT DUETOS" console message that the
 * Start menu used to print. Opens a real window that holds a
 * scrollable readout of the things a user wants to know:
 *
 *   - Build banner (DuetOS version + flavor + tag)
 *   - Uptime — derived from `time::TickCount()` / `time::TickHz()`
 *   - Active theme name
 *   - Framebuffer resolution and bpp (from `FramebufferGet`)
 *   - FAT32 mount status (volume index 0)
 *   - Kernel heap stats — pool / used / free / largest-free-run
 *   - Live window count
 *
 * No buttons, no input. Refreshes on every compositor paint so
 * uptime + heap counters tick visibly. Closing happens through
 * the chrome's [X] button like every other kernel app window.
 *
 * Context: kernel. Caller MUST hold the compositor lock — same
 * discipline as Settings / Calculator. The DrawFn samples
 * KernelHeapStatsRead and FramebufferGet directly; both are cheap.
 */

namespace duetos::apps::about
{

/// Install About state on `handle`. Registers the content-draw
/// callback; no widgets, no per-app keyboard wiring.
void AboutInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the About window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle AboutWindow();

/// Boot self-test. Validates the byte-format helpers (number-to-
/// decimal, KiB / MiB suffix selection) and the uptime formatter
/// (HH:MM:SS round-trip). Pure compute; runs unconditionally.
void AboutSelfTest();

} // namespace duetos::apps::about
