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
/// callback and the Pass D AppToolbar + AppLabels chrome; no
/// per-app keyboard wiring.
void AboutInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the About window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle AboutWindow();

/// Boot self-test. Validates the byte-format helpers (number-to-
/// decimal, KiB / MiB suffix selection) and the uptime formatter
/// (HH:MM:SS round-trip), then drives a synthetic click through
/// the Pass D RFRSH toolbar button (read-only — only touches
/// snapshot APIs, safe to run at boot). Pure compute; runs
/// unconditionally. Emits `[about-selftest] PASS` / `FAIL`.
void AboutSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// AboutSelfTest() invocation ran every check (including the
/// synthetic toolbar button click) without error.
bool AboutSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every
/// motion packet. Edge-detects left-button press / release
/// internally and dispatches MouseMove / MouseDown / MouseUp
/// into the WidgetGroup so AppButton hover state tracks the
/// cursor on tactility themes. The raw body rows (BUILD /
/// COMMIT / UPTIME / THEME / DISPLAY / DISK / HEAP / WINDOWS)
/// stay raw paint (carve-out) and have no per-row click
/// semantics. No-op before AboutInit has wired a window.
void AboutMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::about
