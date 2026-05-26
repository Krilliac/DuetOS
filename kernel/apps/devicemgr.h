#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Device Manager — v0.
 *
 * Read-only viewer over `kernel/drivers/pci/pci.h` accessors.
 * Lists every device the legacy port-IO PCI walk discovered, with
 * its address (bus:dev.fn), vendor:device IDs, and class/subclass
 * tag. The same data the shell `lspci` command prints, just in a
 * window.
 *
 * Scope limits (deliberate v0):
 *   - PCI only — no USB, no virtio child devices, no platform.
 *   - No tree view by class / bridge — flat list.
 *   - No BAR / interrupt / capability inspector.
 *   - No eject / rescan.
 *
 * Context: kernel. Draw is called under the compositor lock.
 */

namespace duetos::apps::devicemgr
{

/// Install the content-draw callback on `handle`.
void DeviceMgrInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the device-manager window. Returns `kWindowInvalid`
/// if `DeviceMgrInit` has not run.
duetos::drivers::video::WindowHandle DeviceMgrWindow();

/// Boot self-test: walks `PciDeviceCount()` and confirms every
/// `PciDevice(idx)` is non-empty. Also drives a synthetic click
/// through the Pass D toolbar's WidgetGroup to verify the
/// dispatch chain is wired end-to-end. Prints PASS/FAIL on COM1.
void DeviceMgrSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// DeviceMgrSelfTest() invocation ran every check (including the
/// synthetic toolbar button click) without error.
bool DeviceMgrSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every motion
/// packet. Edge-detects left-button press / release internally
/// and dispatches MouseMove / MouseDown / MouseUp into the
/// WidgetGroup so AppButton hover state tracks the cursor on
/// tactility themes. The raw PCI + USB list (variable-length
/// tabular blocks with section headings + column-header sublines)
/// stays raw paint (carve-out) — AppListRow has no multi-column /
/// section-header model. The list has no per-row click semantics
/// in v0 (no selection, no detail). No-op before DeviceMgrInit
/// has wired a window.
void DeviceMgrMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::devicemgr
