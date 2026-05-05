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
/// `PciDevice(idx)` is non-empty. Prints PASS/FAIL on COM1.
void DeviceMgrSelfTest();

} // namespace duetos::apps::devicemgr
