#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Network Status — v0.
 *
 * Read-only viewer over `kernel/net/stack.h` accessors. Lists
 * every interface NetStackInit has bound, with index, MAC, IPv4,
 * and bound state. Refresh is driven by the ui-ticker's compose
 * cadence — same pattern as the clock window.
 *
 * Scope limits (deliberate v0):
 *   - No editing surface (set IP, bring up/down, scan Wi-Fi).
 *   - No per-interface counters (rx/tx packets/bytes, errors).
 *   - No DNS / route / ARP table view.
 *   - No IPv6.
 *
 * Context: kernel. Draw is called under the compositor lock.
 */

namespace duetos::apps::netstatus
{

/// Install the content-draw callback on `handle`. No other state
/// — every paint pulls fresh values from the net stack.
void NetStatusInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the network-status window. Returns `kWindowInvalid`
/// if `NetStatusInit` has not run.
duetos::drivers::video::WindowHandle NetStatusWindow();

/// Boot self-test: walks `InterfaceCount()` and confirms each
/// accessor returns without faulting. Prints PASS/FAIL on COM1.
void NetStatusSelfTest();

} // namespace duetos::apps::netstatus
