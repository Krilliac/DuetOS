#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Network Status — v0.
 *
 * Read-only viewer over `kernel/net/stack.h` accessors. Lists
 * every interface NetStackInit has bound, with index, MAC, IPv4,
 * bound state, per-iface RX/TX counters and firewall drops, plus
 * the most recent DHCP lease (gateway / DNS / lease seconds) and
 * a Wi-Fi scan band. Refresh is driven by the ui-ticker's compose
 * cadence — same pattern as the clock window.
 *
 * Pass D chrome: AppToolbar with one AppButton (RFRSH) plus two
 * AppLabels (header "NETWORK STATUS", footer hint). The multi-
 * column interface / lease / Wi-Fi tables stay raw paint
 * (carve-out) — AppListRow has no multi-column / per-row colour
 * model (BOUND=green vs DOWN=amber).
 *
 * Scope limits (deliberate v0):
 *   - No editing surface (set IP, bring up/down, scan Wi-Fi).
 *   - No per-interface counters editing (read-only counters only).
 *   - No ARP table view.
 *   - No IPv6.
 *
 * Context: kernel. Draw is called under the compositor lock.
 */

namespace duetos::apps::netstatus
{

/// Install the content-draw callback on `handle`. Also binds the
/// Pass D WidgetGroup the first time it runs.
void NetStatusInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the network-status window. Returns `kWindowInvalid`
/// if `NetStatusInit` has not run.
duetos::drivers::video::WindowHandle NetStatusWindow();

/// Boot self-test: walks `InterfaceCount()` and confirms each
/// accessor returns without faulting, then drives a synthetic
/// click through the Pass D toolbar's WidgetGroup (RFRSH is
/// read-only over the net::stack snapshot accessors, so this is
/// safe to run unconditionally at boot). Confirms RFRSH does not
/// mutate the per-iface counters. Prints PASS/FAIL on COM1.
void NetStatusSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// NetStatusSelfTest() invocation ran every check (including
/// the synthetic toolbar button click) without error.
bool NetStatusSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every
/// motion packet. Edge-detects left-button press / release
/// internally and dispatches MouseMove / MouseDown / MouseUp
/// into the WidgetGroup so AppButton hover state tracks the
/// cursor on tactility themes. The raw netstatus content
/// (multi-column iface table, DHCP lease lines, Wi-Fi scan)
/// stays raw paint (carve-out) — AppPanel / AppListRow /
/// AppLabel have no multi-column / section-header / per-row
/// colour model. The content has no per-row click semantics in
/// v0; iface editing is gated to the kernel shell. No-op before
/// NetStatusInit has wired a window.
void NetStatusMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::netstatus
