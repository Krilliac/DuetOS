#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Firewall — v0.
 *
 * Read-only viewer over `kernel/net/firewall.h`: defaults,
 * stats, rule table (first-match-wins), conntrack snapshot,
 * recent denials. Rule editing remains gated to the kernel
 * shell with `kCapNetAdmin` — the toolbar surfaces a read-only
 * RFRSH affordance only.
 *
 * Context: kernel. Draw is called under the compositor lock.
 */

namespace duetos::apps::firewall
{

/// Install the content-draw callback on `handle`.
void FirewallInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the firewall window. Returns `kWindowInvalid` if
/// `FirewallInit` has not run.
duetos::drivers::video::WindowHandle FirewallWindow();

/// Boot self-test: drives a synthetic click through the Pass D
/// toolbar's WidgetGroup (RFRSH is read-only, so this is safe
/// to run unconditionally at boot) and verifies the dispatch
/// path is wired end-to-end. Confirms RFRSH does not mutate any
/// stats counter or denial-log sequence. Prints PASS/FAIL on
/// COM1.
void FirewallSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// FirewallSelfTest() invocation ran every check (including
/// the synthetic toolbar button click) without error.
bool FirewallSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every
/// motion packet. Edge-detects left-button press / release
/// internally and dispatches MouseMove / MouseDown / MouseUp
/// into the WidgetGroup so AppButton hover state tracks the
/// cursor on tactility themes. The raw firewall content
/// (defaults / stats / multi-column tables for rules /
/// conntrack / denials) stays raw paint (carve-out) — AppPanel
/// / AppListRow / AppLabel have no multi-column / section-
/// header / per-row colour model. The content has no per-row
/// click semantics in v0; rule editing is gated to the kernel
/// shell with `kCapNetAdmin`. No-op before FirewallInit has
/// wired a window.
void FirewallMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::firewall
