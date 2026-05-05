#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Firewall — v0 placeholder.
 *
 * GAP: no kernel firewall module exists yet — there is no packet
 * filter, no ruleset, no per-port allow/deny, no zone model. The
 * Start menu surfaces a Firewall entry because users expect it
 * (and it pairs with the Network Status viewer); the window
 * itself paints an honest empty-state message pointing at the
 * Roadmap. Replace the body with a real rule list when the
 * filter subsystem lands.
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

} // namespace duetos::apps::firewall
