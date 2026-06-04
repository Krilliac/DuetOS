#pragma once

#include "security/privilege/arm_state.h"
#include "security/privilege/scope.h"
#include "web/js/interp.h"

/*
 * DuetOS — Privileged-Origin Mode (spec §13.7): the `window.duetos.*` JS
 * host binding. This is the BROWSER client's (Client A) adapter onto the
 * kernel-level Privilege Engine (kernel/security/privilege/): it builds the
 * host-object tree and marshals each method call to
 * security::privilege::ValidateRequest. The pure engine stays JS-free; this
 * one file is the JS bridge.
 *
 * Installed ONLY on an armed tab's JS context (PrivConfig.available &&
 * PrivTab.IsArmed). A non-armed page sees `window.duetos === undefined`.
 */

namespace duetos::web::priv
{
struct PrivBind
{
    const duetos::security::privilege::PrivTab* tab = nullptr;
    duetos::security::privilege::Roots roots{};
    const char* origin = "https://claude.ai/code";
    const char* client = "browser"; // audit client-identity tag
};

// Build the `duetos` host object (hostGet exposes armed/origin/scope +
// fs/proc/kernel/net; installHandler is intentionally absent). Returns the
// Object JsValue, or Undefined on arena exhaustion.
js::JsValue BuildDuetosObject(js::Interp& I, PrivBind* bind);

// Define `duetos` + a `window` host object (window.duetos) on I.global.
// Call only when the tab is armed. Returns false if there is no global env.
bool PrivBindingInstall(js::Interp& I, PrivBind* bind);

// Test-only hook: format the current wall clock as "YYYY-MM-DDTHH:MM:SSZ" into
// `out` (cap must be >= 21). Exposed solely so the boot self-test can assert the
// stamp's shape without a mounted FAT32 volume; production code uses the
// internal formatter directly.
void PrivBindingFormatIso8601(char* out, duetos::u32 cap);

void PrivBindingSelfTest();

} // namespace duetos::web::priv
