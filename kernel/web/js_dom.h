#pragma once

/*
 * DuetOS — kernel/web: JavaScript ⇄ DOM bindings.
 *
 * This is the layer that turns the standalone JS interpreter
 * (kernel/web/js/) into a *scripting* engine: it installs a live
 * `document` object into a fresh JS global env and exposes the parsed
 * DOM tree (kernel/web/dom.h) to script. A script can now read and
 * MUTATE the page — `getElementById`, `setAttribute`, `textContent`,
 * `createElement`/`appendChild`, etc. — and the effects land in the
 * real Node tree, not a copy.
 *
 * Memory model: DOM nodes/attrs/strings created by a script
 * (createElement, createTextNode, setAttribute, textContent=, …) are
 * carved out of the *DOM* arena passed to JsRunOnDocument — the same
 * arena that owns the document — so the mutations outlive the eval.
 * Transient JS values (strings the script computes, the wrapper
 * objects, arrays returned by getElementsByTagName) live in a separate
 * JS scratch arena reclaimed when the eval returns.
 *
 * Bounded execution: the underlying engine's step budget still applies
 * (a runaway script returns Timeout instead of hanging the boot).
 *
 * REAL surface (see the per-method comments in js_dom.cpp):
 *   document.getElementById / getElementsByTagName / querySelector
 *           (#id/.class/tag) / createElement / createTextNode /
 *           body / documentElement
 *   Element: tagName, id, className (get/set), getAttribute /
 *           setAttribute / hasAttribute / removeAttribute, textContent
 *           (get/set), children / childNodes, firstChild / parentNode /
 *           nextSibling, appendChild / removeChild, innerHTML (get =
 *           serialize).
 *
 * GAP (deliberately out of scope for this slice):
 *   - Event model (addEventListener / dispatchEvent).
 *   - innerHTML SET (get-only here; parse-and-replace is heavy).
 *   - querySelectorAll and complex/compound selectors.
 *   - Live HTMLCollection semantics (children/childNodes are snapshots).
 *   - CSSOM / element.style.
 *   - Timers (setTimeout) and network (fetch / XMLHttpRequest).
 *   - The full HTMLElement property surface (offsetWidth, dataset, …).
 */

#include "util/result.h"
#include "util/types.h"
#include "web/dom.h"

namespace duetos::web
{

using duetos::core::ErrorCode;
using duetos::core::Result;

// The DOM root is a Node with NodeKind::Document. Alias for readability
// at the binding boundary — a "Document" is just that synthetic root.
using Document = Node;

/// Result of running a script against a document: the success/error
/// status plus the captured console output (already written into the
/// caller's buffer). `consoleLen` is the byte count (excluding NUL).
struct JsDomResult
{
    Result<void> status;
    u32 consoleLen = 0;
};

/*
 * Install a `document` binding for `doc` into a fresh JS global env and
 * evaluate `script` (length `len`) against the LIVE DOM. New DOM nodes
 * the script creates are allocated out of `domArena` (must be the arena
 * that owns `doc`, so mutations persist). `console_out` receives the
 * script's console.log output (NUL-terminated, truncated to
 * console_cap-1).
 *
 * Returns the eval status in `JsDomResult::status` — Ok on success, or
 * the engine's error (InvalidArgument syntax error, Timeout runaway,
 * OutOfMemory, BadState runtime type error).
 */
JsDomResult JsRunOnDocument(Document* doc, const char* script, u32 len, Arena& domArena, char* console_out,
                            u32 console_cap);

/*
 * Boot self-test. Parses a small HTML document, runs a battery of
 * scripts, and asserts the JS↔DOM effects both via the returned console
 * buffer and by re-walking the live DOM (getElementById textContent,
 * setAttribute round-trip, textContent mutation, createElement +
 * appendChild growth, getElementsByTagName length, console.log of a DOM
 * value). Emits `[js-dom-selftest] PASS (N/N)` on success; on any
 * failure fires KBP_PROBE_V(kBootSelftestFail, idx) and emits a FAIL
 * line. Wired into boot_bringup via DUETOS_BOOT_SELFTEST after the JS
 * engine self-test.
 */
void JsDomSelfTest();

} // namespace duetos::web
