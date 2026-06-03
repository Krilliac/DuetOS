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
 *   document.getElementById / getElementsByTagName /
 *           getElementsByClassName / querySelector / querySelectorAll
 *           (single compound: tag / .class / #id / * , in combination) /
 *           createElement / createTextNode / body / documentElement
 *   Element: tagName, id, className (get/set), getAttribute /
 *           setAttribute / hasAttribute / removeAttribute, textContent
 *           (get/set), children / childNodes, firstChild / parentNode /
 *           nextSibling, appendChild / removeChild, innerHTML
 *           (get = serialize, set = parse-and-replace),
 *           querySelector / querySelectorAll / getElementsByTagName /
 *           getElementsByClassName (subtree-scoped to the element),
 *           classList.add / remove / contains / toggle,
 *           addEventListener / removeEventListener / dispatchEvent /
 *           click() — programmatic event dispatch with bubbling up the
 *           ancestor chain, stopPropagation / preventDefault, and an
 *           event object exposing type / target.
 *
 * GAP (deliberately out of scope for this slice):
 *   - Event model: programmatic dispatchEvent()/click() + bubbling are
 *     REAL; capture phase, the `once`/`passive` listener options, and
 *     event delegation edge cases are unimplemented. REAL user input
 *     (mouse/keyboard from the window manager) is not yet routed to these
 *     listeners — but the retained JsDomContext below (with
 *     JsDomContextDispatchClick) now provides the persistent listener
 *     table + dispatch entry point a WM click can call once apps/browser.cpp
 *     wires it (Create at render → RunScript per <script> → DispatchClick
 *     on a click). See the event-model block in js_dom.cpp.
 *   - querySelector/All: only a SINGLE compound selector is matched
 *     (tag, .class, #id, or universal). Descendant/child/sibling combinators, attribute
 *     and pseudo selectors, and comma selector-lists are unsupported —
 *     the CSS selector engine in kernel/web/css.cpp keeps its
 *     parse/Matches entry points in an anonymous namespace, so they are
 *     not reachable from here. Revisit once css.h exports a public
 *     `ParseSelector` + `Matches(SimpleSelector*, const Node*)`.
 *   - classList: no replace / item / length / iteration.
 *   - Live HTMLCollection semantics (children/childNodes/getElementsBy*
 *     and querySelectorAll all return snapshots, not live collections).
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
 * Retained DOM+JS context. Unlike JsRunOnDocument (one-shot: build an
 * interpreter, run one script, discard everything), a JsDomContext
 * PERSISTS the JS interpreter, its global env, and the DOM binding's
 * listener table + wrapper cache across multiple RunScript calls and
 * across the run→dispatch gap. This is the foundation for browser
 * interactivity: a page <script> can register an `addEventListener`
 * during render, and a later user click (translated by the browser app
 * into a Node dispatch) still finds that listener alive.
 *
 * The context is an opaque, file-static SINGLETON — exactly one page is
 * active at a time. (GAP: no tabs / no concurrent pages — a second
 * Create resets the first. The browser app owns one loaded page, so the
 * singleton matches today's need; lifting it to per-tab needs the arena
 * backing store to become per-context rather than the single
 * g_jsDomArena.)
 *
 * Lifetime contract the caller (apps/browser.cpp) must honor:
 *   - The DOM nodes live in `domArena` (the browser's persistent render
 *     arena that owns `doc`), NOT in the context's JS arena. The browser
 *     keeps that arena + `doc` alive for as long as it dispatches into
 *     the context. DispatchClick takes a raw Node* into that tree.
 *   - The JS arena (listeners, closures, wrapper cache) is reset ONLY by
 *     Create (a new page). It is NOT reset between RunScript and
 *     DispatchClick, so a listener registered by one script survives to
 *     be fired by a later dispatch.
 */
struct JsDomContext;

/*
 * (Re)create the single active context bound to `doc`. Resets the JS
 * arena, reinstalls the language builtins + the live `document` binding,
 * and points the DOM binding at `doc` / `domArena` (the arena that owns
 * `doc`, so script-created nodes persist). `console_out` (optional) is
 * mirrored the captured console.log output of each RunScript; pass null
 * if the caller doesn't need it. Returns the singleton (never null on a
 * valid `doc`), or null if `doc` is null or the global env / builtins
 * fail to install.
 */
JsDomContext* JsDomContextCreate(Document* doc, Arena& domArena, char* console_out, u32 console_cap);

/*
 * Lex/parse/evaluate `script` (length `len`) against the RETAINED
 * interpreter + global env + DOM binding. Listeners the script registers
 * via addEventListener PERSIST in the context for a later DispatchClick.
 * Returns the eval status (Ok, or InvalidArgument syntax error / Timeout
 * runaway / Overflow recursion / OutOfMemory / BadState runtime error).
 * A null / dead context returns InvalidArgument.
 */
Result<void> JsDomContextRunScript(JsDomContext* ctx, const char* script, u32 len);

/*
 * Dispatch a "click" event to `target` through the retained listener
 * table, bubbling up the ancestor chain exactly like the scripted
 * element.click() path. Returns true iff a listener called
 * preventDefault() (so the browser knows whether to follow the default
 * action, e.g. a link navigation). A null / dead context, or a null
 * target, returns false.
 */
bool JsDomContextDispatchClick(JsDomContext* ctx, Node* target);

/*
 * Read-and-clear the context's "DOM was mutated" flag. Returns true iff a
 * DOM-tree mutation (setAttribute / textContent / innerHTML / classList)
 * has landed since the last consume. The browser calls this right after a
 * click dispatch: a true result means the retained DOM changed, so the
 * page must be re-laid-out for the change to reach the screen. A null
 * context returns false. Idempotent after a true (clears the flag).
 */
bool JsDomContextConsumeDirty(JsDomContext* ctx);

/*
 * Boot self-test. Parses a small HTML document, runs a battery of
 * scripts, and asserts the JS↔DOM effects both via the returned console
 * buffer and by re-walking the live DOM (getElementById textContent,
 * setAttribute round-trip, textContent mutation, createElement +
 * appendChild growth, getElementsByTagName length, getElementsByClassName,
 * querySelector/querySelectorAll, classList add/remove/contains/toggle,
 * addEventListener + click() firing, event bubbling, stopPropagation,
 * removeEventListener, event.target identity, console.log of a DOM
 * value). Emits `[js-dom-selftest] PASS (N/N)` on
 * success; on any
 * failure fires KBP_PROBE_V(kBootSelftestFail, idx) and emits a FAIL
 * line. Wired into boot_bringup via DUETOS_BOOT_SELFTEST after the JS
 * engine self-test.
 */
void JsDomSelfTest();

} // namespace duetos::web
