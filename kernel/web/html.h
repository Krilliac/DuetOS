#pragma once

/*
 * DuetOS — HTML tokenizer + tree builder (parse substrate).
 *
 * `ParseHtml` turns a byte buffer of (possibly messy) HTML into a
 * DOM tree rooted at a synthetic Document node, allocating every
 * node/attribute/string out of the caller's `Arena`. No rendering,
 * no styling, no scripting — that is a later swarm's job.
 *
 * What the parser handles (REAL):
 *   - Open / close / self-closing tags, with attributes that are
 *     double-quoted, single-quoted, unquoted, or valueless.
 *   - Text runs with HTML entity decoding (&amp; &lt; &gt; &quot;
 *     &apos; &nbsp; &copy; &#NN; &#xHH; and a small named set).
 *   - Comments <!-- ... --> (preserved as Comment nodes) and the
 *     doctype declaration (skipped).
 *   - Void elements (br, img, hr, input, meta, link, ...) — never
 *     get children, auto-closed on open.
 *   - Pragmatic recovery: <li> closes an open <li>, a block-level
 *     start closes an open <p>, stray close tags that match no open
 *     element are ignored, and everything still open at EOF is
 *     closed against the Document root.
 *   - <script>/<style>/<title>/<textarea> raw-text modes: their
 *     content is captured verbatim as a single Text child (entities
 *     are NOT decoded inside script/style) and not interpreted.
 *
 * GAP (deliberately out of scope for v0 — revisit when CSS/layout
 * lands and demands more conformance):
 *   - Full HTML5 tree construction: table foster-parenting, the
 *     adoption-agency formatting-element algorithm, the insertion-
 *     mode state machine. We use a flat open-element stack with a
 *     handful of recovery rules, not the spec's mode machine.
 *   - <template> content document fragments.
 *   - SVG / MathML foreign-content namespaces.
 *   - Character-encoding sniffing: input is assumed UTF-8 / ASCII;
 *     bytes >= 0x80 pass through untouched.
 *   - Script execution (captured raw, never run).
 */

#include "util/types.h"
#include "web/dom.h"

namespace duetos::web
{

using duetos::u32;

/// Parse `len` bytes of `html` into a DOM tree. Returns the synthetic
/// Document root (kind == NodeKind::Document), or nullptr if the arena
/// could not even hold the root node. The Document's children are the
/// top-level parsed nodes.
Node* ParseHtml(const char* html, u32 len, Arena& arena);

/// Parse `len` bytes of `html` as an HTML *fragment* (the markup that
/// would live inside an element, e.g. an `innerHTML` assignment). Shares
/// the same tokenizer / tree builder as `ParseHtml`; the difference is
/// purely the caller's contract — the returned node is a detached
/// container (kind == NodeKind::Element, tag `nullptr`) whose children
/// are the parsed fragment nodes, ready to be re-parented under the
/// target element. Returns nullptr if the arena could not hold the
/// container node. The container itself is a scratch holder and is not
/// meant to be inserted into a live tree.
///
/// `contextTag` is the lowercased tag name of the element the fragment is
/// being parsed *into* (the `innerHTML` target), or nullptr for a generic
/// (Document-like) context. Table-related contexts seed the tree builder
/// with the synthetic ancestor chain the HTML5 fragment-parsing algorithm
/// requires, so the fragment's natural children nest correctly:
///   - `table`                   → table > (tr/td land under an implied tbody-equivalent)
///   - `tbody` / `thead` / `tfoot` → table > tbody, so a bare `<tr>` nests
///   - `tr`                      → table > tbody > tr, so a bare `<td>`/`<th>` nests
///   - `colgroup`                → table > colgroup, so a bare `<col>` nests
///   - `select`                  → select, so a bare `<option>`/`<optgroup>` nests
/// Any other (or null) context falls back to the generic Document-like
/// path. The synthetic ancestors are scratch — only the fragment's own
/// children are returned under the detached container.
///
/// GAP: this seeds the *initial insertion context* (the element-specific
/// ancestor chain) but still drives the existing flat-stack tree builder,
/// not the spec's full insertion-mode state machine. Foster-parenting of
/// non-table content inside a table, the "in cell"/"in caption" mode
/// transitions, and `<template>` content fragments remain unimplemented —
/// revisit when CSS/layout demands fuller table conformance.
Node* ParseHtmlFragment(const char* html, u32 len, Arena& arena, const char* contextTag = nullptr);

/// Recursively concatenate the text content of `node` and all its
/// descendants into `out` (NUL-terminated, truncated to `outCap-1`
/// bytes). Comment nodes are skipped. Returns the number of bytes
/// written (excluding the NUL).
u32 CollectText(const Node* node, char* out, u32 outCap);

/// Boot self-test: parse representative fragments and assert the tree
/// shape, attributes, entity decoding, recovery, and text extraction.
/// Emits `[html-dom-selftest] PASS (...)` on success; on failure fires
/// KBP_PROBE_V(kBootSelftestFail, ...) and emits a FAIL line.
void HtmlDomSelfTest();

} // namespace duetos::web
