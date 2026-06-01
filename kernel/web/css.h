#pragma once

/*
 * DuetOS — CSS cascade engine (computed style per DOM element).
 *
 * This consumes the DOM that kernel/web/dom.{h,cpp} + html.{h,cpp}
 * produce and emits one `ComputedStyle` per element. It is the input
 * the *next* swarm's layout/paint will consume — there is NO layout
 * and NO painting here. The job is strictly: tokenize/parse CSS,
 * match selectors, run the cascade (origin → specificity → source
 * order), inherit the inherited properties, and hand back a style
 * map keyed by Node*.
 *
 * Memory discipline (kernel rules: no naked new/delete, no libc):
 * every parsed rule, selector, declaration, and the per-node
 * ComputedStyle blocks are carved out of a caller-supplied
 * `duetos::web::Arena` (the SAME arena type the DOM uses — this
 * header reuses it, it does NOT define a second one). Arena
 * exhaustion is signalled by a null return / a truncated rule list;
 * nothing here faults or calls a global allocator.
 *
 * What is REAL:
 *   - Tokenizer + parser for stylesheets and inline `style="..."`.
 *   - Selectors: type, .class, #id, *, descendant combinator (space),
 *     compound (div.note#x), comma selector-lists. Specificity (a,b,c).
 *   - A practical ComputedStyle subset (see the struct below).
 *   - Value parsing: px, %, named colors + #rgb/#rrggbb + rgb()/rgba().
 *   - A built-in User-Agent default stylesheet.
 *   - Cascade UA < author, specificity then source order, inheritance.
 *
 * GAP (deliberately out of scope for this slice):
 *   - Pseudo-classes/elements (:hover, ::before), attribute selectors
 *     ([type=text]), child/sibling combinators (>, +, ~), :nth-child.
 *   - @media / @import / @font-face (parsed-past, not honored).
 *   - calc(), custom properties / var(), !important (best-effort/GAP).
 *   - flexbox / grid / floats / position; em/rem/vh units. We support
 *     px + % + a handful of keywords only.
 */

#include "util/types.h"
#include "web/dom.h"

namespace duetos::web
{

using duetos::i32;
using duetos::u16;
using duetos::u32;
using duetos::u8;

/// An sRGB color with 8-bit channels + alpha. `a == 0` is fully
/// transparent; the `transparent` keyword and an unset background map
/// to {0,0,0,0}.
struct Color
{
    u8 r = 0;
    u8 g = 0;
    u8 b = 0;
    u8 a = 255;

    constexpr bool operator==(const Color& o) const { return r == o.r && g == o.g && b == o.b && a == o.a; }
};

/// A CSS length: either an absolute pixel count, a percentage of some
/// layout-defined basis, or the `auto` keyword. We do not resolve
/// percentages here — that is layout's job; we only carry the kind +
/// magnitude through the cascade.
enum class LengthKind : u8
{
    Auto,
    Px,
    Percent,
};

struct Length
{
    LengthKind kind = LengthKind::Auto;
    i32 value = 0; // px or percent magnitude; meaningless when Auto

    static constexpr Length Px(i32 v) { return Length{LengthKind::Px, v}; }
    static constexpr Length AutoVal() { return Length{LengthKind::Auto, 0}; }
    constexpr bool IsAuto() const { return kind == LengthKind::Auto; }
};

enum class Display : u8
{
    Block,
    Inline,
    InlineBlock,
    None,
};

enum class FontWeight : u8
{
    Normal,
    Bold,
};

enum class FontStyleKind : u8
{
    Normal,
    Italic,
};

enum class TextAlign : u8
{
    Left,
    Right,
    Center,
    Justify,
};

enum class WhiteSpace : u8
{
    Normal,
    Pre,
    Nowrap,
};

enum class BorderStyle : u8
{
    None,
    Solid, // any non-`none` style collapses to Solid in this subset
};

/// Per-edge box metrics (margin / padding). Top/right/bottom/left.
struct EdgeLengths
{
    Length top;
    Length right;
    Length bottom;
    Length left;
};

/// A single resolved border edge: width (px), color, on/off style.
struct Border
{
    i32 width = 0;
    Color color{0, 0, 0, 255};
    BorderStyle style = BorderStyle::None;
};

/// The computed style for one element. This is a *practical* subset of
/// CSS, not the full property set — enough for a text-document layout
/// engine to render headings, paragraphs, links, lists, and simple
/// boxes. Inherited properties (color, font-*, text-align, line-height,
/// white-space, list-style) propagate from the parent; everything else
/// resets to the initial values baked into this struct's defaults.
struct ComputedStyle
{
    // --- inherited ---
    Color color{0, 0, 0, 255};
    i32 fontSize = 16; // px
    FontWeight fontWeight = FontWeight::Normal;
    FontStyleKind fontStyle = FontStyleKind::Normal;
    TextAlign textAlign = TextAlign::Left;
    i32 lineHeight = 0; // px; 0 == "normal" (layout derives from fontSize)
    WhiteSpace whiteSpace = WhiteSpace::Normal;
    bool listStyleNone = false; // list-style: none

    // --- non-inherited ---
    Display display = Display::Inline;
    Color backgroundColor{0, 0, 0, 0}; // transparent
    bool underline = false;            // text-decoration: underline
    EdgeLengths margin{};
    EdgeLengths padding{};
    Border border{}; // single uniform border for all edges (subset)
    Length width = Length::AutoVal();
    Length height = Length::AutoVal();
};

// ---------------------------------------------------------------------
// Parsed stylesheet representation
// ---------------------------------------------------------------------

/// One simple compound selector, e.g. `div.note#x`. A descendant
/// selector chains several of these via `ancestor` (the left side must
/// match some ancestor of the element the right side matches).
struct SimpleSelector
{
    const char* tag = nullptr;       // type selector; nullptr == universal/none
    const char* id = nullptr;        // #id (one supported)
    const char* className = nullptr; // .class (one supported)
    bool universal = false;          // `*`
    // For descendant combinator: this selector's match must have an
    // ancestor matching `ancestor` (which may itself chain further).
    SimpleSelector* ancestor = nullptr;
};

/// One declaration: `property: value`. The value is the raw,
/// whitespace-trimmed token string; the cascade interprets it per
/// property.
struct Declaration
{
    const char* property = nullptr; // lowercased
    const char* value = nullptr;    // trimmed raw value
    bool important = false;         // `!important` (best-effort; GAP)
    Declaration* next = nullptr;
};

/// One rule: a selector (the rightmost compound of a complex selector)
/// + its declaration block + a precomputed specificity and source
/// order. A comma selector-list expands into one Rule per selector.
struct Rule
{
    SimpleSelector* selector = nullptr;
    Declaration* decls = nullptr;
    u32 specificity = 0; // packed (a<<16)|(b<<8)|c
    u32 order = 0;       // source order within the parsed sheet sequence
    bool userAgent = false;
    Rule* next = nullptr;
};

/// A parsed stylesheet: a singly-linked list of rules in source order.
struct StyleSheet
{
    Rule* rules = nullptr;
    Rule* tail = nullptr;
    u32 ruleCount = 0;
};

// ---------------------------------------------------------------------
// Per-node style attachment
// ---------------------------------------------------------------------

/// The computed-style map. Styles are attached *out of band* (the DOM
/// Node has no style pointer), keyed by Node*. Layout looks a node's
/// style up via `Get`. Backed by an arena-allocated parallel array.
struct StyleMap
{
    const Node** keys = nullptr;
    ComputedStyle* styles = nullptr;
    u32 count = 0;
    u32 cap = 0;

    /// Returns the computed style for `n`, or nullptr if `n` was not an
    /// element styled during ComputeStyles (e.g. a text/comment node).
    const ComputedStyle* Get(const Node* n) const;
};

// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

/// Parse a stylesheet from `css` (`len` bytes) into `sheet`, appending
/// rules. `userAgent` tags the rules as UA-origin (lower cascade
/// priority than author rules). Unknown @-rules are skipped without
/// choking. Safe to call repeatedly to layer sheets into one StyleSheet
/// (source order is preserved across calls).
void ParseStyleSheet(StyleSheet& sheet, const char* css, u32 len, bool userAgent, Arena& arena);

/// Parse an inline `style="..."` declaration block (no selector, no
/// braces) into a declaration list. Returns the head, or nullptr if
/// empty / out of arena.
Declaration* ParseInlineStyle(const char* style, u32 len, Arena& arena);

/// Append DuetOS's built-in User-Agent default stylesheet into `sheet`
/// (tagged userAgent=true). Call this before the author sheet so author
/// rules win ties.
void AppendUserAgentStyles(StyleSheet& sheet, Arena& arena);

/// Walk `doc`, matching `sheet` against every element, folding in each
/// element's inline style, and inheriting from the parent's computed
/// style. Returns a StyleMap keyed by Node*. The map and every style in
/// it are arena-allocated.
StyleMap ComputeStyles(const Node* doc, const StyleSheet& sheet, Arena& arena);

/// Parse a CSS color value (named / #rgb / #rrggbb / rgb() / rgba())
/// into `out`. Returns true on success. Exposed for the self-test.
bool ParseColor(const char* s, Color& out);

/// Parse a CSS length token ("12px", "50%", "auto", bare number) into
/// `out`. Returns true on success. GAP: em/rem/vh accepted as px.
bool ParseLength(const char* s, Length& out);

/// Boot self-test: builds a small DOM + author sheet, computes styles,
/// and asserts specificity ordering, inline-over-sheet, inheritance, a
/// UA default, display:none, and color-equivalence. Emits
/// `[css-selftest] PASS (...)`; on first failed sub-check fires
/// KBP_PROBE_V(kBootSelftestFail, <check#>) and emits a FAIL line.
void CssSelfTest();

} // namespace duetos::web
