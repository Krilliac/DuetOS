#pragma once

/*
 * DuetOS — block + inline box-layout engine (DOM + styles -> display list).
 *
 * Consumes a styled DOM — a `Document*` plus the `css::StyleMap` of
 * per-node ComputedStyle that ComputeStyles produced — and emits a flat,
 * paint-order `DisplayList` of drawing commands (see display_list.h).
 * There is NO framebuffer drawing here: we describe the draws; the
 * browser/painter swarm executes them.
 *
 * Text is treated as MONOSPACE against a fixed glyph cell, because the
 * kernel framebuffer font is a fixed cell. The caller supplies the cell
 * metrics (glyph_w, glyph_h) and a bold/size scale via `TextMetrics`, so
 * the self-test is deterministic. A char advances glyph_w; a line
 * advances glyph_h * line-height.
 *
 * What is REAL:
 *   - Block formatting: block boxes stack vertically; width = containing
 *     block width minus own horizontal margin/border/padding (honoring
 *     width:px/% / auto); height = content height unless height is set;
 *     margin/padding/border box metrics; FillRect for the padding box;
 *     Border commands when border width > 0. display:none skips the
 *     subtree.
 *   - Inline formatting: inline content (text + inline elements) flows
 *     left-to-right into line boxes within the content width, WRAPPING at
 *     word boundaries (hard-breaking an over-long word); each line
 *     advances by glyph_h * line-height; one TextRun per run with the
 *     element's color/bold/italic/font-size; text-align left/center/right
 *     per line; white-space:pre keeps spaces + honors newlines.
 *   - Block-in-inline split: an inline element (e.g. <span>) that
 *     contains a block-level descendant is split around the block per
 *     CSS box generation — the inline content before/after the block
 *     each forms an anonymous block, the block child is pulled out, and
 *     the three stack vertically in the block formatting context (the
 *     inverse of the anonymous-block wrapping that wraps loose inline
 *     siblings around a block). The split fragments carry the inline
 *     element's own style.
 *   - <img> -> ImageBox sized by width/height style if present else a
 *     default placeholder; carries the src attr for the painter.
 *
 * GAP (deliberately out of scope for this slice): inline-box DECORATION
 * splitting (the block-in-inline split stacks the inline element's text
 * but does NOT re-draw the split inline element's own borders/padding/
 * background on the before/after fragments); floats; position
 * (absolute/relative/fixed/sticky); flexbox/grid; tables;
 * margin-collapsing; z-index / stacking contexts; overflow/scroll
 * clipping; proportional/measured fonts (monospace only); inline-block
 * sizing nuances; vertical-align; bidi/RTL; writing-modes.
 *
 * Memory discipline (kernel rules: no naked new/delete, no libc): the
 * DisplayList, its item array, and any scratch all come from the
 * caller's `duetos::web::Arena` (reused from dom.h). Exhaustion truncates
 * the list rather than faulting.
 */

#include "util/types.h"
#include "web/css.h"
#include "web/display_list.h"
#include "web/dom.h"

namespace duetos::web
{

using duetos::i32;
using duetos::u32;

/// Fixed-cell font metrics. The kernel framebuffer font is monospace, so
/// every glyph occupies `glyphW x glyphH` device px. `boldScale` and
/// `sizeScaleNum/Den` let the caller widen bold runs / scale the cell to
/// the computed font-size; the engine keeps them simple integer ratios so
/// layout stays deterministic for the self-test.
struct TextMetrics
{
    i32 glyphW = 8;      // advance per char, device px
    i32 glyphH = 16;     // cell height, device px
    i32 baseFontPx = 16; // the font-size glyphW/glyphH were measured at

    /// Advance width (device px) for a run of `chars` glyphs at the given
    /// computed font-size. Scales the cell linearly by fontPx/baseFontPx.
    i32 AdvanceFor(u32 chars, i32 fontPx) const
    {
        const i32 cellW = (baseFontPx > 0) ? (glyphW * fontPx) / baseFontPx : glyphW;
        return static_cast<i32>(chars) * cellW;
    }

    /// Glyph cell height (device px) for the given computed font-size.
    i32 CellHeight(i32 fontPx) const { return (baseFontPx > 0) ? (glyphH * fontPx) / baseFontPx : glyphH; }
};

/// Lay `doc` out at `viewportW` device px using `styles` + `metrics`,
/// returning an arena-allocated DisplayList in paint order. Never null:
/// on arena exhaustion the returned list is empty / truncated. The
/// returned pointer and every item it holds live in `arena`.
/// (Note: ComputeStyles / StyleMap / ComputedStyle live directly in the
/// duetos::web namespace — there is no nested `css::` namespace; the
/// `css.h` header just declares them here.)
DisplayList* LayoutDocument(const Node* doc, const StyleMap& styles, u32 viewportW, const TextMetrics& metrics,
                            Arena& arena);

/// Boot self-test: parses a small HTML doc, computes styles, lays it out
/// at a fixed width + metrics, and asserts the display list (styled div
/// FillRect at the expected rect; bold heading run at the expected y;
/// long paragraph wraps to >= 2 runs; stacked blocks' y offsets;
/// display:none emits nothing; text-align:center shifts a run's x).
/// Emits `[layout-selftest] PASS (...)`; on the first failed sub-check
/// fires KBP_PROBE_V(kBootSelftestFail, <#>) and emits a FAIL line.
void LayoutSelfTest();

} // namespace duetos::web
