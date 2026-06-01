#pragma once

/*
 * DuetOS — internal shared declarations for the layout engine.
 *
 * The layout engine is split across two translation units that share a
 * small set of helpers and a context struct:
 *   - layout.cpp        — block formatting + the public LayoutDocument.
 *   - layout_inline.cpp — inline formatting (line boxes, word wrap).
 * This header is the seam between them. It is NOT part of the public API
 * (layout.h is) — only the two layout TUs include it.
 *
 * Everything here is freestanding kernel code: no libc, allocations go
 * through the caller's web::Arena (reused from dom.h via css_arena.h).
 */

#include "util/types.h"
#include "web/css.h"
#include "web/display_list.h"
#include "web/dom.h"
#include "web/layout.h" // TextMetrics

namespace duetos::web
{

using duetos::i32;
using duetos::u32;

namespace layout_detail
{

// The block default line-height multiple, applied when ComputedStyle's
// lineHeight is 0 ("normal"): line box height = fontSize * 12 / 10.
constexpr i32 kNormalLineNum = 12;
constexpr i32 kNormalLineDen = 10;

// Default <img> placeholder box when neither width nor height is styled.
constexpr i32 kDefaultImgW = 32;
constexpr i32 kDefaultImgH = 32;

/// Per-walk layout state shared by the block + inline passes.
struct LayoutCtx
{
    const StyleMap& styles;
    const TextMetrics& metrics;
    DisplayList* out;
    Arena& arena;
};

/// Computed line-box height (device px) for a style: explicit
/// line-height wins, else fontSize scaled by the "normal" multiple.
inline i32 LineHeightPx(const ComputedStyle& s)
{
    if (s.lineHeight > 0)
    {
        return s.lineHeight;
    }
    const i32 fs = (s.fontSize > 0) ? s.fontSize : 16;
    return (fs * kNormalLineNum) / kNormalLineDen;
}

/// Resolve a CSS Length against a containing-block extent. `autoVal` is
/// returned for `auto`; percentages resolve against `basis`.
inline i32 ResolveLength(const Length& len, i32 basis, i32 autoVal)
{
    switch (len.kind)
    {
    case LengthKind::Px:
        return len.value;
    case LengthKind::Percent:
        return (basis * len.value) / 100;
    case LengthKind::Auto:
    default:
        return autoVal;
    }
}

/// Edge resolution for margin/padding. `auto` resolves to 0 here
/// (GAP: auto-margin centering — text-align covers inline centering).
inline i32 EdgePx(const Length& len, i32 basis)
{
    return ResolveLength(len, basis, 0);
}

inline bool IsWhitespaceByte(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

/// The computed style for a node (nullptr for text/comment nodes).
inline const ComputedStyle* StyleOf(const LayoutCtx& ctx, const Node* n)
{
    return ctx.styles.Get(n);
}

/// An inline "run": a contiguous text slice carrying the style of the
/// element that owns it. Shared between the block pass (loose-text
/// fallback) and the inline pass.
struct InlineRun
{
    const char* text = nullptr; // points into arena-owned DOM text
    u32 len = 0;
    const ComputedStyle* style = nullptr; // owning element's style
};

// Defined in layout_inline.cpp: emit one TextRun command for the slice
// [start, start+len) of `run` at top-left (x, y). Shared so the block
// pass's loose-text fallback can emit a single run without duplicating
// the metric math.
void EmitTextRun(LayoutCtx& ctx, const InlineRun& run, u32 start, u32 len, i32 x, i32 y);

// Defined in layout_inline.cpp: lay the inline runs of `parent` out
// within the content box [contentX, contentX+contentW) from `originY`;
// returns the y just past the last line.
i32 LayoutInline(LayoutCtx& ctx, const Node* parent, const ComputedStyle& parentStyle, i32 contentX, i32 contentW,
                 i32 originY);

// Defined in layout.cpp: lay one block-level box out; returns the y just
// past the box's bottom margin edge. Declared here so the inline TU's
// (currently none) and the recursive block walk share one prototype.
i32 LayoutBlock(LayoutCtx& ctx, const Node* node, i32 cbX, i32 cbWidth, i32 originY);

} // namespace layout_detail

} // namespace duetos::web
