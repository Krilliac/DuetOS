/*
 * DuetOS — inline formatting for the layout engine.
 *
 * Turns a block's inline children (text nodes + inline elements) into
 * line boxes within the block's content width, wrapping at word
 * boundaries (hard-breaking an over-long word), honoring text-align
 * per line and white-space:pre. Emits one TextRun display command per
 * fragment. The block pass (layout.cpp) calls LayoutInline; the shared
 * seam is layout_internal.h.
 *
 * Monospace only: each glyph advances TextMetrics::glyphW (scaled by
 * font-size). GAP: proportional/measured fonts, bidi/RTL, vertical-
 * align, inline-block sizing nuances, inline images.
 */

#include "web/layout_internal.h"

#include "util/string.h"
#include "web/css_arena.h"

namespace duetos::web
{
namespace layout_detail
{

void EmitTextRun(LayoutCtx& ctx, const InlineRun& run, u32 start, u32 len, i32 x, i32 y)
{
    if (len == 0)
    {
        return;
    }
    const ComputedStyle& s = *run.style;
    DisplayItem it;
    it.cmd = DisplayCmd::TextRun;
    it.rect.x = x;
    it.rect.y = y;
    it.rect.w = ctx.metrics.AdvanceFor(len, s.fontSize);
    it.rect.h = ctx.metrics.CellHeight(s.fontSize);
    it.color = s.color;
    it.text = run.text + start;
    it.textLen = len;
    it.bold = (s.fontWeight == FontWeight::Bold);
    it.italic = (s.fontStyle == FontStyleKind::Italic);
    it.fontPx = s.fontSize;
    ctx.out->Push(it);
}

namespace
{

// Collect inline runs from `parent`'s inline subtree into `runs[]`
// (bounded by `cap`); returns the count produced. Inline elements
// contribute their text children carrying the element's own style.
// display:none subtrees are skipped. (GAP: inline images.)
u32 CollectInlineRuns(const LayoutCtx& ctx, const Node* parent, const ComputedStyle* inheritedStyle, InlineRun* runs,
                      u32 cap, u32 count)
{
    for (const Node* c = parent->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (count >= cap)
        {
            break;
        }
        if (c->kind == NodeKind::Text)
        {
            if (c->text != nullptr && c->text[0] != '\0')
            {
                runs[count].text = c->text;
                runs[count].len = static_cast<u32>(duetos::core::StrLen(c->text));
                runs[count].style = inheritedStyle;
                ++count;
            }
        }
        else if (c->kind == NodeKind::Element)
        {
            const ComputedStyle* cs = StyleOf(ctx, c);
            if (cs != nullptr && cs->display == Display::None)
            {
                continue;
            }
            const ComputedStyle* childStyle = (cs != nullptr) ? cs : inheritedStyle;
            count = CollectInlineRuns(ctx, c, childStyle, runs, cap, count);
        }
    }
    return count;
}

// One pending fragment on the current line: a (run, start, len) slice
// plus its measured pixel width and x within the line content.
struct LineFrag
{
    const InlineRun* run = nullptr;
    u32 start = 0;
    u32 len = 0;
    i32 x = 0; // x offset within the content box (pre-align)
    i32 w = 0;
};

// Flush the accumulated line fragments at vertical `y`, applying `align`
// across [contentX, contentX+contentW). `lineW` is the used width.
void FlushLine(LayoutCtx& ctx, LineFrag* frags, u32 nFrags, i32 contentX, i32 contentW, i32 lineW, i32 y,
               TextAlign align)
{
    i32 shift = 0;
    if (align == TextAlign::Center)
    {
        shift = (contentW - lineW) / 2;
        if (shift < 0)
        {
            shift = 0;
        }
    }
    else if (align == TextAlign::Right)
    {
        shift = contentW - lineW;
        if (shift < 0)
        {
            shift = 0;
        }
    }
    for (u32 i = 0; i < nFrags; ++i)
    {
        const LineFrag& f = frags[i];
        EmitTextRun(ctx, *f.run, f.start, f.len, contentX + f.x + shift, y);
    }
}

} // namespace

i32 LayoutInline(LayoutCtx& ctx, const Node* parent, const ComputedStyle& parentStyle, i32 contentX, i32 contentW,
                 i32 originY)
{
    // Gather runs. Bound the run count; deep inline trees beyond this
    // truncate (GAP) rather than over-allocating.
    constexpr u32 kMaxRuns = 256;
    InlineRun* runs = ArenaArray<InlineRun>(ctx.arena, kMaxRuns);
    if (runs == nullptr)
    {
        return originY;
    }
    const u32 nRuns = CollectInlineRuns(ctx, parent, &parentStyle, runs, kMaxRuns, 0);
    if (nRuns == 0)
    {
        return originY;
    }

    // Line accumulator. Fragments per line are bounded; busy lines
    // truncate (GAP).
    constexpr u32 kMaxFragsPerLine = 256;
    LineFrag* frags = ArenaArray<LineFrag>(ctx.arena, kMaxFragsPerLine);
    if (frags == nullptr)
    {
        return originY;
    }

    i32 y = originY;
    i32 penX = 0;       // x within content box for the next fragment
    u32 nFrags = 0;     // fragments on the current line
    i32 lineHeight = 0; // tallest line-height seen on the current line
    const TextAlign align = parentStyle.textAlign;

    auto finishLine = [&]()
    {
        if (lineHeight == 0)
        {
            lineHeight = LineHeightPx(parentStyle);
        }
        FlushLine(ctx, frags, nFrags, contentX, contentW, penX, y, align);
        y += lineHeight;
        penX = 0;
        nFrags = 0;
        lineHeight = 0;
    };

    for (u32 ri = 0; ri < nRuns; ++ri)
    {
        const InlineRun& run = runs[ri];
        const ComputedStyle& rs = *run.style;
        const bool pre = (rs.whiteSpace == WhiteSpace::Pre);
        const i32 rlh = LineHeightPx(rs);
        if (rlh > lineHeight)
        {
            lineHeight = rlh;
        }

        u32 i = 0;
        while (i < run.len)
        {
            if (pre)
            {
                // white-space:pre — emit up to a newline verbatim, no
                // wrapping; newline forces a line break.
                u32 segStart = i;
                while (i < run.len && run.text[i] != '\n')
                {
                    ++i;
                }
                const u32 segLen = i - segStart;
                if (segLen > 0 && nFrags < kMaxFragsPerLine)
                {
                    const i32 w = ctx.metrics.AdvanceFor(segLen, rs.fontSize);
                    frags[nFrags] = LineFrag{&run, segStart, segLen, penX, w};
                    ++nFrags;
                    penX += w;
                }
                if (i < run.len && run.text[i] == '\n')
                {
                    ++i; // consume newline
                    finishLine();
                    lineHeight = rlh;
                }
                continue;
            }

            // Normal white-space: skip runs of whitespace (collapse to a
            // single advance only when a word already sits on the line).
            if (IsWhitespaceByte(run.text[i]))
            {
                while (i < run.len && IsWhitespaceByte(run.text[i]))
                {
                    ++i;
                }
                if (nFrags > 0 && i < run.len)
                {
                    // A single inter-word space, if it fits; otherwise the
                    // next word's fit check will wrap.
                    const i32 spaceW = ctx.metrics.AdvanceFor(1, rs.fontSize);
                    if (penX + spaceW <= contentW)
                    {
                        penX += spaceW;
                    }
                }
                continue;
            }

            // Measure the next word [i, wordEnd).
            u32 wordEnd = i;
            while (wordEnd < run.len && !IsWhitespaceByte(run.text[wordEnd]))
            {
                ++wordEnd;
            }
            const u32 wordLen = wordEnd - i;
            const i32 wordW = ctx.metrics.AdvanceFor(wordLen, rs.fontSize);

            if (penX + wordW > contentW && penX > 0)
            {
                // Doesn't fit and the line isn't empty: wrap first.
                finishLine();
                lineHeight = rlh;
            }

            if (wordW <= contentW)
            {
                // Whole word fits on a (possibly fresh) line.
                if (nFrags < kMaxFragsPerLine)
                {
                    frags[nFrags] = LineFrag{&run, i, wordLen, penX, wordW};
                    ++nFrags;
                    penX += wordW;
                }
                i = wordEnd;
            }
            else
            {
                // Hard-break an over-long word across lines, chunk by
                // chunk, until it is consumed.
                const i32 cellW = ctx.metrics.AdvanceFor(1, rs.fontSize);
                const u32 perLine = (cellW > 0) ? static_cast<u32>(contentW / cellW) : wordLen;
                u32 chunkStart = i;
                while (chunkStart < wordEnd)
                {
                    u32 take = perLine;
                    if (take == 0)
                    {
                        take = 1; // always make progress
                    }
                    if (chunkStart + take > wordEnd)
                    {
                        take = wordEnd - chunkStart;
                    }
                    if (penX > 0)
                    {
                        finishLine();
                        lineHeight = rlh;
                    }
                    if (nFrags < kMaxFragsPerLine)
                    {
                        const i32 w = ctx.metrics.AdvanceFor(take, rs.fontSize);
                        frags[nFrags] = LineFrag{&run, chunkStart, take, penX, w};
                        ++nFrags;
                        penX += w;
                    }
                    chunkStart += take;
                    if (chunkStart < wordEnd)
                    {
                        finishLine();
                        lineHeight = rlh;
                    }
                }
                i = wordEnd;
            }
        }
    }

    if (nFrags > 0 || penX > 0)
    {
        finishLine();
    }

    return y;
}

} // namespace layout_detail
} // namespace duetos::web
