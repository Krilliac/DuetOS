/*
 * DuetOS — block formatting + the public LayoutDocument entry point.
 *
 * Walks a styled DOM and produces a flat, paint-order DisplayList. See
 * layout.h for the feature/GAP contract; inline formatting (line boxes,
 * word wrap) lives in layout_inline.cpp; the shared seam is
 * layout_internal.h. Every allocation comes from the caller's web::Arena
 * (reused via web/css_arena.h's ArenaNew/ArenaArray).
 *
 * Block formatting: block-level boxes stack vertically; the box width is
 * the containing-block width minus the box's own horizontal margin /
 * border / padding (honoring width:px/% / auto); the height is the
 * content height (sum of in-flow children) unless `height` is set; the
 * padding-box background paints first, then the border, then content.
 * A block whose children are all inline runs an inline formatting
 * context; a block child breaks the inline flow. display:none skips the
 * subtree. GAP: full anonymous-box generation, margin-collapsing,
 * floats, positioning — see layout.h.
 */

#include "web/layout.h"

#include "util/string.h"
#include "web/css_arena.h"
#include "web/layout_internal.h"

namespace duetos::web
{

using layout_detail::EdgePx;
using layout_detail::EmitTextRun;
using layout_detail::InlineRun;
using layout_detail::IsWhitespaceByte;
using layout_detail::kDefaultImgH;
using layout_detail::kDefaultImgW;
using layout_detail::LayoutCtx;
using layout_detail::LayoutInline;
using layout_detail::LineHeightPx;
using layout_detail::ResolveLength;
using layout_detail::StyleOf;

namespace layout_detail
{
namespace
{

// Does `node` contain any block-level (or img) element child? Decides
// between an inline and a block formatting context for its children.
bool HasBlockChild(const LayoutCtx& ctx, const Node* node)
{
    for (const Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind != NodeKind::Element)
        {
            continue;
        }
        const ComputedStyle* cs = StyleOf(ctx, c);
        if (cs == nullptr || cs->display == Display::None)
        {
            continue;
        }
        if (cs->display == Display::Block || cs->display == Display::InlineBlock)
        {
            return true;
        }
        if (c->tag != nullptr && duetos::core::StrEqual(c->tag, "img"))
        {
            return true;
        }
    }
    return false;
}

// Emit an <img> ImageBox sized by width/height style (default placeholder
// otherwise). Returns the box height consumed.
i32 LayoutImage(LayoutCtx& ctx, const Node* node, const ComputedStyle& s, i32 x, i32 cbWidth, i32 y)
{
    const i32 w = ResolveLength(s.width, cbWidth, kDefaultImgW);
    const i32 h = ResolveLength(s.height, 0, kDefaultImgH);
    DisplayItem it;
    it.cmd = DisplayCmd::ImageBox;
    it.rect.x = x;
    it.rect.y = y;
    it.rect.w = (w > 0) ? w : kDefaultImgW;
    it.rect.h = (h > 0) ? h : kDefaultImgH;
    const char* src = node->GetAttr("src");
    if (src != nullptr)
    {
        it.src = src;
        it.srcLen = static_cast<u32>(duetos::core::StrLen(src));
    }
    ctx.out->Push(it);
    return it.rect.h;
}

} // namespace

// Lay one block-level `node` out. The containing block content runs from
// [cbX, cbX+cbWidth); the box's top margin edge sits at `originY`.
// Returns the y just past this box's bottom margin edge.
i32 LayoutBlock(LayoutCtx& ctx, const Node* node, i32 cbX, i32 cbWidth, i32 originY)
{
    const ComputedStyle* sp = StyleOf(ctx, node);
    if (sp == nullptr)
    {
        return originY; // unstyled element — nothing to place
    }
    const ComputedStyle& s = *sp;
    if (s.display == Display::None)
    {
        return originY; // skip subtree entirely
    }

    // <img> as a block-level box.
    if (node->tag != nullptr && duetos::core::StrEqual(node->tag, "img"))
    {
        const i32 mTop = EdgePx(s.margin.top, cbWidth);
        const i32 mBot = EdgePx(s.margin.bottom, cbWidth);
        const i32 mLeft = EdgePx(s.margin.left, cbWidth);
        const i32 h = LayoutImage(ctx, node, s, cbX + mLeft, cbWidth, originY + mTop);
        return originY + mTop + h + mBot;
    }

    // Box metrics, resolved against the containing block width.
    const i32 mTop = EdgePx(s.margin.top, cbWidth);
    const i32 mRight = EdgePx(s.margin.right, cbWidth);
    const i32 mBot = EdgePx(s.margin.bottom, cbWidth);
    const i32 mLeft = EdgePx(s.margin.left, cbWidth);
    const i32 pTop = EdgePx(s.padding.top, cbWidth);
    const i32 pRight = EdgePx(s.padding.right, cbWidth);
    const i32 pBot = EdgePx(s.padding.bottom, cbWidth);
    const i32 pLeft = EdgePx(s.padding.left, cbWidth);
    const i32 bw = (s.border.style != BorderStyle::None) ? s.border.width : 0;

    // Resolved content width: explicit width:px/% wins, else fill the
    // containing block minus own horizontal box metrics ("auto").
    const i32 autoContentW = cbWidth - mLeft - mRight - 2 * bw - pLeft - pRight;
    i32 contentW = ResolveLength(s.width, cbWidth, autoContentW);
    if (contentW < 0)
    {
        contentW = 0;
    }

    // Border-box + content-box top-left.
    const i32 borderX = cbX + mLeft;
    const i32 borderY = originY + mTop;
    const i32 borderBoxW = contentW + 2 * bw + pLeft + pRight;
    const i32 contentX = borderX + bw + pLeft;
    const i32 contentTop = borderY + bw + pTop;

    // Reserve display-list slots for the background + border NOW, before
    // any child content is pushed, so paint order is correct (background
    // and border paint behind the box's content). Backfill their geometry
    // once the box height is known; kNoSlot means "this box has none".
    constexpr u32 kNoSlot = 0xFFFFFFFFu;
    u32 bgSlot = kNoSlot;
    u32 borderSlot = kNoSlot;
    if (s.backgroundColor.a != 0)
    {
        DisplayItem placeholder; // FillRect, geometry backfilled below
        placeholder.cmd = DisplayCmd::FillRect;
        placeholder.color = s.backgroundColor;
        if (ctx.out->Push(placeholder))
        {
            bgSlot = ctx.out->count - 1;
        }
    }
    if (bw > 0)
    {
        DisplayItem placeholder; // Border, geometry backfilled below
        placeholder.cmd = DisplayCmd::Border;
        placeholder.color = s.border.color;
        placeholder.borderWidth = bw;
        if (ctx.out->Push(placeholder))
        {
            borderSlot = ctx.out->count - 1;
        }
    }

    // Lay children to learn content height (unless height is fixed).
    i32 childY = contentTop;
    const bool inlineCtx = !HasBlockChild(ctx, node);
    if (inlineCtx)
    {
        childY = LayoutInline(ctx, node, s, contentX, contentW, contentTop);
    }
    else
    {
        for (const Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
        {
            if (c->kind == NodeKind::Element)
            {
                childY = LayoutBlock(ctx, c, contentX, contentW, childY);
            }
            else if (c->kind == NodeKind::Text && c->text != nullptr)
            {
                // A loose text node sitting between block siblings: emit it
                // as a single unwrapped line in the parent's style.
                // GAP: anonymous-block wrapping — a loose text node next to
                // block boxes is not wrapped to the content width; revisit
                // when documents that mix bare text with block children
                // (rare in practice) need it.
                bool nonWs = false;
                for (const char* p = c->text; *p != '\0'; ++p)
                {
                    if (!IsWhitespaceByte(*p))
                    {
                        nonWs = true;
                        break;
                    }
                }
                if (nonWs)
                {
                    InlineRun one{c->text, static_cast<u32>(duetos::core::StrLen(c->text)), &s};
                    EmitTextRun(ctx, one, 0, one.len, contentX, childY);
                    childY += LineHeightPx(s);
                }
            }
        }
    }

    const i32 contentHeight = childY - contentTop;

    // Resolved content height: explicit height wins, else measured.
    i32 finalContentH = ResolveLength(s.height, 0, contentHeight);
    if (finalContentH < 0)
    {
        finalContentH = 0;
    }

    // The padding box wraps content + padding (background paints here);
    // the border box wraps the padding box + the border stroke.
    const i32 paddingBoxX = borderX + bw;
    const i32 paddingBoxY = borderY + bw;
    const i32 paddingBoxW = contentW + pLeft + pRight;
    const i32 paddingBoxH = finalContentH + pTop + pBot;
    const i32 borderBoxH = paddingBoxH + 2 * bw;

    // Backfill the reserved slots now that geometry is known.
    if (bgSlot != kNoSlot)
    {
        ctx.out->items[bgSlot].rect = Rect{paddingBoxX, paddingBoxY, paddingBoxW, paddingBoxH};
    }
    if (borderSlot != kNoSlot)
    {
        ctx.out->items[borderSlot].rect = Rect{borderX, borderY, borderBoxW, borderBoxH};
    }

    // Advance past this box's bottom margin edge.
    return borderY + borderBoxH + mBot;
}

} // namespace layout_detail

DisplayList* LayoutDocument(const Node* doc, const StyleMap& styles, u32 viewportW, const TextMetrics& metrics,
                            Arena& arena)
{
    DisplayList* list = ArenaNew<DisplayList>(arena);
    if (list == nullptr)
    {
        return nullptr;
    }
    // Display-list capacity: bounded by the styled node count (a couple
    // of commands per element plus inline runs). Use a generous multiple.
    constexpr u32 kCmdsPerNode = 6;
    u32 cap = (styles.count + 1) * kCmdsPerNode;
    if (cap < 64)
    {
        cap = 64;
    }
    list->items = ArenaArray<DisplayItem>(arena, cap);
    list->count = 0;
    list->cap = (list->items != nullptr) ? cap : 0;

    if (doc == nullptr)
    {
        return list;
    }

    layout_detail::LayoutCtx ctx{styles, metrics, list, arena};

    // The Document root has no box; lay its element children out as block
    // boxes filling the viewport, stacked vertically from y=0.
    i32 y = 0;
    for (const Node* c = doc->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element)
        {
            y = layout_detail::LayoutBlock(ctx, c, 0, static_cast<i32>(viewportW), y);
        }
    }
    return list;
}

} // namespace duetos::web
