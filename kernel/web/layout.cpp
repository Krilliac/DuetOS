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
 * context; a block child breaks the inline flow, and each consecutive run
 * of inline-level siblings adjacent to block siblings is wrapped in an
 * anonymous block box (CSS box generation). An inline element that
 * contains a block-level descendant is itself split around that block
 * (block-in-inline): the inline content before/after each becomes an
 * anonymous block and the block is pulled out, all stacking vertically.
 * display:none skips the subtree. GAP: inline-box DECORATION splitting
 * (split fragments don't re-draw the inline element's border/padding),
 * margin-collapsing, floats, positioning — see layout.h.
 */

#include "web/layout.h"

#include "util/string.h"
#include "web/css_arena.h"
#include "web/layout_internal.h"

namespace duetos::web
{

using layout_detail::EdgePx;
using layout_detail::IsWhitespaceByte;
using layout_detail::kDefaultImgH;
using layout_detail::kDefaultImgW;
using layout_detail::LayoutCtx;
using layout_detail::LayoutInline;
using layout_detail::LayoutInlineSiblings;
using layout_detail::ResolveLength;
using layout_detail::StyleOf;

namespace layout_detail
{
namespace
{

// Is child `c` a block-level box that breaks its parent's inline flow?
// Block / inline-block displays and a bare <img> count as block-level for
// box generation; text nodes and inline elements do not. display:none and
// unstyled elements are neither (they contribute no box). Returns false for
// non-element nodes (text/comment) — those are inline-level content.
bool IsBlockLevelChild(const LayoutCtx& ctx, const Node* c)
{
    if (c->kind != NodeKind::Element)
    {
        return false;
    }
    const ComputedStyle* cs = StyleOf(ctx, c);
    if (cs == nullptr || cs->display == Display::None)
    {
        return false;
    }
    if (cs->display == Display::Block || cs->display == Display::InlineBlock)
    {
        return true;
    }
    return c->tag != nullptr && duetos::core::StrEqual(c->tag, "img");
}

// Does inline-level element `node`'s subtree TRANSITIVELY contain a
// block-level box? Per CSS box generation, a block box nested inside an
// inline box forces the inline box to be split around the block (the
// "block-in-inline" case). This predicate lets the parent's
// formatting-context decision treat such an inline child as
// block-breaking even though the child itself is inline-level. Skips
// display:none subtrees (they generate no box). Bounded by the DOM depth
// the arena already caps (Arena::kMaxNodes), so plain recursion is safe.
bool ContainsBlockDescendant(const LayoutCtx& ctx, const Node* node)
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
        if (IsBlockLevelChild(ctx, c))
        {
            return true;
        }
        // Recurse only through inline-level element children.
        if (ContainsBlockDescendant(ctx, c))
        {
            return true;
        }
    }
    return false;
}

// Is direct child `c` a child that breaks its parent's inline flow? This
// is true for a block-level box (IsBlockLevelChild) AND for an
// inline-level element that transitively contains a block descendant
// (the block-in-inline split case — that inline element must be pulled
// apart into stacked block-level pieces). Text/inline content without a
// block descendant does not break the flow.
bool BreaksInlineFlow(const LayoutCtx& ctx, const Node* c)
{
    if (IsBlockLevelChild(ctx, c))
    {
        return true;
    }
    if (c->kind != NodeKind::Element)
    {
        return false;
    }
    const ComputedStyle* cs = StyleOf(ctx, c);
    if (cs == nullptr || cs->display == Display::None)
    {
        return false;
    }
    return ContainsBlockDescendant(ctx, c);
}

// Does `node` contain any direct child that breaks its inline flow?
// Decides between an inline and a block formatting context for its
// children. A block-level child OR an inline child carrying a block
// descendant (block-in-inline) both force the block path.
bool HasBlockChild(const LayoutCtx& ctx, const Node* node)
{
    for (const Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (BreaksInlineFlow(ctx, c))
        {
            return true;
        }
    }
    return false;
}

// Does the half-open sibling range [first, stopBefore) hold any inline-
// level content worth wrapping in an anonymous block? An all-whitespace
// text run between two block siblings generates no anonymous box (per CSS
// box generation, white space adjacent to block-level boxes that would
// otherwise be collapsed away produces no box). Empty/whitespace-only runs
// are skipped so we don't stack zero-height anonymous boxes.
bool HasRenderableInline(const LayoutCtx& ctx, const Node* first, const Node* stopBefore)
{
    for (const Node* c = first; c != nullptr && c != stopBefore; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Text)
        {
            if (c->text == nullptr)
            {
                continue;
            }
            for (const char* p = c->text; *p != '\0'; ++p)
            {
                if (!IsWhitespaceByte(*p))
                {
                    return true;
                }
            }
            continue;
        }
        if (c->kind == NodeKind::Element)
        {
            const ComputedStyle* cs = StyleOf(ctx, c);
            if (cs != nullptr && cs->display != Display::None)
            {
                return true; // an inline element generates a box
            }
        }
    }
    return false;
}

// Emit an <img> ImageBox sized by width/height style (default placeholder
// otherwise). Returns the box height consumed. `linkHref` (when non-null)
// tags the box so an <a href><img></a> is hit-testable as a link.
i32 LayoutImage(LayoutCtx& ctx, const Node* node, const ComputedStyle& s, i32 x, i32 cbWidth, i32 y,
                const char* linkHref)
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
    if (linkHref != nullptr)
    {
        it.href = linkHref;
        it.hrefLen = static_cast<u32>(duetos::core::StrLen(linkHref));
    }
    ctx.out->Push(it);
    return it.rect.h;
}

} // namespace

// Forward declaration: split an inline element that contains a block
// descendant into stacked block-level pieces. Mutually recursive with
// LayoutBlock (the contained block is laid out via LayoutBlock, which may
// in turn re-enter the mixed-children walk). Defined below LayoutBlock.
i32 LayoutBlockInInline(LayoutCtx& ctx, const Node* inlineEl, const ComputedStyle& cbStyle, i32 cbX, i32 cbWidth,
                        i32 originY, const char* linkHref);

// Lay one block-level `node` out. The containing block content runs from
// [cbX, cbX+cbWidth); the box's top margin edge sits at `originY`.
// Returns the y just past this box's bottom margin edge.
i32 LayoutBlock(LayoutCtx& ctx, const Node* node, i32 cbX, i32 cbWidth, i32 originY, const char* linkHref)
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

    // An <a href> at block level becomes the active link for this box and
    // everything it contains; non-anchor blocks keep the inherited link so
    // a block wrapped by an ancestor anchor stays a link surface.
    const char* selfHref = AnchorHref(node);
    if (selfHref == nullptr)
    {
        selfHref = linkHref;
    }

    // <img> as a block-level box.
    if (node->tag != nullptr && duetos::core::StrEqual(node->tag, "img"))
    {
        const i32 mTop = EdgePx(s.margin.top, cbWidth);
        const i32 mBot = EdgePx(s.margin.bottom, cbWidth);
        const i32 mLeft = EdgePx(s.margin.left, cbWidth);
        const i32 h = LayoutImage(ctx, node, s, cbX + mLeft, cbWidth, originY + mTop, selfHref);
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
    // A styled <a href> block (background / border) is a clickable surface
    // too, so tag its bg/border items with the link — that way a link with
    // no text run (e.g. an image-only or padding-only anchor) is still
    // hit-testable from its painted box.
    const u32 selfHrefLen = (selfHref != nullptr) ? static_cast<u32>(duetos::core::StrLen(selfHref)) : 0;
    if (s.backgroundColor.a != 0)
    {
        DisplayItem placeholder; // FillRect, geometry backfilled below
        placeholder.cmd = DisplayCmd::FillRect;
        placeholder.color = s.backgroundColor;
        placeholder.href = selfHref;
        placeholder.hrefLen = selfHrefLen;
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
        placeholder.href = selfHref;
        placeholder.hrefLen = selfHrefLen;
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
        childY = LayoutInline(ctx, node, s, contentX, contentW, contentTop, selfHref);
    }
    else
    {
        // Mixed block + inline children: per CSS box generation, each
        // consecutive run of inline-level siblings (text + inline elements)
        // adjacent to block siblings is wrapped in an ANONYMOUS BLOCK box
        // that establishes its own inline formatting context, and those
        // anonymous blocks stack vertically alongside the real block boxes.
        // Walk the child list, flushing a pending inline run into an
        // anonymous block whenever a block-level child interrupts it (and
        // once more at the end).
        const Node* inlineStart = nullptr; // first sibling of the pending inline run
        for (const Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
        {
            if (BreaksInlineFlow(ctx, c))
            {
                // Flush any inline run that preceded this block-breaking
                // child into an anonymous block laid out as a normal block
                // box.
                if (inlineStart != nullptr && HasRenderableInline(ctx, inlineStart, c))
                {
                    childY = LayoutInlineSiblings(ctx, s, inlineStart, c, contentX, contentW, childY, selfHref);
                }
                inlineStart = nullptr;
                if (IsBlockLevelChild(ctx, c))
                {
                    // A genuine block-level child: lay it out directly.
                    childY = LayoutBlock(ctx, c, contentX, contentW, childY, selfHref);
                }
                else
                {
                    // An inline element carrying a block descendant: split
                    // the inline box around the block (block-in-inline).
                    childY = LayoutBlockInInline(ctx, c, s, contentX, contentW, childY, selfHref);
                }
            }
            else
            {
                // Inline-level (text node or inline element with no block
                // descendant): start a new pending run if none is open;
                // otherwise extend it.
                if (inlineStart == nullptr)
                {
                    inlineStart = c;
                }
            }
        }
        // A trailing inline run after the last block child.
        if (inlineStart != nullptr && HasRenderableInline(ctx, inlineStart, nullptr))
        {
            childY = LayoutInlineSiblings(ctx, s, inlineStart, nullptr, contentX, contentW, childY, selfHref);
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

// Split an inline element that contains a block-level descendant into
// vertically-stacked block-level pieces (CSS box generation's
// "block-in-inline"): the inline content before the block forms an
// anonymous block, the block child is pulled out as its own block box,
// and the inline content after forms another anonymous block. The three
// stack in the containing block formatting context. `inlineEl` is the
// inline element being split (e.g. a <span>); `cbStyle` is the
// containing block's style (drives the anonymous blocks' inline
// formatting context — text-align, line-height); the runs themselves
// carry `inlineEl`'s own computed style so the span's color/font/weight
// is preserved. Returns the y just past the last piece.
//
// GAP: the split does NOT re-create `inlineEl`'s own borders/padding/
// background on the before/after fragments (CSS would draw the inline
// box's left/right border on the first/last fragment) — only the text
// content is stacked. Revisit when inline-box decoration splitting is
// needed.
i32 LayoutBlockInInline(LayoutCtx& ctx, const Node* inlineEl, const ComputedStyle& cbStyle, i32 cbX, i32 cbWidth,
                        i32 originY, const char* linkHref)
{
    const ComputedStyle* sp = StyleOf(ctx, inlineEl);
    // The inline element's own style drives its text runs; fall back to
    // the containing block's style if (defensively) it has none.
    const ComputedStyle& runStyle = (sp != nullptr) ? *sp : cbStyle;

    // An <a href> inline element makes its content a link surface;
    // otherwise inherit the threaded link.
    const char* selfHref = AnchorHref(inlineEl);
    if (selfHref == nullptr)
    {
        selfHref = linkHref;
    }

    i32 y = originY;
    const Node* inlineStart = nullptr; // first pending inline-run child
    for (const Node* c = inlineEl->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (BreaksInlineFlow(ctx, c))
        {
            // Flush the inline run that preceded this block-breaking child
            // into an anonymous block carrying the split inline element's
            // style.
            if (inlineStart != nullptr && HasRenderableInline(ctx, inlineStart, c))
            {
                y = LayoutInlineSiblings(ctx, runStyle, inlineStart, c, cbX, cbWidth, y, selfHref);
            }
            inlineStart = nullptr;
            if (IsBlockLevelChild(ctx, c))
            {
                y = LayoutBlock(ctx, c, cbX, cbWidth, y, selfHref);
            }
            else
            {
                // A nested inline element that itself carries a block
                // descendant: recurse to split it too.
                y = LayoutBlockInInline(ctx, c, cbStyle, cbX, cbWidth, y, selfHref);
            }
        }
        else
        {
            if (inlineStart == nullptr)
            {
                inlineStart = c;
            }
        }
    }
    // Trailing inline run after the last block-breaking child.
    if (inlineStart != nullptr && HasRenderableInline(ctx, inlineStart, nullptr))
    {
        y = LayoutInlineSiblings(ctx, runStyle, inlineStart, nullptr, cbX, cbWidth, y, selfHref);
    }
    return y;
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
            y = layout_detail::LayoutBlock(ctx, c, 0, static_cast<i32>(viewportW), y, /*linkHref=*/nullptr);
        }
    }
    return list;
}

} // namespace duetos::web
