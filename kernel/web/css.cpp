/*
 * DuetOS — CSS cascade engine. See css.h.
 *
 * Given a parsed StyleSheet (css_parse.cpp) and a DOM (dom.h/html.h),
 * this computes one ComputedStyle per element:
 *   1. start from the parent's inherited values (or the root initials);
 *   2. apply every matching rule in cascade order (UA < author, then
 *      specificity, then source order);
 *   3. fold in the element's inline `style="..."` (highest priority);
 *   4. recurse into children with this element's style as their parent.
 *
 * No layout, no paint — the StyleMap this returns is what the next
 * swarm's layout consumes. The per-property `value -> ComputedStyle`
 * application lives in css_apply.cpp; this file owns selector matching,
 * inheritance, the cascade priority sort, and the tree walk.
 *
 * Matching honors type, .class, #id, universal, the descendant (space),
 * child (>), adjacent-sibling (+) and general-sibling (~) combinators,
 * the structural pseudo-classes :first-child / :last-child / :only-child,
 * the same -of-type family (:first-of-type / :last-of-type / :only-of-type),
 * :nth-child / :nth-last-child / :nth-of-type / :nth-last-of-type
 * (each taking N|even|odd|an+b), :not(simple), and attribute selectors
 * ([attr], [attr="v"], [attr~=], [attr^=], [attr$=], [attr*=]).
 *
 * GAP: :not() with a compound/complex argument, the column combinator (||),
 * and dynamic pseudo-classes (:hover, …) are not matched. !important is
 * parsed but not given its own cascade tier (best-effort). em/rem/vh resolve
 * as px.
 */

#include "web/css.h"

#include "util/string.h"
#include "web/css_arena.h"
#include "web/css_internal.h"

namespace duetos::web
{

using duetos::u64;

namespace
{

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    return duetos::core::StrEqual(a, b);
}

bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

// Does the element's space-separated `class` attribute contain `cls`?
bool HasClass(const Node* el, const char* cls)
{
    if (cls == nullptr)
    {
        return false;
    }
    const char* classes = el->GetAttr("class");
    if (classes == nullptr)
    {
        return false;
    }
    u32 clen = static_cast<u32>(duetos::core::StrLen(cls));
    const char* p = classes;
    while (*p != '\0')
    {
        while (*p != '\0' && IsSpace(*p))
        {
            ++p;
        }
        const char* tokB = p;
        while (*p != '\0' && !IsSpace(*p))
        {
            ++p;
        }
        u32 tlen = static_cast<u32>(p - tokB);
        if (tlen == clen)
        {
            bool eq = true;
            for (u32 i = 0; i < tlen; ++i)
            {
                // class names are case-sensitive in HTML; cls is already
                // lowercased by the selector parser, attribute is raw.
                char ac = tokB[i];
                if (ac >= 'A' && ac <= 'Z')
                {
                    ac = static_cast<char>(ac - 'A' + 'a');
                }
                if (ac != cls[i])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
            {
                return true;
            }
        }
    }
    return false;
}

// Do two tag names denote the same element type? Tag names are stored
// lowercased on both the DOM node and (when parsed) the selector, so a
// plain byte compare suffices — but we go through StrEqual for safety and
// to mirror the comparison used in MatchesCompound.
bool TagEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return a == b;
    }
    return duetos::core::StrEqual(a, b);
}

// 1-based index of `el` among its parent's element children, plus the
// total count over that same set. When `ofType` is set the set is
// restricted to siblings sharing `el`'s tag name; otherwise it is all
// element siblings. When `fromEnd` is set the returned position is counted
// from the last sibling (so the last element is position 1). For a root
// element (no parent) the element is an only child at position 1.
void SiblingPosition(const Node* el, bool ofType, bool fromEnd, u32& posOut, u32& totalOut)
{
    posOut = 0;
    totalOut = 0;
    const Node* parent = el->parent;
    if (parent == nullptr)
    {
        posOut = 1;
        totalOut = 1;
        return;
    }
    u32 idx = 0;
    u32 forwardPos = 0;
    for (const Node* c = parent->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind != NodeKind::Element)
        {
            continue;
        }
        if (ofType && !TagEq(c->tag, el->tag))
        {
            continue;
        }
        ++idx;
        if (c == el)
        {
            forwardPos = idx;
        }
    }
    totalOut = idx;
    // From-end position: the last sibling in the set is position 1.
    posOut = fromEnd ? (totalOut - forwardPos + 1) : forwardPos;
}

// Does the An+B formula (a, b) select 1-based position `pos`? Matches iff
// there is an integer k >= 0 with pos == a*k + b. Shared by every nth-*
// variant (child / of-type / last-child / last-of-type).
bool NthMatches(i32 a, i32 b, u32 pos)
{
    const i32 p = static_cast<i32>(pos);
    if (a == 0)
    {
        return p == b; // "0n+b" == ":nth-*(b)"
    }
    // p = a*k + b  =>  (p - b) must be a multiple of a with k >= 0.
    const i32 diff = p - b;
    if (a > 0)
    {
        return diff >= 0 && (diff % a) == 0;
    }
    // a < 0: k = diff/a must still be >= 0, i.e. diff and a share sign
    // (diff <= 0) and a divides diff evenly.
    return diff <= 0 && (diff % a) == 0;
}

// Evaluate the structural pseudo-class (if any) on `el`. The `ofType` and
// `fromEnd` flags on `sel` select which sibling set the position is
// computed over and from which end (see StructuralPseudo in css.h).
bool MatchesPseudo(const SimpleSelector* sel, const Node* el)
{
    if (sel->pseudo == StructuralPseudo::None)
    {
        return true;
    }
    u32 pos = 0, total = 0;
    SiblingPosition(el, sel->ofType, sel->fromEnd, pos, total);
    switch (sel->pseudo)
    {
    case StructuralPseudo::FirstChild:
        // :first-child / :first-of-type. With fromEnd this is :last-* (the
        // parser uses LastChild for those, but honour the flag regardless).
        return pos == 1;
    case StructuralPseudo::LastChild:
        // :last-child / :last-of-type. `pos` already accounts for fromEnd;
        // the last element of the set is whichever has pos == total.
        return pos == total;
    case StructuralPseudo::OnlyChild:
        // :only-child / :only-of-type — sole member of its sibling set.
        return total == 1;
    case StructuralPseudo::NthChildLit:
        return sel->nthChild > 0 && pos == static_cast<u32>(sel->nthChild);
    case StructuralPseudo::NthChildEven:
        return (pos % 2) == 0;
    case StructuralPseudo::NthChildOdd:
        return (pos % 2) == 1;
    case StructuralPseudo::NthChildFormula:
        return NthMatches(sel->nthA, sel->nthB, pos);
    default:
        return true;
    }
}

// Is `c` a separator inside a whitespace-list attribute value?
bool IsWsSep(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

// [attr~="v"]: does the space-separated attribute value contain the
// exact word `needle`? An empty needle never matches (per spec).
bool AttrHasWord(const char* haystack, const char* needle)
{
    if (haystack == nullptr || needle == nullptr || needle[0] == '\0')
    {
        return false;
    }
    u32 nlen = static_cast<u32>(duetos::core::StrLen(needle));
    const char* p = haystack;
    while (*p != '\0')
    {
        while (*p != '\0' && IsWsSep(*p))
        {
            ++p;
        }
        const char* tokB = p;
        while (*p != '\0' && !IsWsSep(*p))
        {
            ++p;
        }
        u32 tlen = static_cast<u32>(p - tokB);
        if (tlen == nlen)
        {
            bool eq = true;
            for (u32 i = 0; i < tlen; ++i)
            {
                if (tokB[i] != needle[i])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
            {
                return true;
            }
        }
    }
    return false;
}

// Prefix / suffix / substring tests (case-sensitive, matching the
// authored value verbatim). Empty value never matches for ^=/$=/*=.
bool StrHasPrefix(const char* s, const char* pre)
{
    if (pre[0] == '\0')
    {
        return false;
    }
    for (u32 i = 0; pre[i] != '\0'; ++i)
    {
        if (s[i] != pre[i])
        {
            return false;
        }
    }
    return true;
}

bool StrHasSuffix(const char* s, const char* suf)
{
    u32 slen = static_cast<u32>(duetos::core::StrLen(s));
    u32 flen = static_cast<u32>(duetos::core::StrLen(suf));
    if (flen == 0 || flen > slen)
    {
        return false;
    }
    const char* start = s + (slen - flen);
    for (u32 i = 0; i < flen; ++i)
    {
        if (start[i] != suf[i])
        {
            return false;
        }
    }
    return true;
}

bool StrHasSubstr(const char* s, const char* sub)
{
    if (sub[0] == '\0')
    {
        return false;
    }
    for (const char* p = s; *p != '\0'; ++p)
    {
        u32 i = 0;
        for (; sub[i] != '\0'; ++i)
        {
            if (p[i] != sub[i])
            {
                break;
            }
        }
        if (sub[i] == '\0')
        {
            return true;
        }
    }
    return false;
}

// Evaluate all attribute-selector clauses on `el`.
bool MatchesAttrs(const SimpleSelector* sel, const Node* el)
{
    for (const AttrSelector* a = sel->attrs; a != nullptr; a = a->next)
    {
        const char* v = el->GetAttr(a->name);
        if (v == nullptr)
        {
            return false; // attribute absent — every op requires presence
        }
        switch (a->op)
        {
        case AttrOp::Exists:
            break; // presence already satisfied
        case AttrOp::Exact:
            if (!StrEq(v, a->value))
            {
                return false;
            }
            break;
        case AttrOp::Whitespace:
            if (!AttrHasWord(v, a->value))
            {
                return false;
            }
            break;
        case AttrOp::Prefix:
            if (!StrHasPrefix(v, a->value))
            {
                return false;
            }
            break;
        case AttrOp::Suffix:
            if (!StrHasSuffix(v, a->value))
            {
                return false;
            }
            break;
        case AttrOp::Substring:
            if (!StrHasSubstr(v, a->value))
            {
                return false;
            }
            break;
        }
    }
    return true;
}

// Does one compound selector match this element (ignoring ancestry)?
bool MatchesCompound(const SimpleSelector* sel, const Node* el)
{
    if (sel->tag != nullptr && !StrEq(sel->tag, el->tag))
    {
        return false;
    }
    if (sel->id != nullptr)
    {
        const char* elId = el->GetAttr("id");
        // ids are case-sensitive; sel->id was lowercased — compare ci.
        if (elId == nullptr)
        {
            return false;
        }
        u32 i = 0;
        for (; sel->id[i] != '\0' && elId[i] != '\0'; ++i)
        {
            char a = elId[i];
            if (a >= 'A' && a <= 'Z')
            {
                a = static_cast<char>(a - 'A' + 'a');
            }
            if (a != sel->id[i])
            {
                return false;
            }
        }
        if (sel->id[i] != '\0' || elId[i] != '\0')
        {
            return false;
        }
    }
    if (sel->className != nullptr && !HasClass(el, sel->className))
    {
        return false;
    }
    if (sel->attrs != nullptr && !MatchesAttrs(sel, el))
    {
        return false;
    }
    if (!MatchesPseudo(sel, el))
    {
        return false;
    }
    // :not(simple) — the element must NOT match any negated simple
    // selector. Each negation is a one-component compound (its own
    // `negations` list is empty, so this does not recurse).
    for (const SimpleSelector* neg = sel->negations; neg != nullptr; neg = neg->notNext)
    {
        if (MatchesCompound(neg, el))
        {
            return false;
        }
    }
    return true;
}

// The immediately-preceding *element* sibling of `el`, or nullptr. The
// DOM has only firstChild/nextSibling, so we walk the parent's child list
// and remember the last element seen before reaching `el`.
const Node* PreviousElementSibling(const Node* el)
{
    const Node* parent = el->parent;
    if (parent == nullptr)
    {
        return nullptr;
    }
    const Node* prevEl = nullptr;
    for (const Node* c = parent->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c == el)
        {
            return prevEl;
        }
        if (c->kind == NodeKind::Element)
        {
            prevEl = c;
        }
    }
    return nullptr; // el not found under its parent (shouldn't happen)
}

// The direct parent element of `el`, or nullptr if its parent is not an
// element (e.g. the Document root).
const Node* ParentElement(const Node* el)
{
    const Node* p = el->parent;
    if (p != nullptr && p->kind == NodeKind::Element)
    {
        return p;
    }
    return nullptr;
}

// Full selector match across the combinator chain: the rightmost compound
// (`sel`) must match `el`, and each compound to its left must match the
// node reachable from the current node via that left compound's
// combinator. The combinator lives on the *child* (right) compound and
// describes its relationship to its `ancestor` (left) compound.
//
// GAP: the descendant and general-sibling steps match the FIRST candidate
// greedily without backtracking. A pathological selector whose earlier
// (righter) descendant/sibling choice forecloses a valid leftward match
// (e.g. "a b a c" shapes) can therefore miss. Child and adjacent steps are
// deterministic (single candidate) and exact. The common cases all resolve
// correctly; full backtracking is deferred.
bool Matches(const SimpleSelector* sel, const Node* el)
{
    if (!MatchesCompound(sel, el))
    {
        return false;
    }

    // `right` is the compound we just matched against `cur`; we now walk
    // to its `ancestor` (left) compound using `right->combinator`.
    const SimpleSelector* right = sel;
    const Node* cur = el;
    while (right->ancestor != nullptr)
    {
        const SimpleSelector* left = right->ancestor;
        switch (right->combinator)
        {
        case Combinator::Child:
        {
            const Node* parent = ParentElement(cur);
            if (parent == nullptr || !MatchesCompound(left, parent))
            {
                return false;
            }
            cur = parent;
            break;
        }
        case Combinator::Adjacent:
        {
            const Node* prev = PreviousElementSibling(cur);
            if (prev == nullptr || !MatchesCompound(left, prev))
            {
                return false;
            }
            cur = prev;
            break;
        }
        case Combinator::General:
        {
            // Any preceding element sibling matching `left` satisfies it;
            // matching continues from that sibling.
            bool found = false;
            for (const Node* prev = PreviousElementSibling(cur); prev != nullptr; prev = PreviousElementSibling(prev))
            {
                if (MatchesCompound(left, prev))
                {
                    cur = prev;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
            break;
        }
        case Combinator::Descendant:
        default:
        {
            // Some ancestor must match `left`; matching continues from it.
            bool found = false;
            for (const Node* anc = ParentElement(cur); anc != nullptr; anc = ParentElement(anc))
            {
                if (MatchesCompound(left, anc))
                {
                    cur = anc;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
            break;
        }
        }
        right = left;
    }
    return true;
}

// Seed a child's style from its parent's: copy ONLY the inherited
// properties; reset everything else to initial values.
ComputedStyle InheritFrom(const ComputedStyle& parent)
{
    ComputedStyle cs{}; // initial values (struct defaults)
    cs.color = parent.color;
    cs.fontSize = parent.fontSize;
    cs.fontWeight = parent.fontWeight;
    cs.fontStyle = parent.fontStyle;
    cs.textAlign = parent.textAlign;
    cs.lineHeight = parent.lineHeight;
    cs.whiteSpace = parent.whiteSpace;
    cs.listStyleNone = parent.listStyleNone;
    return cs;
}

// --- cascade: pick + apply all matching rules in priority order -----
// We do an insertion-sort-free approach: for each rule we compute a
// 64-bit sort key (origin<<48 | specificity<<16 | order) and apply rules
// in ascending key order so later (higher-priority) wins. With a small
// matched set we just scan repeatedly for the next-lowest key.
struct MatchEntry
{
    const Rule* rule;
    u64 key;
};

void CascadeInto(ComputedStyle& cs, const StyleSheet& sheet, const Node* el, MatchEntry* scratch, u32 scratchCap)
{
    u32 nMatched = 0;
    for (const Rule* r = sheet.rules; r != nullptr; r = r->next)
    {
        if (!Matches(r->selector, el))
        {
            continue;
        }
        if (nMatched >= scratchCap)
        {
            break; // pathological selector count; apply what we have
        }
        u64 origin = r->userAgent ? 0u : 1u; // author beats UA
        u64 key = (origin << 48) | (static_cast<u64>(r->specificity) << 16) | r->order;
        scratch[nMatched].rule = r;
        scratch[nMatched].key = key;
        ++nMatched;
    }

    // Apply in ascending key order (low priority first, high last).
    for (u32 applied = 0; applied < nMatched; ++applied)
    {
        u32 minIdx = u32(-1);
        u64 minKey = ~0ull;
        for (u32 i = 0; i < nMatched; ++i)
        {
            if (scratch[i].rule != nullptr && scratch[i].key <= minKey)
            {
                // <= keeps source order stable for equal keys (impossible
                // here since order is unique, but harmless).
                minKey = scratch[i].key;
                minIdx = i;
            }
        }
        if (minIdx == u32(-1))
        {
            break;
        }
        ApplyDeclList(cs, scratch[minIdx].rule->decls);
        scratch[minIdx].rule = nullptr; // consumed
    }
}

// Recursive walk; styles[*idx] is filled and *idx advanced for each
// element. `parentStyle` carries the computed style to inherit from.
void StyleSubtree(const Node* node, const ComputedStyle& parentStyle, const StyleSheet& sheet, StyleMap& map,
                  Arena& arena, MatchEntry* scratch, u32 scratchCap)
{
    for (const Node* child = node->firstChild; child != nullptr; child = child->nextSibling)
    {
        if (child->kind != NodeKind::Element)
        {
            continue;
        }
        if (map.count >= map.cap)
        {
            return; // map full — stop styling (graceful)
        }

        ComputedStyle cs = InheritFrom(parentStyle);
        CascadeInto(cs, sheet, child, scratch, scratchCap);

        // Inline style="..." has the final word.
        const char* inlineStyle = child->GetAttr("style");
        if (inlineStyle != nullptr)
        {
            Declaration* inl =
                ParseInlineStyle(inlineStyle, static_cast<u32>(duetos::core::StrLen(inlineStyle)), arena);
            ApplyDeclList(cs, inl);
        }

        u32 slot = map.count;
        map.keys[slot] = child;
        map.styles[slot] = cs;
        ++map.count;

        StyleSubtree(child, cs, sheet, map, arena, scratch, scratchCap);
    }
}

// Count elements in the subtree so we can size the StyleMap arrays.
u32 CountElements(const Node* node)
{
    u32 n = 0;
    for (const Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element)
        {
            ++n;
            n += CountElements(c);
        }
    }
    return n;
}

} // namespace

const ComputedStyle* StyleMap::Get(const Node* n) const
{
    for (u32 i = 0; i < count; ++i)
    {
        if (keys[i] == n)
        {
            return &styles[i];
        }
    }
    return nullptr;
}

StyleMap ComputeStyles(const Node* doc, const StyleSheet& sheet, Arena& arena)
{
    StyleMap map{};
    if (doc == nullptr)
    {
        return map;
    }

    u32 nEls = CountElements(doc);
    if (nEls == 0)
    {
        return map;
    }
    map.keys = ArenaArray<const Node*>(arena, nEls);
    map.styles = ArenaArray<ComputedStyle>(arena, nEls);
    if (map.keys == nullptr || map.styles == nullptr)
    {
        map.keys = nullptr;
        map.styles = nullptr;
        return map; // arena exhausted
    }
    map.cap = nEls;
    map.count = 0;

    // Per-element matched-rule scratch (bounded). 64 simultaneous
    // matches is comfortably more than any sane element accumulates.
    static constexpr u32 kScratchCap = 64;
    MatchEntry* scratch = ArenaArray<MatchEntry>(arena, kScratchCap);
    if (scratch == nullptr)
    {
        map.cap = 0;
        return map;
    }

    // The document root's "parent style" is the initial-value style. The
    // html/body UA rules will set the real document defaults as they
    // match.
    ComputedStyle rootInitial{};
    StyleSubtree(doc, rootInitial, sheet, map, arena, scratch, kScratchCap);
    return map;
}

} // namespace duetos::web
