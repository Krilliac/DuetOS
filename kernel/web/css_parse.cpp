/*
 * DuetOS — CSS tokenizer + parser. See css.h.
 *
 * Turns stylesheet text (rule = selector-list '{' declaration* '}')
 * and inline `style="..."` blocks into the Rule / Declaration /
 * SimpleSelector representation declared in css.h. Everything is
 * carved from the caller's web::Arena (via css_arena.h); exhaustion
 * stops the parse gracefully (a truncated rule list) rather than
 * faulting.
 *
 * Robustness: unknown @-rules (@media/@import/@font-face/@charset/…)
 * are skipped — the no-block forms up to ';', the block forms by
 * balanced-brace skipping. Malformed declarations are dropped. The
 * parser never reads past `end`.
 *
 * Recognised selectors: type, .class, #id, universal, the descendant
 * combinator (space), the structural pseudo-classes :first-child /
 * :last-child / :nth-child(N|even|odd), and attribute selectors
 * [attr], [attr="v"], [attr~="v"], [attr^="v"], [attr$="v"], [attr*="v"].
 *
 * GAP: :nth-child(an+b) formula form and other pseudo-classes/elements
 * (:hover, ::before, :not, :nth-of-type, …), child/sibling combinators
 * (>, +, ~). !important is detected best-effort.
 */

#include "web/css.h"

#include "util/string.h"
#include "web/css_arena.h"

namespace duetos::web
{

namespace
{

bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

char Lower(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

// Copy [b,e) into the arena, lowercased + NUL-terminated. nullptr on OOM
// / empty.
const char* CopyLower(const char* b, const char* e, Arena& arena)
{
    if (e <= b)
    {
        return nullptr;
    }
    u32 len = static_cast<u32>(e - b);
    const char* raw = arena.CopyString(b, len);
    if (raw == nullptr)
    {
        return nullptr;
    }
    char* m = const_cast<char*>(raw);
    for (u32 i = 0; i < len; ++i)
    {
        m[i] = Lower(m[i]);
    }
    return raw;
}

// Copy [b,e) verbatim (value strings keep case for colors/urls). Empty
// range yields "".
const char* CopyVerbatim(const char* b, const char* e, Arena& arena)
{
    if (e <= b)
    {
        return arena.CopyString("", 0);
    }
    return arena.CopyString(b, static_cast<u32>(e - b));
}

void Trim(const char*& b, const char*& e)
{
    while (b < e && IsSpace(*b))
    {
        ++b;
    }
    while (e > b && IsSpace(*(e - 1)))
    {
        --e;
    }
}

// Is `c` a boundary that ends a simple-selector fragment (type, class,
// or id name token)? A name runs until the next class/id/pseudo/attr
// marker.
bool IsFragBoundary(char c)
{
    return c == '.' || c == '#' || c == ':' || c == '[';
}

// Parse a `:pseudo` or `:pseudo(arg)` fragment beginning at *p (which
// points just past the ':'). Advances *p past the fragment, records the
// structural pseudo on `sel`, and bumps `bClasses` (pseudo-classes count
// as a class-level specificity component). Unknown pseudo-classes are
// skipped without setting anything (still consume their token + any
// parenthesised arg) so a `:hover` etc. doesn't break the parse. GAP:
// ::pseudo-elements and the an+b form of nth-child.
void ParsePseudo(const char*& p, const char* e, SimpleSelector* sel, Arena& arena, u32& bClasses)
{
    const char* ns = p;
    while (p < e && !IsFragBoundary(*p) && *p != '(')
    {
        ++p;
    }
    const char* name = CopyLower(ns, p, arena);

    // Optional ( ... ) argument (e.g. nth-child(2)).
    const char* argB = nullptr;
    const char* argE = nullptr;
    if (p < e && *p == '(')
    {
        ++p;
        argB = p;
        while (p < e && *p != ')')
        {
            ++p;
        }
        argE = p;
        if (p < e) // consume ')'
        {
            ++p;
        }
        Trim(argB, argE);
    }

    if (name == nullptr)
    {
        return; // empty / OOM — skip
    }

    StructuralPseudo matched = StructuralPseudo::None;
    if (duetos::core::StrEqual(name, "first-child"))
    {
        matched = StructuralPseudo::FirstChild;
    }
    else if (duetos::core::StrEqual(name, "last-child"))
    {
        matched = StructuralPseudo::LastChild;
    }
    else if (duetos::core::StrEqual(name, "nth-child") && argB != nullptr)
    {
        // even / odd keywords, or a literal positive integer. GAP: an+b.
        u32 argLen = static_cast<u32>(argE - argB);
        if (argLen == 4 && Lower(argB[0]) == 'e' && Lower(argB[1]) == 'v' && Lower(argB[2]) == 'e' &&
            Lower(argB[3]) == 'n')
        {
            matched = StructuralPseudo::NthChildEven;
        }
        else if (argLen == 3 && Lower(argB[0]) == 'o' && Lower(argB[1]) == 'd' && Lower(argB[2]) == 'd')
        {
            matched = StructuralPseudo::NthChildOdd;
        }
        else
        {
            // Literal integer (no '+' / 'n' formula handling — GAP).
            bool allDigits = argLen > 0;
            i32 n = 0;
            for (const char* d = argB; d < argE; ++d)
            {
                if (*d < '0' || *d > '9')
                {
                    allDigits = false;
                    break;
                }
                n = n * 10 + (*d - '0');
            }
            if (allDigits)
            {
                matched = StructuralPseudo::NthChildLit;
                sel->nthChild = n;
            }
        }
    }

    if (matched != StructuralPseudo::None)
    {
        // Only the first structural pseudo on a compound is honored
        // (multiple structural pseudo-classes on one compound is a GAP);
        // each still contributes to specificity.
        if (sel->pseudo == StructuralPseudo::None)
        {
            sel->pseudo = matched;
        }
        ++bClasses;
    }
    // Unknown/dynamic pseudo-classes (:hover, :not, …) are skipped: token
    // + arg already consumed. GAP: they neither match nor add specificity
    // here (we have no way to evaluate them statically).
}

// Parse a `[attr op "val"]` fragment beginning at *p (which points just
// past the '['). Advances *p past the closing ']', appends an
// AttrSelector to `sel`, and bumps `bClasses` (attribute selectors count
// as class-level). Tolerant of quoted or bare values and surrounding
// whitespace.
void ParseAttr(const char*& p, const char* e, SimpleSelector* sel, Arena& arena, u32& bClasses)
{
    // Name runs until an operator char, whitespace, or ']'.
    while (p < e && IsSpace(*p))
    {
        ++p;
    }
    const char* ns = p;
    while (p < e && *p != ']' && *p != '=' && *p != '~' && *p != '^' && *p != '$' && *p != '*' && !IsSpace(*p))
    {
        ++p;
    }
    const char* nameE = p;

    while (p < e && IsSpace(*p))
    {
        ++p;
    }

    AttrOp op = AttrOp::Exists;
    if (p < e && *p == '=')
    {
        op = AttrOp::Exact;
        ++p;
    }
    else if (p < e && (*p == '~' || *p == '^' || *p == '$' || *p == '*') && (p + 1 < e) && p[1] == '=')
    {
        switch (*p)
        {
        case '~':
            op = AttrOp::Whitespace;
            break;
        case '^':
            op = AttrOp::Prefix;
            break;
        case '$':
            op = AttrOp::Suffix;
            break;
        default:
            op = AttrOp::Substring;
            break;
        }
        p += 2;
    }

    const char* valB = nullptr;
    const char* valE = nullptr;
    if (op != AttrOp::Exists)
    {
        while (p < e && IsSpace(*p))
        {
            ++p;
        }
        if (p < e && (*p == '"' || *p == '\''))
        {
            char quote = *p;
            ++p;
            valB = p;
            while (p < e && *p != quote)
            {
                ++p;
            }
            valE = p;
            if (p < e) // consume closing quote
            {
                ++p;
            }
        }
        else
        {
            valB = p;
            while (p < e && *p != ']' && !IsSpace(*p))
            {
                ++p;
            }
            valE = p;
        }
    }

    // Skip to and past the closing ']'.
    while (p < e && *p != ']')
    {
        ++p;
    }
    if (p < e)
    {
        ++p;
    }

    const char* name = CopyLower(ns, nameE, arena);
    if (name == nullptr)
    {
        return; // malformed empty name — drop
    }

    AttrSelector* a = ArenaNew<AttrSelector>(arena);
    if (a == nullptr)
    {
        return; // OOM — drop this clause, keep the rest of the selector
    }
    a->name = name;
    a->op = op;
    if (op != AttrOp::Exists)
    {
        a->value = CopyVerbatim(valB, valE, arena);
    }

    // Append (preserve author order; order is irrelevant to matching but
    // keeps the structure predictable).
    AttrSelector** link = &sel->attrs;
    while (*link != nullptr)
    {
        link = &(*link)->next;
    }
    *link = a;
    ++bClasses;
}

// ----- compound selector: "div.note#x" -> SimpleSelector -----------
// Reads the rightmost-or-only compound (no spaces inside). Folds the
// specificity contribution into the a/b/c counters. nullptr on OOM /
// empty.
SimpleSelector* ParseCompound(const char* b, const char* e, Arena& arena, u32& aIds, u32& bClasses, u32& cTypes)
{
    Trim(b, e);
    if (b >= e)
    {
        return nullptr;
    }
    SimpleSelector* sel = ArenaNew<SimpleSelector>(arena);
    if (sel == nullptr)
    {
        return nullptr;
    }

    const char* p = b;
    // Leading type token (or '*'), if present.
    if (*p == '*')
    {
        sel->universal = true;
        ++p;
    }
    else if (!IsFragBoundary(*p))
    {
        const char* ts = p;
        while (p < e && !IsFragBoundary(*p))
        {
            ++p;
        }
        sel->tag = CopyLower(ts, p, arena);
        ++cTypes; // type selector adds to 'c'
    }

    // Then a sequence of .class / #id / :pseudo / [attr] fragments.
    while (p < e)
    {
        char kind = *p;
        if (kind == ':')
        {
            ++p;
            ParsePseudo(p, e, sel, arena, bClasses);
            continue;
        }
        if (kind == '[')
        {
            ++p;
            ParseAttr(p, e, sel, arena, bClasses);
            continue;
        }
        if (kind != '.' && kind != '#')
        {
            ++p; // skip anything unexpected
            continue;
        }
        ++p;
        const char* fs = p;
        while (p < e && !IsFragBoundary(*p))
        {
            ++p;
        }
        if (kind == '.')
        {
            sel->className = CopyLower(fs, p, arena);
            ++bClasses;
        }
        else
        {
            sel->id = CopyLower(fs, p, arena);
            ++aIds;
        }
    }
    return sel;
}

// ----- complex selector: "ul li.note" (descendant chain) -----------
// Splits on whitespace into compounds, builds a right-anchored chain
// where the returned selector is the rightmost compound and its
// `ancestor` links walk leftward. Computes packed specificity.
SimpleSelector* ParseComplex(const char* b, const char* e, Arena& arena, u32& specOut)
{
    Trim(b, e);
    if (b >= e)
    {
        return nullptr;
    }

    u32 aIds = 0, bClasses = 0, cTypes = 0;

    // Collect compounds left-to-right, chaining each new one as the
    // `ancestor` of the previous tail... but we want the RIGHTMOST as
    // the head with ancestor pointing left. So we build a small forward
    // list then relink.
    SimpleSelector* rightmost = nullptr; // the element we ultimately match
    SimpleSelector* prevTail = nullptr;  // last-built compound (its ancestor = next-left)

    const char* p = b;
    while (p < e)
    {
        while (p < e && IsSpace(*p)) // skip combinator whitespace
        {
            ++p;
        }
        if (p >= e)
        {
            break;
        }
        const char* cs = p;
        while (p < e && !IsSpace(*p))
        {
            ++p;
        }
        SimpleSelector* comp = ParseCompound(cs, p, arena, aIds, bClasses, cTypes);
        if (comp == nullptr)
        {
            return nullptr;
        }
        if (rightmost == nullptr)
        {
            rightmost = comp;
            prevTail = comp;
        }
        else
        {
            // `comp` is further right than prevTail. The element matches
            // the rightmost compound; each compound to the left must
            // match some ancestor. So the newer (righter) compound's
            // `ancestor` points at the previous (lefter) one.
            comp->ancestor = prevTail;
            prevTail = comp;
            rightmost = comp;
        }
    }

    // `rightmost` is the last compound parsed (the rightmost in source),
    // which is exactly the element-matching head; its ancestor chain
    // walks leftward. Pack the specificity counters.
    u32 a = aIds > 255 ? 255 : aIds;
    u32 bb = bClasses > 255 ? 255 : bClasses;
    u32 c = cTypes > 255 ? 255 : cTypes;
    specOut = (a << 16) | (bb << 8) | c;
    return rightmost;
}

// ----- declaration block: "color:red; font-weight: bold" -----------
Declaration* ParseDeclList(const char* b, const char* e, Arena& arena)
{
    Declaration* head = nullptr;
    Declaration* tail = nullptr;

    const char* p = b;
    while (p < e)
    {
        // One declaration up to ';' (or end).
        const char* declStart = p;
        while (p < e && *p != ';')
        {
            ++p;
        }
        const char* declEnd = p;
        if (p < e)
        {
            ++p; // consume ';'
        }

        // Split on the first ':'.
        const char* colon = declStart;
        while (colon < declEnd && *colon != ':')
        {
            ++colon;
        }
        if (colon >= declEnd)
        {
            continue; // no ':' — malformed, drop
        }

        const char* nameB = declStart;
        const char* nameE = colon;
        const char* valB = colon + 1;
        const char* valE = declEnd;
        Trim(nameB, nameE);
        Trim(valB, valE);
        if (nameB >= nameE || valB >= valE)
        {
            continue;
        }

        // Detect a trailing !important and strip it from the value.
        // (best-effort; full !important cascade ordering is a GAP)
        bool important = false;
        for (const char* s = valB; s + 10 <= valE; ++s)
        {
            if (s[0] == '!' && Lower(s[1]) == 'i' && Lower(s[2]) == 'm' && Lower(s[3]) == 'p' && Lower(s[4]) == 'o' &&
                Lower(s[5]) == 'r' && Lower(s[6]) == 't' && Lower(s[7]) == 'a' && Lower(s[8]) == 'n' &&
                Lower(s[9]) == 't')
            {
                important = true;
                valE = s; // truncate before '!'
                Trim(valB, valE);
                break;
            }
        }

        Declaration* d = ArenaNew<Declaration>(arena);
        if (d == nullptr)
        {
            break; // arena exhausted — stop, keep what we have
        }
        d->property = CopyLower(nameB, nameE, arena);
        d->value = CopyVerbatim(valB, valE, arena);
        d->important = important;
        if (d->property == nullptr || d->value == nullptr)
        {
            continue;
        }

        if (tail == nullptr)
        {
            head = d;
        }
        else
        {
            tail->next = d;
        }
        tail = d;
    }
    return head;
}

void AppendRule(StyleSheet& sheet, Rule* r)
{
    r->order = sheet.ruleCount;
    if (sheet.tail == nullptr)
    {
        sheet.rules = r;
    }
    else
    {
        sheet.tail->next = r;
    }
    sheet.tail = r;
    ++sheet.ruleCount;
}

} // namespace

void ParseStyleSheet(StyleSheet& sheet, const char* css, u32 len, bool userAgent, Arena& arena)
{
    if (css == nullptr || len == 0)
    {
        return;
    }
    const char* p = css;
    const char* end = css + len;

    while (p < end)
    {
        while (p < end && IsSpace(*p))
        {
            ++p;
        }
        if (p >= end)
        {
            break;
        }

        // Skip CSS comments /* ... */.
        if (p + 1 < end && p[0] == '/' && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            p = (p + 1 < end) ? p + 2 : end;
            continue;
        }

        // Skip unknown @-rules. @media/@font-face/@supports have blocks;
        // @import/@charset/@namespace end at ';'. We don't honor any of
        // them in this slice.
        if (*p == '@')
        {
            const char* q = p;
            while (q < end && *q != '{' && *q != ';')
            {
                ++q;
            }
            if (q < end && *q == '{')
            {
                // Balanced-brace skip of the @-block body.
                int depth = 0;
                while (q < end)
                {
                    if (*q == '{')
                    {
                        ++depth;
                    }
                    else if (*q == '}')
                    {
                        --depth;
                        if (depth == 0)
                        {
                            ++q;
                            break;
                        }
                    }
                    ++q;
                }
            }
            else if (q < end)
            {
                ++q; // consume ';'
            }
            p = q;
            continue;
        }

        // A normal rule: selector-list up to '{', then declarations to '}'.
        const char* selStart = p;
        while (p < end && *p != '{')
        {
            ++p;
        }
        if (p >= end)
        {
            break; // no block — malformed trailing junk
        }
        const char* selEnd = p;
        ++p; // consume '{'
        const char* declStart = p;
        while (p < end && *p != '}')
        {
            ++p;
        }
        const char* declEnd = p;
        if (p < end)
        {
            ++p; // consume '}'
        }

        Declaration* decls = ParseDeclList(declStart, declEnd, arena);
        if (decls == nullptr)
        {
            continue; // empty / unparseable block — nothing to apply
        }

        // Split the selector list on top-level commas; one Rule each.
        const char* s = selStart;
        while (s < selEnd)
        {
            const char* comma = s;
            while (comma < selEnd && *comma != ',')
            {
                ++comma;
            }
            u32 spec = 0;
            SimpleSelector* sel = ParseComplex(s, comma, arena, spec);
            if (sel != nullptr)
            {
                Rule* r = ArenaNew<Rule>(arena);
                if (r == nullptr)
                {
                    return; // arena exhausted
                }
                r->selector = sel;
                r->decls = decls;
                r->specificity = spec;
                r->userAgent = userAgent;
                AppendRule(sheet, r);
            }
            s = (comma < selEnd) ? comma + 1 : selEnd;
        }
    }
}

Declaration* ParseInlineStyle(const char* style, u32 len, Arena& arena)
{
    if (style == nullptr || len == 0)
    {
        return nullptr;
    }
    return ParseDeclList(style, style + len, arena);
}

} // namespace duetos::web
