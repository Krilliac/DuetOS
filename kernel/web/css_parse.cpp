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
 * GAP: pseudo-classes/elements, attribute selectors, child/sibling
 * combinators, :nth-child — only type, .class, #id, universal, and the
 * descendant combinator are recognised. !important is detected
 * best-effort.
 */

#include "web/css.h"

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
    else if (*p != '.' && *p != '#')
    {
        const char* ts = p;
        while (p < e && *p != '.' && *p != '#')
        {
            ++p;
        }
        sel->tag = CopyLower(ts, p, arena);
        ++cTypes; // type selector adds to 'c'
    }

    // Then a sequence of .class / #id fragments.
    while (p < e)
    {
        char kind = *p;
        if (kind != '.' && kind != '#')
        {
            ++p; // skip anything unexpected (e.g. a stray ':')
            continue;
        }
        ++p;
        const char* fs = p;
        while (p < e && *p != '.' && *p != '#')
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
