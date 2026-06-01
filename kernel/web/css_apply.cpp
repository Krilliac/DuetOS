/*
 * DuetOS — CSS property application: value -> ComputedStyle field.
 *
 * Split out of the cascade engine (css.cpp) so the large flat property
 * dispatch lives in its own translation unit. Each `property: value`
 * pair is matched by name and the parsed value folded into the
 * ComputedStyle. Unknown / unparseable properties are silently ignored
 * (the cascade simply keeps the inherited / initial value).
 *
 * GAP: 4-value margin/padding shorthands, the full border shorthand
 * grammar, and any property not in the practical subset declared in
 * css.h are not handled.
 */

#include "web/css_internal.h"

#include "util/string.h"

namespace duetos::web
{

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

} // namespace

void ApplyDeclaration(ComputedStyle& cs, const char* prop, const char* val)
{
    if (StrEq(prop, "display"))
    {
        if (StrEq(val, "none"))
        {
            cs.display = Display::None;
        }
        else if (StrEq(val, "inline"))
        {
            cs.display = Display::Inline;
        }
        else if (StrEq(val, "inline-block"))
        {
            cs.display = Display::InlineBlock;
        }
        else if (StrEq(val, "block"))
        {
            cs.display = Display::Block;
        }
        return;
    }
    if (StrEq(prop, "color"))
    {
        Color c;
        if (ParseColor(val, c))
        {
            cs.color = c;
        }
        return;
    }
    if (StrEq(prop, "background-color") || StrEq(prop, "background"))
    {
        Color c;
        if (ParseColor(val, c))
        {
            cs.backgroundColor = c;
        }
        return;
    }
    if (StrEq(prop, "font-size"))
    {
        Length l;
        if (ParseLength(val, l) && l.kind == LengthKind::Px)
        {
            cs.fontSize = l.value;
        }
        return;
    }
    if (StrEq(prop, "font-weight"))
    {
        if (StrEq(val, "bold") || StrEq(val, "bolder") || StrEq(val, "700") || StrEq(val, "800") || StrEq(val, "900"))
        {
            cs.fontWeight = FontWeight::Bold;
        }
        else if (StrEq(val, "normal") || StrEq(val, "400"))
        {
            cs.fontWeight = FontWeight::Normal;
        }
        return;
    }
    if (StrEq(prop, "font-style"))
    {
        cs.fontStyle = (StrEq(val, "italic") || StrEq(val, "oblique")) ? FontStyleKind::Italic : FontStyleKind::Normal;
        return;
    }
    if (StrEq(prop, "text-align"))
    {
        if (StrEq(val, "center"))
        {
            cs.textAlign = TextAlign::Center;
        }
        else if (StrEq(val, "right"))
        {
            cs.textAlign = TextAlign::Right;
        }
        else if (StrEq(val, "justify"))
        {
            cs.textAlign = TextAlign::Justify;
        }
        else if (StrEq(val, "left"))
        {
            cs.textAlign = TextAlign::Left;
        }
        return;
    }
    if (StrEq(prop, "text-decoration") || StrEq(prop, "text-decoration-line"))
    {
        cs.underline = StrEq(val, "underline");
        return;
    }
    if (StrEq(prop, "line-height"))
    {
        Length l;
        if (ParseLength(val, l) && l.kind == LengthKind::Px)
        {
            cs.lineHeight = l.value;
        }
        return;
    }
    if (StrEq(prop, "white-space"))
    {
        if (StrEq(val, "pre"))
        {
            cs.whiteSpace = WhiteSpace::Pre;
        }
        else if (StrEq(val, "nowrap"))
        {
            cs.whiteSpace = WhiteSpace::Nowrap;
        }
        else
        {
            cs.whiteSpace = WhiteSpace::Normal;
        }
        return;
    }
    if (StrEq(prop, "list-style") || StrEq(prop, "list-style-type"))
    {
        cs.listStyleNone = StrEq(val, "none");
        return;
    }
    if (StrEq(prop, "width"))
    {
        Length l;
        if (ParseLength(val, l))
        {
            cs.width = l;
        }
        return;
    }
    if (StrEq(prop, "height"))
    {
        Length l;
        if (ParseLength(val, l))
        {
            cs.height = l;
        }
        return;
    }

    // Margin / padding: only the longhand single-edge and the all-edge
    // shorthand-as-one-value forms (the common cases). A 4-value
    // shorthand is a GAP.
    if (StrEq(prop, "margin") || StrEq(prop, "padding"))
    {
        Length l;
        if (ParseLength(val, l))
        {
            EdgeLengths& edges = StrEq(prop, "margin") ? cs.margin : cs.padding;
            edges.top = edges.right = edges.bottom = edges.left = l;
        }
        return;
    }
    auto edgeSetter = [&](EdgeLengths& edges, const char* p) -> bool
    {
        Length l;
        if (StrEq(p, "-top") && ParseLength(val, l))
        {
            edges.top = l;
            return true;
        }
        if (StrEq(p, "-right") && ParseLength(val, l))
        {
            edges.right = l;
            return true;
        }
        if (StrEq(p, "-bottom") && ParseLength(val, l))
        {
            edges.bottom = l;
            return true;
        }
        if (StrEq(p, "-left") && ParseLength(val, l))
        {
            edges.left = l;
            return true;
        }
        return false;
    };
    // margin-top / padding-left / ...
    {
        const char* mtag = "margin";
        const char* ptag = "padding";
        u32 ml = 6, pl = 7;
        for (u32 i = 0;; ++i) // compare prefix "margin"
        {
            if (i == ml)
            {
                if (edgeSetter(cs.margin, prop + ml))
                {
                    return;
                }
                break;
            }
            if (prop[i] != mtag[i])
            {
                break;
            }
        }
        for (u32 i = 0;; ++i) // compare prefix "padding"
        {
            if (i == pl)
            {
                if (edgeSetter(cs.padding, prop + pl))
                {
                    return;
                }
                break;
            }
            if (prop[i] != ptag[i])
            {
                break;
            }
        }
    }

    // Border: width / color / style longhands + a tolerant `border`
    // shorthand "Npx solid #rgb" (order-insensitive token scan).
    if (StrEq(prop, "border-width"))
    {
        Length l;
        if (ParseLength(val, l) && l.kind == LengthKind::Px)
        {
            cs.border.width = l.value;
            if (cs.border.style == BorderStyle::None && l.value > 0)
            {
                cs.border.style = BorderStyle::Solid;
            }
        }
        return;
    }
    if (StrEq(prop, "border-color"))
    {
        Color c;
        if (ParseColor(val, c))
        {
            cs.border.color = c;
        }
        return;
    }
    if (StrEq(prop, "border-style"))
    {
        cs.border.style = StrEq(val, "none") ? BorderStyle::None : BorderStyle::Solid;
        return;
    }
    if (StrEq(prop, "border"))
    {
        // Scan space-separated tokens; a number→width, color→color,
        // "none"→off, anything else (solid/dashed)→on.
        const char* p = val;
        bool any = false;
        while (*p != '\0')
        {
            while (*p != '\0' && IsSpace(*p))
            {
                ++p;
            }
            const char* tb = p;
            while (*p != '\0' && !IsSpace(*p))
            {
                ++p;
            }
            if (p == tb)
            {
                break;
            }
            // NUL-terminate a local copy via stack buffer (tokens short).
            char tok[32];
            u32 n = static_cast<u32>(p - tb);
            if (n >= sizeof(tok))
            {
                n = sizeof(tok) - 1;
            }
            for (u32 i = 0; i < n; ++i)
            {
                tok[i] = tb[i];
            }
            tok[n] = '\0';

            Length l;
            Color c;
            if (StrEq(tok, "none"))
            {
                cs.border.style = BorderStyle::None;
            }
            else if (ParseLength(tok, l) && l.kind == LengthKind::Px)
            {
                cs.border.width = l.value;
                any = true;
            }
            else if (ParseColor(tok, c))
            {
                cs.border.color = c;
                any = true;
            }
            else
            {
                // a style keyword (solid/dashed/dotted/...) — turn on
                cs.border.style = BorderStyle::Solid;
                any = true;
            }
        }
        if (any && cs.border.style == BorderStyle::None && cs.border.width > 0)
        {
            cs.border.style = BorderStyle::Solid;
        }
        return;
    }
}

void ApplyDeclList(ComputedStyle& cs, const Declaration* d)
{
    for (; d != nullptr; d = d->next)
    {
        ApplyDeclaration(cs, d->property, d->value);
    }
}

} // namespace duetos::web
