/*
 * DuetOS — CSS value parsing: colors and lengths. See css.h.
 *
 * Split out of the cascade engine so the color table + the numeric
 * scanners live in one coherent unit. Pure functions, no arena, no
 * allocation — they read a NUL-terminated (or length-bounded) token
 * and fill a small POD. Everything is freestanding; the only kernel
 * dependency is the string helpers.
 */

#include "web/css.h"

#include "util/string.h"

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

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

// Parse one hex nibble; returns -1 on non-hex.
int HexNibble(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    char l = Lower(c);
    if (l >= 'a' && l <= 'f')
    {
        return l - 'a' + 10;
    }
    return -1;
}

// Case-insensitive compare of a token against a lowercase literal,
// where the token may be followed by trailing space/garbage we ignore
// only when `exact` is false. When `exact`, the token must end (NUL).
bool TokEq(const char* tok, const char* lit, bool exact)
{
    u32 i = 0;
    for (; lit[i] != '\0'; ++i)
    {
        if (Lower(tok[i]) != lit[i])
        {
            return false;
        }
    }
    if (exact && tok[i] != '\0')
    {
        return false;
    }
    return true;
}

// The named-color table. A reasonable practical subset (the 16 base
// HTML colors + a handful layout/UA sheets actually use). GAP: not the
// full 140-name CSS3 set.
struct NamedColor
{
    const char* name;
    u8 r, g, b;
};

constexpr NamedColor kNamedColors[] = {
    {"black", 0, 0, 0},           {"white", 255, 255, 255},     {"red", 255, 0, 0},
    {"green", 0, 128, 0},         {"lime", 0, 255, 0},          {"blue", 0, 0, 255},
    {"yellow", 255, 255, 0},      {"cyan", 0, 255, 255},        {"aqua", 0, 255, 255},
    {"magenta", 255, 0, 255},     {"fuchsia", 255, 0, 255},     {"gray", 128, 128, 128},
    {"grey", 128, 128, 128},      {"silver", 192, 192, 192},    {"maroon", 128, 0, 0},
    {"olive", 128, 128, 0},       {"navy", 0, 0, 128},          {"teal", 0, 128, 128},
    {"purple", 128, 0, 128},      {"orange", 255, 165, 0},      {"pink", 255, 192, 203},
    {"brown", 165, 42, 42},       {"gold", 255, 215, 0},        {"darkgray", 169, 169, 169},
    {"darkgrey", 169, 169, 169},  {"lightgray", 211, 211, 211}, {"lightgrey", 211, 211, 211},
    {"dodgerblue", 30, 144, 255}, {"steelblue", 70, 130, 180},
};

// Parse the unsigned integer at *p (advancing *p), clamped to 0..255
// is the caller's job; here we just read the value. Stops at first
// non-digit.
u32 ScanUint(const char*& p)
{
    u32 v = 0;
    while (IsDigit(*p))
    {
        v = v * 10 + static_cast<u32>(*p - '0');
        if (v > 1000000) // saturate; nothing legitimate is this big
        {
            v = 1000000;
        }
        ++p;
    }
    return v;
}

u8 Clamp255(u32 v)
{
    return static_cast<u8>(v > 255 ? 255 : v);
}

// Parse rgb(...) / rgba(...) starting at the '(' content. `hasAlpha`
// selects rgba. Returns true on success.
bool ParseRgbFunc(const char* p, bool hasAlpha, Color& out)
{
    auto skipSep = [&p]()
    {
        while (IsSpace(*p) || *p == ',')
        {
            ++p;
        }
    };

    skipSep();
    if (!IsDigit(*p))
    {
        return false;
    }
    u32 r = ScanUint(p);
    skipSep();
    if (!IsDigit(*p))
    {
        return false;
    }
    u32 g = ScanUint(p);
    skipSep();
    if (!IsDigit(*p))
    {
        return false;
    }
    u32 b = ScanUint(p);

    u8 a = 255;
    if (hasAlpha)
    {
        skipSep();
        // Alpha is 0..1 float. We scan integer part + up to 3 fractional
        // digits and map to 0..255. "1" -> 255, "0" -> 0, "0.5" -> 127.
        if (!IsDigit(*p) && *p != '.')
        {
            return false;
        }
        u32 whole = ScanUint(p);
        u32 milli = 0; // thousandths
        if (*p == '.')
        {
            ++p;
            u32 scale = 100;
            while (IsDigit(*p) && scale > 0)
            {
                milli += static_cast<u32>(*p - '0') * scale;
                scale /= 10;
                ++p;
            }
            while (IsDigit(*p)) // consume excess fractional digits
            {
                ++p;
            }
        }
        u32 alpha1000 = whole >= 1 ? 1000 : milli;
        a = static_cast<u8>((alpha1000 * 255 + 500) / 1000);
    }

    out = Color{Clamp255(r), Clamp255(g), Clamp255(b), a};
    return true;
}

} // namespace

bool ParseColor(const char* s, Color& out)
{
    if (s == nullptr)
    {
        return false;
    }
    // Trim leading space.
    while (IsSpace(*s))
    {
        ++s;
    }
    if (*s == '\0')
    {
        return false;
    }

    // #rgb / #rrggbb
    if (*s == '#')
    {
        const char* h = s + 1;
        u32 n = 0;
        while (HexNibble(h[n]) >= 0)
        {
            ++n;
        }
        if (n == 3)
        {
            int r = HexNibble(h[0]);
            int g = HexNibble(h[1]);
            int b = HexNibble(h[2]);
            out = Color{static_cast<u8>(r * 17), static_cast<u8>(g * 17), static_cast<u8>(b * 17), 255};
            return true;
        }
        if (n == 6)
        {
            int r = HexNibble(h[0]) * 16 + HexNibble(h[1]);
            int g = HexNibble(h[2]) * 16 + HexNibble(h[3]);
            int b = HexNibble(h[4]) * 16 + HexNibble(h[5]);
            out = Color{static_cast<u8>(r), static_cast<u8>(g), static_cast<u8>(b), 255};
            return true;
        }
        return false;
    }

    // rgb(...) / rgba(...)
    if (TokEq(s, "rgba", false) && s[4] == '(')
    {
        return ParseRgbFunc(s + 5, true, out);
    }
    if (TokEq(s, "rgb", false) && s[3] == '(')
    {
        return ParseRgbFunc(s + 4, false, out);
    }

    // transparent keyword
    if (TokEq(s, "transparent", true))
    {
        out = Color{0, 0, 0, 0};
        return true;
    }

    // Named colors.
    for (const NamedColor& nc : kNamedColors)
    {
        if (TokEq(s, nc.name, true))
        {
            out = Color{nc.r, nc.g, nc.b, 255};
            return true;
        }
    }
    return false;
}

// Parse a length token: "12px", "50%", "auto", or a bare number (treated
// as px, matching the leniency layout wants). Returns true on success.
bool ParseLength(const char* s, Length& out)
{
    if (s == nullptr)
    {
        return false;
    }
    while (IsSpace(*s))
    {
        ++s;
    }
    if (TokEq(s, "auto", true))
    {
        out = Length::AutoVal();
        return true;
    }

    bool neg = false;
    if (*s == '-')
    {
        neg = true;
        ++s;
    }
    else if (*s == '+')
    {
        ++s;
    }
    if (!IsDigit(*s) && *s != '.')
    {
        return false;
    }

    const char* p = s;
    i32 v = static_cast<i32>(ScanUint(p));
    if (*p == '.') // tolerate a fractional part; truncate toward zero
    {
        ++p;
        while (IsDigit(*p))
        {
            ++p;
        }
    }
    if (neg)
    {
        v = -v;
    }

    while (IsSpace(*p))
    {
        ++p;
    }
    if (*p == '%')
    {
        out = Length{LengthKind::Percent, v};
        return true;
    }
    // px or unitless (default to px). Any other unit (em/rem/vh) is a GAP
    // — we still accept it as px so layout has a number to work with.
    out = Length::Px(v);
    return true;
}

} // namespace duetos::web
