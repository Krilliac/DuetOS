/*
 * DuetOS — HTML entity decoder. See entities.h.
 *
 * Supports numeric references (&#NN; decimal and &#xHH; hex) and a
 * pragmatic named set covering the references that show up in real
 * markup. The output is UTF-8; a codepoint encodes to 1..4 bytes.
 * GAP: not the full HTML5 named-character-reference table (~2200
 * entries) — the common ~30 plus all numeric refs. Revisit if a
 * real page trips a missing name.
 */

#include "web/entities.h"

namespace duetos::web
{

namespace
{

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

bool IsHexDigit(char c)
{
    return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

u32 HexVal(char c)
{
    if (IsDigit(c))
    {
        return static_cast<u32>(c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return static_cast<u32>(c - 'a' + 10);
    }
    return static_cast<u32>(c - 'A' + 10);
}

bool NameEq(const char* a, u32 alen, const char* b)
{
    u32 i = 0;
    for (; i < alen; ++i)
    {
        if (b[i] == '\0' || a[i] != b[i])
        {
            return false;
        }
    }
    return b[i] == '\0';
}

// Encode a Unicode codepoint as UTF-8 into out (capacity outCap).
// Returns bytes written, or 0 if it would not fit / is invalid.
u32 EncodeUtf8(u32 cp, char* out, u32 outCap)
{
    if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
    {
        // Invalid / lone surrogate — emit U+FFFD replacement.
        cp = 0xFFFD;
    }
    if (cp < 0x80)
    {
        if (outCap < 1)
        {
            return 0;
        }
        out[0] = static_cast<char>(cp);
        return 1;
    }
    if (cp < 0x800)
    {
        if (outCap < 2)
        {
            return 0;
        }
        out[0] = static_cast<char>(0xC0 | (cp >> 6));
        out[1] = static_cast<char>(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000)
    {
        if (outCap < 3)
        {
            return 0;
        }
        out[0] = static_cast<char>(0xE0 | (cp >> 12));
        out[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out[2] = static_cast<char>(0x80 | (cp & 0x3F));
        return 3;
    }
    if (outCap < 4)
    {
        return 0;
    }
    out[0] = static_cast<char>(0xF0 | (cp >> 18));
    out[1] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out[2] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out[3] = static_cast<char>(0x80 | (cp & 0x3F));
    return 4;
}

struct NamedEntity
{
    const char* name;
    u32 codepoint;
};

// Pragmatic named set: the references that actually appear in the
// wild. Numeric refs cover the rest.
constexpr NamedEntity kNamed[] = {
    {"amp", 0x26},     {"lt", 0x3C},      {"gt", 0x3E},      {"quot", 0x22},     {"apos", 0x27},     {"nbsp", 0xA0},
    {"copy", 0xA9},    {"reg", 0xAE},     {"trade", 0x2122}, {"hellip", 0x2026}, {"mdash", 0x2014},  {"ndash", 0x2013},
    {"lsquo", 0x2018}, {"rsquo", 0x2019}, {"ldquo", 0x201C}, {"rdquo", 0x201D},  {"deg", 0xB0},      {"plusmn", 0xB1},
    {"times", 0xD7},   {"divide", 0xF7},  {"euro", 0x20AC},  {"pound", 0xA3},    {"cent", 0xA2},     {"yen", 0xA5},
    {"sect", 0xA7},    {"para", 0xB6},    {"middot", 0xB7},  {"bull", 0x2022},   {"dagger", 0x2020}, {"laquo", 0xAB},
    {"raquo", 0xBB},   {"frac12", 0xBD},  {"frac14", 0xBC},  {"frac34", 0xBE},
};

} // namespace

u32 DecodeEntity(const char* src, u32 len, char* out, u32 outCap, u32* consumed)
{
    *consumed = 0;
    if (len < 2 || src[0] != '&')
    {
        return 0;
    }

    // Numeric: &#NN;  or  &#xHH;
    if (src[1] == '#')
    {
        u32 i = 2;
        u32 cp = 0;
        bool hex = false;
        if (i < len && (src[i] == 'x' || src[i] == 'X'))
        {
            hex = true;
            ++i;
        }
        u32 start = i;
        while (i < len)
        {
            char c = src[i];
            if (hex)
            {
                if (!IsHexDigit(c))
                {
                    break;
                }
                cp = cp * 16 + HexVal(c);
            }
            else
            {
                if (!IsDigit(c))
                {
                    break;
                }
                cp = cp * 10 + static_cast<u32>(c - '0');
            }
            if (cp > 0x10FFFF)
            {
                cp = 0xFFFD; // clamp runaway
            }
            ++i;
        }
        if (i == start)
        {
            return 0; // "&#" / "&#x" with no digits — literal
        }
        // Optional trailing semicolon.
        if (i < len && src[i] == ';')
        {
            ++i;
        }
        u32 wrote = EncodeUtf8(cp, out, outCap);
        if (wrote == 0)
        {
            return 0;
        }
        *consumed = i;
        return wrote;
    }

    // Named: &name; — scan the name up to ';' or a non-name char.
    u32 i = 1;
    while (i < len && i < 33)
    {
        char c = src[i];
        bool nameChar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!nameChar)
        {
            break;
        }
        ++i;
    }
    u32 nameLen = i - 1;
    if (nameLen == 0)
    {
        return 0;
    }
    bool hasSemi = (i < len && src[i] == ';');
    for (const NamedEntity& e : kNamed)
    {
        if (NameEq(src + 1, nameLen, e.name))
        {
            u32 wrote = EncodeUtf8(e.codepoint, out, outCap);
            if (wrote == 0)
            {
                return 0;
            }
            *consumed = hasSemi ? (i + 1) : i;
            return wrote;
        }
    }
    return 0; // unknown name — caller emits literal '&'
}

} // namespace duetos::web
