#include "util/unicode.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

bool IsSurrogate(u32 cp)
{
    return cp >= kUtf16SurrogateLo && cp <= kUtf16SurrogateHi;
}

bool IsHighSurrogate(u16 unit)
{
    return unit >= 0xD800 && unit <= 0xDBFF;
}

bool IsLowSurrogate(u16 unit)
{
    return unit >= 0xDC00 && unit <= 0xDFFF;
}

} // namespace

u32 Utf8Encode(u32 cp, u8 out[kUtf8MaxBytes])
{
    if (cp > kUnicodeMaxCodepoint || IsSurrogate(cp))
        return 0;
    if (cp < 0x80)
    {
        out[0] = u8(cp);
        return 1;
    }
    if (cp < 0x800)
    {
        out[0] = u8(0xC0 | (cp >> 6));
        out[1] = u8(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000)
    {
        out[0] = u8(0xE0 | (cp >> 12));
        out[1] = u8(0x80 | ((cp >> 6) & 0x3F));
        out[2] = u8(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = u8(0xF0 | (cp >> 18));
    out[1] = u8(0x80 | ((cp >> 12) & 0x3F));
    out[2] = u8(0x80 | ((cp >> 6) & 0x3F));
    out[3] = u8(0x80 | (cp & 0x3F));
    return 4;
}

u32 Utf8Decode(const u8* in, u32 in_len, u32& cp)
{
    if (in_len == 0)
        return 0;
    const u8 b0 = in[0];

    if (b0 < 0x80)
    {
        cp = b0;
        return 1;
    }

    u32 needed = 0;
    u32 value = 0;
    u32 min_value = 0;
    if ((b0 & 0xE0) == 0xC0)
    {
        needed = 2;
        value = b0 & 0x1F;
        min_value = 0x80;
    }
    else if ((b0 & 0xF0) == 0xE0)
    {
        needed = 3;
        value = b0 & 0x0F;
        min_value = 0x800;
    }
    else if ((b0 & 0xF8) == 0xF0)
    {
        needed = 4;
        value = b0 & 0x07;
        min_value = 0x10000;
    }
    else
    {
        return 0; // bare continuation byte or invalid lead
    }

    if (in_len < needed)
        return 0;
    for (u32 i = 1; i < needed; ++i)
    {
        const u8 cb = in[i];
        if ((cb & 0xC0) != 0x80)
            return 0;
        value = (value << 6) | (cb & 0x3F);
    }
    if (value < min_value)
        return 0; // overlong
    if (value > kUnicodeMaxCodepoint)
        return 0;
    if (IsSurrogate(value))
        return 0;
    cp = value;
    return needed;
}

u32 Utf16Encode(u32 cp, u16 out[kUtf16MaxUnits])
{
    if (cp > kUnicodeMaxCodepoint || IsSurrogate(cp))
        return 0;
    if (cp < 0x10000)
    {
        out[0] = u16(cp);
        return 1;
    }
    const u32 v = cp - 0x10000;
    out[0] = u16(0xD800 | (v >> 10));
    out[1] = u16(0xDC00 | (v & 0x3FF));
    return 2;
}

u32 Utf16Decode(const u16* in, u32 in_units, u32& cp)
{
    if (in_units == 0)
        return 0;
    const u16 u0 = in[0];
    if (IsLowSurrogate(u0))
        return 0; // lone low surrogate
    if (!IsHighSurrogate(u0))
    {
        cp = u0;
        return 1;
    }
    if (in_units < 2)
        return 0; // truncated pair
    const u16 u1 = in[1];
    if (!IsLowSurrogate(u1))
        return 0; // bad pair
    cp = 0x10000u + ((u32(u0 - 0xD800) << 10) | u32(u1 - 0xDC00));
    return 2;
}

char Utf16CpToSafeAscii(u32 cp)
{
    if (cp == 0)
        return '\0';
    if (cp >= 0x20 && cp < 0x7F)
        return char(cp);
    return '?';
}

u32 Utf16LeBufferToSafeAscii(const u8* in, u32 byte_len, char* out, u32 out_cap)
{
    if (out_cap == 0)
        return 0;
    if (out_cap == 1)
    {
        out[0] = '\0';
        return 0;
    }
    // Even-byte input only — drop a trailing odd byte.
    const u32 units = byte_len / 2;
    u16 buf[kUtf16MaxUnits];
    u32 written = 0;
    u32 i = 0;
    while (i < units && written + 1 < out_cap)
    {
        buf[0] = u16(in[i * 2]) | (u16(in[i * 2 + 1]) << 8);
        u32 cp;
        u32 consumed;
        if (IsHighSurrogate(buf[0]) && i + 1 < units)
        {
            buf[1] = u16(in[(i + 1) * 2]) | (u16(in[(i + 1) * 2 + 1]) << 8);
            consumed = Utf16Decode(buf, 2, cp);
        }
        else
        {
            consumed = Utf16Decode(buf, 1, cp);
        }
        if (consumed == 0)
        {
            // Skip the broken unit, emit replacement.
            cp = kUnicodeReplacement;
            consumed = 1;
        }
        if (cp == 0)
            break; // NUL terminator inside the UTF-16 buffer
        out[written++] = Utf16CpToSafeAscii(cp);
        i += consumed;
    }
    out[written] = '\0';
    return written;
}

void UnicodeSelfTest()
{
    // ----- UTF-8 encode round-trips for the four length classes.
    {
        u8 buf[kUtf8MaxBytes];

        // 1-byte: 'A' (U+0041).
        u32 n = Utf8Encode(0x0041, buf);
        KASSERT(n == 1 && buf[0] == 0x41, "util/unicode", "UTF-8 ASCII encode wrong");

        // 2-byte: 'é' (U+00E9) → C3 A9.
        n = Utf8Encode(0x00E9, buf);
        KASSERT(n == 2 && buf[0] == 0xC3 && buf[1] == 0xA9, "util/unicode", "UTF-8 2-byte encode wrong");

        // 3-byte: '€' (U+20AC) → E2 82 AC.
        n = Utf8Encode(0x20AC, buf);
        KASSERT(n == 3 && buf[0] == 0xE2 && buf[1] == 0x82 && buf[2] == 0xAC, "util/unicode",
                "UTF-8 3-byte encode wrong");

        // 4-byte: U+1F600 (😀) → F0 9F 98 80.
        n = Utf8Encode(0x1F600, buf);
        KASSERT(n == 4 && buf[0] == 0xF0 && buf[1] == 0x9F && buf[2] == 0x98 && buf[3] == 0x80, "util/unicode",
                "UTF-8 4-byte encode wrong");
    }

    // ----- UTF-8 decode round-trips.
    {
        const u8 ascii[1] = {0x41};
        u32 cp = 0;
        u32 n = Utf8Decode(ascii, 1, cp);
        KASSERT(n == 1 && cp == 0x41, "util/unicode", "UTF-8 ASCII decode wrong");

        const u8 two[2] = {0xC3, 0xA9};
        n = Utf8Decode(two, 2, cp);
        KASSERT(n == 2 && cp == 0x00E9, "util/unicode", "UTF-8 2-byte decode wrong");

        const u8 three[3] = {0xE2, 0x82, 0xAC};
        n = Utf8Decode(three, 3, cp);
        KASSERT(n == 3 && cp == 0x20AC, "util/unicode", "UTF-8 3-byte decode wrong");

        const u8 four[4] = {0xF0, 0x9F, 0x98, 0x80};
        n = Utf8Decode(four, 4, cp);
        KASSERT(n == 4 && cp == 0x1F600, "util/unicode", "UTF-8 4-byte decode wrong");
    }

    // ----- UTF-8 negative cases: overlong, truncated, surrogate,
    // bare continuation, codepoint > 0x10FFFF.
    {
        u32 cp = 0;
        // Overlong "/" (0x2F) as 0xC0 0xAF — must reject.
        const u8 overlong[2] = {0xC0, 0xAF};
        KASSERT(Utf8Decode(overlong, 2, cp) == 0, "util/unicode", "UTF-8 overlong not rejected");

        // Truncated 3-byte sequence.
        const u8 trunc[2] = {0xE2, 0x82};
        KASSERT(Utf8Decode(trunc, 2, cp) == 0, "util/unicode", "UTF-8 truncated not rejected");

        // Surrogate U+D800 encoded as 3-byte: ED A0 80 — must reject.
        const u8 surr[3] = {0xED, 0xA0, 0x80};
        KASSERT(Utf8Decode(surr, 3, cp) == 0, "util/unicode", "UTF-8 surrogate not rejected");

        // Bare continuation byte.
        const u8 bare[1] = {0x80};
        KASSERT(Utf8Decode(bare, 1, cp) == 0, "util/unicode", "UTF-8 bare-continuation not rejected");

        // Codepoint > U+10FFFF: F4 90 80 80 (= U+110000).
        const u8 oob[4] = {0xF4, 0x90, 0x80, 0x80};
        KASSERT(Utf8Decode(oob, 4, cp) == 0, "util/unicode", "UTF-8 oob codepoint not rejected");
    }

    // ----- UTF-16 surrogate-pair round-trip for U+1F600.
    {
        u16 units[kUtf16MaxUnits];
        u32 n = Utf16Encode(0x1F600, units);
        KASSERT(n == 2 && units[0] == 0xD83D && units[1] == 0xDE00, "util/unicode",
                "UTF-16 surrogate-pair encode wrong");

        u32 cp = 0;
        n = Utf16Decode(units, 2, cp);
        KASSERT(n == 2 && cp == 0x1F600, "util/unicode", "UTF-16 surrogate-pair decode wrong");
    }

    // ----- UTF-16 BMP round-trip for U+20AC ('€').
    {
        u16 units[kUtf16MaxUnits];
        u32 n = Utf16Encode(0x20AC, units);
        KASSERT(n == 1 && units[0] == 0x20AC, "util/unicode", "UTF-16 BMP encode wrong");

        u32 cp = 0;
        n = Utf16Decode(units, 1, cp);
        KASSERT(n == 1 && cp == 0x20AC, "util/unicode", "UTF-16 BMP decode wrong");
    }

    // ----- UTF-16 negative cases.
    {
        u32 cp = 0;
        // Lone low surrogate.
        const u16 lone_lo[1] = {0xDC00};
        KASSERT(Utf16Decode(lone_lo, 1, cp) == 0, "util/unicode", "UTF-16 lone-low not rejected");

        // High surrogate without a follower.
        const u16 lone_hi[1] = {0xD800};
        KASSERT(Utf16Decode(lone_hi, 1, cp) == 0, "util/unicode", "UTF-16 truncated-high not rejected");

        // High followed by non-low.
        const u16 bad_pair[2] = {0xD800, 0x0041};
        KASSERT(Utf16Decode(bad_pair, 2, cp) == 0, "util/unicode", "UTF-16 bad-pair not rejected");

        // Encode rejects surrogate codepoint.
        u16 buf[kUtf16MaxUnits];
        KASSERT(Utf16Encode(0xD800, buf) == 0, "util/unicode", "UTF-16 encode of surrogate not rejected");
    }

    // ----- UTF-16LE buffer → ASCII smoke (mirrors what exfat/ntfs
    // care about): "He€r" with the BMP € collapsed to '?', surrogate-pair
    // pumpkin (U+1F383) collapsed to '?', NUL terminator stops the walk.
    {
        // UTF-16LE bytes for: 'H' 'e' '€' 'r' [surrogate pair U+1F383] 'X' '\0'
        // After a trailing NUL we should stop, so X must NOT appear.
        const u8 raw[] = {
            0x48, 0x00,             // 'H'
            0x65, 0x00,             // 'e'
            0xAC, 0x20,             // '€'
            0x72, 0x00,             // 'r'
            0x3C, 0xD8, 0x83, 0xDF, // U+1F383 (surrogate pair, low byte first)
            0x00, 0x00,             // NUL — stops here
            0x58, 0x00,             // 'X' (must not appear)
        };
        char out[16];
        u32 n = Utf16LeBufferToSafeAscii(raw, sizeof(raw), out, sizeof(out));
        KASSERT(n == 5, "util/unicode", "UTF-16LE→ASCII length mismatch");
        const char want[] = {'H', 'e', '?', 'r', '?', '\0'};
        for (u32 i = 0; i < 6; ++i)
            KASSERT(out[i] == want[i], "util/unicode", "UTF-16LE→ASCII content mismatch");
    }
}

} // namespace duetos::util
