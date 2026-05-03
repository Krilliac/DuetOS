#include "util/base64.h"

#include "core/panic.h"

/*
 * Reference: RFC 4648 §4 (standard base64 alphabet with '='
 * padding). Constant-table approach — encode reads three bytes
 * and emits four characters; decode reads up to four characters
 * (skipping whitespace) and emits up to three bytes.
 */

namespace duetos::util
{

namespace
{

const char k_alphabet[64] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                             'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                             'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                             'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

// 0xFF means invalid / non-alphabet. Pad ('=') and whitespace
// (' ', '\t', '\r', '\n') get distinct sentinels so the decoder
// can react to them.
constexpr u8 kPad = 0xFEu;
constexpr u8 kWs = 0xFDu;
constexpr u8 kBad = 0xFFu;

constinit u8 g_decode_table[256] = {};
constinit bool g_decode_ready = false;

void InitDecodeTable()
{
    if (g_decode_ready)
        return;
    for (u32 i = 0; i < 256; ++i)
        g_decode_table[i] = kBad;
    for (u32 i = 0; i < 64; ++i)
        g_decode_table[static_cast<u8>(k_alphabet[i])] = static_cast<u8>(i);
    g_decode_table[static_cast<u8>('=')] = kPad;
    g_decode_table[static_cast<u8>(' ')] = kWs;
    g_decode_table[static_cast<u8>('\t')] = kWs;
    g_decode_table[static_cast<u8>('\r')] = kWs;
    g_decode_table[static_cast<u8>('\n')] = kWs;
    g_decode_ready = true;
}

} // namespace

u32 Base64Encode(const u8* in, u32 len, char* out)
{
    if (in == nullptr || out == nullptr)
        return 0;

    u32 i = 0;
    u32 j = 0;
    while (i + 3 <= len)
    {
        const u32 v =
            (static_cast<u32>(in[i]) << 16) | (static_cast<u32>(in[i + 1]) << 8) | static_cast<u32>(in[i + 2]);
        out[j + 0] = k_alphabet[(v >> 18) & 0x3Fu];
        out[j + 1] = k_alphabet[(v >> 12) & 0x3Fu];
        out[j + 2] = k_alphabet[(v >> 6) & 0x3Fu];
        out[j + 3] = k_alphabet[v & 0x3Fu];
        i += 3;
        j += 4;
    }
    const u32 rem = len - i;
    if (rem == 1)
    {
        const u32 v = static_cast<u32>(in[i]) << 16;
        out[j + 0] = k_alphabet[(v >> 18) & 0x3Fu];
        out[j + 1] = k_alphabet[(v >> 12) & 0x3Fu];
        out[j + 2] = '=';
        out[j + 3] = '=';
        j += 4;
    }
    else if (rem == 2)
    {
        const u32 v = (static_cast<u32>(in[i]) << 16) | (static_cast<u32>(in[i + 1]) << 8);
        out[j + 0] = k_alphabet[(v >> 18) & 0x3Fu];
        out[j + 1] = k_alphabet[(v >> 12) & 0x3Fu];
        out[j + 2] = k_alphabet[(v >> 6) & 0x3Fu];
        out[j + 3] = '=';
        j += 4;
    }
    return j;
}

bool Base64Decode(const char* in, u32 in_len, u8* out, u32 out_capacity, u32* out_bytes)
{
    if (in == nullptr || out == nullptr || out_bytes == nullptr)
        return false;
    InitDecodeTable();

    u32 quad[4];
    u32 quad_fill = 0;
    u32 written = 0;
    u32 pad_seen = 0;
    bool past_pad = false;

    for (u32 i = 0; i < in_len; ++i)
    {
        const u8 v = g_decode_table[static_cast<u8>(in[i])];
        if (v == kWs)
            continue;
        if (v == kBad)
            return false;
        if (past_pad && v != kWs)
            return false; // bytes after a '=' that aren't whitespace
        if (v == kPad)
        {
            ++pad_seen;
            if (pad_seen > 2)
                return false;
            quad[quad_fill++] = kPad;
        }
        else
        {
            if (pad_seen != 0)
                return false; // alphabet byte after '='
            quad[quad_fill++] = v;
        }
        if (quad_fill == 4)
        {
            // Resolve this 4-char group.
            const u32 a = quad[0];
            const u32 b = quad[1];
            const u32 c = quad[2];
            const u32 d = quad[3];
            if (a == kPad || b == kPad)
                return false; // first two MUST be alphabet
            if (c == kPad && d != kPad)
                return false; // can't have "X=Y"
            const u32 val = (a << 18) | (b << 12) | ((c == kPad ? 0u : c) << 6) | (d == kPad ? 0u : d);
            if (written >= out_capacity)
                return false;
            out[written++] = static_cast<u8>((val >> 16) & 0xFFu);
            if (c != kPad)
            {
                if (written >= out_capacity)
                    return false;
                out[written++] = static_cast<u8>((val >> 8) & 0xFFu);
            }
            if (d != kPad)
            {
                if (written >= out_capacity)
                    return false;
                out[written++] = static_cast<u8>(val & 0xFFu);
            }
            if (c == kPad || d == kPad)
                past_pad = true;
            quad_fill = 0;
        }
    }
    if (quad_fill != 0)
        return false; // truncated input — encoded data is always 4-aligned
    *out_bytes = written;
    return true;
}

void Base64SelfTest()
{
    InitDecodeTable();

    // RFC 4648 §10 test vectors.
    struct Vector
    {
        const char* raw;
        u32 raw_len;
        const char* encoded;
    };

    const Vector vectors[7] = {{"", 0, ""},
                               {"f", 1, "Zg=="},
                               {"fo", 2, "Zm8="},
                               {"foo", 3, "Zm9v"},
                               {"foob", 4, "Zm9vYg=="},
                               {"fooba", 5, "Zm9vYmE="},
                               {"foobar", 6, "Zm9vYmFy"}};

    for (u32 v = 0; v < 7; ++v)
    {
        char enc[16];
        const u32 written = Base64Encode(reinterpret_cast<const u8*>(vectors[v].raw), vectors[v].raw_len, enc);
        u32 expected_len = 0;
        while (vectors[v].encoded[expected_len] != 0)
            ++expected_len;
        KASSERT(written == expected_len, "util/base64", "RFC 4648 encode length mismatch");
        for (u32 k = 0; k < expected_len; ++k)
            KASSERT(enc[k] == vectors[v].encoded[k], "util/base64", "RFC 4648 encode byte mismatch");

        u8 dec[16];
        u32 dec_bytes = 0;
        const bool ok = Base64Decode(vectors[v].encoded, expected_len, dec, sizeof(dec), &dec_bytes);
        KASSERT(ok, "util/base64", "RFC 4648 decode rejected valid encoding");
        KASSERT(dec_bytes == vectors[v].raw_len, "util/base64", "RFC 4648 decode length mismatch");
        for (u32 k = 0; k < dec_bytes; ++k)
            KASSERT(dec[k] == static_cast<u8>(vectors[v].raw[k]), "util/base64", "RFC 4648 decode byte mismatch");
    }

    // Whitespace tolerance (MIME-style line breaks).
    {
        const char* enc = "Zm9v\r\nYmFy";
        u8 dec[8];
        u32 dec_bytes = 0;
        const bool ok = Base64Decode(enc, 10, dec, sizeof(dec), &dec_bytes);
        KASSERT(ok, "util/base64", "decode rejected whitespace-tolerant input");
        KASSERT(dec_bytes == 6, "util/base64", "decode-with-whitespace len mismatch");
        const u8 want[6] = {'f', 'o', 'o', 'b', 'a', 'r'};
        for (u32 k = 0; k < 6; ++k)
            KASSERT(dec[k] == want[k], "util/base64", "decode-with-whitespace byte mismatch");
    }

    // Bad-input rejection.
    {
        u8 dec[8];
        u32 dec_bytes = 0;
        // Non-alphabet character.
        KASSERT(!Base64Decode("Zm$v", 4, dec, sizeof(dec), &dec_bytes), "util/base64", "decode accepted '$'");
        // Truncated (not multiple of 4 after whitespace strip).
        KASSERT(!Base64Decode("Zm9", 3, dec, sizeof(dec), &dec_bytes), "util/base64",
                "decode accepted truncated input");
        // Padding in the wrong place.
        KASSERT(!Base64Decode("Z=9v", 4, dec, sizeof(dec), &dec_bytes), "util/base64",
                "decode accepted '=' before alphabet");
        // Output buffer too small.
        u8 small[1];
        KASSERT(!Base64Decode("Zm9vYmFy", 8, small, sizeof(small), &dec_bytes), "util/base64",
                "decode accepted into undersized output");
    }
}

} // namespace duetos::util
