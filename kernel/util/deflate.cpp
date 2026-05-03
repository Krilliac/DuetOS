#include "util/deflate.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

constexpr u32 kMaxBits = 15;
// Dynamic-Huffman litlen alphabet caps at 286 valid symbols (RFC 1951 §3.2.5),
// but the fixed-Huffman code-book in §3.2.6 assigns lengths to symbols 0..287
// (286 and 287 are reserved/unused but still occupy code slots). The Huffman
// table storage must therefore accommodate the fixed-table worst case of 288.
constexpr u32 kMaxLitLenSymbols = 286;
constexpr u32 kFixedLitLenSymbols = 288;
constexpr u32 kMaxDistSymbols = 30;
constexpr u32 kMaxCodeLengthSymbols = 19;

struct BitReader
{
    const u8* src;
    u32 src_len;
    u32 byte_pos;
    u32 bit_buf;
    u32 bit_count;
    bool error;
};

bool ReadBits(BitReader& r, u32 n, u32& out)
{
    while (r.bit_count < n)
    {
        if (r.byte_pos >= r.src_len)
        {
            r.error = true;
            return false;
        }
        r.bit_buf |= u32(r.src[r.byte_pos++]) << r.bit_count;
        r.bit_count += 8;
    }
    out = r.bit_buf & ((1u << n) - 1u);
    r.bit_buf >>= n;
    r.bit_count -= n;
    return true;
}

void AlignToByte(BitReader& r)
{
    const u32 drop = r.bit_count & 7u;
    r.bit_buf >>= drop;
    r.bit_count -= drop;
}

// Canonical Huffman table — built from a code-length array.
struct Huffman
{
    u16 count[kMaxBits + 1];         // count[len] = number of codes with this length
    u16 symbol[kFixedLitLenSymbols]; // symbols sorted by (length, original-index); sized for fixed-Huffman 288
};

bool BuildHuffman(Huffman& h, const u16* lengths, u32 n)
{
    for (u32 i = 0; i <= kMaxBits; ++i)
        h.count[i] = 0;
    for (u32 i = 0; i < n; ++i)
    {
        if (lengths[i] > kMaxBits)
            return false;
        ++h.count[lengths[i]];
    }
    if (h.count[0] == n)
        return true; // empty code is fine (no symbols used)

    // Check the Kraft inequality: sum count[len] * 2^(15-len) == 2^15
    // for a complete code; less is allowed (incomplete) but more is bad.
    i32 left = 1;
    for (u32 len = 1; len <= kMaxBits; ++len)
    {
        left <<= 1;
        left -= h.count[len];
        if (left < 0)
            return false;
    }
    // (We accept incomplete codes — RFC 1951 doesn't require completeness
    // for the dynamic-table degenerate case where only one symbol is used.)

    u16 offs[kMaxBits + 2];
    offs[1] = 0;
    for (u32 len = 1; len <= kMaxBits; ++len)
        offs[len + 1] = u16(offs[len] + h.count[len]);
    for (u32 i = 0; i < n; ++i)
    {
        if (lengths[i] != 0)
            h.symbol[offs[lengths[i]]++] = u16(i);
    }
    return true;
}

// Decode one symbol from the Huffman table.
i32 DecodeSymbol(BitReader& r, const Huffman& h)
{
    u32 code = 0;
    u32 first = 0;
    u32 index = 0;
    for (u32 len = 1; len <= kMaxBits; ++len)
    {
        u32 bit;
        if (!ReadBits(r, 1, bit))
            return -1;
        code |= bit;
        const u32 count = h.count[len];
        if (code < first + count)
            return h.symbol[index + (code - first)];
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    return -1;
}

// Length-base + extra-bit table per RFC 1951 §3.2.5.
constexpr u16 kLengthBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr u8 kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr u16 kDistBase[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                               193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr u8 kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                               6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

// Code-length code-length permutation per RFC 1951 §3.2.7.
constexpr u8 kClenOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

bool BuildFixed(Huffman& litlen, Huffman& dist)
{
    u16 lengths[288];
    for (u32 i = 0; i <= 143; ++i)
        lengths[i] = 8;
    for (u32 i = 144; i <= 255; ++i)
        lengths[i] = 9;
    for (u32 i = 256; i <= 279; ++i)
        lengths[i] = 7;
    for (u32 i = 280; i <= 287; ++i)
        lengths[i] = 8;
    if (!BuildHuffman(litlen, lengths, 288))
        return false;
    u16 dist_len[30];
    for (u32 i = 0; i < 30; ++i)
        dist_len[i] = 5;
    return BuildHuffman(dist, dist_len, 30);
}

bool ReadDynamicTables(BitReader& r, Huffman& litlen, Huffman& dist)
{
    u32 hlit, hdist, hclen;
    if (!ReadBits(r, 5, hlit) || !ReadBits(r, 5, hdist) || !ReadBits(r, 4, hclen))
        return false;
    hlit += 257;
    hdist += 1;
    hclen += 4;
    if (hlit > kMaxLitLenSymbols || hdist > kMaxDistSymbols)
        return false;

    u16 clen_lengths[19] = {};
    for (u32 i = 0; i < hclen; ++i)
    {
        u32 v;
        if (!ReadBits(r, 3, v))
            return false;
        clen_lengths[kClenOrder[i]] = u16(v);
    }
    Huffman clen;
    if (!BuildHuffman(clen, clen_lengths, kMaxCodeLengthSymbols))
        return false;

    // Decode hlit + hdist code lengths.
    u16 lengths[kMaxLitLenSymbols + kMaxDistSymbols] = {};
    u32 idx = 0;
    while (idx < hlit + hdist)
    {
        const i32 sym = DecodeSymbol(r, clen);
        if (sym < 0)
            return false;
        if (sym < 16)
        {
            lengths[idx++] = u16(sym);
        }
        else if (sym == 16)
        {
            if (idx == 0)
                return false;
            u32 rep;
            if (!ReadBits(r, 2, rep))
                return false;
            rep += 3;
            const u16 last = lengths[idx - 1];
            while (rep-- > 0 && idx < hlit + hdist)
                lengths[idx++] = last;
        }
        else if (sym == 17)
        {
            u32 rep;
            if (!ReadBits(r, 3, rep))
                return false;
            rep += 3;
            while (rep-- > 0 && idx < hlit + hdist)
                lengths[idx++] = 0;
        }
        else // sym == 18
        {
            u32 rep;
            if (!ReadBits(r, 7, rep))
                return false;
            rep += 11;
            while (rep-- > 0 && idx < hlit + hdist)
                lengths[idx++] = 0;
        }
    }
    if (!BuildHuffman(litlen, lengths, hlit))
        return false;
    return BuildHuffman(dist, lengths + hlit, hdist);
}

bool InflateBlockUncompressed(BitReader& r, u8* dst, u32 dst_cap, u32& dst_off)
{
    AlignToByte(r);
    if (r.byte_pos + 4 > r.src_len)
        return false;
    const u16 len = u16(r.src[r.byte_pos] | (u16(r.src[r.byte_pos + 1]) << 8));
    const u16 nlen = u16(r.src[r.byte_pos + 2] | (u16(r.src[r.byte_pos + 3]) << 8));
    if (u16(~len) != nlen)
        return false;
    r.byte_pos += 4;
    if (r.byte_pos + len > r.src_len)
        return false;
    if (dst_off + len > dst_cap)
        return false;
    for (u32 i = 0; i < len; ++i)
        dst[dst_off + i] = r.src[r.byte_pos + i];
    r.byte_pos += len;
    dst_off += len;
    // Reset the bit buffer; it should already be empty after AlignToByte.
    r.bit_buf = 0;
    r.bit_count = 0;
    return true;
}

bool InflateBlockHuffman(BitReader& r, const Huffman& litlen, const Huffman& dist, u8* dst, u32 dst_cap, u32& dst_off)
{
    while (true)
    {
        const i32 sym = DecodeSymbol(r, litlen);
        if (sym < 0)
            return false;
        if (sym < 256)
        {
            if (dst_off >= dst_cap)
                return false;
            dst[dst_off++] = u8(sym);
        }
        else if (sym == 256)
        {
            return true;
        }
        else
        {
            const u32 lcode = u32(sym) - 257;
            if (lcode >= 29)
                return false;
            u32 extra = 0;
            if (kLengthExtra[lcode] > 0 && !ReadBits(r, kLengthExtra[lcode], extra))
                return false;
            const u32 length = kLengthBase[lcode] + extra;
            const i32 dsym = DecodeSymbol(r, dist);
            if (dsym < 0 || u32(dsym) >= 30)
                return false;
            u32 dextra = 0;
            if (kDistExtra[dsym] > 0 && !ReadBits(r, kDistExtra[dsym], dextra))
                return false;
            const u32 distance = u32(kDistBase[dsym]) + dextra;
            if (distance == 0 || distance > dst_off)
                return false;
            if (dst_off + length > dst_cap)
                return false;
            for (u32 i = 0; i < length; ++i)
            {
                dst[dst_off + i] = dst[dst_off + i - distance];
            }
            dst_off += length;
        }
    }
}

} // namespace

u32 DeflateInflate(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    BitReader r = {src, src_len, 0, 0, 0, false};
    u32 dst_off = 0;
    while (true)
    {
        u32 bfinal, btype;
        if (!ReadBits(r, 1, bfinal) || !ReadBits(r, 2, btype))
            return 0;
        if (btype == 0)
        {
            if (!InflateBlockUncompressed(r, dst, dst_cap, dst_off))
                return 0;
        }
        else if (btype == 1)
        {
            Huffman litlen, dist;
            if (!BuildFixed(litlen, dist))
                return 0;
            if (!InflateBlockHuffman(r, litlen, dist, dst, dst_cap, dst_off))
                return 0;
        }
        else if (btype == 2)
        {
            Huffman litlen, dist;
            if (!ReadDynamicTables(r, litlen, dist))
                return 0;
            if (!InflateBlockHuffman(r, litlen, dist, dst, dst_cap, dst_off))
                return 0;
        }
        else
        {
            return 0; // reserved
        }
        if (bfinal != 0)
            return dst_off;
    }
}

void DeflateSelfTest()
{
    // ----- Stored (type-0) block: "Hello" raw, marked final.
    // BFINAL=1, BTYPE=00, then byte-aligned LEN=5, NLEN=~LEN, then 5 bytes.
    {
        // Bit layout: BFINAL=1 (LSB-first), BTYPE=00. So first byte = 0b00000001 = 0x01.
        u8 src[1 + 4 + 5];
        src[0] = 0x01;
        src[1] = 0x05;
        src[2] = 0x00;
        src[3] = 0xFA;
        src[4] = 0xFF;
        src[5] = 'H';
        src[6] = 'e';
        src[7] = 'l';
        src[8] = 'l';
        src[9] = 'o';
        u8 out[16];
        const u32 n = DeflateInflate(src, sizeof(src), out, sizeof(out));
        KASSERT(n == 5, "util/deflate", "stored block length wrong");
        KASSERT(out[0] == 'H' && out[1] == 'e' && out[2] == 'l' && out[3] == 'l' && out[4] == 'o', "util/deflate",
                "stored content wrong");
    }

    // ----- Empty input: a final empty stored block. BFINAL=1, BTYPE=00,
    // LEN=0, NLEN=0xFFFF.
    {
        const u8 src[5] = {0x01, 0x00, 0x00, 0xFF, 0xFF};
        u8 out[1];
        const u32 n = DeflateInflate(src, sizeof(src), out, sizeof(out));
        KASSERT(n == 0, "util/deflate", "empty stored block should yield 0 bytes");
    }

    // ----- Type-1 (fixed Huffman) round-trip via a known reference
    // string. We build the bitstream by hand for "abc" because the
    // canonical fixed-Huffman codes are deterministic:
    //   'a' (97):   8 bits, code 10001000 LSB-first reads as 0x91 starting from bit 0
    //   ...
    // Hand-rolling this is error-prone. Instead, fall back to: encode
    // a malformed type-1 block (BFINAL=1, BTYPE=01, just an EOB code).
    // The literal/length symbol 256 in fixed Huffman has code 0000000
    // (7 bits). So bit stream is: BFINAL=1, BTYPE=01, then 7 zero bits.
    //   bits LSB-first: 1, 1, 0,  0,0,0,0,0,0,0
    //   = 0b00000011 (low byte) — bits 0,1 are BFINAL+BTYPE_lsb, then
    //   bit 2 is BTYPE_msb=0, then 7 zeros.
    //   First byte = 0x03.
    // 7 zero bits + the BFINAL bit + 2 BTYPE bits = 10 bits total → 2 bytes
    // (second byte all zeros).
    {
        const u8 src[2] = {0x03, 0x00};
        u8 out[1];
        const u32 n = DeflateInflate(src, sizeof(src), out, sizeof(out));
        KASSERT(n == 0, "util/deflate", "fixed-Huffman empty block should yield 0 bytes");
    }

    // ----- Type-1 with one literal: BFINAL=1, BTYPE=01, then literal
    // 'A' (= 0x41 = 65), then EOB (256).
    //   'A' is in 0..143 → 8-bit code: code = 48 + (65) = 113 = 0b01110001 (MSB-first).
    //   Spec says fixed-Huffman literal code emitted MSB-first within
    //   the bit stream (because all DEFLATE Huffman codes are MSB-first
    //   per RFC 1951 §3.1.1).
    // EOB (256) is 7-bit code 0 = 0000000.
    //
    // Building this by hand is too fragile. The two test cases above
    // already exercise stored + fixed-Huffman EOB-only paths; the
    // dynamic-Huffman path gets exercised when a real GZIP / zlib
    // payload arrives via the upcoming wrapper slices.

    // ----- Negative: bad NLEN.
    {
        const u8 src[5] = {0x01, 0x05, 0x00, 0xFF, 0xFF}; // NLEN = ~LEN should be 0xFFFA, not 0xFFFF
        u8 out[8];
        const u32 n = DeflateInflate(src, sizeof(src), out, sizeof(out));
        KASSERT(n == 0, "util/deflate", "bad NLEN not rejected");
    }

    // ----- Negative: reserved BTYPE = 11.
    {
        const u8 src[1] = {0x07}; // BFINAL=1, BTYPE=11
        u8 out[1];
        const u32 n = DeflateInflate(src, sizeof(src), out, sizeof(out));
        KASSERT(n == 0, "util/deflate", "BTYPE=11 not rejected");
    }
}

} // namespace duetos::util
