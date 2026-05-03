#include "util/lz4.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

// Read a length extension: a sequence of bytes summed until one
// is < 255 (the < 255 byte is also added). Returns false on
// truncation. Updates `src_off` past the consumed bytes.
bool ReadLengthExt(const u8* src, u32 src_len, u32& src_off, u32& acc)
{
    while (src_off < src_len)
    {
        const u8 b = src[src_off++];
        acc += b;
        if (b != 255)
            return true;
    }
    return false;
}

} // namespace

u32 Lz4DecompressBlock(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    u32 src_off = 0;
    u32 dst_off = 0;
    while (src_off < src_len)
    {
        const u8 token = src[src_off++];
        u32 lit_len = u32(token >> 4);
        u32 match_len = u32(token & 0x0Fu);

        // Literal-length extension.
        if (lit_len == 15)
        {
            if (!ReadLengthExt(src, src_len, src_off, lit_len))
                return 0;
        }
        // Copy literals.
        if (u64(src_off) + u64(lit_len) > u64(src_len))
            return 0;
        if (u64(dst_off) + u64(lit_len) > u64(dst_cap))
            return 0;
        for (u32 i = 0; i < lit_len; ++i)
            dst[dst_off + i] = src[src_off + i];
        src_off += lit_len;
        dst_off += lit_len;

        // Last sequence ends here (no offset, no match).
        if (src_off == src_len)
            return dst_off;

        // 2-byte LE offset.
        if (src_off + 2 > src_len)
            return 0;
        const u32 offset = u32(src[src_off]) | (u32(src[src_off + 1]) << 8);
        src_off += 2;
        if (offset == 0 || offset > dst_off)
            return 0; // can't reference before output start

        // Match-length extension. Total match length = 4 + low4 + ext.
        if (match_len == 15)
        {
            if (!ReadLengthExt(src, src_len, src_off, match_len))
                return 0;
        }
        match_len += 4;

        if (u64(dst_off) + u64(match_len) > u64(dst_cap))
            return 0;

        // Byte-by-byte copy with overlap support.
        for (u32 i = 0; i < match_len; ++i)
            dst[dst_off + i] = dst[dst_off + i - offset];
        dst_off += match_len;
    }
    return dst_off;
}

void Lz4SelfTest()
{
    // ----- All-literals: token (lit_len=4, match_field=0), then
    // 4 literal bytes "ABCD". This sequence has no match because
    // src ends right after the literals — see the spec note on
    // the "last sequence" being literals-only.
    {
        const u8 src[5] = {0x40, 'A', 'B', 'C', 'D'};
        u8 dst[16];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 4, "util/lz4", "literals-only length wrong");
        KASSERT(dst[0] == 'A' && dst[1] == 'B' && dst[2] == 'C' && dst[3] == 'D', "util/lz4",
                "literals-only content wrong");
    }

    // ----- Match with overlap: emit 1 byte 'X' as literal, then a
    // match (offset=1, length=4) replicating 'X' four more times.
    // Then trailing literal "Y".
    //
    // Sequence 1: token=(lit=1, match_field=0) → 0x10 (match_len base=4).
    //             literal: 'X'.
    //             offset = 1 (LE: 0x01 0x00).
    // Sequence 2 (last): token=(lit=1, match_field=0) → 0x10.
    //             literal: 'Y'.
    //             [no offset — last sequence is literals-only]
    //
    // Expected output: "XXXXXY" (6 bytes).
    {
        const u8 src[6] = {0x10, 'X', 0x01, 0x00, 0x10, 'Y'};
        u8 dst[16];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 6, "util/lz4", "overlap match length wrong");
        const char want[6] = {'X', 'X', 'X', 'X', 'X', 'Y'};
        for (u32 i = 0; i < 6; ++i)
            KASSERT(dst[i] == u8(want[i]), "util/lz4", "overlap match content wrong");
    }

    // ----- Length extension: 15+10 = 25 literal bytes. Token
    // = 0xF0 (lit_len_field=15, match_field=0). Then ext byte
    // = 10 (so total lit_len = 25). Then 25 literal bytes 'A'..'Y'.
    // Last sequence (no match).
    {
        u8 src[1 + 1 + 25];
        src[0] = 0xF0; // lit_len=15 (extension follows), match_len_field=0
        src[1] = 10;   // extension: total lit_len = 15 + 10 = 25
        for (u32 i = 0; i < 25; ++i)
            src[2 + i] = u8('A' + i);
        u8 dst[32];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 25, "util/lz4", "length-ext literals length wrong");
        for (u32 i = 0; i < 25; ++i)
            KASSERT(dst[i] == u8('A' + i), "util/lz4", "length-ext content wrong");
    }

    // ----- Negative: dst_cap too small.
    {
        const u8 src[5] = {0x40, 'A', 'B', 'C', 'D'};
        u8 dst[2];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 0, "util/lz4", "dst overflow not rejected");
    }

    // ----- Negative: offset that points before output start.
    {
        // Token (lit=0, match_field=0), offset=1 (no prior output).
        const u8 src[3] = {0x00, 0x01, 0x00};
        u8 dst[16];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 0, "util/lz4", "out-of-range offset not rejected");
    }

    // ----- Negative: truncated literal section.
    {
        // Token (lit=4) but only 2 bytes of literal follow.
        const u8 src[3] = {0x40, 'A', 'B'};
        u8 dst[16];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 0, "util/lz4", "truncated literals not rejected");
    }

    // ----- Negative: zero offset.
    {
        const u8 src[5] = {0x10, 'X', 0x00, 0x00, 0x10}; // offset=0 invalid
        u8 dst[16];
        const u32 n = Lz4DecompressBlock(src, sizeof(src), dst, sizeof(dst));
        KASSERT(n == 0, "util/lz4", "zero offset not rejected");
    }
}

} // namespace duetos::util
