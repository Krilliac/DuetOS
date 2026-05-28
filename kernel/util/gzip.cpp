#include "util/gzip.h"

#include "core/panic.h"
#include "util/adler32.h"
#include "util/crc32.h"
#include "util/deflate.h"

namespace duetos::util
{

namespace
{

constexpr u8 kGzipId1 = 0x1F;
constexpr u8 kGzipId2 = 0x8B;
constexpr u8 kGzipCmDeflate = 0x08;

constexpr u8 kGzipFlagFHcrc = 0x02;
constexpr u8 kGzipFlagFExtra = 0x04;
constexpr u8 kGzipFlagFName = 0x08;
constexpr u8 kGzipFlagFComment = 0x10;

inline u32 LoadU32Le(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

} // namespace

u32 GzipInflate(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    if (src_len < 18) // 10-byte header + 8-byte trailer
        return 0;
    if (src[0] != kGzipId1 || src[1] != kGzipId2)
        return 0;
    if (src[2] != kGzipCmDeflate)
        return 0;
    const u8 flg = src[3];
    // src[4..7] mtime, src[8] xfl, src[9] os.

    u32 off = 10;
    if (flg & kGzipFlagFExtra)
    {
        if (off + 2 > src_len)
            return 0;
        const u32 xlen = u32(src[off]) | (u32(src[off + 1]) << 8);
        off += 2;
        if (off + xlen > src_len)
            return 0;
        off += xlen;
    }
    if (flg & kGzipFlagFName)
    {
        while (off < src_len && src[off] != 0)
            ++off;
        if (off >= src_len)
            return 0;
        ++off; // skip NUL
    }
    if (flg & kGzipFlagFComment)
    {
        while (off < src_len && src[off] != 0)
            ++off;
        if (off >= src_len)
            return 0;
        ++off; // skip NUL
    }
    if (flg & kGzipFlagFHcrc)
    {
        if (off + 2 > src_len)
            return 0;
        // We accept the 16-bit header CRC blindly — verifying it
        // duplicates work the bulk CRC-32 already does.
        off += 2;
    }
    if (off + 8 > src_len)
        return 0;

    const u32 deflate_len = src_len - off - 8;
    const auto inflated = DeflateInflate(src + off, deflate_len, dst, dst_cap);
    if (!inflated.has_value())
        return 0;
    const u32 produced = inflated.value();
    // Trailer: CRC-32 (LE) + ISIZE (LE).
    const u8* trailer = src + src_len - 8;
    const u32 want_crc = LoadU32Le(trailer + 0);
    const u32 want_isize = LoadU32Le(trailer + 4);
    if (produced != want_isize)
        return 0;
    const u32 actual_crc = Crc32(dst, produced);
    if (actual_crc != want_crc)
        return 0;
    return produced;
}

u32 ZlibInflate(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    if (src_len < 6) // 2-byte header + 4-byte Adler tail
        return 0;
    const u8 cmf = src[0];
    const u8 flg = src[1];
    if ((cmf & 0x0F) != 0x08) // CM = DEFLATE
        return 0;
    if ((cmf & 0xF0) > 0x70) // CINFO ≤ 7 → window ≤ 32 KiB
        return 0;
    if ((u32(cmf) * 256u + u32(flg)) % 31u != 0)
        return 0;
    if (flg & 0x20) // FDICT — preset dictionary not supported in v0
        return 0;

    const u32 deflate_len = src_len - 2 - 4;
    const auto inflated = DeflateInflate(src + 2, deflate_len, dst, dst_cap);
    if (!inflated.has_value())
        return 0;
    const u32 produced = inflated.value();

    const u8* tail = src + src_len - 4;
    // Adler-32 stored big-endian.
    const u32 want_adler = (u32(tail[0]) << 24) | (u32(tail[1]) << 16) | (u32(tail[2]) << 8) | u32(tail[3]);
    const u32 actual_adler = Adler32(dst, produced);
    if (actual_adler != want_adler)
        return 0;
    return produced;
}

namespace
{

// Build a minimal valid GZIP wrapper around a stored-block "Hello"
// payload. The header is the canonical 10-byte form (no flags),
// then the type-0 stored block we already used in DeflateSelfTest,
// then CRC32("Hello") + 5 (uncompressed size).
u32 BuildGzipFixture(u8 buf[64])
{
    for (u32 i = 0; i < 64; ++i)
        buf[i] = 0;
    buf[0] = kGzipId1;
    buf[1] = kGzipId2;
    buf[2] = kGzipCmDeflate;
    buf[3] = 0; // flags
    // mtime / xfl / os left zero.
    buf[9] = 0xFF; // OS = unknown
    // DEFLATE payload (final stored block "Hello"):
    buf[10] = 0x01; // BFINAL=1, BTYPE=00
    buf[11] = 0x05;
    buf[12] = 0x00;
    buf[13] = 0xFA;
    buf[14] = 0xFF;
    buf[15] = 'H';
    buf[16] = 'e';
    buf[17] = 'l';
    buf[18] = 'l';
    buf[19] = 'o';
    // Trailer CRC-32 (LE) + ISIZE (LE).
    const u8 hello[5] = {'H', 'e', 'l', 'l', 'o'};
    const u32 crc = Crc32(hello, 5);
    buf[20] = u8(crc);
    buf[21] = u8(crc >> 8);
    buf[22] = u8(crc >> 16);
    buf[23] = u8(crc >> 24);
    buf[24] = 5;
    buf[25] = 0;
    buf[26] = 0;
    buf[27] = 0;
    return 28;
}

u32 BuildZlibFixture(u8 buf[64])
{
    for (u32 i = 0; i < 64; ++i)
        buf[i] = 0;
    // CMF: CM=8 (deflate), CINFO=7 (32 KiB window) → 0x78.
    // FLG: choose lowest bits so that (CMF*256 + FLG) % 31 == 0.
    // 0x78*256 = 30720. 30720 % 31 = 30720 - 31*991 = 30720 - 30721 = -1 → 30. So FLG must give residue 1 mod 31.
    // FLG byte's low 5 bits encode FCHECK such that the total is divisible by 31.
    // 30720 + FLG ≡ 0 (mod 31). 30720 mod 31 = 30, so FLG mod 31 = 1. FLG = 0x01 works.
    buf[0] = 0x78;
    buf[1] = 0x01;
    // DEFLATE stored "Hello".
    buf[2] = 0x01;
    buf[3] = 0x05;
    buf[4] = 0x00;
    buf[5] = 0xFA;
    buf[6] = 0xFF;
    buf[7] = 'H';
    buf[8] = 'e';
    buf[9] = 'l';
    buf[10] = 'l';
    buf[11] = 'o';
    // Adler-32(Hello) big-endian.
    const u8 hello[5] = {'H', 'e', 'l', 'l', 'o'};
    const u32 adler = Adler32(hello, 5);
    buf[12] = u8(adler >> 24);
    buf[13] = u8(adler >> 16);
    buf[14] = u8(adler >> 8);
    buf[15] = u8(adler);
    return 16;
}

} // namespace

void GzipZlibSelfTest()
{
    // ----- GZIP happy path.
    {
        u8 src[64];
        const u32 n = BuildGzipFixture(src);
        u8 out[16];
        const u32 produced = GzipInflate(src, n, out, sizeof(out));
        KASSERT(produced == 5, "util/gzip", "GZIP inflate length wrong");
        const char want[5] = {'H', 'e', 'l', 'l', 'o'};
        for (u32 i = 0; i < 5; ++i)
            KASSERT(out[i] == u8(want[i]), "util/gzip", "GZIP content wrong");
    }
    // ----- GZIP CRC tamper rejection.
    {
        u8 src[64];
        const u32 n = BuildGzipFixture(src);
        src[20] ^= 0xFF; // flip a CRC byte
        u8 out[16];
        const u32 produced = GzipInflate(src, n, out, sizeof(out));
        KASSERT(produced == 0, "util/gzip", "GZIP CRC tamper not rejected");
    }
    // ----- GZIP ISIZE mismatch rejection.
    {
        u8 src[64];
        const u32 n = BuildGzipFixture(src);
        src[24] = 99; // claim 99 bytes; actual is 5
        u8 out[16];
        const u32 produced = GzipInflate(src, n, out, sizeof(out));
        KASSERT(produced == 0, "util/gzip", "GZIP ISIZE mismatch not rejected");
    }

    // ----- zlib happy path.
    {
        u8 src[32];
        const u32 n = BuildZlibFixture(src);
        u8 out[16];
        const u32 produced = ZlibInflate(src, n, out, sizeof(out));
        KASSERT(produced == 5, "util/zlib", "zlib inflate length wrong");
        for (u32 i = 0; i < 5; ++i)
            KASSERT(out[i] == u8("Hello"[i]), "util/zlib", "zlib content wrong");
    }
    // ----- zlib FCHECK mismatch.
    {
        u8 src[32];
        const u32 n = BuildZlibFixture(src);
        src[1] = 0x02; // breaks the (CMF*256 + FLG) % 31 == 0 invariant
        u8 out[16];
        const u32 produced = ZlibInflate(src, n, out, sizeof(out));
        KASSERT(produced == 0, "util/zlib", "zlib FCHECK mismatch not rejected");
    }
    // ----- zlib Adler tamper.
    {
        u8 src[32];
        const u32 n = BuildZlibFixture(src);
        src[12] ^= 0xFF;
        u8 out[16];
        const u32 produced = ZlibInflate(src, n, out, sizeof(out));
        KASSERT(produced == 0, "util/zlib", "zlib Adler tamper not rejected");
    }
}

} // namespace duetos::util
