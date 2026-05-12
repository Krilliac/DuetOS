#include "util/png.h"

#include "core/panic.h"
#include "img_meta_rust.h"
#include "util/adler32.h"
#include "util/crc32.h"
#include "util/gzip.h"

namespace duetos::util
{

namespace
{

inline u32 LoadU32Be(const u8* p)
{
    return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}

constexpr u8 kSignature[kPngSignatureBytes] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

constexpr u8 kColorTypeRgba = 6;

bool TagEq(const u8* p, const char* tag)
{
    return p[0] == u8(tag[0]) && p[1] == u8(tag[1]) && p[2] == u8(tag[2]) && p[3] == u8(tag[3]);
}

bool VerifyChunkCrc(const u8* type_and_data, u32 type_and_data_len, u32 stored_crc)
{
    return Crc32(type_and_data, type_and_data_len) == stored_crc;
}

inline u8 PaethPredictor(u8 a, u8 b, u8 c)
{
    const i32 p = i32(a) + i32(b) - i32(c);
    const i32 pa = (p >= a) ? (p - a) : (a - p);
    const i32 pb = (p >= b) ? (p - b) : (b - p);
    const i32 pc = (p >= c) ? (p - c) : (c - p);
    if (pa <= pb && pa <= pc)
        return a;
    if (pb <= pc)
        return b;
    return c;
}

} // namespace

PngInfo PngParseHeader(const u8* src, u32 src_len)
{
    // Validation lives in the Rust crate `duetos_img_meta` — same
    // bounds-checked walker, CRC32 verification, dimension /
    // bit-depth / colour-type / compress / filter / interlace
    // gates. C++ wrapper does field-by-field copy on the way out
    // so layout drift between Rust and C++ can't silently break.
    PngInfo info = {};
    img_meta::DuetosPngInfo r{};
    if (!img_meta::duetos_img_meta_parse_png(src, static_cast<usize>(src_len), &r))
        return info;
    info.width = r.width;
    info.height = r.height;
    info.bit_depth = r.bit_depth;
    info.color_type = r.color_type;
    info.ok = (r.ok != 0);
    return info;
}

bool PngDecode(const u8* src, u32 src_len, const PngInfo& info, u8* scratch, u32 scratch_cap, u32* out_pixels)
{
    if (!info.ok)
        return false;
    const u32 bpp = (info.color_type == kColorTypeRgba) ? 4u : 3u;
    const u64 row_bytes = u64(info.width) * bpp;
    const u64 filtered_bytes = (row_bytes + 1) * info.height; // +1 filter byte per row
    if (filtered_bytes > scratch_cap)
        return false;

    // Walk chunks. Concatenate IDAT bytes into the tail of `scratch`
    // (above the filtered-scanlines region we'll fill on inflate).
    u8* idat_buf = scratch + filtered_bytes;
    const u32 idat_cap = scratch_cap - u32(filtered_bytes);
    u32 idat_len = 0;
    bool seen_iend = false;

    u32 off = kPngSignatureBytes + 8 + 13 + 4; // past IHDR
    while (!seen_iend)
    {
        if (off + 8 > src_len)
            return false;
        const u32 chunk_len = LoadU32Be(src + off);
        const u8* type_ptr = src + off + 4;
        const u8* data_ptr = src + off + 8;
        if (u64(off) + 8 + chunk_len + 4 > u64(src_len))
            return false;
        const u32 stored_crc = LoadU32Be(src + off + 8 + chunk_len);
        if (!VerifyChunkCrc(type_ptr, 4 + chunk_len, stored_crc))
            return false;

        if (TagEq(type_ptr, "IDAT"))
        {
            if (idat_len + chunk_len > idat_cap)
                return false;
            for (u32 i = 0; i < chunk_len; ++i)
                idat_buf[idat_len + i] = data_ptr[i];
            idat_len += chunk_len;
        }
        else if (TagEq(type_ptr, "IEND"))
        {
            if (chunk_len != 0)
                return false;
            seen_iend = true;
        }
        // Every other chunk is walked past tolerantly.
        off += 8 + chunk_len + 4;
    }

    if (idat_len == 0)
        return false;

    // Inflate the concatenated IDAT through the zlib wrapper. Output
    // lands in the low end of scratch, ahead of the IDAT bytes.
    const u32 produced = ZlibInflate(idat_buf, idat_len, scratch, u32(filtered_bytes));
    if (u64(produced) != filtered_bytes)
        return false;

    // Unfilter scanlines in place, then convert to BGRA8888.
    for (u32 y = 0; y < info.height; ++y)
    {
        const u64 row_off = (row_bytes + 1) * y;
        const u8 filter_byte = scratch[row_off];
        u8* cur = scratch + row_off + 1;
        const u8* prev = (y > 0) ? (scratch + (row_bytes + 1) * (y - 1) + 1) : nullptr;

        switch (filter_byte)
        {
        case 0: // None
            break;
        case 1: // Sub
            for (u64 i = bpp; i < row_bytes; ++i)
                cur[i] = u8(cur[i] + cur[i - bpp]);
            break;
        case 2: // Up
            if (prev != nullptr)
            {
                for (u64 i = 0; i < row_bytes; ++i)
                    cur[i] = u8(cur[i] + prev[i]);
            }
            break;
        case 3: // Average
            for (u64 i = 0; i < row_bytes; ++i)
            {
                const u32 left = (i >= bpp) ? cur[i - bpp] : 0;
                const u32 up = (prev != nullptr) ? prev[i] : 0;
                cur[i] = u8(cur[i] + u8((left + up) / 2));
            }
            break;
        case 4: // Paeth
            for (u64 i = 0; i < row_bytes; ++i)
            {
                const u8 left = (i >= bpp) ? cur[i - bpp] : 0;
                const u8 up = (prev != nullptr) ? prev[i] : 0;
                const u8 ul = (prev != nullptr && i >= bpp) ? prev[i - bpp] : 0;
                cur[i] = u8(cur[i] + PaethPredictor(left, up, ul));
            }
            break;
        default:
            return false;
        }

        // Pack into BGRA8888 (low byte = B). PNG stores RGB or RGBA
        // big-endian-per-channel, so a straightforward channel swap.
        u32* drow = out_pixels + u64(y) * info.width;
        for (u32 x = 0; x < info.width; ++x)
        {
            const u8* p = cur + u64(x) * bpp;
            const u32 r = p[0];
            const u32 g = p[1];
            const u32 b = p[2];
            const u32 a = (bpp == 4) ? p[3] : 0xFFu;
            drow[x] = b | (g << 8) | (r << 16) | (a << 24);
        }
    }
    return true;
}

namespace
{

// Test-fixture builder: produce a 2×2 RGBA PNG with hand-picked
// pixels using our in-tree CRC32, Adler32, and a hand-built
// stored DEFLATE block. Decoding this through PngDecode must
// reproduce the same pixels.
void StoreU32Be(u8* p, u32 v)
{
    p[0] = u8(v >> 24);
    p[1] = u8(v >> 16);
    p[2] = u8(v >> 8);
    p[3] = u8(v);
}

// Build a 2×2 RGBA PNG with these top-down pixels:
//   (0,0) = red    FF 00 00 FF
//   (1,0) = green  00 FF 00 FF
//   (0,1) = blue   00 00 FF FF
//   (1,1) = white  FF FF FF FF
// All filter bytes = 0 (None). Returns total byte length.
u32 BuildFixturePng(u8 buf[256])
{
    for (u32 i = 0; i < 256; ++i)
        buf[i] = 0;
    // Signature.
    for (u32 i = 0; i < kPngSignatureBytes; ++i)
        buf[i] = kSignature[i];
    u32 off = 8;

    // IHDR (13 bytes).
    StoreU32Be(buf + off, 13);
    off += 4;
    buf[off + 0] = 'I';
    buf[off + 1] = 'H';
    buf[off + 2] = 'D';
    buf[off + 3] = 'R';
    StoreU32Be(buf + off + 4, 2); // width
    StoreU32Be(buf + off + 8, 2); // height
    buf[off + 12] = 8;            // bit_depth
    buf[off + 13] = kColorTypeRgba;
    buf[off + 14] = 0; // compress
    buf[off + 15] = 0; // filter
    buf[off + 16] = 0; // interlace
    const u32 ihdr_crc = Crc32(buf + off, 4 + 13);
    StoreU32Be(buf + off + 4 + 13, ihdr_crc);
    off += 4 + 13 + 4;

    // Filtered scanlines for IDAT input — 2 rows × (1 filter byte +
    // 4 px × 4 bytes) = 18 bytes.
    u8 raw[18];
    raw[0] = 0; // filter None
    // (0,0) red, (1,0) green
    raw[1] = 0xFF;
    raw[2] = 0x00;
    raw[3] = 0x00;
    raw[4] = 0xFF;
    raw[5] = 0x00;
    raw[6] = 0xFF;
    raw[7] = 0x00;
    raw[8] = 0xFF;
    raw[9] = 0; // filter None
    // (0,1) blue, (1,1) white
    raw[10] = 0x00;
    raw[11] = 0x00;
    raw[12] = 0xFF;
    raw[13] = 0xFF;
    raw[14] = 0xFF;
    raw[15] = 0xFF;
    raw[16] = 0xFF;
    raw[17] = 0xFF;

    // Wrap in a stored DEFLATE block + zlib envelope:
    //   zlib header: 78 01 (CMF=8, FLG=1; (CMF*256+FLG) % 31 == 0)
    //   DEFLATE final stored block: 01 LEN(LE) ~LEN(LE) <raw>
    //   zlib trailer: Adler-32 big-endian
    u8 idat_data[2 + 5 + 18 + 4];
    idat_data[0] = 0x78;
    idat_data[1] = 0x01;
    idat_data[2] = 0x01;   // BFINAL=1, BTYPE=00 (stored)
    idat_data[3] = u8(18); // LEN low
    idat_data[4] = u8(18 >> 8);
    idat_data[5] = u8(~18);
    idat_data[6] = u8((~18) >> 8);
    for (u32 i = 0; i < 18; ++i)
        idat_data[7 + i] = raw[i];
    const u32 adler = Adler32(raw, 18);
    idat_data[2 + 5 + 18 + 0] = u8(adler >> 24);
    idat_data[2 + 5 + 18 + 1] = u8(adler >> 16);
    idat_data[2 + 5 + 18 + 2] = u8(adler >> 8);
    idat_data[2 + 5 + 18 + 3] = u8(adler);

    // IDAT chunk.
    StoreU32Be(buf + off, sizeof(idat_data));
    off += 4;
    buf[off + 0] = 'I';
    buf[off + 1] = 'D';
    buf[off + 2] = 'A';
    buf[off + 3] = 'T';
    for (u32 i = 0; i < sizeof(idat_data); ++i)
        buf[off + 4 + i] = idat_data[i];
    const u32 idat_crc = Crc32(buf + off, 4 + sizeof(idat_data));
    StoreU32Be(buf + off + 4 + sizeof(idat_data), idat_crc);
    off += 4 + sizeof(idat_data) + 4;

    // IEND chunk (length 0).
    StoreU32Be(buf + off, 0);
    off += 4;
    buf[off + 0] = 'I';
    buf[off + 1] = 'E';
    buf[off + 2] = 'N';
    buf[off + 3] = 'D';
    const u32 iend_crc = Crc32(buf + off, 4);
    StoreU32Be(buf + off + 4, iend_crc);
    off += 4 + 4;
    return off;
}

} // namespace

void PngSelfTest()
{
    // ----- Happy path: build a 2×2 RGBA PNG fixture, parse,
    // decode, verify every pixel.
    {
        u8 src[256];
        const u32 src_len = BuildFixturePng(src);
        const PngInfo info = PngParseHeader(src, src_len);
        KASSERT(info.ok && info.width == 2 && info.height == 2 && info.bit_depth == 8 &&
                    info.color_type == kColorTypeRgba,
                "util/png", "header parse wrong");

        u8 scratch[64];
        u32 pixels[4];
        const bool ok = PngDecode(src, src_len, info, scratch, sizeof(scratch), pixels);
        KASSERT(ok, "util/png", "decode failed");
        // Expected BGRA-packed (low byte = B, high byte = A):
        //   red   = 0xFFFF0000
        //   green = 0xFF00FF00
        //   blue  = 0xFF0000FF
        //   white = 0xFFFFFFFF
        KASSERT(pixels[0] == 0xFFFF0000u, "util/png", "pixel(0,0) wrong");
        KASSERT(pixels[1] == 0xFF00FF00u, "util/png", "pixel(1,0) wrong");
        KASSERT(pixels[2] == 0xFF0000FFu, "util/png", "pixel(0,1) wrong");
        KASSERT(pixels[3] == 0xFFFFFFFFu, "util/png", "pixel(1,1) wrong");
    }

    // ----- Negative: bad signature.
    {
        u8 src[256];
        const u32 src_len = BuildFixturePng(src);
        src[0] = 0x88;
        const PngInfo info = PngParseHeader(src, src_len);
        KASSERT(!info.ok, "util/png", "bad signature not rejected");
    }

    // ----- Negative: unsupported colour type (palette = 3).
    {
        u8 src[256];
        const u32 src_len = BuildFixturePng(src);
        // Patch IHDR's color_type to 3. Need to recompute IHDR CRC.
        const u32 ihdr_data_off = 12;
        src[ihdr_data_off + 4 + 9] = 3; // ihdr.data[9] is color_type
        const u32 new_crc = Crc32(src + ihdr_data_off, 4 + 13);
        StoreU32Be(src + ihdr_data_off + 4 + 13, new_crc);
        const PngInfo info = PngParseHeader(src, src_len);
        KASSERT(!info.ok, "util/png", "palette color type not rejected");
    }

    // ----- Negative: IHDR CRC tamper.
    {
        u8 src[256];
        const u32 src_len = BuildFixturePng(src);
        src[12 + 4 + 13] ^= 0xFF; // flip a CRC byte
        const PngInfo info = PngParseHeader(src, src_len);
        KASSERT(!info.ok, "util/png", "IHDR CRC tamper not rejected");
    }

    // ----- Negative: scratch too small.
    {
        u8 src[256];
        const u32 src_len = BuildFixturePng(src);
        const PngInfo info = PngParseHeader(src, src_len);
        KASSERT(info.ok, "util/png", "header should parse");
        u8 scratch[8];
        u32 pixels[4];
        KASSERT(!PngDecode(src, src_len, info, scratch, sizeof(scratch), pixels), "util/png",
                "scratch overflow not rejected");
    }
}

} // namespace duetos::util
