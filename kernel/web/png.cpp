#include "web/png.h"

#include "util/crc32.h"
#include "util/deflate.h"

namespace duetos::web
{

namespace
{

inline u32 LoadU32Be(const u8* p)
{
    return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}

constexpr u8 kSignature[kPngSignatureBytes] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

// Colour-type codes (PNG IHDR byte 9).
constexpr u8 kColorGray = 0;
constexpr u8 kColorRgb = 2;
constexpr u8 kColorPalette = 3;
constexpr u8 kColorGrayAlpha = 4;
constexpr u8 kColorRgba = 6;

bool TagEq(const u8* p, const char* tag)
{
    return p[0] == u8(tag[0]) && p[1] == u8(tag[1]) && p[2] == u8(tag[2]) && p[3] == u8(tag[3]);
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

/// Samples per pixel for a supported 8-bit colour type. Returns 0
/// for an unsupported / interlaced / non-8-bit subformat — the
/// caller treats 0 as "reject".
u32 SamplesPerPixel(u8 color_type)
{
    switch (color_type)
    {
    case kColorGray:
        return 1;
    case kColorRgb:
        return 3;
    case kColorPalette:
        return 1; // one palette index per pixel
    case kColorGrayAlpha:
        return 2;
    case kColorRgba:
        return 4;
    default:
        return 0;
    }
}

struct Header
{
    u32 width;
    u32 height;
    u8 bit_depth;
    u8 color_type;
    u32 bpp;       // filter unit: bytes per pixel of the *raw* sample stream
    u64 row_bytes; // raw bytes per scanline (excludes the filter byte)
};

} // namespace

bool PngDecode(const u8* data, u32 len, PngArena& arena, PngImage* out)
{
    if (data == nullptr || out == nullptr)
        return false;
    if (len < kPngSignatureBytes + 8 + 13 + 4 || len > kPngMaxInputBytes)
        return false;

    // ----- Signature.
    for (u32 i = 0; i < kPngSignatureBytes; ++i)
    {
        if (data[i] != kSignature[i])
            return false;
    }

    // ----- IHDR must be the first chunk, length 13.
    u32 off = kPngSignatureBytes;
    if (LoadU32Be(data + off) != 13 || !TagEq(data + off + 4, "IHDR"))
        return false;
    {
        const u8* ihdr = data + off + 8;
        const u32 stored_crc = LoadU32Be(data + off + 8 + 13);
        if (util::Crc32(data + off + 4, 4 + 13) != stored_crc)
            return false;

        Header hdr{};
        hdr.width = LoadU32Be(ihdr + 0);
        hdr.height = LoadU32Be(ihdr + 4);
        hdr.bit_depth = ihdr[8];
        hdr.color_type = ihdr[9];
        const u8 compression = ihdr[10];
        const u8 filter_method = ihdr[11];
        const u8 interlace = ihdr[12];

        if (hdr.width == 0 || hdr.height == 0)
            return false;
        if (hdr.width > kPngMaxDimension || hdr.height > kPngMaxDimension)
            return false;
        // GAP: 16-bit and sub-byte depths unimplemented — only 8-bit.
        if (hdr.bit_depth != 8)
            return false;
        if (compression != 0 || filter_method != 0)
            return false;
        // GAP: Adam7 interlacing unimplemented — reject interlaced.
        if (interlace != 0)
            return false;

        const u32 samples = SamplesPerPixel(hdr.color_type);
        if (samples == 0)
            return false;
        hdr.bpp = samples; // 8-bit -> one byte per sample
        hdr.row_bytes = u64(hdr.width) * hdr.bpp;

        off += 8 + 13 + 4; // advance past IHDR

        // ----- Walk remaining chunks: collect PLTE, tRNS, IDAT; stop at IEND.
        // The concatenated IDAT bytes and the palette/tRNS tables all
        // come out of the arena. We size IDAT staging at the input
        // length (a safe upper bound on summed IDAT payloads).
        u8* idat_buf = arena.Alloc(len);
        if (idat_buf == nullptr)
            return false;
        u32 idat_len = 0;

        u8 palette[256][3] = {};
        u8 palette_alpha[256];
        u32 palette_count = 0;
        bool have_palette = false;
        // tRNS for non-palette types: a single transparent sample value.
        bool have_trns_color = false;
        u8 trns_gray = 0;
        u8 trns_r = 0, trns_g = 0, trns_b = 0;
        for (u32 i = 0; i < 256; ++i)
            palette_alpha[i] = 0xFF;

        bool seen_iend = false;
        while (!seen_iend)
        {
            if (u64(off) + 8 > len)
                return false;
            const u32 chunk_len = LoadU32Be(data + off);
            const u8* type_ptr = data + off + 4;
            const u8* chunk_data = data + off + 8;
            if (chunk_len > kPngMaxInputBytes)
                return false;
            if (u64(off) + 8 + chunk_len + 4 > u64(len))
                return false;
            const u32 stored = LoadU32Be(data + off + 8 + chunk_len);
            if (util::Crc32(type_ptr, 4 + chunk_len) != stored)
                return false;

            if (TagEq(type_ptr, "PLTE"))
            {
                if (chunk_len == 0 || chunk_len % 3 != 0 || chunk_len > 256 * 3)
                    return false;
                palette_count = chunk_len / 3;
                for (u32 e = 0; e < palette_count; ++e)
                {
                    palette[e][0] = chunk_data[e * 3 + 0];
                    palette[e][1] = chunk_data[e * 3 + 1];
                    palette[e][2] = chunk_data[e * 3 + 2];
                }
                have_palette = true;
            }
            else if (TagEq(type_ptr, "tRNS"))
            {
                if (hdr.color_type == kColorPalette)
                {
                    // One alpha byte per palette entry; entries past the
                    // tRNS length stay fully opaque.
                    if (chunk_len > 256)
                        return false;
                    for (u32 e = 0; e < chunk_len; ++e)
                        palette_alpha[e] = chunk_data[e];
                }
                else if (hdr.color_type == kColorGray)
                {
                    if (chunk_len != 2)
                        return false;
                    // 16-bit value; low byte is the 8-bit sample.
                    trns_gray = chunk_data[1];
                    have_trns_color = true;
                }
                else if (hdr.color_type == kColorRgb)
                {
                    if (chunk_len != 6)
                        return false;
                    trns_r = chunk_data[1];
                    trns_g = chunk_data[3];
                    trns_b = chunk_data[5];
                    have_trns_color = true;
                }
                // tRNS on RGBA / GrayAlpha is illegal; ignore tolerantly.
            }
            else if (TagEq(type_ptr, "IDAT"))
            {
                if (idat_len > len - chunk_len)
                    return false;
                for (u32 b = 0; b < chunk_len; ++b)
                    idat_buf[idat_len + b] = chunk_data[b];
                idat_len += chunk_len;
            }
            else if (TagEq(type_ptr, "IEND"))
            {
                if (chunk_len != 0)
                    return false;
                seen_iend = true;
            }
            // Every other (ancillary) chunk is walked past tolerantly.

            off += 8 + chunk_len + 4;
        }

        if (idat_len == 0)
            return false;
        if (hdr.color_type == kColorPalette && !have_palette)
            return false;

        // ----- Inflate the zlib-wrapped IDAT. Skip the 2-byte zlib
        // header (CMF + FLG) and the optional 4-byte FDICT (FLG bit 5);
        // feed the DEFLATE body to DeflateInflate. The trailing Adler-32
        // is not re-verified — DEFLATE's own structural checks plus the
        // exact-length check below reject a corrupt stream.
        if (idat_len < 2)
            return false;
        const u8 cmf = idat_buf[0];
        const u8 flg = idat_buf[1];
        // Validate zlib header: CM=8 (deflate), window <= 32K, checksum.
        if ((cmf & 0x0F) != 8)
            return false;
        if (((u32(cmf) << 8) | flg) % 31 != 0)
            return false;
        u32 deflate_off = 2;
        if (flg & 0x20) // FDICT — preset dictionary, 4-byte DICTID follows.
        {
            if (idat_len < 6)
                return false;
            deflate_off = 6;
        }

        const u64 scanline_bytes = (hdr.row_bytes + 1) * hdr.height; // +1 filter byte/row
        if (scanline_bytes > kPngMaxInputBytes)
            return false;
        u8* scan = arena.Alloc(u32(scanline_bytes));
        if (scan == nullptr)
            return false;

        const auto inflated =
            util::DeflateInflate(idat_buf + deflate_off, idat_len - deflate_off, scan, u32(scanline_bytes));
        if (!inflated.has_value() || u64(inflated.value()) != scanline_bytes)
            return false;

        // ----- Allocate the RGBA output.
        const u64 rgba_bytes = u64(hdr.width) * hdr.height * 4;
        if (rgba_bytes > kPngMaxInputBytes)
            return false;
        u8* rgba = arena.Alloc(u32(rgba_bytes));
        if (rgba == nullptr)
            return false;

        // ----- Unfilter scanlines in place, then expand to RGBA.
        const u32 bpp = hdr.bpp;
        const u64 row_bytes = hdr.row_bytes;
        for (u32 y = 0; y < hdr.height; ++y)
        {
            const u64 row_off = (row_bytes + 1) * y;
            const u8 filter_byte = scan[row_off];
            u8* cur = scan + row_off + 1;
            const u8* prev = (y > 0) ? (scan + (row_bytes + 1) * (y - 1) + 1) : nullptr;

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

            // Expand the now-unfiltered raw samples into RGBA.
            u8* drow = rgba + u64(y) * hdr.width * 4;
            for (u32 x = 0; x < hdr.width; ++x)
            {
                const u8* s = cur + u64(x) * bpp;
                u8 r, g, b, a;
                switch (hdr.color_type)
                {
                case kColorGray:
                {
                    r = g = b = s[0];
                    a = (have_trns_color && s[0] == trns_gray) ? 0x00 : 0xFF;
                    break;
                }
                case kColorRgb:
                {
                    r = s[0];
                    g = s[1];
                    b = s[2];
                    a = (have_trns_color && s[0] == trns_r && s[1] == trns_g && s[2] == trns_b) ? 0x00 : 0xFF;
                    break;
                }
                case kColorPalette:
                {
                    const u32 idx = s[0];
                    if (idx >= palette_count)
                        return false;
                    r = palette[idx][0];
                    g = palette[idx][1];
                    b = palette[idx][2];
                    a = palette_alpha[idx];
                    break;
                }
                case kColorGrayAlpha:
                {
                    r = g = b = s[0];
                    a = s[1];
                    break;
                }
                case kColorRgba:
                default:
                {
                    r = s[0];
                    g = s[1];
                    b = s[2];
                    a = s[3];
                    break;
                }
                }
                drow[x * 4 + 0] = r;
                drow[x * 4 + 1] = g;
                drow[x * 4 + 2] = b;
                drow[x * 4 + 3] = a;
            }
        }

        out->width = hdr.width;
        out->height = hdr.height;
        out->pixels = rgba;
        return true;
    }
}

} // namespace duetos::web
