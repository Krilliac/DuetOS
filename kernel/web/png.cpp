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

/// Samples per pixel for a supported colour type. Returns 0 for an
/// unsupported subformat — the caller treats 0 as "reject".
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

/// Validates that a (bit_depth, colour_type) pair is one PNG allows.
/// The PNG spec restricts the legal bit depths per colour type:
///   gray (0):        1, 2, 4, 8, 16
///   truecolour (2):  8, 16
///   palette (3):     1, 2, 4, 8
///   gray+alpha (4):  8, 16
///   truecolour+a (6):8, 16
bool BitDepthLegal(u8 color_type, u8 bit_depth)
{
    switch (color_type)
    {
    case kColorGray:
        return bit_depth == 1 || bit_depth == 2 || bit_depth == 4 || bit_depth == 8 || bit_depth == 16;
    case kColorPalette:
        return bit_depth == 1 || bit_depth == 2 || bit_depth == 4 || bit_depth == 8;
    case kColorRgb:
    case kColorGrayAlpha:
    case kColorRgba:
        return bit_depth == 8 || bit_depth == 16;
    default:
        return false;
    }
}

struct Header
{
    u32 width;
    u32 height;
    u8 bit_depth;
    u8 color_type;
    u32 samples;   // samples per pixel (channels)
    u32 bpp;       // filter unit: ceil(bits-per-pixel / 8), min 1
    u64 row_bytes; // raw bytes per scanline (excludes the filter byte)
};

/// Per-decode colour context shared across passes: palette, tRNS,
/// and the header. Keeps the pixel-expansion helper's signature
/// small while staying free of global mutable state.
struct DecodeCtx
{
    const Header* hdr;
    const u8 (*palette)[3];
    const u8* palette_alpha;
    u32 palette_count;
    bool have_trns_color;
    u8 trns_gray;
    u8 trns_r, trns_g, trns_b;
};

/// row_bytes for a scanline of `pixels` pixels at the header's
/// bit-depth and channel count. ceil(pixels * channels * depth / 8).
inline u64 RowBytesFor(const Header& hdr, u64 pixels)
{
    const u64 bits = pixels * u64(hdr.samples) * u64(hdr.bit_depth);
    return (bits + 7u) / 8u;
}

/// Read sample `sample_idx` of pixel `px` from an unfiltered raw
/// scanline `row` (length `row_len` bytes), scaling it to an 8-bit
/// value. Handles 1/2/4/8/16-bit depths. For palette indices (depth
/// <= 8) the caller wants the raw index, not a scaled value — pass
/// `raw_index = true` to get the unscaled sample. Every byte index
/// is bounded against `row_len`; an out-of-range read returns 0,
/// which the palette path rejects downstream.
u32 ReadSample(const u8* row, u64 row_len, const Header& hdr, u64 px, u32 sample_idx, bool raw_index)
{
    const u32 depth = hdr.bit_depth;
    const u64 sample_ordinal = px * u64(hdr.samples) + sample_idx;

    if (depth == 16)
    {
        const u64 byte_off = sample_ordinal * 2u;
        if (byte_off + 1u >= row_len)
            return 0;
        // Downsample 16->8: take the high byte (big-endian sample).
        return row[byte_off];
    }
    if (depth == 8)
    {
        const u64 byte_off = sample_ordinal;
        if (byte_off >= row_len)
            return 0;
        const u32 v = row[byte_off];
        return v;
    }

    // Sub-byte depths (1/2/4): samples are packed MSB-first within
    // each byte, with each scanline starting on a byte boundary.
    const u64 bit_pos = sample_ordinal * u64(depth);
    const u64 byte_off = bit_pos / 8u;
    if (byte_off >= row_len)
        return 0;
    const u32 shift = u32(8u - depth - (bit_pos % 8u));
    const u32 mask = (1u << depth) - 1u;
    const u32 raw = (u32(row[byte_off]) >> shift) & mask;
    if (raw_index)
        return raw;
    // Scale the sub-byte sample up to the full 8-bit range so that
    // e.g. a 1-bit value of 1 becomes 0xFF, a 2-bit 0b10 becomes
    // 0xAA, a 4-bit 0xF becomes 0xFF. The standard scaling is
    // raw * (255 / (2^depth - 1)), which equals replicating the
    // bit pattern across the byte.
    return raw * (255u / mask);
}

/// Expand one pixel (read from unfiltered raw scanline `row`) to
/// RGBA8888 and write it to `dst` (4 bytes). Returns false only for
/// a palette index out of range (a corrupt-input reject). All other
/// colour types always succeed.
bool ExpandPixel(const u8* row, u64 row_len, const DecodeCtx& ctx, u64 px, u8* dst)
{
    const Header& hdr = *ctx.hdr;
    u8 r, g, b, a;
    switch (hdr.color_type)
    {
    case kColorGray:
    {
        const u32 v = ReadSample(row, row_len, hdr, px, 0, false);
        // tRNS for gray compares against the *raw* (unscaled) sample
        // at the source depth; trns_gray is already that raw value.
        const u32 raw = ReadSample(row, row_len, hdr, px, 0, true);
        r = g = b = u8(v);
        a = (ctx.have_trns_color && raw == ctx.trns_gray) ? 0x00 : 0xFF;
        break;
    }
    case kColorRgb:
    {
        const u32 rr = ReadSample(row, row_len, hdr, px, 0, true);
        const u32 gg = ReadSample(row, row_len, hdr, px, 1, true);
        const u32 bb = ReadSample(row, row_len, hdr, px, 2, true);
        r = u8(ReadSample(row, row_len, hdr, px, 0, false));
        g = u8(ReadSample(row, row_len, hdr, px, 1, false));
        b = u8(ReadSample(row, row_len, hdr, px, 2, false));
        a = (ctx.have_trns_color && rr == ctx.trns_r && gg == ctx.trns_g && bb == ctx.trns_b) ? 0x00 : 0xFF;
        break;
    }
    case kColorPalette:
    {
        const u32 idx = ReadSample(row, row_len, hdr, px, 0, true);
        if (idx >= ctx.palette_count)
            return false;
        r = ctx.palette[idx][0];
        g = ctx.palette[idx][1];
        b = ctx.palette[idx][2];
        a = ctx.palette_alpha[idx];
        break;
    }
    case kColorGrayAlpha:
    {
        r = g = b = u8(ReadSample(row, row_len, hdr, px, 0, false));
        a = u8(ReadSample(row, row_len, hdr, px, 1, false));
        break;
    }
    case kColorRgba:
    default:
    {
        r = u8(ReadSample(row, row_len, hdr, px, 0, false));
        g = u8(ReadSample(row, row_len, hdr, px, 1, false));
        b = u8(ReadSample(row, row_len, hdr, px, 2, false));
        a = u8(ReadSample(row, row_len, hdr, px, 3, false));
        break;
    }
    }
    dst[0] = r;
    dst[1] = g;
    dst[2] = b;
    dst[3] = a;
    return true;
}

/// Unfilter `pass_h` scanlines of `pass_w` pixels each, stored
/// contiguously in `scan` (each row prefixed by its 1-byte filter
/// type), then expand each pixel into the final RGBA raster `rgba`
/// at the Adam7-mapped position (x_start + col*x_step,
/// y_start + row*y_step). For the non-interlaced case the caller
/// passes x_start=y_start=0 and x_step=y_step=1, so the mapping is
/// the identity. `scan` is modified in place (defiltered). Returns
/// false on a malformed filter byte or a palette-index reject.
bool ProcessPass(u8* scan, const DecodeCtx& ctx, u32 pass_w, u32 pass_h, u32 x_start, u32 y_start, u32 x_step,
                 u32 y_step, u8* rgba)
{
    const Header& hdr = *ctx.hdr;
    const u32 bpp = hdr.bpp;
    const u64 row_bytes = RowBytesFor(hdr, pass_w);
    const u64 stride = row_bytes + 1; // +1 filter byte per row

    for (u32 sy = 0; sy < pass_h; ++sy)
    {
        const u64 row_off = stride * sy;
        const u8 filter_byte = scan[row_off];
        u8* cur = scan + row_off + 1;
        const u8* prev = (sy > 0) ? (scan + stride * (sy - 1) + 1) : nullptr;

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

        // Expand this sub-image row into the destination raster.
        const u32 dy = y_start + sy * y_step;
        for (u32 sx = 0; sx < pass_w; ++sx)
        {
            const u32 dx = x_start + sx * x_step;
            u8* dst = rgba + (u64(dy) * hdr.width + dx) * 4;
            if (!ExpandPixel(cur, row_bytes, ctx, sx, dst))
                return false;
        }
    }
    return true;
}

// Adam7 interlacing constants: per-pass starting offset and step in
// each axis. Pass i covers pixels (x,y) with x%x_step==x_start and
// y%y_step==y_start.
constexpr u32 kAdam7XStart[7] = {0, 4, 0, 2, 0, 1, 0};
constexpr u32 kAdam7YStart[7] = {0, 0, 4, 0, 2, 0, 1};
constexpr u32 kAdam7XStep[7] = {8, 8, 4, 4, 2, 2, 1};
constexpr u32 kAdam7YStep[7] = {8, 8, 8, 4, 4, 2, 2};

/// Sub-image pixel count along one axis for an Adam7 pass.
/// = number of grid points in [0, full) at stride `step` from
/// `start`, i.e. ceil((full - start) / step) for start < full else 0.
inline u32 Adam7PassExtent(u32 full, u32 start, u32 step)
{
    if (start >= full)
        return 0;
    return (full - start + step - 1) / step;
}

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
        if (compression != 0 || filter_method != 0)
            return false;
        if (interlace != 0 && interlace != 1)
            return false;

        const u32 samples = SamplesPerPixel(hdr.color_type);
        if (samples == 0)
            return false;
        if (!BitDepthLegal(hdr.color_type, hdr.bit_depth))
            return false;
        hdr.samples = samples;
        // Filter unit is ceil(bits-per-pixel / 8), with a one-byte
        // minimum for sub-byte depths (1/2/4-bit pack < 1 byte/pixel).
        const u32 bits_per_pixel = samples * u32(hdr.bit_depth);
        hdr.bpp = (bits_per_pixel + 7u) / 8u;
        // Whole-image scanline length (used for the non-interlaced
        // path and as the inflate-size baseline for interlaced).
        hdr.row_bytes = RowBytesFor(hdr, hdr.width);

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
                    // tRNS stores a 16-bit sample regardless of depth. We
                    // compare against the *raw* sample ReadSample yields:
                    // for 16-bit that's the high byte; for 8 / sub-byte
                    // the low byte holds the actual value.
                    trns_gray = (hdr.bit_depth == 16) ? chunk_data[0] : chunk_data[1];
                    have_trns_color = true;
                }
                else if (hdr.color_type == kColorRgb)
                {
                    if (chunk_len != 6)
                        return false;
                    const u32 lo = (hdr.bit_depth == 16) ? 0u : 1u;
                    trns_r = chunk_data[0 + lo];
                    trns_g = chunk_data[2 + lo];
                    trns_b = chunk_data[4 + lo];
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

        // ----- Compute the exact inflated raw size. Non-interlaced is
        // one image of `height` rows; Adam7 is seven sub-images, each
        // with its own (possibly empty) dimensions. Each row carries a
        // leading filter byte. We sum the per-pass sizes so the
        // exact-length check still gates a corrupt stream.
        const bool interlaced = (interlace == 1);
        u64 scanline_bytes = 0;
        if (!interlaced)
        {
            scanline_bytes = (hdr.row_bytes + 1) * hdr.height;
        }
        else
        {
            for (u32 p = 0; p < 7; ++p)
            {
                const u32 pw = Adam7PassExtent(hdr.width, kAdam7XStart[p], kAdam7XStep[p]);
                const u32 ph = Adam7PassExtent(hdr.height, kAdam7YStart[p], kAdam7YStep[p]);
                if (pw == 0 || ph == 0)
                    continue;
                scanline_bytes += (RowBytesFor(hdr, pw) + 1) * u64(ph);
            }
        }
        if (scanline_bytes == 0 || scanline_bytes > kPngMaxInputBytes)
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

        DecodeCtx ctx{};
        ctx.hdr = &hdr;
        ctx.palette = palette;
        ctx.palette_alpha = palette_alpha;
        ctx.palette_count = palette_count;
        ctx.have_trns_color = have_trns_color;
        ctx.trns_gray = trns_gray;
        ctx.trns_r = trns_r;
        ctx.trns_g = trns_g;
        ctx.trns_b = trns_b;

        // ----- Unfilter + expand. One pass for non-interlaced; seven
        // Adam7 sub-image passes otherwise. ProcessPass defilters a
        // contiguous block of scanlines in place and scatters its pixels
        // into the final raster at the pass's grid positions.
        if (!interlaced)
        {
            if (!ProcessPass(scan, ctx, hdr.width, hdr.height, 0, 0, 1, 1, rgba))
                return false;
        }
        else
        {
            u8* pass_scan = scan;
            for (u32 p = 0; p < 7; ++p)
            {
                const u32 pw = Adam7PassExtent(hdr.width, kAdam7XStart[p], kAdam7XStep[p]);
                const u32 ph = Adam7PassExtent(hdr.height, kAdam7YStart[p], kAdam7YStep[p]);
                if (pw == 0 || ph == 0)
                    continue;
                if (!ProcessPass(pass_scan, ctx, pw, ph, kAdam7XStart[p], kAdam7YStart[p], kAdam7XStep[p],
                                 kAdam7YStep[p], rgba))
                    return false;
                pass_scan += (RowBytesFor(hdr, pw) + 1) * u64(ph);
            }
        }

        out->width = hdr.width;
        out->height = hdr.height;
        out->pixels = rgba;
        return true;
    }
}

} // namespace duetos::web
