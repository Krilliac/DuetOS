#include "util/tga.h"

#include "core/panic.h"
#include "img_meta_rust.h"
#include "util/result.h"

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

namespace duetos::util
{

namespace
{

// Layout-byte offsets used by `TgaWriteHeader32` + `BuildFixture32Bpp`
// below. The parser side of these constants now lives in
// kernel/util/img_meta_rust/src/lib.rs.
constexpr u32 kHdrImageType = 2;
constexpr u32 kHdrImageWidth = 12;
constexpr u32 kHdrImageHeight = 14;
constexpr u32 kHdrPixelDepth = 16;
constexpr u32 kHdrImageDescriptor = 17;
constexpr u32 kImageTypeUncompressedTrueColor = 2;
constexpr u8 kDescriptorOriginTop = 0x20;

} // namespace

TgaInfo TgaParseHeader(const u8* hdr)
{
    // Validation lives in the Rust crate `duetos_img_meta` —
    // bounds-checked walker, image-type / colormap / pixel-depth /
    // dimension gates, descriptor-bit decode. C++ wrapper does
    // field-by-field copy on the way out so layout drift between
    // Rust and C++ can't silently break callers. The historic C++
    // signature took no length parameter and assumed `hdr` carried
    // at least 18 bytes; we pass kTgaHeaderBytes down to the Rust
    // crate so a future shorter-than-expected caller still gets a
    // clean failure rather than reading uninit memory.
    TgaInfo info = {};
    img_meta::DuetosTgaInfo r{};
    if (!img_meta::duetos_img_meta_parse_tga(hdr, static_cast<usize>(kTgaHeaderBytes), &r))
        return info;
    info.width = r.width;
    info.height = r.height;
    info.bpp = r.bpp;
    info.image_type = r.image_type;
    info.pixel_offset = r.pixel_offset;
    info.top_down = (r.top_down != 0);
    info.right_to_left = (r.right_to_left != 0);
    info.ok = (r.ok != 0);
    return info;
}

Result<void> TgaDecodeUncompressed(const u8* src, u32 src_len, const TgaInfo& info, u32* out_pixels)
{
    if (!info.ok)
        return Err{ErrorCode::InvalidArgument};
    if (info.image_type != kImageTypeUncompressedTrueColor)
        return Err{ErrorCode::Unsupported};

    const u32 bytes_per_pixel = info.bpp / 8;
    const u64 pixel_bytes = u64(info.width) * info.height * bytes_per_pixel;
    if (u64(info.pixel_offset) + pixel_bytes > u64(src_len))
        return Err{ErrorCode::Truncated};

    const u8* pix = src + info.pixel_offset;
    const u32 w = info.width;
    const u32 h = info.height;

    for (u32 y = 0; y < h; ++y)
    {
        // Bottom-up source: spec stores row 0 at the bottom of the
        // image (descriptor bit 5 clear). Flip so output is always
        // top-down.
        const u32 src_row = info.top_down ? y : (h - 1 - y);
        const u8* row = pix + u64(src_row) * w * bytes_per_pixel;
        u32* dst_row = out_pixels + u64(y) * w;
        for (u32 x = 0; x < w; ++x)
        {
            // Left-to-right when the right-to-left bit is clear.
            const u32 src_col = info.right_to_left ? (w - 1 - x) : x;
            const u8* p = row + u64(src_col) * bytes_per_pixel;
            const u32 b = p[0];
            const u32 g = p[1];
            const u32 r = p[2];
            const u32 a = (bytes_per_pixel == 4) ? p[3] : 0xFFu;
            dst_row[x] = b | (g << 8) | (r << 16) | (a << 24);
        }
    }
    return {};
}

Result<void> TgaWriteHeader32(u8 out[kTgaHeaderBytes], u32 width, u32 height)
{
    if (width == 0 || height == 0 || width > kTgaMaxDim || height > kTgaMaxDim)
        return Err{ErrorCode::InvalidArgument};
    for (u32 i = 0; i < kTgaHeaderBytes; ++i)
        out[i] = 0;
    out[kHdrImageType] = u8(kImageTypeUncompressedTrueColor);
    out[kHdrImageWidth] = u8(width);
    out[kHdrImageWidth + 1] = u8(width >> 8);
    out[kHdrImageHeight] = u8(height);
    out[kHdrImageHeight + 1] = u8(height >> 8);
    out[kHdrPixelDepth] = 32;
    out[kHdrImageDescriptor] = u8(kDescriptorOriginTop | 0x08); // top-down + 8-bit alpha
    return {};
}

u32 TgaEncode32(const u32* pixels, u32 width, u32 height, u8* out, u32 out_cap)
{
    if (width == 0 || height == 0 || width > kTgaMaxDim || height > kTgaMaxDim)
        return 0;
    const u64 pixel_bytes = u64(width) * height * 4;
    const u64 total = u64(kTgaHeaderBytes) + pixel_bytes;
    if (total > u64(out_cap))
        return 0;
    if (!TgaWriteHeader32(out, width, height).has_value())
        return 0;
    // Pixels: BGRA8888 LE u32 → spec-required B G R A byte order.
    u8* dst = out + kTgaHeaderBytes;
    for (u32 y = 0; y < height; ++y)
    {
        const u32* src_row = pixels + u64(y) * width;
        u8* dst_row = dst + u64(y) * width * 4;
        for (u32 x = 0; x < width; ++x)
        {
            const u32 px = src_row[x];
            dst_row[x * 4 + 0] = u8(px);
            dst_row[x * 4 + 1] = u8(px >> 8);
            dst_row[x * 4 + 2] = u8(px >> 16);
            dst_row[x * 4 + 3] = u8(px >> 24);
        }
    }
    return u32(total);
}

namespace
{

// Build a synthetic 2x2 32-bpp uncompressed bottom-up TGA in `buf`.
// Pixel layout (after row-flip on decode):
//   row 0 (top):    red, green
//   row 1 (bottom): blue, white
//
// Returns the byte length of the encoded image.
u32 BuildFixture32Bpp(u8 buf[64])
{
    // Header (18 bytes).
    for (u32 i = 0; i < 18; ++i)
        buf[i] = 0;
    buf[kHdrImageType] = u8(kImageTypeUncompressedTrueColor);
    buf[kHdrImageWidth] = 2;
    buf[kHdrImageWidth + 1] = 0;
    buf[kHdrImageHeight] = 2;
    buf[kHdrImageHeight + 1] = 0;
    buf[kHdrPixelDepth] = 32;
    buf[kHdrImageDescriptor] = 0; // bottom-up, alpha=8 lower nibble could be set; spec is loose
    // Pixels: BGRA bytes, bottom row first.
    // Bottom row: blue, white.
    // pixel 0 (bottom-left blue):
    buf[18] = 0xFF; // B
    buf[19] = 0x00; // G
    buf[20] = 0x00; // R
    buf[21] = 0xFF; // A
    // pixel 1 (bottom-right white):
    buf[22] = 0xFF;
    buf[23] = 0xFF;
    buf[24] = 0xFF;
    buf[25] = 0xFF;
    // Top row: red, green.
    buf[26] = 0x00; // pixel (0,0) red: B
    buf[27] = 0x00;
    buf[28] = 0xFF; // R
    buf[29] = 0xFF; // A
    buf[30] = 0x00; // pixel (1,0) green: B
    buf[31] = 0xFF;
    buf[32] = 0x00;
    buf[33] = 0xFF;
    return 34;
}

// Build a synthetic 1x1 24-bpp uncompressed top-down TGA in `buf`.
// Single pixel = pure cyan (B=FF, G=FF, R=00).
// Returns the byte length.
u32 BuildFixture24BppTopDown(u8 buf[32])
{
    for (u32 i = 0; i < 18; ++i)
        buf[i] = 0;
    buf[kHdrImageType] = u8(kImageTypeUncompressedTrueColor);
    buf[kHdrImageWidth] = 1;
    buf[kHdrImageHeight] = 1;
    buf[kHdrPixelDepth] = 24;
    buf[kHdrImageDescriptor] = kDescriptorOriginTop;
    buf[18] = 0xFF;
    buf[19] = 0xFF;
    buf[20] = 0x00;
    return 21;
}

} // namespace

void TgaSelfTest()
{
    // ----- 32-bpp bottom-up fixture round-trip.
    {
        u8 buf[64];
        const u32 len = BuildFixture32Bpp(buf);
        TgaInfo info = TgaParseHeader(buf);
        KASSERT(info.ok && info.width == 2 && info.height == 2 && info.bpp == 32, "util/tga",
                "32-bpp header parse wrong");
        KASSERT(!info.top_down, "util/tga", "32-bpp fixture must be bottom-up");

        u32 px[4] = {0, 0, 0, 0};
        const bool ok = TgaDecodeUncompressed(buf, len, info, px).has_value();
        KASSERT(ok, "util/tga", "32-bpp decode failed");
        // Expected output (top-down):
        //   px[0] = (0,0) red    = 0xFF FF 00 00 → B=00 G=00 R=FF A=FF → 0xFFFF0000
        //   px[1] = (1,0) green  = 0xFF 00 FF 00 → B=00 G=FF R=00 A=FF → 0xFF00FF00
        //   px[2] = (0,1) blue   = 0xFF 00 00 FF → B=FF G=00 R=00 A=FF → 0xFF0000FF
        //   px[3] = (1,1) white  = 0xFF FF FF FF → 0xFFFFFFFF
        KASSERT(px[0] == 0xFFFF0000u, "util/tga", "32-bpp pixel(0,0) wrong");
        KASSERT(px[1] == 0xFF00FF00u, "util/tga", "32-bpp pixel(1,0) wrong");
        KASSERT(px[2] == 0xFF0000FFu, "util/tga", "32-bpp pixel(0,1) wrong");
        KASSERT(px[3] == 0xFFFFFFFFu, "util/tga", "32-bpp pixel(1,1) wrong");
    }

    // ----- 24-bpp top-down fixture round-trip (single cyan pixel).
    {
        u8 buf[32];
        const u32 len = BuildFixture24BppTopDown(buf);
        TgaInfo info = TgaParseHeader(buf);
        KASSERT(info.ok && info.width == 1 && info.height == 1 && info.bpp == 24, "util/tga",
                "24-bpp header parse wrong");
        KASSERT(info.top_down, "util/tga", "24-bpp fixture must be top-down");

        u32 px = 0;
        const bool ok = TgaDecodeUncompressed(buf, len, info, &px).has_value();
        KASSERT(ok, "util/tga", "24-bpp decode failed");
        // Cyan with implicit alpha=FF: B=FF G=FF R=00 A=FF → 0xFF00FFFF
        KASSERT(px == 0xFF00FFFFu, "util/tga", "24-bpp cyan pixel wrong");
    }

    // ----- Negative: image type 1 (colormapped) must reject.
    {
        u8 buf[18] = {};
        buf[kHdrImageType] = 1; // colormapped
        buf[kHdrImageWidth] = 1;
        buf[kHdrImageHeight] = 1;
        buf[kHdrPixelDepth] = 24;
        const TgaInfo info = TgaParseHeader(buf);
        KASSERT(!info.ok, "util/tga", "colormapped not rejected");
    }

    // ----- Negative: image type 10 (RLE) — must reject in v0.
    {
        u8 buf[18] = {};
        buf[kHdrImageType] = 10;
        buf[kHdrImageWidth] = 4;
        buf[kHdrImageHeight] = 4;
        buf[kHdrPixelDepth] = 24;
        const TgaInfo info = TgaParseHeader(buf);
        KASSERT(!info.ok, "util/tga", "RLE not rejected (v0 deferred)");
    }

    // ----- Negative: oversize dimension.
    {
        u8 buf[18] = {};
        buf[kHdrImageType] = 2;
        buf[kHdrImageWidth] = 0xFF;
        buf[kHdrImageWidth + 1] = 0xFF; // 65535 > kTgaMaxDim
        buf[kHdrImageHeight] = 1;
        buf[kHdrPixelDepth] = 24;
        const TgaInfo info = TgaParseHeader(buf);
        KASSERT(!info.ok, "util/tga", "oversize dim not rejected");
    }

    // ----- Negative: 16-bpp (TGA legitimately allows it but v0 rejects).
    {
        u8 buf[18] = {};
        buf[kHdrImageType] = 2;
        buf[kHdrImageWidth] = 1;
        buf[kHdrImageHeight] = 1;
        buf[kHdrPixelDepth] = 16;
        const TgaInfo info = TgaParseHeader(buf);
        KASSERT(!info.ok, "util/tga", "16-bpp not rejected");
    }

    // ----- Negative: truncated buffer (header says 4×4×24 but only
    // 1 byte of pixel data given) → decode must fail cleanly.
    {
        u8 buf[19] = {};
        buf[kHdrImageType] = 2;
        buf[kHdrImageWidth] = 4;
        buf[kHdrImageHeight] = 4;
        buf[kHdrPixelDepth] = 24;
        const TgaInfo info = TgaParseHeader(buf);
        KASSERT(info.ok, "util/tga", "valid header should parse");
        u32 px[16] = {};
        KASSERT(!TgaDecodeUncompressed(buf, sizeof(buf), info, px).has_value(), "util/tga",
                "truncated decode not rejected");
    }

    // ----- Encode → Decode round-trip for a 2×2 mosaic.
    {
        const u32 mosaic[4] = {0xFFFF0000u, 0xFF00FF00u, 0xFF0000FFu, 0xFFFFFFFFu};
        u8 enc[kTgaHeaderBytes + 16];
        const u32 n = TgaEncode32(mosaic, 2, 2, enc, sizeof(enc));
        KASSERT(n == kTgaHeaderBytes + 16, "util/tga", "encode byte count wrong");
        const TgaInfo info = TgaParseHeader(enc);
        KASSERT(info.ok && info.bpp == 32 && info.width == 2 && info.height == 2, "util/tga",
                "encode header parse wrong");
        KASSERT(info.top_down, "util/tga", "encode must be top-down");
        u32 round[4] = {};
        KASSERT(TgaDecodeUncompressed(enc, n, info, round).has_value(), "util/tga", "encode round-trip decode failed");
        for (u32 i = 0; i < 4; ++i)
            KASSERT(round[i] == mosaic[i], "util/tga", "encode round-trip pixel mismatch");
    }

    // ----- Encoder negative case: out_cap too small.
    {
        const u32 px = 0xFFFFFFFFu;
        u8 small[10];
        KASSERT(TgaEncode32(&px, 1, 1, small, sizeof(small)) == 0, "util/tga", "encode out_cap underflow not rejected");
    }
}

} // namespace duetos::util
