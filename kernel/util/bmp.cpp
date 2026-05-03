#include "util/bmp.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

inline void StoreU16(u8* p, u16 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
}

inline void StoreU32(u8* p, u32 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
    p[2] = u8(v >> 16);
    p[3] = u8(v >> 24);
}

inline u16 LoadU16(const u8* p)
{
    return u16(u16(p[0]) | (u16(p[1]) << 8));
}

inline u32 LoadU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

} // namespace

void BmpWriteHeader32(u8 out[kBmpHeaderBytes], u32 width, u32 height, bool top_down)
{
    const u32 pixel_bytes = width * height * 4;
    const u32 file_size = u32(kBmpHeaderBytes) + pixel_bytes;

    // BITMAPFILEHEADER (14 bytes)
    out[0] = 'B';
    out[1] = 'M';
    StoreU32(out + 2, file_size);
    StoreU16(out + 6, 0); // reserved
    StoreU16(out + 8, 0); // reserved
    StoreU32(out + 10, u32(kBmpHeaderBytes));

    // BITMAPINFOHEADER (40 bytes)
    StoreU32(out + 14, u32(kBmpInfoHeaderBytes));
    StoreU32(out + 18, width);
    // Negative height = top-down DIB (no row flip on decode).
    const u32 height_field = top_down ? u32(-i32(height)) : height;
    StoreU32(out + 22, height_field);
    StoreU16(out + 26, 1);  // planes
    StoreU16(out + 28, 32); // bpp
    StoreU32(out + 30, 0);  // BI_RGB (uncompressed)
    StoreU32(out + 34, pixel_bytes);
    StoreU32(out + 38, 2835); // ~72 DPI in pixels-per-metre
    StoreU32(out + 42, 2835);
    StoreU32(out + 46, 0); // colors used
    StoreU32(out + 50, 0); // colors important
}

BmpInfo BmpParseHeader(const u8* hdr)
{
    BmpInfo info = {};
    if (hdr[0] != 'B' || hdr[1] != 'M')
        return info;
    info.pixel_offset = LoadU32(hdr + 10);
    const u32 dib_size = LoadU32(hdr + 14);
    if (dib_size < 40)
        return info;
    info.width = LoadU32(hdr + 18);
    const i32 signed_height = i32(LoadU32(hdr + 22));
    if (signed_height < 0)
    {
        info.height = u32(-signed_height);
        info.top_down = true;
    }
    else
    {
        info.height = u32(signed_height);
        info.top_down = false;
    }
    info.bpp = LoadU16(hdr + 28);
    info.compression = LoadU32(hdr + 30);
    constexpr u32 kMaxDim = 16384;
    if (info.width == 0 || info.height == 0 || info.width > kMaxDim || info.height > kMaxDim)
        return info;
    info.ok = true;
    return info;
}

void BmpSelfTest()
{
    // ----- 32-bpp top-down round-trip.
    {
        u8 buf[kBmpHeaderBytes];
        BmpWriteHeader32(buf, 320, 200, true);
        const BmpInfo info = BmpParseHeader(buf);
        KASSERT(info.ok && info.width == 320 && info.height == 200, "util/bmp", "32-bpp top-down round-trip wrong");
        KASSERT(info.bpp == 32 && info.compression == 0, "util/bmp", "32-bpp top-down bpp/comp wrong");
        KASSERT(info.top_down, "util/bmp", "top-down flag lost");
        KASSERT(info.pixel_offset == kBmpHeaderBytes, "util/bmp", "pixel_offset wrong");
    }
    // ----- 32-bpp bottom-up round-trip.
    {
        u8 buf[kBmpHeaderBytes];
        BmpWriteHeader32(buf, 64, 64, false);
        const BmpInfo info = BmpParseHeader(buf);
        KASSERT(info.ok && info.width == 64 && info.height == 64, "util/bmp", "32-bpp bottom-up round-trip wrong");
        KASSERT(!info.top_down, "util/bmp", "bottom-up flag lost");
    }
    // ----- Negative: bad signature.
    {
        u8 buf[kBmpHeaderBytes] = {};
        buf[0] = 'X';
        buf[1] = 'M';
        const BmpInfo info = BmpParseHeader(buf);
        KASSERT(!info.ok, "util/bmp", "bad signature not rejected");
    }
    // ----- Negative: DIB size < 40.
    {
        u8 buf[kBmpHeaderBytes] = {};
        buf[0] = 'B';
        buf[1] = 'M';
        // dib_size = 12 (BITMAPCOREHEADER) — explicitly out of v0 scope.
        buf[14] = 12;
        const BmpInfo info = BmpParseHeader(buf);
        KASSERT(!info.ok, "util/bmp", "DIB<40 not rejected");
    }
    // ----- Negative: oversize dimension.
    {
        u8 buf[kBmpHeaderBytes];
        BmpWriteHeader32(buf, 1, 1, true);
        // Patch width to 0xFFFFFFFF — far above kMaxDim.
        buf[18] = buf[19] = buf[20] = buf[21] = 0xFF;
        const BmpInfo info = BmpParseHeader(buf);
        KASSERT(!info.ok, "util/bmp", "oversize width not rejected");
    }
}

} // namespace duetos::util
