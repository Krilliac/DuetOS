#pragma once

// DuetOS — off-screen GDI surface arithmetic.
//
// Pure constexpr math with no kernel dependencies, so the hosted unit
// test (tests/host/test_gdi_surface.cpp) can include this header
// directly instead of booting QEMU to find out that a stride was off
// by a DWORD.
//
// Everything here answers a question about GUEST-CONTROLLED numbers.
// A PE picks the width, the height, the bit depth, and the blit
// rectangle; the kernel has to decide "is this allocation sane" and
// "does this rectangle stay inside both surfaces" BEFORE it touches a
// byte. Those two decisions are the whole file:
//
//   SurfaceByteSize     — overflow-checked w * h * 4 for our native
//                         BGRA8888 backing store.
//   DibStrideBytes      — Win32 DIB row stride: rows are padded up to
//                         a 4-byte boundary, which is where naive
//                         `width * bpp / 8` implementations go wrong.
//   DibImageByteSize    — overflow-checked stride * |height|.
//   DibIsTopDown        — the BITMAPINFOHEADER sign convention.
//   ClipBlit            — intersect a blit against both surfaces.
//   BudgetAdmits        — per-process allocation admission.
//
// Rationale for living in a header rather than a .cpp: the same math
// has to run in the kernel and in the hosted test, and there is no
// kernel-object dependency to justify a TU. See blend_math.h for the
// same pattern applied to the compositor's blend arithmetic.

#include "util/types.h"

namespace duetos::subsystems::win32
{

// Hard ceiling on pixels in a single surface, independent of who asks.
// 1024 * 1024 * 4 = 4 MiB per surface.
inline constexpr u64 kMaxSurfacePixels = 1024u * 1024u;

// Largest bit depth the DIB paths accept. 32bpp is the native format;
// 24 and 16 are converted on upload. Anything palettised is refused
// outright rather than silently mis-rendered.
inline constexpr u32 kMaxDibBpp = 32;

/// Byte size of a `width x height` BGRA8888 surface, or 0 if the
/// request is empty, over the per-surface ceiling, or would overflow.
///
/// The overflow guard is not theatre: `width` and `height` arrive as
/// guest-supplied 32-bit integers, so `width * height` in 32-bit math
/// wraps for e.g. 65536 x 65536 and yields a 0-byte allocation that a
/// subsequent blit happily writes past.
constexpr u64 SurfaceByteSize(u32 width, u32 height)
{
    if (width == 0 || height == 0)
    {
        return 0;
    }
    const u64 pixels = static_cast<u64>(width) * static_cast<u64>(height);
    if (pixels > kMaxSurfacePixels)
    {
        return 0;
    }
    return pixels * 4u;
}

/// Win32 DIB row stride in bytes: each row is padded up to the next
/// 4-byte boundary. Returns 0 for an unsupported depth or a width
/// whose padded stride would overflow 32 bits.
///
/// The classic bug this exists to prevent: using `width * 4` for a
/// 24bpp DIB. A 3-pixel-wide 24bpp row is 9 bytes of pixel data but a
/// 12-byte stride, and reading it at 9 shears the image progressively.
constexpr u32 DibStrideBytes(u32 width, u32 bpp)
{
    if (width == 0)
    {
        return 0;
    }
    if (bpp != 16 && bpp != 24 && bpp != 32)
    {
        return 0;
    }
    // (width * bpp + 31) / 32 * 4, in 64-bit math so the +31 cannot wrap.
    const u64 bits = static_cast<u64>(width) * static_cast<u64>(bpp);
    const u64 stride = ((bits + 31u) / 32u) * 4u;
    if (stride > 0xFFFFFFFFu)
    {
        return 0;
    }
    return static_cast<u32>(stride);
}

/// Total bytes a DIB's pixel array occupies, or 0 if unrepresentable.
/// `height` is the raw BITMAPINFOHEADER value: negative means
/// top-down, and its magnitude is the row count either way.
constexpr u64 DibImageByteSize(u32 width, i32 height, u32 bpp)
{
    if (height == 0)
    {
        return 0;
    }
    // Negate in 64-bit: i32 INT32_MIN has no positive counterpart, so
    // `-height` on the raw i32 is UB for that one value a guest can
    // absolutely pass.
    const u64 rows = (height < 0) ? static_cast<u64>(-static_cast<i64>(height)) : static_cast<u64>(height);
    const u32 stride = DibStrideBytes(width, bpp);
    if (stride == 0)
    {
        return 0;
    }
    if (static_cast<u64>(width) * rows > kMaxSurfacePixels)
    {
        return 0;
    }
    return static_cast<u64>(stride) * rows;
}

/// BITMAPINFOHEADER sign convention: a NEGATIVE biHeight means the
/// first row in memory is the TOP row (top-down). A positive biHeight
/// means the first row in memory is the BOTTOM row (bottom-up), which
/// is the Windows default and the one that renders upside down when a
/// port forgets it.
constexpr bool DibIsTopDown(i32 height)
{
    return height < 0;
}

/// A blit rectangle after clipping, in both surfaces' coordinates.
struct BlitRect
{
    i32 src_x;
    i32 src_y;
    i32 dst_x;
    i32 dst_y;
    i32 width;
    i32 height;
};

/// Clip a `w x h` blit from `(sx, sy)` in a `src_w x src_h` surface to
/// `(dx, dy)` in a `dst_w x dst_h` surface. Returns a rect whose
/// `width`/`height` are 0 when nothing survives.
///
/// Both origins may be negative — Win32 callers do that routinely when
/// scrolling — and the shared overhang has to come off BOTH sides so
/// the source and destination stay in step. Getting that wrong shifts
/// the image by the clip amount instead of cropping it.
constexpr BlitRect ClipBlit(i32 sx, i32 sy, i32 dx, i32 dy, i32 w, i32 h, i32 src_w, i32 src_h, i32 dst_w, i32 dst_h)
{
    BlitRect out{0, 0, 0, 0, 0, 0};
    if (w <= 0 || h <= 0 || src_w <= 0 || src_h <= 0 || dst_w <= 0 || dst_h <= 0)
    {
        return out;
    }

    // Left/top overhang: whichever surface starts furthest negative
    // sets the trim, and both origins advance by it together.
    i64 trim_x = 0;
    if (sx < 0)
    {
        trim_x = -static_cast<i64>(sx);
    }
    if (dx < 0 && -static_cast<i64>(dx) > trim_x)
    {
        trim_x = -static_cast<i64>(dx);
    }
    i64 trim_y = 0;
    if (sy < 0)
    {
        trim_y = -static_cast<i64>(sy);
    }
    if (dy < 0 && -static_cast<i64>(dy) > trim_y)
    {
        trim_y = -static_cast<i64>(dy);
    }
    if (trim_x >= w || trim_y >= h)
    {
        return out;
    }

    const i64 nsx = static_cast<i64>(sx) + trim_x;
    const i64 nsy = static_cast<i64>(sy) + trim_y;
    const i64 ndx = static_cast<i64>(dx) + trim_x;
    const i64 ndy = static_cast<i64>(dy) + trim_y;
    i64 nw = static_cast<i64>(w) - trim_x;
    i64 nh = static_cast<i64>(h) - trim_y;

    // Right/bottom overhang, again against both surfaces.
    if (nsx + nw > src_w)
    {
        nw = static_cast<i64>(src_w) - nsx;
    }
    if (ndx + nw > dst_w)
    {
        nw = static_cast<i64>(dst_w) - ndx;
    }
    if (nsy + nh > src_h)
    {
        nh = static_cast<i64>(src_h) - nsy;
    }
    if (ndy + nh > dst_h)
    {
        nh = static_cast<i64>(dst_h) - ndy;
    }
    if (nw <= 0 || nh <= 0)
    {
        return out;
    }

    out.src_x = static_cast<i32>(nsx);
    out.src_y = static_cast<i32>(nsy);
    out.dst_x = static_cast<i32>(ndx);
    out.dst_y = static_cast<i32>(ndy);
    out.width = static_cast<i32>(nw);
    out.height = static_cast<i32>(nh);
    return out;
}

// --- ROP2 (binary raster op) pixel math ---------------------------
//
// Win32 SetROP2 codes the memory-DC paint helpers honour. Kept here
// (not gdi_objects.h) so the hosted test test_gdi32_rop2.cpp can pin
// the per-pixel truth table without pulling kernel headers.
inline constexpr u8 kRop2Black = 1;    // R2_BLACK   — always 0
inline constexpr u8 kRop2Not = 6;      // R2_NOT     — ~dst
inline constexpr u8 kRop2XorPen = 7;   // R2_XORPEN  — dst ^ pen
inline constexpr u8 kRop2CopyPen = 13; // R2_COPYPEN — pen (default)
inline constexpr u8 kRop2White = 16;   // R2_WHITE   — always 1s

/// Apply a binary raster op to one 0x00RRGGBB pixel. `dst` is the
/// current surface pixel, `src` the pen/brush colour.
/// GAP: of the 16 Win32 R2_* codes only BLACK / NOT / XORPEN /
/// COPYPEN / WHITE are computed; the other 11 fall back to COPYPEN.
/// Revisit when a PE draws with R2_MASKPEN-family ops.
constexpr u32 Rop2Apply(u8 rop2, u32 dst, u32 src)
{
    switch (rop2)
    {
    case kRop2Black:
        return 0x00000000u;
    case kRop2White:
        return 0x00FFFFFFu;
    case kRop2Not:
        return ~dst & 0x00FFFFFFu;
    case kRop2XorPen:
        return (dst ^ src) & 0x00FFFFFFu;
    default:
        return src;
    }
}

/// True when the op reads the destination pixel (read-modify-write);
/// false ops can precompute one value and store it straight through.
constexpr bool Rop2NeedsDst(u8 rop2)
{
    return rop2 == kRop2Not || rop2 == kRop2XorPen;
}

/// True for the mode values SetROP2 accepts (Win32 R2_* range).
constexpr bool Rop2ModeValid(u8 rop2)
{
    return rop2 >= 1 && rop2 <= 16;
}

/// Per-process allocation admission: would granting `want_bytes` (one
/// more object) keep this owner inside both its object-count and its
/// byte budget?
///
/// The GDI tables are system-wide. Without this, one PE can hold every
/// slot and every byte, and every process that starts afterwards gets
/// a NULL from CreateCompatibleBitmap for the rest of the boot.
constexpr bool BudgetAdmits(u32 held_count, u64 held_bytes, u64 want_bytes, u32 max_count, u64 max_bytes)
{
    if (want_bytes == 0)
    {
        return false;
    }
    if (held_count >= max_count)
    {
        return false;
    }
    if (want_bytes > max_bytes)
    {
        return false;
    }
    // Subtract rather than add so the comparison cannot overflow even
    // if a caller passes a bogus held_bytes.
    if (held_bytes > max_bytes)
    {
        return false;
    }
    return want_bytes <= (max_bytes - held_bytes);
}

} // namespace duetos::subsystems::win32
