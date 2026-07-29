/*
 * DuetOS — DIB <-> off-screen-surface transfer: implementation.
 *
 * See gdi_dib.h for what this backs and why it is its own TU.
 *
 * FORMAT NOTES
 *   Kernel surfaces hold one u32 per pixel, 0x00RRGGBB — the same
 *   value every other compositor path uses (see blend_math.h).
 *
 *   A Windows DIB scanline is bottom-up when biHeight is POSITIVE
 *   and top-down when it is NEGATIVE. Positive is the default a
 *   BITMAPINFOHEADER gets when nobody thinks about it, so "the image
 *   is upside down" is the single most common DIB porting bug; the
 *   row index is computed once, in RowOffset, rather than at each
 *   call site.
 *
 *   Rows are padded up to a 4-byte boundary. DibStrideBytes owns
 *   that; nothing here multiplies width by a byte depth directly.
 */

#include "subsystems/win32/gdi_dib.h"

#include "subsystems/win32/gdi_objects.h"
#include "subsystems/win32/gdi_surface_math.h"

#include "arch/x86_64/serial.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::win32
{

namespace
{

// Which DIB scanline holds surface row `y`, given the image's row
// count and origin convention.
u64 RowOffset(u64 y, u64 rows, bool top_down)
{
    return top_down ? y : (rows - 1u - y);
}

// Unpack one DIB row into 0x00RRGGBB surface pixels.
//
// `count` is already clipped to what BOTH the source row and the
// destination row can hold, so this loop does no bounds work of its
// own — that decision lives in the caller, once.
void UnpackRow(const u8* src, u32* dst, u32 count, u32 bpp)
{
    if (bpp == 32)
    {
        // DIB 32bpp is B,G,R,A in memory. Read the little-endian u32
        // and drop the alpha byte: surfaces carry colour only, and
        // the blend path supplies alpha separately.
        for (u32 i = 0; i < count; ++i)
        {
            const u32 b = src[i * 4u + 0u];
            const u32 g = src[i * 4u + 1u];
            const u32 r = src[i * 4u + 2u];
            dst[i] = (r << 16) | (g << 8) | b;
        }
        return;
    }
    if (bpp == 24)
    {
        for (u32 i = 0; i < count; ++i)
        {
            const u32 b = src[i * 3u + 0u];
            const u32 g = src[i * 3u + 1u];
            const u32 r = src[i * 3u + 2u];
            dst[i] = (r << 16) | (g << 8) | b;
        }
        return;
    }
    // 16bpp. BI_RGB at 16bpp is X1-R5-G5-B5 — the 5-6-5 layout needs
    // a BI_BITFIELDS header, which the DIB paths do not parse.
    // GAP: no BI_BITFIELDS 5-6-5 — revisit when a PE ships one.
    for (u32 i = 0; i < count; ++i)
    {
        const u32 v = static_cast<u32>(src[i * 2u + 0u]) | (static_cast<u32>(src[i * 2u + 1u]) << 8);
        // Replicate the high bits into the low ones so 0x1F maps to
        // 0xFF rather than 0xF8 (otherwise white is not quite white).
        const u32 r5 = (v >> 10) & 0x1Fu;
        const u32 g5 = (v >> 5) & 0x1Fu;
        const u32 b5 = v & 0x1Fu;
        const u32 r = (r5 << 3) | (r5 >> 2);
        const u32 g = (g5 << 3) | (g5 >> 2);
        const u32 b = (b5 << 3) | (b5 >> 2);
        dst[i] = (r << 16) | (g << 8) | b;
    }
}

// Pack surface pixels back into one DIB row. The inverse of
// UnpackRow; 32bpp writes an opaque alpha because a surface has none
// to give and callers that read it (icon compositing, screenshot
// paths) expect 0xFF rather than 0.
void PackRow(const u32* src, u8* dst, u32 count, u32 bpp)
{
    if (bpp == 32)
    {
        for (u32 i = 0; i < count; ++i)
        {
            const u32 v = src[i];
            dst[i * 4u + 0u] = static_cast<u8>(v & 0xFFu);
            dst[i * 4u + 1u] = static_cast<u8>((v >> 8) & 0xFFu);
            dst[i * 4u + 2u] = static_cast<u8>((v >> 16) & 0xFFu);
            dst[i * 4u + 3u] = 0xFFu;
        }
        return;
    }
    if (bpp == 24)
    {
        for (u32 i = 0; i < count; ++i)
        {
            const u32 v = src[i];
            dst[i * 3u + 0u] = static_cast<u8>(v & 0xFFu);
            dst[i * 3u + 1u] = static_cast<u8>((v >> 8) & 0xFFu);
            dst[i * 3u + 2u] = static_cast<u8>((v >> 16) & 0xFFu);
        }
        return;
    }
    for (u32 i = 0; i < count; ++i)
    {
        const u32 v = src[i];
        const u32 r5 = ((v >> 16) & 0xFFu) >> 3;
        const u32 g5 = ((v >> 8) & 0xFFu) >> 3;
        const u32 b5 = (v & 0xFFu) >> 3;
        const u32 packed = (r5 << 10) | (g5 << 5) | b5;
        dst[i * 2u + 0u] = static_cast<u8>(packed & 0xFFu);
        dst[i * 2u + 1u] = static_cast<u8>((packed >> 8) & 0xFFu);
    }
}

// Everything both directions need to agree on before a byte moves.
// Returns false — with nothing allocated and nothing copied — for
// any request that does not describe a transfer we can perform
// safely.
struct DibPlan
{
    Bitmap* bmp;
    u32 stride;    // bytes per DIB row, DWORD-padded
    u64 rows;      // |height|
    u32 copy_px;   // pixels per row actually transferred
    bool top_down; // DIB origin convention
};

bool PlanTransfer(u64 hbmp, u32 width, i32 height, u32 bpp, u64 user_bytes, DibPlan* out)
{
    // Owner-checked: a handle belonging to another process resolves
    // to nullptr here, so neither direction can reach its pixels.
    Bitmap* bmp = GdiLookupBitmap(hbmp);
    if (bmp == nullptr || bmp->pixels == nullptr)
        return false;

    // Overflow-checked against the per-surface ceiling, and refuses
    // the depths we do not convert. Also rejects an INT32_MIN height
    // rather than negating it.
    const u64 need = DibImageByteSize(width, height, bpp);
    if (need == 0)
        return false;

    // The caller's own claim about its buffer must cover the image
    // the header describes. Without this a PE can pass a 4-byte
    // buffer with a 1024x1024 header and we read 4 MiB past it.
    if (user_bytes < need)
        return false;

    const u32 stride = DibStrideBytes(width, bpp);
    if (stride == 0)
        return false;

    const u64 rows = (height < 0) ? static_cast<u64>(-static_cast<i64>(height)) : static_cast<u64>(height);

    // Transfer the intersection of the DIB and the surface. Win32
    // clips rather than failing when the two disagree on size, and a
    // caller that got the size right sees no difference.
    const u32 copy_px = (width < bmp->width) ? width : bmp->width;
    if (copy_px == 0)
        return false;

    out->bmp = bmp;
    out->stride = stride;
    out->rows = rows;
    out->copy_px = copy_px;
    out->top_down = DibIsTopDown(height);
    return true;
}

} // namespace

void DoGdiSetDiBits(arch::TrapFrame* frame)
{
    // rdi = HBITMAP, rsi = user bits, rdx = width, r10 = height
    // (signed), r8 = bpp, r9 = caller's buffer byte count.
    // rax <- rows transferred, 0 on refusal.
    frame->rax = 0;

    if (duetos::core::CurrentProcess() == nullptr)
        return;
    const u64 user_bits = frame->rsi;
    if (user_bits == 0)
        return;

    const u32 width = static_cast<u32>(frame->rdx);
    const i32 height = static_cast<i32>(static_cast<u32>(frame->r10));
    const u32 bpp = static_cast<u32>(frame->r8);
    const u64 user_bytes = frame->r9;

    DibPlan plan{};
    if (!PlanTransfer(frame->rdi, width, height, bpp, user_bytes, &plan))
        return;

    // One row of staging rather than the whole image: the peak extra
    // allocation is a single stride, and the guest buffer is never
    // read twice for the same bytes (so it cannot be swapped between
    // a validation pass and a use pass).
    u8* row = static_cast<u8*>(duetos::mm::KMalloc(plan.stride));
    if (row == nullptr)
        return;

    const u64 dst_rows = (plan.rows < plan.bmp->height) ? plan.rows : plan.bmp->height;
    const u32 dst_stride_px = plan.bmp->pitch / 4u;
    u64 done = 0;
    for (u64 y = 0; y < dst_rows; ++y)
    {
        const u64 src_row = RowOffset(y, plan.rows, plan.top_down);
        const u8* src = reinterpret_cast<const u8*>(user_bits + src_row * plan.stride);
        if (!duetos::mm::CopyFromUser(row, src, plan.stride))
            break;
        UnpackRow(row, plan.bmp->pixels + y * dst_stride_px, plan.copy_px, bpp);
        ++done;
    }

    duetos::mm::KFree(row);
    frame->rax = done;
}

void DoGdiGetDiBits(arch::TrapFrame* frame)
{
    // Same argument shape as DoGdiSetDiBits; rsi is the destination.
    frame->rax = 0;

    if (duetos::core::CurrentProcess() == nullptr)
        return;
    const u64 user_bits = frame->rsi;
    if (user_bits == 0)
        return;

    const u32 width = static_cast<u32>(frame->rdx);
    const i32 height = static_cast<i32>(static_cast<u32>(frame->r10));
    const u32 bpp = static_cast<u32>(frame->r8);
    const u64 user_bytes = frame->r9;

    DibPlan plan{};
    if (!PlanTransfer(frame->rdi, width, height, bpp, user_bytes, &plan))
        return;

    u8* row = static_cast<u8*>(duetos::mm::KMalloc(plan.stride));
    if (row == nullptr)
        return;

    const u64 src_rows = (plan.rows < plan.bmp->height) ? plan.rows : plan.bmp->height;
    const u32 src_stride_px = plan.bmp->pitch / 4u;
    u64 done = 0;
    for (u64 y = 0; y < src_rows; ++y)
    {
        // Zero the pad bytes at the end of the row so we never hand
        // the guest whatever the staging buffer held last.
        for (u32 i = 0; i < plan.stride; ++i)
            row[i] = 0;
        PackRow(plan.bmp->pixels + y * src_stride_px, row, plan.copy_px, bpp);

        const u64 dst_row = RowOffset(y, plan.rows, plan.top_down);
        u8* dst = reinterpret_cast<u8*>(user_bits + dst_row * plan.stride);
        if (!duetos::mm::CopyToUser(dst, row, plan.stride))
            break;
        ++done;
    }

    duetos::mm::KFree(row);
    frame->rax = done;
}

} // namespace duetos::subsystems::win32
