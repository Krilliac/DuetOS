#pragma once

#include "../../arch/x86_64/traps.h"
#include "../../core/types.h"

/*
 * DuetOS — Win32 GDI object + DC registry.
 *
 * Tracks the kernel-side state backing the Win32 GDI handle family
 * (HDC, HBITMAP, HBRUSH, HPEN, ...). v0 coverage:
 *
 *   HDC       — window DCs (HDC == HWND, trivially) OR memory DCs
 *                created via CreateCompatibleDC. Memory DCs own a
 *                selected HBITMAP that's used as the source for a
 *                subsequent BitBlt.
 *   HBITMAP   — a kernel-owned BGRA8888 pixel buffer + geometry.
 *                Allocated via CreateCompatibleBitmap; pixels start
 *                zeroed.
 *   HBRUSH    — a solid-colour brush. Stock brushes (WHITE/LTGRAY/
 *                GRAY/DKGRAY/BLACK) pre-registered so GetStockObject
 *                returns deterministic handles without allocation.
 *
 * Handle values carry a 4-bit type tag in bits 27:24, with the
 * index in bits 15:0. Makes SelectObject / DeleteObject able to
 * route by inspection — no per-handle lookup for the type check.
 *
 * Not in scope (v0):
 *   - HPEN / HFONT / HRGN state (stock handles only, no real
 *     draw-path consumers yet).
 *   - DC colour state (SetTextColor / SetBkColor). TextOutA uses
 *     a hard-coded white ink.
 *   - Coordinate transforms (no SetWindowOrgEx et al.).
 *   - Per-process scoping — handle table is system-wide.
 *
 * Context: kernel. Every entry point is reachable from a ring-3 PE
 * via a SYS_GDI_* syscall; the handle-manager side holds no locks
 * of its own (the compositor mutex held by the caller suffices).
 */

namespace duetos::subsystems::win32
{

// Handle tag in bits 27:24 (chosen so values are still small enough
// to fit in the int32 HDC / HBITMAP Win32 types if a PE uses that).
inline constexpr u64 kGdiTagMask = 0x0F000000u;
inline constexpr u64 kGdiTagMemDC = 0x01000000u;
inline constexpr u64 kGdiTagBitmap = 0x02000000u;
inline constexpr u64 kGdiTagBrush = 0x03000000u;

inline constexpr u32 kMaxMemDcs = 64;
inline constexpr u32 kMaxBitmaps = 64;
inline constexpr u32 kMaxBrushes = 64;

// Max pixels per compatible bitmap. Keeps a malicious caller from
// requesting a 100 MB bitmap. 1024 × 1024 × 4 = 4 MiB per bitmap;
// at 64 bitmaps that's 256 MiB worst-case, but typical usage is
// a handful of <= window-sized bitmaps.
inline constexpr u32 kMaxBitmapPixels = 1024 * 1024;

struct MemDC
{
    bool alive;
    u64 selected_bitmap; // HBITMAP handle (with tag) or 0 = none
};

struct Bitmap
{
    bool alive;
    u32 width;
    u32 height;
    u32 pitch;   // bytes per row; always width * 4 in v0
    u32* pixels; // kernel BGRA8888 buffer, KMalloc'd
};

struct Brush
{
    bool alive;
    u32 rgb;    // 0x00RRGGBB
    bool stock; // stock brushes are never freed
};

// Stock brush indices (Win32 GetStockObject codes).
inline constexpr u32 kStockWhiteBrush = 0;
inline constexpr u32 kStockLtGrayBrush = 1;
inline constexpr u32 kStockGrayBrush = 2;
inline constexpr u32 kStockDkGrayBrush = 3;
inline constexpr u32 kStockBlackBrush = 4;
inline constexpr u32 kStockNullBrush = 5;

/// One-time registration of the pre-defined stock objects.
/// Safe to call multiple times (idempotent).
void GdiInit();

// Handle type inspection. Returns one of the kGdiTag* values, or 0
// if the handle has no tag (which includes every window HDC/HWND
// since those are small integers from the WindowHandle registry).
u64 GdiHandleType(u64 h);

// Accessors — return nullptr / false on invalid handle. The
// returned pointer is kernel-owned and stable until the handle is
// deleted.
MemDC* GdiLookupMemDC(u64 h);
Bitmap* GdiLookupBitmap(u64 h);
Brush* GdiLookupBrush(u64 h);

// Operations (called from the syscall dispatchers).
u64 GdiCreateCompatibleDC();
u64 GdiCreateCompatibleBitmap(u32 width, u32 height);
u64 GdiCreateSolidBrush(u32 rgb);
u64 GdiGetStockObject(u32 index);
u64 GdiSelectObject(u64 hdc, u64 hobj); // returns previous selection (0 if none / unsupported)
bool GdiDeleteDC(u64 hdc);
bool GdiDeleteObject(u64 hobj); // works on any GDI object kind

// Syscall dispatchers.
void DoGdiCreateCompatibleDC(arch::TrapFrame* frame);
void DoGdiCreateCompatibleBitmap(arch::TrapFrame* frame);
void DoGdiCreateSolidBrush(arch::TrapFrame* frame);
void DoGdiGetStockObject(arch::TrapFrame* frame);
void DoGdiSelectObject(arch::TrapFrame* frame);
void DoGdiDeleteDC(arch::TrapFrame* frame);
void DoGdiDeleteObject(arch::TrapFrame* frame);
void DoGdiBitBltDC(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
