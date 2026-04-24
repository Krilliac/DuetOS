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
inline constexpr u64 kGdiTagPen = 0x04000000u;

inline constexpr u32 kMaxMemDcs = 64;
inline constexpr u32 kMaxBitmaps = 64;
inline constexpr u32 kMaxBrushes = 64;
inline constexpr u32 kMaxPens = 64;

// Max pixels per compatible bitmap. Keeps a malicious caller from
// requesting a 100 MB bitmap. 1024 × 1024 × 4 = 4 MiB per bitmap;
// at 64 bitmaps that's 256 MiB worst-case, but typical usage is
// a handful of <= window-sized bitmaps.
inline constexpr u32 kMaxBitmapPixels = 1024 * 1024;

// Background mode constants — Win32 SetBkMode values.
inline constexpr u8 kBkModeTransparent = 1;
inline constexpr u8 kBkModeOpaque = 2;

struct MemDC
{
    bool alive;
    u64 selected_bitmap; // HBITMAP handle (with tag) or 0 = none
    u64 selected_pen;    // HPEN handle (with tag) or 0 = use BLACK_PEN implicitly
    u32 text_color;      // 0x00RRGGBB (unpacked from COLORREF on set)
    u32 bk_color;        // 0x00RRGGBB
    u8 bk_mode;          // kBkModeTransparent (default) or kBkModeOpaque
    i32 cur_x;           // DC current position, set by MoveToEx, read by LineTo
    i32 cur_y;
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

struct Pen
{
    bool alive;
    u32 rgb;
    u32 width; // pixels; 0 means "1 pixel cosmetic"
    bool stock;
};

// Stock object indices (Win32 GetStockObject codes). Our brush
// indices 0..5 match Win32 exactly; pen indices start at 6 (we
// use them as internal brush-table slots so the handle tag can
// discriminate without extra plumbing).
inline constexpr u32 kStockWhiteBrush = 0;
inline constexpr u32 kStockLtGrayBrush = 1;
inline constexpr u32 kStockGrayBrush = 2;
inline constexpr u32 kStockDkGrayBrush = 3;
inline constexpr u32 kStockBlackBrush = 4;
inline constexpr u32 kStockNullBrush = 5;
inline constexpr u32 kStockWhitePen = 6;
inline constexpr u32 kStockBlackPen = 7;
inline constexpr u32 kStockNullPen = 8;

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
Pen* GdiLookupPen(u64 h);

// Operations (called from the syscall dispatchers).
u64 GdiCreateCompatibleDC();
u64 GdiCreateCompatibleBitmap(u32 width, u32 height);
u64 GdiCreateSolidBrush(u32 rgb);
u64 GdiCreatePen(u32 style, u32 width, u32 rgb);
u64 GdiGetStockObject(u32 index);
u64 GdiSelectObject(u64 hdc, u64 hobj); // returns previous selection (0 if none / unsupported)
bool GdiDeleteDC(u64 hdc);
bool GdiDeleteObject(u64 hobj); // works on any GDI object kind

// Bitmap paint helpers. Each writes into the bitmap's pixel buffer
// (not any display list) with its own clipping; callers pass the
// already-looked-up Bitmap*. Source rects from user land must be
// bounds-checked BEFORE calling — these helpers clip to the
// bitmap extents but do not reject arbitrary inputs.
void GdiPaintRectOnBitmap(Bitmap* bmp, i32 x, i32 y, i32 w, i32 h, u32 rgb);

/// Paint NUL-terminated ASCII into `bmp` using the 8x8 bitmap font.
/// `fg` inks glyph pixels; `bg` paints the glyph cell background if
/// `opaque` is true. Stops at the first NUL or when the next glyph
/// cell would exit the bitmap horizontally.
void GdiPaintTextOnBitmap(Bitmap* bmp, i32 x, i32 y, const char* text, u32 fg, u32 bg, bool opaque);

/// Copy `src_w × src_h` BGRA pixels from `src` into `bmp` at
/// `(dst_x, dst_y)`. `src_pitch_px` is the source stride in pixels
/// (allowing a clipped subrect of a larger source).
void GdiBlitIntoBitmap(Bitmap* bmp, i32 dst_x, i32 dst_y, const u32* src, u32 src_w, u32 src_h, u32 src_pitch_px);

/// Bresenham line from `(x0, y0)` to `(x1, y1)` inclusive, colour
/// `rgb`. Surface-clipped. Width is a single pixel regardless of
/// the caller's pen width (wide lines are a future slice).
void GdiDrawLineOnBitmap(Bitmap* bmp, i32 x0, i32 y0, i32 x1, i32 y1, u32 rgb);

// Per-window DC state. Window HDCs don't need a separate entry in
// the handle registry because HDC == HWND (v0 design); instead, a
// parallel table indexed by compositor window handle carries the
// DC state so `SetTextColor(hwnd)` / `MoveToEx(hwnd, ...)` /
// `SelectObject(hwnd, pen)` all take effect as they would in real
// Windows. `kMaxWindows` slots matches the compositor's window
// registry size.
inline constexpr u32 kMaxWindowDcSlots = 16;

struct WindowDcState
{
    bool init;
    u32 text_color;
    u32 bk_color;
    u8 bk_mode;
    u64 selected_pen;
    i32 cur_x;
    i32 cur_y;
};

/// Look up (and lazily initialise) the DC state for a compositor
/// window handle. Returns nullptr for out-of-range handles. Lazy
/// init fills Win32 defaults (text=black, bk=white, OPAQUE, no pen
/// = BLACK_PEN, cur_pos=(0,0)).
WindowDcState* GdiWindowDcState(u32 window_handle);

// DC colour state (memDC only in v0; window-DC variants are no-op
// pass-throughs that return the supplied value so
// SetTextColor/GetTextColor round-trips don't break).
u32 GdiSetTextColor(u64 hdc, u32 rgb); // returns previous
u32 GdiSetBkColor(u64 hdc, u32 rgb);   // returns previous
u8 GdiSetBkMode(u64 hdc, u8 mode);     // returns previous

// Syscall dispatchers.
void DoGdiCreateCompatibleDC(arch::TrapFrame* frame);
void DoGdiCreateCompatibleBitmap(arch::TrapFrame* frame);
void DoGdiCreateSolidBrush(arch::TrapFrame* frame);
void DoGdiGetStockObject(arch::TrapFrame* frame);
void DoGdiSelectObject(arch::TrapFrame* frame);
void DoGdiDeleteDC(arch::TrapFrame* frame);
void DoGdiDeleteObject(arch::TrapFrame* frame);
void DoGdiBitBltDC(arch::TrapFrame* frame);
void DoGdiStretchBltDC(arch::TrapFrame* frame);
void DoGdiSetTextColor(arch::TrapFrame* frame);
void DoGdiSetBkColor(arch::TrapFrame* frame);
void DoGdiSetBkMode(arch::TrapFrame* frame);
void DoGdiCreatePen(arch::TrapFrame* frame);
void DoGdiMoveToEx(arch::TrapFrame* frame);
void DoGdiLineTo(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
