#pragma once

#include "arch/x86_64/traps.h"
#include "util/types.h"

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
 * OWNERSHIP
 *   The tables are system-wide but every non-stock object records
 *   the pid that created it, and `GdiLookup*` refuses a handle whose
 *   owner is not the calling process. That check lives in the lookup
 *   rather than at each syscall entry on purpose: handle values are
 *   `tag | index` with index in 0..63, so they are trivially
 *   guessable, and a per-call-site allow-list would only have to
 *   miss once for a PE to read another process's off-screen pixels
 *   back out through BitBlt.
 *
 *   Creation is bounded per-process (kMax*PerProcess plus a byte
 *   budget for pixel-backed objects) so one guest cannot take every
 *   slot, and `GdiReapByOwner` frees whatever a process still holds
 *   when it exits.
 *
 * Not in scope (v0):
 *   - HRGN state (stock handles only, no real draw-path consumers).
 *   - Coordinate transforms (no SetWindowOrgEx et al.).
 *   - Palettised (<= 8bpp) DIBs. 16 / 24 / 32bpp only.
 *
 * Context: kernel. Every entry point is reachable from a ring-3 PE
 * via a SYS_GDI_* syscall; the handle-manager side holds no locks
 * of its own (the compositor mutex held by the caller suffices).
 */

namespace duetos::subsystems::graphics
{
struct FontEntry;
} // namespace duetos::subsystems::graphics

namespace duetos::subsystems::win32
{

// Handle tag in bits 27:24 (chosen so values are still small enough
// to fit in the int32 HDC / HBITMAP Win32 types if a PE uses that).
inline constexpr u64 kGdiTagMask = 0x0F000000u;
inline constexpr u64 kGdiTagMemDC = 0x01000000u;
inline constexpr u64 kGdiTagBitmap = 0x02000000u;
inline constexpr u64 kGdiTagBrush = 0x03000000u;
inline constexpr u64 kGdiTagPen = 0x04000000u;
inline constexpr u64 kGdiTagFont = 0x05000000u;

inline constexpr u32 kMaxMemDcs = 64;
inline constexpr u32 kMaxBitmaps = 64;
inline constexpr u32 kMaxBrushes = 64;
inline constexpr u32 kMaxPens = 64;
inline constexpr u32 kMaxFonts = 64;

// Max pixels per compatible bitmap. Keeps a malicious caller from
// requesting a 100 MB bitmap. 1024 × 1024 × 4 = 4 MiB per bitmap.
// (Same value as gdi_surface_math.h's kMaxSurfacePixels, which is
// what actually enforces it — this alias keeps existing callers
// reading naturally.)
inline constexpr u32 kMaxBitmapPixels = 1024 * 1024;

// Per-process ceilings. The tables above are the SYSTEM-wide limit;
// these bound what any single guest can hold out of them, so a PE
// that leaks (or deliberately hoards) cannot deny GDI to every
// process that starts after it. 8 MiB of off-screen pixels is four
// full 1024x768 double-buffers — comfortably more than a v0 Win32
// app needs and 1/32 of the system total.
inline constexpr u32 kMaxMemDcsPerProcess = 16;
inline constexpr u32 kMaxBitmapsPerProcess = 16;
inline constexpr u32 kMaxBrushesPerProcess = 16;
inline constexpr u32 kMaxPensPerProcess = 16;
inline constexpr u32 kMaxFontsPerProcess = 16;
inline constexpr u64 kMaxBitmapBytesPerProcess = 8u * 1024u * 1024u;

// Background mode constants — Win32 SetBkMode values.
inline constexpr u8 kBkModeTransparent = 1;
inline constexpr u8 kBkModeOpaque = 2;

struct MemDC
{
    bool alive;
    u64 owner_pid;       // creating process; only that pid may look it up
    u64 selected_bitmap; // HBITMAP handle (with tag) or 0 = none
    u64 selected_pen;    // HPEN handle (with tag) or 0 = use BLACK_PEN implicitly
    u64 selected_brush;  // HBRUSH handle (with tag) or 0 = use WHITE_BRUSH implicitly
    u64 selected_font;   // HFONT handle (with tag) or 0 = use SYSTEM_FONT implicitly
    u32 text_color;      // 0x00RRGGBB (unpacked from COLORREF on set)
    u32 bk_color;        // 0x00RRGGBB
    u8 bk_mode;          // kBkModeTransparent (default) or kBkModeOpaque
    i32 cur_x;           // DC current position, set by MoveToEx, read by LineTo
    i32 cur_y;
};

struct Bitmap
{
    bool alive;
    u64 owner_pid;
    u32 width;
    u32 height;
    u32 pitch;   // bytes per row; always width * 4 in v0
    u32* pixels; // kernel BGRA8888 buffer, KMalloc'd
};

struct Brush
{
    bool alive;
    u64 owner_pid; // 0 for stock / sys-colour brushes (shared, never freed)
    u32 rgb;       // 0x00RRGGBB
    bool stock;    // stock brushes are never freed
};

struct Pen
{
    bool alive;
    u64 owner_pid;
    u32 rgb;
    u32 width; // pixels; 0 means "1 pixel cosmetic"
    bool stock;
};

struct GdiFont
{
    bool alive;
    u64 owner_pid;
    u32 registry_index; // index into the font registry
    bool stock;         // stock fonts are never freed
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
inline constexpr u32 kStockSystemFont = 13;
inline constexpr u32 kStockSystemFixedFont = 16;

/// One-time registration of the pre-defined stock objects.
/// Safe to call multiple times (idempotent).
void GdiInit();

// Handle type inspection. Returns one of the kGdiTag* values, or 0
// if the handle has no tag (which includes every window HDC/HWND;
// public HWNDs reserve bits 24..31 as zero).
u64 GdiHandleType(u64 h);

// Accessors — return nullptr on an invalid handle OR on a handle
// owned by a different process. Stock and sys-colour brushes/pens
// are shared and resolve for everyone; DCs and bitmaps never are.
// The returned pointer is kernel-owned and stable until the handle
// is deleted.
//
// The owner check is what stops a PE from walking handle indices
// 0..63 and blitting another process's off-screen surface into its
// own window. Callers in kernel context (no current process) are
// treated as the kernel owner and see everything.
MemDC* GdiLookupMemDC(u64 h);
Bitmap* GdiLookupBitmap(u64 h);
Brush* GdiLookupBrush(u64 h);
Pen* GdiLookupPen(u64 h);
GdiFont* GdiLookupFont(u64 h);

/// Free every GDI object owned by `pid` and clear its slots. Called
/// from process teardown so an exiting PE cannot strand pixel bytes
/// or table slots for the rest of the boot. Returns the number of
/// objects reclaimed. Refuses pid == 0 (kernel/stock objects).
u32 GdiReapByOwner(u64 pid);

/// Unfiltered table census, for the leak detector. Deliberately not
/// expressed via GdiLookup* — those are owner-filtered now, and a
/// system-wide accounting pass must see every slot.
struct GdiUsage
{
    u32 mem_dcs;
    u32 bitmaps;
    u32 brushes; // non-stock only
    u32 pens;    // non-stock only
    u64 bitmap_bytes;
};
GdiUsage GdiSnapshotUsage();

// Operations (called from the syscall dispatchers).
u64 GdiCreateCompatibleDC();
u64 GdiCreateCompatibleBitmap(u32 width, u32 height);
u64 GdiCreateSolidBrush(u32 rgb);
u64 GdiCreatePen(u32 style, u32 width, u32 rgb);
u64 GdiCreateFont(u32 height, u32 weight, bool italic, u8 charset, const char* face_name);
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

/// Paint text using a specific font from the registry. If
/// `font_handle` is 0 or invalid, falls back to the 8x8 System font.
void GdiPaintTextOnBitmapWithFont(Bitmap* bmp, i32 x, i32 y, const char* text, u32 fg, u32 bg, bool opaque,
                                  u64 font_handle);

/// Resolve a DC's effective font. Returns the FontEntry pointer for
/// the DC's selected font, or the System font if none is selected.
const graphics::FontEntry* GdiResolveDcFont(u64 font_handle);

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
// parallel table indexed by the decoded compositor slot carries the
// DC state so `SetTextColor(hwnd)` / `MoveToEx(hwnd, ...)` /
// `SelectObject(hwnd, pen)` all take effect as they would in real
// Windows. `kMaxWindows` slots matches the compositor's window
// registry size.
inline constexpr u32 kMaxWindowDcSlots = 40;

struct WindowDcState
{
    bool init;
    bool text_color_set;
    u32 hwnd_identity; // exact public slot+generation identity
    u32 text_color;
    u32 bk_color;
    u8 bk_mode;
    u64 selected_pen;
    u64 selected_brush;
    u64 selected_font;
    i32 cur_x;
    i32 cur_y;
};

/// Resolve an owned, live public generation-tagged HWND and look up its
/// per-slot DC state. Stale/foreign identities are rejected. A new generation
/// resets every selection/colour field so reused compositor slots cannot
/// inherit state from a destroyed window.
WindowDcState* GdiWindowDcState(u32 public_hwnd);

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
void DoGdiRectangleFilled(arch::TrapFrame* frame);
void DoGdiEllipseFilled(arch::TrapFrame* frame);
void DoGdiPatBlt(arch::TrapFrame* frame);
void DoGdiGetSysColor(arch::TrapFrame* frame);
void DoGdiGetSysColorBrush(arch::TrapFrame* frame);
void DoGdiCreateFont(arch::TrapFrame* frame);
void DoGdiGetTextMetrics(arch::TrapFrame* frame);

// System palette — Win32 COLOR_* indices 0..30. Returns a
// Classic-theme COLORREF or 0x00C0C0C0 for unknown indices.
u32 GdiSysColor(u32 index);

/// HBRUSH for a sys-colour index. Pre-allocated at GdiInit time
/// and shared across processes (stock-like semantics — the
/// handle is never freed even if DeleteObject is called on it).
u64 GdiSysColorBrush(u32 index);

} // namespace duetos::subsystems::win32
