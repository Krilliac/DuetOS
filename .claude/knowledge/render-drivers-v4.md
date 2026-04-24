# render/drivers v4 — memDC painting + DC colour state + StretchBlt

**Last updated:** 2026-04-24
**Type:** Observation
**Status:** Active — memDCs are now first-class off-screen render
targets. Every GDI primitive routed through the v3 object table
works equally on windows and on memDCs, so the canonical Win32
double-buffered paint idiom produces real pixels end-to-end.

## What landed

### Paint into memDC bitmaps

The v3 slice landed the HDC/HBITMAP registry but left a gap: no
syscall wrote pixels INTO a memDC's selected bitmap, so
`BitBlt(hdc, ..., memDC, ..., SRCCOPY)` only ever copied zeros.

Fix: three kernel paint helpers in `gdi_objects.cpp` that write
raw BGRA pixels into a `Bitmap*`:

- `GdiPaintRectOnBitmap(bmp, x, y, w, h, rgb)` — surface-clipped
  solid fill.
- `GdiPaintTextOnBitmap(bmp, x, y, text, fg, bg, opaque)` —
  8x8 font render via `Font8x8Lookup` with per-pixel clipping.
  TRANSPARENT mode leaves non-glyph pixels untouched; OPAQUE
  fills the glyph cell background with `bg`.
- `GdiBlitIntoBitmap(bmp, dx, dy, src, sw, sh, src_pitch_px)` —
  BGRA rect copy with pitch + source-offset slide for negative
  dst coordinates.

The syscall dispatchers `DoGdiFillRectUser`, `DoGdiTextOut`, and
`DoGdiBitBltDC` now inspect the destination HDC's type tag
(bits 27:24) and branch:

- Tag `kGdiTagMemDC` → look up the memDC's `selected_bitmap`,
  call the matching bitmap helper.
- Tag `0` (no tag) → treat as HWND, call the existing
  `WindowClient*` display-list path + recompose.

BitBlt also picked up a memDC-to-memDC case (write directly into
the dst bitmap, no staging round-trip).

### DC colour state

`MemDC` struct extended with:

| Field         | Win32 default                  |
| ------------- | ------------------------------ |
| `text_color`  | 0x000000 (black)               |
| `bk_color`    | 0xFFFFFF (white)               |
| `bk_mode`     | `OPAQUE` (2)                   |

`CreateCompatibleDC` installs those defaults, so a PE that skips
`SetTextColor` and draws straight after `BeginPaint` gets the
Win32 standard black-on-white output (instead of our previous
hard-coded white).

Three new syscalls + IAT stubs:

| Syscall                    | # | Win32 entry point |
| -------------------------- | - | ----------------- |
| SYS_GDI_SET_TEXT_COLOR     | 114 | SetTextColor    |
| SYS_GDI_SET_BK_COLOR       | 115 | SetBkColor      |
| SYS_GDI_SET_BK_MODE        | 116 | SetBkMode       |

Each returns the previous value (Win32 round-trip semantics).
Window HDCs (no tag bits) are treated as a "round-trip the input"
no-op — pair round-trips still work, but the value has no effect
until we grow per-window DC state.

`GdiPaintTextOnBitmap` now consults the DC's colour state. The
existing IAT stub for `gdi32.TextOutA` still defaults the
syscall's `r9` colour arg to white — that's ignored when the
target is a memDC (the bitmap helper reads from the MemDC
struct) and used only when the target is a window.

### StretchBlt — nearest-neighbor

Win32 `StretchBlt` takes 11 args. Same user-stack-struct pattern
as BitBlt:

- User IAT stub (`sub rsp, 88`) packs 11 u64 slots —
  hdcDst/dst_x/dst_y/dst_w/dst_h/hdcSrc/src_x/src_y/src_w/src_h/
  rop — then `mov rdi, rsp; mov eax, 117; int 0x80`.
- Stack args land at `[rsp+128..+176]` after the sub (8-byte
  disp32 encoding because the displacement ≥ 128).
- Kernel does one CopyFromUser, validates the src rect fits in
  the src bitmap, caps `dst_w * dst_h` at `kWinBlitMaxPx` (4096
  px), KMallocs a staging buffer, and runs a nearest-neighbor
  sample loop:
  ```
  sx = src_x + (ox * src_w) / dst_w
  sy = src_y + (oy * src_h) / dst_h
  ```
  with u64 intermediates so large dims don't overflow the
  multiply.
- Dispatch by dst tag matches BitBlt.

129-byte stub is the longest one on the page; total layout now
ends at 0xE8E (3726 bytes of the 4 KiB stub page).

## Canonical flow that works now

```c
case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);                    // 103
    HDC memDC = CreateCompatibleDC(hdc);                // 106
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);    // 107
    SelectObject(memDC, bmp);                           // 110
    SetTextColor(memDC, RGB(255,255,255));              // 114
    SetBkColor(memDC,   RGB(  0,  0,  0));              // 115
    SetBkMode(memDC, OPAQUE);                           // 116
    RECT rc = {0, 0, w, h};
    FillRect(memDC, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
                                                        // 105 via 109
    TextOutA(memDC, 10, 10, "Hello", 5);                // 66
    BitBlt(hdc, 0, 0, w, h, memDC, 0, 0, SRCCOPY);      // 113
    DeleteObject(bmp);                                  // 112
    DeleteDC(memDC);                                    // 111
    EndPaint(hwnd, &ps);                                // 104
}
```

Every syscall in that list is wired; every GDI primitive that
touches `memDC` writes into its bitmap; the final BitBlt copies
those pixels into the window's display list → compositor →
framebuffer (→ virtio-gpu host if present).

## Observation — memDC paint path bypasses the compositor lock

`WindowClientFillRect` / `WindowClientTextOut` take the
compositor lock before recording a display-list prim. The memDC
equivalents (`GdiPaintRectOnBitmap` etc.) don't — the bitmap
is process-owned state, not shared compositor state. That's
correct but worth flagging: a PE that spawns two threads both
painting into the same memDC will corrupt pixels (tearing at
worst, lost writes more commonly). Single-threaded PEs (which
is essentially every v0 PE) are fine.

If we grow a multithreaded-paint story, add a per-bitmap mutex
to `Bitmap`.

## Remaining gaps

- **Window-DC colour state**: `SetTextColor` on a window HDC
  round-trips but doesn't take effect. Needs a per-window DC
  state (probably a parallel `g_window_dc_state[kMaxWindows]`
  array indexed by compositor window handle).
- **Bilinear StretchBlt**: nearest-neighbor is fine for integer
  multiples but visibly jagged for arbitrary scale. Real
  Windows defaults to nearest too but supports `SetStretchBltMode
  (HALFTONE)` for a box filter. Defer until a real use case.
- **Pen state + line primitives**: `CreatePen`, `MoveToEx`,
  `LineTo` still land on `kOffReturnOne`. Would need a pen
  registry in `gdi_objects.cpp`.
- **DrawTextA / DrawTextEx**: more sophisticated than TextOutA
  (alignment, wrapping, RECT-bounded). Skipped for v4.

## Pattern — type-tag dispatch in syscall handlers

v3 introduced the tag-in-bits-27:24 convention for GDI handles.
v4 cemented it as the dispatch pattern — every `DoGdi*` that
accepts an HDC starts with:

```cpp
const u64 tag = hdc & kGdiTagMask;
if (tag == kGdiTagMemDC) { ... bitmap-path ... }
else if (tag == 0)       { ... window-path ... }
else                     { frame->rax = 0; return; }
```

Clean, zero lookups for the type check, extensible when a new
handle class lands (HBRUSH-as-DC? HRGN?).

## References

- `kernel/subsystems/win32/gdi_objects.{h,cpp}` —
  paint helpers, colour-state accessors, StretchBlt handler.
- `kernel/subsystems/win32/window_syscall.cpp` — DoGdiFillRectUser
  + DoGdiTextOut tag-dispatch.
- `kernel/subsystems/win32/stubs.cpp` — offsets 0xDE3..0xE8D
  (3 colour-state stubs, 1 StretchBlt stub).
- `kernel/core/syscall.h` — SYS_GDI_SET_TEXT_COLOR (114) through
  SYS_GDI_STRETCH_BLT_DC (117).
