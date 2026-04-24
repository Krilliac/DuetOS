# render/drivers v5 — Rectangle/Ellipse/SetPixel IAT + pen state + MoveToEx/LineTo + DrawTextA

**Last updated:** 2026-04-24
**Type:** Observation
**Status:** Active — GDI outline primitives + text alignment are
now real. A Win32 PE that paints `Rectangle` / `Ellipse` /
`SetPixel` / `MoveToEx+LineTo` / `DrawTextA` gets visible pixels
on both window HDCs and memory DCs.

## What landed

### Rectangle / Ellipse / SetPixel — IAT routes for existing syscalls

The kernel's `SYS_GDI_RECTANGLE` (67), `SYS_GDI_ELLIPSE` (75),
`SYS_GDI_SET_PIXEL` (76) handlers were alive and wired into
`WindowClient*` display-list prims since v0, but had no IAT
route — `gdi32.Rectangle` etc. all returned dummy 1.

Three hand-written stubs (40 + 40 + 20 B at offsets
0xE8E..0xEF1) repack Win32's LTRB rect form + 4-arg SetPixel
shape into the kernel's (x, y, w, h, color) shape:

```asm
; Rectangle: LTRB → (L, T, R-L, B-T)
mov  r11, [rsp+40]   ; B (5th arg on stack)
sub  r11, r8         ; h = B - T
mov  r10, r9         ; R
sub  r10, rdx        ; w = R - L
mov  rdi, rcx        ; hwnd
mov  rsi, rdx        ; x = L
mov  rdx, r8         ; y = T
mov  r8,  r11        ; h
mov  r9d, 0xFFFFFF   ; colour = white (pen-aware in v5+)
mov  eax, 67
int  0x80
ret
```

SetPixelV aliases the same stub (BOOL return is a superset of
COLORREF). All four IAT retargets drop the previous
`kOffReturnOne` in favour of the new offsets.

### Pen state + stock pen handles

New `Pen` type in `gdi_objects.h` (rgb + width + stock flag).
Stock pens registered at slots 6..8 matching Win32 GetStockObject
codes: `WHITE_PEN = 6`, `BLACK_PEN = 7`, `NULL_PEN = 8`.
Non-stock pens via `CreatePen` start at slot 9.

The type-tag convention grew a fourth kind: `kGdiTagPen =
0x04000000`. `GdiLookupPen` mirrors the existing lookup helpers.

`SelectObject` now routes HPEN selections into both memDC's
`selected_pen` and window-DC state's `selected_pen`. Brushes
still round-trip on memDC (no use case for brush selection
tracking beyond FillRect, which takes the brush/colour as an
explicit arg).

### Per-window DC state

Before: `HDC == HWND` on window HDCs, no DC state tracked.
`SetTextColor(hwnd)` round-tripped but didn't stick.

After: a parallel `WindowDcState[16]` table indexed by
compositor window handle. Same shape as `MemDC` — text/bk
colour + mode, selected pen, current position. Lazily
initialised on first `GdiWindowDcState(h)` call with Win32
defaults (black text, white bk, OPAQUE, no pen, cur=(0,0)).

`GdiSetTextColor / GdiSetBkColor / GdiSetBkMode / GdiSelectObject`
all got a window-HDC branch that writes into this table. The
`DoGdiTextOut` window path now reads the stored `text_color`
before falling back to the syscall's colour arg.

Scoping note: the side table is system-wide (not per-process),
same as the handle registry. A malicious PE could call
`SetTextColor` on a window owned by another process — but
`HwndToCompositorHandleForCaller` still guards every actual
paint call, so the DC-state write is harmless without an
accompanying paint syscall that would be refused.

### MoveToEx / LineTo with Bresenham on memDC

Two new syscalls: `SYS_GDI_MOVE_TO_EX (119)`, `SYS_GDI_LINE_TO
(120)`. MoveToEx updates the DC's cur_x/cur_y + (optionally)
writes the old position to a user POINT; LineTo reads cur_x/y,
draws to (x1, y1), updates cur_x/y.

New helper `GdiDrawLineOnBitmap` implements standard Bresenham
with a per-pixel surface clip. No Cohen-Sutherland pre-clip —
single-pixel writes are cheap enough that an early out beats a
clip test in the common case.

Pen-colour resolution (helper `ResolvePenColor`): look up
selected_pen on memDC or on window DC state, fall back to
`BLACK_PEN` (0x000000) if none selected.

### DrawTextA with alignment

`SYS_GDI_DRAW_TEXT_USER (121)` takes a user string (bounded 127
chars), an LPRECT, and Win32 format flags. Measures the text at
a fixed 8-px/glyph advance (matches our font8x8), computes
origin from alignment flags:

| Flag         | Effect                                            |
| ------------ | ------------------------------------------------- |
| DT_LEFT (0)  | default                                           |
| DT_CENTER    | `x = rect.left + (rw - text_w) / 2`               |
| DT_RIGHT     | `x = rect.right - text_w`                         |
| DT_TOP (0)   | default                                           |
| DT_VCENTER   | `y = rect.top + (rh - 8) / 2`                     |
| DT_SINGLELINE| implied (multi-line not in v0 scope)              |

Dispatch by HDC tag: memDC → GdiPaintTextOnBitmap, window →
WindowClientTextOut. Both honour the DC's text colour; memDC
also honours bk_mode / bk_color.

IAT stub at 0xF28 (25 bytes). Both `gdi32.DrawTextA` and
`user32.DrawTextA` retargeted — Microsoft moved the export
between DLLs between Windows versions.

## Typical Win32 paint handler now visible end-to-end

```c
case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    SetBkMode(hdc, OPAQUE);
    SetBkColor(hdc, RGB(0, 0, 64));        // dark blue
    SetTextColor(hdc, RGB(255, 255, 255)); // white

    RECT title = {10, 10, 200, 30};
    DrawTextA(hdc, "Hello, DuetOS!", -1, &title, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 0, 0));
    SelectObject(hdc, pen);
    MoveToEx(hdc, 10, 40, NULL);
    LineTo(hdc, 190, 40);                   // red underline

    Rectangle(hdc, 10, 50, 190, 100);       // outlined box
    Ellipse(hdc, 60, 110, 140, 150);        // outlined circle
    DeleteObject(pen);

    EndPaint(hwnd, &ps);
    return 0;
}
```

Every call above is now backed by real kernel state and produces
the expected pixels in the window.

## Still missing after v5

- Input routing: mouse clicks + key events → WM_LBUTTONDOWN /
  WM_KEYDOWN / WM_MOUSEMOVE in the focused/captured window's
  message queue. Without this, PEs can paint but can't be
  interacted with. This is the most user-visible gap.
- Pen width > 1 (Bresenham currently draws a single-pixel line
  regardless of the pen's `width` field).
- DT_WORDBREAK + multi-line text in DrawTextA.
- SetDIBits / StretchDIBits for raw pixel upload from PE.
- Rectangle / Ellipse should fill with the current brush (we
  currently only draw the 1-px outline).
- Polygon + Polyline.
- Region support (HRGN) for CombineRgn / FillRgn.

## Pattern — expose helpers across files via a central types header

Adding `HwndToCompositorHandleForCaller` to `window_syscall.h` in
v3 unlocked cross-module GDI work. v5 extended this: `GdiWindowDcState`
is public from `gdi_objects.h` so `window_syscall.cpp` can consult
per-window text colour without a back-door include. Any time
state's natural owner is in one module but consumers are in
several, hoist the lookup to the header.

## References

- `kernel/subsystems/win32/gdi_objects.{h,cpp}` — Pen registry,
  WindowDcState, CreatePen, MoveToEx, LineTo, Bresenham helper,
  ResolvePenColor.
- `kernel/subsystems/win32/window_syscall.cpp` — DoGdiDrawText
  with alignment flags.
- `kernel/subsystems/win32/stubs.cpp` — offsets 0xE8E..0xF40
  (Rectangle/Ellipse/SetPixel/CreatePen/MoveToEx/LineTo/DrawTextA).
- `kernel/core/syscall.h` — SYS_GDI_CREATE_PEN (118) through
  SYS_GDI_DRAW_TEXT_USER (121).
