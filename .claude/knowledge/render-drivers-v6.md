# Render / drivers — current state (through v6)

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active — a Win32 GUI app paints, takes mouse +
keyboard input, dispatches WM_PAINT through a user-registered
WndProc, and queries the system palette. End-to-end on every
boot via `windowed_hello`.

## Scope

Cumulative snapshot of every render / GDI / GPU bring-up slice
that has landed. Replaces the per-slice notes
(`render-drivers-v1/v2/v3/v4/v5`) — git history preserves them;
this doc captures the system as it stands today. The matching
windowing-side slice notes live in `win32-windowing-v1.4.md`.

## Stack

```
PE (gdi32 IAT) ──► gdi32 stub bytecode (8 KiB R-X over 2 frames) ──► int 0x80
                                                                      │
                                                                      ▼
                                                                 SYS_GDI_*
                                                                      │
                                                       ┌──────────────┴────────────────┐
                                                       ▼                               ▼
                                          window-DC compositor prims           memDC bitmap pixel writes
                                          (display-list in widget.cpp)        (gdi_objects.cpp paint helpers)
                                                       │                               │
                                                       └──────────► framebuffer ◄──────┘
                                                                          │
                                                                          ▼
                                                              FramebufferPresent hook
                                                                          │
                                                                          ▼
                                                       virtio-gpu TRANSFER_TO_HOST_2D + RESOURCE_FLUSH
                                                          (or noop on plain `-vga std`)
```

## What is wired

### GPU discovery + virtio-gpu kernel framebuffer
- `drivers/gpu/gpu.cpp` walks PCI display-class devices, maps
  BAR0, runs vendor-specific MMIO liveness probes (NVIDIA reads
  `PMC_BOOT_0`; Intel reads BAR0+0; AMD GFX9+ documents the BAR5
  gap without mapping).
- `drivers/gpu/virtio_gpu.cpp` runs the full virtio 1.0 §3.1.1
  handshake, then the five-command 2D scanout cycle:
  RESOURCE_CREATE_2D / ATTACH_BACKING / SET_SCANOUT /
  TRANSFER_TO_HOST_2D / RESOURCE_FLUSH. Backing pages are
  RAM-allocated via `AllocateContiguousFrames` and bound to the
  framebuffer via `FramebufferRebindExternal` (the cacheable
  sibling of `FramebufferRebind` — virtio-gpu backing must NOT
  go through `MapMmio`).
- `FramebufferSetPresentHook(fn)` registers the per-compose
  flush callback. On QEMU `-vga virtio` every desktop compose
  flushes through to the host.

### GDI object table
- `gdi_objects.{h,cpp}` owns four parallel arrays: `g_pens`,
  `g_brushes`, `g_bitmaps`, `g_mem_dcs`. Handles encode a tag
  in the high bits (`kGdiTagPen`, `kGdiTagBrush`, `kGdiTagBitmap`,
  `kGdiTagMemDC`); raw 0..N values are window HDCs.
- `WindowDcState` (one per compositor window slot) holds
  `text_color` + `text_color_set` flag (so SetTextColor(BLACK) is
  honored), `bk_color`, `bk_mode`, `selected_pen`, `selected_brush`,
  `cur_x` / `cur_y` for MoveToEx + LineTo.
- `MemDC` mirrors that state with an additional `selected_bitmap`.
  memDC paint helpers always read `text_color` directly (no flag
  needed because the field is the only source).
- Stock objects (`GetStockObject`) return real handles; deleting
  them is a safe no-op.

### Outline + fill primitives
- `Rectangle` (LTRB, fill+outline), `FillRect`, `Ellipse`
  (fill+outline including a window-path `FilledEllipse` compositor
  prim and a memDC outline-on-fill helper),
  `MoveToEx` + `LineTo` (Bresenham), `SetPixel`, `PatBlt`
  (PATCOPY only — ROP ignored).
- Filled-shape syscalls: `SYS_GDI_RECTANGLE_FILLED` (122),
  `SYS_GDI_ELLIPSE_FILLED` (123), `SYS_GDI_PAT_BLT` (124).
- The integer-ellipse test
  `(x-cx)²·b² + (y-cy)²·a² ≤ a²·b²` is used everywhere — no sqrt,
  no sin/cos.

### Text
- `TextOutA` (66) / `TextOutW` (125) / `DrawTextA` (alignment) /
  `DrawTextW` (126). UTF-16 text is downcoded to ASCII on the
  syscall boundary (`(char)wc` if `wc < 0x80`, else `'?'`).
- 8×8 built-in font (`drivers/video/font8x8.cpp`): ASCII +
  digits + punctuation. Lowercase aliased to uppercase. Unmapped
  codes render as a filled-box placeholder.
- `DrawTextAsciiOnDc` is the alignment + dispatch core shared by
  the A and W variants after their respective copy-ins.

### memDC pixel writes
- `GdiPaintRectOnBitmap(bmp, x, y, w, h, rgb)` — clipped solid
  fill.
- `GdiPaintTextOnBitmap(bmp, x, y, text, fg, bg, opaque)` — 8×8
  glyphs with per-pixel clipping. TRANSPARENT mode leaves
  non-glyph pixels untouched.
- `GdiBlitIntoBitmap(bmp, dx, dy, src, sw, sh, src_pitch_px)` —
  BGRA rect copy with pitch + source-offset slide for negative
  dst coordinates.

### BitBlt / StretchBlt
- `SYS_GDI_BITBLT` (window↔window, window↔memDC, memDC↔memDC,
  via the object-table dispatch).
- `SYS_GDI_STRETCH_BLT_DC` (117): 11-arg StretchBlt packed into
  a single user-stack struct, nearest-neighbor sampling, capped
  at `kWinBlitMaxPx`.

### System palette
- 31-entry Classic-theme table covers `COLOR_SCROLLBAR` (0)
  through `COLOR_MENUBAR` (30). `GetSysColor` returns the raw
  COLORREF; `GdiSysColorBrush(idx)` lazily allocates a real
  HBRUSH on first access and caches it with `.stock = true`.

### Stub page
- `kernel/subsystems/win32/thunks.cpp` lives across two contiguous
  4 KiB R-X frames at `kWin32StubsVa` (allocated by
  `pe_loader.cpp:PeLoad` via `AllocateContiguousFrames(2)`).
  Static-asserted at `<= 8192`; current end ~0x1048 leaves
  ~50 % of the second page free.

## Worked example — what a real PE now does

```c
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        FillRect(hdc, &ps.rcPaint, GetSysColorBrush(COLOR_WINDOW));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
        RECT r = {10, 10, 300, 40};
        DrawTextW(hdc, L"Hello, DuetOS!", -1, &r,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Rectangle(hdc, 10, 60, 290, 120);   // filled + outlined
        EndPaint(h, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN:
        MessageBoxA(h, "You clicked!", "Hi", MB_OK);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}
```

Every call has a real backing.

## Not yet wired

- **Real Unicode rendering** — non-ASCII renders `?`.
- **Pen width > 1** — thick lines.
- **DT_WORDBREAK + multi-line DrawText**.
- **SetDIBits / StretchDIBits** — raw pixel upload from PE memory.
- **GetSystemMetrics** — returns 0 for all indices.
- **Hardware-accelerated paint paths** — every prim is CPU
  software-renderered into the framebuffer; the GPU drivers
  do scanout + flush only.

## References

- `kernel/subsystems/win32/thunks.cpp` — gdi32 IAT bytecode.
- `kernel/subsystems/win32/gdi_objects.{h,cpp}` — handle table,
  paint helpers, sys-palette table + brush pool.
- `kernel/subsystems/win32/window_syscall.cpp` — DoGdi* dispatch
  + DrawTextAsciiOnDc helper.
- `kernel/syscall/syscall.h` — SYS_GDI_* (60–128) constants and ABI.
- `kernel/drivers/gpu/virtio_gpu.cpp` — virtio-gpu 2D cycle.
- `kernel/drivers/video/widget.cpp` — compositor + display-list
  prims (FilledEllipse, FillRect, Rectangle, TextOut, ...).
- `kernel/drivers/video/font8x8.{h,cpp}` — 8×8 font lookup.

## Notes

- **See also:** [win32-windowing-v1.4.md](win32-windowing-v1.4.md)
  for the message-pump + lifecycle layer that drives this paint
  surface.
- **See also:** [directx-v0.md](directx-v0.md) for the COM-vtable
  d3d/dxgi DLLs that sit alongside gdi32.
