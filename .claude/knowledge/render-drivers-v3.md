# render/drivers v3 — virtio-gpu kernel FB + TextOutA + GDI object table + real BitBlt

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Active — the classic Windows double-buffered paint
idiom works end-to-end: `BeginPaint → CreateCompatibleDC →
CreateCompatibleBitmap → SelectObject → BitBlt → EndPaint` now
reaches the kernel compositor and (on virtio-gpu hosts) actually
lands pixels on the display.

## What landed

### virtio-gpu as kernel framebuffer

- `FramebufferRebindExternal(virt, phys, w, h, pitch, bpp)` —
  sibling of `FramebufferRebind` that accepts an already-mapped
  kernel VA. The existing `FramebufferRebind` always calls
  `MapMmio`, which is wrong for RAM-backed framebuffers (forces
  uncacheable mapping + consumes MMIO arena). The new entry
  point is the correct primitive for virtio-gpu backing and any
  future guest-owned framebuffer.
- `FramebufferSetPresentHook(fn)` + `FramebufferPresent()`
  registers a backend-driver callback that runs as the last step
  of `DesktopCompose`. `drivers/gpu/gpu.cpp` installs a hook
  after `VirtioGpuSetupScanout`: each compose triggers
  `VirtioGpuFlushScanout(0, 0, full_w, full_h)`, issuing
  TRANSFER_TO_HOST_2D + RESOURCE_FLUSH.
- Net effect: on QEMU `-vga virtio` the compositor writes
  straight into the virtio-gpu backing, and every frame lands on
  the host display after one flush. No double-buffering overhead
  (the guest memory IS the back buffer).

### Real gdi32.TextOutA

31-byte IAT stub that repacks the Win32 x64 ABI for
`TextOutA(HDC, int x, int y, LPCSTR, int cchString)`. The 5th
arg (`cchString`) lives on the user stack at `[rsp+0x28]` — 8
bytes above the 32-byte shadow space. Reused the existing
SYS_GDI_TEXT_OUT (66); defaulted ink colour to white because the
Win32 API carries text colour on the DC (via `SetTextColor`,
which we don't track yet). Moves gdi32.TextOutA from "returns 1,
no effect" to "records a TextOut display-list primitive that the
compositor replays with 8x8 glyphs."

### GDI object handle registry

New module `subsystems/win32/gdi_objects.{h,cpp}`. Three typed
handle tables (up to 64 each) with a **4-bit type tag in bits
27:24** of the handle value:

| Kind    | Tag         | Payload                                      |
| ------- | ----------- | -------------------------------------------- |
| MemDC   | `0x01000000` | `selected_bitmap` handle                    |
| Bitmap  | `0x02000000` | `width`, `height`, `pitch`, KMalloc BGRA    |
| Brush   | `0x03000000` | RGB + `stock` bit                           |

Design choices:
- **Type tag makes `SelectObject` / `DeleteObject` dispatch by
  inspection** instead of walking every table. A `DeleteObject`
  for a bitmap handle only touches the bitmap table.
- **Stock brushes pre-registered at slot 0..5.** GetStockObject
  returns a deterministic handle (`0x03000000 | stock_index`)
  without going through the allocator. Non-stock
  CreateSolidBrush starts at slot 6.
- **System-wide (not per-process)** — a process that leaks a
  bitmap leaks across the system. Acceptable v0, tightens when
  we add per-process GDI table scoping.
- **Bounded bitmap size** — `kMaxBitmapPixels = 1024 × 1024` =
  4 MiB worst case per bitmap. Keeps a malicious caller from
  demanding a 100 MB alloc.

Seven syscalls (106–112), seven 11–17-byte IAT stubs. Stubs
replaced dummy `kOffReturnOne` for `CreateCompatibleDC`,
`CreateCompatibleBitmap`, `CreateSolidBrush`, `GetStockObject`,
`SelectObject`, `DeleteDC`, `DeleteObject`.

### Real BitBlt (memory DC → window)

BitBlt has **9 args** which our 6-register syscall ABI can't
carry directly. Solution:

- User stub builds a **72-byte args struct on its own stack**
  (`sub rsp, 72`), copies rcx/rdx/r8/r9 + four stack slots
  `[rsp+40..72]` + rop into the struct, passes struct pointer in
  `rdi` to SYS_GDI_BITBLT_DC (113), adds rsp back and returns.
- 103 bytes of ASM at stub offset 0xD7C. Tested at compile time:
  each `mov rax, [rsp+N]` uses a 4-byte disp8/disp32 SIB-relative
  form because N is ≥ 112.

Kernel (`DoGdiBitBltDC`):

1. CopyFromUser the 72-byte struct.
2. Cast low 32 bits of each integer slot to `i32`. Upper 32 bits
   are Win64-undefined — we tolerate garbage there.
3. Bound-check dimensions: `cx × cy ≤ kWinBlitMaxPx = 4096` px.
4. Resolve source `hdc_src` — must be a memory DC with a
   selected bitmap; otherwise fail.
5. Validate src subrect fits inside the bitmap extents.
6. Extract the subrect into a KMalloc'd BGRA staging buffer
   (tight-packed, pitch = cx*4).
7. Resolve dst `hdc_dst` — currently **must be a window HWND**
   (no tag bits set); memDC-to-memDC blit not yet wired.
8. `WindowClientBitBlt(h_comp, dst_x, dst_y, staging, cx, cy)`
   records a Blit primitive in the window's display list.
9. `DesktopCompose` + KFree staging.

ROP value is ignored — SRCCOPY is the only supported raster op
in v0. Not an issue for the double-buffered paint idiom since
that's what `BitBlt(..., SRCCOPY)` is nearly always.

### End-to-end flow that now works

Canonical WM_PAINT handler:
```c
case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);            // SYS_WIN_BEGIN_PAINT
    HDC memDC = CreateCompatibleDC(hdc);        // SYS_GDI_CREATE_COMPAT_DC
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
                                                 // SYS_GDI_CREATE_COMPAT_BITMAP
    SelectObject(memDC, bmp);                    // SYS_GDI_SELECT_OBJECT
    // (paint into memDC via any draw path that writes to bmp->pixels)
    BitBlt(hdc, 0, 0, w, h, memDC, 0, 0, SRCCOPY);
                                                 // SYS_GDI_BITBLT_DC
    DeleteObject(bmp);                           // SYS_GDI_DELETE_OBJECT
    DeleteDC(memDC);                             // SYS_GDI_DELETE_DC
    EndPaint(hwnd, &ps);                         // SYS_WIN_END_PAINT
    return 0;
}
```

Every syscall in that list is now backed by real kernel state.
The paint actually displays — previously this idiom silently
no-op'd through dummy `kOffReturnOne` stubs.

### Gap — how does the memDC get painted in the first place?

`SelectObject(memDC, bmp)` gives the memDC a bitmap, but today
we have no syscalls that let user mode write pixels INTO the
bitmap. The bitmap starts zeroed (per spec), and nothing ever
touches it. So BitBlt-from-memDC currently copies a black
rectangle to the window.

Next-slice targets:
- **GDI primitives on memDC** — extend SYS_GDI_FILL_RECT_USER,
  TextOutA, etc. to also accept memDC handles (switch on
  GdiHandleType) and write into the bitmap instead of the
  display list.
- **StretchBlt** — resize + BitBlt in one.
- **SetDIBits / GetDIBits** — raw pixel upload/download.
- **SetTextColor / SetBkColor** — real DC colour state so
  TextOutA doesn't have to hard-code white.

## Pattern — struct-on-stack for many-arg Win32 syscalls

Win64 ABI passes only the first 4 args in registers (rcx, rdx,
r8, r9). Our syscall ABI has 6 slots (rdi, rsi, rdx, r10, r8,
r9). For any Win32 import with > 6 args — BitBlt, StretchBlt,
CreateWindowExA (12 args!), MessageBoxExA — the clean pattern is:

1. User IAT stub `sub rsp, sizeof(struct)` on its own stack.
2. `mov [rsp+N], reg` for each register arg and
   `mov rax, [rsp+old_slot]; mov [rsp+N], rax` for each stack
   arg. Use 8-byte u64 slots for everything — the kernel reads
   only the low 32 bits for int args.
3. `mov rdi, rsp; mov eax, SYS_NUM; int 0x80`.
4. `add rsp, sizeof(struct); ret`.

Kernel does one `CopyFromUser(&args, rdi, sizeof(struct))` and
then reads fields normally. Much cleaner than register-budget
gymnastics.

Downside: adds ~100 B per large-arg IAT stub. Given we have
~700 B remaining in the stub page, we can fit ~7 more of these
before needing a second page.

## Observation — where pre-existing gdi32 entries stood

Before this slice: 44 gdi32 IAT entries, all pointing at
`kOffReturnOne`. After: 10 retargeted at real handlers
(CreateCompatibleDC, CreateCompatibleBitmap, CreateSolidBrush,
GetStockObject, SelectObject, DeleteDC, DeleteObject, BitBlt,
FillRect, TextOutA). The remaining 34 still return a placeholder
1 — most of those handle paths (lines, ellipses, polygon,
stretch-blt, DIB section, pen/font family) are candidates for
future slices.

## References

- `kernel/drivers/video/framebuffer.{h,cpp}` —
  `FramebufferRebindExternal`, `FramebufferPresent`,
  `FramebufferSetPresentHook`.
- `kernel/drivers/video/widget.cpp` — `DesktopCompose` calls
  `FramebufferPresent` as its final step.
- `kernel/drivers/gpu/gpu.cpp` — installs present hook +
  rebinds framebuffer after virtio-gpu v2 setup.
- `kernel/subsystems/win32/gdi_objects.{h,cpp}` — entire new
  module.
- `kernel/subsystems/win32/stubs.cpp` — stub offsets
  `0xD07..0xDE2`, new IAT retargets.
- `kernel/subsystems/win32/window_syscall.{h,cpp}` —
  `HwndToCompositorHandleForCaller` exposed for cross-module use.
- `kernel/core/syscall.h` — SYS_GDI_CREATE_COMPAT_DC (106)
  through SYS_GDI_BITBLT_DC (113).
