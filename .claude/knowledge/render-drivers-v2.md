# render/drivers v2 — virtio-gpu 2D + SYS_GDI_BITBLT + real paint IAT

**Last updated:** 2026-04-24
**Type:** Observation + Pattern
**Status:** Active — render stack is now end-to-end. Kernel drives
a virtio-gpu scanout; Win32 PEs that paint via the canonical
BeginPaint/FillRect/EndPaint idiom reach the compositor.

## What landed

### virtio-gpu v2 — full 2D display cycle

All five commands from the virtio-gpu 2D blit cycle now work:

| Command                         | ID      | DuetOS call                   |
| ------------------------------- | ------- | ----------------------------- |
| VIRTIO_GPU_CMD_RESOURCE_CREATE_2D | 0x0101 | `VirtioGpuSetupScanout`       |
| VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING | 0x0106 | (same — step 2)          |
| VIRTIO_GPU_CMD_SET_SCANOUT      | 0x0103 | (same — step 3)               |
| VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D | 0x0105 | `VirtioGpuFlushScanout`     |
| VIRTIO_GPU_CMD_RESOURCE_FLUSH   | 0x0104 | (same — step 2 of flush)      |

Key architecture:
- `SubmitControlq(req_len, resp_len, *bytes_out)` is a generic
  controlq submitter that builds a 2-descriptor chain, kicks the
  device, polls used->idx with a bounded spin, and writes the
  resp_bytes through on success. GET_DISPLAY_INFO was refactored
  to use it; all v2 commands share the same path.
- `SubmitHeaderCommand(req_len, label)` is the thin wrapper every
  "returns RESP_OK_NODATA" command uses — 6 lines per command in
  the v2 functions.
- Backing is a single contiguous run of `(w*h*4 + 4095) >> 12`
  frames, attached as one `virtio_gpu_mem_entry`. 1024×768×4 =
  768 frames, well within the frame allocator's typical
  largest-free-run at boot.
- Pixel format is `VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM` — on little-
  endian x86 a `u32 = (A<<24)|(R<<16)|(G<<8)|B` lays out as
  B,G,R,A in memory, exactly what the host expects.
- Only scanout 0 + resource id 1 in v2. Resource id 0 is reserved
  by spec; the single-scanout restriction is acceptable for the
  first proof and simplifies reclaim (not yet implemented).

Boot-time proof: after `VirtioGpuGetDisplayInfo` reports at least
one enabled scanout, we `VirtioGpuSetupScanout(w, h)`, paint a
diagonal R/G gradient + four 16×16 corner swatches
(red/green/blue/white) into the backing, and call
`VirtioGpuFlushScanout(0,0,w,h)`. On QEMU `-vga virtio` the host
composites that image and we see it. First time guest pixels have
ever left DuetOS via virtio-gpu.

### SYS_GDI_BITBLT — blits all the way to the compositor

Three layers:

1. **`FramebufferBlit(dst_x, dst_y, src, w, h, src_pitch_px)`** —
   surface-clipped memcpy of BGRA rows into the MMIO framebuffer.
   No per-pixel branching beyond the clip.
2. **Per-window blit pool + `Blit` display-list prim.** Each
   `RegisteredWindow` now has `blit_pool[16 KiB]` + `blit_pool_used`
   alongside its prim array. `WindowClientBitBlt` appends a `Blit`
   prim that references a byte range inside the pool; the pool
   resets every time `prim_count` resets (fresh frame). Pool is
   small enough that total bss overhead is `kMaxWindows *
   kWinBlitPoolBytes = 256 KiB`.
3. **`SYS_GDI_BITBLT` (102).** User passes `(hwnd, dx, dy, w, h,
   src_ptr)`; kernel `KMalloc`s a bounce buffer, `CopyFromUser`s
   pixels into it, takes compositor lock, `WindowClientBitBlt`s,
   `DesktopCompose`s, releases, `KFree`s.

Max single blit: `kWinBlitPoolBytes / 4 = 4096 px = 64×64`.
Large blits must be chunked by the caller.

### Real Win32 paint-lifecycle IAT

Three more syscalls + seven real stubs close the gap between
"PE imports these" and "compositor actually sees the calls":

| Syscall              | # | Purpose                                |
| -------------------- | - | -------------------------------------- |
| SYS_WIN_BEGIN_PAINT  | 103 | Fills 72-B PAINTSTRUCT + validates     |
| SYS_WIN_END_PAINT    | 104 | TRUE no-op (validate already ran)     |
| SYS_GDI_FILL_RECT_USER | 105 | Reads Win32 RECT* + records FillRect |

Stubs at offsets `0xCB8..0xD06` (page still under 4 KiB). IAT
retargets:
- `user32.BeginPaint` / `EndPaint` → new stubs.
- `user32.InvalidateRect` → SYS_WIN_INVALIDATE (bErase from r8, lpRect ignored in v1).
- `user32.UpdateWindow` → SYS_WIN_INVALIDATE(bErase=0).
- `user32.GetDC` / `ReleaseDC` → HDC=HWND pass-through / const 1.
- `user32.FillRect` / `gdi32.FillRect` → SYS_GDI_FILL_RECT_USER.

A standard WndProc `case WM_PAINT: { PAINTSTRUCT ps; HDC hdc =
BeginPaint(hwnd, &ps); FillRect(hdc, &ps.rcPaint, hbr); EndPaint
(hwnd, &ps); return 0; }` now reaches the compositor and paints.

## Pattern — kernel freestanding, cont'd

Extends the v1 knowledge: PAINTSTRUCT-style whole-struct fills
keep working when you field-init a local + one `CopyToUser` at
the end (neither of which clang lowers to memset/memcpy when the
struct is on the stack and the destination is `u8*`-cast). The
dangerous cases remain:

- `T x = {};` for `sizeof(T) > ~64` → `memset`.
- `T a = b;` for large `T` → `memcpy`.
- Returning large structs by value → `memcpy` of the RVO slot.
- Brace-assigning a sub-struct → `memcpy` of the sub-struct.

The DuetOS pattern of returning `const T&` + file-scope storage +
field-by-field init stays the right default for anything wider
than a pointer-pair.

## Observation — virtio-gpu mem_entry / BAR alignment

The `virtio_gpu_mem_entry.addr` field is `u64 le` and can point
at any page-aligned guest physical address — it does NOT have to
be inside any PCI BAR. The host reads guest RAM directly to
satisfy TRANSFER_TO_HOST_2D. This means our backing is ordinary
allocated frames, not MMIO — `AllocateContiguousFrames` is the
right primitive, and the corresponding kernel VA comes from
`PhysToVirt` rather than `MapMmio`. Got this wrong once mentally
before re-reading §5.7.

## Next slices

1. **Input routing to ring-3 Win32 PEs.** A PE can now paint, but
   WM_KEYDOWN / WM_LBUTTONDOWN / WM_MOUSEMOVE still aren't getting
   routed back through SYS_WIN_GET_MSG reliably — keyboard focus
   + mouse capture story needs a pass.
2. **virtio-gpu resource reclaim + RESOURCE_UNREF.** v2 leaks its
   single resource at boot forever. Safe because we only allocate
   one, but the hook needs to exist before multi-scanout or
   mode-change support.
3. **virtio-gpu as the kernel framebuffer.** Today the scanout
   backing is separate from the Multiboot2 handoff framebuffer —
   the compositor paints to the latter. On virtio-gpu-only boards
   there's no Multiboot2 framebuffer, so we need to rebind.
4. **Real BitBlt IAT stub.** Current `gdi32.BitBlt` still returns
   1 (dummy). A full impl needs the source DC tracked — at least
   for the common "BitBlt from a CreateCompatibleBitmap" case. Ties
   into the broader HDC → bitmap-buffer handle table.
5. **GDI textual primitives.** `TextOutA/W` / `DrawTextA/W` still
   dummy. Route through SYS_GDI_TEXT_OUT (already exists) with a
   user-ptr variant that reads the string.
6. **MSI-X interrupt path for virtio-gpu.** Polled used-ring
   completion works but wastes CPU; MSI-X hookup would finish the
   "production ready" story.

## References

- virtio 1.0 spec §2.6 split virtqueues, §5.7 virtio-gpu (commands
  0x0100..0x0106, pmodes format, ctrl_hdr layout).
- `kernel/drivers/gpu/virtio_gpu.{h,cpp}` — v1 + v2 commands.
- `kernel/drivers/video/framebuffer.{h,cpp}` — `FramebufferBlit`.
- `kernel/drivers/video/widget.{h,cpp}` — `WinGdiPrimKind::Blit`,
  `blit_pool`, `WindowClientBitBlt`, compositor replay case.
- `kernel/subsystems/win32/stubs.cpp` — offsets 0xCB8..0xD06 +
  new IAT entries.
- `kernel/subsystems/win32/window_syscall.cpp` — `DoGdiBitBlt`,
  `DoWinBeginPaint`, `DoWinEndPaint`, `DoGdiFillRectUser`.
- `kernel/core/syscall.h` — SYS_GDI_BITBLT (102),
  SYS_WIN_BEGIN_PAINT (103), SYS_WIN_END_PAINT (104),
  SYS_GDI_FILL_RECT_USER (105).
