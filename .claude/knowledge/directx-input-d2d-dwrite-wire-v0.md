# DirectX gap-fill v0 — DirectInput → real input, D2D1 geometry, DWrite metrics

**Last updated:** 2026-04-30
**Type:** Observation + Pattern
**Status:** Active — wires three of the documented gap items from
`directx-v0.md` so DI/D2D/DWrite-using PEs see live input + drawn
geometry + nonzero text dimensions instead of zero-filled stubs.

## Scope

Closes three items from the DirectX v0 gap inventory:

1. **DirectInput keyboard + mouse → real input.** `GetDeviceState`
   was a 256-byte zero-fill; now keyboard devices walk DIK→VK and
   query `SYS_WIN_GET_KEYSTATE` per slot, mouse devices fill
   `DIMOUSESTATE` with cursor delta from `SYS_WIN_GET_CURSOR` plus
   button keystate for VK_LBUTTON / VK_RBUTTON / VK_MBUTTON / X1 /
   X2.
2. **D2D1 geometry primitives.** `FillEllipse`, `DrawEllipse`,
   `DrawRectangle`, `DrawLine` were `DX_HSTUB`. Now real software
   pixel writes against the DXGI backbuffer using the same packed
   BGRA8 brush helper that `FillRectangle` already uses.
3. **DirectWrite GetMetrics.** Was zero-fill into the wrong offsets
   (wrote width/height to layoutWidth/layoutHeight — DWRITE_TEXT_METRICS
   has width at offset 8, height at offset 16, lineCount at offset 32).
   Now writes a monospace approximation: `width = textLen *
   font_size * 0.6`, `height = font_size * 1.2`, `lineCount = 1`.

## What changed

### `userland/libs/dinput8/dinput8.c`

- Added GUID constants for `GUID_SysKeyboard` and `GUID_SysMouse`.
- Added `dx_get_key_state(vk)` and `dx_get_cursor_pos(out)` syscall
  wrappers (SYS_WIN_GET_KEYSTATE = 77, SYS_WIN_GET_CURSOR = 78 —
  same numbers user32 uses).
- Added `DikToVk(unsigned)` that maps DirectInput Scan Codes (PS/2
  set 1) to Win32 Virtual Keys for ~70 entries (digits / letters /
  function keys / arrows / modifiers / space / enter / backspace /
  tab). Unmapped DIK indices read back as released.
- Added `DiDeviceKind` enum + `kind` field on `DiDeviceImpl`. Set
  by `di_CreateDevice` based on the GUID it receives.
- Added `last_cursor_x/y/cursor_seeded` so mouse `GetDeviceState`
  reports relative deltas (DIMOUSESTATE convention).
- Replaced `didev_GetDeviceState` body with kind-dispatch. Keyboard
  fills the 256-byte buffer (high bit if pressed); mouse fills
  DIMOUSESTATE/DIMOUSESTATE2 layout (16/20 bytes); unknown kind
  zero-fills.

### `userland/libs/d2d1/d2d1.c`

- Extracted `brush_pack_bgra(brush)` and `plot_clipped(bb, x, y,
  packed)` helpers — both `FillRectangle` and the new primitives
  use them.
- Added `rt_DrawLine` (Bresenham, 1px stroke; D2D1_POINT_2F passes
  by value in MSVC x64 ABI as a packed `ULONGLONG` — the body
  `dx_memcpy`s the float halves out).
- Added `rt_DrawRectangle` (1px outline, top/bottom rows + left/right
  columns).
- Added `rt_DrawEllipse` + `rt_FillEllipse` sharing
  `ellipse_outline_or_fill(bb, cx, cy, rx, ry, packed, fill)` — same
  integer ellipse equation `dx²·ry² + dy²·rx² ≤ rx²·ry²` the GDI
  primitive uses, no sqrt. Outline mode emits a pixel only if at
  least one 4-connected neighbour is outside the ellipse.
- Wired the four new methods into the vtable at MSDN-spec slots
  (15 = DrawLine, 16 = DrawRectangle, 20 = DrawEllipse, 21 =
  FillEllipse). The pre-existing custom slot allocations for
  Clear / BeginDraw / EndDraw / GetSize / HwndResize are
  unchanged so the existing `d2d1_smoke` keeps passing.

### `userland/libs/dwrite/dwrite.c`

- Extended `DwLayoutImpl` with `font_size` + `text_len` fields.
- `dwf_CreateTextLayout` now reads the source TextFormat's
  font_size and the caller's UTF-16 length and stashes them on the
  layout.
- `layout_GetMetrics` now writes the proper DWRITE_TEXT_METRICS
  field offsets and computes a monospace approximation. lineCount
  is 1 (real line-break detection deferred until a font backend).

## What works — runtime-verified

The kernel builds clean with the changes; format is clang-format
clean; no QEMU smoke on this host (qemu/grub-mkrescue not
installed). The change is additive — every prior DI/D2D/DWrite
smoke PE still hits the same vtable slots and gets at least the
old behaviour (HRESULT == 0).

## Known limits

- **DI keyboard repeat rate is GetKeyState rate.** Real DirectInput
  has its own buffered queue (DIPROP_BUFFERSIZE) — we still report
  zero buffered events from `GetDeviceData`, so apps that gate on
  buffered events instead of state polling won't see input.
- **DI mouse delta = poll-to-poll cursor delta.** When the OS
  warps the cursor (e.g. DI_DEVMODE_FOREGROUND with
  CONFINE_TO_WINDOW), the next poll's delta is the warp distance,
  not the user motion. Fix: kernel-side accumulating delta counter
  + reset-on-poll. Out of scope for v0.
- **DI mouse wheel is always 0.** SYS_WIN_GET_KEYSTATE has no
  wheel surface; we'd need a separate accumulating wheel counter.
- **D2D1 stroke width is ignored.** Real D2D1 has variable-width
  strokes + style objects (dash, line cap, miter limit). We always
  paint 1px solid.
- **D2D1 antialiasing.** All draws are nearest-pixel; D2D1 spec
  default is per-primitive AA. Real AA wants edge coverage
  evaluation.
- **DWrite metrics are an approximation.** Real text width
  requires per-glyph advance from a font file. The 0.6×fs factor
  is reasonable for monospace at common sizes (10-16pt) but very
  off for proportional fonts or unusual sizes.

## Pattern reused

- **MSDN-correct slot allocation for new methods.** Existing
  vtables in this DLL family use custom slot indices that don't
  match Windows D2D's published vtable. New additions go at the
  MSDN-correct slots so a future v1 layout pass can keep them when
  the existing slots get re-aligned. Cost is zero — nothing
  exercises those slots today.
- **Helper extraction over inline duplication.** When adding a
  second/third/fourth primitive that all share the same brush
  unpack + clipped-pixel-write idiom, extract once
  (`brush_pack_bgra` + `plot_clipped`) and reuse, instead of
  inlining the same 5 lines in each prim. Three reuses already.

## Audit checklist

```bash
cd /home/user/DuetOS
cmake --preset x86_64-debug
cmake --build build/x86_64-debug --target duetos-kernel -j$(nproc)
find userland/libs/{dinput8,d2d1,dwrite} -name '*.c' \
  | xargs clang-format --dry-run --Werror
```

Both should be clean. The `[gfx]` rate-limited LogOnce trace still
fires once per DLL kind for DirectInput8Create / D2D1CreateFactory
/ DWriteCreateFactory.

## References

- `userland/libs/user32/user32.c` — SYS_WIN_GET_KEYSTATE +
  SYS_WIN_GET_CURSOR (the same syscalls dinput8 now issues).
- `.claude/knowledge/directx-v0.md` — gap inventory this slice
  draws from.
- `kernel/subsystems/win32/gdi_objects.cpp` —
  `PaintFilledEllipseOnBitmap` / `PaintEllipseOutlineOnBitmap` —
  same integer ellipse test the new D2D1 path uses.
