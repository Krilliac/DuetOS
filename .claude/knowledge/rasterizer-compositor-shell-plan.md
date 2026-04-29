# Rasterizer / compositor / userland-shell — multi-slice plan

_Type: Plan._
_Last updated: 2026-04-29._
_Branch: `claude/plan-rasterizer-compositor-SzST5`._

## Status (2026-04-29)

| Slice | Effect | Commit |
|-------|--------|--------|
| Plan landed | Plan file + index row | `914dba2` |
| Slice 1 | Shadow framebuffer foundation — `FramebufferBeginCompose` / `EndCompose` / `ComposeActive` in framebuffer.{h,cpp}; lazy-allocated offscreen RAM-backed surface from the physical frame allocator; 5 primitive write sites retargeted via `GetWriteTarget`; `DesktopCompose` wraps its desktop paint with Begin/End so writes land in the shadow then get flushed to live MMIO row-by-row before `FramebufferPresent`. | `dfd5635` |
| Slice 2 | Inactive-window dim + per-window opacity overlays now blend toward `g_compose_desktop_rgb` (the active theme's desktop background) instead of toward black. With slice 1's shadow in place these are real read-modify-write src-over blends against the in-progress paint. Reads as "fading toward the desktop" rather than the previous "darkening toward black", which was a misleading cue on light themes. Real per-pixel transparency through the window to the underlying app stack still needs per-window backbuffers — captured as a future tier. | `1a315d4` |
| Slice 3 | TTF / OpenType parser — `kernel/drivers/video/ttf.{h,cpp}`. Reads the sfnt table directory and validates `head` / `maxp` / `hhea` / `hmtx` / `cmap` / `loca` / `glyf` offsets+lengths against the file size. `TtfGlyphIndex` walks cmap format-4 (BMP coverage). `TtfDecodeGlyph` walks the simple-glyph encoding (flag-byte runs, X then Y delta-encoded coords) into a caller-supplied scratch buffer; no allocation. Composite glyphs (`number_of_contours < 0`) and CFF / OTTO outlines reject cleanly. `TtfSelfTest` exercises the bounds-check + sniff paths and is wired into the boot `Phase::Drivers` initcall list. | _this commit_ |

Deferred (in execution order):

1. Slice 4 — TTF scanline rasterizer (winding-rule fill of glyf
   contours into a `u8` coverage buffer; integer-AA at 4x4 super-
   sampling). Wired into `FramebufferDrawString` as a parallel
   path gated by a per-theme `font_kind` flag.
2. Slice 5 — userland crt0 + minimal libc + CMake ELF build rule.
   Replace the 181-byte hand-coded `usershell.elf` byte array in
   `ramfs.cpp` with the artifact of a real build rule that
   compiles `userland/shell/shell.c` against `userland/libc/`.
3. Slice 6 — prompt-driven shell (read line via SYS_READ on the
   serial console, dispatch a tiny built-in command table:
   `help`, `pid`, `echo`, `exit`).
4. Slice 7 — SVG loader (subset: `<svg>`, `<path d=...>`,
   `<circle>`, `<line>` only) consuming the path-stroker primitive
   so the prototype's topo / syscalls SVGs can ship as wallpaper
   sources without re-implementing them as kernel paint code.

## Resume prompt

> Pick up the rasterizer / compositor / userland-shell plan in
> `.claude/knowledge/rasterizer-compositor-shell-plan.md`. Read
> the Status table to see what's landed, then start the first
> still-deferred slice. Each slice is intentionally scoped to a
> single session's worth of work; do not bundle slices across
> commits. After landing a slice, update the Status table in the
> same commit.

## Why this shape

The three big-ticket items the user named — real TTF rasterizer,
real compositor with backbuffer, real userland shell — share a
common trait: each needs **a piece of foundational infrastructure
that doesn't exist yet**, not just chrome work. The previous
desktop-chrome polish slices (commits up through `7c1a4c1`)
landed every item that could be done WITHOUT new infrastructure.
What's left is structural.

The plan orders slices by **dependency leverage**:

- **Shadow framebuffer (Slice 1) is the keystone.** It unblocks
  both the rasterizer (which needs to blit a coverage mask into
  RAM-backed pixels — you can't read MMIO efficiently) and the
  compositor (which needs an offscreen surface to read-modify-
  write for true alpha). Doing it first means slices 2 and 4 are
  small additions on top, not separate scaffolding projects.
- **Alpha (Slice 2) is the immediate payoff.** The current
  inactive-window dim and per-window opacity are post-paint
  black overlays — they read as a darkening cue, not real
  transparency. Slice 1 makes them real for free: the alpha
  blend just becomes "read the shadow pixel, src-over, write
  back" instead of "overlay black at alpha-N".
- **TTF parser before rasterizer (Slices 3 → 4).** The parser
  is the small, easy-to-test layer; the rasterizer is the
  heavy compute. Splitting them means the parser can land with
  its own tests (a known-good font's tables decode to known
  values) before the rasterizer's harder algorithmic work
  begins.
- **Userland libc + ELF build rule (Slice 5) before prompt
  shell (Slice 6).** The shell's value is in being a real
  prompt loop; without a real libc + build rule, everything
  about it is hand-coded bytes. Once the build rule is in
  place, the shell itself is ~150 lines of straightforward C.
- **SVG loader (Slice 7) is last because it's optional.** The
  prototype's topo / syscalls SVGs already have programmatic
  approximations in `wallpaper.cpp`. The SVG loader is a
  fidelity upgrade, not a capability gap.

## Slice 1 — shadow framebuffer foundation

**Files touched (planned):**

- `kernel/drivers/video/framebuffer.h` — declare
  `FramebufferBeginCompose()` / `FramebufferEndCompose()`.
- `kernel/drivers/video/framebuffer.cpp` — add three globals
  (`g_shadow_buf`, `g_shadow_pitch_bytes`, `g_compose_active`)
  and an internal `GetWriteTarget()` accessor that returns the
  shadow when compose is active, else the live MMIO. Refactor
  the 5 sites that currently read `g_info.virt` / `g_info.pitch`
  for pixel writes (PutPixel, FillRect, Blit, FillRectAlpha,
  FillRectGradient — line numbers as of `7c1a4c1`).
- `kernel/drivers/video/widget.cpp` — wrap `DesktopCompose`'s
  body with `BeginCompose` / `EndCompose`.
- `kernel/core/main.cpp` — allocate the shadow buffer once
  `FramebufferInit` reports available, sized to
  `pitch * height` bytes from `kheap`.

**Shape:**

- Shadow buffer is a flat `u32[width * height]` in normal RAM,
  pitch = `width * 4` (no alignment padding needed for kheap
  allocation).
- `FramebufferBeginCompose()`:
  - If `g_shadow_buf` is null, allocate it from kheap. Failure
    falls through to direct-to-MMIO mode (compose_active stays
    false).
  - Sets `g_compose_active = true`.
- Pixel write primitives read `GetWriteTarget()` and write to
  whichever surface that returns. Reads (e.g. the
  read-modify-write in `FillRectAlpha`) read from the same
  surface. **Volatility** is preserved on both branches — the
  `volatile u32*` cast is harmless for normal RAM.
- `FramebufferEndCompose()`:
  - If compose was active: memcpy shadow → live MMIO row by row
    (different pitches if the live framebuffer has a non-tight
    pitch).
  - Set `g_compose_active = false`.
  - Call `FramebufferPresent()` so virtio-gpu (and future
    hardware backends) flushes the new pixels.

**Correctness invariants:**

- `g_info` (the live framebuffer descriptor) never changes
  during compose. Code that calls `FramebufferGet()` or
  `FramebufferRebind` continues to see the live spec.
- Width / height / pitch reads in clipping logic also stay
  unchanged — they read `g_info.{width,height}` (which is the
  spec for both surfaces — shadow is the same dimensions).
- The shadow buffer's pitch = `width * 4` (tight); the live
  pitch may have stride padding. Code that loops `yi *
  g_info.pitch` keeps working for the live target; for the
  shadow target the helper returns `width * 4` as the pitch.
- Out-of-compose paint paths (panic-screen direct writes,
  early boot before main has run) bypass the shadow naturally
  — `compose_active` is false until `BeginCompose` flips it.

**Verification:**

- Compile clean with `-Werror`.
- No QEMU smoke this slice (no observable runtime delta:
  visually identical, just an extra memcpy + present per
  compose pass). Slice 2 is the first visual win.

## Slice 2 — true alpha-blend

**Files touched (planned):**

- `kernel/drivers/video/framebuffer.cpp` — `FramebufferFillRectAlpha`
  reads + writes the shadow when compose-active, so its
  src-over blend now blends against whatever was painted
  earlier in the same compose pass.
- `kernel/drivers/video/widget.cpp` — replace the post-paint
  black overlay for inactive windows (currently `0x18000000`
  full-rect alpha over black) with `FramebufferFillRectAlpha`
  using the theme's `desktop_bg` as the blend source so
  inactive windows fade toward the desktop, not toward black.
- Per-window opacity (`window->opacity` field) becomes a real
  alpha blend of the window's chrome + content against the
  shadow — same change site, different alpha source.

**Why this is one commit:** slice 1 already changed alpha to
read the shadow. Slice 2 is just *changing the source colour*
of two callsites, which is a 4-line edit per site.

## Slice 3 — TTF table parser

**Files touched (planned):**

- `kernel/drivers/video/ttf.h` — public types: `TtfFont`,
  `TtfGlyph`, `TtfPoint`, `TtfTable`. Bounded parser, no allocations.
- `kernel/drivers/video/ttf.cpp` — read `head`, `maxp`, `hhea`,
  `cmap` (format 4 only — covers BMP), `loca`, `glyf` table
  pointers. `TtfFont::FindGlyph(codepoint) -> Result<TtfGlyph>`.
- `userland/assets/test_font.ttf` — a small (≤ 100 KiB) OFL
  font subset with ASCII coverage. Embedded as a byte array in
  `ramfs.cpp` (or referenced via a symlink-to-bytes if the
  build system supports it).

**Note:** the parser reads the glyf outline points but does
not rasterize. That's slice 4. Slice 3's "verification" is a
boot-time self-test that decodes a known glyph (e.g. 'A') and
asserts the contour count + first endpoint matches the font's
spec.

## Slice 4 — TTF scanline rasterizer

Heaviest algorithmic slice. Standard approach:

- Flatten quadratic Bezier glyf contours into line segments
  (de Casteljau, depth-cap 4 — TrueType uses quads, not cubics
  like the existing `FramebufferStrokePath`).
- Build an active edge table per output scanline.
- 4x4 supersample → 4-bit coverage value per output pixel.
- Blit coverage as a 256-level alpha into the shadow surface.

**Wired into:** a new `FramebufferDrawStringTTF(x, y, text, fg,
size, font)` primitive. The bitmap path stays — themes opt in
via a new `Theme.font_kind` enum (`Bitmap8x8`, `Ttf`).

## Slice 5 — userland crt0 + libc + ELF build rule

**Files touched (planned):**

- `userland/libc/include/{stdio,stdlib,string,unistd}.h` — minimal
  freestanding headers.
- `userland/libc/src/{syscall.S,start.S,stdio.c,string.c,exit.c}` —
  syscall trampoline (`int 0x80` ABI), `_start` that calls `main`
  then `SYS_EXIT`, `write`, `read`, `strlen`, `memcpy`, `memset`.
- `userland/shell/shell.c` — promoted from "future" to real source.
- `CMakeLists.txt` (root + userland subdir) — rule that compiles
  `shell.c` + `libc.a` into a static-pie ELF64.
- `kernel/fs/ramfs.cpp` — replace `kBinUsershellElfBytes` byte
  array with a build-time-included artifact (CMake `objcopy
  --binary-architecture` step that turns the ELF into a `.o`
  with `_binary_shell_elf_{start,end,size}` symbols). The
  existing `kBinUsershellElfBytes` accessor becomes a thin
  wrapper around those symbols.

**Why a CMake build rule is the foundational piece:** every
"real userland binary" item the project will ever need (more
ELFs, native test apps, eventually init / a window-manager
client) goes through this same rule. Once it exists, it's
write-once.

## Slice 6 — prompt-driven shell

Once slice 5 is in:

- `userland/shell/shell.c` — `main()` loop: print `duet$ `,
  read a line via `read(0, ...)`, dispatch a tiny built-in
  command table:
  - `help` — list commands
  - `pid` — print our PID
  - `echo <args>` — write args back
  - `exit` — call `exit(0)`
- Wire SYS_READ for the kernel-side serial console so the
  shell can read line input. Already half-built (the kernel's
  PS/2 keyboard driver feeds the framebuffer console; needs a
  per-process stdin queue).

## Slice 7 — SVG loader (optional)

- `kernel/drivers/video/svg.{h,cpp}` — subset parser:
  `<svg viewBox=...>`, `<path d="M ... C ... Z">`,
  `<circle cx=... cy=... r=...>`, `<line>`. Outputs
  `PathSegment[]` consumed by the existing
  `FramebufferStrokePath`.
- `kernel/drivers/video/wallpaper.cpp` — replace the
  programmatic topo + duet-arcs paint paths with SVG-driven
  versions sourced from
  `docs/duet-theme/prototype/*.svg` (re-encoded as ramfs byte
  arrays).
- This is fidelity, not a capability gap. Defer until 1–6 are
  in.

## Risks / mitigations

- **Memory footprint:** shadow framebuffer at 1024×768×4 =
  3 MiB. Acceptable on a kernel that already has ~64 MiB heap
  budget; bigger resolutions (1920×1080×4 = 8 MiB) want a
  decision in slice 1 about whether to lazily allocate or
  refuse. **Mitigation:** lazy alloc with a fallback to direct
  mode if the heap can't satisfy. Logged at boot.
- **TTF rasterizer perf:** scanline filling at 1024×768 with
  4x supersample is ~1M coverage samples per glyph row,
  manageable per-glyph but expensive for full-screen text.
  **Mitigation:** glyph cache (per-glyph 8-bit alpha bitmap
  in heap, keyed by codepoint+size). Cache lives in the font
  struct.
- **Userland libc scope creep:** "minimal libc" can grow into
  a real libc if not bounded. **Mitigation:** scope the v0 to
  exactly the symbols `shell.c` needs. Add new symbols only
  when a new userland binary needs them.
- **Build-rule integration:** the CMake `objcopy --binary` step
  is platform-specific. **Mitigation:** the existing project
  already compiles user-mode DLLs in `userland/libs/*` via
  `tools/build/build-kernel32-dll.sh` — same toolchain pattern.

## Out-of-session resume

If a session ends mid-slice, the slice in flight is on the
feature branch. The Status table at the top of this file
tracks which slices have landed; a fresh session reads the
table, picks the next deferred slice, and starts.

Each slice is intentionally one commit. Do NOT bundle multiple
slices in one commit — the granularity is what makes the plan
re-startable across sessions.
