# Image Viewer — v0 (BMP only)

_Type: Observation + Decision._
_Last updated: 2026-05-02._

## What landed

A native kernel app that reads 32-bpp uncompressed BMP files from
the FAT32 root volume and paints them in a window. Closes the
"P1 #7 image / PDF / media viewers" gap on the BMP side
(`feature-gaps-end-user-v0.md`), and is the first viewer to pair
naturally with the Screenshot app — every `Ctrl+Alt+P` capture
already lands as a `SHOTNNNN.BMP` whose layout this viewer accepts
byte-for-byte.

Files:

- `kernel/apps/imageview.h` — public API (`ImageViewInit`,
  `ImageViewWindow`, `ImageViewFeedChar`, `ImageViewFeedArrow`,
  `ImageViewSelfTest`).
- `kernel/apps/imageview.cpp` — single TU, ~570 LOC, holds the
  BMP header decoder, the streaming row sampler (driven by
  `Fat32ReadFileStream`), the filename-list scanner, and the
  content-draw callback.

Wiring:

- `kernel/drivers/video/theme.h` — `ThemeRole::ImageView = 8`,
  `kCount = 9`.
- `kernel/drivers/video/theme.cpp` — extended `role_title` and
  `role_client` arrays for all 10 themes (Classic, Slate10, Amber,
  Duet, DuetLight, DuetBlue, DuetViolet, DuetGreen, DuetClassic,
  HighContrast). `g_role_window` array bumped to 9 slots.
- `kernel/drivers/video/start_menu_apps.cpp` — manifest target
  parser accepts `imageview` / `imageviewer`.
- `kernel/core/main.cpp` — window registration, Start-menu entry
  ("IMAGE VIEWER"), keyboard router (Left/Right arrows for
  prev/next; characters routed for N/P/R when ImageView is
  active), boot self-test invocation.

## Behaviour

Boot:
- Window is registered hidden by default (raised from the Start
  menu's IMAGE VIEWER entry). Initial size 460×360 at (280, 90).
- `ImageViewInit` runs after FAT32 probe, scans the root for any
  `.BMP` (case-insensitive), and seeds the file list. If FAT32
  isn't mounted, the list stays empty and the window paints a
  hint pointing users at `Ctrl+Alt+P` + `R`.

Navigation (when ImageView is the focused window):
- `n` / `N` / Right arrow — next file (wraps).
- `p` / `P` / Left arrow — previous file (wraps).
- `r` / `R` — re-scan the FAT32 root for new BMPs (raises a
  `NotifyShow` toast confirming the rescan).

Decode:
- Lazy: a navigation event marks `needs_decode = true`; the next
  compose tick (which already holds the compositor lock) actually
  reads the file. This avoids reading the disk on the keyboard-
  reader thread.
- Streaming via `Fat32ReadFileStream`: the chunk callback
  accumulates the 54-byte header, validates magic/dib-size/bpp,
  computes the destination thumbnail dimensions, allocates the
  thumbnail buffer + a one-row scratch from `KMalloc`, then
  sources rows one at a time and nearest-neighbour-samples them
  into the destination. We never buffer the whole file (a
  1024×768 screenshot is ~3 MiB; the kernel heap budget is 2 MiB).
- Aspect-preserving fit, no upscale: a 4×4 image stays 4×4
  centred on the panel; a 1920×1080 image scales down to fit
  the content rect.
- Bottom-up DIB (positive `biHeight`) and top-down DIB (negative
  `biHeight`) both supported; the v-flip is applied per source
  row in `EmitSourceRow`.

Reject:
- bpp != 32 — status line shows `unsupported BMP (Nbpp comp=N)`.
- Non-`BI_RGB` compression — same status line.
- Header corrupt / file truncated / FAT32 not mounted — status
  line shows the failure mode; image area paints the panel
  ground.

## Out of scope (deliberate)

- 24-bpp / 16-bpp / palette / RLE BMPs. The header parser
  recognises them (`info.ok` is set), the dispatcher then
  rejects with a typed status. Adding 24-bpp support is one
  case in `EmitSourceRow` — left for a future slice once a real
  use case appears.
- PNG / JPEG / GIF — each format wants its own parser TU; this
  app would dispatch by extension once the parsers exist.
- Subdirectory walk; thumbnail strip; rotate / zoom; clipboard
  handoff.

## Self-test (`ImageViewSelfTest`)

Pure-compute round-trip — no FAT32 read, no kheap allocation —
runs under `DUETOS_BOOT_SELFTESTS`:

1. Synthesises a 4×4 32-bpp top-down BMP header in a stack
   buffer using the byte layout `apps/screenshot.cpp` writes.
2. `ParseBmpHeader` round-trip: width/height/bpp/compression/
   top_down all match expected.
3. Negative case 1: swap magic byte → parse fails (`info.ok`
   stays false).
4. Negative case 2: claim 24 bpp → header still structurally
   parses (`info.ok == true`, `info.bpp == 24`) so the
   downstream "unsupported subformat" branch can do its job.
5. Bottom-up sign flip: positive height → `top_down == false`,
   `height` reflects the magnitude.
6. Aspect-fit math: 1024×768 into 320×240 → exact 320×240 (4:3
   preserved). No-upscale: 4×4 source into 320×240 rect → stays
   4×4.

Boot log signature: `[image] self-test OK (BMP header
round-trip + aspect-fit math)`.

## Why BMP first

- Pairs naturally with the Screenshot app — users already
  have BMPs on disk after `Ctrl+Alt+P`.
- Format is structurally trivial (54-byte header + raw pixel
  rows for the 32-bpp case we care about). No compression
  state machine, no dictionary, no Huffman tables.
- Decode is byte-for-byte deterministic — nothing to debug
  beyond endianness, sign of `biHeight`, and BGR vs RGB.
- File-system primitive (`Fat32ReadFileStream`) was already
  available — no new VFS work.

## Runtime verification

Compile-clean (debug + release configurations build with no new
warnings; clang-format clean across all touched files). Boot
self-test exercises the parser + aspect-fit math end-to-end at
boot under `DUETOS_BOOT_SELFTESTS=ON`.

**Live UI test deferred** — `qemu-system-x86_64`,
`grub-mkrescue`, `xorriso`, `mtools`, `ovmf` are not pre-
installed on this dev host (per CLAUDE.md "Live-test runtime
tooling — install on demand"). The runtime path reuses three
proven primitives: `Fat32ReadFileStream` (Screenshot, Notes
load, Klog persist all use it), `WindowSetContentDraw` (every
existing kernel app uses it), and the keyboard-router pattern
(Settings, Files, Notes use the same idiom). The slice's
novel surface is the BMP header decoder + the streaming
row-sampler, both covered by the boot self-test.

## Cross-app dispatch (added 2026-05-02)

`ImageViewSelectByName(const char* name)` — public entrypoint
that re-scans the FAT32 root, finds a BMP whose 8.3 name
matches case-insensitively, and queues it for decode on the
next paint. Returns true iff the file was found. The Files
app uses it for "open with ImageView": when the user hits
Enter on a `.BMP` entry in disk view, Files calls
`ImageViewSelectByName(e.name)` then
`WindowRaise(ThemeRoleWindow(ImageView))`. This keeps the
hand-off cheap — no new IPC, no plumbing through ring 3, just
a function call inside the kernel-resident app namespace.

## Resume prompt

> Read `.claude/knowledge/imageview-bmp-v0.md`. The image
> viewer in `kernel/apps/imageview.{h,cpp}` reads 32-bpp BMPs
> from the FAT32 root and paints them with NN downsample. To
> add 24-bpp support, extend `EmitSourceRow` with a 3-byte
> path (BMP rows are 4-byte aligned even at 24 bpp; the row
> stride is `((width * 3 + 3) & ~3)` rather than `width * 4`).
> To add PNG, write `kernel/apps/imageview_png.cpp` and
> dispatch from `imageview.cpp` by extension; the existing
> filename scan can keep its single-extension test or grow a
> second branch. The `ImageViewSelectByName` entrypoint is
> the cross-app hand-off — Files calls it for Enter on
> `.BMP`; future apps (e.g. shell `view <file>`) can do the
> same.
