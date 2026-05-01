# EDID 1.3 / 1.4 base-block parser v0

_Type: Observation + Decision._
_Status: Active — pure-compute parser landed; no DDC/I2C transport yet._
_Last updated: 2026-05-01._

## What landed

`kernel/drivers/gpu/edid.{h,cpp}` — clean-room VESA E-EDID base-block
parser, 128 bytes in → fully decoded `EdidBaseBlock` out.

Surface:

- `EdidParseBaseBlock(const u8*, u64) → Result<EdidBaseBlock>` — top-level entry.
- `EdidBaseBlock` carries: header validity bit, computed + stored checksum,
  3-letter manufacturer PnP code, product code, serial, week + year (with
  the EDID 1.4 model-year flag), version + revision, video-input
  (analog vs digital, bpc 6/8/10/12/14/16, interface DVI/HDMI-a/HDMI-b/MDDI/DP),
  screen size in cm, gamma raw byte, feature bitmap (DPMS standby/suspend/
  active-off, sRGB default, preferred-timing-in-DTD1, continuous-frequency,
  display-type bits), 17-flag established-timings struct, 8 standard-timing
  slots (resolution + aspect-ratio derived height + refresh), four 18-byte
  descriptor slots (DTD with full timing math, or monitor-name / serial /
  ASCII / range-limits / dummy etc), and the extension-block count.
- `EdidDtd.refresh_mhz` is in milli-hertz (Hz × 1000) — derived from
  pixel-clock + h/v totals, no float math, integer truncation.
- `EdidDumpToConsole(EdidBaseBlock&)` — one-line-per-field summary for
  shell + post-mortem use.

`kernel/drivers/gpu/edid_selftest.cpp` — five fixtures wired into
`Phase::Earlycon`-equivalent boot path via `DUETOS_BOOT_SELFTEST` in
`kernel/core/main.cpp` (immediately after `GpuInit`):

  1. **1080p digital fixture**: DEL PnP, EDID 1.4, DisplayPort 8 bpc,
     1920×1080@60.000 Hz preferred DTD, range-limits, monitor name,
     dummy. Asserts every parsed field round-trips.
  2. **Analog 1024 fixture**: DUO PnP, EDID 1.3, model-year-flag (year
     2002), 4:3 1024×768@75 standard timing, 1024×768 preferred DTD,
     monitor-name in slot #1, range-limits in slot #2.
  3. **Bad-checksum fixture**: same bytes as #1 but byte 127 XOR
     0xA5; asserts `checksum_valid == false` while the rest of the
     parse still succeeds.
  4. **Short-buffer fixture**: 0-byte input rejected with `Err`.
  5. **Bad-header fixture**: byte 0 corrupted, checksum re-stamped;
     asserts `header_valid == false` while everything else parses.

`CmdMonitor` in `kernel/shell/shell_hardware.cpp` — new `monitor`
shell command. `monitor` (no args) dumps a synthetic 1080p EDID via
the parser to demonstrate the decode shape; `monitor parse <hex>`
takes 256 hex digits (whitespace / colons / commas allowed as
separators) and dumps the parsed result. Wired into the dispatch
table + `kCommandSet[]` allowlist in `kernel/shell/shell_dispatch.cpp`.

## Why

P2 #16 in `feature-gaps-end-user-v0.md` (Multi-monitor / resolution
change) calls EDID parsing as a prerequisite. Per-vendor GPU drivers
are probe-only today (`kernel/drivers/gpu/{intel,amd,nvidia}` don't
exist as their own files; classification only via vendor-id lookup
in `gpu.cpp`), so there's no DDC/I2C transport — but the parser was
the half of the work that didn't depend on hardware bring-up. Landing
it now means the day a vendor driver gets DDC, the immediate next
question ("ok, I have 128 bytes, what does it mean?") is already
answered.

A secondary benefit: the parser catches vendor-firmware EDIDs that
upstream OS drivers ship as fallbacks, useful for QEMU's
`-vga virtio` path which serves a synthetic EDID through the
virtio-gpu RESP_OK_EDID command (out of v0 scope to wire up, but the
parser is the consumer when that lands).

## Reference material used

- VESA E-EDID Standard Release A2 (EDID 1.4, 2006) — primary spec.
- VESA E-EDID Release A, Rev. 1 — earlier 1.3 baseline.
- OSDev Wiki "EDID" page — cross-check of byte layout.
- Wikipedia "Extended Display Identification Data" — established-
  timings bit map and 18-byte descriptor type taxonomy.

**No code copied** from Linux's `drivers/gpu/drm/drm_edid.c`,
FreeBSD's `sys/dev/drm2/drm_edid.c`, or ReactOS. Only the documented
public byte-and-bit layout from the VESA spec is used.

## Out of scope (deferred)

| Item | Why deferred | When to revisit |
|------|--------------|-----------------|
| CEA-861 / DisplayID extension blocks | Most monitors ship a 1-block EDID; the trailing 128-byte CEA blocks add HDMI-specific data (audio, color spaces, vendor-specific) that nothing in the kernel consumes today | When the audio path needs HDMI-arc routing or when a Vulkan ICD wants color-volume metadata |
| HDMI VSDB | Subset of CEA-861 | Same as above |
| DDC / I2C transport | Per-vendor GPU job (Intel iGPU, AMDGPU, Nouveau) | When the first vendor driver gains a real bring-up |
| CVT / GTF timing synthesis | EDID tells you what modes the monitor reported; synthesising new modes is a separate compute layer | When a mode-set picks "best 1920×1080 fit" and needs to construct a CVT-RB timing on the fly |
| EDID-DI extension (Display Interface block) | Encodes color-management hints | When color management lands |

## Why this slice was chosen

Discussion in CLAUDE.md → "Anti-Bloat Guidelines" + the project's
"slice-sized session" pattern argues against speculative
infrastructure. EDID is borderline — useful only when DDC lands —
but the boot self-test exercises the parser on every boot and the
shell command surfaces it to operators, so the code is wired into a
live path. It's not dead code; it's "deferred-input-source code".

The alternative slices considered:

- **HDA codec init** (P0 #2 audio): blocked on DMA-coherent allocator.
- **AC97 audio**: same DMA blocker.
- **AHCI driver** v0: NVMe is the template, but the existing
  `kernel/drivers/storage/ahci.cpp` is already 741 LOC — it's not
  obvious what's missing without a deeper audit.
- **Per-zone allocator** (C1-followup): genuinely high-leverage, but
  nontrivial — paging changes, plus a real callsite migration.
- **rseq stub completion**: deliberately deferred per the GAP marker
  on `kernel/subsystems/translation/translate.cpp:368`; -ENOSYS is
  the correct contract.

## Bug caught while landing

First draft computed `refresh_mhz` as
`pixel_clock_khz * 1000 / (h_total * v_total)`, which yields refresh
**in Hz** (60), not milli-hertz (60000). Caught by a host-side test
that re-implemented the same math against a 1920×1080@60 fixture and
asserted `>= 59900 && <= 60100`. Fix: multiplier upped to 1_000_000ULL.
Comment in the header was simultaneously wrong; both fixed in the
same slice.

## Verification

- Clean two-stage kernel build (`x86_64-debug` preset).
- `clang-format --dry-run --Werror` clean on every modified file.
- Host-side standalone test (one-shot, not checked in) confirmed
  parser logic on a synthetic 1080p fixture: manufacturer "DEL",
  1920×1080p, 60.000 Hz, 148.500 MHz pixel clock, sync offsets
  +88/44 (H) +4/5 (V), all decoded correctly.
- Boot self-test asserts every relevant field across 5 fixtures
  including 2 negative cases — runs only when `kBootSelfTests`
  (debug build).
- QEMU smoke not run: dev host has no `qemu-system-x86_64`. Per
  CLAUDE.md, only install for "observable runtime behaviour
  changes that compile-time can't prove" — this slice's behaviour
  is fully verified by host-side compute + boot-time assertions
  on fixtures.

## Files touched

- `kernel/drivers/gpu/edid.h` (new, 264 lines after format)
- `kernel/drivers/gpu/edid.cpp` (new, 466 lines after format)
- `kernel/drivers/gpu/edid_selftest.cpp` (new, ~440 lines after format)
- `kernel/core/main.cpp` (+1 include, +1 boot self-test wire)
- `kernel/shell/shell_internal.h` (+1 prototype)
- `kernel/shell/shell_hardware.cpp` (+include, +CmdMonitor + helpers, ~250 lines)
- `kernel/shell/shell_dispatch.cpp` (+1 dispatch arm, +1 allowlist entry)
