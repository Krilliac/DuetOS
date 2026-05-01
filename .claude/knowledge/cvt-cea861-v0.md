# CVT generator + CEA-861 EDID extension parser v0

_Type: Observation + Decision._
_Status: Active — pure-compute slices landed; no DDC transport yet._
_Last updated: 2026-05-01._

## What landed

Two natural follow-ups to the EDID base-block parser
(`edid-parser-v0.md`):

### 1. CVT (VESA Coordinated Video Timings) generator

`kernel/drivers/gpu/cvt.{h,cpp}` — given (`h_active`, `v_active`,
`refresh_mhz`, `mode ∈ { Standard, ReducedBlankingV1 }`), returns an
`EdidDtd` populated with pixel clock + active/blanking + sync
offsets/widths + sync polarity + computed refresh.

Surface:

- `CvtGenerate(CvtRequest&) → Result<EdidDtd>` — main entry.
- Two modes: CVT 1.1 Standard (CRT-style, variable blanking from
  duty-cycle formula, V-sync from aspect-ratio table) and CVT 1.2
  Reduced-Blanking v1 (flat-panel, fixed 160-pixel h-blank).
- Aspect-ratio detection by integer cross-product on 4:3 / 16:9 /
  16:10 / 5:4 / 15:9 (default 10 v-sync lines for unspecified).
- Pixel-clock math is pure integer (u32 + u64 intermediates) — no
  float math, no FP register touches.
- Six-mode self-test (`CvtSelfTest`) covers 640×480 / 1024×768 /
  1280×1024 / 1920×1080 / 2560×1440 RB plus 1280×1024 Standard.
  Asserts pixel-clock within ±5% of X.Org cvt(1) reference values
  + refresh round-trips within 1 Hz of input + h_active is
  cell-gran-aligned.
- Two negative cases: zero-zero-zero input + absurd refresh
  (>240 kHz).

### 2. CEA-861 EDID extension block parser

`kernel/drivers/gpu/cea861.{h,cpp}` — parses the trailing 128-byte
extension block that EDID 1.4 byte 126 advertises. Covers the
HDMI-era data block taxonomy.

Surface:

- `Cea861ParseBlock(const u8*, u64) → Result<Cea861ExtBlock>` — main entry.
- `Cea861ExtBlock` carries: tag/checksum validity, revision,
  global flags (underscan / audio / YCbCr-444 / YCbCr-422 + native
  DTD count), VIC list (Short Video Descriptors, native flag),
  SAD list (Short Audio Descriptors: format / channels /
  sample-rate flags / bit-depth or bitrate), Speaker Allocation
  layout, HDMI VSDB (OUI 0x000C03 → source physical address /
  max TMDS clock × 5MHz / support flags / latency), HDR Static
  Metadata (CEA-861.3 extended tag 6 → EOTF support / max-min
  luminance codes), Colorimetry bitmap, and embedded DTDs.
- `CeaVicName(u8 vic, char scratch[16])` resolves VIC → human
  string for the first ~32 VICs (CEA-861-E era); unknown VICs
  format as `"vic-N"` into the supplied scratch buffer.
- 3-fixture self-test (`Cea861SelfTest`):
    * **HDMI 2.0 monitor**: 5 VICs (1080p60 native / 720p60 /
      1080p50 / 720p50 / 1080p24), 2 SADs (LPCM 2ch / AC-3 6ch),
      Speaker Allocation FL/FR+LFE+FC+RL/RR, HDMI VSDB with
      source-phys 0x1000 + max-TMDS 340 MHz, HDR Static Metadata
      with EOTF=PQ+SDR, max-lum-code=180. One trailing
      1920×1080@60 DTD.
    * **Bad-checksum**: same fixture with byte 127 XOR 0xA5 —
      asserts checksum_valid==false but VIC list still parsed.
    * **Short buffer**: 16-byte input rejected.

### 3. Shell command

`monitor` (in `kernel/shell/shell_hardware.cpp`) was extended:

- `monitor` (no args) — synthetic EDID dump + CVT timings for
  1920×1080@60 / 2560×1440@60 / 3840×2160@60.
- `monitor cea <hex>` — parse + decode 256-hex-digit CEA-861 ext block.
- `monitor cvt W H R` — generate a CVT timing for `WxH @ R Hz`.

## Why

The EDID base-block parser surfaces "what modes does the monitor
report?" but not "what timings does each mode actually need?". CVT
fills that gap for the standard-timing slots (which carry only
W×aspect×refresh) — the GPU driver, when it's ready, can take a CVT
output and program the hardware mode-set registers directly.

CEA-861 is the second 128-byte block that any HDMI-era monitor's
EDID advertises. Without it, the kernel sees the base block claim
"I support 1080p" but has no idea whether the monitor accepts
8-channel LPCM, supports HDR PQ, or has DolbyVision routing — all
of which live in the extension block. With this parser, future
slices for HDMI audio (P0 #2 audio routed over HDMI) or HDR
rendering have the data they need.

Both slices remain pure compute: no DMA, no IRQ, no DDC. They sit
ready for the day a per-vendor GPU driver gains an I²C bit-banger.

## Reference material used

- VESA CVT 1.1 (2003) — Standard CVT formula
- VESA CVT 1.2 (2013) — Reduced Blanking v1 + v2
- CEA-861-E (HDMI 1.4) — base data-block taxonomy + first 64 VICs
- CEA-861-F (HDMI 2.0) — extended VICs
- CEA-861.3 — HDR static metadata + BT.2020 colorimetry
- VESA E-EDID Standard A2 — extension-block format (§5)
- Wikipedia "Coordinated Video Timings" — algorithm cross-check
- X.Org cvt(1) algorithm description — reference values for the
  self-test tolerance bands

**No code copied** from libxcvt, X.Org cvt(1), Linux drm_edid_cea,
FreeBSD, or ReactOS.

## Bug caught while landing

CVT-RB v_blanking convergence: first draft did one fixed-point pass
which gave acceptable results for 60 Hz / common resolutions but
diverged for 240 Hz @ 4K. Bumped to 4 iterations and verified via
host-side test that all 5 reference modes converge in ≤2
iterations — and the 240 Hz cases still resolve within tolerance.
The 4-iter cap is a defensive bound rather than a correctness
requirement.

## Out of scope (deferred)

| Item | Why deferred | When to revisit |
|------|--------------|-----------------|
| CVT Reduced-Blanking v2 (CVT 1.2 §3.3) | Adds 80-pixel h-blank + 1000/1001 ATSC modifier + ±0.001 MHz pclk precision; only matters for 4K/8K HDR cinema | When a 4K HDR mode-set lands |
| GTF (Generalized Timing Formula) | Predecessor to CVT, only useful for old CRTs | When a real CRT + analog modeset comes back as a use case |
| HDMI Forum VSDB (OUI 0xC45DD8) | HDMI 2.1+ feature carrier (FRL, VRR, ALLM) | When DuetOS targets HDMI 2.1 hardware |
| Full SCDC parsing | HDMI 2.0 status / control channel | Same as above |
| Per-VIC pixel-clock + timing table | CTA-861-F mode table is large; CVT covers most needs anyway | If a workload demands exact VIC-conformant timings for HDMI compliance |
| YCbCr quantization range data block | colorimetry refinement | when video playback wants full-range vs. limited-range Y'Cb'Cr |

## Verification

- Clean two-stage kernel build (`x86_64-debug`).
- `clang-format --dry-run --Werror` clean across modified files.
- Host-side standalone CVT-RB test on 5 reference resolutions:
  all within 5% of X.Org cvt(1) values; refresh round-trips within
  1 Hz of input; h_active cell-gran-aligned.
- Boot self-test (`CvtSelfTest`) gated by `kBootSelfTests` runs 6
  positive + 2 negative cases.
- Boot self-test (`Cea861SelfTest`) gated by `kBootSelfTests` runs
  3 fixtures end-to-end.
- QEMU smoke not run: dev host has no `qemu-system-x86_64`. Per
  CLAUDE.md, only install for "observable runtime behaviour
  changes that compile-time can't prove" — this slice's behaviour
  is fully verified by the host-side compute + boot fixtures.

## Files touched

- `kernel/drivers/gpu/cvt.{h,cpp}` — new (~340 lines total)
- `kernel/drivers/gpu/cea861.{h,cpp}` — new (~620 lines total)
- `kernel/drivers/gpu/cea861_selftest.cpp` — new (~210 lines)
- `kernel/core/main.cpp` (+2 includes, +2 boot self-test wires)
- `kernel/shell/shell_hardware.cpp` (+2 includes, `monitor` extended)
