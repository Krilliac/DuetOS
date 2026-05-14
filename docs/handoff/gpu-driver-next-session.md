# Handoff Prompt — Real GPU Driver, Next Session

> Copy the section between the `===PROMPT START===` and `===PROMPT END===`
> markers into a fresh Claude Code session on branch
> `claude/setup-unity-engine-vJGc0`. Everything outside the markers is
> background for the operator that's launching the session.

## Background for the operator

This document is the handoff for the third of three parked items from
the long-running session that ran from the original "download Unity
engine and try to run the exe" task. The first two items shipped on
2026-05-14:

| # | Item | Status | Last commit |
|---|------|--------|-------------|
| 1 | TLS Tier 2 / ECDHE (P-256 + ECDSA + ECDHE handshake) | **deferred** — multi-week scope, no foundation in tree yet | n/a (Tier 1 RSA path is at `f9a479b`) |
| 2 | DllLoad import-resolution walk | shipped | `a255cce` |
| 3 | **Real GPU driver** (this handoff) | not started | n/a |

The next session's task is #3. #1 is also explicitly deferred — note
its scope at the bottom of this file so the GPU work doesn't
accidentally trip into TLS dependencies. The two are independent.

Branch state at handoff: working tree clean, 28 commits ahead of
`main`, all pushed to `origin/claude/setup-unity-engine-vJGc0`. Boot
selftests (`zip-st`, `aes-gcm`, `bigint`, `asn1`, `rsa`, `x509`,
`tls`, `hkdf`, `workpool`) are all PASS on the most recent QEMU run.

The Unity exe is **not vendored** — the user removed it in `ceaf972`
and explicitly does not want it back. Test the GPU work with the
existing scanout self-tests and a real `.exe` only if the user drops
one onto the desktop themselves.

===PROMPT START===

# Task — Real GPU driver bring-up (Intel | AMD | NVIDIA), DuetOS

You are picking up where session `claude/setup-unity-engine-vJGc0` left
off. Your job is to take one of the three tier-1 GPU vendor scaffolds
from "probe-only" to "real command submission" so the Vulkan ICD,
compositor, and any future D3D/DXVK path stop being CPU-only.

Read `CLAUDE.md` first. The project rules — anti-bloat, subsystem
isolation, "fix everything that surfaces, no deferring", the wiring-in
rule — all apply. They are not negotiable.

## Where the GPU stack is today

**In the tree, working:**

- `kernel/drivers/gpu/gpu.{h,cpp}` — PCI walk + classify + map BAR0
  for every display-class controller. Vendor dispatch via
  `RunVendorProbe`.
- `kernel/drivers/gpu/intel_gpu.{h,cpp}` — Gen9..Gen13 register decode
  (`GEN_INFO`, `FUSE_STRAP`, `GFX_MODE`, `PWR_WELL_CTL2`). Looks up
  `guc.bin` / `huc.bin` / GSC firmware. `Bringup` allocates the 4 KiB
  RCS ring DMA buffer, **logs** the would-be register pokes, then
  frees the buffer and returns `Unsupported`.
- `kernel/drivers/gpu/amd_gpu.{h,cpp}` — GFX9+ probe. Maps BAR5 (not
  BAR0 — registers live there on AMD) and reads `mmGRBM_STATUS` /
  `mmRLC_GPM_STAT`. Bringup is the same gated-stub shape as Intel.
- `kernel/drivers/gpu/nvidia_gpu.{h,cpp}` — Turing+ probe. Reads
  `PMC_BOOT_0`, `PMC_INTR_EN_0`, `PFIFO_INTR`, `PFB_PRI_RD`. Bringup
  is the same gated-stub shape.
- `kernel/drivers/gpu/virtio_gpu.cpp` — **the only path that
  produces pixels today.** 2D scanout cycle: write pixels →
  `TRANSFER_TO_HOST_2D` → `RESOURCE_FLUSH`. This is the reference for
  "command submission that actually presents."
- `kernel/drivers/gpu/bochs_vbe.{h,cpp}` — Bochs/QEMU VBE direct
  framebuffer (no commands; pure MMIO writes).
- `kernel/drivers/gpu/edid.{h,cpp}`, `cea861.{h,cpp}`, `cvt.{h,cpp}`,
  `dpms.{h,cpp}` — modeset support code, parsed but not consumed by
  a real driver yet.
- `kernel/drivers/gpu/intel_gsc_fw.{h,cpp}` — clean-room Intel GSC
  firmware-image (FPT) parser. Diagnostic-only — no MEI driver to
  push the update.
- `kernel/drivers/mei/mei.{h,cpp}` — PCI-side scaffold for the
  Management Engine Interface. BAR0 mapped, device classified
  (CSME / GSC / TXE / SPS). HECI protocol not implemented.
- `kernel/subsystems/graphics/graphics_vk*.cpp` — Vulkan 1.3 ICD
  with full lifecycle, CPU triangle rasterizer for `vkCmdDraw`, and
  WSI (`vkAcquireNextImageKHR` / `vkQueuePresentKHR`). Submission is
  synchronous and CPU-only.
- `kernel/drivers/video/framebuffer.{h,cpp}` — shadow framebuffer +
  single-bbox damage tracker + present hook. virtio-gpu's
  `FlushScanout` is the registered hook today.

**Not in the tree:**

- Any real GPU command-ring submission (Intel RCS, AMD CP, NVIDIA
  PFIFO/HOST).
- Firmware push: GuC/HuC (Intel), MEC/RLC (AMD), GSP (NVIDIA).
- GTT / GART page-table programming for any vendor.
- MSI/MSI-X interrupt routing for GPU devices.
- SPIR-V execution (orthogonal — gated on a future shader-translator
  slice).
- Modeset (DDI / display-pipe programming). EDID / CEA-861 / CVT are
  parsed but consumed by nothing.

## What "real GPU driver" means for this task

Pick **one vendor** (Intel is the recommended start — see "Why
Intel first" below). For that vendor, deliver:

1. **A working command ring** — DMA-coherent ringbuffer that the
   GPU actually consumes. For Intel: RCS at MMIO 0x2000. For AMD:
   GFX CP via PM4 packets. For NVIDIA: a PFIFO channel + USERD push
   buffer.
2. **A NOOP submission that completes** — write the vendor's NOOP
   opcode (`MI_NOOP` = 0x0 for Intel; `PACKET3_NOP` for AMD; a host-
   subchannel NOP for NVIDIA), kick the ring (write
   `RCS_TAIL` / `CP_RB_WPTR` / `GP_PUT`), wait for the ring head to
   catch up (poll `RCS_HEAD` / `CP_RB_RPTR` / `GP_GET`), declare the
   bring-up alive.
3. **A scanout-flush submission that draws** — the smallest end-to-
   end test that proves command submission produces visible pixels.
   For Intel without modeset, this is currently `MI_STORE_DWORD_IMM`
   into a known address (probe). For a real graphics output you need
   modeset + display-pipe programming, which is a follow-on slice.
4. **Self-test + boot-log breadcrumb** — `<Vendor>RingSelfTest` in
   the same style as `IntelGscFwSelfTest`, hooked to
   `BOOT_SELFTEST`. PASS line via `arch::SerialWrite` (matches the
   discipline from `CLAUDE.md` — "self-tests pass silently by
   default" — but this one is a structural sentinel CI can grep).
5. **Probe/probe-fire**: `KBP_PROBE(kGpuRingBringupFail, ...)` on
   the failure leg so a regression run halts in GDB at the exact
   frame.

**Out of scope for this slice:**

- Don't try to land all three vendors. Pick one, finish it, ship.
- Don't try to land modeset. EDID is parsed; DDI programming is a
  separate multi-week slice.
- Don't try to land SPIR-V execution. The CPU rasterizer in
  `graphics_vk_raster.cpp` is the current path; you're adding the
  GPU path alongside it, not replacing it.
- Don't try to add a new userland API. The Vulkan ICD is the
  consumer; touch only `vkQueueSubmit` to optionally route through
  the GPU ring when one is up.
- Don't add a feature flag that's never flipped. If the bring-up
  works, default it on; if it doesn't, keep it stubbed but explain
  in the commit why.

## Why Intel first

- Linux's `i915` driver is the most thoroughly documented open
  source GPU codebase. Every register read is auditable.
- Intel publishes Programmer's Reference Manuals (PRMs) for every
  generation. Search "Intel Gen9 Vol 7 Memory Interface and
  Commands."
- The RCS register file at MMIO 0x2000 has been stable from
  Skylake (2015) through Alder Lake (2021). One driver covers a
  decade of laptops.
- The scaffold (`kernel/drivers/gpu/intel_gpu.cpp`) already
  allocates the ring buffer and knows where the registers live —
  you're flipping the gate, not building from zero.
- GuC firmware lookup is wired in (`intel::Probe`) — drop
  `guc.bin` into `/lib/firmware/duetos/open/intel-gpu/` and the
  loader picks it up.

AMD is more complex (BIF / SDMA / GFX overlap; PM4 packet
encoding; MEC/RLC firmware ordering matters). NVIDIA is the
hardest (GSP firmware is mandatory on Turing+ — no GSP = no GPU;
need to talk to the GSP through a mailbox + RPC channel, no public
docs for the RPC schema except via reverse-engineering `nouveau`).

If the user later wants AMD/NVIDIA, do them in follow-on slices.

## Concrete first steps (Intel path)

1. **Read the existing scaffold end-to-end.** Don't skim.
   - `kernel/drivers/gpu/intel_gpu.{h,cpp}` (290 lines total)
   - `kernel/drivers/gpu/gpu.{h,cpp}` (dispatch + BAR map)
   - `kernel/drivers/gpu/virtio_gpu.cpp` (working command submission
     reference — the patterns transfer)
   - `kernel/mm/dma.h` (the `AllocDmaCoherent` / `DmaBuffer` API)
   - `CLAUDE.md` (Anti-Bloat Guidelines, Fix Anything You Surface,
     Wiring Things In)

2. **Decide where the command ring lives.** You have two options:
   - Inline in `intel_gpu.cpp` (current scaffold's path; keep the
     file under the 500-line threshold)
   - New TU `kernel/drivers/gpu/intel/rcs_ring.{h,cpp}` if the ring
     code is going to grow past ~200 lines. Move only when needed,
     not preemptively.

3. **Implement the ring program.** This is what the scaffold's
   STUB comment says it *would* do:
   ```cpp
   // After AllocDmaCoherent(kIntelRingBytes, Zone::Dma32):
   //   Mmio32Write(g, kIntelRcsTail,  0);
   //   Mmio32Write(g, kIntelRcsHead,  0);
   //   Mmio32Write(g, kIntelRcsStart, ring.phys);   // 4 KiB-aligned
   //   Mmio32Write(g, kIntelRcsCtl,
   //       ((kIntelRingBytes - 0x1000) & kIntelRingLengthMask) |
   //       kIntelRingEnable);
   ```
   You need `Mmio32Write` — symmetric to the existing `Mmio32` read
   helper. Add it. Use `volatile u32*` writes; no compiler reorder
   tricks.

4. **Build an `MI_NOOP` submitter.**
   - `MI_NOOP` = 0x00000000 (top bit clear → engine instruction,
     remaining bits zero → NOOP).
   - Write N NOOPs to the ring buffer starting at offset 0.
   - Advance the tail: `Mmio32Write(g, kIntelRcsTail, N * 4)`.
   - Poll `Mmio32(g, kIntelRcsHead)` until it equals tail, or
     until 100 ms timeout (use `time::MonotonicNs` + bounded loop).
   - If head reaches tail: ring is alive. Emit `[gpu/intel/rcs]
     selftest PASS (head=tail=...)`.
   - If timeout: fire `kGpuRingBringupFail` probe, emit WARN with
     the last seen head value, return `Unsupported` and leave the
     ring disabled.

5. **Add the boot self-test** in `kernel/diag/boot_selftest.cpp`
   (look at how `GraphicsIcdSelfTest` is wired).

6. **Wire it through `GpuInit`.** Today `RunVendorProbe` only
   calls `intel::Probe`. After Probe succeeds for an Intel device,
   call `intel::Bringup`. Don't gate it behind a build flag — if
   the user has Intel hardware, run it; if it's QEMU's `-vga std`,
   it'll fail at the MMIO live check and return early.

7. **Update `wiki/drivers/Graphics-Drivers.md`** with the new
   status. The "Known Limits / GAPs" section currently says "No
   real Intel/AMD/NVIDIA driver beyond discovery." If Intel ships,
   update that line. **In the same commit** as the code, per
   `CLAUDE.md`'s session-end rule.

## Testing on real silicon vs QEMU

QEMU's `-vga std` is Bochs VBE — it will not pretend to be Intel
hardware, so the ring program will fail at the MMIO live check
(`probe_reg == 0xFFFFFFFF`). That's correct behaviour, not a bug.

If you have access to a machine with an Intel iGPU and can boot
DuetOS off USB, run the bring-up there. The boot log line to grep
for is:
```
[gpu/intel/rcs] selftest PASS (head=tail=...)
```

If you don't have hardware access, ship the code with the gate
flipped on for any Intel device, document in the commit message
that it's not been validated on real silicon, and rely on someone
with the hardware to flip the bit if a register poke is wrong.
**Do not** add a build flag that defaults off — that's the dead-
code pattern the wiring-in rule prohibits.

## Subsystem-isolation reminders

- The GPU driver is kernel-side. It does not call into
  `kernel/subsystems/win32/` or `kernel/subsystems/linux/`. Those
  call into the Vulkan ICD or the compositor, which call into the
  GPU driver. One-way arrows.
- DMA buffer ownership: `AllocDmaCoherent` returns a `DmaBuffer`;
  the GPU driver owns it for its lifetime and `FreeDmaCoherent`s
  on shutdown. Don't leak — every Bringup path (success, failure,
  re-entry) must account for the buffer.
- Capability gate: any new syscall surface that lets userland
  submit commands needs a new `kCapGpuSubmit` or similar. v0
  doesn't expose userland submission, so you shouldn't need one
  this slice — but if you do, the gate goes in
  `kernel/core/capability.h` and every test/handler routes through
  it. No bypasses.

## What the user cares about

The user is running this on `claude-opus-4-7[1m]`. They have
previously shipped 28 commits on this branch and are tracking
boot-log signal closely. Their guidance has been consistent:

- **No vendored binaries.** Don't add `.bin` blobs to the repo.
  Firmware-loader lookup paths exist; the user decides what to
  drop into `/lib/firmware/`.
- **No half-built systems.** If you scaffold a ring but don't kick
  it, the next session will see it as dead code and delete it.
  Either deliver the NOOP submission test or don't open the file.
- **Boot must stay clean.** A failed bring-up emits one WARN
  line + a probe fire + DEBUG detail. It does NOT emit a stream
  of register dumps on every boot. Use `KLOG_DEBUG_V` for the
  detail.
- **Fix everything that surfaces.** When you build and a warning
  appears in `gpu.cpp` that predates your slice, fix it. When the
  scaffolds drift relative to your new ring code, update them. The
  symptom-cluster rule applies: one investigation, root-cause it,
  retire N issues.

## Definition of done

1. `cmake --build build/x86_64-release` clean.
2. `clang-format --dry-run --Werror` clean.
3. `ctest --output-on-failure` clean.
4. `tools/qemu/run.sh` boots clean and emits one of:
   - `[gpu/intel/rcs] selftest PASS` (on real silicon)
   - `[gpu/intel/rcs] no Intel device — skipped` (on QEMU)
   No `[E]`, no `PANIC`, no `task-kill`, no `out of range`.
5. `wiki/drivers/Graphics-Drivers.md` updated in the same commit.
6. Branch pushed to `origin/claude/setup-unity-engine-vJGc0`.

## Reference reading

- Intel Graphics Programmer's Reference Manuals:
  search "Intel Graphics Open Source Programmer's Reference
  Manuals" — published per architecture, vol 7 is commands.
- Linux `drivers/gpu/drm/i915/gt/intel_ring_submission.c` — the
  reference ring submitter. Read for shape, not for verbatim
  translation; the Linux DRM abstractions don't map onto DuetOS.
- DuetOS `kernel/drivers/gpu/virtio_gpu.cpp` — working in-tree
  reference for "kernel-side command queue produces pixels."
- DuetOS `kernel/drivers/gpu/intel_gpu.cpp` — the existing
  scaffold; this is what you're finishing.

===PROMPT END===

## Companion context — TLS Tier 2 (still deferred)

The GPU prompt above doesn't need this; it's here so the operator
launching the GPU session can decide whether to fold TLS into the
same branch or split it. **Recommendation: split.** Networking and
graphics share no surface, and TLS Tier 2 is a separate multi-week
crypto effort that benefits from a focused session.

If a future session does pick up TLS Tier 2, the scope is:

1. **P-256 field arithmetic** (`kernel/crypto/p256_field.{h,cpp}`)
   - 256-bit field over `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`
   - Montgomery form or unsaturated 4×64-bit; pick one and document
   - Mul, sqr, add, sub, inv (Fermat or Bernstein-Yang)
   - Self-test against NIST CAVP vectors
2. **P-256 point operations** (`kernel/crypto/p256_point.{h,cpp}`)
   - Jacobian projective coordinates
   - Point add, point double, scalar mult (constant-time ladder)
   - Decompress / encode in SEC1 uncompressed (0x04 ‖ X ‖ Y)
3. **ECDSA verify** (`kernel/crypto/ecdsa.{h,cpp}`)
   - For X.509 cert chains that use ECDSA-with-SHA256 (NIST P-256)
   - Verify against RFC 6979 test vectors
4. **ECDH key agreement** for the handshake's premaster secret
5. **TLS 1.2 ECDHE handshake additions** in `kernel/net/tls.cpp`
   - Parse ServerKeyExchange (curve params + ECDH public + signed)
   - Send modified ClientKeyExchange (ECDH public, no encrypted PMS)
   - Verify the SKE signature against the cert's public key
6. **TLS 1.2 HKDF key schedule** for ECDHE suites — different from
   the RSA suite's PRF-based schedule but uses the existing
   `kernel/crypto/hkdf.{h,cpp}`.

The Tier 2 suites the client should advertise (in priority order):

```
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   0xC0,0x2B
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     0xC0,0x2F
```

Reuse the existing AES-128-GCM AEAD (`kernel/crypto/aes_gcm.{h,cpp}`).
Reuse the existing X.509 parser; extend it to recognise the
`ecdsa-with-SHA256` OID (1.2.840.10045.4.3.2) and the
`id-ecPublicKey` OID with `prime256v1` parameters
(1.2.840.10045.2.1 + 1.2.840.10045.3.1.7).

Estimated scope: 4-6 sessions, depending on how aggressively
the constant-time invariants are validated.

The current TLS Tier 1 state is documented in
`wiki/networking/TLS-Roadmap.md`. Update that page when Tier 2
ships, the same way Tier 1 was marked complete in `f9a479b`.

## Companion context — Unity engine, original task

The original task was "download Unity engine and try to run the
exe; fix failures until it runs." The user explicitly said they
do not want the binary in the repo. The infrastructure to run
arbitrary PE binaries from `/desktop/<name>.exe` is now in place
(commands: `wget`, `unzip`, `cp`, `exec`; auto-preload of any DLL
dropped into `/lib/`; PE loader resolves a vendored DLL's own
imports as of `a255cce`).

Do not re-vendor Unity. If the user wants to test a real PE
workload, they will drop one onto the running OS via the existing
shell. The GPU work in the prompt above does not depend on Unity
being present.
