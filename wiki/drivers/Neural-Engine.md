# Neural Engine (NPU / AI accelerator)

> **Audience:** Driver authors, kernel hackers, anyone working the
> autonomic-OS arc
>
> **Execution context:** Kernel — probe in early driver init; no
> command path yet
>
> **Maturity:** v0 — PCI scaffold only (probe + classify + inventory).
> Firmware load and command submission are deferred.

## Overview

[`kernel/drivers/npu/`](../../kernel/drivers/npu/) detects the
fixed-function inference accelerator that ships on-die on recent
commodity x86_64 SoCs, alongside the iGPU:

- **Intel "AI Boost" NPU** — the ex-Movidius VPU lineage. NPU 3720 on
  Meteor Lake / Arrow Lake, NPU 4000 on Lunar Lake. Vendor `0x8086`.
- **AMD XDNA ("Ryzen AI")** — the AIE-ML tile. XDNA1 on Phoenix / Hawk
  Point, XDNA2 on Strix Point. Vendor `0x1022`.

It mirrors the [MEI driver](../../kernel/drivers/mei/) idiom: a
probe-only PCI scaffold that a later slice builds the firmware and
command path on top of.

```
PCI enumeration (kernel/drivers/pci/) discovers every endpoint
                |
                v
NpuInit() — walks the list, applies the two-gate match, classifies
                |
        +-------+--------+
        v                v
  Intel AI Boost    AMD XDNA
  (device-ID gate)  (class-0x12 gate)
                |
                v
  inventory + boot-log line + `npu` shell command
```

## The two-gate match

There is no single PCI signature that covers both vendors, so the
probe uses a **property-first** gate with a documented exception:

1. **Primary (property):** PCI base-class `0x12` "Processing
   Accelerators". AMD XDNA and any spec-compliant NPU report this.
   Keying on the class — not a per-vendor device-ID whitelist —
   avoids the *whitelist-incompleteness* failure class (a new
   compliant part is matched without a code change).
2. **Secondary (device-ID):** Intel's NPU mis-reports as a
   Multimedia controller, so a small explicit Intel NPU device-ID
   set (`NpuIsIntelNpuDeviceId`) covers it.

| Vendor | Device | Generation | `NpuKind` tag |
|--------|--------|------------|---------------|
| Intel `0x8086` | `0x7D1D` | NPU 3720 — Meteor Lake | `intel-npu37` |
| Intel `0x8086` | `0xAD1D` | NPU 3720 — Arrow Lake  | `intel-npu37` |
| Intel `0x8086` | `0x643E` | NPU 4000 — Lunar Lake  | `intel-npu40` |
| AMD `0x1022`   | `0x1502` | AIE-ML — Phoenix / Hawk Point | `amd-xdna1` |
| AMD `0x1022`   | `0x17F0` | AIE-ML v2 — Strix Point | `amd-xdna2` |

An unrecognised device that still matches the class gate is recorded
with `NpuKind::Unknown` (tag `?`) rather than mis-labelled — the
honest fallback. The classifier's coverage is asserted by
`NpuSelfTest()` (boot self-test, emits `[npu] selftest pass`).

**GAP:** the device-ID table is per-SKU and will lag new silicon
(Panther Lake, future Ryzen AI). AMD parts keep matching via the
class gate; an unrecognised *Intel* part is missed until its ID is
added. Revisit when a board with a newer NPU enters the test matrix.

## What v0 does and does not do

Does:

- Probe, classify, map a capped (64 KiB) window of BAR0 so a later
  slice can reach the boot register file without re-running the size
  probe.
- Expose a stable inventory (`NpuDeviceCount` / `NpuDevice`), a
  boot-log line per device, and the `npu` (alias `ml`) shell command.

Does **not** (deferred — each its own slice):

- Load signed NPU firmware or run the boot handshake.
- Set up the command ring / doorbell / completion IRQ.
- Provide a cap-gated `SYS_*` submit surface, or any Win32 / Linux
  inference-API facade. Per
  [Subsystem Isolation](../kernel/Subsystem-Isolation.md), subsystems
  will reach the NPU only through a kernel-owned, cap-gated submit
  syscall — never directly. That gate does not exist yet, so nothing
  outside the kernel can touch the device today.

## The longer arc — toward an autonomic OS

This driver is brick #1 of a longer goal: an OS that senses its own
internal and external environment, decides, and acts — an *autonomic*
control loop, not a conscious one. The honest path:

1. **NPU substrate** (this slice) — the kernel can find and own the
   inference silicon. Nothing learns without hardware to run on.
2. **Sense → decide → act loop** — wire the existing
   [`kernel/env/`](../../kernel/env/) env-monitor signals into a
   kernel-owned policy point (today's "idle reaction deferred" TODO
   is the embryo).
3. **Learned policy** — once the NPU has a firmware + submit path,
   that decision point can consult a small on-device model instead
   of hand-written heuristics. That is the realistic form of
   "reacts with its own judgment": an autonomic OS whose control
   policy is learned, kernel-owned, and cap-gated like every other
   effect a workload can have.

Each step is a separate slice with a nameable caller before it is
written — the arc is recorded here so the next slice does not have to
re-derive it, not as licence to build ahead of need.

## Files

- [`kernel/drivers/npu/npu.h`](../../kernel/drivers/npu/npu.h) — API,
  `NpuKind`, the two gate constants.
- [`kernel/drivers/npu/npu.cpp`](../../kernel/drivers/npu/npu.cpp) —
  probe, classifier, BAR0 map, self-test.
- Wired from `kernel/core/boot_bringup.cpp` (probe + self-test),
  `kernel/shell/shell_hardware.cpp` (reinit + HW summary), and the
  `npu` command in `kernel/shell/shell_display.cpp`.
