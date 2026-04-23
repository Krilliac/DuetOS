# GPU discovery v0 — PCI classification + BAR map

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — first boot slice of the `drivers/gpu/` tree.
Enumerates display-class PCI devices, classifies them by vendor,
maps BAR 0 into the MMIO arena, and logs a one-line-per-GPU summary.
No actual driver — this is the aperture-claim step every
vendor-specific slice will build on.

## What it does

`GpuInit()` (called from `kernel/core/main.cpp` immediately after
`PciEnumerate`) walks the cached `pci::Device` table, picks every
entry with `class_code == 0x03` (display controller), and for each:

1. Copies `vendor_id`, `device_id`, bus/dev/fn, `subclass`.
2. Looks up the vendor in a small in-file table; falls back to
   `vendor="unknown" tier="unknown"` so unfamiliar GPUs are still
   recorded + visible in the boot log.
3. Reads BAR 0 via `pci::PciReadBar(d.addr, 0)`.
4. If BAR 0 is a non-empty MMIO region, calls `mm::MapMmio(phys,
   min(size, 16 MiB))` and caches the returned kernel VA.
5. Logs a structured line per GPU.

Records live in `g_gpus[kMaxGpus]` (cap 4). Accessors: `GpuCount()`,
`Gpu(i)`.

## Vendor / tier table

Mirrors `docs/knowledge/hardware-target-matrix.md`:

| Vendor ID | Short name    | Tier                  |
| --------- | ------------- | --------------------- |
| 0x8086    | Intel         | `tier1-intel-igpu`    |
| 0x1002    | AMD           | `tier1-amd-radeon`    |
| 0x10DE    | NVIDIA        | `tier1-nvidia`        |
| 0x15AD    | VMware-SVGA   | `tier3-vm`            |
| 0x1234    | QEMU-Bochs    | `tier3-dev`           |
| 0x1AF4    | virtio-gpu    | `tier3-dev`           |

Unknown vendors get `vendor="unknown" tier="unknown"` — still logged.

## Observed on QEMU q35

```
[boot] Detecting GPUs.
[I] drivers/gpu : discovered GPUs   val=0x1 (1)
  gpu 0:1.0  vid=0x1234 did=0x1111 vendor="QEMU-Bochs" tier=tier3-dev
             sub=VGA bar0=0xfd000000/0x1000000 -> 0xffffffffc03ed000
```

The Bochs VGA's 16 MiB framebuffer BAR lands in the MMIO arena at
`0xffffffffc03ed000` — reachable by the kernel for a future mode-set
/ blit slice. The existing Multiboot2 framebuffer and this BAR point
at the same physical memory; future slices can consolidate.

## What's intentionally NOT here

- No driver logic (command ring, engine init, power management).
- No modeset — the framebuffer geometry still comes from Multiboot2.
- No user-mode surface (Vulkan ICD, D3D translation).
- No IRQ wiring. MSI/MSI-X capability discovery is already in
  `pci::PciMsixFind`; the first vendor driver slice will use it.
- No bridge walking — `PciEnumerate` covers bus 0..3, which is fine
  for q35 + every typical workstation but will miss GPUs behind
  PCIe-to-PCIe bridges on server boards. Followup.

## Boot-smoke guard

`tools/ctest-boot-smoke.sh` now asserts the
`drivers/gpu : discovered GPUs` klog line appears. A regression in
PCI enumeration or GpuInit wiring fails the smoke.

## Next slice candidates

1. **Vendor-specific driver stubs** — empty `IntelGen9Probe`,
   `AmdGfx9Probe`, `NvidiaTuringProbe` entry points gated on
   (vendor_id, device_id). Each prints "probe OK" and is wired
   into GpuInit's per-device classification step.

2. **Vulkan ICD skeleton** — stub `vk` user-mode surface that
   forwards every entry point to a logging no-op. This is the
   user-mode half of the "direct GPU driver, Vulkan first" roadmap.

3. **virtio-gpu bring-up** — tier-3 but genuinely useful. Simple
   virtqueue, 2D cursor / blit commands; the smallest non-trivial
   GPU driver we could actually run.

4. **D3D11/D3D12 translation to Vulkan** — this is where
   Valve's wine DXVK / vkd3d (ValveSoftware/wine fork) becomes
   relevant. Their IR lowering + descriptor-table handling is
   worth studying even though we don't fork them.

## References

- `kernel/drivers/gpu/gpu.{h,cpp}` — this slice.
- `kernel/drivers/pci/pci.h` — `PciDevice`, `PciReadBar` consumed here.
- `kernel/mm/paging.h` — `MapMmio` consumed here.
- `docs/knowledge/hardware-target-matrix.md` — tier definitions.
- ValveSoftware/wine (github) — prior art for D3D11/D3D12 → Vulkan
  translation layers (DXVK, vkd3d-proton).
