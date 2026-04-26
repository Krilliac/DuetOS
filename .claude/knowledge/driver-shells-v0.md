# Driver shells v0 — net / usb / audio / gpu-probes

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — discovery + classification + BAR map shells for
every device class we expect on commodity x86 hardware. No driver
logic; every shell is a "ready to grow" surface a future
vendor-specific slice drops into.

## Shells that landed

| Directory                | Entry point       | Classes handled         |
| ------------------------ | ----------------- | ----------------------- |
| `kernel/drivers/gpu/`    | `GpuInit()`       | PCI class 0x03 display  |
| `kernel/drivers/net/`    | `NetInit()`       | PCI class 0x02 network  |
| `kernel/drivers/usb/`    | `UsbInit()`       | PCI class 0x0C/0x03 USB |
| `kernel/drivers/audio/`  | `AudioInit()`     | PCI class 0x04 audio    |

Each shell:
- Walks the cached PCI device table via `pci::PciDevice(i)`.
- Filters by `class_code` (and `subclass` / `prog_if` where
  relevant — USB needs the prog_if to distinguish UHCI/OHCI/EHCI/xHCI).
- Classifies by vendor or by prog_if, picks a short family tag.
- Reads BAR 0 via `pci::PciReadBar`, maps it via `mm::MapMmio`
  (capped to a class-appropriate ceiling to protect the MMIO
  arena).
- Caches the result in a fixed-capacity array.
- Exposes a `XxxCount()` / `Xxx(i)` accessor.
- Logs a structured per-device line plus a summary count.
- `KASSERT`s a single-init-per-boot contract.

The layout mirrors `drivers/gpu/gpu.{h,cpp}` exactly — same
constants + log format + array + accessors — so the next slice
for any of them is a vendor driver replacement rather than a
structural rewrite.

## Boot order

`kernel/core/main.cpp` runs discovery in this order, straight
after `PciEnumerate`:

```
PciEnumerate()
GpuInit()          // display
NetInit()          // network
UsbInit()          // USB host controllers
AudioInit()        // audio
BlockLayerInit()   // AHCI / NVMe block layer
```

A driver that panics in init would halt boot before the block
layer comes up — ordering deliberately keeps the riskiest code
(our first real interactions with unfamiliar BAR regions)
before anything stateful.

## Observed on QEMU q35 default

```
[boot] Detecting GPUs.
[gpu-probe] vid=0x1234 did=0x1111 family=qemu-bochs-vga
drivers/gpu : discovered GPUs   val=1
  gpu 0:1.0 vendor="QEMU-Bochs" tier=tier3-dev sub=VGA bar0=0xfd000000/0x1000000 -> 0xffffffffc03ed000

[boot] Detecting NICs.
[net-probe] vid=0x8086 did=0x10d3 family=e1000e-82574
drivers/net : discovered NICs   val=1
  nic 0:2.0 vendor="Intel" sub=ethernet bar0=0xfeb80000/0x20000 -> 0xffffffffc13ed000

[boot] Detecting USB host controllers.
drivers/usb : discovered host controllers   val=0
[W] drivers/usb : no USB host controllers found
[usb] class drivers registered: hid, msc, hub, video

[boot] Detecting audio controllers.
drivers/audio : discovered audio controllers   val=0
[W] drivers/audio : no PCI audio controllers found (QEMU default q35 is silent)
```

q35 default gives us Bochs VGA + e1000e NIC. USB + audio
controllers are absent — exercising the "no devices found"
warning path of each shell.

## Vendor tag coverage

### GPU (`drivers/gpu/gpu.cpp::IntelGenTag` etc.)

Intel: gen9-skylake/kabylake, gen9.5-coffeelake, gen11-12 icelake/tigerlake, gen13-alderlake, gen12.7-dg2-arc.
AMD: gfx9-raven/vega, gfx10-navi1x, gfx10.3-navi2x, gfx11-navi3x.
NVIDIA: turing-rtx-2000, ampere-rtx-3000, ampere-ga10x, ada-rtx-4000.

### Network (`drivers/net/net.cpp`)

Intel: e1000-82540em, e1000e-82574/82579/i210/i217, ixgbe-82598/x540/x550, i40e-x710, iwlwifi.
Realtek: rtl8139, rtl8169, rtl8101e, rtl8125-2.5g, rtl8821ae-wifi.
Broadcom: bcm57xx-tg3, bcm4331-wifi.
virtio-net: 0x1000 and 0x1041 (transitional + modern).

### USB (`drivers/usb/usb.cpp::HciKindName`)

Dispatch by prog_if: UHCI / OHCI / EHCI / xHCI / device-controller
(skipped).

### Audio (`drivers/audio/audio.cpp::AudioKindName`)

Dispatch by subclass: legacy / ac97 / hda / other.

## Class-driver surface (USB)

`drivers/usb/` also registers a small table of class-driver
probes (HID, MSC, Hub, Video). They're invoked once per
attached USB device by a future bus-enumeration slice; today
each logs `"[usb-xxx] probe ... (stub — not claimed)"` and
refuses to attach. The surface exists so that the xHCI slice
has somewhere to dispatch to when it lands.

## MMIO mapping caps (per class)

Different classes get different per-BAR size caps to avoid
exhausting the 512 MiB MMIO arena:

| Class   | Cap   | Rationale                                 |
| ------- | ----- | ----------------------------------------- |
| GPU     | 16 MiB | Register file + limited framebuffer window |
| NIC     | 2 MiB  | Register file only                        |
| USB HC  | 1 MiB  | Register file + ring base                 |
| Audio   | 256 KiB | HDA is <64 KiB                           |

A driver that needs more maps extra BARs itself during its own
init.

## Boot-smoke guards

`tools/test/ctest-boot-smoke.sh` asserts every shell's
`discovered Xxx` klog line, every vendor probe's tag, and the
`class drivers registered` line for USB. The e1000e + Bochs
family tags are also explicit — they won't drift unless QEMU's
default devices change.

## Companion skeletons that landed alongside

- **`kernel/net/stack.{h,cpp}`** — L2/L3/L4 types + NetStackInit.
  Binds each NIC from `drivers::net` as an interface. Logs a
  per-iface line. `static_assert`s every on-wire header size.
- **`kernel/fs/ext4.{h,cpp}`**, **`kernel/fs/ntfs.{h,cpp}`**,
  **`kernel/fs/exfat.{h,cpp}`** — boot-sector / superblock probe
  shells for the three interoperability formats. Each scans
  every block device and logs "volumes found" (0 on QEMU's
  ramfs-only boot).
- **`kernel/subsystems/graphics/graphics.{h,cpp}`** — Vulkan
  ICD skeleton + D3D11/D3D12/DXGI translation stubs. Enumerates
  `drivers::gpu::Gpu(i)` as physical devices, returns
  `VK_ERROR_INCOMPATIBLE_DRIVER` / `E_FAIL` so callers hit
  their fallback paths cleanly.

## Next slice candidates

1. **virtio-gpu bring-up** — simplest real GPU driver. 2D
   cursor / blit via a virtqueue; exercise the 16 MiB BAR we
   already mapped.
2. **e1000e MAC read + link-state** — smallest valuable real
   NIC step. Doesn't need TCP/IP, just prove the register file
   is addressable.
3. **xHCI enumeration scaffolding** — capability register
   layout + operational registers. No ring setup yet, just
   validating that the MMIO window decodes.
4. **Intel HDA codec probe** — 2 MMIO reads to confirm the
   controller presence, no codec parsing.
5. **ext4 superblock → directory walk** — the probe shell
   already validated the magic; next is reading block-group
   descriptors and the root-directory inode.
6. **Wire D3D PE imports into the graphics ICD** —
   win32/thunks.cpp would route `d3d11.dll!D3D11CreateDevice`
   straight to `subsystems::graphics::D3D11CreateDeviceStub`
   instead of the miss-logger. First step toward
   DXVK/vkd3d-proton-style translation.

Each is a single commit's worth of work.

## References

- `kernel/drivers/gpu/`  — GPU shell + vendor tags.
- `kernel/drivers/net/`  — network shell + classifiers.
- `kernel/drivers/usb/`  — USB shell + class-driver table.
- `kernel/drivers/audio/` — audio shell.
- `kernel/drivers/pci/pci.h` — consumed API.
- `docs/knowledge/hardware-target-matrix.md` — tier definitions.
- `docs/knowledge/usb-xhci-scope-estimate.md` — deferred real
  xHCI work.
- ValveSoftware/wine — prior art for D3D → Vulkan translation
  (DXVK / vkd3d-proton) when we reach that layer.
