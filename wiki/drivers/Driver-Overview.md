# Driver Overview

> **Audience:** Driver authors, kernel hackers
>
> **Execution context:** Kernel — drivers can be IRQ-context, softirq, or process
>
> **Maturity:** Mixed — see per-driver pages

## Overview

DuetOS drivers live under `kernel/drivers/`, organised by device class.
Each driver is responsible for stating its execution context (IRQ /
softirq / process) at the top of its header. The driver framework is
deliberately monolithic-style for hot paths — drivers compile into the
kernel image and call kernel APIs (`mm::*`, `sched::*`, `pci::*`)
directly.

## Device Classes

| Class | Path | Notable drivers |
|-------|------|-----------------|
| PCI bus | `kernel/drivers/pci/` | PCIe enumeration |
| Storage | `kernel/drivers/storage/` | NVMe, AHCI |
| USB | `kernel/drivers/usb/` | xHCI host + HID/MSC/CDC-ECM/RNDIS class |
| Network | `kernel/drivers/net/` | Intel e1000 |
| GPU | `kernel/drivers/gpu/` | virtio-gpu, Intel/AMD/NVIDIA discovery |
| Audio | `kernel/drivers/audio/` | Intel HDA |
| Input | `kernel/drivers/input/` | PS/2 keyboard/mouse |
| Video | `kernel/drivers/video/` | Framebuffer, compositor primitives, theme |
| Power | `kernel/drivers/power/` | Reboot / shutdown |

## Hardware Target Matrix

The kernel uses these tiers for vendor matching across drivers; per
class, tier 1 is the "must work" target, tier 2 the "nice to have",
tier 3 the dev/QEMU-only path.

| Class | Tier 1 | Tier 2 | Tier 3 (dev) |
|-------|--------|--------|--------------|
| CPU | Intel x86_64 (Coffee Lake → Sapphire Rapids), AMD Zen+ | Intel pre-Coffee Lake, AMD pre-Zen+ | QEMU TCG |
| GPU | Intel iGPU (Gen9+), AMD Radeon (GFX9+), NVIDIA (Turing+) | Older Intel/AMD/NVIDIA | virtio-gpu |
| NIC | Intel e1000 / e1000e | Realtek rtl8169, Broadcom bcm57xx | virtio-net |
| Wi-Fi | iwlwifi (Intel), rtl88xx, bcm43xx | (none yet) | (none) |
| USB | xHCI 1.0+ | EHCI (legacy fallback) | (none) |
| Storage | NVMe, AHCI/SATA | (legacy IDE deferred) | virtio-blk |
| Audio | Intel HDA | AC'97 (deferred) | (none) |

## Driver Lifecycle

1. **Bus enumeration** discovers candidate devices (PCI walks the bus,
   USB enumerates after the host controller comes up).
2. **Probe** matches each device against registered drivers via
   `(vendor, device)` pairs or class codes.
3. **Init** maps MMIO BARs, sets up rings/queues, registers IRQ
   handler, exposes the device-class interface (block / netif /
   input / framebuffer / etc.).
4. **Use**: kernel subsystems and userland reach the device through
   the device-class interface, never through driver-internal symbols.

Per the [anti-bloat checklist](../tooling/Anti-Bloat-Guidelines.md):
**every driver must be probed**. A `probe()` that compiles but isn't
called from a bus enumerator is dead code. Either wire it in or
delete it.

## Threading Rules

- **IRQ handlers**: must not sleep, must not allocate from sleeping
  paths, must not hold a sleeping mutex. Defer real work to a
  bottom-half or worker thread.
- **DMA**: no driver holds a sleeping mutex across DMA. Use the
  appropriate softirq / completion primitive.
- **MMIO mappings**: `mm::MapMmio` is the only sanctioned way to
  reach device registers — it sets `kPageCacheDisable` (PCD)
  automatically.

## Capability Surface

Most drivers expose their capabilities through the kernel's syscall
gates (`SYS_FILE_*` for storage, `SYS_SOCK_*` for net, `SYS_GDI_*` /
`SYS_WIN_*` for the video path). They are not directly reachable from
userland. See [Subsystem Isolation](../kernel/Subsystem-Isolation.md).

<!-- AUTO:driver_list -->
| Class | Source files | Path |
|-------|--------------|------|
| `audio` | 5 | `kernel/drivers/audio/` |
| `gpu` | 15 | `kernel/drivers/gpu/` |
| `input` | 2 | `kernel/drivers/input/` |
| `mei` | 1 | `kernel/drivers/mei/` |
| `net` | 18 | `kernel/drivers/net/` |
| `pci` | 1 | `kernel/drivers/pci/` |
| `power` | 1 | `kernel/drivers/power/` |
| `storage` | 3 | `kernel/drivers/storage/` |
| `usb` | 20 | `kernel/drivers/usb/` |
| `video` | 25 | `kernel/drivers/video/` |
<!-- /AUTO:driver_list -->

_The driver inventory above is auto-synced by `docs/sync-wiki.sh sync`
from the `kernel/drivers/<class>/<name>` directory tree._

## Related Pages

- [PCIe Enumeration](PCIe-Enumeration.md) — first driver step at boot
- [Storage (NVMe + AHCI)](Storage.md)
- [USB (xHCI + class)](USB.md)
- [Networking Drivers](Networking-Drivers.md)
- [Graphics Drivers](Graphics-Drivers.md)
- [Audio](Audio.md)
- [Input](Input.md)
