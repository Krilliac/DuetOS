# PCIe Enumeration

> **Audience:** Driver authors
>
> **Execution context:** Kernel — process context during boot
>
> **Maturity:** v0 (legacy port-IO walk); ECAM/MMCONFIG path planned

## Overview

The PCI enumerator walks every (bus, device, function) tuple via the
legacy `0xCF8` / `0xCFC` port-IO config-space mechanism, capturing
vendor/device IDs, class codes, BARs, and capability lists. It is the
**first driver step at boot** — every other driver depends on its
device list.

## Enumeration Strategy

```
for bus in 0..255:
    for dev in 0..31:
        for fn in 0..7:
            vendor = readw(bus, dev, fn, 0x00)
            if vendor == 0xFFFF: continue
            record device
            if header_type & 0x80 == 0: break  # not multifunction
```

Multi-function devices are detected via the `0x80` bit on the header
type at function 0. Bridges are recorded but not recursively walked
in v0 — every device the kernel cares about today (NVMe, AHCI, e1000,
xHCI, virtio-gpu, HDA) is on the root bus or one hop down.

## What Gets Recorded

Per device:

- `(vendor_id, device_id)` for driver matching
- Class / subclass / prog-IF for class-based matching
- Up to 6 BARs with type (MMIO / IO), 64-bit aware
- Capability list (MSI / MSI-X / PCIe extended caps)

The list lives in `kernel/drivers/pci/pci.{h,cpp}`. Driver matching
walks the recorded list and calls each registered driver's `probe`
function with the matched device.

## Driver Probe Pattern

A driver registers (`(vendor, device)` pair OR `(class, subclass)`
match) and a `probe(device)` function. The PCI enumerator calls
`probe` for every matching device in `pci_init`'s second pass, after
the device list is fully built.

```cpp
static const PciId nvme_match[] = {
    { .class_code = 0x01, .subclass = 0x08, .prog_if = 0x02 },
    { 0 },
};

PCI_REGISTER_DRIVER("nvme", nvme_match, NvmeProbe);
```

## Known Limits / GAPs

- **No PCIe ECAM (MMCONFIG) walk.** Legacy port IO works for QEMU q35
  and most modern hardware but is slower than ECAM and is gated to
  the first 256 buses. `kernel/drivers/pci/` will need an ECAM path
  when running on multi-segment systems.
- **No bus rescan.** Hot-plug (Thunderbolt, U.2 NVMe) is not yet
  supported — devices found at boot are the device list forever.
- **MSI/MSI-X**: capability list is parsed; full programming is
  driver-specific (NVMe and e1000 use MSI-X today).

GPU discovery uses class `0x03` (display controller). The probe
records BAR0 (framebuffer), BAR2 (config / I/O), and the capability
chain. Vendor classification (Intel iGPU / AMD GFX / NVIDIA) is by
PCI vendor-ID bit pattern and used by [Graphics Drivers](Graphics-Drivers.md)
to dispatch to the per-vendor probe.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Storage (NVMe + AHCI)](Storage.md)
- [Networking Drivers](Networking-Drivers.md)
- [Graphics Drivers](Graphics-Drivers.md)
- [Boot Path](../kernel/Boot.md)
