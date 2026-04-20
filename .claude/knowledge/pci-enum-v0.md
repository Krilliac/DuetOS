# PCI Enumeration v0 — Legacy port-IO walk

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

First walk of the PCI config space. Uses the classic 0xCF8/0xCFC
port pair (Configuration Mechanism #1) to read every device on
bus 0..3. Each present device is cached in `g_devices[]` and logged
with bus/dev/fn, vendor/device IDs, class/subclass/prog_if, and
header type.

Deliberately not using the faster MMCONFIG/ECAM path yet — MCFG
table parsing is deferred to the same commit that introduces the
xHCI driver (see `usb-xhci-scope-estimate.md`). Legacy port-IO works
on every x86 machine and is ~150 lines; MCFG is faster + doesn't
need a shared port pair, but doesn't unblock anything today.

Verified output on QEMU q35 (6 devices, matches the documented
q35 baseline):

```
[I] drivers/pci : enumerated devices val=0x6
  pci 0:00.0  vid=0x8086 did=0x29c0 class=0x6/0x0/0x0 (bridge)
  pci 0:01.0  vid=0x1234 did=0x1111 class=0x3/0x0/0x0 (display)
  pci 0:02.0  vid=0x8086 did=0x10d3 class=0x2/0x0/0x0 (network)  ← e1000
  pci 0:1f.0  vid=0x8086 did=0x2918 class=0x6/0x1/0x0 (bridge)   ← ICH9 LPC
  pci 0:1f.2  vid=0x8086 did=0x2922 class=0x1/0x6/0x1 (mass storage) ← AHCI
  pci 0:1f.3  vid=0x8086 did=0x2930 class=0xc/0x5/0x0 (serial bus)   ← SMBus
```

## Context

Applies to:
- `kernel/drivers/pci/pci.{h,cpp}` — module itself
- `kernel/core/main.cpp` — calls `PciEnumerate()` after
  `SmpStartAps()` and before `StartHeartbeatThread()`

Depends on `arch::Outb` / `arch::Inb` (port IO — already in `cpu.h`)
and the core klog/panic infrastructure. No ACPI dependency for the
legacy path.

Unblocks: AHCI / NVMe / xHCI / e1000 / GPU drivers — each needs
`PciConfigRead*` to discover its device and read BARs. Also a
prerequisite for MSI setup (which writes to the device's
config-space capability registers).

## Details

### Configuration Mechanism #1

Write a 32-bit "address" to port 0xCF8, read/write a 32-bit "data"
word at port 0xCFC. Address layout:

| Bit(s) | Field | Notes |
|--------|-------|-------|
| 31 | Enable | Always 1 for a meaningful access |
| 30:24 | Reserved | 0 |
| 23:16 | Bus | 0..255 |
| 15:11 | Device | 0..31 |
| 10:8 | Function | 0..7 |
| 7:2 | Register (dword index) | 0x00..0xFC |
| 1:0 | Must be 0 | Low two bits reserved |

Only 32-bit reads/writes are meaningful in legacy mode. 16/8-bit
accessors just read the full dword and extract the slice.

### Device presence check

Read the 32-bit dword at offset 0 (vendor_id + device_id). If the
vendor_id low 16 bits are `0xFFFF`, no device is present — any
device must have a non-0xFFFF vendor ID per the PCI SIG spec.

### Multi-function devices

Each (bus, device) slot can host up to 8 functions but most only
expose function 0. Bit 7 of the `header_type` field (offset 0x0E)
is the "multi-function" flag; if set, scan functions 1..7 also.
Without this check we'd miss two ICH9 devices on q35 — the LPC
bridge exposes AHCI and SMBus as separate functions.

### Bus scan scope

v0 scans bus 0..3. QEMU q35 puts everything on bus 0; bridges
would expose downstream buses (1+). Adding recursive walking
("when you find a bridge, scan its secondary bus") is a separate
commit — triggered when a board actually has bridges with
interesting devices downstream.

### Regression canaries

- **Zero devices enumerated:** port IO path broken, or 0xCF8/0xCFC
  aren't mapped on this machine. Test by manually reading bus 0
  device 0 in the debugger — should return the host bridge's
  vendor_id.
- **Every read returns 0xFFFFFFFF:** CONFIG_ENABLE bit not set in
  the address. Check `MakeAddress`.
- **Function 0 of a multi-function device cached, others missed:**
  multi-function bit test regressed. Header bit 7 lives at offset
  0x0E, not 0x0D.
- **QEMU q35 shows only 2-3 devices:** user ran QEMU without
  `-machine q35`, probably got the old i440fx. That's a different
  topology (LPC on 0x01.3) so the baseline log shape won't match.

### What's missing

- **BAR parsing + size probe + resource allocation.** Today we read
  BAR 0..5 raw on demand via `PciConfigRead32`. Sizing a BAR requires
  writing all 1s then reading back the mask, which is destructive
  and needs a driver-side "I want this BAR" convention. Deferred.
- **MSI / MSI-X setup.** The device's capabilities list (pointer at
  offset 0x34) chains MSI/MSI-X/PM/PCIe-Cap structures. A driver
  that wants MSI-X has to walk this list and write the target
  address + vector. Separate commit.
- **INTx routing.** Needs the ACPI `_PRT` (PCI Routing Table) or a
  hardcoded q35 map for v0. Drivers needing legacy INTx fall back
  to the IOAPIC machinery we already have; the `interrupt_line` /
  `interrupt_pin` config fields give the wiring.
- **MCFG / MMCONFIG.** 4 KiB of ECAM space per function at a fixed
  physical address, mapped via `MapMmio`. Faster + no shared
  CONFIG_ADDRESS port to serialise across CPUs. Deferred until a
  driver cares about config-read latency or SMP contention.
- **Bridge recursion.** See "Bus scan scope" above.
- **Hot-plug.** PCIe SHPC / nativ hot-plug arrives with the driver
  model.

## Notes

- **Not SMP-safe.** Two CPUs simultaneously touching the
  CONFIG_ADDRESS register would corrupt each other's reads. Wrap
  in a spinlock when the scheduler SMP refactor adds runqueue
  spinlocks (Commit C in `smp-ap-bringup-scope.md`).
- **Not recoverable.** Enumerate-on-boot is one-shot; there's no
  re-scan mechanism. When hot-plug arrives, the dispatch path
  grows but the initial walk stays.
- **No driver binding yet.** Devices are cached; no one iterates
  the cache to match-and-bind drivers. When the first real driver
  lands it'll look up its (vendor_id, device_id) pair in the cache
  and call its own init.
- **See also:**
  - `acpi-madt-v0.md` — ACPI machinery PCI will share (MCFG
    parsing lives next to MADT parsing when it lands).
  - `ioapic-v0.md` — INTx routing target for every PCI device
    that doesn't use MSI.
  - `runtime-recovery-strategy.md` Class B — driver restart hooks
    future PCI-backed drivers will use when they fault.
  - `usb-xhci-scope-estimate.md` — the staged plan that starts
    with "MCFG + ECAM + BAR allocation" building on top of this
    legacy enumerator.
