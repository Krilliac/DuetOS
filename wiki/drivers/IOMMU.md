# IOMMU (Intel VT-d + AMD-Vi)

> **Audience:** Driver authors, kernel hackers, security / threat modellers
>
> **Execution context:** Kernel — boot bring-up (process context, before SMP); no IRQ path in v0
>
> **Maturity:** v0 — Intel VT-d discovery → decode → identity page tables → enable is complete and **ON by default** (`DUETOS_IOMMU_ENABLE=ON`; identity map + GCMD.TE when a DMAR is present; `iommu=off` cmdline escape hatch); AMD-Vi is parse-only; DMAR fault-IRQ handler still residual

## Overview

The IOMMU driver is the kernel's DMA-remapping layer. An IOMMU sits between
PCI(e) devices and physical memory and translates the addresses a device emits
during DMA (IO virtual addresses, IOVAs) into host physical addresses, exactly
the way the CPU's MMU translates virtual addresses for software. With it on, a
compromised or buggy device — or a malicious driver feeding a device a bad
descriptor — can only touch the memory its IOMMU context permits, instead of the
entire physical address space.

DuetOS supports both commodity IOMMU implementations:

- **Intel VT-d**, discovered through the ACPI **DMAR** table.
- **AMD-Vi**, discovered through the ACPI **IVRS** table.

Both expose the same conceptual surface — *parse the firmware table → decode the
capability registers → build page tables → enable translation* — but their
register layouts and ACPI tables differ. `kernel/drivers/iommu/iommu.h` is the
thin vendor-neutral dispatcher `boot_bringup` calls; the concrete work lives in
the per-vendor translation units.

| Vendor | Parse | Reg-decode | Paging | Enable |
|--------|-------|-----------|--------|--------|
| Intel  | `DmarInit` | `VtdInit` | `VtdPagingInit` | `VtdProgramAndEnable` |
| AMD    | `IvrsInit` | *deferred* | *deferred* | *deferred* |

AMD-Vi register decode, page tables, and enable are deferred until an AMD test
machine is available; today only the IVRS parser runs and `IommuEnableAtBoot`
returns `Unsupported` on AMD platforms.

## When to Use / When to Read

- You are adding per-device DMA isolation (the next step beyond identity
  passthrough) and need to know where contexts and page tables are built.
- You are bringing up the AMD-Vi enable path (slices mirroring the VT-d
  sequence) and need the vendor-neutral seam.
- You are debugging a boot that panics in `boot/iommu`, or a device whose DMA
  stopped working after `DUETOS_IOMMU_ENABLE` was turned on.
- You are threat-modelling device DMA and need to know what protection is
  actually live (see [Driver and Fault Domains](../security/Driver-Domains.md)
  and [ME / PSP Mitigation](../security/ME-PSP-Mitigation.md)).

## Boot Integration

`boot_bringup` runs the IOMMU sequence after `AcpiInit()` (the parsers need the
RSDP cache), in `kernel/core/boot_bringup.cpp`:

```
DmarInit();        DmarSelfTest();        // Intel: parse DMAR
VtdInit();         VtdSelfTest();         // Intel: decode capability registers
VtdPagingInit();   VtdPagingSelfTest();   // Intel: build identity page tables
IvrsInit();        IvrsSelfTest();        // AMD: parse IVRS
// then, only if IommuEnableEffective():
IommuEnableAtBoot();                      // flip translation on
```

Each `*SelfTest()` runs under `DUETOS_BOOT_SELFTEST` and emits a
`[<unit>-selftest] PASS` line; each parser logs `[<unit>] present=...` so the
boot log records what the firmware advertised. Most QEMU defaults and VirtualBox
report **no** IOMMU — add `-device intel-iommu` to exercise the VT-d path.

## Build Flags

The enable path is **OFF by default** — a regression in it would brick all
device DMA at boot. Operators opt in per build:

| Flag | Effect | Accessor |
|------|--------|----------|
| `DUETOS_IOMMU_ENABLE` | Allows `IommuEnableAtBoot` to flip translation on (still requires a discovered IOMMU) | `VtdEnableRequested()` / `IommuEnableEffective()` |
| `DUETOS_IOMMU_REQUIRE` | A failed `IommuEnableAtBoot` **panics** instead of silently leaving translation off — the deployment-safety gate release builds set so the kernel refuses to run without IOMMU protection | `IommuRequireEffective()` |

`IommuEnableEffective()` = `VtdEnableRequested() && IommuDetectedVendor() != None`.
The boot site, not the driver, is responsible for consulting these gates;
`VtdProgramAndEnable()` does **not** check the build flag itself.

## Key APIs and Types

### Vendor-neutral dispatcher — `kernel/drivers/iommu/iommu.h`

- `void IommuInit()` — runs the full Intel decode/paging chain + the AMD parse.
- `IommuVendor IommuDetectedVendor()` — `None` / `Intel` / `Amd` / `Both`.
- `Result<void> IommuEnableAtBoot()` — picks the vendor path; `Ok` when nothing
  to enable, `Unsupported` on AMD, otherwise the VT-d enable result.

### Intel DMAR parser — `kernel/drivers/iommu/dmar.h`

Walks the ACPI DMAR table (byte-walker in the Rust `duetos_dmar` crate; C++
owns the cache). Surfaces `DmarPresent()`, `DmarHostAddressWidth()` (HAW),
DRHD entries (`DmarDrhd`, each a distinct IOMMU MMIO base + segment), and RMRR
entries (`DmarRmrr`, regions any page tables **must** identity-map — legacy USB,
VGA hand-off).

### Intel VT-d register decode — `kernel/drivers/iommu/vtd.h`

`VtdInit()` maps each DRHD's MMIO window via `mm::MapMmio` and decodes the
Version / Capability / Extended-Capability registers into a typed
`VtdIommuInfo` (SAGAW mask, MGAW, fault-record layout, caching mode,
queued-invalidation / interrupt-remap / pass-through / snoop-control support,
etc.). Slice 27b is **read-only** — no control bits written.

### Intel VT-d page tables — `kernel/drivers/iommu/vtd_paging.h`

`VtdPagingInit()` allocates a root table, a single shared context table, and a
shared second-level page-table tree that **identity-maps** physical memory 1:1
(IOVA == phys). Identity passthrough is the conservative default that turns the
IOMMU on without breaking existing DMA: drivers keep handing devices physical
addresses and the IOMMU translates them to themselves. `VtdWalk(bus, dev, func,
iova)` is a software walk that simulates the hardware translation for tests.

- AGAW: 3-level (39-bit) only in v0 — the only AGAW QEMU's `intel-iommu`
  advertises. 4-level (48-bit) is a future slice.
- Memory cost: **12 KiB per IOMMU** (root + shared context + shared PDPT of
  512×1 GiB identity leaves). All 256 root entries share one context table.

### AMD IVRS parser — `kernel/drivers/iommu/ivrs.h`

Mirror of the DMAR parser for AMD. `IvrsInit()` walks the ACPI IVRS table
(Rust `duetos_ivrs` crate), surfacing `IvrsPresent()`, `IvrsInfo()` (the
IVinfo bitfield), IVHD entries (each an AMD-Vi IOMMU, with a cached EFR image
for extended types 0x11/0x40), and IVMD entries (must-identity-map regions,
AMD's analogue of RMRR).

## Threading & Locking Model

All IOMMU code runs **once, single-threaded, during boot bring-up**, before
SMP AP start and before the scheduler is online — so it takes no locks. The
cached parser/decoder state (`Dmar*`, `Vtd*`, `Ivrs*` getters) is read-only
after init; there is no IRQ handler and no runtime mutation path in v0. When
per-device contexts and runtime (un)mapping land, they will need a lock around
the context table and IOTLB invalidation — that lock does not exist yet because
no runtime mutator exists yet.

## Capability / Privilege Surface

The IOMMU is **not** reachable from userland and is gated by no `kCap*` bit — it
is pure kernel boot infrastructure with no syscall surface. Its security value
is structural: it constrains what physical memory a device (and therefore a
device driver, and therefore a malicious PE/ELF that reaches a driver) can reach
via DMA. See [Driver and Fault Domains](../security/Driver-Domains.md).

## Performance Notes

- One-time boot cost: a handful of ACPI-table reads, a few MMIO register reads
  per DRHD, and three 4 KiB frame allocations per IOMMU.
- With translation enabled, the hardware IOTLB caches translations; identity
  passthrough with 1 GiB super-pages keeps the page-walk depth at one level, so
  the steady-state DMA overhead is negligible. Per-device contexts (a later
  slice) trade some of that for isolation.

## Known Limits / GAPs / STUBs

These are design-deferred slices, not `// STUB:` / `// GAP:` markers — the v0
code is clean (no markers in `kernel/drivers/iommu/`), but the following are
explicitly out of scope for v0:

- **AMD-Vi enable is unimplemented.** Only IVRS parsing runs; register decode,
  page tables, and the enable flip are deferred (slices 28b/c/d, mirroring VT-d
  27b/c/d). `IommuEnableAtBoot()` returns `Unsupported` on AMD.
- **Identity passthrough only.** Every device shares one context that maps any
  IOVA to the same physical address. Per-device contexts (the real isolation
  win) are a later slice.
- **3-level (39-bit) AGAW only** for Intel. A 4-level fallback for IOMMUs that
  don't advertise 39-bit is future work.
- **No runtime (un)map / interrupt remapping.** v0 builds the tables once at
  boot and enables translation; there is no API to map/unmap an IOVA at runtime
  and interrupt remapping is decoded but not programmed.
- **Enable is OFF by default** (`DUETOS_IOMMU_ENABLE`), so on a default build the
  IOMMU is discovered, decoded, and self-tested but translation is not turned on.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `[dmar] present=0` / `[ivrs] present=0` under QEMU | No IOMMU emulated. Launch with `-device intel-iommu` (Intel) to exercise the VT-d path. |
| Device DMA breaks after enabling `DUETOS_IOMMU_ENABLE` | An RMRR/IVMD region the firmware requires wasn't identity-mapped, or the device needs a region outside the 0..512 GiB identity window. Check the `[vtd]`/`[dmar]` boot lines for the RMRR list. |
| Boot panics in `boot/iommu` | `DUETOS_IOMMU_REQUIRE` is set but `IommuEnableAtBoot` failed — read the preceding `[iommu]`/`[vtd]` lines for the failing step (map failed, `RTPS`/`TES` timeout, paging not built). |
| `VtdProgramAndEnable` returns `Timeout` | `GSTS.RTPS` or `GSTS.TES` didn't flip within the hardware bound — usually a wrong RTADDR or a register window mapped at the wrong offset. |

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [PCIe Enumeration](PCIe-Enumeration.md)
- [ACPI](../kernel/ACPI.md) — provides the DMAR / IVRS table addresses
- [Driver and Fault Domains](../security/Driver-Domains.md)
- [Intel ME / AMD PSP Mitigation](../security/ME-PSP-Mitigation.md)
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — the `duetos_dmar` / `duetos_ivrs` parser crates
