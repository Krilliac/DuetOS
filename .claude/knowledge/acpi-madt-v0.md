# ACPI MADT Discovery v0 — RSDP → XSDT/RSDT → APIC table

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel now walks ACPI static tables at boot. `AcpiInit` finds the
RSDP via the Multiboot2 tag stream, validates the v1 and (if present)
v2 checksums, follows the XSDT in preference to the RSDT, locates the
MADT by its "APIC" signature, and caches the MADT entries we need to
bring up IOAPIC-routed device interrupts:

- the LAPIC base physical address (with MADT type-5 override applied
  when the firmware provides one),
- every IOAPIC record (id, MMIO base, GSI base),
- every ISA Interrupt Source Override (ISA IRQ → GSI + MPS flags).

Everything past MADT — FADT, MCFG, HPET, the DSDT/SSDT AML tables — is
deliberately deferred. Adding a generic "find table by signature"
dispatcher is trivial; adding an AML interpreter is not. We'll do the
latter only when we actually need something AML-encoded.

## Context

Applies to:

- `kernel/acpi/acpi.{h,cpp}` — the module itself
- `kernel/mm/multiboot2.h` — added RSDP tag types (14 = v1, 15 = v2)
- `kernel/core/main.cpp` — calls `AcpiInit(multiboot_info)` right after
  `PagingInit` and before `PicDisable`

Depends on the paging direct-map window (uses `mm::PhysToVirt` to
reach the ACPI tables; panics on any table outside the first 1 GiB of
physical RAM). Unblocks: IOAPIC driver + any subsequent device IRQ
routing, SMP AP bring-up (needs the per-CPU LAPIC entries from MADT),
the FADT/HPET consumers.

## Details

### RSDP acquisition

Multiboot2 GRUB passes the RSDP **embedded** in one of two tags:

- type 14 (`kMultibootTagAcpiOld`) — ACPI 1.0 RSDP, 20 bytes
- type 15 (`kMultibootTagAcpiNew`) — ACPI 2.0+ RSDP, 36 bytes

The tag payload is the RSDP bytes themselves — no pointer indirection
to chase. If both tags are present (some loaders ship both for
compatibility), we pick whichever we see first. Either works: the
revision byte inside the RSDP tells us which format we have, and the
extended fields only matter when `revision >= 2`.

No EBDA / low-1MiB fallback scan. GRUB always provides the tag; a
loader that doesn't is a misconfiguration we'd rather catch at boot
than paper over.

### Checksum validation

Two separate checksums for the RSDP:

1. **v1 checksum** — one byte, covering the first 20 bytes. Sum of all
   20 bytes (including the checksum byte itself) must be zero mod 256.
   Required on every RSDP, regardless of revision.
2. **v2 extended checksum** — one byte, covering the first `length`
   bytes (36 on typical v2). Only required when `revision >= 2`.

Every SDT (RSDT, XSDT, MADT, ...) has its own one-byte checksum in the
common header, covering the full `length` bytes. Validated the same way.

Checksum failure is a panic. The kernel cannot safely proceed with
corrupted firmware tables — wrong LAPIC address, missing IOAPIC entry,
or a bad ISA-override will manifest as "IRQs never deliver" or
"interrupts go to the wrong handler" with no obvious root cause. Loud
at boot is the right default.

### XSDT vs RSDT

On ACPI 2.0+ firmware the RSDP exposes both an XSDT and an RSDT. Both
typically list the same tables. We prefer the XSDT for two reasons:

1. 64-bit entry pointers — future-proof against tables placed above
   4 GiB (rare on small boards, common on servers).
2. On some firmware, RSDT is stale / partial (a v1 compatibility
   shim); XSDT is canonical.

Fall back to RSDT only when `revision < 2` or `xsdt_address == 0`.

### MADT parsing

MADT = "Multiple APIC Description Table", signature `"APIC"` (yes,
confusingly the on-disk signature is `APIC` but every doc calls it
MADT). Structure:

```
[SdtHeader              | 36 bytes ]
[local_apic_addr u32    |  4 bytes ]
[flags u32              |  4 bytes ]
[entries ...            |         ]
```

Each entry starts with `{type, length}`. We handle three:

| Type | Name | Purpose |
|------|------|---------|
| 1 | I/O APIC | I/O APIC record — `id`, MMIO `address`, `gsi_base` |
| 2 | Int Source Override | ISA IRQ → GSI remap + MPS polarity/trigger flags |
| 5 | LAPIC Address Override | Replaces the 32-bit LAPIC addr with a 64-bit one |

Type 0 (Processor Local APIC), type 4 (Local APIC NMI), and the others
are recognised but not cached — we don't need per-CPU info until SMP
AP bring-up, and the NMI routing can wait until we actually care about
watchdog NMIs.

### Interrupt source overrides

Crucial detail that's easy to miss: **do not** assume ISA IRQ N maps
to GSI N. On QEMU with its default q35 machine, ISA IRQ 0 (PIT) is
overridden to GSI 2, and some IRQs come with explicit polarity/trigger
flags. Routing the IOAPIC assuming an identity map will send the
keyboard IRQ to the wrong pin, or deliver it with the wrong trigger
mode, and it just silently doesn't fire.

`IsaIrqToGsi(isa_irq)` returns the override target if present, else
`isa_irq` unchanged. `IsaIrqFlags(isa_irq)` returns the MPS-style
polarity/trigger bits the IOAPIC redirection entry needs:

- bits 0..1 polarity: `00` bus default, `01` high, `11` low
- bits 2..3 trigger: `00` bus default, `01` edge, `11` level

### Why AcpiInit runs *before* LapicInit

LapicInit reads the IA32_APIC_BASE MSR to find the LAPIC MMIO. The MSR
and MADT agree on every correctly-configured machine we've seen — but
the spec-mandated tiebreaker is MADT. Some legacy firmware relocates
the LAPIC and updates the MSR but leaves a stale MADT, or vice versa.
Reading both and asserting agreement (future: warning if they differ)
turns "mysterious IRQs to phantom addresses" into a boot-time panic.

For v0 we just cache the MADT value in `LocalApicAddress()` and let
LapicInit continue using the MSR; the cross-check comes when IOAPIC
bring-up lands and we actually route an IRQ.

### Boot-time output

A healthy boot on the default QEMU q35 machine prints something like:

```
[boot] Parsing ACPI tables.
[acpi] rsdp rev=0x2 lapic=0xFEE00000 ioapics=0x1 overrides=0x2
  ioapic[0x0] id=0x0 addr=0xFEC00000 gsi_base=0x0
  override[0x0] isa=0x0 gsi=0x2 flags=0x0
  override[0x1] isa=0x9 gsi=0x9 flags=0xD
```

Sanity:
- `rsdp rev=0x2` → ACPI 2.0+ (modern).
- `lapic=0xFEE00000` → LAPIC at the canonical address.
- `ioapics=0x1 … addr=0xFEC00000 gsi_base=0x0` → single IOAPIC covering
  GSIs 0..23 (the usual 24-pin IOAPIC on q35).
- Override ISA 0 → GSI 2 → the PIT-to-GSI-2 remap QEMU reports.
- Override ISA 9 flags 0xD → level-triggered, active low (typical for
  SCI).

### Regression canaries

- **`[panic] acpi: no ACPI RSDP tag in Multiboot2 info`** — GRUB not
  providing the tag. Check `boot/grub/grub.cfg` and that we're booting
  via GRUB's Multiboot2 path, not the older Multiboot1.
- **`RSDP v1 checksum failed`** — RSDP bytes got truncated or the
  Multiboot2 parser walked off the end of the tag. Check
  `sizeof(MbAcpiTag)` hasn't drifted and we're adding it, not the full
  tag size, to reach the RSDP payload.
- **`MADT checksum failed`** on real hardware — either corrupt
  firmware (rare) or we've dereferenced the wrong physical address.
  Cross-check by logging `madt_hdr` and comparing to the XSDT entry.
- **IOAPIC `addr=0x0` or `gsi_base` obviously wrong** — MADT entry
  layout drifted, or the walker advanced by the wrong step size. The
  MADT entry `length` field is authoritative; always advance by
  `h->length`, never by `sizeof(SpecificEntry)`.
- **No interrupt source overrides printed on q35** → we skipped the
  override case in the switch. Every modern QEMU reports at least one.

## Notes

- **No FADT / MCFG / HPET yet.** FADT tells us the SMI port, reset
  register, and PM timer. MCFG gives the PCIe ECAM base. HPET is the
  high-precision timer. Each is ~30 lines of parsing; add them when a
  consumer shows up.
- **No AML.** No DSDT, no SSDT, no _PRT for PCI interrupt routing.
  PCI IRQ routing will need _PRT evaluation to work on bare metal;
  QEMU q35 has a simple enough topology that we can bypass it with a
  hardcoded map for v0. Long-term: bite the bullet and integrate an
  AML interpreter (we may end up writing our own — ACPICA's license is
  fine but it's a heavy dependency to vendor).
- **Fixed-capacity caches.** `kMaxIoapics = 4`, `kMaxInterruptOverrides
  = 16`. Generous for any board we'd reasonably run on; panics
  loudly if exceeded. A machine with more is either an exotic server
  (grow the arrays) or a malformed MADT (fix the firmware).
- **Not thread-safe.** AcpiInit runs once from `kernel_main` and the
  getters are read-only after; no locking required today. SMP AP
  bring-up will read from multiple CPUs — still safe because
  post-init the data is immutable, but the annotation story will need
  to say so explicitly.
- **Out-of-direct-map handling.** Any ACPI table above 1 GiB physical
  will panic via `PhysToVirt`. The fix is to `MapMmio` the table's
  page range on demand — straightforward, deferred until we actually
  see a machine that places tables up there.
- **See also:**
  - [paging-v0.md](paging-v0.md) — provides `PhysToVirt` for reaching
    ACPI tables in the direct map and `MapMmio` for the eventual
    IOAPIC MMIO mapping.
  - [lapic-timer-v0.md](lapic-timer-v0.md) — LapicInit currently
    trusts the MSR; the MADT cross-check lands with IOAPIC bring-up.
