# IOAPIC Driver v0 — MMIO Redirection Table + ACPI Override Routing

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The IOAPIC consumes the ACPI MADT cache, maps every IOAPIC's 4 KiB
MMIO window into the kernel MMIO arena, reads the VERSION register to
determine how many redirection entries it has, and masks all of them.
`IoApicRoute(gsi, vector, lapic_id, isa_irq)` writes a redirection
entry (honouring the MADT's polarity + trigger flags for ISA IRQs
that were overridden) and unmasks the pin. `IoApicMask` / `Unmask`
flip only the mask bit. One controller up today (q35 has a single
24-entry IOAPIC); up to `acpi::kMaxIoapics = 4` supported.

Self-test: write `0x1005A` (masked + vector 0x5A) to redirection
entry 0, read it back, check the low 16 bits round-trip, then
re-mask. Anything lost in the round-trip means the MMIO mapping is
cached (missing PCD) or pointing at the wrong physical address.

## Context

Applies to:

- `kernel/arch/x86_64/ioapic.{h,cpp}` — driver
- `kernel/core/main.cpp` — calls `IoApicInit()` right after `LapicInit()`
- `kernel/acpi/acpi.h` — read-only consumer of `IoApicCount()`,
  `IoApic(i)`, and `IsaIrqFlags(isa_irq)`

Depends on the LAPIC (routes deliver to it), the ACPI MADT cache
(where the IOAPIC MMIO address and ISA overrides live), and the paging
`MapMmio` arena (for the MMIO window). Unblocks: PS/2 keyboard, AHCI,
NVMe, every PCIe INTx-backed device — anything beyond the in-package
LAPIC timer.

## Details

### MMIO register layout (two registers visible to software)

| Offset | Name | Description |
|--------|------|-------------|
| `+0x00` | IOREGSEL | Write the *index* of the internal register to access |
| `+0x10` | IOWIN    | Read/write the *data* of the register selected by IOREGSEL |

Every internal register is addressed indirectly through this pair.
Writing sequence: `IOREGSEL = index; IOWIN = value`. Reading:
`IOREGSEL = index; value = IOWIN`. Concurrent callers would race on
the indirection — single-CPU today; future SMP will wrap every access
in a spinlock on the per-IOAPIC struct.

### Internal registers we touch

| Index | Name | Purpose |
|-------|------|---------|
| `0x00` | ID | APIC ID (unused here; trust the MADT) |
| `0x01` | VER | Bits 0..7 version, bits 16..23 MaxRedirEntry (redir_count - 1) |
| `0x10 + 2n` | REDTBL[n].lo | Vector + flags (mask, level, polarity, etc.) |
| `0x11 + 2n` | REDTBL[n].hi | Destination APIC ID (bits 24..31 of high u32 = bits 56..63 of 64-bit entry) |

Each redirection entry is 64 bits, split into two 32-bit registers
because IOREGSEL/IOWIN are 32-bit only. Writes must hit both halves.

### Redirection-entry format (low 32 bits)

| Bit | Field | Notes |
|-----|-------|-------|
| 0..7 | Vector | LAPIC vector this IRQ is delivered as |
| 8..10 | Delivery mode | 000 = fixed (what we use) |
| 11 | Dest mode | 0 = physical, 1 = logical |
| 12 | Delivery status | RO |
| 13 | Polarity | 0 = active-high, 1 = active-low |
| 14 | Remote IRR | RO (level-trig only) |
| 15 | Trigger | 0 = edge, 1 = level |
| 16 | Mask | 1 = pin masked, 0 = enabled |

High 32 bits: bits 24..31 hold the destination APIC ID when
`dest_mode = physical`.

### Write ordering — high half first, then low

`WriteRedir` writes the high half first so the low half (with the
mask bit) is the last thing touched. Rationale: during a rewrite,
the pin is "live pointing at a stale destination" for the window
between the two writes. If we wrote low first, a spurious IRQ on the
pin during the gap would route using the OLD high (old APIC ID /
destination). By writing high first we guarantee the destination is
up-to-date before vectors start flowing. Small thing, but exactly
the class of bug that never shows up in QEMU and occasionally shows
up on a real box under stress.

Additionally, `IoApicRoute` masks the pin explicitly before rewriting
and unmasks implicitly via the final low-half write. Two barriers
for the price of one — and the explicit mask ensures we're starting
from a known state even if we're re-routing an already-live pin.

### MPS flags decoding

MADT Interrupt Source Override entries carry 16 flag bits with the
MPS 1.4 encoding:

- bits 0..1 polarity: `00` conforms-to-bus (ISA = active-high by
  default), `01` active-high, `11` active-low.
- bits 2..3 trigger: `00` conforms-to-bus (ISA = edge by default),
  `01` edge, `11` level.

Values `10` are reserved. We only flip the bit if the firmware
explicitly said "active-low" / "level"; conforms-to-bus and
active-high-edge default paths fall through to 0.

For non-ISA callers, pass `isa_irq = 0xFF` to skip override decoding
and use bus-default (edge, active-high). PCIe INTx routing (through
AML _PRT) will need its own polarity handling when we get there —
the standard flags say level-triggered active-low for shared PCI
interrupts, but an AML interpreter is out of scope for v0.

### Mask-all at init

Every pin on every IOAPIC is masked before any handler is installed.
Rationale: spurious IRQs from partially-configured firmware. Some
chipsets occasionally fire pins left over from bootloader state,
some firmware leaves pins enabled pointing at bogus vectors. A stray
IRQ at boot delivered to an unregistered handler lands in the IRQ
dispatcher's "unhandled vector" branch, prints noise, and — because
we haven't EOI'd a phantom IRQ — potentially stalls the LAPIC. Mask
everything, let drivers explicitly route-and-unmask the pins they
own.

### Self-test round-trip

Writes `kRedirLowMask | 0x5A` to REDTBL[0], reads back, checks low
16 bits match. Only the low 16 bits are checked because bit 12
(delivery status) is read-only and may flip between read and write,
and we haven't written the high half with a real destination — it
stays zero and a read back of zero is fine.

Panic paths:
- `ACPI MADT reported zero IOAPICs` → MADT parse missed the IOAPIC
  entries, or the machine genuinely has none (shouldn't happen on
  any x86_64 since ~2002).
- `MapMmio failed for IOAPIC window` → MMIO arena exhausted (won't
  happen at boot with 512 MiB available), or the paging layer
  rejected the physical address.
- `IOAPIC redirection register round-trip failed` → MMIO caching is
  wrong (PCD must be set), or the IOREGSEL/IOWIN offsets are off.
  Check `kKernelMmio` in `paging.h` still includes `kPageCacheDisable`.
- `IoApicRoute: GSI outside any IOAPIC window` → caller passed a
  GSI we never saw in the MADT; check the IOAPIC list and the GSI
  base + `redir_count` ranges printed at init.

### Regression canaries

- **Keyboard IRQ fires at the wrong vector** → MPS flag decoding
  wrong; level vs edge got swapped. Log `acpi::IsaIrqFlags(1)` and
  compare to expected (usually 0x0 on q35 → bus default = edge/high).
- **Keyboard IRQ never fires** → routing sent to a `lapic_id` that
  isn't the currently-running BSP's APIC ID. Cross-check with
  `LapicRead(kLapicRegId) >> 24`.
- **After routing a pin, timer IRQ stops** → you clobbered timer
  LVT (in the LAPIC, not the IOAPIC) by accident. IOAPIC routes
  produce LAPIC-vector-equivalent IRQs; they DO NOT touch LAPIC LVT
  entries.
- **GSI route works on QEMU but not real hardware** → IOAPIC ID
  might need explicit programming via register 0x00 on some boards.
  v0 doesn't write the ID (trusts firmware); if a board ships with
  a conflicting ID, `IoApicWrite(io, kIoApicRegId, ...)` at init
  time is the fix.

## Notes

- **Single destination (BSP) today.** Every route targets the APIC
  ID of whatever CPU is running `IoApicInit` (we don't even read it
  yet — caller supplies `lapic_id` and currently the only sensible
  value is `0` for BSP). SMP work will change this: per-IRQ
  affinity, IRQ steering, and IPI-based rebalancing.
- **No MSI / MSI-X.** MSI bypasses the IOAPIC entirely: the device
  writes its interrupt message to an address decoded by the LAPIC
  directly. PCIe devices should prefer MSI when available. The
  IOAPIC path is for legacy PCI INTx + chipset interrupts.
- **No spinlocks.** IOREGSEL/IOWIN are a classic shared-resource
  pair; concurrent accesses would corrupt each other. Not an issue
  today (single CPU, no pre-emption inside the two-step write on
  modern x86 because we're at IF=whatever the caller had, and
  Schedule doesn't run mid-write). SMP will need a per-IOAPIC
  spinlock.
- **No graceful teardown.** `UnmapMmio` exists but the driver never
  calls it — IOAPICs aren't hot-unpluggable and we never stop using
  them.
- **No PCI interrupt routing.** PCI devices have four INTA/B/C/D pins
  per slot, which get swizzled to GSIs by the chipset in a topology-
  dependent way. On QEMU q35 the mapping is basically known; on real
  boards we'd read the PCI IRQ routing table via AML (_PRT).
  Deferred until PCI enumeration starts needing it.
- **See also:**
  - [acpi-madt-v0.md](acpi-madt-v0.md) — provides the IOAPIC list
    and ISA flag overrides this driver consumes.
  - [lapic-timer-v0.md](lapic-timer-v0.md) — the LAPIC is the
    destination for every route; vectors here are vectors there.
  - [paging-v0.md](paging-v0.md) — `MapMmio` installs the
    `kKernelMmio` mapping with PCD set.
