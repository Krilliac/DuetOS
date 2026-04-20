# USB xHCI + HID — Scope Estimate & Staged Plan

_Last updated: 2026-04-20_

## Why this doc exists

When the request "land USB HID so real-hardware keyboards work" came
up during the PS/2 keyboard session, we scoped it and deliberately
**deferred**. This doc explains why, what the actual work is, and
what stage gates we'd build toward when USB actually becomes the
critical path.

If you're reading this after USB has been prioritised and are asking
"where do I start?" — start with §Staged Plan below.

## Scope reality

A minimally viable USB HID keyboard stack requires **four** distinct
subsystems, each a nontrivial commit:

### 1) PCI enumeration (Track 6 prerequisite)

Before we can find the xHCI controller, we have to enumerate PCIe:

- MCFG table parse (extends our ACPI module — ~50 lines)
- ECAM (Enhanced Configuration Access Mechanism) access primitives —
  ~80 lines
- Bus/device/function scan with BAR allocation — ~200 lines
- Device class matching + probe dispatch — ~80 lines
- Design-decisions log entries for all of the above

**Estimate:** ~500 lines, one focused session.

### 2) xHCI host controller driver

The xHCI spec is ~700 pages. A "minimally functional" driver that
can enumerate USB 2.0 / 3.0 devices and configure endpoint 0 is:

- Controller reset + reset sequencing — ~80 lines
- Device context + input context structures — ~200 lines
- Command Ring + Transfer Ring setup — ~200 lines
- Event Ring + MSI-X interrupt handler — ~150 lines
- Port reset + speed detection — ~100 lines
- Slot enable + Address Device TRB — ~80 lines
- Endpoint 0 control transfers (GET_DESCRIPTOR dance) — ~120 lines
- Memory model (64-byte aligned contexts, DMA-safe buffers) — ~100
  lines
- Panic / diagnostic path for all the above — ~100 lines

**Estimate:** ~1000-1500 lines, likely 2-3 sessions if done carefully.

Worth calling out specifically:
- **64-bit DMA addressing** — need physical addresses for every
  descriptor ring pointer. The current kernel has a 1 GiB direct map
  and a bump-MMIO arena; neither is the right answer for
  "allocate 4 KiB aligned buffer we can hand to a device for DMA."
  We'll need either:
    - A DMA-friendly pool (contiguous frame ranges, mapped + cached +
      tracked).
    - An IOMMU (Intel VT-d / AMD-Vi) abstraction that remaps device
      DMA through page tables we control. Long-term correct answer;
      large lift.
- **MSI / MSI-X setup** — xHCI prefers MSI-X over legacy INTx. We
  have IOAPIC INTx but no MSI path. Adding MSI is ~100 lines and
  should land before xHCI (separate commit).

### 3) USB device-model + core

Even the simplest HID class driver needs:

- Device enumeration state machine (Attached → Powered → Default →
  Address → Configured) — ~150 lines
- Standard control transfer wrappers (GET_DESCRIPTOR, SET_ADDRESS,
  SET_CONFIGURATION, GET_CONFIGURATION) — ~100 lines
- Descriptor parser (device, configuration, interface, endpoint,
  HID) — ~150 lines
- Class driver binding — ~50 lines

**Estimate:** ~450 lines, one session.

### 4) HID class driver

- Boot protocol vs. report protocol selection — ~30 lines
- Report descriptor parser (full HID parser is ~500 lines; boot
  protocol keyboard is ~80 lines) — pick boot protocol for v0
- Interrupt endpoint polling — ~100 lines
- Translation from HID usage codes to an input event stream — ~80
  lines
- Integration with our existing `WaitQueue`-based input path — ~40
  lines

**Estimate:** ~350 lines (boot-protocol only), one session.

## Total estimate

- **Lines of code:** ~2300-2800 (PCI + xHCI + USB core + HID)
- **Sessions at our current pace:** 4-6 focused sessions
- **Prerequisites not yet in place:**
  - MSI / MSI-X support
  - DMA-safe memory allocator
  - PCI enumeration + BAR allocation
  - SMP (USB interrupts benefit from steering off CPU 0 onto a
    less-busy core)

## Why we deferred in the "continue" sequence

The PS/2 keyboard driver already closes the full IRQ-driven pipeline
(ACPI → IOAPIC → IDT → dispatcher → driver → wait-queue → scheduler)
end-to-end. It's functional on QEMU and on any emulated machine, and
it validated the plumbing we built in `acpi-madt-v0`, `ioapic-v0`,
and `sched-blocking-primitives-v0`.

USB HID is the **real-hardware follow-up** — needed for bare-metal
boots, but not unblocking anything in the VM boot loop where we're
doing current development. Work on it in earnest when one of:

1. We're ready to test on real hardware and have a USB-only target
   machine.
2. We want an input path that also exposes mice / touch / gamepads
   (HID covers all of these with the same stack).
3. We're bringing up PCIe enumeration anyway for storage (AHCI /
   NVMe) and can amortise the PCI work across both.

## Staged plan (when we come back to it)

**Commit 1 — PCI enumeration + MCFG parsing**
Delivers: every PCI device listed in boot log, can read BARs, can
set the bus-master / IO bits.
Depends on: ACPI MADT module (done); paging `MapMmio` (done).
Gate:  G1 (integration — enumerate on QEMU q35, print every device),
       G3 (operability — useful log format),
       G5 (doc — PCI enumeration knowledge file).

**Commit 2 — MSI / MSI-X support for PCIe devices**
Delivers: `PciDeviceEnableMsi(dev, vector, cpu)` analogous to
         `IoApicRoute`.
Depends on: Commit 1, IOAPIC driver (done).
Gate:  G1 (integration — test with a dummy device that asserts
       legacy and MSI and verify the latter wins).

**Commit 3 — DMA buffer pool**
Delivers: `DmaAlloc(size, alignment) → {virt, phys}` pair. Drops
         frame allocator `AllocateContiguousFrames` callers into
         this when they need DMA.
Depends on: frame allocator (done).
Gate:  G1, G4 (performance — we'll measure allocation latency).

**Commit 4 — xHCI controller + port reset**
Delivers: `[xhci] controller online, N ports ready` log line on
         boot, MSI-X IRQs wired, command ring responds to NO-OP.
Depends on: Commits 1-3.
Gate:  G1 + G3 + G5. Likely needs to be split into two if the
        trampoline gets messy.

**Commit 5 — USB device model**
Delivers: `[usb] device attached on port N class=0x03 (HID)` log
         line when a virtual HID keyboard is attached.
Depends on: Commit 4.
Gate:  G1 + G5.

**Commit 6 — HID boot-protocol keyboard class driver**
Delivers: HID keyboard produces the same `[kbd] scan=0xNN` stream
         the PS/2 driver does, over USB, through the same wait
         queue. A future input layer consumes from one queue either
         way.
Depends on: Commit 5.
Gate:  G1 + G3 + G5.

## Why this matters right now

The PS/2 driver we landed uses a device-agnostic wait-queue protocol
on the kernel side. When USB HID lands, it feeds bytes into the same
`WaitQueue` and the consumer (shell, compositor, init) doesn't need
to know which bus delivered the keystroke. Keeping the driver-to-
consumer interface stable across PS/2 → USB migration is the win
from deferring USB and building the simpler driver first.

## Revisit when

- Real-hardware boot becomes the target (Track 6 M-test on a real
  machine).
- AHCI / NVMe driver work starts (PCI enumeration is shared).
- USB-only target machine joins the testing matrix (most modern
  laptops).
- Mouse, gamepad, or external storage input becomes a required
  feature.

## See also

- `track-2-platform-foundation-implementation-plan.md` §3 (SMP /
  PCIe) and §4 (early diagnostics) — PCI enumeration context.
- `design-decisions-log.md` entries 014 (PS/2) + 015/016 (boot
  verified) — the `WaitQueue`-based input pipeline USB will plug
  into.
- `ioapic-v0.md` — the interrupt path that will need MSI added to
  it for PCIe devices.
