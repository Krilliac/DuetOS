# Boot Verification v0 — End-to-End QEMU Boot

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

First end-to-end boot of the kernel in QEMU observed. `cmake --preset
x86_64-debug` + `cmake --build … --target duetos-iso` produces a
bootable ISO; `tools/qemu/run.sh` launches QEMU with `-machine q35
-cpu max -m 512M`, serial piped to stdio, `-d int,cpu_reset`, headless
display, and a configurable timeout.

Every self-test in the boot path passes. The kernel reaches
`IdleLoop` with three demo-mutex workers + a `kbd-reader` task
scheduled, timer ticks keep flowing after workers exit, and QEMU
terminates cleanly on the 20-second timeout with no triple fault.
This is the baseline we can regression-test against from now on.

## Context

Applies to:

- `tools/qemu/run.sh` — launcher script
- `boot/grub/grub.cfg` — Multiboot2 command entry
- Every file in `kernel/**` that runs in the boot path

Depends on: `qemu-system-x86_64`, `grub-mkrescue` (from `grub-pc-bin`),
`xorriso`, `mtools` — install with
`sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin xorriso mtools`.

## Details

### Expected boot log (baseline)

On a healthy boot the serial output contains, in order:

```
[boot] DuetOS kernel reached long mode.
[boot] Multiboot2 handoff verified.
[boot] Installing kernel GDT.
[boot] Installing IDT (vectors 0..31).
[boot] Parsing Multiboot2 memory map.
[mm] Multiboot2 memory map:
  base=0x0..0x9fc00 len=0x9fc00 type=available      <-- conventional memory
  base=0x9fc00..0xa0000 len=0x400 type=reserved     <-- EBDA
  base=0xf0000..0x100000 len=0x10000 type=reserved  <-- video BIOS
  base=0x100000..0x1ffdf000 len=... type=available  <-- main RAM
  base=0x1ffdf000..0x20000000 len=0x21000 type=reserved
  base=0xb0000000..0xc0000000 len=0x10000000 type=reserved  <-- PCIe MMCONFIG
  base=0xfed1c000..0xfed20000 len=0x4000 type=reserved
  base=0xfffc0000..0x100000000 len=0x40000 type=reserved
  base=0xfd00000000..0x10000000000 len=0x300000000 type=reserved
  total frames : 0x1ffdf
  free frames  : 0x1fec6                            <-- ~127 MiB usable of 128 MiB
[mm] frame allocator self-test OK
[mm] kernel heap online: pool=0x200000 base_virt=0xffffffff80119000 ...
[mm] kernel heap self-test OK
[mm] paging adopted boot PML4: cr3_phys=0x102000 ...
[mm] paging self-test OK
[acpi] rsdp rev=0x2 lapic=0xfee00000 ioapics=0x1 overrides=0x5
  ioapic[0x0] id=0x0 addr=0xfec00000 gsi_base=0x0
  override[0x0] isa=0x0 gsi=0x2 flags=0x0          <-- PIT remap (QEMU q35)
  override[0x1] isa=0x5 gsi=0x5 flags=0xd
  override[0x2] isa=0x9 gsi=0x9 flags=0xd          <-- SCI (level + active low)
  override[0x3] isa=0xa gsi=0xa flags=0xd
  override[0x4] isa=0xb gsi=0xb flags=0xd
[pic] 8259 remapped (0x20..0x2F) and fully masked
[lapic] base_phys=0xfee00000 mmio=0xffffffffc0002000 id=0x0 version=0x50014
[ioapic] mapped id=0x0 mmio=0xffffffffc0003000 ver=0x20 entries=0x18 gsi_base=0x0
[ioapic] init OK, 0x1 controller(s) online, all pins masked.
[timer] calibrated: lapic_ticks/10ms=0x99804 ...
[timer] periodic LAPIC timer armed at 0x64 Hz on vector 0x20
[sched] online; task 0 is "kboot"
[ps2kbd] routed isa_irq=0x1 gsi=0x1 vector=0x21 lapic_id=0x0
[sched] created task id=0x1 name="kbd-reader" ...
[sched] created task id=0x2 name="worker-A" ...
[sched] created task id=0x3 name="worker-B" ...
[sched] created task id=0x4 name="worker-C" ...
[boot] All subsystems online. Entering idle loop.
[sched] A i=0x0 counter=0x1
[sched] B i=0x0 counter=0x2
[sched] C i=0x0 counter=0x3
  ... (15 lines total, counter 0x1 through 0xf)
[sched] C i=0x4 counter=0xf
[timer] tick=0x64
[timer] tick=0xc8
  ... (forever, once per second at 100 Hz)
```

Key shape the log must match:

- `total_frames` + `free_frames` add up to the "available" ranges
  in the memory map minus kernel / bitmap / low 1 MiB.
- ACPI override for ISA 0 → GSI 2 (the famous PIT remap).
- LAPIC version `0x50014` — bit pattern Intel documents for
  xAPIC mode.
- IOAPIC `entries=0x18` (24) — q35's default.
- Timer calibration gives `~0x99804` (about 629,252 LAPIC ticks per
  10 ms, i.e. ~62.9 MHz APIC bus on QEMU's default CPU model).
- Counter goes `1 → 2 → 3 → ... → 15` with **no gaps**. A single gap
  means the mutex didn't serialise — race on `counter_before`.
- Timer ticks monotonically increase after workers exit — EOI
  ordering in `TrapDispatch` is correct (any regression here drops
  all ticks after the first context switch).

### ACPI RSDP rev 0 observed — GRUB only ships the v1 tag here

Boot log shows `rsdp rev=0x0` on QEMU q35 with the default SeaBIOS +
GRUB 2 stack. Investigation: GRUB's Multiboot2 implementation in this
environment only provides the type-14 (v1, 20-byte RSDP) tag, not the
type-15 (v2, 36-byte) tag. The v1 RSDP reports `revision = 0` and
only the 32-bit RSDT address, so we walk the RSDT, not the XSDT.

We fixed the tag walker to **prefer** type-15 when both tags are
present (see design-log entry 015) — but in this env only v1 is
shipped, so we still take the RSDT path. Functional: all five
interrupt-source overrides, the single IOAPIC, and the LAPIC base
all decode correctly from RSDT entries.

The fix still matters for two reasons:
1. GRUB versions that DO ship both tags would previously have picked
   the v1 one by accident, losing XSDT 64-bit pointers.
2. On machines where ACPI tables sit above 4 GiB, only the XSDT can
   describe them — a future port (or a bigger QEMU RAM config with
   `-m 8G`) may surface this.

### Regression gate: the self-tests ARE the boot test

The kernel's early boot is itself a regression test. Every phase
ends with a `[... self-test OK` or equivalent explicit "ready"
message. If a change makes any self-test panic, `tools/qemu/run.sh`
will print `[panic]` on stderr and the test fails visibly. Future
CI should diff the expected boot log shape against the actual.

### Regression canaries

- **Kernel doesn't reach `kernel_main`** (no `[boot] DuetOS
  kernel reached long mode.` line): boot.S / Multiboot2 / linker
  script issue. Check that the Multiboot2 header checksum still
  adds to zero, and that the kernel ELF's entrypoint is aligned
  correctly.
- **Hangs after `[mm] kernel heap online`**: paging self-test
  probably wrote into an MMIO arena that isn't actually mapped yet.
- **`[panic] acpi: RSDP v1 checksum failed`**: firmware table got
  relocated and the Multiboot2 info points into it — check our tag
  walker is adding `sizeof(MbAcpiTag)` (=8), not `sizeof(Rsdp)` or
  `sizeof(MultibootTagHeader)`.
- **Counter ends at less than 0x0F**: mutex regression — see
  `sched-blocking-primitives-v0.md`.
- **`qemu.log` shows triple-fault-and-reset loop**: enable
  `-d guest_errors` in `run.sh` to see which exception is firing in
  which handler and triple-faulting out.

## Notes

- **Headless-only for now.** `DUETOS_DISPLAY=gtk` switches to a
  graphical window; useful when we start rendering to a framebuffer.
- **No automated log diff yet.** The shape of the healthy log is
  documented here but not enforced. Cheap CI win: grep for `[panic]`
  in the boot output and fail on match.
- **OVMF not used.** The default GRUB path is BIOS-style SeaBIOS +
  GRUB i386-pc. Once we care about UEFI-direct boot (Track 2), add
  `-bios /usr/share/ovmf/OVMF.fd` and a UEFI GRUB module.
- **Timer tick printing adds noise.** The heartbeat
  `[timer] tick=0xNN` every second is useful as a liveness signal
  during boot bring-up. Gate it behind a compile-time flag once
  boot is stable enough that we trust it.
- **See also:**
  - `docs/knowledge/design-decisions-log.md` — entries 001..014
    cover every component exercised by this boot.
  - `tools/qemu/run.sh` — the launcher script itself.
