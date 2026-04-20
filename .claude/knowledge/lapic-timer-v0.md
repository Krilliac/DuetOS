# LAPIC + Periodic Timer v0 — PIT-calibrated 100 Hz Tick

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel now has a working hardware-IRQ path. The legacy 8259 PIC is
remapped to vectors 0x20..0x2F and fully masked, the BSP's LAPIC is
detected via CPUID, its MMIO window is mapped (cache-disabled) into the
kernel MMIO arena, and the LAPIC timer is calibrated against PIT
channel 2 and armed in periodic mode at 100 Hz on vector 0x20.
`kernel_main` ends in `IdleLoop()` (sti + hlt), and the boot log shows
the heartbeat `[timer] tick=…` line every second.

## Context

Applies to:

- `kernel/arch/x86_64/exceptions.S` — IRQ stubs for vectors 32..47 plus
  a dedicated `isr_spurious` for vector 0xFF
- `kernel/arch/x86_64/idt.{h,cpp}` — extended to install the 16 IRQ
  gates and exposes `IdtSetGate` for late vectors
- `kernel/arch/x86_64/traps.{h,cpp}` — `TrapDispatch` no longer
  `[[noreturn]]`; routes vector ≥ 32 to a per-vector `IrqHandler` table,
  EOIs the LAPIC, returns through `iretq`. New `IrqInstall`.
- `kernel/arch/x86_64/cpu.h` — adds `IdleLoop` (the `sti; hlt` loop, the
  intentional counterpart to `Halt`'s `cli; hlt`)
- `kernel/arch/x86_64/pic.{h,cpp}` — `PicDisable`
- `kernel/arch/x86_64/lapic.{h,cpp}` — `LapicInit`, `LapicEoi`,
  `LapicRead`, `LapicWrite`
- `kernel/arch/x86_64/timer.{h,cpp}` — `TimerInit`, `TimerTicks`

Boot order is now:

```
Serial → GDT → IDT → FrameAllocatorInit → KernelHeapInit →
PagingInit → PicDisable → LapicInit → TimerInit → IdleLoop
```

## Details

### 8259 disable (`pic.cpp`)

Even though we never use the 8259 again, it gets the standard ICW1..ICW4
init sequence. Two reasons:

1. The default vector base (0x08..0x0F master, 0x70..0x77 slave) collides
   with CPU exception vectors. A stray IRQ during early bring-up — before
   the chip is masked — would land on `#DF` or similar and look like a
   real fault. Remapping master to 0x20..0x27 and slave to 0x28..0x2F
   matches the IRQ stubs we just wired into the IDT.
2. After remap, OCW1 writes `0xFF` to both data ports, masking every
   line. From this point only the LAPIC delivers interrupts.

### LAPIC bring-up (`lapic.cpp`)

1. CPUID leaf 1, EDX bit 9 confirms the LAPIC is present.
2. Read `IA32_APIC_BASE` (MSR `0x1B`) for the MMIO physical base. Default
   is `0xFEE00000`; firmware can relocate, so trust the MSR. Bits 12..51
   are the base; bit 11 is the global enable (set if not already).
3. `MapMmio(base_phys, 4 KiB)` returns a kernel virtual pointer with
   `PCD=1`. Cached MMIO would silently lose every register write.
4. Install `isr_spurious` (defined in `exceptions.S`) at vector `0xFF`
   via `IdtSetGate`.
5. `TPR = 0` (accept all priority classes).
6. `SVR = software-enable | 0xFF` enables the LAPIC and sets the spurious
   vector. The low 4 bits of the SVR's vector field are hard-wired to 1
   on most CPUs, hence the conventional 0xFF.

### LAPIC register access pattern

LAPIC registers are 32 bits each but are spaced 16 bytes apart in the
MMIO window — only the 32-bit at offset N is meaningful, the next 12 bytes
are reserved. The accessor uses `g_lapic_mmio[reg / 4]` so callers pass
the SDM-documented byte offset (`kLapicRegEoi = 0x0B0`) and the divide-
by-4 turns it into a `u32` index. Don't change the pattern; matching the
SDM offsets makes register lookups debuggable against the manual.

`g_lapic_mmio` is `volatile u32*` — for MMIO, volatile is the *correct*
qualifier (the hardware is the other reader/writer), unlike for the tick
counter where I dropped it.

### Spurious vector EOI exception

Per Intel SDM, the CPU does NOT advance the In-Service Register (ISR)
when delivering the spurious vector. If the dispatcher EOIs anyway, the
EOI is consumed by whatever interrupt is currently in service —
acknowledging that one and silently losing it. The dispatcher checks
explicitly:

```cpp
if (frame->vector != kSpuriousVector)
{
    LapicEoi();
}
```

Forgetting this is a classic "weird intermittent IRQ loss" bug.

### PIT calibration (`timer.cpp::CalibrateLapicTimer`)

Sequence:

1. Enable PIT channel 2 gate, disable speaker (port `0x61`, bits 0/1).
2. Program channel 2 in mode 0 (interrupt-on-terminal-count): control
   byte `0xB0` to port `0x43`.
3. Configure the LAPIC timer divider (`/16`) and mask the LVT entry — we
   want it counting but not raising IRQs during calibration.
4. Write the PIT count low+high to port `0x42`. This commits the count
   and starts channel 2.
5. Immediately write `0xFFFFFFFF` to the LAPIC initial-count register —
   this starts the LAPIC timer counting down. The window between PIT-go
   and LAPIC-go is one I/O write of latency (sub-microsecond on QEMU).
6. Spin on port `0x61` bit 5 (OUT2) waiting for it to go high. In mode 0
   this fires when the channel reaches its terminal count.
7. Read the LAPIC current-count register, then re-mask the LVT timer.
8. `lapic_ticks_per_10ms = 0xFFFFFFFF - residual`.

The 10 ms calibration window:

- Long enough to be insensitive to a few hundred nanoseconds of
  PIT-vs-LAPIC start skew.
- Short enough to leave headroom in the 32-bit count (would need a
  ~429 GHz LAPIC bus to overflow at this divisor).
- Adds a fixed 10 ms to boot, which is invisible.

### Periodic mode arming

After calibration:

```cpp
LapicWrite(kLapicRegTimerDivide, 0x3);                       // /16
LapicWrite(kLapicRegLvtTimer, kLvtTimerPeriodicBit | 0x20);  // periodic, vec 0x20
LapicWrite(kLapicRegTimerInit, ticks_per_kernel_tick);       // start
```

Writing `TimerInit` is what starts the timer counting; it then both
raises an IRQ on each underflow and reloads from `TimerInit` for the
next period. `IrqInstall(0x20, TimerHandler)` MUST happen before this
write, otherwise the very first tick lands on a null handler.

### Tick counter (`g_ticks`)

Plain `u64`, not `volatile` and not atomic. Single-CPU world: the IRQ
handler runs on the same core as any reader, and 8-byte loads are atomic
on x86_64. SMP bring-up will swap to `__atomic_fetch_add` and the read
accessor becomes an acquire load. Documented in source.

The handler emits a `[timer] tick=…` line every `kTickFrequencyHz` ticks
(once per second at 100 Hz) so the boot log proves the IRQ path is
alive. Drop this once a real periodic workload exists.

### IRQ dispatch path

`isr_common` already builds the `TrapFrame` and calls `TrapDispatch`.
The change: `TrapDispatch` is no longer `[[noreturn]]`. For
`vector ∈ [32, 48) ∪ {0xFF}`, it consults `g_irq_handlers[slot]` (16
slots for IRQs + 1 for spurious), runs the handler, EOIs (except for
spurious), and returns. `isr_common`'s pre-existing iretq path then
restores the interrupted context.

The previous "halt on every TrapDispatch entry" was correct when the
table only held exception vectors. Now that IRQs share the path, the
exception branch keeps the halt; only the IRQ branch returns.

### Verified boot output (QEMU q35, 512 MiB)

```
[boot] Bringing up paging.
[mm] paging adopted boot PML4: cr3_phys=0x0000000000110000 pml4_virt=0xFFFFFFFF80110000
[mm] paging self-test
  alias A    : 0xFFFFFFFFC0000000
  alias B    : 0xFFFFFFFFC0001000
  tables     : 0x0000000000000003 mappings_installed=0x0000000000000002 removed=0x0000000000000002
[mm] paging self-test OK
[boot] Disabling 8259 PIC.
[pic] 8259 remapped (0x20..0x2F) and fully masked
[boot] Bringing up LAPIC.
[lapic] base_phys=0x00000000FEE00000 mmio=0xFFFFFFFFC0002000 id=0x0000000000000000 version=0x0000000000050014
[boot] Bringing up periodic timer.
[timer] calibrated: lapic_ticks/10ms=0x0000000000XXXXXX ticks_per_kernel_tick=0x0000000000XXXXXX
[timer] periodic LAPIC timer armed at 0x0000000000000064 Hz on vector 0x0000000000000020
[boot] All subsystems online. Entering idle loop.
[timer] tick=0x0000000000000064
[timer] tick=0x00000000000000C8
[timer] tick=0x000000000000012C
...
```

(Build verified locally; QEMU smoke deferred until QEMU/grub-mkrescue
land on the dev host. The exact LAPIC tick count is host/CPU dependent.)

### How to verify after edits

```bash
cmake --build build/x86_64-debug
CUSTOMOS_TIMEOUT=10 tools/qemu/run.sh
```

Smoke checks:

- The first `[timer] tick=0x64` line proves: the LVT timer is configured
  in periodic mode, the IRQ stub is installed, the IRQ dispatcher
  routes 0x20 correctly, EOI clears the in-service bit, iretq returns
  to `IdleLoop`'s `hlt`, and the next IRQ wakes it again.
- `lapic_ticks/10ms` should be on the order of LAPIC bus clock / 16
  for 10 ms. On QEMU's default TSC, that's typically 10–20 million.

Canaries for "this regressed":

- Boot stops at `[boot] Bringing up periodic timer.` with no further
  output → calibration is hanging in `WaitPitTerminal`. PIT channel 2
  gate (port `0x61` bit 0) likely not enabled, or speaker bit 1 was set
  and is masking OUT2.
- Boot reaches `[timer] periodic LAPIC timer armed` then no ticks fire
  → either the LVT was written with the mask bit set, or `IdleLoop` is
  running with IF=0 (check that `IdleLoop`'s asm uses `sti; hlt`, not
  `cli; hlt`).
- One tick prints, then nothing → EOI is missing or wrong. The next IRQ
  is suppressed because the in-service bit for vector 0x20 is still set.
- `[irq] unhandled vector 0xFF` floods the log → the SVR was misconfig-
  ured (vector field doesn't have low 4 bits set, so 0xF0–0xFE actually
  fires) OR a real hardware spurious storm (very unlikely on QEMU).
- Triple-fault on the first tick → IRQ stub or `isr_common` is mis-
  aligned with `TrapFrame`. Use QEMU `-d int,cpu_reset` to confirm the
  vector and pre-fault state.

## Notes

- **xAPIC MMIO mode only.** x2APIC (MSR-based, no MMIO) is straight-
  forward to add and recommended on >256-thread systems. Defer until
  it matters.
- **No TSC-deadline mode.** TSC-deadline drops the divide register and
  uses an absolute deadline instead of a counter — lower jitter. Add
  when scheduling latency starts mattering.
- **One-shot calibration.** No re-cal on CPU frequency / power changes.
  For early bring-up this is fine; for a serious workload, recalibrate
  on P-state transitions or use HPET as a stable reference.
- **No IOAPIC yet.** Device IRQs (NIC, AHCI, USB, etc.) need IOAPIC
  routing. Lands with the first device driver that takes interrupts.
- **No SMP.** Only the BSP's LAPIC is brought up. AP timers will be
  per-CPU; the calibration code generalises trivially because each CPU
  has its own LAPIC bus clock.
- **The heartbeat print is debug-grade.** When the scheduler runs, the
  tick handler will increment a real time-of-day and run the runqueue —
  the log line goes away then.
- **`isr_spurious` outside `isr_stub_table`.** Vector 0xFF is the only
  one we install above the IRQ range, so extending the table to 256
  entries to hold one extra address would be wasteful. The pattern
  generalises if more sparse vectors land later (debug exceptions,
  syscall entry).
- **See also:**
  - [paging-v0.md](paging-v0.md) — supplies `MapMmio` for the LAPIC
    register window.
  - [gdt-idt-v0.md](gdt-idt-v0.md) — original IDT install. Now
    extended to 48 entries.
