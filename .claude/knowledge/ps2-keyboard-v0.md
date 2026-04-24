# PS/2 Keyboard Driver v0 — First End-to-End IRQ Path

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

First real device driver, chosen deliberately as the smallest viable
closure of the full IRQ-driven pipeline: ACPI (MADT IRQ override) →
IOAPIC (redirection entry) → IDT (stub isr_33) → TrapDispatch (IRQ
path) → per-vector handler → ring buffer → WaitQueueWakeOne →
Schedule → reader task resumes. If every link in that chain works,
typing in QEMU produces `[kbd] char='X'` lines on the serial console
(or `[kbd] scan=0xNN` if a consumer asks for raw bytes via the lower-
level API).

Two levels of access are exposed:
- `Ps2KeyboardRead()` — raw scan code bytes, lossless.
- `Ps2KeyboardReadChar()` — US QWERTY scan code set 1 → ASCII
  translation with LShift / RShift / Caps Lock tracking. Consumes
  modifier transitions, releases, and 0xE0-prefixed extended keys
  internally; only returns on a real printable press.

Still not a finished keyboard subsystem — no aux (mouse) channel,
no typematic configuration, no Ctrl / Alt / Meta chord reporting,
no KeyEvent stream with modifier bitmaps, no alternate layouts.

## Context

Applies to:

- `kernel/drivers/input/ps2kbd.{h,cpp}` — the driver itself
- `kernel/core/main.cpp` — calls `Ps2KeyboardInit()` after `SchedInit`
  and spawns a `kbd-reader` kernel thread that prints each scan code
- `kernel/arch/x86_64/exceptions.S` — provides the `isr_33` stub (IRQ
  vector 0x21 = ISA IRQ 1 + offset 0x20)

Depends on the ACPI MADT cache (`IsaIrqToGsi(1)`), the IOAPIC driver
(routes GSI → vector), the IDT (handler install), the trap dispatcher
(IRQ dispatch), and the scheduler's wait queues. Unblocks: anything
that needs an interactive input source — the shell, debug consoles,
eventually the compositor.

## Details

### 8042 interface, minimal slice

Two I/O ports:

- `0x60` — data (read scan code byte)
- `0x64` — status (bit 0 = output buffer full, data waiting)

We don't reset the controller, don't disable/re-enable channels, don't
set the scan code translation mode. QEMU's firmware leaves it in scan
code set 1 with translation on; typical BIOS/UEFI does the same. A
real 8042 init sequence is ~40 lines and lands when we hit a board
that ships the controller in a weird state.

The IRQ handler drains the output buffer in a loop:

```cpp
while ((Inb(0x64) & 1) != 0) {
    byte = Inb(0x60);
    push_to_ring(byte);
}
```

A single keypress can produce 1..3 bytes (make code + break code + E0
prefix for extended keys), and key-repeat can stack multiple presses
before the next IRQ. Draining inside the handler keeps IRQs from
backlogging.

### Ring buffer, single-producer-single-consumer

Power-of-two size (64 bytes), head + tail advance monotonically and
are masked on access. No atomics needed:

- Producer runs in IRQ context at IF=0; consumer runs in task context
  and only blocks under `arch::Cli`. They cannot interleave.
- 64-bit writes on x86_64 are atomic for naturally-aligned addresses.

Overflow policy: drop **oldest** byte (advance tail past one entry,
then push). Dropping newest would lose key-release bytes after a
press, turning a stuck-key bug from "you see the press" into "the key
stays down forever" — worse outcome. `bytes_dropped` is tracked in
stats for observability.

### Wait-queue wake path

IRQ handler ends with:

```cpp
duetos::sched::WaitQueueWakeOne(&g_readers);
```

which sets `need_resched` on the woken task's behalf. The IRQ
dispatcher in `traps.cpp` calls `Schedule()` after EOI when
`TakeNeedResched()` returns true. Net effect: the reader thread is
running by the time the IRQ returns, in typical boot where the
reader is the only parked task.

### Reader blocking pattern

```cpp
arch::Cli();
while (head == tail) WaitQueueBlock(&g_readers);
byte = ring[tail++ & mask];
arch::Sti();
```

The `while` (not `if`) guards against the possibility of spurious
wakes once future callers reuse the queue — good defensive habit
even though today's only waker is the IRQ that also pushed a byte.
CLI is held across the check-and-block to close the race: if we
checked `head == tail` with interrupts on, an IRQ could push a byte
AND wake the queue before we enqueue on it — our own `WaitQueueBlock`
would then park us waiting for a wake that already happened.

### Route destination — BSP LAPIC ID

We read the current LAPIC ID at init time:

```cpp
u8 bsp_id = LapicRead(kLapicRegId) >> 24;
IoApicRoute(gsi, 0x21, bsp_id, /*isa_irq*/ 1);
```

For v0 every device IRQ targets CPU 0. SMP work will introduce per-IRQ
affinity, potentially with IRQ steering based on load.

### Draining at init

Before arming the IOAPIC route, we drain any bytes the 8042 has
latched from boot-time key presses (e.g. arrow-key navigation in the
GRUB menu):

```cpp
while ((Inb(0x64) & 1) != 0) (void)Inb(0x60);
```

Without this drain, unmasking would immediately fire one stale IRQ —
harmless, but the log gets noisy with a `[kbd] scan=...` for each
byte the user pressed during GRUB.

### Regression canaries

- **No IRQs seen** (`Ps2KeyboardStats().irqs_seen == 0` after key
  presses): route didn't land. Check `gsi = IsaIrqToGsi(1)` matches
  the IOAPIC's range, APIC destination ID matches the BSP, mask bit
  is cleared in the redirection entry.
- **IRQs seen but no bytes**: IRQ path works but we're reading from
  the wrong port, or the 8042 is outputting bytes before the handler
  reads them (spurious IRQ with empty output buffer is allowed).
  Trace: log `Inb(0x64)` inside the handler.
- **Exactly one scan code, then nothing**: EOI ordering regression
  (see `scheduler-v0.md`). LAPIC in-service bit stuck; no further
  IRQ1 delivered.
- **`bytes_dropped` grows monotonically during normal typing**:
  reader thread never runs, or runs too slowly. Check scheduler
  stats — the reader should be consuming one byte per IRQ on
  average.
- **Scan code 0x00 printed repeatedly at boot**: firmware left a
  sentinel byte. Drain pass in `Ps2KeyboardInit` should absorb it;
  if not, increase the drain loop to drain-and-wait.

## Notes

- **Scan code set not validated.** We return raw bytes. A future
  input-translation layer needs to know whether the controller is in
  set 1 or set 2 (and whether translation to set 1 is enabled in the
  8042). Set 1 + translation is the x86 default; set 2 is the wire
  encoding. Once we have a keymap, query the controller (command 0xF0
  / 0 on port 0x60) and either set it explicitly or handle both.
- **No aux channel.** PS/2 mouse is the aux channel of the same
  controller. Adding it requires enabling the aux clock line (0xA8 on
  port 0x64), a separate ring buffer, a separate wait queue, and
  handling the "byte belongs to mouse" case (status bit 5). Separate
  commit when a mouse-using feature needs it.
- **Single reader.** Two threads simultaneously in `Ps2KeyboardRead`
  would race: after one is woken, the other's check of `head == tail`
  might see the byte already consumed, double-decrement, etc. Not
  broken today because the boot has exactly one `kbd-reader` task.
  Fix when a multi-reader use case shows up.
- **No USB HID path.** Modern machines don't have PS/2. QEMU
  emulates it for convenience. Real-hardware support requires USB
  stack + HID class driver — Track 6. This driver stays for VMs and
  as a fallback; USB-HID becomes the primary input on bare metal.
- **See also:**
  - [ioapic-v0.md](ioapic-v0.md) — provides the routing primitive.
  - [acpi-madt-v0.md](acpi-madt-v0.md) — provides
    `IsaIrqToGsi`.
  - [sched-blocking-primitives-v0.md](sched-blocking-primitives-v0.md)
    — the wait-queue machinery.
