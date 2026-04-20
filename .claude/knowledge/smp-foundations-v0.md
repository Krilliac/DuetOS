# SMP Foundations v0 — Spinlocks + Per-CPU Data

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

Two primitives that every SMP-related refactor after this point will
depend on:

1. **Spinlock** (`kernel/sync/spinlock.{h,cpp}`) — test-and-set
   via `xchg`, with interrupt save/restore baked in. RAII guard +
   manual acquire/release. Owner-CPU tracking for panic-on-misuse.
2. **Per-CPU data** (`kernel/cpu/percpu.{h,cpp}`) — a `PerCpu`
   struct (cpu_id, lapic_id, current_task, need_resched, padding).
   The pointer lives in `IA32_GS_BASE` MSR, so any CPU reads its own
   region with an MSR read. BSP's struct installed before
   `SchedInit`; AP structs come with AP bring-up.

**No scheduler refactor yet.** `g_current` and `g_need_resched` in
`sched.cpp` stay global for now. The point of this slice is to have
the primitives ready so AP bring-up is a focused follow-up, not a
megacommit that also changes every piece of scheduler state.

Boot-time self-test round-trips the spinlock (acquire/release,
guard scope, `SpinLockAssertHeld`) and panics on any misuse. Verified
on QEMU q35 with the BSP.

## Context

Applies to:

- `kernel/sync/spinlock.{h,cpp}` — the primitive itself
- `kernel/cpu/percpu.{h,cpp}` — per-CPU data + GSBASE access
- `kernel/core/main.cpp` — calls `PerCpuInitBsp()` after `IoApicInit`
  and `SpinLockSelfTest()` right after

Depends on the LAPIC (BSP reads its APIC ID). Unblocks: SMP AP
bring-up, per-CPU runqueues, SMP-safe refactor of the scheduler
+ heap + wait queues.

## Details

### Spinlock ABI

```cpp
struct SpinLock { volatile u32 locked; volatile u32 owner_cpu; };

IrqFlags SpinLockAcquire(SpinLock&);          // save RFLAGS, CLI, xchg-loop
void SpinLockRelease(SpinLock&, IrqFlags);    // unlock, restore IF
SpinLockGuard guard(lock);                    // RAII
```

`IrqFlags` is the opaque save-restore token returned by Acquire.
Mixing tokens across locks corrupts IF — hence the `[[nodiscard]]`
on Acquire and the non-copy/non-move guard.

### Interrupt-state preservation

Every Acquire reads the current RFLAGS BEFORE `cli`. If the caller
already had interrupts disabled (nested acquire, or acquire from IRQ
context), Release sees `IF = 0` in the saved flags and does NOT
re-enable. If the caller had IF=1, Release calls `sti`.

```
                    [caller enters]
                    IF was either 0 or 1
Acquire: read RFLAGS     ─> captures original IF state
         cli               ─> safe to enter critical section
         xchg loop         ─> busy-wait for lock
                    [critical section]
Release: unlock
         if saved_IF=1: sti
         else:         leave IF=0   (preserves nested caller's state)
```

### Release-side assertions

`SpinLockRelease` panics if:
- The lock isn't held (double-release / never acquired).
- The lock is held, but by a different CPU (foreign unlock —
  catastrophic SMP bug waiting to happen).

Release sets `owner_cpu = 0xFFFFFFFF` BEFORE clearing `locked`. The
compiler fence (`asm volatile("" ::: "memory")`) keeps the compiler
from reordering; the store to `locked` itself is the store-release
visible to other CPUs.

### Why xchg + pause loop

Pattern: `while (locked == 0 ? maybe-xchg : pause)`. Details:

1. Plain read checks the lock word without locking the bus. Cache
   coherence keeps the read fresh.
2. When the lock goes free, try `xchg` — atomic swap, returns the
   previous value. If prev was 0 we won; if prev was 1 somebody
   else beat us to it.
3. On lost race, back to the pause loop.

`pause` is a hint for the CPU's memory-ordering predictor that this
is a spin loop. Saves power, reduces mis-speculation cost. It's a
no-op on pre-Pentium-4 CPUs but we don't target those.

### Per-CPU data via GSBASE

Written with `wrmsr` to MSR `0xC0000101`. Read with `rdmsr` on the
same MSR (we don't use `rdgsbase` yet because gating on
CPUID.EBX.FSGSBASE adds complexity we don't need at v0).

For v0, `CurrentCpu()` issues a plain `rdmsr` every call. Once we're
on hot paths, switch to `rdgsbase` (one-instruction, no MSR round-
trip) behind a CPUID gate. Further: once the scheduler does swapgs
across ring transitions, access becomes `mov rax, gs:[offset]` —
single instruction, no MSR at all.

### `CurrentCpuIdOrBsp` fallback

`g_bsp_installed` guards against calling `CurrentCpu()` before
GSBASE is valid. Without the guard, the spinlock self-test (which
runs AFTER `PerCpuInitBsp`) would be fine, but any early-boot
spinlock use (hypothetically — we have none today) would
dereference 0 and triple-fault.

The fallback returns 0 = BSP for lock-owner tracking. Not strictly
necessary today (nothing acquires a lock before PerCpuInitBsp), but
cheap insurance and documents intent.

### BSP bring-up order

Explicit sequence in `kernel_main`:

```
IoApicInit()                     // LAPIC is already up; IOAPIC now too
PerCpuInitBsp()                  // reads LAPIC ID → per-CPU struct → GSBASE
SpinLockSelfTest()               // now CurrentCpu() is valid
TimerInit()                      // timer IRQ will soon increment g_ticks
SchedInit()                      // the boot task is attached to BSP's PerCpu
```

Not yet: SchedInit does not consult `CurrentCpu()->current_task` —
`g_current` in sched.cpp is still the source of truth. AP bring-up
will migrate that pointer into PerCpu.

### Regression canaries

- **`[panic] sync/spinlock: SpinLockRelease on unheld lock`**: a
  caller is double-releasing, or never acquired. `SpinLockAssertHeld`
  at the top of suspect functions localises.
- **`[panic] sync/spinlock: SpinLockRelease by wrong CPU`**:
  someone migrated tasks across CPUs while holding a lock. At v0
  this can't happen (single CPU); when it can, the bug is that
  acquire+release straddled a context switch between cores.
- **`[cpu] BSP PerCpu installed` line missing or shows lapic_id=0
  when we expected non-zero**: LAPIC ID register read before LAPIC
  MMIO was mapped. Check PerCpuInitBsp runs after LapicInit.
- **Spinlock self-test hangs**: the CLI path isn't actually saving
  IF, so Release is unconditionally turning IF back on, and a
  subsequent interrupt clobbers something. Trace with `-d int` in
  QEMU.

## Notes

- **Not recursive.** A CPU that re-acquires the same lock it already
  holds will deadlock forever (the busy-loop on `locked != 0` never
  ends because only the current CPU could clear it and it's spinning
  in the wait loop). Don't add recursion — fix the design.
- **No lockdep.** We don't track lock ordering, deadlock cycles, or
  ABBA patterns. When a second kernel lock lands, add a simple
  "acquire order" integer per lock + debug-only cycle check.
- **No MCS / ticket lock.** Test-and-set is fine while contention is
  low. With 2-4 CPUs it's close to optimal; with 16+ it cache-line
  ping-pongs. Upgrade when profiles demand.
- **GSBASE is not swapped on ring transitions yet** — no ring 3
  today. When userland lands, syscall entry will `swapgs` to get to
  the kernel GSBASE; user processes see a different GSBASE
  (traditionally the TLS base).
- **See also:**
  - `design-decisions-log.md` entry 017 (this slice).
  - `scheduler-v0.md` + `sched-blocking-primitives-v0.md` — future
    targets of the SMP refactor.
  - `lapic-timer-v0.md` — BSP LAPIC ID read here relies on LAPIC MMIO.
