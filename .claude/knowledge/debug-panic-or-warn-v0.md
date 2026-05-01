# DebugPanicOrWarn — release-stable variant of Panic (v0)

**Last updated:** 2026-05-01
**Type:** Decision + Pattern
**Status:** Active — helper landed, ~10 call sites converted, migration is opportunistic

## What

`kernel/core/panic.h` exposes two new helpers next to the existing
`Panic` / `PanicWithValue`:

```cpp
[[gnu::cold]] void DebugPanicOrWarn(const char* subsystem, const char* message);
[[gnu::cold]] void DebugPanicOrWarnWithValue(const char* subsystem, const char* message, u64 value);
```

In a debug build (`DUETOS_BUILD_FLAVOR == 1`) they call straight
through to `Panic` / `PanicWithValue` — the CPU halts and emits a
full crash dump.

In a release build they emit a `LogLevel::Error` line through klog
and **return**. Same severity, same subsystem tag, same ring-buffer
capture for the post-mortem story; just no halt.

The flavor decision is a `if constexpr (kIsDebugBuild)` inside the
helper — both paths compile every build, but only one survives DCE.

## Why

Two complementary facts pushed this:

1. Many existing `core::Panic` sites are **caller-side invariant
   violations**, not corruption of kernel-owned state. Examples:
   - `KMutexRelease` by a non-owner;
   - `RwLockReleaseShared` on a lock with no readers;
   - `KSemaphoreRelease` that would overflow `max_count`;
   - `PciMsixSetEntry` with `index >= table_size`;
   - `SpinLockRelease` out-of-acquire-order (held-locks
     bookkeeping mismatch).
   For each, the *kernel's* invariants are still intact — only the
   caller has a bug. Halting the box for that bug throws away
   uptime that nothing in the v0 policy actually wants to throw
   away.

2. We already have all three sibling primitives:
   - `KASSERT` — always-on panic-on-false.
   - `DEBUG_ASSERT` — debug-only panic-on-false; release no-op.
   - `Panic` / `PanicWithValue` — unconditional halt.

   What was missing was the cell at "release: still report, don't
   halt". Adding `DebugPanicOrWarn` fills that cell without
   changing the meaning of the existing three.

## When to use which

| Situation | Primitive |
|-----------|-----------|
| Heap / frame-allocator / page-table corruption | `Panic` / `PanicWithValue` |
| Stack-canary mismatch (real overflow) | `Panic` / `PanicWithValue` |
| Boot-time fatal init (no clocksource, no LAPIC, ACPI parse fails, BAR unmappable) | `Panic` |
| Trap-frame state the kernel can't represent (kstack overflow) | `Panic` / `PanicWithValue` |
| Caller-side invariant violation, "do nothing" is safe recovery | `DebugPanicOrWarn` |
| Cheap inner-loop sanity check only worth running in debug | `DEBUG_ASSERT` |
| Always-on invariant, panic on false | `KASSERT` |
| Self-test inside `DUETOS_BOOT_SELFTEST(...)` block | `Panic` (the wrapper already release-skips the call) |

The "do nothing is safe" criterion is the bar to clear before
swapping a `Panic` for `DebugPanicOrWarn`. If the call site
half-mutated state before the panic, the conversion either has to
unwind that state first (e.g. `MutexUnlock` before
`DebugPanicOrWarn` + `return`) or stick with `Panic`.

## Initial conversion (2026-05-01)

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/sync/spinlock.cpp:108` (held-locks pop mismatch) | log; skip zeroing the wrong slot; pop count anyway |
| `kernel/sync/rwlock.cpp:50` (release-shared on no-readers) | unlock inner mutex; log; refuse the release |
| `kernel/sync/rwlock.cpp:81` (release-exclusive on no-writer) | unlock inner mutex; log; refuse the release |
| `kernel/ipc/kmutex.cpp:46` (destroy on still-held mutex) | log; leak the mutex (skip `KFree`) |
| `kernel/ipc/kmutex.cpp:88` (release by non-owner) | log; refuse the release |
| `kernel/ipc/kmutex.cpp:92` (release on already-released) | log; refuse the release |
| `kernel/ipc/ksemaphore.cpp:78` (release would overflow `max_count`) | log; refuse the release (mutex already dropped) |
| `kernel/drivers/pci/pci.cpp:283` (`PciMsixSetEntry` OOB index) | log + value; refuse the write |
| `kernel/drivers/pci/pci.cpp:315` (`PciMsixMaskEntry` OOB index) | log + value; refuse the write |
| `kernel/drivers/pci/pci.cpp:325` (`PciMsixUnmaskEntry` OOB index) | log + value; refuse the write |
| `kernel/drivers/pci/pci.cpp:336` (`PciMsixEnable` on non-MSI-X device) | log; refuse — driver can fall back |

## Third pass (2026-05-01) — thread-entry, kobject, spinlock contracts, MMIO mapping, SMP boot

20 more sites broken into five families:

### Ring-3 thread-entry invariants (debug-panic + release-SchedExit)

`Ring3ThreadEntry` and `LinuxCloneEntry` are
`[[noreturn]]`-tagged kernel-side trampolines that prepare ring-3
state and then `iretq` into user mode. The two preconditions they
panic on (`SchedCurrentKernelStackTop()` returning 0 and a null
descriptor pointer) are programming errors in the front-end.

The new shape pairs `DebugPanicOrWarn` with a follow-up
`sched::SchedExit()` (which is itself `[[noreturn]]`):

```cpp
if (kstack_top == 0)
{
    core::DebugPanicOrWarn("win32/thread", "...");
    if (arg != nullptr) mm::KFree(arg);  // dead code in debug
    sched::SchedExit();
}
```

Debug builds halt at the panic; release builds free the
heap-allocated descriptor (avoiding a per-call leak) and route
just this task to the reaper. The function's `[[noreturn]]`
contract holds in both flavors because exactly one of `Panic` or
`SchedExit` is reachable.

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/subsystems/win32/thread_syscall.cpp:48` (kstack_top==0) | KFree(arg); SchedExit |
| `kernel/subsystems/win32/thread_syscall.cpp:54` (arg==null) | SchedExit |
| `kernel/subsystems/linux/syscall_clone.cpp:84` (kstack_top==0) | KFree(arg); SchedExit |
| `kernel/subsystems/linux/syscall_clone.cpp:89` (arg==null) | SchedExit |

### KObject contract violations

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/ipc/kobject.cpp:69` (`KObjectInit` on null) | log; refuse |
| `kernel/ipc/kobject.cpp:73` (`KObjectInit` with `Invalid`) | log; refuse |
| `kernel/ipc/kobject.cpp:84` (`KObjectAcquire` on null) | log; refuse |
| `kernel/ipc/kobject.cpp:89` (acquire on dead object) | log; SpinLockGuard unwinds; refuse |
| `kernel/ipc/kobject.cpp:107` (release on dead object) | log; SpinLockGuard unwinds; refuse |

### Spinlock contract violations

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/sync/spinlock.cpp:170` (`Release` on unheld lock) | log; return without touching IRQ state or lock |
| `kernel/sync/spinlock.cpp:174` (`Release` by wrong CPU) | log; return without touching the rightful holder's view |
| `kernel/sync/spinlock.cpp:199` (`AssertHeld` on unheld) | log; return |
| `kernel/sync/spinlock.cpp:203` (`AssertHeld` on lock owned by another CPU) | log; return |

### Driver MMIO mapping failures

These were boot-fatal-on-this-driver but never boot-fatal for the
kernel as a whole — the affected device just becomes unusable.
Each file already had a parallel "no BAR" early-return path with
the same release shape; the conversions match it.

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/drivers/storage/nvme.cpp:938` (`MapMmio` failed for BAR0) | log; return — controller skipped |
| `kernel/drivers/storage/ahci.cpp:551` (`MapMmio` failed for HBA window) | log; return — controller skipped |
| `kernel/arch/x86_64/hpet.cpp:52` (`MapMmio` failed for HPET block) | log; leave g_mmio null; timekeeper falls back to LAPIC |
| `kernel/arch/x86_64/hpet.cpp:65` (32-bit HPET counter unsupported) | log; clear g_mmio; same LAPIC fallback path |

### SMP boot — degraded-mode fallback

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/arch/x86_64/smp.cpp:251` (trampoline image > 4 KiB) | log; return 0 — BSP runs uniprocessor |
| `kernel/arch/x86_64/smp.cpp:294` (KMalloc failed for AP PerCpu) | log; `continue` — skip this AP, try the next |
| `kernel/arch/x86_64/smp.cpp:328` (KMalloc failed for AP stack) | log; KFree the just-allocated PerCpu; `continue` |

These all predate fault-domain isolation, so the user-visible
recovery is "fewer cores online" — exactly what a hardware AP
no-show would already produce.

## Second pass (2026-05-01) — scheduler primitive contract violations

`PanicSched` was used for two different things: real boot-time
disasters (KMalloc-failed-for-Task, no-runnable-task) AND
caller-side contract violations on the kernel mutex / condvar
primitives. Only the second category is a candidate for the
release-soft helper; the first stays as `PanicSched` because
"continue with no Task struct" has no defined meaning.

| Site | Recovery shape in release |
|------|---------------------------|
| `kernel/sched/sched.cpp:2371` (`MutexUnlock` by non-owner) | re-enable IRQs; log; return without mutating m |
| `kernel/sched/sched.cpp:2417` (`CondvarWait` w/o companion mutex) | re-enable IRQs; log; return without enqueuing |
| `kernel/sched/sched.cpp:2477` (`CondvarWaitTimeout` w/o companion mutex) | re-enable IRQs; log; return false (timeout) |

The `arch::Sti()` before each return is load-bearing — the
contract-check sits between `arch::Cli()` and the normal SpinLockGuard
acquire, so leaving IRQs disabled would wedge the CPU.

The leak in `KMutexDestroy` is the only conversion that costs
*permanent* state. A one-time leak is recoverable; a
use-after-free of the still-held mutex is not, so the trade is
obvious.

## What was deliberately NOT converted

- **Self-tests** (every `*SelfTest()` panic in the inventory) —
  call sites are wrapped in `DUETOS_BOOT_SELFTEST(call)`, so the
  whole call is dead code in release. The internal `Panic` is
  reachable only when the test actually runs (debug + paranoid
  presets), which is exactly when we want it.
- **`PanicSched` boot/OOM failures** (`sched/sched.cpp:598`,
  `:655`, `:671`, `:935`) — KMalloc-failed-for-Task,
  AllocateKernelStack-failed, no-runnable-task. These need a
  `Result<T,E>` return-type refactor on `SchedCreate` (or, for the
  no-runnable-task invariant, a guarantee the idle task is always
  on the runqueue) before they can become recoverable. The three
  *contract-violation* `PanicSched` calls (Mutex/Condvar misuse)
  were converted to `DebugPanicOrWarn` in the second pass above —
  they sit between explicit `arch::Cli()` / `arch::Sti()` so each
  release-path return needs an explicit `Sti()`.
- **`LinuxCloneEntry` / `Ring3ThreadEntry` invariants** —
  converted in the third pass (above) by pairing
  `DebugPanicOrWarn` with a follow-up `sched::SchedExit()` so the
  function's `[[noreturn]]` contract holds in both flavors.

What stays as hard `Panic` deliberately:
- Heap / frame-allocator / page-table corruption.
- Stack-canary mismatch (real overflow).
- ACPI table parse / signature / checksum failures.
- LAPIC / IOAPIC init failures (kernel cannot run without them).
- Trap-frame state the kernel can't represent (kstack overflow).
- SeqLock writer-leak invariants (continuing produces torn reads).

## Test surface

- **Debug build** `cmake --preset x86_64-debug && cmake --build
  build/x86_64-debug` — clean.
- **Release build** `cmake --preset x86_64-release && cmake
  --build build/x86_64-release` — clean.
- No new runtime smoke needed yet — none of the converted sites
  fire on the existing boot path; if they did, debug would catch
  them today.

## Resume prompt

> Continue the "soften release-build panics" work. The
> `DebugPanicOrWarn` / `DebugPanicOrWarnWithValue` helpers are in
> `kernel/core/panic.{h,cpp}`. 34 sites converted across three
> passes — see the tables in this file for the full inventory.
>
> What's left to triage:
> - Boot-time `PanicSched` OOM (`sched.cpp:598/655/671/935`) —
>   needs `SchedCreate` to return `Result<T,E>` first.
> - `SeqLock` invariant violations (`sync/seqlock.cpp:77,98`) —
>   continuing past these can produce torn reads, so they need a
>   different recovery shape (perhaps "drop the seqlock-protected
>   subsystem entirely").
> - `arch/x86_64/smp.cpp:92` (IPI delivery-status bit stuck) —
>   wedge-during-AP-bringup; recovery is unclear without
>   per-AP-IPI tracking.
>
> Deliberately untouched: heap / frame-allocator / page-table
> corruption (KEEP); ACPI table parse failures (KEEP — fundamental
> firmware data); LAPIC / IOAPIC init (KEEP — kernel cannot run
> without them); `*SelfTest` panics (already dead code in release
> via `DUETOS_BOOT_SELFTEST(call)`).
