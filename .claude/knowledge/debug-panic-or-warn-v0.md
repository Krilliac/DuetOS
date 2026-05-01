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
- **`PanicSched` family** (`sched/sched.cpp:316` and friends —
  "MutexUnlock by non-owner", "no runnable task available",
  KMalloc-failed-for-Task, …) — most are `[[noreturn]]` boot-time
  failures or early-init OOM where "continue" doesn't have a
  defined meaning. Conversion would require un-`[[noreturn]]`-ing
  the helper and refactoring multiple call sites that assume the
  helper doesn't return.
- **`LinuxCloneEntry` / `Ring3ThreadEntry` invariants** — the
  fail-paths run on a fresh kernel stack at task entry; the only
  sane release recovery is "exit this task back to scheduler",
  which is more involved than a return. Left as hard panics.

These are good follow-up targets for a v1 pass once the v0 helper
has burned in.

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
> `DebugPanicOrWarn` / `DebugPanicOrWarnWithValue` helpers landed
> in `kernel/core/panic.{h,cpp}` and 11 sites were converted (see
> `.claude/knowledge/debug-panic-or-warn-v0.md` for the table).
> Next candidates: scheduler primitive misuse (`PanicSched` calls
> in `kernel/sched/sched.cpp:2371,2417,2477` — Mutex/Condvar
> contract violations), and the `Linux/Win32` thread-entry
> invariants once a "exit task to scheduler" recovery path is
> available. Self-test panics deliberately stay as-is — they're
> dead code in release via `DUETOS_BOOT_SELFTEST(call)`.
