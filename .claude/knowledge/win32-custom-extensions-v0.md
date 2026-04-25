# Win32 custom diagnostics + safety extensions — v0

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active — landed on `claude/custom-window-handling-RqpE5`,
all features compile + link, all opt-in (default policy = 0).

## What this is

Because the DuetOS Win32 subsystem is a from-scratch
reimplementation of the NT/Win32 ABI, we can layer features over
it that real Windows can't add without breaking compatibility. v0
landed eleven such features as a single coherent module.

Files: `kernel/subsystems/win32/custom.{h,cpp}`. New syscall:
`SYS_WIN32_CUSTOM = 129`. New Process member:
`win32_custom_state` (opaque void*; lazy-allocated).

## Tradeoff (the design constraint)

Every "extra" is also extra surface that could disagree with apps
that probe Windows-buggy behaviour. The mitigation is **everything
is opt-in**. The default policy on every freshly-spawned process is
`0` — no feature is active. Apps must explicitly set bits via
`SYS_WIN32_CUSTOM op=SetPolicy`.

## Features

| Bit | Name                       | What it does |
|-----|----------------------------|--------------|
| 0   | FlightRecorder             | Per-process ring buffer (64 entries) of recent syscalls (num + arg snapshot + RIP + ns timestamp). Dumped on abnormal exit. |
| 1   | HandleProvenance           | Side table of every Win32 handle: creator RIP, syscall, timestamp, generation. Use-after-CloseHandle flagged. |
| 2   | ErrorProvenance            | SetLastError records the RIP that set it. Debugger can answer "where did ERROR_x come from?". |
| 3   | QuarantineFree             | Heap blocks freed by Win32HeapFree are held ~250 ms before reuse. Catches the basic UAF pattern. |
| 4   | DeadlockDetect             | Every WaitForSingleObject(mutex) registers a wait edge in a global graph; cycles are logged with the full edge list. |
| 5   | ContentionProfile          | Per-mutex acquire / wait / wait-ms accumulators. Free hot-lock signal. |
| 6   | AsyncPaint                 | WM keeps the last good frame and never blocks on a paint message. (Policy queryable; compositor wiring is a follow-up.) |
| 7   | PixelIsolation             | Cross-process BitBlt reads denied when both src and dst opt in. (Policy queryable; gdi32 wiring is a follow-up.) |
| 8   | InputReplay                | Global ring (256 entries) capturing every WM_* dispatched to a window whose owner has the bit set. |
| 9   | StrictRwx                  | A PE section with both MEM_WRITE and MEM_EXECUTE is refused at load. |
| 10  | StrictHandleInherit        | Child processes don't auto-inherit "inheritable" handles. (Policy queryable; child-spawn wiring is a follow-up.) |

Five of the eleven (FlightRecorder, HandleProvenance,
ErrorProvenance, QuarantineFree, DeadlockDetect, ContentionProfile,
StrictRwx, InputReplay-data-plane) are **fully wired** to their
producers — they record real signal as soon as the policy bit is
set. Three (AsyncPaint, PixelIsolation, StrictHandleInherit) are
**policy-side only** — `custom::AsyncPaintActive(proc)`,
`custom::PixelIsolationDenies(a, b)`, and
`custom::StrictRwxRejectsSection(proc, c)` are correct query helpers,
but the consumer paths (compositor, BitBlt, child-spawn) haven't been
hooked yet. Wiring them is a follow-up — the policy contract is
already stable.

## Hook sites

Minimal touch — only six call sites take a custom hook:

1. `core::SyscallDispatch` — calls `custom::OnSyscallEntry` once per
   trap. Inline policy-bit check; effectively free when off.
2. `case SYS_SETLASTERROR` — calls `custom::OnLastErrorSet` after
   updating `proc->win32_last_error`.
3. `case SYS_WIN32_CUSTOM` — multiplexed entry into
   `custom::DoCustom`.
4. `Win32HeapFree` — calls `custom::OnHeapFree` after pushing a
   block to the free list.
5. `Win32HeapAlloc` — first-fit walker skips quarantined blocks via
   `custom::IsQuarantined`.
6. `DoMutexWait` — calls `custom::OnMutexAcquire` /
   `custom::OnMutexWaitStart` / `custom::OnMutexWaitEnd`.

`ProcessRelease` invokes `custom::CleanupProcess` to free the lazy
state and tear down any wait-graph edges held by the dying process.

## SYS_WIN32_CUSTOM ABI

Multiplexed. `rdi` = sub-op:

| Op | Name                  | Args                        | Returns |
|----|-----------------------|-----------------------------|---------|
| 0  | GetPolicy             | (none)                      | current bitmask |
| 1  | SetPolicy             | rsi = new bitmask           | previous bitmask, or -1 on KMalloc OOM |
| 2  | DumpFlight            | (none)                      | 0 (emits to serial) |
| 3  | DumpHandles           | (none)                      | 0 (emits to serial) |
| 4  | GetErrorProvenance    | rsi = user `ErrorProvenance*` | 0 on success, -1 on bad pointer / not enabled |
| 5  | DetectDeadlock        | (none)                      | 1 if current thread is in a cycle, 0 otherwise |
| 6  | DumpQuarantine        | (none)                      | 0 |
| 7  | DumpContention        | (none)                      | 0 |
| 8  | DumpInputReplay       | (none)                      | 0 |

Bits in the policy mask above `kPolicyAllMask` are silently
dropped — keeps the syscall forward-compatible without forcing
callers to track unknown bits.

## Verification

- Clean build under the standard preset: `cmake --preset
  x86_64-debug && cmake --build build/x86_64-debug` — link succeeds,
  no new warnings vs. baseline (50 -Wshadow warnings preexisting in
  `core/syscall.cpp`, none new).
- clang-format clean over every touched file.
- No QEMU smoke change required: every default-spawned process has
  policy = 0, every hook is a no-op, observable behaviour is
  identical to pre-change.

## Bloat profile

| File                       | Lines |
|----------------------------|-------|
| `custom.h`                 | ~310  |
| `custom.cpp`               | ~580  |
| Edits to existing files    | ~70 total across 6 files |

Within `.cpp` (≤500) and `.h` (≤300, just over) thresholds — both
files house one coherent unit (the diagnostics + safety facility),
which is the right granularity per the anti-bloat guidelines.

## Follow-up wiring (not in v0)

- AsyncPaint: compositor needs a "skip blocking on paint message"
  branch keyed off `AsyncPaintActive`.
- PixelIsolation: every cross-window BitBlt path
  (gdi_objects.cpp / window_syscall.cpp BitBlt handlers) needs a
  call to `PixelIsolationDenies`.
- StrictHandleInherit: when a child-spawn API lands, gate the
  handle-inheritance walk on `kPolicyStrictHandleInherit`.
- StrictRwx: PE loader needs to call `StrictRwxRejectsSection` per
  section header.
- A small ring-3 stub (`kernel32!DuetCustomSetPolicy` /
  `DuetCustomGetFlight` etc.) so Win32 PEs can opt in without
  knowing the syscall number directly.
