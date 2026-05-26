# Code Path Ledger (KPath)

A global, automatic record of **which code paths fired during this
boot**. Answers "did X actually run?" without manual `KLOG_DEBUG`
sprinkling, and without grepping. Sits next to the [fix
journal](Diagnostics.md) and the [probe registry](Logging-And-Tracing.md)
as the third pillar of the kernel's observe-and-record diagnostic
surface.

Source: `kernel/diag/kpath.{h,cpp}`, `kernel/diag/kpath_dump.cpp`,
`kernel/diag/kpath_persist.{h,cpp}`, `kernel/diag/kpath_selftest.cpp`,
`kernel/shell/shell_kpath.cpp`. Linker sections in
`kernel/arch/x86_64/linker.ld`.

## Why

Every prior diagnostic surface was either curated (45 probes), bound
to a specific failure shape (fix journal records `// STUB:` /
`// GAP:` hits), or required someone to add a log line ahead of time.
None of them answer the broad question "which code paths fired this
boot?" KPath does — a single ledger that:

- Auto-enrolls every syscall number, every IDT vector, every
  initcall, every existing `KBP_PROBE`, every fix-journal record.
- Provides a `KPATH(category, name)` macro for marking
  interesting conditional branches that fall outside dispatch
  surfaces.
- Emits one structured `[kpath] visited=N/M ...` sentinel at
  smoke completion (and on panic) for CI consumption.
- Writes `KERNEL.KPATH.TSV` to the FAT32 root so an offline diff
  tool can compare coverage across boots.

## Storage

Two linker-collected ELF sections, modelled on the existing
`.duetos_hotpatch_pairs` registry:

| Section | Type | Purpose |
|---|---|---|
| `.kpath_sites` | read-only (`.rodata`) | One `KPathSite` record (40B) per call site. Linker emits `__kpath_sites_start` and `__kpath_sites_end`. |
| `.kpath_hits` | mutable (`.data`) | One `u64` counter per site. Linker emits `__kpath_hits_start` and `__kpath_hits_end`. |

Each `KPATH(...)` macro stamps one record into each section from
the same TU. The `KPathSite` carries an explicit `hits_ptr` so we
never rely on the linker preserving order across sections.

Auto-enrolled surfaces use fixed-size tables instead of bloating
`.kpath_sites`:

| Surface | Storage | Bumped by |
|---|---|---|
| Syscalls | `g_kpath_syscall_hits[256]` | `KPathHitSyscall(num)` at the top of `SyscallDispatch` |
| IDT vectors | `g_kpath_vector_hits[256]` | `KPathHitVector(v)` at the top of `TrapDispatch` |
| Initcalls | `InitcallRecord::invoke_count` (already exists) | `RunPhase()` |
| Probes | `ProbeInfo::fire_count` (already exists) | `KBP_PROBE` macro |
| Fix-journal | `FixRecord::repeat_count` (already exists) | `FixJournalRecord*` |

The unified iterator (`KPathForEach`) walks `.kpath_sites` first,
then yields synthetic rows for each auto-enrolled surface.

## Macros

```cpp
KPATH(category, name)                  // 1 atomic add when armed
KPATH_V(category, name, value)         // same; value reserved for future capture
KPATH_HOT(category, name)              // flagged hot; same code path today
```

Categories (`KPathCat` enum):

- `Manual` — hand-placed at an interesting site.
- `Branch` — hand-placed at a specific conditional arm.
- `SelfTest` — boot self-test entry marker.
- `Syscall`, `Vector`, `Initcall`, `Probe`, `Fix` — virtual rows
  produced by the iterator from auto-enrolled tables; macros never
  use these.

Fire cost: one byte load of `g_kpath_enabled` (predicted not
taken when disabled) + one relaxed atomic add on the per-site
counter. Safe in IRQ / trap / scheduler contexts — no allocator,
no klog, no spinlock.

Compile-time off: `-DDUETOS_KPATH_OFF` disables the macros
entirely (`((void)0)`). The dispatch-table hooks remain since
they're plain function calls, but the global enable flag silences
them too.

## Output

Three channels, all wired:

### Serial sentinel

`KPathEmitBootSummary()` emits one structured line at smoke
completion (called from `kernel/test/smoke_profile.cpp`):

```
[kpath] visited=412/1023 (40%) cats=site:5/5 syscall:23/256 vector:14/256 initcall:48/48 probe=12 fix=3
```

CI greps this verbatim — see `tools/test/boot-log-analyze.sh`
for the parser. The same line fires from the panic path via
`DumpDiagnostics` so a crash log carries last-known coverage.

### Shell command

```
kpath list                — per-category visit summary
kpath show <category>     — every row in a category
kpath hits <substring>    — rows whose name contains substring
kpath dump                — full TSV to the console
kpath flush               — rewrite KERNEL.KPATH.TSV
```

No admin gate on the read paths — the data is already in the boot
log. `flush` only writes the same TSV the smoke path emits, so no
gate there either.

### FAT32 sink

`KERNEL.KPATH.TSV` on the FAT32 root volume. Plain UTF-8:

```
# kpath TSV v1
# fields: category    name    hits    file    line    syscall vector
syscall syscall 12      kernel/syscall/syscall.cpp 0   1       -
vector  vector  148     kernel/arch/x86_64/traps.cpp 0  -      32
manual  loader.pe.resolve_imports  3   kernel/loader/pe_loader.cpp 1633  -  -
...
```

`KPathPersistInstall()` is called next to `FixJournalPersistInstall`
in `boot_bringup.cpp`. `KPathPersistFlush()` rewrites the file at
smoke completion. The format is plain TSV so the offline diff tool
is a shell script, not a binary parser.

## Cross-boot coverage diff

`tools/test/kpath-coverage.sh` compares two TSV snapshots and
reports:

- **Newly visited**: sites that didn't fire in the baseline but
  fire now (good — new feature wired in).
- **Newly cold**: sites that fired in the baseline but don't
  fire now (bad — silent regression).
- **visited% delta**: gates on a threshold (default 5pp drop).

Returns nonzero exit when newly-cold sites exist OR percentage
fell past the threshold. Designed to slot into CI alongside
`boot-log-analyze.sh`.

```
$ tools/test/kpath-coverage.sh known-good.tsv build/x86_64-release/KERNEL.KPATH.TSV
kpath coverage diff:
  baseline: known-good.tsv
  current : build/x86_64-release/KERNEL.KPATH.TSV
...
NEWLY VISITED (didn't fire in baseline, fires now):
  + manual|loader.pe.resolve_imports  hits=3
NEWLY COLD (fired in baseline, doesn't fire now):
  (none)
visited%: baseline=41%  current=42%  threshold-drop=5pp
verdict: OK
```

## Init order

In `kernel/core/boot_bringup.cpp`:

```cpp
duetos::diag::FixJournalInit();
DUETOS_BOOT_SELFTEST(duetos::diag::FixJournalSelfTest());

duetos::diag::KPathInit();
duetos::core::InitcallRegisterOrPanic(
    duetos::core::Phase::Earlycon, "kpath-selftest",
    []() { return duetos::diag::KPathSelfTest(); });
```

`KPathInit` is idempotent. The counters are `.bss`-zeroed, so any
fire that lands before `KPathInit` runs is still recorded (the
enable flag defaults to 1).

Persist install runs after the FAT32 volume is mounted:

```cpp
duetos::diag::FixJournalPersistInstall();
DUETOS_BOOT_SELFTEST(duetos::diag::FixJournalPersistSelfTest());

duetos::diag::KPathPersistInstall();
```

## Self-test

`KPathSelfTest()` (registered as `Phase::Earlycon` initcall):

1. Fires a `KPATH(SelfTest, "kpath.selftest.site")` macro 1000 times,
   asserts the counter rose by exactly 1000.
2. Walks the unified iterator and confirms the selftest row appears
   with `hits >= 1000`.
3. Bumps `KPathHitSyscall(0xFE)` and `KPathHitVector(0xFD)` once each;
   asserts the deltas equal 1.

Emits `[smoke] kpath=ok sites_visited=<n>` via `KLOG_INFO` on pass.
On failure, fires `kBootSelftestFail` with a per-check value so an
attached GDB can `b duetos::debug::ProbeFire` and halt at the exact
mismatch.

## Performance

The `KPATH(...)` macro path is a single relaxed atomic add on
contention-light sites. Hot paths (timer tick, context switch) use
`KPATH_HOT(...)` — same code today; the `hot=1` flag is recorded
so a future slice can route those sites through a per-CPU shard
table without changing call sites.

Disable in production via `-DDUETOS_KPATH_OFF` (all macros
become `((void)0)`) or set `g_kpath_enabled=0` at runtime
(short-circuits at the byte load).

## Related

- [Diagnostics](Diagnostics.md) — fix journal, probes, runtime
  checker, the diag-module table.
- [Logging and Tracing](Logging-And-Tracing.md) — klog, probe
  macros, STUB/GAP conventions.
- [QEMU Smoke](../tooling/QEMU-Smoke.md) — boot-log gates that
  consume the `[kpath]` sentinel.
