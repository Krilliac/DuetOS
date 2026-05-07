# Fix Journal — Observe-and-Record Self-Healing

## What it is

A kernel-internal **observation-only** record of "this gap was hit at this site." When the running kernel reaches a `// STUB:` / `// GAP:` site, an unmapped Win32 thunk, an unknown syscall number, a soft-fault recovery, or a PE/ELF loader reject, the journal captures the event into a structured `FixRecord`. Records persist (in priority order) into:

1. **Tier 1** — in-RAM ring (`kernel/diag/fix_journal.cpp`, 1024 records × 128 B = 128 KiB)
2. **Tier 2** — FAT32 file `/KERNEL.FIX` with cross-boot rotation (`kernel/diag/fix_journal_persist.cpp`, depth = 4)
3. **Tier 3** — NVMe panic-reserved LBA region (`kernel/drivers/storage/nvme.cpp`, second half of the existing 4 MiB crash-dump reservation). Fires for **both** soft panics (`core::Panic` / `PanicWithValue`) **and** hard crashes (#PF / #GP / #UD / etc. via `EmitMinidumpFromTrapFrame`) — both routes through `PersistToDisk` in `kernel/diag/minidump.cpp`. The Tier-3 snapshot is **lock-free** (`FixJournalSnapshotPanicSafe`) so a hard crash that interrupts a recorder mid-update does not deadlock on the journal's spinlock; readers (e.g. `gen-fix-report.py`) validate per-record magic and skip torn rows.

A reviewer (typically a Claude session attached to a live boot) reads the journal — via the `dfix` shell command, the `/proc/fixjournal` ramfs view, or the offline `tools/build/gen-fix-report.py` summarizer — and converts records into real source fixes in the tree. **The kernel never auto-applies a fix.**

## Why it is observe-only

[Design-Decision #016](../reference/Design-Decisions.md) explicitly forbids silent self-healing: *"sophisticated rootkits actively exploit self-healing code … silent self-heal is the anti-pattern, security-relevant corruption must be visible."* Every fix-journal record IS the audit event #016 demands. There is no path in the kernel where reaching a journal record causes `.text`, dispatch tables, function pointers, or any other runtime state to mutate.

The "self-healing" framing in the feature name describes the **workflow**, not the mechanism: the kernel observes its own gaps, the reviewer applies the fixes, the kernel evolves. The kernel itself stays passive.

## Detectors

| Detector | Source pin format | Where it fires |
|----------|-------------------|----------------|
| `StubMarker` | `path:Function` | `FIX_NOTE_STUB(...)` macro (1 line below a `// STUB:` comment) |
| `GapMarker` | `path:Function` | `FIX_NOTE_GAP(...)` macro (1 line below a `// GAP:` comment) |
| `UnknownSyscall` | `syscall#<hex>` | `kernel/syscall/syscall.cpp` default arm, after `NativeGapFill` declines |
| `UnmappedThunk` | `<dll>!<func>` | `kernel/loader/pe_loader.cpp` Win32 catch-all branch |
| `SoftFaultRecov` | caller-supplied label | `RetryWithBackoff` success-after-retry and give-up paths |
| `LoaderReject` | `loader/pe:<status>` | PE rejected for `BadMachine`, `RelocsNonEmpty`, `TlsCallbacksUnsupported`, etc. |

Dedup is keyed on `(detector, source_pin)`. A workload that hits the same gap 1000 times produces **one** record with `repeat_count=1000`, not 1000 records.

## On-disk format

Every tier uses the same layout:

```
[u32 magic 'FIXJ' = 0x4A584946]
[u32 version = 1]
[u32 record_count]
[u32 reserved (must be 0)]
[FixRecord × record_count]      // each record is exactly 128 B
```

`FixRecord` field order is part of the on-disk ABI — see `kernel/diag/fix_journal.h`. Bumping `version` is the only sanctioned way to change the record stride or field set; readers (`gen-fix-report.py`) check the version and refuse to interpret older / newer files.

## Live review

While a boot is running:

```sh
$ dfix list                       # tail the last 20 un-audited records
$ dfix show 42                    # one record by seq, with caller_rip symbolized
$ dfix stats                      # counters + per-detector tally
$ dfix mark-done 42               # filter seq=42 from default `list`
$ dfix flush                      # force a write to KERNEL.FIX
$ cat /proc/fixjournal            # tab-separated dump (no shell needed)
```

Audited records are excluded from `dfix list` unless `--all` is passed, so the working set stays focused on un-triaged gaps.

## Offline review

After capture (or a panic), a host-side script summarizes the journal:

```sh
$ python3 tools/build/gen-fix-report.py KERNEL.FIX KERNEL.F0 KERNEL.F1
```

The output is a markdown report grouping records by detector and source pin, sorted by repeat count, with a triage workflow at the end.

## Reviewer workflow

1. **Pick a gap.** `dfix list` (or the markdown report) gives the un-audited rows. The highest-repeat row in each detector is the best ROI.
2. **Open the source pin.** `path:Function` → open the file. `dll!fn` → check `wiki/reference/Win32-Surface-Status.md` for the DLL's REAL/STUB/GAP/MISSING table.
3. **Decide the fix.** Implement the missing path; route through an existing primitive; or accept the gap.
4. **Land the source change** as a normal commit on a feature branch. The journal is observational — it does not commit anything to the tree.
5. **Mark the record audited** so future `dfix list` calls don't re-surface it: `dfix mark-done <seq>`. The audited bit also persists into the next FAT32 flush.

## Anti-bloat decisions made on purpose

- **No userland flusher.** The original plan included a userland service that would mirror `/proc/fixjournal` to durable storage. The Tier-2 FAT32 sink already does that from kernel space, so the userland service would be a duplicate subsystem. Per the [anti-bloat guidelines](../tooling/Anti-Bloat-Guidelines.md), dropped.
- **No "fix templates" library or DSL.** The `hint` field is one 40-byte string. Anything more elaborate belongs in the source tree, not the runtime record.
- **No new fault-domain.** The journal is a passive observer of the existing `FaultReactDispatch` chokepoint; it does not register itself as a domain that could itself fail and get restarted.
- **No `auto-apply` even behind a feature flag.** Adding it is a separate design conversation that has to engage with #016 head-on; nothing in this subsystem is one knob away from auto-application.

## File map

| File | Role | LOC |
|------|------|-----|
| `kernel/diag/fix_journal.h/.cpp` | Public API + ring + dedup + selftest | 165 + 430 |
| `kernel/diag/fix_journal_persist.h/.cpp` | Tier-2 FAT32 sink + Tier-3 NVMe panic write | 90 + 320 |
| `kernel/shell/shell_diag.cpp` | `dfix` command (5 sub-operations) | 280 |
| `kernel/fs/ramfs.cpp` (additions) | `/proc/fixjournal` snapshot view | ~80 |
| `tools/build/gen-fix-report.py` | Offline markdown summarizer | 250 |

Insertions into existing files (single-digit lines each): `kernel/syscall/syscall.cpp`, `kernel/loader/pe_loader.cpp`, `kernel/diag/recovery.h`, `kernel/core/main.cpp`, `kernel/core/panic.cpp`, `kernel/diag/heartbeat.cpp`, plus six representative `// STUB:` / `// GAP:` sites that gained `FIX_NOTE_*` macros.

## Verification

- **Boot self-test** (`FixJournalSelfTest()`) injects one record per detector kind, asserts `records_unique` rose by exactly the number injected, asserts a known dedup hit collapses, asserts mark-done sets the audited flag, asserts mark-done on a missing seq returns `NotFound`. Panics on mismatch via `kBootSelftestFail`. Prints `[smoke] fix_journal=ok records=<n>` on pass.
- **Persistence self-test** (`FixJournalPersistSelfTest()`) flushes, reads back the FAT32 header, validates magic + version + size = header + count × 128. Prints `[smoke] fix_journal_persist=ok records=<n>` on pass; SKIP if FAT32 isn't mounted.
- **Probe**: a brand-new unique record fires `kFixJournaled` with `(seq << 32) | detector` packed into the value field. ArmedLog by default → a clean run logs the count of unique gaps; an attached GDB can `b duetos::debug::ProbeFire` and break on each one.
