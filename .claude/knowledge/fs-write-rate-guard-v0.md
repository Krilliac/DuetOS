# FS write-rate guard + canary wall — v1

**Type:** Decision + Pattern + Observation
**Status:** Active — v1 lands two compounding walls
**Last updated:** 2026-05-03

## What it is

Layered self-defense against ransomware-style file mutation:

1. **Multi-window FS write-rate guard** — three rolling
   per-process byte caps at decreasing granularities (burst /
   sustained / long-tail). Catches the full range of pacing
   strategies, including the open-source-aware low-and-slow
   evasion an attacker can mount once they read our threshold
   constants.
2. **Canary / honey-path wall** — a static registry of
   "forbidden" file paths and ransomware-typical suffix
   extensions. Any process that creates / writes / unlinks /
   renames a matched path dies on the first touch. No
   thresholds, so an attacker who paces under the rate caps
   still trips this wall the moment they hit a canary.

The two walls cover orthogonal evasion strategies:

| Attacker strategy | Rate guard | Canary wall |
|---|---|---|
| "Encrypt as fast as possible" | ✅ catches at burst tier | ✅ trips on first canary file in path |
| "Stay under burst cap, sustained pace" | ✅ catches at sustained tier | ✅ same |
| "Stay under sustained cap, hour-long pace" | ✅ catches at long-tail tier | ✅ same |
| "Stay under all three rate caps + steer around canary list" | ❌ silent | ⚠️ only if attacker decoded the list |

Closes the "Ransomware (mass FS encrypt)" gap from
`.claude/knowledge/redteam-coverage-matrix-v0.md` plus the
"low-and-slow rate-cap evasion" gap a v0 design left open.

## Multi-window rate guard

Three rolling windows, all checked on every successful file
write. First cap-cross kills the caller (no cumulative scoring
— any single window over budget is enough).

| Level | Window ticks | Window | Byte cap | Effective rate ceiling |
|---|---|---|---|---|
| 0 — burst    | 100        | 1 s    | 16 MiB  | 16 MiB/s peak |
| 1 — sustained | 30 000     | 5 min  | 256 MiB | ~850 KiB/s avg |
| 2 — long      | 360 000    | 1 h    | 2 GiB   | ~580 KiB/s avg |

Tunable as `kFsWriteWindowTicksByLevel[]` /
`kFsWriteWindowByteCapByLevel[]` in `kernel/proc/process.h`.
Process struct holds parallel arrays
`fs_write_window_bytes[3]` / `fs_write_window_start_tick[3]`;
`fs_write_bytes_total` is the lifetime telemetry counter (no
gate).

`RecordFsWriteCheckLevel(p, bytes)` returns the index of the
first level that tripped, or -1. Existing `RecordFsWriteCheck`
keeps its `bool` shape for back-compat. `RecordFsWrite`
(production) calls the level variant, logs the matched level
label (e.g. "5min/256MiB"), bumps the matching HealthIssue
counter, and flags the calling task for kill.

Three new HealthIssues — `MassFsWriteRate` (burst, the original
v0 issue), `MassFsWriteRateSustained`, `MassFsWriteRateLong` —
let operators tell which timescale's wall fired. An attacker
who tripped the long-tail wall is materially different from one
who tripped burst.

`KillReason::FsWriteRateExceeded = 4` is unchanged — the kill
reason is a single value because the three tiers are different
shades of the same defense.

## Canary wall

Static registry in `kernel/security/canary.h`:

- `kCanaryPaths[]` — 16 entries today: DuetOS-native sentinels
  (`/canary/`, `DUETOS_CANARY.DAT`, `DO_NOT_DELETE.TXT`,
  `DUETOS_HONEY`) + ransomware-bait names (`WALLET.DAT`,
  `PASSWORDS.TXT`, `BACKUP.ZIP`, `ID_RSA`, `PAYROLL.XLS`,
  `INVOICES.PDF`, `SECRET.TXT`, `IMPORTANT.{DOC,DOCX,TXT}`).
- `kCanarySuspiciousExtensions[]` — 18 entries: the trailing
  `.<ext>` substrings real-world ransomware families append to
  encrypted output (`.locked`, `.encrypted`, `.crypto`,
  `.crypt`, `.crypted`, `.enc`, `.encrypt`, `.lock`, `.ransom`,
  `.wcry`, `.wncry`, `.cerber`, `.thor`, `.aes`, `.rsa`,
  `.pay`, `.paymrts`, `.doxxed`).

Both matchers are case-insensitive ASCII. Path matcher tries
three rules in order:

1. Whole-string equals a registered exact path.
2. Basename (after last `/` or `\\`) equals a registered name.
3. Path begins with a registered prefix (e.g. anything under
   `/canary/`).

`CanaryCheck(path, op)` runs both matchers and trips on the
first hit. `CanaryTrip` does the kill: bumps the
`CanaryFileTouched` HealthIssue, logs the event with the op
tag (`create` / `unlink` / `rename-src` / `rename-dst` /
`open-O_CREAT`), and flags the caller for kill via
`KillReason::CanaryFileTouched = 5`.

### Wired-in syscall sites

Every path-bearing FS-mutation syscall site, on both ABIs:

| Syscall | TU | Hook site |
|---|---|---|
| Win32 `SYS_FILE_CREATE` | `kernel/fs/file_route.cpp` `CreateForProcess` | before the on-disk plant |
| Win32 unlink | `kernel/fs/file_route.cpp` `UnlinkForProcess` | before `Fat32DeleteAtPath` |
| Win32 rename | `kernel/fs/file_route.cpp` `RenameForProcess` | both src and dst paths |
| Linux `unlink` / `unlinkat` | `kernel/subsystems/linux/syscall_fs_mut.cpp` `DoUnlink` | after path strip |
| Linux `rename` / `renameat` | `kernel/subsystems/linux/syscall_fs_mut.cpp` `DoRename` | both endpoints |
| Linux `open` / `openat` with `O_CREAT` | `kernel/subsystems/linux/syscall_file.cpp` `DoOpen` | inside the `!exists && O_CREAT` branch |

The Win32 write-to-existing path (`WriteForProcess`) is NOT
canary-checked because handles don't carry their open-time
path; canary-tripping ransomware on the in-place-overwrite
strategy currently relies on the rate guard. A v1 follow-up
that stamps `is_canary` on `Win32FileHandle` at create/open
time would close this without needing a per-write path lookup.

### What's intentionally not covered

- **Random per-boot canary names**. The list is compile-time,
  visible in the kernel symbol table, so a determined attacker
  who reads the binary can steer around. v1 follow-up: register
  the list at boot from a kernel-entropy-derived randomized
  salt + plant decoy files at the names so dir-enumerator
  ransomware picks them up before user data.
- **Decoy files on disk**. The matcher trips on path strings
  alone, even if the file doesn't exist. Real on-disk decoys
  would lure ransomware that enumerates dirs first; deferred
  until FAT32 mkfs lands cleanly.
- **Cross-process aggregate**. The rate guard is per-process by
  design. A coordinated multi-process attack that keeps each
  pid under the cap is theoretically possible. A global
  per-system rate counter would close that but needs a fork-
  rate detector to be useful (without one, the attacker just
  forks-bombs to scale up).

## Test wiring (attack_sim)

Three attacks added to `kernel/security/attack_sim.cpp`:

1. **Ransomware FS write-rate flood (burst tier)** —
   `AttackRansomwareWriteRate`. Hammers the synthetic process
   with 4 KiB writes until it tips past the 16 MiB / 1 s cap.
   Verifies `RecordFsWriteCheckLevel` returns 0 (burst tier)
   and bumps `MassFsWriteRate`.
2. **Ransomware low-and-slow (sustained tier)** —
   `AttackRansomwareLowAndSlow`. Writes the burst-cap value
   per iteration but back-dates the burst window's start_tick
   between iterations to simulate "the attacker waited 1 s
   between bursts." After 16 iterations the sustained window
   trips — verifying that the open-source-aware pacing
   strategy gets caught by tier 1 even when tier 0 stays
   green. Bumps `MassFsWriteRateSustained`.
3. **Canary file touch** — `AttackCanaryTouch`. Calls the
   path matcher against `WALLET.DAT` (registry hit) and the
   suspicious-extension matcher against
   `/disk0/Documents/notes.encrypted` — verifies both fire,
   bumps `CanaryFileTouched`.

All three use a synthetic `Process` on a static buffer (no
KMalloc, no scheduler, no FlagCurrentForKill — the production
hooks would terminate the kernel main task running the suite).
The standard `RunAttack` before/after counter compare reports
PASS when the matching health counter incremented.

Total spec table grows from 12 → 14 entries (still under
`kMaxAttackResults = 16` ceiling).

## Files touched (this slice)

New:

- `kernel/security/canary.h` — public API
- `kernel/security/canary.cpp` — registry + matchers + trip

Modified:

- `kernel/sched/sched.h` / `sched.cpp` — `KillReason::CanaryFileTouched`
- `kernel/proc/process.h` — multi-window arrays, constants,
  `RecordFsWriteCheckLevel` decl
- `kernel/proc/process.cpp` — multi-window logic
- `kernel/diag/runtime_checker.h` / `.cpp` — three new
  HealthIssues (`MassFsWriteRateSustained`, `MassFsWriteRateLong`,
  `CanaryFileTouched`), `RuntimeCheckerNoteFsWriteRate-
  Exceeded(level)` extended, new `RuntimeCheckerNoteCanaryFile-
  Touched`
- `kernel/fs/file_route.cpp` — canary checks on create / unlink /
  rename
- `kernel/subsystems/linux/syscall_fs_mut.cpp` — canary checks on
  Linux unlink + rename
- `kernel/subsystems/linux/syscall_file.cpp` — canary check on
  Linux open with O_CREAT
- `kernel/security/attack_sim.cpp` — three new attacks +
  spec-table entries
