# Linux compatibility tooling

Reference data + generator that expand the translator's "known
Linux syscall" table from a hand-curated ~80 entries to the full
x86_64 syscall ABI (0..462 as of Linux 6.10).

## Why this exists

`kernel/subsystems/translation/translate.cpp` looks up a Linux
syscall number in `kLinuxNames` whenever the primary dispatcher
bounces an unrecognised number to the translator. The logged
name is what lets us tell "musl called getrandom (318)" apart
from "musl called some garbage" — crucial for ABI bring-up.

Prior to this tooling the table was hand-written and covered
only what we'd seen in practice. Adding any new known-by-name
number required a code edit. The generator below consumes the
canonical kernel table (`arch/x86/entry/syscalls/syscall_64.tbl`)
and emits one C++ row per number, so every Linux binary we run
now logs with a real name even if the call itself is still
unimplemented.

## What's here

| File                                | Purpose                                                     |
| ----------------------------------- | ----------------------------------------------------------- |
| `linux-syscalls-x86_64.csv`         | Canonical x86_64 syscall table: `number,name,args`          |
| `gen-linux-syscall-table.py`        | Generator that emits `linux_syscall_table_generated.h`      |
| `check-gapfill-overlap.py`          | Fails when dispatch + translator both claim same syscall nr |
| `gapfill-overlap-allowlist.txt`     | Explicit temporary overlap allowlist for the check script   |

## Provenance

`linux-syscalls-x86_64.csv` is a transcription of the upstream
Linux kernel `arch/x86/entry/syscalls/syscall_64.tbl` file
(GPL-2.0, Linus Torvalds et al.). Only the `common` / `64` ABI
rows are captured — x32 (512..547) is not a CustomOS target. Arg
counts come from `include/linux/syscalls.h` on the matching
kernel version. These are ABI facts: numbers and names are the
interoperability primitive. The same legal posture covers this
that covers j00ru's NT table (see `../win32-compat/README.md`).

## Regenerating

```sh
tools/regenerate-syscall-artifacts.sh
```

This runs the Linux table generator, the NT table generator, and
the unified ABI matrix generator so the docs stay in sync with
the generated headers.

Commit the updated CSV/header inputs and generated outputs. The
build does NOT invoke Python; generated artifacts are checked in.

## Dispatcher vs translator ownership check

`kernel/subsystems/linux/syscall.cpp` is the primary owner for
implemented Linux ABI behavior. `kernel/subsystems/translation/translate.cpp`
must only synthesize unresolved misses.

Run this in CI (or locally) to prevent overlap drift:

```sh
python3 tools/linux-compat/check-gapfill-overlap.py
```

If overlap is deliberate and temporary, add the syscall number (or
`kSys*` symbol) to `tools/linux-compat/gapfill-overlap-allowlist.txt`
with a comment explaining why.

## Scoreboard

The generator emits two explicit coverage metrics:

1. **primary** — syscalls with a live `Do*` handler in
   `kernel/subsystems/linux/syscall.cpp` (name-matched).
2. **effective** — primary coverage plus syscall numbers handled by
   `translation::LinuxGapFill(...)` in
   `kernel/subsystems/translation/translate.cpp`.

Both metrics are written into the generated header preamble and are
printed by the Linux boot log coverage line with explicit
`primary`/`effective` labels.
