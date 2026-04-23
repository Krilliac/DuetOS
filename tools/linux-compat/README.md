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
python3 tools/linux-compat/gen-linux-syscall-table.py \
    --csv tools/linux-compat/linux-syscalls-x86_64.csv \
    --out kernel/subsystems/linux/linux_syscall_table_generated.h
```

Commit both the CSV and the regenerated header. The build does
NOT invoke Python; the header is checked in.

## Scoreboard

The generator tallies how many syscalls have a live mapping to a
`Do*` handler in `syscall.cpp` (by name match). The emitted header
contains both the sorted syscall row table and a dense by-number
index (`nullptr` for unknown holes), so `LinuxSyscallLookup(nr)`
is O(1) on both hit and miss paths. A boot-time log line prints
"linux ABI coverage: N/M" once the dispatcher pulls the new table in.
