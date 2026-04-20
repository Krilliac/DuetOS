# Crash dump v0 — embedded symbol table + bracketed dump file

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-20
**Commit**: (see current branch HEAD)

## Summary

`core::Panic` now emits a self-contained, symbolicated crash dump bracketed by
`=== CUSTOMOS CRASH DUMP BEGIN ===` / `=== CUSTOMOS CRASH DUMP END ===`. Every
in-kernel code address in the dump (RIP, backtrace frames, stack quads) is
inline-annotated with `function+0xOFFSET (kernel/path/file.cpp:LINE)` using an
embedded symbol table linked into the kernel at build time.

Because there is no kernel filesystem yet, "dump file" means "the bytes between
the two markers on COM1". `tools/test-panic.sh` extracts that range into
`build/<preset>/crash-dumps/<UTC-timestamp>.dump` and asserts the dump's shape
against a schema.

## Why embed the symbol table

A post-mortem symbolizer like `llvm-symbolizer` exists (see `tools/symbolize.sh`),
but it runs **off-box**. That's fine for developer ergonomics — but:

1. On real hardware we often can't pair-ship the ELF + log to the same place.
2. Bug reports from users arrive as serial captures, not DWARF.
3. During early-boot crashes the kernel might be hours into bring-up on a
   mystery box; the dump has to explain itself.

Embedding the function table makes the dump *locally* readable. DWARF line
tables are intentionally not embedded — too much surface area to decode in a
panic path. Function + file + line is the lowest-common-denominator debug unit.

## Two-stage build

The symbol table has to know every function's VA, but *including* the table
changes those VAs. Classic chicken-and-egg. Resolved with a two-stage link:

1. `customos-kernel-stage1.elf` links with `core/symbols_stub.cpp` (empty table).
2. `tools/gen-symbols.sh` reads stage-1's `llvm-nm` output, resolves every
   higher-half text symbol via `llvm-addr2line`, and emits
   `symbols_generated.cpp` — a sorted `{addr, size, line, name, file}` array.
3. `customos-kernel.elf` links the same sources with `symbols_generated.cpp`
   replacing the stub.

**Key invariant — source ordering.** `symbols_stub.cpp` / `symbols_generated.cpp`
MUST be the last source listed in `kernel/CMakeLists.txt`. The linker emits
input sections in command-line order, so the generated TU's `.rodata` lands at
the end of the kernel's `.rodata`. Every other function / rodata VA is
therefore identical between stage 1 and stage 2, which makes the extracted
table valid for the final image.

Text-segment VAs are stable across stages (verified with `llvm-nm`). BSS
addresses shift because rodata grew, but we only resolve *code* addresses in
the crash dump, so BSS drift is irrelevant.

## On-the-wire format

```
=== CUSTOMOS CRASH DUMP BEGIN ===
  version  : 0x0000000000000001
  subsystem: <subsys>
  message  : <message>
  value    : 0xNN                         (present for PanicWithValue only)
  symtab_entries : 0xNN
[panic] --- diagnostics ---
  uptime   : 0xNN
  cpu_id   : 0xNN
  lapic_id : 0xNN
  task_ptr : 0xNN                         (present after SchedInit)
  rip      : 0xNN  [fn+0xOFF (file:line)]
  rsp      : 0xNN
  rbp      : 0xNN
  cr0..cr4 : 0xNN
  rflags   : 0xNN
  efer     : 0xNN
  backtrace (up to 16 frames, innermost first):
    #0x00000000  rip=0xNN  [fn+0xOFF (file:line)]
                 rbp=0xNN
    ...
  stack (0x10 quads from rsp):
    [0xNN] = 0xNN  [fn+0xOFF (file:line)]
    ...
[panic] --- log ring (last 0xNN entries, oldest first) ---
  [I] ...
  ...
=== CUSTOMOS CRASH DUMP END ===
[panic] CPU halted — no recovery.
```

The schema is v1. Bump `kDumpSchemaVersion` in `core/panic.cpp` when the layout
changes in a way a parser would care about.

## Resolver semantics

`customos::core::ResolveAddress(addr, &out)`:

- Binary searches the sorted table for the largest entry with `entry->addr <= addr`.
- Matches if `addr - entry->addr < entry->size`, **except** when `size == 0`:
  zero-sized symbols (asm labels, alias symbols) only match their exact start.
  This avoids silently mis-attributing linker-inserted alignment padding to the
  previous function.
- Returns `(entry, offset)` — caller formats.
- Safe in any context: no allocation, no lock, read-only rodata.

Lookups are O(log N). With ~300 symbols today the longest walk is 9 iterations
— fine on the panic path.

## Files

- `kernel/core/symbols.{h,cpp}` — resolver + output helpers.
- `kernel/core/symbols_stub.cpp` — stage-1 placeholder (count = 0).
- `tools/gen-symbols.sh` — ELF → `symbols_generated.cpp` generator. Depends on
  `llvm-nm` (or `nm`) + `llvm-addr2line` (or `addr2line`). Filter uses
  mawk-compatible awk — no gawk-only builtins like `strtonum`.
- `kernel/core/panic.cpp` — emits the bracketed dump, symbolizes RIP +
  backtrace frames + stack quads.
- `kernel/CMakeLists.txt` — two-stage build wiring.
- `tools/test-panic.sh` — captures the dump into
  `build/<preset>/crash-dumps/<timestamp>.dump` and asserts its shape.

## Cost

- Build: one extra link + one `nm`+`addr2line`+`awk` pass. On the current
  kernel (281 function symbols) the end-to-end cost is <100 ms.
- Kernel image: ~35 KiB of `.rodata` (strings + entry array) at 281 symbols.
  Scales roughly linearly with symbol count.
- Panic path: `WriteAddressWithSymbol` is one binary search + a handful of
  `SerialWrite` calls per address. Already bounded by the 16-frame backtrace
  and 16-quad stack dumps.

## Revisit when

- **DWARF line tables**: if `function+offset` stops being precise enough (e.g.
  heavy inlining in release builds), embed a compressed `.debug_line`
  subset so we can resolve arbitrary RIPs to the true source line, not just
  the function-entry line.
- **SMP-safe serial**: two CPUs panicking simultaneously today interleave the
  dump. Currently tolerable because only one CPU reaches `Panic` in the happy
  path; when we have real multi-CPU drivers firing concurrently, put the dump
  emitter behind a ticket lock + a per-CPU "I'm panicking, everyone stop" IPI.
- **On-disk persistence**: once a filesystem exists, write the captured dump
  to `/var/crash/<timestamp>.dump` (or equivalent) so reboots don't lose it.
  The BEGIN/END markers are already the right framing for an on-disk record.
- **Userland dumps**: when ring-3 lands, a trapping user process should
  produce the same dump shape, but for the faulting process's address space —
  different symbol table (per-binary), same output contract.
