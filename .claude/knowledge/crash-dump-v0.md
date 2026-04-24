# Crash dump v0 — embedded symbol table + bracketed dump file

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-20
**Commit**: (see current branch HEAD)

## Summary

Both `core::Panic` and `arch::TrapDispatch` (CPU-exception path) emit a
self-contained, symbolicated crash dump bracketed by
`=== DUETOS CRASH DUMP BEGIN ===` / `=== DUETOS CRASH DUMP END ===`. Every
in-kernel code address in the dump (RIP, backtrace frames, stack quads) is
inline-annotated with `function+0xOFFSET (kernel/path/file.cpp:LINE)` using an
embedded symbol table linked into the kernel at build time.

The two entry points share one emission contract via the public API pair
`core::BeginCrashDump(subsystem, message, optional_value)` + `core::EndCrashDump()`
so a parser that handles one handles the other. The differences are in the
body: `Panic` emits control registers + diagnostics; `TrapDispatch` also emits
every GPR (`rax..r15`) captured in the TrapFrame, which is worth a lot when the
fault is register-dependent (bad `cr2`, garbage `rdi`, etc.).

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

1. `duetos-kernel-stage1.elf` links with `core/symbols_stub.cpp` (empty table).
2. `tools/gen-symbols.sh` reads stage-1's `llvm-nm` output, resolves every
   higher-half text symbol via `llvm-addr2line`, and emits
   `symbols_generated.cpp` — a sorted `{addr, size, line, name, file}` array.
3. `duetos-kernel.elf` links the same sources with `symbols_generated.cpp`
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
=== DUETOS CRASH DUMP BEGIN ===
  version  : 0x0000000000000001
  subsystem: <subsys>                     (e.g. "arch/traps", "test/panic-demo")
  message  : <message>                    (vector mnemonic for traps; caller string for Panic)
  value    : 0xNN                         (present for PanicWithValue + every trap; error_code on traps)
  symtab_entries : 0xNN
  <trap-only: vector + rip + cs + rflags + rsp + ss + cr2(PF) + all GPRs>
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
=== DUETOS CRASH DUMP END ===
[panic] CPU halted — no recovery.
```

The schema is v1. Bump `kDumpSchemaVersion` in `core/panic.cpp` when the layout
changes in a way a parser would care about.

## Resolver semantics

`duetos::core::ResolveAddress(addr, &out)`:

- Binary searches the sorted table for the largest entry with `entry->addr <= addr`.
- Matches if `addr - entry->addr < entry->size`, **except** when `size == 0`:
  zero-sized symbols (asm labels, alias symbols) only match their exact start.
  This avoids silently mis-attributing linker-inserted alignment padding to the
  previous function.
- **Post-end slack**: a `[[noreturn]]` call to `Panic` leaves
  `__builtin_return_address(0)` pointing one byte past the caller's
  claimed end (the byte AFTER the trailing `call` instruction). The
  resolver treats `offset == size` as still-inside, matching how
  `addr2line` reports it. Without this slack every deliberate-panic
  RIP resolves to `??` — found the hard way when the first pass of
  `test-panic.sh` failed on the RIP line while every other address
  resolved cleanly.
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
- `kernel/core/panic.{h,cpp}` — emits the bracketed dump, symbolizes RIP +
  backtrace frames + stack quads. Exposes `BeginCrashDump` / `EndCrashDump`
  for reuse by the trap dispatcher.
- `kernel/arch/x86_64/traps.cpp` — CPU-exception path wraps its register +
  GPR dump in the same BEGIN/END markers with `subsystem: arch/traps`,
  `message: <vector mnemonic>` (e.g. `#PF Page fault`, `#UD Invalid opcode`),
  `value: <error_code>`, and symbolized `rip`.
- `kernel/CMakeLists.txt` — two-stage build wiring. Gates `DUETOS_PANIC_DEMO`
  (deliberate `Panic()` at end of `kernel_main`) and `DUETOS_TRAP_DEMO`
  (deliberate `ud2` at end of `kernel_main` → `#UD`).
- `tools/test-panic.sh` — exercises the `Panic` path. Captures the dump into
  `build/<preset>/crash-dumps/<timestamp>.dump` and asserts its shape.
- `tools/test-trap.sh` — exercises the trap-dispatcher path via `ud2`.
  Captures into `<timestamp>-trap.dump` and asserts the trap-specific fields
  (`subsystem: arch/traps`, `#UD` message, symbolized RIP). Kept separate so
  a regression in one path can't masquerade as a regression in the other.

## Cost

- Build: one extra link + one `nm`+`addr2line`+`awk` pass. On the current
  kernel (281 function symbols) the end-to-end cost is <100 ms.
- Kernel image: ~35 KiB of `.rodata` (strings + entry array) at 281 symbols.
  Scales roughly linearly with symbol count.
- Panic path: `WriteAddressWithSymbol` is one binary search + a handful of
  `SerialWrite` calls per address. Already bounded by the 16-frame backtrace
  and 16-quad stack dumps.

## Why two entry points, one contract

The panic path and the trap path are semantically different kinds of crash —
`Panic` is the kernel noticing its own invariant violation, a trap is the CPU
telling the kernel "you asked me to do something illegal". They come in
through different code paths (direct call vs. IDT → isr_common → TrapDispatch)
and carry different data (panic captures call-site frame; trap captures the
hardware TrapFrame including all GPRs + error code + segment selectors).

Sharing `BeginCrashDump` / `EndCrashDump` means:

1. Host-side tooling (`test-panic.sh`, `test-trap.sh`, and anything built later
   that harvests dumps from serial captures) uses **one** extraction routine.
2. The schema version field tells a parser what fields to expect — bumping it
   is a single point of coordination.
3. The symbol-resolution path is identical: whatever `WriteAddressWithSymbol`
   does for a Panic RIP, it does for a trap RIP.

Keeping two test scripts (`test-panic.sh` + `test-trap.sh`) was deliberate: a
regression in `TrapDispatch` shouldn't be masked by a passing Panic test, and
vice versa. Each script builds with its own deliberate-crash flag, boots, and
asserts the path-specific shape.

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
