# Crash dump v0 — embedded symbol table + bracketed dump file

**Type**: Observation
**Status**: Active
**Last updated**: 2026-04-25
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
the two markers on COM1". `tools/debug/test-panic.sh` extracts that range into
`build/<preset>/crash-dumps/<UTC-timestamp>.dump` and asserts the dump's shape
against a schema.

## Why embed the symbol table

A post-mortem symbolizer like `llvm-symbolizer` exists (see `tools/debug/symbolize.sh`),
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
2. `tools/build/gen-symbols.sh` reads stage-1's `llvm-nm` output, resolves every
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
  <trap-only: vector + vector_name + rip + cs[ring=N ...] + rflags[...] + rsp + ss[...] + cr2(PF) + all GPRs>
[panic] --- diagnostics ---
  uptime   : 0xNN
  uptime   : <12.345 ms / 1.234 s / 1m 02.345s> since boot
  cpu_id   : 0xNN
  lapic_id : 0xNN
  task_ptr : 0xNN                         (present after SchedInit)
  task     : <name>#<id>                  (resolved via sched::TaskName / sched::TaskId)
  rip      : 0xNN  [fn+0xOFF (file:line)]
  rsp      : 0xNN
  rbp      : 0xNN
  cr0      : 0xNN [PE|MP|...|WP|PG]
  cr2      : 0xNN
  cr3      : 0xNN [pml4=0x... pcid=N]
  cr4      : 0xNN [PAE|PGE|...|SMEP|SMAP]
  rflags   : 0xNN [IF|RF|IOPL=N|...]
  efer     : 0xNN [SCE|LME|LMA|NXE]
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

Trap-path GPR lines (`rax..r15`) carry an inline `[fn+0xOFF (file:line)]`
annotation when the value falls in plausible kernel code range — surfaces
stale callback pointers / vtable spills / saved-RIP residue without forcing
the operator to re-symbolize by hand.

The schema is v1. Bump `kDumpSchemaVersion` in `core/panic.cpp` when the layout
changes in a way a parser would care about. The bit-decoded suffixes (e.g.
`[PE|WP|PG]`) live on the SAME line as the existing `<label> : <hex>` token
sequence, so a parser that anchors on `<label> : 0x[0-9a-f]+` keeps working;
human readers get the meaning for free.

Human-readable decoders live in `kernel/core/diag_decode.{h,cpp}`:
`WriteCr0Bits` / `WriteCr4Bits` / `WriteRflagsBits` / `WriteEferBits` /
`WriteCr3Decoded` / `WriteSegmentSelectorBits` / `WritePageFaultErrBits` /
`WritePteFlags` plus `WriteUptimeReadable` and `WriteCurrentTaskLabel`.
All call only into `arch::Serial*` and the embedded symbol resolver, so
they're safe from panic / IRQ / trap context.

The same readability pass extends throughout the kernel — every log
that previously emitted opaque hex now also surfaces a decoded
interpretation. Coverage by subsystem (each file owns the decoder
nearest its data):

- `kernel/core/log_names.{h,cpp}` — POSIX/Linux: `LinuxSignalName`
  (1..31 + RT range), `LinuxErrnoName` (1..115); Win32:
  `NtStatusName` (curated subset of STATUS_*); flag printers
  `SerialWriteWin32AccessMask` / `SerialWriteOpenFlags` /
  `SerialWriteMmapProt` / `SerialWriteMmapFlags` /
  `SerialWriteInodeMode` / `SerialWriteFatAttr`.
- `kernel/drivers/pci/pci.{h,cpp}` — `PciSubclassDetail` for the
  (class, subclass, prog_if) triple → "SATA AHCI", "USB xHCI",
  "NVMe", etc.
- `kernel/drivers/storage/nvme.{h,cpp}` — `NvmeStatusName` (SCT/SC
  pair → "Internal Error" / "LBA Out of Range" / ...) and
  `NvmeOpcodeName` (admin / NVM op → name). `CSTS.CFS` failure
  log surfaces `[RDY|CFS|SHST|...]`.
- `kernel/drivers/storage/ahci.cpp` — controller summary now
  emits `cap [SNCQ|S64A|...|NP=N]`, `vs <major>.<minor>.<patch>`,
  `ghc [AE|IE|HR]` alongside the raw hex.
- `kernel/drivers/usb/xhci.cpp` — `CompletionCodeName` (TRB
  completion code → "USB Transaction Error" / "Stall Error" /
  "Short Packet" / ...). Every "failed code=" log line wraps it.
- `kernel/drivers/usb/usb.cpp` — `hciver` hex now followed by a
  dotted "(major.minor)" rendering of the BCD field.
- `kernel/mm/paging.cpp` — flag-protect log wraps `flags=0xN` with
  `WritePteFlags` `[P|RW|US|...|NX]`.
- `kernel/loader/pe_loader.cpp` — unsupported reloc-type log resolves
  the IMAGE_REL_BASED_* name (DIR64 / HIGHLOW / ABSOLUTE / ...).
- `kernel/fs/gpt.cpp` — partition-type GUID emits a known-name
  suffix ("EFI System", "Microsoft Basic Data", "Linux Filesystem",
  ...) when the GUID matches the curated table.
- `kernel/fs/ext4.cpp` — root-inode log includes
  `SerialWriteInodeMode` `[REG rwxr-xr-x]` next to `mode=0xN`.
- `kernel/fs/fat32.cpp` — directory entry log surfaces the
  attribute byte as `[A|R|H|S|D|V]` or `[LFN]`.
- `kernel/subsystems/linux/syscall.cpp` — `kill` / `tgkill` log
  wraps the signal number with its `SIGTERM` / `SIGKILL` / ...
  name.

Token shape preserved: every existing `<label>=0x<hex>` (or
`SerialWriteHex(...)`) emission stays exactly where and how it
was; the decoded suffix is appended to the same line. Parsers
that anchor on the hex format are unaffected.

### VA-region tag on raw addresses

Beyond the bit-decoders, every raw VA emitted in a crash dump
(`rip` / `rsp` / `rbp` / `cr2`) now carries a `[region=NAME]`
suffix produced by `core::WriteVaRegion`. The classifier
(`core::ClassifyVa` in `kernel/core/diag_decode.{h,cpp}`) walks
the most specific buckets first — kernel image sections
(`k.text` / `k.rodata` / `k.data` / `k.bss` resolved against the
linker's `_text_start..._bss_end` symbols) before the kernel
arenas (`k.directmap` / `k.mmio` / `k.stack-arena` keyed off
`mm::kKernelVirtualBase` / `kMmioArenaBase` /
`kKernelStackArenaBase`) — then falls back to coarse buckets
for canonical user space, the non-canonical hole, the boot
identity map, and the null page.

Why: hex alone tells you the value; the region tag tells you
what the value MEANS. A `cr2 : 0xFFFFFFFFE0000FF8 [region=k.stack-arena]`
on a #PF instantly reads as "kernel stack overflow"; a
`rsp : 0x00007FFF... [region=user-canonical]` on a kernel-mode
panic is a klaxon for "we panicked while still on the user
stack". Without the tag the operator has to keep paging.h's
memory map in their head while reading the dump.

`core::VaRegionSelfTest()` is invoked from `kernel_main`
alongside the other diag self-tests; it asserts the classifier
on both sides of every bucket transition and on the linker
symbols themselves. If the layout in `paging.h` / `kstack.h` /
the linker script ever drifts, the self-test panics at boot
with a labelled mismatch instead of mis-tagging crash-dump
addresses silently.

Token shape preserved: the region tag is appended to the same
line, after a single space, in `[region=...]` form. Parsers
that anchor on the existing hex (or on the
`[fn+0xOFF (path:LINE)]` symbol annotation that may also
precede it on `rip`) are unaffected; the trailing tag is just
extra trivia they can ignore.

### Boot-time kernel mm-map anchor

`core::WriteMmMapSummary` (in `kernel/core/diag_decode.{h,cpp}`)
emits one bracketed block at boot — `=== DUETOS KERNEL MM MAP ===`
… `=== END KERNEL MM MAP ===` — listing every range a `[region=...]`
tag can resolve to (`k.text` / `k.rodata` / `k.data` / `k.bss` /
`k.directmap` / `k.mmio` / `k.stack-arena`) with `lo .. hi (size)`
for each. Sourced directly from the same linker symbols + paging.h
constants the classifier reads, so a layout change updates both
at once. Every later panic dump's region tags map back to this
single anchor without forcing the operator to consult the linker
script or paging.h.

Invoked from `kernel_main` immediately after `VaRegionSelfTest`
so the summary is in the boot log before any subsystem can
panic.

### Peer-CPU snapshot in crash dumps

Both `core::Panic` and the trap dispatcher's panic path now
broadcast NMI to peer CPUs (the trap path didn't before — peers
kept running while the dispatcher dumped). Each peer's vector-2
handler in `arch/x86_64/traps.cpp` captures its own
`rip` / `rsp` / `current_task` into the per-CPU snapshot fields
(`panic_snapshot_*` in `cpu::PerCpu`) BEFORE halting. The
panicking CPU then iterates every cpu_id via
`arch::SmpGetPercpu` + `arch::SmpCpuIdLimit` and emits each
peer's snapshot in a `[panic] --- peer CPU snapshots ---` block:

```
[panic] --- peer CPU snapshots ---
  cpu#0x00000001 lapic=0x00000001
    rip=0xFFFFFFFF80123ABC  [SchedYield+0x4f (sched/sched.cpp:412)] [region=k.text]
    rsp=0xFFFFFFFFE0102FE0 [region=k.stack-arena]
    task=0xFFFF888001234000
    held locks (1):
      [0x00000000] lock=0xFFFFFFFF80250040  acquired-rip=0xFFFFFFFF8011A2D7  [SchedRunQueueEnqueue+0x27 (...)]
  cpu#0x00000002 lapic=0x00000002  <no NMI snapshot — peer may be hung pre-NMI>
```

`panic_snapshot_valid` flips 0→1 atomically (memory barrier
before the flag write) so a partial capture leaves the flag at 0
and the dumper prints the "<no snapshot>" branch. Peer slots
that were never allocated (`SmpGetPercpu` returns nullptr for
unbound cpu_ids) are skipped silently. BSP-only configurations
get one explicit `(none — single CPU online)` line so the
absence of peers is visible.

### Per-CPU held-locks tracking

`SpinLockAcquire` / `SpinLockRelease` in `kernel/sync/spinlock.cpp`
push / pop a `(lock_ptr, caller_rip)` pair on a per-CPU stack
(`held_locks[8]` + `held_lock_rips[8]` in `cpu::PerCpu`).
Caller RIP is captured via `__builtin_return_address(0)` at
acquire time and resolved through the embedded symbol table
when the dump prints — so each entry reads as
`acquired-rip=0xHEX [fn+0xOFF (file:line)]`.

`DumpDiagnostics` emits the panicking CPU's stack as a `held
locks (N, innermost first):` section right after the raw stack
quads; `DumpPeerCpuSnapshots` includes each peer's stack inline
with that peer's snapshot. A panic with a non-empty held-locks
section usually points straight at the deadlock or invariant
break.

Out-of-order release (`SpinLockRelease` whose lock isn't at the
top of the held stack) is itself a bug shape — `HeldLocksPop`
panics with `release out-of-order` + the offending lock pointer
so the misuse surfaces immediately rather than silently
corrupting the dump's later snapshots.

Tracking is gated on `cpu::BspInstalled()`; acquires before
`PerCpuInitBsp` (frame allocator init) silently skip the
bookkeeping. Overflow past `kPerCpuMaxHeldLocks = 8` keeps the
counter climbing so the dump can show the depth without
clobbering the array — a deep nest is its own diagnostic
signal.

`SpinLockSelfTest` exercises the climb / fall on a 2-deep
nested acquire and asserts the counter returns to baseline on
release.

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
- `kernel/util/symbols_stub.cpp` — stage-1 placeholder (count = 0).
- `tools/build/gen-symbols.sh` — ELF → `symbols_generated.cpp` generator. Depends on
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
- `tools/debug/test-panic.sh` — exercises the `Panic` path. Captures the dump into
  `build/<preset>/crash-dumps/<timestamp>.dump` and asserts its shape.
- `tools/debug/test-trap.sh` — exercises the trap-dispatcher path via `ud2`.
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
