# Debugger

DuetOS ships a native interactive debugger that bundles process inspection, live memory view + edit, register view + edit, breakpoint management, byte-pattern scan ("Cheat-Engine"-style), watchlist, and instruction-level disassembly into one operator surface.

The debugger is reachable two ways:

- **GUI** — `Debugger` window registered by the kernel app at boot (700×500, Slate-10 chrome).
- **Shell** — `dbg <subcommand>` from the kernel shell. Identical operations to the GUI, plain-text output to the console.

Both surfaces dispatch through the same `dbg_core` helpers (`kernel/apps/dbg_core.{h,cpp}`), so they cannot drift.

## Capability gating

Mutating operations require `kCapDebug` on the calling shell session:

- `dbg bp add | rm | resume | step`
- `dbg watch add | rm`
- (Future) any `dbg mem-write` syscall surface.

Read-only operations (`dbg ps`, `dbg mem`, `dbg dis`, `dbg bp list`, `dbg watch list`, `dbg regs`, `dbg scan`) work without `kCapDebug`. The GUI app itself runs in kernel context and is implicitly trusted; the cap gate stays in place for the eventual ring-3 wrapper (phase 2).

## GUI keybindings

| Key            | Action                                              |
| -------------- | --------------------------------------------------- |
| `1` … `9`      | Quick-jump to tab 1..9 (Procs / Mem / Regs / BP / Watch / Scan / Disasm / System / Symbols) |
| `0`            | Quick-jump to tab 10 (Threads)                      |
| `Tab`          | Cycle to the next tab                               |
| `Esc`          | Release focus (cycles to the next compositor window)|
| `j` / `J`      | Scroll the active tab down                          |
| `k` / `K`      | Scroll the active tab up                            |
| `Enter`        | In Procs tab: pick the highlighted row as the current target (row 0 is `<kernel>`) |

## Tabs

### Processes

Lists every live process with PID, state (`run` / `zomb`), cumulative ticks, and name. Row 0 is always the `<kernel>` pseudo-target — selecting it routes Memory / Disasm / Scan reads to kernel addresses (bounded by `PlausibleKernelAddress`, no AS walks). Press `Enter` to set the highlighted row as the current target.

### Memory

Hex+ASCII dump centred on the current memory cursor. The cursor advances 16 bytes per `j` / `k`. Reads route through `dbg_core::ReadMem`, which walks the target's address space directly (or delegates to `BpReadMem` if the target is parked on a breakpoint).

### Regs

Pretty-print of the saved `arch::TrapFrame` for the task currently parked on the active breakpoint. All 16 GPRs plus `RIP` and `RFLAGS`. Mutating from the GUI is not yet wired (phase 2); use the shell `dbg regs` to read and the underlying `BpWriteRegs` from kernel code to mutate.

### Breakpoints

Lists every installed breakpoint with ID, kind (`sw` / `hwx` / `hww` / `hwrw`), address, hit count, and parked-task state. Add / remove / resume / step from the shell — the GUI is read-only for v0.

### Watch

Up to 32 user-added rows; values are refreshed on every compositor tick (~250 ms). Each row records `{pid, addr, type, name}` and the most recently observed value. Type selects the rendering — `u8` / `u16` / `u32` / `u64` / `i32` / `i64` / `bytes`.

### Scan

First-pass byte-pattern scan. Run from the shell (`dbg scan <pid> <hexbytes>`); the GUI tab is a stub that points at the shell command. v0 limit: hits are capped at 256 per scan, and a needle straddling a 4 KiB page boundary will not match (known GAP — extend `dbg_core::ScanBytes` if needed).

### Disasm

Full textual disassembly of the current target at the current cursor. Each row shows `addr  hex-bytes  mnemonic operands`. Backed by the in-house decoder at `kernel/debug/disasm.{h,cpp}` covering the common x86_64 subset:

- `MOV` (all forms), `LEA`, `PUSH`, `POP`
- ALU: `ADD` / `OR` / `ADC` / `SBB` / `AND` / `SUB` / `XOR` / `CMP`, `TEST`
- `INC`, `DEC`, `NEG`, `NOT`, `MUL`, `IMUL`, `DIV`, `IDIV`
- `CALL`, `JMP`, all `Jcc`
- `RET`, `RET imm16`, `LEAVE`
- `INT3`, `INT imm8`, `IRETQ`, `SYSCALL`, `SYSRET`
- `HLT`, `CLI`, `STI`, `CLD`, `STD`, `NOP` (single + multi-byte)
- SSE/SSE2 two-XMM-operand subset: `MOV{UP,AP,DQ}{S,D}`, `MOV{SS,SD}`, the scalar+packed arith family (`ADD`/`SUB`/`MUL`/`DIV`/`MIN`/`MAX`/`SQRT`/`CVT`, prefix-selected `ss`/`sd`/`ps`/`pd`), `U/COMIS{S,D}`, `AND`/`ANDN`/`OR`/`XORP{S,D}`, `P{XOR,AND,ANDN,OR}`, `UNPCKL/H P{S,D}`
- SSE XMM↔GPR forms: `MOVD`/`MOVQ`, `CVTSI2SS`/`SD`, `CVT(T)SS2SI`/`SD2SI`, `MOVNTI`
- `MOV{L,H}PS`/`MOV{L,H}PD`, `MOVLHPS`/`MOVHLPS`

Bytes outside the covered set render as `db 0xXX  ; <class>` rows (where `<class>` is `vex` / `evex` / `x87` / `prefix` / `rex` / `unknown` / etc.). This keeps instruction boundaries honest — the operator sees what's actually there, not a fabricated guess.

GAPs (not yet covered, marked in `disasm.cpp`):

- The integer-SIMD `PUNPCK`/`PSHUF`/`PADD`/`PCMP`/`PMOVMSKB` family, the SSE3 dup moves (`MOVDDUP`/`MOVS[LH]DUP`)
- AVX / VEX / EVEX, x87
- The full string-op family (`REP MOVS` / `SCAS` / `CMPS`)
- Far calls / jumps

If those bytes show up frequently in real workloads, vendoring Capstone or Zydis is the planned escape hatch.

### System

Read-only one-page snapshot of system-wide kernel state: heap pool / used / free / alloc-count / free-count / largest-free-run, scheduler context-switch count / live / sleeping / blocked / created / exited / reaped task counts, total + idle ticks, embedded symbol-table count, and the kernel `.text` start/end VAs. Refreshed on every recompose.

### Symbols

Browse the embedded kernel `.symtab`. Each row shows `addr  size  name`. Use `j` / `k` to scroll. The tab itself lists the first window with no filter; use `dbg syms <substring>` from the kernel shell for case-sensitive filtering.

### Threads

Per-task enumeration. DuetOS schedules at task granularity, so a multi-threaded process appears as multiple rows here while the Processes tab sees it once. Each row shows TID, state (`ready` / `RUN` / `sleep` / `block` / `DEAD`), priority, ticks-run, an asterisk for the currently-running task, and the task name.

## Shell command reference

```
dbg ps                                                list every live process
dbg threads                                           list every task
dbg sysinfo                                           heap + scheduler + text-range overview
dbg syms      [filter]                                browse the kernel symbol table (filter is a substring)
dbg mem       <pid|kernel> <addr> [len]               hex+ASCII dump (default 64 B, max 256 B)
dbg dis       <pid|kernel> <addr> [rows]              disassembly (default 16 rows, max 32)
dbg bp        list                                    enumerate every BP
dbg bp        add <addr> <kind> <len> [suspend]       install BP (kind=sw|hwx|hww|hwrw)
dbg bp        rm <id>                                 remove BP
dbg bp        resume <id>                             resume a parked task
dbg bp        step <id>                               single-step a parked task
dbg regs      <bp_id>                                 print the saved trap frame
dbg watch     add <pid|kernel> <addr> <type> <name>   add a watch row
dbg watch     list                                    enumerate the watchlist
dbg watch     rm <slot>                               remove a watch row
dbg scan      <pid|kernel> <hexbytes>                 byte-pattern scan
```

`<pid|kernel>` accepts a numeric PID or the literal `kernel` (or `k`) — the latter routes the operation to kernel-address space. For `mem` / `dis` / `scan`, kernel-mode reads are gated by `PlausibleKernelAddress` (higher-half direct map + MMIO arena only); for `scan kernel`, the sweep is bounded by the kernel `.text` range. Kernel-mode `dbg mem`/`dis` cannot WRITE — patching `.text` is the breakpoint subsystem's job (it owns the W-window dance under spinlock); arbitrary kernel-`.data` writes are a footgun even with `kCapDebug`.

`<addr>` is parsed by `ParseU64Str` — accepts decimal, `0x`-prefixed hex, and (sub)slot indexes. `<hexbytes>` is a contiguous lowercase / uppercase hex string with optional spaces (`deadbeef` and `de ad be ef` are equivalent). `<type>` for `dbg watch add`: `u8` / `u16` / `u32` / `u64` / `i32` / `i64` / `bytes`.

## Reusing existing infrastructure

The debugger does not duplicate any existing primitives. It composes:

- `kernel/debug/breakpoints.*` for BP install / remove / resume / step / register snapshot.
- `kernel/diag/gdb_server.*` is independent (off-target debugging via GDB remote serial protocol stays the way to do source-level work today).
- `kernel/util/symbols.*` for name resolution on disassembled call/jump targets.
- `kernel/mm/address_space.*` for cross-AS memory access via `AddressSpaceLookupUserFrame` + the kernel direct-map alias.
- `kernel/sched/sched.h` for `SchedFindProcessByPid` lookups.

Net-new kernel surface in this slice:

- `BpWriteRegs(id, frame)` — sanitised mutate of a parked task's saved trap frame (`kernel/debug/breakpoints.cpp`).
- `kernel/debug/disasm.{h,cpp}` — in-house x86_64 single-instruction decoder.
- `kernel/apps/dbg.{h,cpp}` + `dbg_core.{h,cpp}` + `dbg_render.cpp` + `dbg_internal.h` — the app itself.
- `kernel/shell/shell_dbg.cpp` — the `dbg` shell command.

## Boot-time self-tests

Two structural log lines confirm the subsystem came up clean:

- `[smoke] disasm=ok rows=N` — decoder fixture passed every expected row.
- `[smoke] dbg=ok rows=N` — window registered, process enumerator returned ≥1 row, watch round-trip succeeded.

CI greps for both lines once it's wired up. Failure paths emit `[smoke] disasm=FAIL row=X` or `[smoke] dbg=FAIL stage=<which>` so the regression points at the specific stage that broke.

## Verification end-to-end

1. Build clean: `cmake --build build/x86_64-release --parallel $(nproc)`.
2. Boot the kernel; check serial for `[smoke] disasm=ok` and `[smoke] dbg=ok`.
3. From the kernel shell:
   - `dbg ps` — should show the boot task plus any PE smoke-test processes.
   - `dbg mem <pid> <addr> 64` — should print four hex+ASCII rows.
   - `dbg dis <pid> <addr> 8` — should print 8 mnemonic rows.
   - `dbg bp add 0xFFFFFFFF80000000 hwx 1 suspend` — should return a non-zero ID.
   - `dbg bp list` — should show the BP just installed.
4. Open the GUI: bring the `Debugger` window to focus, press `1` … `7` to walk every tab.

## Safety: unsafe-zone blocklist + re-entrancy guard

A breakpoint set inside a kernel path that the BP handler itself reaches will recurse — `int3` inside the trap dispatcher / klog / panic / scheduler / heap allocator / spinlock primitives means the BP-hit handler tries to log → re-enters the patched code → triple-faults on UP, deadlocks on SMP. To prevent that, the breakpoint subsystem ships two safety nets.

### Install-time blocklist

At `BpInit`, the kernel walks the embedded `.symtab` and caches `[addr, addr+size)` ranges for every function whose demangled name contains any of the curated unsafe-substrings (the BP handlers themselves, the symbol resolver, `SerialWrite`, klog emitters, panic / trap dispatchers, scheduler core, spinlock primitives, `KMalloc` / `KFree`, frame allocator). `BpInstallSoftware` and `BpInstallHardware` (HW-execute only) reject installs that target one of those ranges with `BpError::UnsafeZone`.

To override — for research, deep kernel debugging, or paths the curated list misses — pass `BpInstallFlags::AllowUnsafe` to the C++ API, or append the literal `unsafe` to the shell command:

```
dbg bp add 0xffffffff80123456 hwx 1 suspend unsafe
```

`dbg bp zones` lists every currently-blocklisted range. The list is populated once at boot and is stable until reboot.

The list is conservative — substrings are picked to match unique tokens (e.g. `Schedule(`, `BpHandleBreakpoint`) so a vague match doesn't over-block a legitimate target.

### Trap-handler re-entrancy guard

A single `g_handler_depth` counter (per-CPU on SMP, when SMP-mode lands) wraps the synchronous portion of `BpHandleBreakpoint` and `BpHandleDebug`. If the counter is > 0 on entry, the handler:

- emits one `RECURSION: nested handler entry at addr=…` warning;
- claims the trap and returns;
- does NOT log a normal hit, run the on-hit callback, or attempt suspend.

The counter is decremented before `MaybeSuspend` runs — once the synchronous danger window (klog + `PokeByte` under `g_lock`) has closed, peer tasks firing BPs while the parked task is on its wait queue are handled normally. The guard's job is exclusively to break the same-CPU synchronous recursion that would otherwise stack-overflow into a triple-fault.

### What's still possible

These safety nets reduce the blast radius but don't make BP-on-anything safe:

- A HW write/read-write watch on a hot kernel data slot (e.g. `g_total_ticks`) is **not** blocked — it's an arms-length data tap that doesn't recurse the handler. But with `suspend_on_hit` it can park the box if it fires faster than the operator can resume.
- A BP installed via `unsafe` override on the trap dispatcher or the panic path will still triple-fault if it actually fires.
- Kernel-data writes via `dbg watch` are read-only by design; writes happen only through `BpWriteRegs` (sanitised) or, if you reach for it, the breakpoint subsystem's `PokeByte` (kernel-`.text` only, under spinlock).

If you want a hot path BP'd anyway, the safest workflow is: install with `unsafe`, observe one fire under serial-only logging, remove. Don't `suspend_on_hit` an unsafe target.

## Out of scope (deliberate)

- DWARF / source-level stepping. Use the GDB stub for that.
- Lua / scripted breakpoint conditions.
- Multi-CPU IPI broadcast for HW BPs (already a known phase-2 limit of `breakpoints.cpp`).
- A "Ghidra-style" decompiler / code-graph view. That is a separate project.
- GPU acceleration — the framebuffer compositor is fast enough at 700×500 / 8×8 font.
