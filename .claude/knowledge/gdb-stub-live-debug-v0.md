# Live debug via in-kernel GDB stub — v0

**Type**: Observation + Pattern
**Status**: Active
**Last updated**: 2026-05-04

## Summary

DuetOS exposes a GDB Remote Serial Protocol (RSP) stub on COM2.
Under QEMU, COM2 is wired to a TCP server on localhost:1234 (set
in `tools/qemu/run.sh`). An external debugger — Visual Studio
(via Remote GDB), VSCode (via the C/C++ extension's `cppdbg`),
`gdb` directly — connects, halts the kernel on int3, and gets
the full live-debug interaction surface: step / break / continue
/ inspect registers / read+write memory / disassemble.

Pairs with the `.dmp` minidump path (post-mortem). Together they
cover both modes of debugging:

- `.dmp`: snapshot, opens after the fact, no resume.
- GDB stub: live attached session, step / break / continue.

## Wire path

```
+------------+      COM2/0x2F8     +-------+    TCP    +--------+
| kernel     | ⇄ outb/inb 16550  ⇄ | QEMU  | ⇄ :1234 ⇄ | gdb +  |
| gdb_stub   |                     | -serial| 127.0.0.1 | host   |
+------------+                     +-------+           +--------+
```

- `kernel/diag/gdb_stub.{h,cpp}` — RSP parser, packet handlers,
  TrapFrame ⇄ register-snapshot plumbing, stop loop.
- `kernel/arch/x86_64/serial.{h,cpp}` — `kCom2Port = 0x2F8`,
  `SerialCom2Init` / `SerialCom2WriteByte` /
  `SerialCom2ReadByteBlocking`. No locking (single-flight by
  construction — the stop loop owns the CPU).
- `tools/qemu/run.sh` — `-serial tcp::${DUETOS_GDB_PORT:-1234},
  server=on,wait=off` adds the second serial port as a TCP
  server.

## Build flags

| Flag | Effect |
|------|--------|
| `DUETOS_GDB_STUB=ON`  | Wire COM2 to the stub at boot. Without this flag the stub stays dormant and int3 routes to the existing recoverable handler — IMPORTANT, because a stub-wired build with no debugger attached would hang on every int3 (the stop loop blocks on a COM2 read that won't arrive). |
| `DUETOS_GDB_DEMO=ON`  | Implies `_STUB`. Adds a deliberate `int3` right after the IDT phase in `kernel_main` so the dev/AI can exercise attach + inspect + continue without staging a real crash. The kernel pauses at the int3 until a debugger attaches AND issues `c` / `D` / `k`. |

## Packet support

Implemented (live):
- `qSupported` — advertises `PacketSize=1000;swbreak+;qXfer:features:read+`.
- `qXfer:features:read:target.xml:OFF,LEN` — serves an inline
  target description with `i386:x86-64` core + sse features
  (24 GPR/segment regs + zeros for FPU/SSE so amd64-tdep
  validates). Without this, GDB falls back to the full default
  amd64 description (~150 regs incl. AVX-512) and rejects our
  `g` reply.
- `?` — halt reason (always `S05` SIGTRAP).
- `g` / `G` — read / write all registers from the published
  snapshot.
- `m<addr>,<len>` / `M<addr>,<len>:<hex>` — read / write
  arbitrary kernel-VA memory (canonical-address gated;
  out-of-canonical returns `E14`).
- `H<g|c><thr>` — set thread (single-thread, replies `OK`).
- `c` — continue. Clears RFLAGS.TF.
- `s` — single-step. Sets RFLAGS.TF; the next instruction
  raises #DB which re-enters the stop loop.
- `Z0,<addr>,<kind>` / `z0,<addr>,<kind>` — software (int3)
  breakpoint set / clear. 32-slot table; rejects on overflow.
- `D` — detach (kernel resumes from the current PC).
- `k` — kill (same effect as detach today; kernel resumes).

Not implemented: `Z1..Z4` (hardware breakpoints / watchpoints —
fall through to the empty reply, GDB synthesises them via `M`
/ `Z0`), async stop on Ctrl-C (no IRQ-driven RX yet).

## TrapFrame plumbing

`kernel/arch/x86_64/traps.cpp` calls
`gdb::HandleSoftwareBreakpoint(frame)` after the existing
`debug::BpHandleBreakpoint(frame)` returns false, and
`gdb::HandleDebugException(frame)` after `BpHandleDebug(frame)`
returns false. Both helpers:

1. Bail (return false) when no GDB sink is wired — the trap
   then falls through to the existing log-and-continue path,
   so non-GDB builds behave exactly as before.
2. Mirror the TrapFrame's GPRs + `cs/ss/rflags/rip` into the
   global `GdbRegSnapshot` (data segments sampled live).
3. For #BP, decrement the snapshot's RIP by 1 — int3 is a
   trap-class fault, RIP saved post-instruction; GDB needs RIP
   AT the int3 byte for the resume-after-z0 sequence to
   re-execute the original instruction.
4. For #DB, clear RFLAGS.TF before the resume so a single-step
   doesn't immediately re-step unless GDB asks again with `s`.
5. Publish the snapshot, call `EnterAndWait(reason)`, then
   write any GDB-edited fields back to the TrapFrame (so a `set
   $rax = 0xN` from the GDB prompt actually takes effect on
   resume).

## AI-friendly helpers

```
tools/debug/duetos-gdb-attach.sh   # interactive session
tools/debug/duetos-gdb-cmd.sh      # batched non-interactive
```

`duetos-gdb-cmd.sh` is the path an AI / scripted workflow uses:

```
# Default inspection (info reg + x/16i $rip + x/16xg $rsp + bt 10):
$ tools/debug/duetos-gdb-cmd.sh

# Custom commands:
$ tools/debug/duetos-gdb-cmd.sh "info reg rax rdi" "p/x g_some_var"

# From a script file:
$ tools/debug/duetos-gdb-cmd.sh -f session.gdb
```

What it does:
1. Configures + builds `DUETOS_GDB_DEMO=ON` (and resets to OFF
   on exit so subsequent normal builds don't keep halting).
2. Starts QEMU in the background, waits for the COM2 TCP server.
3. Polls the QEMU log for the `[gdb-demo] firing int3` line so
   it doesn't connect before the kernel actually pauses.
4. Runs `gdb -batch` against the kernel ELF + the supplied
   commands, then `detach` + `quit`.
5. Prints the GDB output between `----8<----` markers and
   tears down QEMU.

End-to-end exit code reflects the GDB invocation status; stdout
shows the GDB output.

## Verified end-to-end (under TCG)

- Connect resolves rip/rsp/rbp + every GPR + segment selectors
  to live trap-frame values.
- GDB names the source line (`kernel_main … main.cpp:671`) and
  the function offset (`kernel_main+740`).
- Disassembly works around RIP from the captured kernel image.
- Stack walks back to `long_mode_entry` (boot.S:351) with full
  symbol resolution before falling into the boot-stack zeros.
- `detach` resumes the kernel cleanly; the
  `[gdb-demo] resumed from GDB int3` line appears on COM1
  immediately after.

## Why two channels (COM2 + minidump debugcon)

| Concern | Channel | Why |
|---|---|---|
| Live debug (step / break) | COM2 / GDB RSP / TCP | Bidirectional, low-latency, debugger-driven. |
| Post-mortem snapshot | port 0xE9 / debugcon / host file | Unidirectional, fire-and-forget at panic. |
| Human boot log | COM1 / `-serial stdio` | Always-on, narrative log. |

Three independent channels stay out of each other's way. A
panic dump never races with a live GDB session because they
use different ports.

## Real-hardware caveat

`-serial tcp::1234` is QEMU-only. On real PCs COM2 is a
physical serial port at 0x2F8, so attaching means a
null-modem cable + a host-side UART. The kernel-side stub is
unchanged; only the host-side transport is "physical UART"
instead of "QEMU TCP server". The helper scripts assume QEMU.

## Files

- `kernel/diag/gdb_stub.{h,cpp}` — RSP parser + handlers + stop
  loop.
- `kernel/arch/x86_64/serial.{h,cpp}` — COM2 init / write / read.
- `kernel/arch/x86_64/traps.cpp` — int3 / #DB → GDB stub route.
- `kernel/core/main.cpp` — boot-time `GdbStubInitCom2` + the
  `DUETOS_GDB_DEMO` int3.
- `kernel/CMakeLists.txt` — `DUETOS_GDB_STUB` / `DUETOS_GDB_DEMO`
  options.
- `tools/qemu/run.sh` — `-serial tcp::${DUETOS_GDB_PORT}`.
- `tools/debug/duetos-gdb-attach.sh` / `duetos-gdb-cmd.sh` —
  helper scripts.

## Revisit when

- **Async stop (Ctrl-C)**: today the stop loop is purely
  reactive — the kernel only enters it on int3 / #DB. To pause
  a freely-running kernel on demand we need an IRQ-driven COM2
  RX path that detects a 0x03 byte from GDB and triggers a
  software breakpoint at the next safe instruction.
- **Hardware breakpoints / watchpoints**: `Z1..Z4` need DR0..3
  + DR7 setup and a #DB trigger-cause decode. Useful for
  data-only breakpoints (catch a variable change without
  patching code).
- **Per-CPU stop on SMP**: current single-CPU model freezes
  the calling CPU only. Multi-CPU live debug needs an NMI
  broadcast on stop entry (mirrors `core::PanicBroadcastNmi`).
- **Source-line stepping**: GDB's `next` already works because
  symbols + DWARF in the kernel ELF give it line tables; the
  stub doesn't need to do anything extra. A cleaner integration
  with VSCode's launch.json would still be nice.
