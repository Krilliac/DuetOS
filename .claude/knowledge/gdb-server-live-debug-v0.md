# Live debug via in-kernel GDB server — v0

**Type**: Observation + Pattern
**Status**: Active
**Last updated**: 2026-05-04

## Summary

DuetOS exposes a GDB Remote Serial Protocol (RSP) **server**
on COM2 — a complete protocol implementation, not a thin
stub. Under QEMU, COM2 is wired to a TCP server on
localhost:1234 (set in `tools/qemu/run.sh`). An external
debugger — Visual Studio (via Remote GDB), VSCode (via the
C/C++ extension's `cppdbg`), `gdb` directly — connects,
halts the kernel on int3, and gets the full live-debug
interaction surface: step / break / continue / inspect
registers / read+write memory / disassemble, with software
AND hardware breakpoints backed by the existing
`kernel/debug/breakpoints` subsystem.

(Naming: the term "stub" is conventional in GDB / kernel-
debug land for "the protocol speaker on the target side" —
even Linux's complete kgdb is technically a stub by that
definition. We renamed to "server" anyway because the
implementation does enough work — full packet handler set,
target-description XML, swbreak+ semantics, BP-subsystem
integration — that "stub" undersells what's there.)

Pairs with the `.dmp` minidump path (post-mortem). Together they
cover both modes of debugging:

- `.dmp`: snapshot, opens after the fact, no resume.
- GDB stub: live attached session, step / break / continue.

## Wire path

```
+------------+      COM2/0x2F8     +-------+    TCP    +--------+
| kernel     | ⇄ outb/inb 16550  ⇄ | QEMU  | ⇄ :1234 ⇄ | gdb +  |
| gdb_server   |                     | -serial| 127.0.0.1 | host   |
+------------+                     +-------+           +--------+
```

- `kernel/diag/gdb_server.{h,cpp}` — RSP parser, packet handlers,
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
| `DUETOS_GDB_SERVER=ON`  | Wire COM2 to the GDB server at boot. **Default-ON in the x86_64-debug preset** — debug builds are dev-loop builds where you might want to attach at any moment. Release keeps it OFF. Without this flag the server stays dormant and int3 routes to the existing recoverable handler — IMPORTANT, because a server-wired build with no debugger attached would hang on every int3 (the stop loop blocks on a COM2 read that won't arrive). |
| `DUETOS_GDB_DEMO=ON`  | Implies `_SERVER`. Adds a deliberate `int3` right after the IDT phase in `kernel_main` so the dev/AI can exercise attach + inspect + continue **without staging a real crash**. The kernel pauses at the int3 until a debugger attaches AND issues `c` / `D` / `k`. **Test/demo only — not needed for normal use of the GDB server**, just for exercising the attach plumbing without an actual bug to break in on. |

## Packet support

## Backed by `kernel/debug/breakpoints`

GDB's `Z0` / `z0` (software) and `Z1..Z4` (hardware) packets
delegate to `debug::BpInstallSoftware` / `BpInstallHardware`
+ `BpRemove`, getting the existing reinsert-via-TF dance + DR0..3
slot management for free. The BP subsystem grew a new
`BpHitCallback on_hit` field — the GDB stub registers a callback
(`OnGdbBpHit`) that enters the stop loop on every hit. From the
operator's POV: BPs set via the kernel `bp` shell command and
BPs set via GDB coexist in the same registration table; both fire
correctly and don't stomp on each other.

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
  breakpoint set / clear. Backed by `debug::BpInstallSoftware`
  (the kernel BP subsystem owns int3 patching + reinsert).
- `Z1,<addr>,<kind>` / `z1,...` — hardware execute (DR0..3,
  R/W=00, LEN=1). `debug::BpInstallHardware(HwExecute, One)`.
- `Z2,<addr>,<kind>` / `z2,...` — hardware write (R/W=01).
  `debug::BpInstallHardware(HwWrite, ...)`.
- `Z3,<addr>,<kind>` / `z3,...` — hardware read (folded to
  read-write since the BP subsystem doesn't separate read-only).
- `Z4,<addr>,<kind>` / `z4,...` — hardware access (R/W=11).
  `debug::BpInstallHardware(HwReadWrite, ...)`.
- `D` — detach (kernel resumes from the current PC).
- `k` — kill (same effect as detach today; kernel resumes).

Implemented (2026-05-04 follow-on slices):
- **Async stop (Ctrl-C)** via `gdb::PollAsyncStop(frame)`. Hooked
  into `arch::TrapDispatch`'s IRQ branch, after EOI and before
  the resched check. On every IRQ — most commonly the LAPIC
  timer — does one INB on the COM2 LSR; on a 0x03 (ETX) byte,
  routes the IRQ's `TrapFrame` through the same `RouteToStopLoop`
  that #BP / #DB use, with reason `UserHalt`. The resulting GDB
  stop reflects the interrupted code's RIP — exactly "where the
  kernel actually was" — not the polling thread.
- **SMP stop rendezvous** via `arch::SmpStopBroadcastNmi()` /
  `SmpStopReleaseNmi()`. Distinct from `PanicBroadcastNmi` (which
  halts peers forever). Sets a global `g_gdb_stop_active` flag,
  NMI-broadcasts to all-excluding-self. The vector-2 NMI handler
  in `traps.cpp` checks the flag BEFORE the panic-halt path: when
  set, captures `frame->rip / rsp / rflags` into the per-CPU
  `gdb_snapshot_*` fields and parks the live frame pointer in
  `gdb_frozen_frame`, flips `gdb_frozen = 1`, then spins on the
  same flag with `pause` until the BSP clears it. On release, the
  peer iretq's back to whatever it was running.
  `GdbServerEnterAndWait` wraps its existing wait loop in
  `SmpStopBroadcastNmi` / `SmpStopReleaseNmi` and emits each peer's
  snapshot to COM1 so the operator sees what every other CPU was
  doing when the stop landed.
- **Multi-thread GDB visibility** — peer CPUs surface in the
  debugger as separate threads. `qfThreadInfo` / `qsThreadInfo`
  enumerate online CPUs; `qC` reports the current selection; `T<tid>`
  is alive-check; `Hg <tid>` switches the next `g` reply to the
  selected CPU's snapshot (BSP reads the running CPU's
  `g_trap_snapshot`, peers populate
  `g_peer_snapshots[cpu_id]` from `gdb_frozen_frame` on demand).
  Read-only for peers (`G` is gated to the running CPU); `c` / `s`
  always operate on the running CPU's frame so a `Hg <peer>` +
  `c` continues the kernel cleanly.
- **VSCode integration** — `.vscode/launch.json` + `.vscode/tasks.json`
  + `tools/debug/vscode-{start,stop}-qemu.sh`. Two configurations:
  "Attach (live)" boots normally; "Attach (demo int3)" rebuilds
  with `DUETOS_GDB_DEMO=ON` and pauses at the int3 in `kernel_main`.
  Background tasks build, start QEMU, wait for `tcp::1234 ready`,
  then VSCode attaches. PostDebugTask kills the QEMU process so
  cleanup is automatic.

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

- `kernel/diag/gdb_server.{h,cpp}` — RSP parser + handlers + stop
  loop.
- `kernel/arch/x86_64/serial.{h,cpp}` — COM2 init / write / read.
- `kernel/arch/x86_64/traps.cpp` — int3 / #DB → GDB stub route.
- `kernel/core/main.cpp` — boot-time `GdbServerInitCom2` + the
  `DUETOS_GDB_DEMO` int3.
- `kernel/CMakeLists.txt` — `DUETOS_GDB_SERVER` / `DUETOS_GDB_DEMO`
  options.
- `tools/qemu/run.sh` — `-serial tcp::${DUETOS_GDB_PORT}`.
- `tools/debug/duetos-gdb-attach.sh` / `duetos-gdb-cmd.sh` —
  helper scripts.

## Revisit when

- **Writable peer registers** — `G` is gated to the running CPU
  today because writing back across an NMI freeze is risky (peer's
  trap frame on its own kernel stack; modifying it then resuming
  changes the peer's pre-NMI RIP). A future slice could allow it
  if there's a clear use case (e.g. forcing a peer out of a stuck
  spinlock during incident response).
- **`vCont` packet** — GDB's modern resume verb. We accept the
  legacy `c` / `s` — adding `vCont;c:1;s:2` style fanout would let
  the debugger explicitly continue some threads and step others.
  Unblocked once the writable-peer-registers item lands.
- **Hardware-watchpoint coalescing** — the kernel BP subsystem owns
  4 DR slots; setting >4 hardware BPs / watchpoints from GDB
  silently fails the 5th. Mid-priority polish.
