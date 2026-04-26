# Process + capability model — v0

**Type:** Observation
**Status:** Active
**Last updated:** 2026-04-20

## What

A `core::Process` is the unit that owns user-visible state: a private
`mm::AddressSpace` (from the per-process-AS slice) + a `CapSet`
(u64 bitmask) + pid + name. Every ring-3-bound `Task` belongs to
exactly one Process; kernel-only Tasks keep `process == nullptr`.
The scheduler caches `process->as` on the Task so the CR3 flip on
context-switch remains a single pointer load.

Capabilities are a u64 bitmask of privileges. v0 defines one cap:

- `kCapSerialConsole` — permits `SYS_WRITE(fd=1)`.

The syscall dispatcher calls `CurrentProcess()->caps.bits & (1 << cap)`
before each privileged operation. A denial logs
`[sys] denied syscall=<N> pid=<P> cap=<NAME>` and returns `-1` to
user mode.

Two profiles are wired as constexpr helpers:

- `CapSetEmpty()` — zero caps. The sandbox profile.
- `CapSetTrusted()` — every defined cap. For kernel-shipped userland.

## Files

- `kernel/core/process.{h,cpp}` — `Cap`, `CapSet`, `CapSetHas/Add`,
  `CapSetEmpty/Trusted`, `Process`, `ProcessCreate/Retain/Release`,
  `CurrentProcess`, `CapName`.
- `kernel/sched/sched.{h,cpp}` — `Task::process` pointer,
  `SchedCreateUser(..., core::Process*)`, `TaskProcess(Task*)`.
  Reaper calls `ProcessRelease` on death; Process destructor
  transitively releases its AS.
- `kernel/syscall/syscall.cpp` — `DoWrite` gates on `kCapSerialConsole`
  before the SMAP copy path.
- `kernel/proc/ring3_smoke.cpp` — spawns two trusted tasks + one
  sandbox task. All three use the same user-code payload; only
  the sandbox's `SYS_WRITE` is denied (logged + -1 returned). The
  user payload ignores the return value so `SYS_YIELD` and
  `SYS_EXIT` still run — demonstrates clean sandbox semantics.

## Boot output (trimmed)

```
[proc] create pid=0x1 name="ring3-smoke-A" caps=0x2
[proc] create pid=0x2 name="ring3-smoke-B" caps=0x2
[proc] create pid=0x3 name="ring3-smoke-sandbox" caps=0x0
Hello from ring 3!           <- pid=1
Hello from ring 3!           <- pid=2
[sys] denied syscall=SYS_WRITE pid=0x3 cap=SerialConsole
[proc] destroy pid=0x1
[proc] destroy pid=0x2
[proc] destroy pid=0x3
```

## Design notes

- **Cap numbering is ABI.** A process image with a "requested caps"
  manifest stored on disk would break if we renumbered. Always
  add at the end of the enum; never reuse a retired number.
- **Empty cap set isn't `1 << kCapNone`.** `kCapNone = 0` is a
  sentinel — any `1 << 0` bit would shadow it, so real caps start
  at `1`. `CapSetHas(s, kCapNone)` is always false.
- **Sentinel `kCapCount`.** Last enum entry, not a live cap.
  `CapSetTrusted` loops `[1 .. kCapCount)` to build the full set.
- **Single refcount on the Process.** Process owns exactly one AS
  reference. Task holds one Process reference. Reaper drops the
  Process reference; when the last task of a process exits, the
  AS destructor runs inline.
- **Kernel threads have no Process.** SchedCreate leaves
  `t->process = nullptr`. Reaper's `process != nullptr` guard
  lets kernel threads (idle, reaper, workers, keyboard reader)
  fall through with no state change.

## Open issues / next bites

1. **Cap-gate the other syscalls.** SYS_GETPID / SYS_YIELD / SYS_EXIT
   are legitimately unprivileged. But once we add a real syscall
   surface (file I/O, process spawn, IPC), each new number needs
   a matching cap.
2. **A sandbox-denial count in CapSet or per-Process.** Useful for
   detecting a hostile EXE that retries a blocked syscall in a
   loop — "this process hit 1000 cap denials in the last second"
   is enough signal to kill it.
3. **Cap-table revocation.** A process should be able to permanently
   drop a cap (equivalent to `prctl(NO_NEW_PRIVS)`). Trivial to
   add — `CapSetRemove` + a self-syscall.
4. **Per-cap resource metadata.** A `kCapFile` cap alone is useless;
   it needs "which files?" attached. That argues for caps as
   tagged pointers to handle tables rather than pure bitmask bits.
   v0 ships with bitmask only because SYS_WRITE's console is the
   only guarded resource. When VFS lands, caps become handle
   tables.
5. **Process spawn syscall.** Today only the kernel spawns ring-3
   tasks (from ring3_smoke). A real userland needs a cap-gated
   `SYS_SPAWN` that takes an image + a caps manifest; the spawning
   process can only hand over caps it already holds.
