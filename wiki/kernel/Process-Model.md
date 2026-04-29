# Process Model

> **Audience:** Kernel hackers, subsystem authors
>
> **Execution context:** Kernel — `core::Process` lifecycle
>
> **Maturity:** v0 stable

## Overview

`core::Process` is the unit that owns user-visible state: a private
`mm::AddressSpace`, a `CapSet` (u64 bitmask of privileges), pid, name,
VFS root, frame budget, and CPU-tick budget. Every ring-3-bound `Task`
belongs to exactly one Process; kernel-only Tasks keep
`process == nullptr`.

The scheduler caches `process->as` on the `Task` so the CR3 flip on
context switch remains a single pointer load.

## Files

- `kernel/core/process.{h,cpp}` — `Process`, `CapSet`, `CapSetEmpty`,
  `CapSetTrusted`, `ProcessCreate / Retain / Release`, `CurrentProcess`,
  `CapName`.
- `kernel/proc/process.h` — `Process::root` (per-process VFS root).
- `kernel/sched/sched.{h,cpp}` — `Task::process` pointer,
  `SchedCreateUser(..., core::Process*)`, `TaskProcess(Task*)`.
- `kernel/syscall/syscall.cpp` — every privileged syscall gates on
  `CurrentProcess()->caps` before proceeding.

## Lifecycle

1. **Create**: `ProcessCreate(name, caps_template)` allocates the
   `Process`, attaches a fresh `mm::AddressSpace` (loaded with the
   higher-half kernel mirror), sets caps, and assigns a pid.
2. **Spawn task**: `SchedCreateUser(entry, arg, name, process)` makes
   a ring-3 task whose `Task::process` points back. Multi-threaded
   processes share one `Process` across many `Task`s.
3. **Refcount**: `ProcessRetain` / `ProcessRelease`. The reaper calls
   `ProcessRelease` on each task death; the destructor runs when the
   last reference drops.
4. **Destroy**: Process destructor transitively releases the
   `AddressSpace`. AS destructor unmaps every user-half page and
   returns frames.

## Boot Output (trimmed example)

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

The sandbox task hits the denial path on `SYS_WRITE` because it has
zero caps; clean exit follows because the user payload ignores the
return value.

## Sandboxing Walls

A process running with `CapSetEmpty` is bounded by **five orthogonal
walls** (per `.claude/knowledge/sandbox-overview-v0.md`):

1. **Per-process address space** — private PML4, kernel half mirrored.
2. **Capability-gated syscalls** — `Process::caps` checked at every
   privileged surface.
3. **VFS namespace jail** — `Process::root` rooted at a per-process
   subtree. `..` is rejected outright.
4. **W^X enforcement** — `AddressSpaceMapUserPage` panics on
   write+execute combinations. `kPageGlobal` is also refused on user
   pages.
5. **Per-AS frame budget + per-process CPU tick budget** — bounded
   resource exhaustion.

See [Sandboxing](../security/Sandboxing.md) for the full layered story.

## Design Notes

- **Cap numbering is ABI.** Always add at the end of the enum; never
  reuse a retired number.
- **Empty cap set isn't `1 << kCapNone`.** `kCapNone = 0` is a
  sentinel; real caps start at bit 1.
- **Sentinel `kCapCount`** is the last enum entry, not a live cap;
  `CapSetTrusted` loops `[1 .. kCapCount)`.
- **Kernel threads have no Process.** SchedCreate leaves
  `t->process = nullptr`. Reaper's `process != nullptr` guard lets
  kernel threads (idle, reaper, workers, keyboard reader) fall
  through with no state change.

## Related Pages

- [Memory Management](Memory-Management.md) — owns AddressSpace
- [Scheduler](Scheduler.md) — owns Tasks
- [Capabilities](../security/Capabilities.md)
- [Sandboxing](../security/Sandboxing.md)
- [VFS](../filesystem/VFS.md) — per-process root
