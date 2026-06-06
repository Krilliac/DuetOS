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

## Process Spawn

`kernel/proc/spawn.{h,cpp}` is the actual process-creation entry
surface — the place that ties an image's bytes to a fresh `Process`,
an `AddressSpace`, and a queued ring-3 task. Three entry points, one
per image flavour, all sharing the same parse → AS → `ProcessCreate`
→ `SchedCreateUser` pipeline and the same contract (return the new pid
on success, `0` on any failure, with all partial state unwound through
`AddressSpaceRelease`):

```cpp
u64 SpawnElfFile (const char* name, const u8* elf_bytes, u64 elf_len, ...);  // spawn.h:99
u64 SpawnElfLinux(const char* name, const u8* elf_bytes, u64 elf_len, ...);  // spawn.h:113
u64 SpawnPeFile  (const char* name, const u8* pe_bytes,  u64 pe_len,  ...);  // spawn.h:122
```

- **`SpawnElfFile`** loads a native ELF via `ElfLoad` (see
  [Loader](Loader.md#elf64-loader)). It auto-detects Linux-ABI images
  by their `EI_OSABI` byte (`ELFOSABI_LINUX` = 3) and delegates to
  `SpawnElfLinux` so the task's syscall dispatch lands on the Linux
  dispatcher.
- **`SpawnElfLinux`** is the Linux-ABI twin: same load pipeline, but
  flips `Process::abi_flavor = kAbiLinux` so ring-3 `syscall`
  instructions route through `MSR_LSTAR` (the Linux dispatcher) rather
  than the native `int 0x80` path, and seeds `linux_brk_{base,current}`
  + `linux_mmap_cursor`.
- **`SpawnPeFile`** loads a PE/COFF image via the v0 PE loader. It
  pre-loads the standard Win32 DLL set into the new AS before `PeLoad`
  runs so `ResolveImports` can consult their export tables.

## Service Manager (init / supervisor)

`kernel/core/service.{h,cpp}` is the kernel-resident init equivalent. It
owns a single declarative manifest of the userland programs DuetOS
launches at boot (`usershell`, `hello_native`, `nat_calc`, `nat_sysinfo`,
`duet-pkg`) — replacing the hand-unrolled `SpawnElfFile` blocks that used
to live inline in `boot_bringup.cpp`. `ServiceManagerStartAll()` (called
from boot) spawns every `autostart` entry in manifest order through the
canonical `core::Spawn*File` API and starts the `svcmon` supervisor task,
which:

- polls liveness via `SchedProcessAlive(pid)` to track each service's
  state (`Running` → `Exited`). This walks the scheduler's *all-tasks*
  registry, so a daemon parked in a blocking syscall (e.g. `netd` in
  `accept()`, `TaskState::Blocked` on a WaitQueue) correctly reads as
  alive — `SchedFindProcessByPid` only walks the runqueue/sleep/zombie
  lists and would mistake a healthy blocked daemon for a dead one.
  Monotonic PIDs mean a "not alive" verdict can never be a reused id;
- respawns `ServiceRestartPolicy::Always` services on exit with
  fault-domain-style crash-loop protection (≤ 5 respawns / 60 s, else
  `Failed`).

The `svc` shell command drives the set at runtime (`list` for any user;
`start`/`stop`/`restart <name>` admin-gated). v0 scope: services run with
the trusted cap-set (a per-service sandbox profile is a future knob). The
five boot programs are oneshot (`Never`); **`netd`** — a resident TCP echo
server on :7777 (`userland/native-apps/netd`, using the native-libc BSD
socket wrappers in `duet/socket.h`) — is the first `Always` entry, so the
respawn path is exercised by a real resident process as well as by
`ServiceManagerSelfTest`'s crash-loop-rate-limiter unit test. So that a
crashed daemon can actually re-bind its port on respawn, kernel sockets
are now owner-stamped and reclaimed on process exit
(`SocketReleaseByOwner`, called from `ProcessRelease`). **Why
kernel-resident rather than
a `/sbin/init` ELF:** a userland PID-1 needs ring-3 process-spawns-process
plumbing that does not exist yet; the supervisor lives where the other
system services (heartbeat, selfthink, autonomic) already live, and a
future userland init can adopt the same manifest shape.

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
walls**:

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

## Threading & Locking Model

- A `Process` is shared by all its ring-3 `Task`s, so per-process
  mutable state (the cap set is read-mostly after spawn; the Linux fd
  table, OFD pool, and VFS root are read/write) is protected by the
  process's own locks rather than a global one.
- Spawn (`SpawnElfFile` / `SpawnElfLinux` / `SpawnPeFile`) runs in the
  caller's task context. It allocates an `AddressSpace` and maps user
  pages before any second task can observe the process, so the load
  itself needs no cross-task synchronisation; the cleanup-on-failure
  path (`AddressSpaceRelease`) is single-owner.
- Refcounting (`ProcessRetain` / `ProcessRelease`) is the
  cross-context safe handle: the reaper releases on task death from a
  different context than the spawner, and the destructor runs only when
  the last reference drops.

## Known Limits / GAPs

These carry live `// GAP:` markers in
[`kernel/proc/process.cpp`](../../kernel/proc/process.cpp):

- **Pre-OFD open status flags seeded empty.** Opens that predate the
  OFD (open-file-description) tracking get their description flags
  seeded to `0` rather than the real status flags
  ([`process.cpp:1445`](../../kernel/proc/process.cpp)) — revisit when
  `sys_open` / `pipe2` / `socket` route through the OFD pool.
- **Inline offset writers don't propagate to dup siblings.** Syscall
  TUs that write `linux_fds[fd].offset` directly (read, write, lseek,
  sendfile, splice) bypass `LinuxFdSetOffset`, so the shared offset
  isn't propagated to `dup`'d siblings until those write sites migrate
  to the accessor ([`process.cpp:1591`](../../kernel/proc/process.cpp)).
  The OFD is the source of truth; the inline field is a per-fd cache.
- **`fork` under OFD-pool pressure loses offset sharing.** If the OFD
  pool is exhausted at `fork` time, the child's fd is degraded to a
  private offset for that fd (safe, but no longer shared)
  ([`process.cpp:1667`](../../kernel/proc/process.cpp)) — revisit by
  growing `kOfdPoolCap`.

## Related Pages

- [Memory Management](Memory-Management.md) — owns AddressSpace
- [Scheduler](Scheduler.md) — owns Tasks
- [Capabilities](../security/Capabilities.md)
- [Sandboxing](../security/Sandboxing.md)
- [VFS](../filesystem/VFS.md) — per-process root
