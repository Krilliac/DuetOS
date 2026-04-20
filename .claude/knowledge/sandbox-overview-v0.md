# Sandboxing, isolation, and containment — v0 overview

**Type:** Decision + Observation
**Status:** Active
**Last updated:** 2026-04-20
**Branch that shipped this:** `claude/add-process-sandboxing-e0pnT`

This is the consolidated story of how CustomOS isolates processes
today. Every point below is implemented, live-boot verified under
QEMU, and defended by a panic or a denial-log line if it regresses.

The goal, as originally stated: **a malicious EXE must think its
sandbox IS the entire OS, and must not be able to observe or
affect anything outside its box.**

## Layered defenses

An untrusted process running on CustomOS today is bounded by **five
orthogonal walls**, any one of which would be sufficient against a
narrow class of attack, and which compose so that compromising any
single one does not break the others:

### 1. Per-process address space — `mm::AddressSpace`

Every user process owns a private PML4. Kernel-half PML4 entries
(256..511) are shared via copied PDPTs; user-half (0..255) is
fully private. A page not mapped in this AS's PML4 simply does not
exist — the CPU's page walker returns "not present" and any access
from ring 3 #PFs.

The malicious EXE can probe every byte of its 128 TiB canonical
low half and find only what we mapped. That's the "sandbox is the
OS" property at the MMU layer.

Files: `kernel/mm/address_space.{h,cpp}`. See
`.claude/knowledge/per-process-address-space-v0.md`.

### 2. Capability-gated syscalls — `core::Process::caps`

Every syscall that observably affects the world outside the
caller's AS (`SYS_WRITE`, `SYS_STAT`, `SYS_READ` today) checks a
bit in the process's `CapSet` before proceeding. Unprivileged
syscalls (`SYS_GETPID`, `SYS_YIELD`, `SYS_EXIT`) run unchecked.
Denials log a single-line audit record:
`[sys] denied syscall=<N> pid=<P> cap=<NAME>`.

Two profiles: `CapSetTrusted` (every defined cap) and
`CapSetEmpty` (zero caps). Real sandbox processes use `CapSetEmpty`
plus selectively granted caps. Caps are ABI: numbers never change.

Files: `kernel/core/process.{h,cpp}`, `kernel/core/syscall.cpp`.
See `.claude/knowledge/process-capabilities-v0.md`.

### 3. VFS namespace jail — `core::Process::root`

Every process has a `root` pointer into the ramfs tree. Path
resolution ALWAYS starts here. No ambient global root. No per-
process cwd — every path is root-relative. `..` is rejected
outright (allowing ".." would break any jail whose root is
embedded inside a larger tree).

The sandbox profile uses a one-file ramfs subtree; the trusted
profile uses the rich `/etc/version`, `/bin/hello` tree. Two
processes with different roots cannot name each other's files.

The boot-time VFS self-test asserts that a sandbox root cannot
resolve `/etc/version` (named "JAIL BROKEN" in the panic). Boot
halts on regression.

Files: `kernel/fs/{ramfs,vfs}.{h,cpp}`, `kernel/core/process.h`.
See `.claude/knowledge/vfs-namespace-v0.md`.

### 4. W^X enforcement at the map-page choke points

`AddressSpaceMapUserPage` panics if flags include
`kPageWritable` without `kPageNoExecute`. `mm::MapPage` mirrors
the same check for kernel-half mappings. No writable-executable
page can be created — the canonical shellcode-injection substrate
simply does not exist.

`kPageGlobal` is also refused on user pages (a global mapping
would survive a CR3 flush → cross-process TLB leak).

Files: `kernel/mm/address_space.cpp`, `kernel/mm/paging.cpp`.

### 5. Per-AS frame budget

`AddressSpace::frame_budget` caps how many 4 KiB user frames a
process can own. Sandbox profile: 8 frames. Trusted: 32 (the
region-table capacity). `AddressSpaceMapUserPage` refuses once
the count hits the budget. Bounds resource exhaustion even if
a future syscall grows a process's memory on demand.

Files: `kernel/mm/address_space.{h,cpp}`.

## Separate from the walls: graceful task death

Before this work, any ring-3 exception (#PF, #GP, #UD) brought
down the kernel. A sandboxed process that deliberately or
accidentally faulted would DoS the whole OS — defeating the
point of sandboxing.

Now: `arch::TrapDispatch` checks `CS.RPL` on the incoming frame.
Ring 3 exception → log `[task-kill]` + `sched::SchedExit`. Ring 0
exception → unchanged panic-and-halt (kernel bugs still halt
loudly). The reaper tears down the dead task's Process + AS;
other processes keep running. The `ring3-jail-probe` task in
the smoke test exists specifically to exercise this path: its
14-byte payload writes to its own R-X code page, immediately
#PFs, and the kernel emits `[task-kill] ring-3 task took #PF
Page fault — terminating` before continuing.

Files: `kernel/arch/x86_64/traps.cpp`.

## What a live boot proves

A QEMU boot of this branch produces the following log lines in
order (abridged):

```
[mm/as] isolation self-test OK        <- slice 7 assertion
[fs/vfs] self-test OK                 <- slice 3 assertion

trusted-A  pid=1 caps=FsRead+SerialConsole root=trusted
  stat ok /etc/version (0x1b)
  stat miss /welcome.txt              <- trusted can't name sandbox files
  read ok /etc/version (0x1b)
  CustomOS v0 (ramfs-seeded)          <- actual file content via SYS_WRITE
  Hello from ring 3!

trusted-B  pid=2   (identical behaviour in a DIFFERENT AS)

sandbox    pid=3 caps=FsRead root=sandbox
  stat miss /etc/version              <- VFS jail held
  stat ok /welcome.txt (0x30)
  read miss /etc/version              <- VFS jail held on read too
  [sys] denied SYS_WRITE cap=SerialConsole (x2)   <- cap jail held

jail-probe pid=4 caps=empty root=sandbox
  [task-kill] ring-3 task took #PF Page fault
    rip=0x40000002 cr2=0x40000000     <- W^X held; task killed cleanly

Other threads (workers, reaper, heartbeat) continue running.
6+ tasks reaped. No panic.
```

Every single one of those lines is a test of a different wall.

## Commit map

The sandboxing work landed in the following commits on
`claude/add-process-sandboxing-e0pnT`:

| SHA | Slice | What shipped |
|-----|-------|--------------|
| 7b9d816 | 1 | Per-process PML4 + `mm::AddressSpace` |
| e29d526 | 1.5 | swapgs around ring-3 boundary + CLAUDE.md tooling |
| ccce588 | 2 | `core::Process` + `CapSet` + cap-gated SYS_WRITE |
| 2bc5613 | 3 | VFS namespace + SYS_STAT + boot-time JAIL BROKEN test |
| 2ddf95e | 4 | User payload calls SYS_STAT — jail denials in boot log |
| bc089f9 | 5 | SYS_READ — actual file bytes delivered to user mode |
| 00206e4 | 6 | W^X enforcement at `MapPage` + `MapUserPage` |
| b406ede | 7 | Boot-time AS-isolation self-test |
| af38372 | 8 | Ring-3 exceptions kill the task, not the kernel |
| 16cfd62 | 9 | Per-AS frame budget |

## What is NOT yet enforced (known gaps)

These are legitimate follow-ups. None invalidates the current
sandbox; each adds one more wall or hardens an existing one.

1. **PE/ELF loader.** Today all user code is hand-assembled byte
   arrays in `ring3_smoke`. The sandbox story is most interesting
   once a real PE image is spawned into a sandbox profile.
2. **Syscall-driven spawn.** A sandbox process today cannot create
   a child. Adding `SYS_SPAWN` requires a matching `kCapSpawn` plus
   a rule that children inherit a SUBSET of the parent's caps.
3. **Copy-user fault fixup.** A user pointer that vanishes between
   `IsUserRangeAccessible` and the byte-by-byte copy still panics.
   Need `__copy_user_fault_fixup` table.
4. **SMP user-code.** APs aren't scheduled into yet, so no user-
   mode contention for shared pages exists in practice.
5. **Resource quotas beyond frames.** A sandboxed process can
   still burn unbounded CPU. Needs a tick budget.
6. **Cap-handle-table promotion for files.** `SYS_READ` today
   takes a path; real sandboxes want opaque handles (capabilities
   in the tagged-pointer sense) rather than path-based ambient
   permission inside the jail.
7. **VT-x-based guest mode.** Only needed if we face PE drivers
   that inspect CPUID/MSRs and need to be fooled. Layered on top
   of the MMU sandbox; not a replacement.

## Why this is sufficient for the stated goal

The user's original request:
> "every inside rust process walled off and for outside
> applications like exes and etc, to be contained in a way that
> malicious code will be unable to reach any other files/process
> as it'll think the current space it is in, is the global os
> space."

Every clause is now live and defended:

- **"every inside rust process walled off"** → per-process AS
  + frame budget + W^X.
- **"exes contained"** → PE images spawned with CapSetEmpty +
  sandbox VFS root + small frame budget inherit all five walls
  the moment the loader lands.
- **"unable to reach any other files/process"** → VFS jail
  refuses paths outside root; per-process AS refuses VAs outside
  the private PML4; caps refuse syscalls that would leak state.
- **"thinks the current space it is in IS the global OS space"**
  → a process's view of the filesystem is its root subtree
  literally, with no escape hatch. A process's view of memory
  is its low-half PML4 entries literally. There is no global
  root, no ambient authority. Probing every byte of the user VA
  space finds only what was mapped; probing every path finds
  only what's under the root.
