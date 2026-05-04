# Sandboxing

> **Audience:** Security folks, kernel hackers
>
> **Execution context:** N/A (architectural composition)
>
> **Maturity:** v0 — five orthogonal walls live and verified

## Overview

> **The goal**: a malicious EXE must think its sandbox IS the entire
> OS, and must not be able to observe or affect anything outside its
> box.

A process running with `CapSetEmpty` is bounded by **five orthogonal
walls**, any one of which would be sufficient against a narrow class
of attack, and which compose so that compromising any single one does
not break the others. Plus an additional CPU-tick budget gate.

## The Five Walls

### 1. Per-process address space — `mm::AddressSpace`

Every user process owns a private PML4. Kernel-half PML4 entries
(256..511) are shared via copied PDPTs; user-half (0..255) is fully
private. A page not mapped in this AS's PML4 simply does not exist —
the CPU's page walker returns "not present" and any access from
ring 3 #PFs.

The malicious EXE can probe every byte of its 128 TiB canonical low
half and find only what we mapped. That's the "sandbox is the OS"
property at the MMU layer.

Files: `kernel/mm/address_space.{h,cpp}`.

### 2. Capability-gated syscalls — `core::Process::caps`

Every syscall that observably affects the world outside the caller's
AS (`SYS_WRITE`, `SYS_STAT`, `SYS_READ`, ...) checks a bit in the
process's `CapSet` before proceeding. Unprivileged syscalls
(`SYS_GETPID`, `SYS_YIELD`, `SYS_EXIT`) run unchecked. Denials log
`[sys] denied syscall=<NAME> pid=<P> cap=<NAME>`.

Two profiles: `CapSetTrusted` (every defined cap) and `CapSetEmpty`
(zero caps).

See [Capabilities](Capabilities.md).

### 3. VFS namespace jail — `core::Process::root`

Every process has a `root` pointer into the ramfs tree. Path
resolution **always** starts here. No ambient global root. No
per-process cwd — every path is root-relative. `..` is rejected
outright.

The boot-time VFS self-test asserts that a sandbox root cannot
resolve `/etc/version` (named "JAIL BROKEN" in the panic). Boot halts
on regression.

Files: `kernel/fs/{ramfs,vfs}.{h,cpp}`. See
[VFS](../filesystem/VFS.md).

### 4. W^X enforcement at the map-page choke points

`AddressSpaceMapUserPage` panics if flags include `kPageWritable`
without `kPageNoExecute`. `mm::MapPage` mirrors the same check for
kernel-half mappings. **No writable-executable page can be created** —
the canonical shellcode-injection substrate simply does not exist.

`kPageGlobal` is also refused on user pages (a global mapping would
survive a CR3 flush -> cross-process TLB leak).

Files: `kernel/mm/address_space.cpp`, `kernel/mm/paging.cpp`. See
[W^X / NX Enforcement](WX-Enforcement.md).

### 5. Per-AS frame budget

`AddressSpace::frame_budget` caps how many 4 KiB user frames a
process can own. Sandbox profile: 8 frames. Trusted: 32.
`AddressSpaceMapUserPage` refuses once the count hits the budget.
Bounds resource exhaustion.

### 5b. Per-process CPU-tick budget

`Process::tick_budget` caps how many 100 Hz timer ticks a process's
tasks can be Running. The timer IRQ bumps `ticks_used` for the
currently-running task's process; when it exhausts the budget, the
process is marked dead.

## What This Composes Against

| Attack class | Defended by |
|--------------|-------------|
| Out-of-box read / write | Wall 1 (private AS) |
| Privilege escalation via syscall | Wall 2 (caps) |
| Path traversal / chroot escape | Wall 3 (per-process root + `..` ban) |
| Shellcode injection | Wall 4 (W^X) |
| Memory exhaustion DoS | Wall 5 (frame budget) |
| CPU exhaustion DoS | Wall 5b (tick budget) |

## What's Missing

- **Compositor isolation**: a sandbox process can post a window today.
  Co-process window-content read-back is gated by HWND ownership but
  not impossible-to-read by construction.
- **Audio**: same story as compositor — audio output bypass is
  capability-gated, not yet IPC-isolated.
- **Side-channels**: KASAN-equivalent and KASLR are on; KPTI is a
  settled non-implementation decision because every CPU in the
  hardware target matrix reports `RDCL_NO=1` in silicon. See
  [W^X / NX Enforcement](WX-Enforcement.md) and
  [Roadmap > KPTI enable](../reference/Roadmap.md#kpti-enable-settled--deferred).

## Related Pages

- [Capabilities](Capabilities.md)
- [W^X / NX Enforcement](WX-Enforcement.md)
- [Process Model](../kernel/Process-Model.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [VFS](../filesystem/VFS.md)
- [Attack Simulation](Attack-Simulation.md)
- [Runtime Recovery Strategy](Runtime-Recovery.md)
