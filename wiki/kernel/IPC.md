# Inter-Process Communication (IPC)

> **Audience:** Kernel hackers
>
> **Execution context:** Kernel + userland; planned `kernel/ipc/`
>
> **Maturity:** Planned — capability-based ports + shared memory

## Overview

DuetOS's IPC model is **capability-based** — ports and shared-memory
segments are kernel-owned objects, addressable only via opaque handles
held by a process. There is no setuid; there is no global namespace
that any process can probe. A process can only send to a port if it
holds a handle, and it only holds a handle if some authority granted
it.

This is the design plank that lets the kernel be hybrid (microkernel
IPC shape) without giving up monolithic-driver hot paths.

## Status

The dedicated `kernel/ipc/` directory is planned. Today, IPC primitives
land per-subsystem as they're needed:

- **Wait queues + mutexes**: `kernel/sched/sched.{h,cpp}` and
  `kernel/sync/`.
- **Shared event syscalls** (Win32-shaped: `SYS_EVENT_*`,
  `SYS_MUTEX_*`, `SYS_TLS_*`): `kernel/syscall/syscall.cpp` plus the
  per-DLL stubs.
- **Spinlocks + RW locks + RCU-lite**: `kernel/sync/`.

Every cross-process surface today is gated by the per-process
capability set (`Process::caps`). See
[Capabilities](../security/Capabilities.md).

## Design Principles (do not drift)

- **Capability handles are unforgeable.** A process holds a handle iff
  the kernel created it for that process or another holder explicitly
  duplicated it across.
- **No ambient authority.** Every privileged operation is a syscall
  that takes a handle the caller had to acquire.
- **One source of truth per resource.** One kernel-owned port object,
  any number of holders. No reflective "registries" for discovering
  ports by name unless mediated by an explicit naming service that's
  itself a port.
- **Send/receive are the primitive.** Higher-level RPC is an
  application-layer convention over send/receive — not a kernel
  feature.

## When This Lands

The first real IPC user is expected to be the audio subsystem (so
the audio server can run as an isolated process holding the HDA
hardware capability). The VFS namespace, registry, and compositor
are currently in-kernel for hot-path latency — moving them out to
process-isolated services is a longer-horizon item.

## Related Pages

- [Capabilities](../security/Capabilities.md)
- [Process Model](Process-Model.md)
- [Subsystem Isolation](Subsystem-Isolation.md)
- [Sandboxing](../security/Sandboxing.md)
