# Subsystem Isolation (DO NOT VIOLATE)

> **Audience:** Kernel hackers, subsystem authors, userland DLL authors
>
> **Execution context:** N/A (architectural rule)
>
> **Maturity:** Stable doctrine — violations are bugs even if they compile

## Overview

**Win32 and Linux subsystems are facades for executing PE/ELF binaries.
They never drive DuetOS.** The DuetOS kernel — its capability set,
scheduler, address-space ledger, filesystem mediation, and IPC — is
the authority on every effect a guest binary can have on the system.
NT and Linux thunks translate ABI shapes; they don't reach past the
syscall boundary.

## The Six Concrete Rules

Every subsystem TU and userland DLL must follow these:

1. **No subsystem code mutates DuetOS state without going through a
   kernel-mediated, cap-gated syscall.** A Win32 PE that wants to
   write a file goes through `SYS_FILE_WRITE` (kCapFsWrite). A Linux
   binary that wants to spawn a thread goes through
   `SYS_THREAD_CREATE` (kCapSpawnThread). The thunk does not get to
   skip the gate.

2. **Auth and privilege are kernel-owned.** `Process::caps` (kCap*)
   is the source of truth. Any Win32-shaped privilege surface
   (`NtAdjustPrivilegesToken`, `SeDebugPrivilege`, integrity levels,
   ACLs) is a probe-satisfying facade — it does not actually grant or
   revoke anything. The kernel's cap gates are what gate.

3. **Userland DLLs (`userland/libs/*`) are freestanding.** They do not
   include kernel headers and they do not assume kernel internals.
   They issue syscalls and trust the kernel's return.

4. **In-kernel subsystem code (`kernel/subsystems/win32/`,
   `kernel/subsystems/linux/`) routes through public kernel APIs
   (`mm::*`, `sched::*`, `fs::routing::*`, `core::Cap*`).** It does
   not mutate kernel-internal data structures (regions tables,
   runqueues, capability bitsets) directly.

5. **No subsystem-to-subsystem coupling.** Win32 doesn't call Linux,
   Linux doesn't call Win32. They both call the kernel.

6. **One source of truth per resource.** One TCP stack, one VFS, one
   registry, one window manager — each reachable from multiple ABI
   front-ends, but with one kernel-owned implementation.

## The Reviewable Signal

> Could a malicious PE / ELF use this path to do something a native
> DuetOS process couldn't?

If yes, **the gate is wrong, not the workload**.

## Why This Rule Exists

Two parallel TCP stacks (one for DuetOS, one for "Windows") is how
operating systems rot. Two parallel VFSes, two parallel registries,
two parallel compositors — each pair is its own consistency-bug
generator and its own threat-modelling burden.

DuetOS has **one** of each. The Win32 surface is a translator that
adapts the Win32 ABI shape to the same kernel call a native program
would make. The Linux surface is the same shape for ELF + Linux ABI.

## What This Permits / Forbids

| Action | OK? |
|--------|-----|
| A `ws2_32` source file calls `SYS_SOCK_SEND` | Yes |
| A `ws2_32` source file peeks at the kernel's TCP control block | **No** — out of reach by construction |
| A win32 in-kernel TU calls `fs::routing::WriteFile` | Yes |
| A win32 in-kernel TU writes directly to a kernel file-table entry | **No** — must go through `fs::routing::*` |
| A win32 in-kernel TU calls into a linux in-kernel TU | **No** — both must go through the kernel API they share |
| Adding a "Windows tcp socket" implementation parallel to the kernel one | **No** — one TCP stack, period |

## Repository Audit Checklist

When reviewing a patch that touches `kernel/subsystems/*` or
`userland/libs/*`:

- Does any new state-mutating call skip the cap gate?
- Does the userland DLL `#include` anything from `kernel/`?
- Does the in-kernel subsystem code read or write a kernel-internal
  data structure (anything not exported by `mm::*`, `sched::*`,
  `fs::routing::*`, `core::Cap*`)?
- Is there a Win32-shaped ACL/integrity/privilege surface that
  pretends to gate something? It should be a no-op facade.
- Is a new stack (TCP, VFS, registry, compositor) being introduced
  parallel to the existing one?

If a violation makes it past review, fix the underlying gate — do
not extend the violation. The reviewable test is "could a malicious
PE / ELF use this path to do something a native DuetOS process
couldn't?" If yes, the gate is wrong.

## Related Pages

- [Capabilities](../security/Capabilities.md) — the kernel's source of
  truth for privilege
- [Sandboxing](../security/Sandboxing.md) — how the five walls compose
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md)
- [Linux ABI](../subsystems/Linux-ABI.md)
- [Process Model](Process-Model.md)
