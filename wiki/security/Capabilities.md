# Capabilities

> **Audience:** Kernel hackers, security folks, syscall-handler authors
>
> **Execution context:** Kernel — `cap_gate` runs before every privileged syscall
>
> **Maturity:** v0 stable

## Overview

DuetOS uses a capability-bit model for privilege gating. Every process
holds a `CapSet` (u64 bitmask). Every privileged syscall checks
`CurrentProcess()->caps & (1 << capN)` before proceeding. Denials log
`[sys] denied syscall=<NAME> pid=<P> cap=<NAME>` and return `-1`.

There is no setuid; there is no ambient authority. Capability bits are
the only privilege model.

## Files

- `kernel/syscall/cap_table.def` — the `CAP_BIT(name, ...)` X-macro
  list (single source of truth for the bit values)
- `kernel/syscall/cap_gate.{h,cpp}` — `CapGateCheck(cap)` and the
  denial log path
- `kernel/core/process.{h,cpp}` — `CapSet`, `CapSetEmpty`,
  `CapSetTrusted`, `CapName`

## Two Profiles

- **`CapSetEmpty`** — zero bits. The sandbox profile. Only
  unprivileged syscalls (`SYS_GETPID`, `SYS_YIELD`, `SYS_EXIT`)
  succeed; everything observable from outside the process AS denies.
- **`CapSetTrusted`** — every defined cap. For kernel-shipped userland
  fixtures and trusted system processes.

A real process between these extremes uses `CapSetEmpty` plus
selectively-granted bits. Caps are ABI: numbers never change.

## Why `kCapNone = 0` is a Sentinel

The bit-0 slot is reserved as the "no capability" sentinel — it is
not a real cap. Real caps start at bit 1. `CapSetHas(s, kCapNone)` is
always false, so initialised-to-zero structs default to "no
privilege" rather than "has cap zero."

## Sentinel `kCapCount`

Last enum entry, not a live cap. `CapSetTrusted` loops
`[1 .. kCapCount)` to build the full set.

## Cap Numbering is ABI

A process image with a "requested caps" manifest stored on disk would
break if we renumbered bits. Always **add at the end** of
`cap_table.def`; never reuse a retired number.

## Syscall <-> Cap Mapping

`kernel/syscall/cap_table.def` ties each syscall to the bit it
checks. The dispatcher consults this table during dispatch (or via
generated case statements per build choice). See
[Syscalls](../kernel/Syscalls.md).

## Win32 / NT Privilege Surface

Win32 has its own privilege model — `NtAdjustPrivilegesToken`,
`SeDebugPrivilege`, integrity levels, ACLs. Per
[Subsystem Isolation rule 2](../kernel/Subsystem-Isolation.md), those
are **probe-satisfying facades**. They do not actually grant or revoke
anything. The kernel's `kCap*` bits are what gate.

A PE that calls `NtAdjustPrivilegesToken` and asks for
`SeDebugPrivilege` gets `STATUS_SUCCESS` back from `userland/libs/ntdll/`,
but the underlying capability set on the kernel process is unchanged.
A subsequent attempt to `OpenProcess(PROCESS_VM_READ, ...)` against
another PID still hits the cap gate and fails (or succeeds if
`kCapDebug` was already on the calling process).

<!-- AUTO:cap_list -->
| # | Capability |
|---|------------|
| 1 | `kCapCount` |
| 2 | `kCapDebug` |
| 3 | `kCapDiag` |
| 4 | `kCapFsRead` |
| 5 | `kCapFsWrite` |
| 6 | `kCapInput` |
| 7 | `kCapNet` |
| 8 | `kCapNetAdmin` |
| 9 | `kCapNetRecv` |
| 10 | `kCapNetSend` |
| 11 | `kCapNone` |
| 12 | `kCapSerialConsole` |
| 13 | `kCapSpawnThread` |
<!-- /AUTO:cap_list -->

_The capability inventory above is auto-synced by
`docs/sync-wiki.sh sync` from the `kCap*` enum in
`kernel/proc/process.h`._

## Related Pages

- [Sandboxing](Sandboxing.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Process Model](../kernel/Process-Model.md)
- [Syscalls](../kernel/Syscalls.md)
