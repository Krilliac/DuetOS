# Capabilities

> **Audience:** Kernel hackers, security folks, syscall-handler authors
>
> **Execution context:** Kernel — `cap_gate` runs before every privileged syscall
>
> **Maturity:** v0 stable

## Overview

DuetOS uses a capability-bit model for privilege gating. Every process
holds durable caps, generation-tagged temporary leases, and a monotonic
grant ceiling. Every privileged syscall checks an effective snapshot:
`(durable | unexpired_leases) & ceiling`. Denials log
`[sys] denied syscall=<NAME> pid=<P> cap=<NAME>` and return `-1`.

There is no setuid. Capability state is the only privilege model, and
the elevation broker is the only controlled post-spawn grant bridge.

## Files

- `kernel/syscall/cap_table.def` — the `CAP_BIT(name, ...)` X-macro
  list (single source of truth for the bit values)
- `kernel/syscall/cap_gate.{h,cpp}` — syscall-to-mask table lookup,
  effective snapshot check, and denial log path
- `kernel/proc/process.{h,cpp}` — the `kCap*` enum, `CapSet`, the
  ceiling/lease state, and the only public capability mutation helpers
- `kernel/security/{broker,grace}.{h,cpp}` — role/password policy,
  positive-duration Process leases, and prompt-suppression metadata
- `tools/test/capability-access-static.py` — rejects direct published
  `Process` capability access and drift in the exact spawn masks

> A **separate, unrelated** `enum class Cap` lives at
> `kernel/security/privilege/scope.h:33-41` (5 members: `FsRead`,
> `FsWrite`, `ProcSpawn`, `KernelRead`, `Net`). It belongs to the
> privileged-origin / `duetos::security::privilege` path and is a
> distinct namespace from `core::Cap` (`kCap*`). The kernel cap gate
> uses `kCap*`, not this enum — don't conflate the two.

## Two Profiles

- **`CapSetEmpty`** — zero bits. The sandbox profile. Only
  unprivileged syscalls (`SYS_GETPID`, `SYS_YIELD`, `SYS_EXIT`)
  succeed; everything observable from outside the process AS denies.
- **`CapSetTrusted`** — every defined cap. For kernel-shipped userland
  fixtures and trusted system processes **only** — never for an
  operator-chosen binary (it includes `kCapDebug` = cross-process VM
  read/write + `SetContext`, and `kCapDiag` = `SYS_DIAG_FAULT_INJECT`, a
  guest-reachable kernel panic).

A real process between these extremes uses `CapSetEmpty` plus
selectively-granted bits. Caps are ABI: numbers never change.

> **User-launched binaries get least privilege.** The Files app and the
> shell `peexec` command launch arbitrary user-chosen `.exe`/`.elf`
> files — these are **untrusted** and now spawn with `CapSetEmpty` plus
> only `kCapSerialConsole + kCapFsRead + kCapSpawnThread`, into the
> sandbox ramfs root with sandbox-class budgets (modelled on the browser
> broker's `DeriveChildCaps`). They no longer inherit `CapSetTrusted`.
> (Security audit SEC-008, CWE-250/269, 2026-06-07.)

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
[Subsystem Isolation rule 2](../kernel/Subsystem-Isolation.md), token
adjustment is a real translation into the kernel capability model:

- disable clears durable and leased live bits but preserves the ceiling;
- `SE_PRIVILEGE_REMOVED` clears the bit and permanently lowers the
  process ceiling;
- enable of a missing mapped privilege routes through the broker and
  can install only a positive-duration lease;
- integrity levels and ACL-shaped probes remain facades.

Current mapped LUIDs are Debug → `kCapDebug`, Backup →
`kCapFsRead`, Restore → `kCapFsWrite`, and IncreaseBasePriority →
`kCapSchedPriority`. The next privileged kernel operation still
performs the authoritative cap check.

<!-- AUTO:cap_list -->
| # | Capability |
|---|------------|
| 1 | `kCapDebug` |
| 2 | `kCapDiag` |
| 3 | `kCapFsRead` |
| 4 | `kCapFsWrite` |
| 5 | `kCapInput` |
| 6 | `kCapNet` |
| 7 | `kCapNetAdmin` |
| 8 | `kCapSchedPriority` |
| 9 | `kCapSerialConsole` |
| 10 | `kCapSpawnThread` |
<!-- /AUTO:cap_list -->

_The capability inventory above is auto-synced by
`docs/sync-wiki.sh sync` from the `kCap*` enum in
`kernel/proc/process.h`._

## Threading and Locking

`Process::cap_lock` serializes durable caps, lease
generation/deadline state, and the monotonic ceiling. All published
reads use `ProcessCapsSnapshot` or `ProcessHasCap`; the snapshot lazily
expires overdue leases under the same lock. The grace cache may be
evicted or reaped independently because its rows are metadata only.
Lock order is grace-cache lock → `Process::cap_lock`; Process helpers
never call back into the cache or scheduler.

## Performance

The gate takes one per-process spinlock, expires only lease bits that
are present, computes one bitmask snapshot, and releases the lock
before dispatch. It performs no allocation, scheduler-wide lookup, or
grace-cache walk. Processes without live leases take the short expiry
path.

## Troubleshooting

- **`[sys] denied syscall=<NAME> pid=<P> cap=<NAME>`** — the process
  lacks the required bit. Either it was started with `CapSetEmpty` (or
  a profile missing that bit), or the syscall is gated on a cap the
  workload legitimately needs and the profile should grant it.
- **A Win32 PE got success from `NtAdjustPrivilegesToken` but still
  can't do the thing.** The privilege may be unmapped, its broker
  request may have returned `STATUS_NOT_ALL_ASSIGNED`, its lease may
  have expired, or the bit may have been permanently removed from the
  ceiling. The kernel effective snapshot is authoritative.
- **Elevation never succeeds on a clockless boot.** Intentional
  fail-closed behavior: without a monotonic time source the kernel
  cannot enforce a lease deadline.

## Related Pages

- [Sandboxing](Sandboxing.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Process Model](../kernel/Process-Model.md)
- [Syscalls](../kernel/Syscalls.md)
