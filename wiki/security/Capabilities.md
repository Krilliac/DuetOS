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
- `kernel/proc/process.h` — the `kCap*` enum (source of truth for the
  bit values), `CapSet`, `CapSetEmpty`, `CapSetTrusted`, `CapName`

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
| 1 | `kCapDebug` |
| 2 | `kCapDiag` |
| 3 | `kCapFsRead` |
| 4 | `kCapFsWrite` |
| 5 | `kCapInput` |
| 6 | `kCapNet` |
| 7 | `kCapNetAdmin` |
| 8 | `kCapSerialConsole` |
| 9 | `kCapSpawnThread` |
<!-- /AUTO:cap_list -->

_The capability inventory above is auto-synced by
`docs/sync-wiki.sh sync` from the `kCap*` enum in
`kernel/proc/process.h`._

## Threading and Locking

`CapSet` is per-process state, owned by the `Process` struct and only
mutated at process setup (profile application) before the process runs.
The cap gate reads `CurrentProcess()->caps` on the calling CPU during
syscall dispatch — a read of the current process's own field, so no
lock is taken on the gate path. Caps are not mutated by another CPU
mid-syscall.

## Performance

The gate is a single bitmask test (`caps & (1 << capN)`) on the hot
syscall-dispatch path — no allocation, no lock, no branch beyond the
allow/deny decision. The denial log path runs only on the cold (denied)
leg.

## Troubleshooting

- **`[sys] denied syscall=<NAME> pid=<P> cap=<NAME>`** — the process
  lacks the required bit. Either it was started with `CapSetEmpty` (or
  a profile missing that bit), or the syscall is gated on a cap the
  workload legitimately needs and the profile should grant it.
- **A Win32 PE got `STATUS_SUCCESS` from `NtAdjustPrivilegesToken` but
  still can't do the thing.** Expected — that NT surface is a facade
  (rule 2). The kernel `kCap*` bit is what gates; grant the cap on the
  process, not the NT token.

## Related Pages

- [Sandboxing](Sandboxing.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Process Model](../kernel/Process-Model.md)
- [Syscalls](../kernel/Syscalls.md)
