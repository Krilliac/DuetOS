# Win32 Registry

> **Audience:** Win32 ABI authors, PE compatibility maintainers, ops
>
> **Execution context:** Kernel — registry syscall handlers; persistence
> from a worker thread
>
> **Maturity:** v0 — static well-known keys + 32-slot mutable sidecar
> with FAT32 persistence; full HKEY mutation deferred

## Overview

DuetOS implements the Windows registry as a **kernel-resident,
read-mostly tree** with a small **mutable sidecar** for runtime
SetValue / DeleteValue calls. The sidecar is persisted to a FAT32
hive file so per-user settings survive reboots; the read-side
well-known keys are baked into the kernel image so PE binaries
that probe them at startup don't have to wait for I/O.

```
   PE binary (advapi32.dll RegOpenKeyExW → RegQueryValueExW → ...)
                |
                v
       kernel/subsystems/win32/registry.{h,cpp}    <-- per-call dispatch
                |
        +-------+---------+
        |                 |
   static well-known      mutable sidecar pool (32 slots)
   keys (in-image)               |
                                  v
                       FAT32 /REGISTRY.HIV       <-- persistence
```

Sources:

- [`registry.h`](../../kernel/subsystems/win32/registry.h) — public
  syscall handler + helpers
- [`registry.cpp`](../../kernel/subsystems/win32/registry.cpp) —
  dispatcher + sidecar table
- [`registry_hive.cpp`](../../kernel/subsystems/win32/registry_hive.cpp) —
  on-disk format + load/save

## Why a Registry at All

Most non-trivial PE binaries open the registry within the first dozen
syscalls — typically to read the OS version, the user name, the
product key, environment-shaped values. If we stub those calls out,
the PE either falls back to "use default" (best case) or refuses to
run (worst case). The registry exists to make the best case the
default.

We intentionally **do not** implement the full registry semantics —
no notification, no transactions, no security descriptors per key.
That stays explicit in the GAPs list below.

## Static Well-Known Keys

The kernel image bakes in the values the common CRTs and PE
loaders probe at startup. The paths and values are stable enough that
treating them as code is cheaper than building a persistent tree:

- `HKLM\Software\Microsoft\Windows NT\CurrentVersion`
  - `ProductName` — `"DuetOS"` posing as `"Windows 10 Pro"` (the
    string the userland CRTs check)
  - `CurrentVersion` — `"10.0"`
  - `CurrentBuild` — `"19041"`
  - `BuildLab` — DuetOS build commit hash
  - `InstallationType` — `"Client"`
- `HKLM\Hardware\Description\System\CentralProcessor\0`
  - `ProcessorNameString` — the CPU brand string from `CPUID 0x80000002..4`
- `HKCU\Volatile Environment`
  - `USERNAME` — current logged-in account from
    [Auth](../security/Auth-and-Login.md)
  - `USERDOMAIN` — hostname

There is one DuetOS-specific key that PE binaries can probe to detect
they are running on the project:

- `HKLM\Software\DuetOS\Runtime`
  - `Version` — DuetOS version
  - `Build` — commit hash

Use cases:

- PE binaries that read `ProductName` to decide which compat path to
  pick (legacy game launchers).
- Userland CRTs that read `USERNAME` to populate `getenv("USER")`.
- Debuggers that probe `CurrentBuild` to format symbols.

## Mutable Sidecar Pool

Runtime `RegSetValueExW` / `RegDeleteValueW` writes land in a
**32-slot fixed-size pool**. Each slot is one `HiveSnapshot`:

```cpp
struct HiveSnapshot {
    bool   active;
    bool   tombstone;
    HKEY   root;             // HKLM, HKCU, ...
    u32    type;             // REG_SZ, REG_DWORD, REG_BINARY, ...
    u32    size;             // payload bytes
    char   path[128];        // sub-key path
    char   name[64];         // value name
    u8     data[256];        // payload
};
```

The pool's full state lives in RAM. Lookup is linear (32 slots —
under a microsecond) and writes hit the same backing structure.
Tombstones mark deletions so a subsequent read returns
`ERROR_FILE_NOT_FOUND` rather than the static fallback.

When the pool fills, the oldest non-tombstone slot is evicted to make
room. v0 keeps the pool deliberately small because the user-facing
workload (settings app, a handful of compat shims) does not fill it.

## On-Disk Hive Format

`REGISTRY.HIV` lives at the FAT32 root. Format: **line-oriented
ASCII**, deliberately human-readable so an operator can `cat` the
file on another OS to debug.

```
v|80000002|Software\DuetOS\Runtime|Version|1|1.0.0
v|80000001|Volatile Environment|USERNAME|1|alice
t|80000002|Software\Foo|Bar
```

Each line:

- `v` (value) or `t` (tombstone)
- Root sentinel as 8-digit hex (`80000002` = HKLM, `80000001` = HKCU, …)
- Path
- Name
- For `v`: `type|data_hex`

Path and name must not contain `|` or `\n`. The persister enforces
this on write; the loader rejects malformed lines.

Forward-compatibility: unknown lines are silently skipped on load.
That keeps old kernels readable against new hives.

## Persistence Throttling

`RegistryHiveSave()` is **throttled** to avoid drumming the FAT32 layer
on every keystroke from the settings app:

- A pending-save flag is set by every mutation.
- A worker thread polls the flag every ~5 seconds. If set, it
  serialises the active pool into a candidate buffer.
- The candidate is byte-compared against the last successfully written
  payload. If identical, the FAT32 write is skipped (no-op).
- If different, the write goes through and the last-written buffer is
  updated.

The result: a busy mutation period (user dragging a slider) condenses
into a single FAT32 write seconds later, not a write per slider step.

## Capability Gates

Registry read paths are open to any process. Write paths
(`RegSetValueExW`, `RegDeleteValueW`) are gated by the surrounding NT
syscall handler on `kCapRegistryWrite` (proposed) or, in v0,
`kCapFsWrite` since the hive ultimately reaches the disk. See
[Capabilities](../security/Capabilities.md). The settings app
elevates through the broker on first write.

## Boot Self-Test

`RegistrySelfTest()` runs at boot and verifies:

- Static keys read back the expected hard-coded values
- A round-trip Set → Query → Delete on a test key behaves correctly
- Hive load survives a corrupted line at end-of-file
- The throttle path's byte-compare correctly suppresses redundant writes

A failure fires `kBootSelftestFail` with the sub-check index.

## Syscall Surface

The kernel registers a single `SYS_REGISTRY` opcode with an
operation sub-selector. Operations:

| Op | Maps to |
|----|---------|
| `OpenKey` | `RegOpenKeyExW` |
| `CloseKey` | `RegCloseKey` |
| `QueryValue` | `RegQueryValueExW` |
| `EnumerateKey` | `RegEnumKeyExW` |
| `EnumerateValue` | `RegEnumValueW` |
| `QueryKey` | `RegQueryInfoKeyW` |
| `SetValue` | `RegSetValueExW` |
| `DeleteValue` | `RegDeleteValueW` |

The dispatcher lives in `registry.cpp`'s `DoRegistry(TrapFrame*)`. The
Win32 thunks ([`userland/libs/advapi32/`](../../userland/libs/advapi32/))
issue this syscall.

## Threading and Locking

- A single spinlock guards the pool. Writes happen under it; reads
  too (the table is small enough that a per-slot read lock isn't
  worth the complexity).
- The persistence worker takes a snapshot under the lock, then writes
  to FAT32 outside the lock so I/O doesn't block readers.
- Static keys are immutable after boot — no lock needed to read them.

## Known Limits / GAPs

- **`RegCreateKeyEx`** — return `ERROR_NOT_SUPPORTED`. Keys are
  fixed; only values can be added. The mainstream PE startup paths
  do not need this; the few that do are documented compat shims.
- **`RegNotifyChangeKey`** — no-op. v0 doesn't notify on changes.
- **Per-key security descriptors** not modelled. Win32 always sees
  "anyone can read."
- **Transactions** (`KTM`) not modelled.
- **Hive size cap** — 32 sidecar slots; refusal once full. Increases
  belong in a Roadmap entry.
- **Path length cap** — 128 chars. Names — 64. Payload — 256 bytes.
- **No persistence schema migration.** Format changes need a manual
  hive rewrite tool.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md) — broader Win32 story
- [Win32 DLLs](Win32-DLLs.md) — advapi32 is the registry's user-mode face
- [Capabilities](../security/Capabilities.md) — write gate
- [Auth and Login](../security/Auth-and-Login.md) — USERNAME source
- [Win32 Surface Status](../reference/Win32-Surface-Status.md) — per-export
  REAL / STUB / MISSING inventory for advapi32
- [FAT32](../filesystem/FAT32.md) — persistence target
