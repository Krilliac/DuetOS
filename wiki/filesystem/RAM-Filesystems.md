# In-RAM Filesystems (ramfs + tmpfs)

> **Audience:** FS authors, kernel hackers, anyone touching
> per-process root jails or `/proc` / `/sys` / `/tmp` paths
>
> **Execution context:** Kernel — ramfs is read-only and safe at any
> interrupt level; tmpfs is task-context only (no IRQ safety)
>
> **Maturity:** ramfs v1 (constinit + per-process root + mutable
> `/proc` snapshot buffers); tmpfs v0 (writable, 16-slot flat
> namespace)

## Overview

DuetOS has two in-RAM filesystem tiers, separated by mutability:

- **ramfs** — read-only, constinit tree of files and directories
  served from `.rodata`. Hosts `/`, `/etc`, `/bin`, and the
  mutable-but-kernel-owned snapshot files under `/proc/*` and
  `/sys/*`.
- **tmpfs** — writable, flat-namespaced tier mounted at `/tmp`. 16
  named slots × 512-byte content buffers. Lives in `.bss` so boot
  layout is fully static.

Together they let the kernel run with a complete VFS — including
per-process root jails — before any on-disk backend lands.

## When to Read This Page

- Adding a new `/proc` or `/sys` virtual file.
- Investigating why a sandboxed process can or can't see a path.
- Wiring a kernel app's persistent-ish state to `/tmp` before a
  real on-disk write path is available.
- Reviewing teardown semantics around the snapshot buffers.

## ramfs ([`kernel/fs/ramfs.{h,cpp}`](../../kernel/fs/ramfs.h))

### Node shape

```
struct RamfsNode {
    const char*              name;        NUL-terminated basename; empty = root
    RamfsNodeType            type;        kDir or kFile
    const RamfsNode* const*  children;    null-terminated array (kDir only)
    const u8*                file_bytes;  payload (kFile only)
    u64                      file_size;
};
```

Every node lives in `.rodata`. There is no allocation, no
mutation, and no reference counting. A rogue user-mode pointer
cannot corrupt the tree because the underlying pages are
read-only.

### Two trees

`RamfsInit` exposes two roots:

| Root                  | Purpose                                                       |
|-----------------------|---------------------------------------------------------------|
| `RamfsTrustedRoot()`  | Rich layout (`/etc`, `/bin`, `/proc`, `/sys`, …). Every normal process inherits this. |
| `RamfsSandboxRoot()`  | One file. Sandboxed processes literally cannot name anything else. |

Each `core::Process` carries exactly one root pointer; the
per-process view of `/` is that pointer. See
[Sandboxing](../security/Sandboxing.md) for the jail story.

### Mutable snapshot buffers

A handful of "files" in the trusted root have `file_bytes`
pointing at a static buffer that the kernel periodically rewrites:

| Path                  | Snapshot function           | Cadence                              |
|-----------------------|-----------------------------|--------------------------------------|
| `/proc/boottrace`     | `RamfsBoottraceSnapshot`    | Once at end of boot.                 |
| `/proc/dumps`         | `RamfsDumpsSnapshot`        | Every heartbeat tick.                |
| `/proc/fixjournal`    | `RamfsFixJournalSnapshot`   | Every heartbeat tick.                |
| `/proc/cpuhist`       | (push from `RamfsCpuSample`)| Per call (no auto-sampler yet).      |
| `/proc/abi/native`    | `RamfsAbiSnapshot`          | Once at boot — constexpr table.      |
| `/proc/abi/win32`     | `RamfsAbiSnapshot`          | Once at boot — constexpr table.      |
| `/sys/syscalls`       | `RamfsSyscallsSnapshot`     | Once at boot.                        |

The `file_size` on each snapshot file is the **current** populated
length. `RamfsTeardown` resets these (cursor and size both to
zero) so a `cat` between Teardown and the next Snapshot reads
empty. The constinit subtrees are not touched.

### Dentry cache

Lookups go through a 128-slot direct-mapped dentry cache keyed on
`(parent, name)`. Both positive **and** negative results cache,
which kills the repeated-absent-name probe storm that loader and
DLL-search paths otherwise produce. Because the topology is
immutable for the kernel's lifetime, negative entries need no
invalidation.

The contract is pinned by the in-code `CONTRACT` comment in
`vfs.cpp`. A future mutable-ramfs slice MUST flush the cache.

## tmpfs ([`kernel/fs/tmpfs.{h,cpp}`](../../kernel/fs/tmpfs.h))

### Shape

```
kTmpFsSlotCount  = 16   slots
kTmpFsNameMax    = 32   bytes per name
kTmpFsContentMax = 512  bytes per content buffer
```

All storage is `.bss`. Boot layout is fully static; no heap
dependency.

There is no nested directory structure under `/tmp`, no `mtime`,
no `ctime`, no permissions, no reference counting. The shape is
deliberately primitive — the first writable tier exists to prove
the syscall surface, not to be a complete FS.

### Operations (exposed through VFS)

| Operation              | Behaviour                                                                |
|------------------------|--------------------------------------------------------------------------|
| Create `/tmp/<name>`   | Reserves a slot; succeeds idempotently on a duplicate name.              |
| Write `/tmp/<name>`    | Replaces the slot's content; bounded by `kTmpFsContentMax`.              |
| Read `/tmp/<name>`     | Returns the slot's bytes.                                                |
| Delete `/tmp/<name>`   | Frees the slot.                                                          |
| List `/tmp/`           | Walks the slot table; empty slots elided.                                |

### Why kept separate from ramfs

ramfs's read-only constinit shape is the wrong fit for a writable
tier: making it mutable would require allocation, child-array
resizing, and reference counting — and would force every reader to
take a lock that the read-only design avoids today. tmpfs is the
narrow, audited alternative.

Every later writable tier (on-disk FS, network mount) plugs into
the VFS instead of routing through tmpfs. tmpfs is not a stepping
stone toward "ramfs with writes" — it is a permanent /tmp backend.

## Threading & Locking Model

- **ramfs**: stateless traversal over `.rodata`. Safe from IRQ.
  Snapshot writers (`Ramfs*Snapshot`) hold their respective source
  ring's lock during the format — heartbeat thread context, not
  trap context.
- **tmpfs**: no internal synchronisation. All callers are expected
  to be in task context with the shell's single-thread invariant
  holding. SMP / multi-process tmpfs needs a spinlock per slot
  table (or a single coarse one — contention is unlikely).

## Capability Surface

Neither ramfs nor tmpfs themselves are cap-gated; the VFS
syscalls that reach them are. A sandboxed process with the
sandbox root cannot reach `/tmp` because the path simply does not
exist under its root. A trusted process with the trusted root
sees `/tmp` and reaches the tmpfs slot table.

See [Capabilities](../security/Capabilities.md) for `kCapFsRead` /
`kCapFsWrite` definitions.

## Known Limits / GAPs

- **ramfs is immutable in v0.** Adding a new `/proc` file means
  editing the constinit tree in `ramfs.cpp`; mutable directories
  are a future slice that must flush the dentry cache.
- **tmpfs has no subdirectories.** `/tmp/foo/bar` is rejected.
- **tmpfs has no permissions or owner.** Every process with VFS
  visibility can read/write/delete every slot.
- **tmpfs is not persisted.** A reboot wipes every slot.
- **tmpfs slot count is fixed at 16.** Bumping the limit is a
  one-line constant; sizing is conservative until a real workload
  pushes against it.

## Related Pages

- [VFS](VFS.md) — the path walker that consumes both backends.
- [Mount Registry](Mount-Registry.md) — registry shape (ramfs sits
  outside the per-FsType vtable on purpose).
- [Sandboxing](../security/Sandboxing.md) — per-process root
  selection.
- [Process Model](../kernel/Process-Model.md) — where `root` lives
  on `Process`.
- [Diagnostics](../kernel/Diagnostics.md) — the snapshot files
  under `/proc` are the read-side surface for these subsystems.
