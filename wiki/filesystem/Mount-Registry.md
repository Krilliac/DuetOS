# VFS Mount Registry

> **Audience:** FS authors, kernel hackers
>
> **Execution context:** Kernel — boot init + shell mutator paths; lookup
> is process-context-safe from any caller
>
> **Maturity:** v0 — registry + longest-prefix resolution + per-FsType
> lookup vtable; ramfs intentionally not in the vtable

## Overview

[`kernel/fs/mount.{h,cpp}`](../../kernel/fs/mount.h) tracks the
binding between a mount point in the kernel's path namespace and a
backing block device + filesystem type. `VfsResolve` consults the
registry on every lookup, dispatches the longest-prefix match to
the backend's per-`FsType` vtable, and falls back to the ramfs
root for paths that don't match any mount.

A mount point is the single source of truth for "which backend
serves this path." Once a backend is in the table, every consumer
(shell, file-route layer, syscall surface) reaches it the same way.

## When to Read This Page

- Wiring a new on-disk filesystem backend into the VFS.
- Investigating a shell `mount` / `umount` failure or a stale
  registry entry after an installer run.
- Reviewing a slice that introduces a per-process namespace mask
  (process-visible vs. globally-mounted distinction).

## Table Shape

```
kMaxMounts = 16    fixed-size flat array, linear scan add / lookup
struct MountEntry {
    char     mount_point[64];   canonical absolute path
    FsType   fs_type;           Ramfs | Fat32 | Ext4 | Ntfs | DuetFs | RamVol
    u32      block_handle;      0 for ramfs / synth volumes
    u32      mount_seq;         monotonic id, ever-incrementing
    bool     in_use;
};
```

Sizing is deliberately small. The expected steady-state mount count
on a workstation install is ≤8 (root + ESP + system + crash-dump +
maybe a removable / DuetFS host); the table grows when a real
workload demands it.

`mount_seq` is a monotonic counter that increments on every mount
event ever recorded — re-using a freed slot will not collide with
a stale `MountId` from a previous mount. Consumers that cache a
`MountId` across unmount/mount cycles read `mount_seq` to detect
the swap.

## API

| Function                          | Purpose                                                                              |
|-----------------------------------|--------------------------------------------------------------------------------------|
| `VfsMount(path, fs, handle)`      | Register a new mount. Rejects mounting on top of an existing mount.                  |
| `VfsUmount(id)`                   | Drop a mount by id. Idempotent.                                                      |
| `VfsMountFind(path)`              | Exact-match lookup. Returns the entry pointer (stable until that mount's umount).    |
| `VfsMountResolve(path, &sub)`     | **Longest-prefix** lookup. Returns the matched entry plus the in-mount subpath.      |
| `VfsMountEnumerate(cb, cookie)`   | Walk every active mount; callback returns false to stop early.                       |
| `VfsMountCount()`                 | Live mount count.                                                                    |
| `VfsBackendForFsType(t)`          | Return the per-FsType `VfsBackendOps` vtable, or nullptr if no backend is wired.     |

`VfsMountResolve` is component-aware: a mount of `"/disk/0"` matches
`"/disk/0"`, `"/disk/0/"`, `"/disk/0/SUB"`, but **not** `"/disk/01"`.
The matched-prefix string must end at a path-component boundary.

## Per-FsType Lookup Vtable

```
VfsBackendOps {
    VfsBackendLookupFn lookup;   bool(u32 block_handle, const char* subpath, void* out_node)
};
```

`VfsResolve` calls `lookup` with the subpath returned by
`VfsMountResolve` and the entry's `block_handle`. The backend
returns its private vnode in `out_node`; callers stash that opaque
pointer into the resulting `VfsNode` and dispatch by `VfsBackend`
on subsequent reads.

Today's wiring:

| FsType        | Backend ops registered?         |
|---------------|---------------------------------|
| Ramfs         | **No** — see "Why no ramfs"     |
| Fat32         | Yes                             |
| Ext4          | Slot reserved; lookup is nullptr |
| Ntfs          | Slot reserved; lookup is nullptr |
| DuetFs        | Yes                             |
| RamVol        | Yes                             |

`VfsBackendForFsType` returns nullptr for unwired types so
`VfsResolve` falls back to the ramfs root instead of returning a
misleading "not found."

## Why no ramfs in the vtable

`VfsResolve` is **always** called with an explicit ramfs root
argument (`Process::root`). If ramfs were in the global mount
vtable, a process could see another root through the global table —
defeating the per-process jail in
[Sandboxing](../security/Sandboxing.md). The mount registry knows
about ramfs entries (the shell can list them, the boot init creates
them) but it never asks the registry for the lookup function. Path
resolution against ramfs ALWAYS starts from `Process::root`.

This is the only intentional asymmetry between FS backends in the
registry. Any new in-RAM backend must follow the same rule.

## Threading & Locking Model

The table is currently **unlocked**. The only mutator paths are:

- Boot init (single-threaded, runs before scheduler online).
- Kernel shell `mount` / `umount` commands (single shell thread).
- Installer paths (sequenced after the user-typed `INSTALL`
  confirmation).

`VfsMountResolve` is read-only and called from every `VfsResolve`,
so a future SMP scheduler that runs multiple ABI front-ends in
parallel will need a `SpinLock` around mutators and a `Seqlock` or
RCU-style scheme around the read side. Today the cost of adding it
is negligible but premature without a real concurrent caller.

## Boot Time Self-Test

`VfsMountSelfTest` runs from `kernel_main` alongside the other
boot self-tests:

1. Register a synthetic ramfs mount at a unique path.
2. Look it up by path; assert the returned entry matches.
3. Verify `VfsMountResolve` matches a deeper subpath correctly.
4. Unmount; assert the lookup misses.

A regression in path comparison or table bookkeeping panics the
kernel at boot.

## Shell Surface

```
shell$ mount                          # list every active mount
shell$ mount /dev/sda1 /mnt/disk      # register a FAT32 mount
shell$ umount /mnt/disk               # drop the mount
```

The shell command lives in `kernel/shell/shell_storage.cpp` and
walks `VfsMountEnumerate` for the list path.

## Known Limits / GAPs

- **No SMP locking.** Documented above — premature until a
  concurrent mutator exists.
- **Ext4 / NTFS lookup vtables unwired.** The registry slot is
  reserved so a backend can land without touching this file; the
  read paths themselves are the gating work.
- **No per-process mount visibility mask.** Every mount is visible
  to every process. Per-process namespaces would extend
  `MountEntry` with an owning-process or visibility set; the
  file-route layer already consults `Process::root` for ramfs
  isolation, so extending the same scheme to mounts is a one-slice
  change when a real consumer asks for it.

## Related Pages

- [VFS](VFS.md) — the path walker that consumes this table.
- [FAT32](FAT32.md), [ext4](ext4.md), [NTFS](NTFS.md),
  [DuetFS](DuetFS.md), [exFAT](exFAT.md) — the per-backend pages.
- [GPT](GPT.md) — partition discovery; output feeds `VfsMount`.
- [Sandboxing](../security/Sandboxing.md) — why ramfs sits outside
  the vtable.
