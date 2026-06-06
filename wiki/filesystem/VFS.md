# VFS

> **Audience:** FS authors, kernel hackers
>
> **Execution context:** Kernel — process context for path resolution
>
> **Maturity:** v0 with per-process root + `..` rejected

## Overview

The DuetOS VFS routes path operations through a single namespace. Each
process holds a `Process::root` pointer into the VFS tree; **every
path is root-relative**. There is no per-process cwd, no ambient global
root, and `..` is rejected outright (allowing it would break any jail
whose root is embedded inside a larger tree).

## Files

- `kernel/fs/vfs.{h,cpp}` — VFS API + path walker
- `kernel/fs/ramfs.{h,cpp}` — in-memory tree used as boot root + jails
- `kernel/fs/tmpfs.{h,cpp}` — writable in-RAM tier mounted at `/tmp`
- `kernel/fs/mount.{h,cpp}` — mount registry + per-FsType lookup vtable
- `kernel/fs/file_route.{h,cpp}` — syscall-path routing layer used
  by `kernel/subsystems/win32/` and `kernel/subsystems/linux/` (see
  [Syscall Path Routing](#syscall-path-routing))
- `kernel/fs/<backend>.{h,cpp}` — FAT32, ext4, exFAT, NTFS, DuetFS, GPT

## Path Resolution

```
[ Process::root ]                  per-process VFS jail
        |
[ VFS path walker ]                kernel/fs/vfs.cpp
        |
[ FS backend lookup ]              ramfs / fat32 / ext4 / ntfs
        |
[ Storage driver ]                 NVMe / AHCI
```

A process with `CapSetEmpty` and a one-file ramfs subtree as its root
cannot name `/etc/version` even if the global VFS contains it. The
boot-time VFS self-test asserts this (`"JAIL BROKEN"` in the panic if
it regresses).

Ramfs component lookups go through a 128-slot direct-mapped **dentry
cache** keyed on `(parent, name)`. Both resolved *and* not-found
results are memoized — negative caching kills the repeated-absent-name
probe storm (loader / DLL-search / shell-completion) that otherwise
re-pays an O(children) linear scan every call. Because the ramfs tree
topology is immutable for the kernel's lifetime (`RamfsInit` is a
no-op; `RamfsTeardown` only rewinds /proc·/sys snapshot sizes, never
adds/removes/renames a node), negative entries need **no invalidation
or generation counter**. A future mutable-ramfs slice must flush this
cache — the in-code `CONTRACT` comment in `vfs.cpp` pins the
invariant.

## Syscall Path Routing

`kernel/fs/file_route.{h,cpp}` is the routing layer the syscall
dispatcher (Win32 + Linux ABIs) calls so `SYS_FILE_OPEN / READ /
WRITE / STAT` stay generic. It:

- **Routes by prefix.** Paths under `/bin/` resolve to the embedded
  ramfs (binaries baked into the kernel image at build time);
  everything else routes to the active mount at the longest
  matching prefix (FAT32 / ext4 / tmpfs / ramfs / DuetFS).
- **Normalises before any FS sees the path.** Leading-`/`
  enforcement and `..`-escape rejection happen here, so a guest
  binary can't climb out of its mount via `..` regardless of which
  backend serves the path.
- **Routes named-pipe handles.** A handle backed by a named pipe
  (`named_pipe_registry_slot >= 0`) is dispatched to the IPC
  named-pipe layer (`ipc/named_pipes.h`) on close rather than to a
  block-device backend.

## Backends

| Backend | Path | Status |
|---------|------|--------|
| ramfs | `kernel/fs/ramfs.{h,cpp}` | Read-only constinit tree + mutable `/proc` snapshots |
| tmpfs | `kernel/fs/tmpfs.{h,cpp}` | Writable flat `/tmp` (16 slots × 512 B) |
| FAT32 | `kernel/fs/fat32.{h,cpp}` + `fat32_*.cpp` | Read + write (in-place / append / create / delete / rename); LFN-validated |
| exFAT | `kernel/fs/exfat.{h,cpp}` + `exfat_rust/` | Read + bounded root-dir write (in-place / append / create / truncate); first-cluster enumeration |
| ext4 | `kernel/fs/ext4.{h,cpp}` + `ext4_rust/` | Read-only; dir + file extents walked every depth (file reads capped at depth 16); multi-component path resolve |
| NTFS | `kernel/fs/ntfs.{h,cpp}` + `ntfs_rust/` | Read-only; USA fixup + $I30 enum + resident/single-run $DATA reads; multi-component path resolve (resident $INDEX_ROOT only) |
| DuetFS | `kernel/fs/duetfs.{h,cpp}` + `duetfs/` | Native Rust FS; v8, per-block CRCs, symlinks, hard links, journal/crypto/snapshots (dormant on live path) |
| GPT | `kernel/fs/gpt.{h,cpp}` | Partition discovery |

## File Handles

Every Win32-PE-side `FILE*` from `ucrtbase` wraps a `FILE*` struct
around a real kernel handle (range `0x100..0x10F`) and routes through
`SYS_FILE_OPEN / READ / SEEK / CLOSE`. `stdin` / `stdout` / `stderr`
are preallocated with synthetic handles; `fwrite` / `fputs` route to
`SYS_WRITE(fd=1)`.

## Capability Surface

- `kCapFsRead` — `SYS_FILE_OPEN` (RO), `SYS_FILE_READ`, `SYS_STAT`
- `kCapFsWrite` — `SYS_FILE_WRITE` and the create/delete/rename/
  truncate mutators (on-disk write paths are live)

The gate is enforced in the **syscall layer**, not in `kernel/fs/`:
the Linux ABI checks `kCapFsWrite` in
`kernel/subsystems/linux/syscall_io.cpp`, `syscall_fs_mut.cpp`, and
`syscall_file.cpp`; the Win32 ABI gates it centrally through
`SyscallGate` (`cap_table.def`). The FS backends trust the gate has
already run. See [Capabilities](../security/Capabilities.md).

## Known Limits / GAPs

- **FAT32 mid-file growth is unwritten.** In-place writes,
  append-only growth, file create/delete/rename are live; a write
  that would extend the cluster chain is rejected with `-1`. See
  [FAT32](FAT32.md).
- **ext4 and NTFS are read-only.** Write paths for either are
  separate multi-slice efforts.
- **DuetFS symlinks/hard links live; on FAT32 / ext4 / NTFS they
  are not surfaced.** DuetFS resolves symlinks with cycle detection
  capped at 8 hops.
- **No file caching layer** between VFS and FS backends. Each
  backend serialises against the block device directly. Tracked
  in [Roadmap.md](../reference/Roadmap.md) — Haiku-style
  transactional `block_cache` is the next slice.

## Durability path (2026-05-27)

For "data survives a power cut" semantics the chain is:

```
FAT32 / DuetFS / ext4 commit point
        |
[ BlockDeviceFlush(handle) ]               kernel/fs/.../*.cpp
        |
[ Block layer dispatch ]                   kernel/drivers/storage/block.cpp
        |
[ NVMe Flush 0x00 / AHCI FLUSH CACHE EXT 0xEA / virtio-blk T_FLUSH ]
```

Every backend with a possible volatile write cache (every real
SSD, every QEMU virtio-blk over qcow2/raw) now wires the flush
op. `BlockDeviceFlush` on a backend with `flush == nullptr` is a
deliberate no-op success — only legitimate for the RAM-backed
test device, partition views (which forward to the parent), and
read-only mounts.

`BlockDeviceDiscard` rounds out the SSD-friendly tier:
`Fat32Delete*`/`Fat32Truncate*`/`FreeClusterChain` all hand the
freed-cluster LBAs to the block layer, which dispatches via
NVMe DSM Deallocate / AHCI DSM TRIM / virtio-blk DISCARD. The
`fstrim <volume>` shell command exposes the batch path.

## Related Pages

- [FAT32](FAT32.md), [exFAT](exFAT.md), [ext4](ext4.md),
  [NTFS](NTFS.md), [DuetFS](DuetFS.md)
- [RAM Filesystems (ramfs + tmpfs)](RAM-Filesystems.md)
- [Mount Registry](Mount-Registry.md)
- [Boot Slots](Boot-Slots.md)
- [GPT](GPT.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [Capabilities](../security/Capabilities.md)
- [Sandboxing](../security/Sandboxing.md)
