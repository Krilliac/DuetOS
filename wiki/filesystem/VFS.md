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
- `kernel/fs/routing.{h,cpp}` — kernel-side helper API used by
  `kernel/subsystems/win32/` and `kernel/subsystems/linux/`
- `kernel/fs/<backend>/` — FAT32, ext4, NTFS, GPT

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

## Backends

| Backend | Path | Status |
|---------|------|--------|
| ramfs | `kernel/fs/ramfs.{h,cpp}` | Read + write |
| FAT32 | `kernel/fs/fat32/` | Read-only; LFN walker validates SFN checksum |
| ext4 | `kernel/fs/ext4/` | Read-only; root-dir extents walked, depth>0 deferred |
| NTFS | `kernel/fs/ntfs/` | Read-only (work in progress) |
| GPT | `kernel/fs/gpt.{h,cpp}` | Partition discovery |

## File Handles

Every Win32-PE-side `FILE*` from `ucrtbase` wraps a `FILE*` struct
around a real kernel handle (range `0x100..0x10F`) and routes through
`SYS_FILE_OPEN / READ / SEEK / CLOSE`. `stdin` / `stdout` / `stderr`
are preallocated with synthetic handles; `fwrite` / `fputs` route to
`SYS_WRITE(fd=1)`.

## Capability Surface

- `kCapFsRead` — `SYS_FILE_OPEN` (RO), `SYS_FILE_READ`, `SYS_STAT`
- `kCapFsWrite` — `SYS_FILE_WRITE` (when on-disk write paths land)

See [Capabilities](../security/Capabilities.md).

## Known Limits / GAPs

- **No write paths past ramfs.** FAT32 / ext4 / NTFS are read-only;
  the FS write slice is the next FS milestone.
- **No symlinks.** Hard links not supported either.
- **No mount table.** Boot mounts the root ramfs; later FS mounts will
  need a real mount table.
- **No file caching layer** between VFS and FS backends.

## Related Pages

- [FAT32](FAT32.md)
- [ext4](ext4.md)
- [NTFS](NTFS.md)
- [GPT](GPT.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [Capabilities](../security/Capabilities.md)
- [Sandboxing](../security/Sandboxing.md)
