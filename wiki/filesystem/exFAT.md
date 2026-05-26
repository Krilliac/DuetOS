# exFAT

> **Audience:** FS authors, interop-focused contributors
>
> **Execution context:** Kernel — process context, polling synchronous
> at probe time
>
> **Maturity:** v0 — signature probe + root-directory (first cluster)
> walk; subdirectory recursion and FAT-backed multi-cluster chains
> are deferred

## Overview

[`kernel/fs/exfat.{h,cpp}`](../../kernel/fs/exfat.h) reads exFAT
volumes for interoperability with cameras, SD cards, and other
removable media that Windows formats with exFAT instead of FAT32
(any media > 32 GiB on a modern Windows host). It is **not** a
FAT32 extension; the directory entry shape and free-cluster
bitmap layout differ enough that the two backends are kept as
separate files.

## Why a Separate Backend

FAT32 and exFAT share the same boot-sector heritage and the same
0x55AA signature at offset 510, but everything above that
diverges:

- Directory entries are 32 bytes in both formats, but exFAT
  encodes a single logical "file" as a **triad** (primary File
  Directory Entry `0x85` + stream-extension `0xC0` + 1–17 file-name
  entries `0xC1`), each carrying 15 UTF-16 chars of the name. FAT32
  uses an LFN chain of `0x0F` entries plus an 8.3 short name with
  a per-fragment checksum.
- exFAT has no FAT-style 8.3 fallback. Filenames are always Unicode.
- The free-cluster map is an explicit allocation bitmap entry on
  the root directory, not the per-cluster `FAT32_FREE` value.

Forking the parser was cheaper than overloading FAT32 with both
formats. Probe routines (`Fat32Probe` / `ExfatProbe`) sniff the
boot sector first and dispatch by signature.

## What Lives in v0

- **Signature probe.** Reads sector 0, validates the literal
  `"EXFAT   "` string at offset 3 (`EXFAT` plus three spaces) and
  the boot signature at offset 510.
- **Boot sector record.** Captures `bytes_per_sector_shift`,
  `sectors_per_cluster_shift`, FAT offset/length, cluster heap
  offset/count, and `first_cluster_of_root` into a `Volume` struct.
- **Root directory walk.** Reads the **first cluster** of the root
  directory and decodes each entry triad into a `DirEntry` record
  containing name, FAT-style attribute byte (0x10 = DIR,
  0x20 = ARCH), first cluster, valid-data length, and size.
- **Per-volume registry.** Up to `kMaxVolumes = 8` exFAT volumes
  tracked; each volume captures up to `kMaxDirEntries = 32` root
  entries on probe. Look up by index via `ExfatVolumeByIndex`.

## API

| Function                  | Purpose                                                                       |
|---------------------------|-------------------------------------------------------------------------------|
| `ExfatProbe(handle)`      | Sniff a block device; on `EXFAT` signature, parse the boot sector and root.   |
| `ExfatVolumeCount()`      | Live volume count.                                                            |
| `ExfatVolumeByIndex(i)`   | Stable pointer to the `Volume` record for inspection.                         |
| `ExfatScanAll()`          | Iterate every registered block handle and call `ExfatProbe`.                  |

## Directory Entry Shape

```
0x85  File Directory Entry        ─┐ One logical file = one triad:
0xC0  Stream Extension              │   primary File + Stream + Name(s)
0xC1  File Name (15 UTF-16 chars) ──┘
0x00  End of Directory             stops the walk
```

UTF-16 names are decoded to ASCII; non-ASCII code points map to
`'?'` (v0 limit — full Unicode renderer is downstream of the
console / GDI surfaces).

The high bit of the type byte distinguishes "in-use" (1) from
"deleted" (0). The walker rejects every entry with the high bit
clear.

## Known Limits / GAPs

- **First cluster of root only.** A multi-cluster root needs the
  FAT chain walker, which is the next slice. Practically, the
  first cluster (≥ 32 KiB on default-formatted media) carries the
  first ~100 root entries — adequate for verifying the probe path
  on test images, inadequate for a fully-populated camera SD card.
- **No subdirectory recursion.** Only the root is walked; opening
  a subdirectory is a future slice.
- **No reads of file content.** The walker captures
  `first_cluster` + `size_bytes` but the read path (chain walk +
  cluster fetch) is unwired.
- **No writes.** Write support is its own slice (and a much harder
  one given the allocation-bitmap design — see Microsoft's exFAT
  spec for the FAT-vs-bitmap interplay).
- **No upcase-table awareness.** Case-insensitive matching uses
  raw ASCII; correct exFAT behaviour requires consulting the
  on-disk upcase table for non-ASCII collation.

## Reference

The on-disk format is published in
[Microsoft's exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification).
The walker matches the spec for the entry-type values, signature
strings, and triad ordering.

## Related Pages

- [FAT32](FAT32.md) — sibling backend for ≤ 32 GiB volumes.
- [VFS](VFS.md) — mount integration (today exFAT volumes appear in
  the volume registry but are not in the per-FsType lookup vtable).
- [Mount Registry](Mount-Registry.md) — where future exFAT mounts
  would land.
- [GPT](GPT.md) — partition discovery feeds the probe path.
