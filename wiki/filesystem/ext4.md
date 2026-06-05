# ext4

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context
>
> **Maturity:** Read-only; directory extent walk handles every depth,
> file-extent reads still depth-0 only

## Overview

`kernel/fs/ext4.{h,cpp}` reads ext4 partitions for interoperability
with Linux-formatted media. Read paths are live for the
root-directory walk (every depth) and inode metadata; file-content
extent reads are still limited to depth-0 extent trees.

The byte-parsing layer is Rust: `kernel/fs/ext4_rust/` is a
**production crate** (no_std) that owns the superblock probe, the
group-descriptor decoder, the inode-record decoder, the
extent-header decoder, and the `linux_dirent` walker. The C++
wrapper in `ext4.cpp` delegates the byte parsing to the crate and
keeps block I/O, scratch management, the per-volume registry, and
logging.

## Extent Tree

ext4 stores file block lists as a tree of extent nodes. The current
walker:

- Iterates every leaf-extent block at depth 0 via `ProcessLeafExtents`.
- Iterative DFS through interior index nodes at depth > 0 via
  `WalkExtentIndexTree`, capped at 64 node visits to bound a corrupt
  or hostile tree (no parent pointer in the on-disk format means
  cycle detection has to be a visit cap).
- Reads each interior node into a dedicated scratch buffer (separate
  from the leaf-block scratch) so a leaf walk dispatched mid-traversal
  doesn't clobber the node still being iterated.

## Root Directory Walk

The root-dir walk iterates every leaf-extent block, decoding
`ext4_dir_entry_2` records. Names match against the path component
linearly.

## Inode Reading

Inode-table read paths are wired against the block-device read API.
Inode flags (`EXT4_EXTENTS_FL`) gate extent-format vs legacy
indirect-block format; legacy format is **not** supported (modern
mkfs.ext4 emits extent format by default since ~2008).

## Known Limits / GAPs

- **File-extent reads are depth-0 only.** `ext4.cpp:603` — the
  directory walk handles every extent-tree depth, but `Ext4ReadFile`
  only maps file blocks from a depth-0 extent tree; a file whose
  extents live behind an interior index node returns false. (The
  walker logic exists for directories; the file read path doesn't
  reuse it yet.)
- **No 64bit feature support.** `ext4.cpp:658` — only single-block,
  32-byte group descriptors are decoded; 64-byte descriptors /
  multi-block GDT (the `64bit` feature) are not handled.
- **Inode record must not straddle a block.** `ext4.cpp:673` — an
  inode record that crosses a block boundary is rejected.
- **No write path.**
- **No journal replay.** A power-cycled ext4 partition with an unclean
  journal will read the pre-replay state — fine for tested-good
  images, dangerous on real workloads.
- **No legacy indirect-block format.** Modern ext4 only
  (`ext4.cpp:717` rejects classic block maps).

## Capability / Privilege Surface

ext4 is read-only; reads are gated by `kCapFsRead`, enforced in the
syscall layer (see [FAT32](FAT32.md#capability--privilege-surface)
for the gate locations). There is no write surface to gate.

## Related Pages

- [VFS](VFS.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md)
