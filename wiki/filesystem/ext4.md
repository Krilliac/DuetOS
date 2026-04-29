# ext4

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context
>
> **Maturity:** Read-only v0; depth>0 extent-tree walk deferred

## Overview

`kernel/fs/ext4/` reads ext4 partitions for interoperability with
Linux-formatted media. Read paths are live for the common case (root
directory + leaf-extent files); deeper ext4 features are deferred.

## Extent Tree

ext4 stores file block lists as a tree of extent nodes. The current
walker:

- Iterates every leaf-extent block at depth 0.
- Returns blocks for files whose entire extent fits in the inode's
  embedded extent header.

GAP: depth > 0 extent tree walks (large files with many extents,
indirect blocks). See the ext4 entry in
`.claude/knowledge/deferred-task-batch-2026-04-25.md`.

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

- **No depth>0 extent-tree walk.** Large multi-extent files won't
  read past the leaf-block boundary.
- **No write path.**
- **No journal replay.** A power-cycled ext4 partition with an unclean
  journal will read the pre-replay state — fine for tested-good
  images, dangerous on real workloads.
- **No legacy indirect-block format.** Modern ext4 only.

## Related Pages

- [VFS](VFS.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md)
