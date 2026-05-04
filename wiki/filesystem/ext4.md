# ext4

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context
>
> **Maturity:** Read-only v0; depth>0 extent-tree walk deferred

## Overview

`kernel/fs/ext4/` reads ext4 partitions for interoperability with
Linux-formatted media. Read paths are live for the root-directory
walk (every depth) and inode metadata; file-content reads beyond
the boot-time root-dir scan are deferred.

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

- **No file-content read API.** `Ext4ReadFile` / `Ext4LookupPath`
  haven't been written; the boot scan stops at root-dir entries.
  The extent walker is reusable and would need a wrapper that
  takes an inode + offset pair.
- **No write path.**
- **No journal replay.** A power-cycled ext4 partition with an unclean
  journal will read the pre-replay state — fine for tested-good
  images, dangerous on real workloads.
- **No legacy indirect-block format.** Modern ext4 only.

## Related Pages

- [VFS](VFS.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md)
