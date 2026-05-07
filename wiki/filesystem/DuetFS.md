# DuetFS

> **Audience:** FS authors, kernel hackers, anyone touching the C++ ↔ Rust FFI boundary.
>
> **Execution context:** Kernel — process context.
>
> **Maturity:** v1 — full write path, free-block bitmap, mounted at boot.

## Overview

DuetFS is the project's **native filesystem**, written in Rust as the
first Rust subsystem in the kernel. v1 ships a complete read + write
path:

- mkfs (format an empty image)
- create / unlink (files + directories)
- read / write (with auto-grow on write past the current extent)
- truncate (grow + shrink)
- mounted at `/duetfs` from boot via `DuetFsBoot`
- routed through the standard VFS (`VfsResolve("/duetfs/...")` returns a `VfsNode` with `backend == VfsBackend::DuetFs`)

CoW / journal / checksums / encryption / compression / B-tree
directory index land in later slices.

The lineage is **clean-room from RedoxFS** ([redox-os/redoxfs](https://github.com/redox-os/redoxfs),
MIT). RedoxFS uses a B-tree and AES-XTS encryption; DuetFS v1 keeps
neither — they land later, behind their own slices, when the
slice-defining workload makes them earn their complexity.

## Files

- `kernel/fs/duetfs/` — Rust crate (no_std, panic=abort)
  - `Cargo.toml` — manifest; release profile is panic=abort, lto=thin.
  - `src/lib.rs` — module wiring + re-exports.
  - `src/format.rs` — on-disk types: `Superblock`, `Node`, kind tags, layout constants.
  - `src/block_dev.rs` — `BlockDevice` trait + `MemoryBlockDevice` (FFI-borrowing) + `ExternBlockDevice` (callback-driven).
  - `src/alloc_bitmap.rs` — free-block bitmap allocator (1 block, 1 bit per FS block, first-fit).
  - `src/fs.rs` — `Fs<'d, D>` open / sync + node-table I/O + block alloc/free.
  - `src/ops.rs` — `lookup_path / read_at / write_at / create_file / create_dir / unlink / truncate`.
  - `src/ops_dir.rs` — directory + extent helpers (`find_in_dir / dir_add_child / dir_remove_child / grow_file`).
  - `src/path.rs` — path iterator (same shape as `kernel/fs/vfs.h`).
  - `src/mkfs.rs` — formats an empty image with a root dir.
  - `src/ffi.rs` — C ABI surface (`duetfs_probe / duetfs_mkfs / duetfs_lookup / duetfs_read_file / duetfs_write_at / duetfs_create_path / duetfs_unlink_path / duetfs_truncate`).
  - `src/panic.rs` — `#[panic_handler]` → `duetos_rust_panic` shim.
  - `include/duetfs.h` — hand-written C header (mirrored against `ffi.rs`).
  - `CMakeLists.txt` — leaf target wrapping `cargo build`.
- `kernel/fs/duetfs.{h,cpp}` — kernel-side adapter, `DuetFsBoot`, `DuetFsSelfTest`.
- `kernel/fs/duetfs_block_dev.cpp` — `Device` builder helpers (memory + block-handle backed).
- `kernel/fs/duetfs_rust_panic.cpp` — Rust → C++ panic bridge.
- `rust-toolchain.toml` — pinned nightly (rust-src + x86_64-unknown-none target).

## On-disk format (v1)

All multi-byte integers are little-endian. Magic = `"DuetFS01"`,
version = 2.

```
Block 0          Superblock {
                   magic              u64  = "DuetFS01" (0x3130534674657544)
                   version            u32  = 2
                   block_size         u32  = 4096
                   total_blocks       u32
                   node_count         u32  = 64
                   root_node          u32  = 0
                   bitmap_lba         u32  = 1
                   node_table_lba     u32  = 2
                   node_table_blocks  u32  = 4
                   data_lba           u32  = 6
                   free_blocks        u32  (accounting; rederivable)
                   reserved[5]
                 }

Block 1          Free-block bitmap (1 bit per FS block, LSB-first
                 within each byte; bit set = block in use). Caps the
                 image at 32 768 blocks (128 MiB) in v1.

Block 2..=5      Node table — fixed 256 B entries, 16 nodes/block,
                 64 nodes total.
                 Node {
                   kind          u32  (0=unused, 1=file, 2=dir)
                   size_bytes    u32  (file: byte length; dir: child_count*4)
                   first_block   u32  (file/dir extent start)
                   ext_blocks    u32  (number of blocks reserved for the extent)
                   child_count   u32  (dirs only)
                   name_len      u32
                   parent_id     u32
                   reserved      u32
                   name[64]
                   pad[160]
                 }

Block 6..        Data blocks. Files: contiguous extent, ≤ ext_blocks
                 in length. Dirs: child_count × u32 child node IDs
                 packed at the head of the dir's first block (cap:
                 1024 children).
```

**Known limits (v1):**

- Single contiguous extent per file (no fragmentation, no indirect blocks). Writes that exceed the extent trigger a realloc-and-copy grow with a double-and-grow strategy.
- Directories cap at 1024 children (one block of child IDs).
- Maximum image size: 128 MiB (single-block bitmap).
- Maximum node count: 64 per filesystem (4 blocks of node table).
- No CoW, no journal, no checksums, no encryption, no compression.
- No symbolic links.
- `truncate` shrink does NOT free extent blocks (free-on-shrink lands in a follow-up slice).

## Boot integration

`DuetFsBoot()` runs after the cross-mount VfsResolve self-test. It:

1. Builds a `Device` over a 256 KiB `.bss` buffer (`g_boot_image`).
2. Calls `duetfs_mkfs` to format it (kStatusOk required).
3. Seeds `/etc/version` with `"DuetFS v1 (kernel boot)\n"` so any boot-log checker can confirm DuetFS is alive.
4. Registers the volume in the VFS mount table at `/duetfs` with `FsType::DuetFs` and `block_handle = 0xFFFFFFFFu` (the boot-handle sentinel).

After boot, every `VfsResolve("/duetfs/<path>")` call dispatches
through `mount.cpp`'s `DuetFsLookup`, which builds a fresh `Device`
from the stored `block_handle` via `DeviceForMountHandle`, calls
`duetfs_lookup`, and returns a `VfsNode` with `backend ==
VfsBackend::DuetFs` populated.

## C ↔ Rust FFI

The contract is hand-mirrored across two files. Bindgen / cbindgen
are forbidden — the C++ side reads `include/duetfs.h`; the Rust
side reads `src/ffi.rs`.

| Function | Purpose |
|---|---|
| `duetfs_probe(dev)` | Return 1 if the device holds a valid v1 superblock. |
| `duetfs_mkfs(dev)` | Format the device. Wipes superblock + bitmap + node table; creates the root dir. |
| `duetfs_lookup(dev, path, path_max, out)` | Resolve a path; fill `LookupResult{kind, node_id, size_bytes, child_count}`. |
| `duetfs_read_file(dev, node_id, off, dst, dst_max, out_copied)` | Copy file bytes into `dst`. |
| `duetfs_write_at(dev, node_id, off, src, src_max, out_written)` | Write bytes; auto-grow file if needed. |
| `duetfs_create_path(dev, path, path_max, kind, out_node_id)` | Create a file or directory. Parent must exist. |
| `duetfs_unlink_path(dev, path, path_max)` | Remove a file or empty directory. |
| `duetfs_truncate(dev, node_id, new_size)` | Set a file's logical size, growing the extent if needed. |

All ops take a `Device` descriptor with `cookie` + `read` + `write`
callbacks. The crate constructs an internal `Fs` from the
descriptor on each call, performs the op, and lets the `Fs` drop —
no state retained across calls. Bitmap mutations auto-flush, so a
successful return leaves the device consistent.

## VFS routing

`mount.cpp` registers `g_duetfs_ops` in the per-`FsType` vtable.
`VfsResolve("/duetfs/foo/bar")`:

1. The mount-point resolver in `mount.cpp` matches `/duetfs` against
   the table, hands back `(MountEntry{FsType::DuetFs, block_handle},
   subpath="/foo/bar")`.
2. `VfsResolve` calls `g_duetfs_ops.lookup(block_handle, subpath, &node)`.
3. `DuetFsLookup` builds a `Device` via `DeviceForMountHandle(block_handle)`, calls `duetfs_lookup`, and stuffs the result into a `VfsNode`.
4. The caller gets a `VfsNode` with `backend == VfsBackend::DuetFs`,
   `duetfs_node_id`, `duetfs_kind`, `duetfs_size_bytes`,
   `duetfs_child_count` populated. `VfsNodeIsDir / VfsNodeIsFile /
   VfsNodeSize` understand the new backend.

## Boot self-test

`duetos::fs::duetfs::DuetFsSelfTest()` runs against a SCRATCH
RAM image (`g_scratch_image`, 256 KiB in `.bss`) so the boot
mount stays untouched. It exercises:

1. mkfs round-trip: pre-mkfs probe rejects → mkfs returns Ok → post-mkfs probe accepts.
2. Lookup `/` returns the root dir, `node_id = 0`.
3. Create `/hello.txt`, write `"Hello, DuetFS v1!"`, read back, byte-compare.
4. Create `/etc` dir, create `/etc/version` file, write `"v1.0\n"`, lookup, stat the size.
5. `unlink /etc` on non-empty dir returns `kStatusDirNotEmpty`; `unlink /etc/version` succeeds; `unlink /etc` (now empty) succeeds; post-unlink lookup returns `kStatusNotFound`.
6. Truncate `/hello.txt` to 8 KiB (grow), then to 4 bytes (shrink); post-truncate lookup confirms the new size.
7. `lookup /..` returns `kStatusInvalid` (no parent climb).

A clean release boot drops the self-test entirely (`if constexpr
(kBootSelfTests)`); a debug build runs it on every boot.

## Pending work

Tracked in [`Roadmap.md`](../reference/Roadmap.md):

- Multi-extent files (drop the contiguous-extent constraint).
- Multi-block directories (raise the 1024-child cap).
- Free-on-shrink `truncate`.
- B-tree directory index (when first directory grows past ~1000 entries).
- CoW + journal + checksums (durability tier — currently no crash safety).
- AES-XTS encryption + Argon2 KDF.
- LZ4 compression.
- Persistent backing (today the boot image is `.bss`, lost on reboot — a real on-disk DuetFS partition is the next-after-this slice).
- `fsck` (re-derive the bitmap from the node table at mount).
