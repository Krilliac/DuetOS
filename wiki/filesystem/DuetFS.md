# DuetFS

> **Audience:** FS authors, kernel hackers, anyone touching the C++ ↔ Rust FFI boundary.
>
> **Execution context:** Kernel — process context.
>
> **Maturity:** v0 — read-only, in-memory image. No block-device backing yet.

## Overview

DuetFS is the project's **native filesystem**, written in Rust as the
first Rust subsystem in the kernel. v0 ships a tiny read-only path:
the C++ kernel hands the crate a byte slice (today: a synthesized
4-block image baked at boot in `.bss`), the crate parses the
superblock, walks the node table, resolves a path, and returns
file contents. The full DuetFS roadmap (CoW, journal, encryption,
compression, on-disk durability) lives behind subsequent slices.

The lineage is **clean-room from RedoxFS** ([redox-os/redoxfs](https://github.com/redox-os/redoxfs),
MIT). RedoxFS uses a B-tree and AES-XTS encryption; DuetFS v0 keeps
neither — they land later, behind their own slices, when the
slice-defining workload makes them earn their complexity.

## Files

- `kernel/fs/duetfs/` — Rust crate (no_std, panic=abort)
  - `Cargo.toml` — manifest; release profile is panic=abort, lto=thin.
  - `src/lib.rs` — module wiring + re-exports.
  - `src/format.rs` — on-disk types: `Superblock`, `Node`, kind tags.
  - `src/image.rs` — read-only view over a byte slice.
  - `src/lookup.rs` — path resolver (same shape rules as `vfs.h`).
  - `src/ffi.rs` — C ABI exports (`duetfs_probe`, `duetfs_lookup`, `duetfs_read_file`).
  - `src/panic.rs` — `#[panic_handler]` → `duetos_rust_panic` shim.
  - `include/duetfs.h` — hand-written C header (mirrored against `ffi.rs`).
  - `CMakeLists.txt` — leaf target wrapping `cargo build`.
- `kernel/fs/duetfs.{h,cpp}` — kernel-side adapter + boot self-test.
- `kernel/fs/duetfs_image.cpp` — synthesizes the v0 self-test image.
- `kernel/fs/duetfs_rust_panic.cpp` — Rust → C++ panic bridge.
- `rust-toolchain.toml` — pinned nightly (rust-src + x86_64-unknown-none target).

## On-disk format (v0)

All multi-byte integers are little-endian.

```
Block 0 (4 KiB)  Superblock {
                   magic         u64  = "DuetFS00"  (0x3030534674657544)
                   version       u32  = 1
                   block_size    u32  = 4096
                   total_blocks  u32
                   node_count    u32
                   root_node     u32  = 0
                   node_table_start u32 = 1
                   data_start    u32
                   reserved[8]
                 }

Block 1..N       Node table — fixed 256 B entries, 16 nodes/block.
                 Node {
                   kind          u32  (0=unused, 1=file, 2=dir)
                   size_bytes    u32  (file size or dir child_count*4)
                   first_block   u32  (file: extent start; dir: child id list)
                   child_count   u32  (dirs only)
                   name_len      u32
                   reserved      u32
                   name[64]
                   pad[168]
                 }

Block N+1..      Data blocks. Files: contiguous extent. Dirs:
                 child_count × u32 child node IDs, packed at the
                 head of one block.
```

**Known limits (v0):**

- Read-only.
- Single contiguous extent per file (no fragmentation).
- One block per directory's child list (cap: `child_count ≤ 1024`).
- No CoW, no journal, no encryption, no compression, no checksums.
- File names are case-sensitive, byte-for-byte; UTF-8 by convention.
- No symbolic links.

## C ↔ Rust FFI

The contract is hand-mirrored across two files. Bindgen / cbindgen
are forbidden — the C++ side reads `include/duetfs.h`; the Rust
side reads `src/ffi.rs`; both are short enough that a code review
catches a drift.

| Function | Purpose |
|---|---|
| `duetfs_probe(image, len)` | Returns 1 if the byte slice has a valid v0 superblock; cheap. |
| `duetfs_lookup(image, len, path, path_max, out)` | Resolves `path`; fills `LookupResult{kind, node_id, size_bytes, child_count}`. |
| `duetfs_read_file(image, len, node_id, off, dst, dst_max)` | Copies file bytes into `dst`; returns bytes copied. |

**Path-resolution rules** mirror `kernel/fs/vfs.h` exactly: leading
`/` optional, `.` skipped, `..` rejected, empty components
tolerated.

## Build wiring

`kernel/fs/duetfs/CMakeLists.txt` calls `cargo build --release
--target x86_64-unknown-none -Z build-std=core,alloc -Z
build-std-features=compiler-builtins-mem` and emits a `libduetfs.a`
that both kernel stages link against. The toolchain channel +
components are pinned in `/rust-toolchain.toml`; rustup picks them
up automatically when cargo runs.

A clean `cmake --preset x86_64-debug && cmake --build build/x86_64-debug`
invokes the cargo build once and links it into both `duetos-kernel-stage1.elf`
and `duetos-kernel.elf`. The crate's compiled `.a` lives at:

```
build/x86_64-debug/kernel/fs/duetfs/cargo-target/x86_64-unknown-none/release/libduetfs.a
```

## Boot self-test

`duetos::fs::duetfs::DuetFsSelfTest()` runs after the cross-mount VFS
self-test. It synthesizes an image, exercises five contracts, and
panics with subsystem `duetfs/selftest` on failure. Cases:

1. Probe accepts the synthesized image.
2. Probe rejects a corrupted superblock (XOR'd magic byte).
3. Lookup `/hello.txt` returns `kind=file`, `size=14`, `node_id=1`.
4. `read_file` returns `"Hello, DuetFS!"`.
5. Lookup of `/no_such_file` misses.
6. Lookup of `/..` is rejected (no parent climb).

A clean release boot drops the self-test entirely (`if constexpr
(kBootSelfTests)`); a debug build runs it on every boot.

## Pending work

Tracked in [`Roadmap.md`](../reference/Roadmap.md):

- Block-device backed image (today: in-memory only).
- Write path (mkfs in Rust, runtime mkdir / create / write).
- B-tree directory index (replace flat node table).
- Multi-extent files.
- CoW + journal + checksums.
- AES-XTS encryption + Argon2 key derivation.
- LZ4 compression.
- VFS routing — `FsType::DuetFs` enum value and registration in
  `kernel/fs/mount.cpp`'s `VfsBackendForFsType`.
