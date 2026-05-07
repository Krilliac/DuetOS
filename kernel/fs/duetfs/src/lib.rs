// DuetFS — DuetOS native filesystem.
//
// First Rust subsystem to land in the kernel tree. Clean-room
// rewrite inspired by RedoxFS — see Cargo.toml for the lineage note.
//
// v1 surface:
//   - mkfs (format an empty image)
//   - lookup_path / read_at / write_at
//   - create_file / create_dir
//   - unlink (file or empty dir)
//   - truncate (grow + shrink files)
//   - free-block bitmap (real allocation, not bump-only)
//   - single contiguous extent per file/dir + auto-grow on write
//
// The C++ kernel side talks to this crate exclusively through the
// C FFI declared in include/duetfs.h. No `unsafe` outside the FFI
// wall (block_dev.rs's pointer-borrowing impls are FFI-adjacent
// and live behind the `unsafe fn` constructors).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod alloc_bitmap;
mod block_dev;
mod crc32;
mod crc_table;
mod format;
mod fs;
mod fsck;
mod mkfs;
mod ops;
mod ops_dir;
mod panic;
mod path;

pub mod ffi;
