// DuetFS — DuetOS native filesystem, v0.
//
// First Rust subsystem to land in the kernel tree. Clean-room rewrite
// inspired by RedoxFS — see Cargo.toml for the lineage note.
//
// Scope of v0 (deliberately tiny — proves FFI + build + VFS plumbing):
//   - read-only path lookup
//   - fixed 256-byte nodes, 4 KiB blocks
//   - one root directory, files store contiguous extents
//   - no CoW, no journal, no encryption, no compression
//
// The C++ kernel side talks to this crate exclusively through the C
// FFI declared in include/duetfs.h. No `unsafe` outside the FFI wall.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod format;
mod image;
mod lookup;
mod panic;

pub use format::{BLOCK_SIZE, MAGIC, NODE_SIZE, NODES_PER_BLOCK, NODE_KIND_DIR,
                 NODE_KIND_FILE, NODE_KIND_UNUSED, ROOT_NODE_ID, VERSION};

pub mod ffi;
