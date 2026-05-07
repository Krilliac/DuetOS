#pragma once

#include "util/types.h"

/*
 * DuetFS — C++ kernel-side adapter for the Rust crate at
 * kernel/fs/duetfs/. The crate exposes its FFI through
 * kernel/fs/duetfs/include/duetfs.h; this header layers the
 * kernel-facing concerns on top:
 *
 *   - Synthesizing a v0 test image at boot (BuildSelfTestImage).
 *   - Running the FFI round-trip self-test (DuetFsSelfTest).
 *   - The `duetos_rust_panic` shim (duetfs_rust_panic.cpp) that
 *     funnels Rust panics into the kernel panic path.
 *
 * Lineage: clean-room rewrite inspired by RedoxFS
 * (https://github.com/redox-os/redoxfs, MIT). The on-disk format
 * shipped by the Rust crate is documented in the crate's source —
 * this layer is purely about wiring the crate into the kernel.
 *
 * Context: kernel. Init runs late at boot, after klog is online
 * and well after the heap is up. The self-test allocates only
 * static storage (the synthesized image lives in .bss).
 */

namespace duetos::fs::duetfs
{

/// Size of the synthesized self-test image. v0 needs 4 blocks
/// (superblock + node table + dir-children block + one file's
/// data extent), 4 KiB each.
inline constexpr u32 kSelfTestImageBlocks = 4;
inline constexpr u32 kSelfTestImageBytes = kSelfTestImageBlocks * 4096u;

/// Build a synthesized DuetFS v0 image into `out_buf` of size
/// `kSelfTestImageBytes`. The image contains:
///   - root dir (node 0) with one child
///   - file "hello.txt" (node 1) holding the literal "Hello, DuetFS!"
///
/// No allocation; the buffer is the only storage. Called once by
/// the self-test at boot.
void BuildSelfTestImage(u8* out_buf);

/// Boot-time self-test of the DuetFS Rust crate FFI:
///   1. probe the synthesized image — must succeed
///   2. resolve "/hello.txt" — must return kind=file, size=14
///   3. read the file's bytes — must equal "Hello, DuetFS!"
///   4. resolve "/missing" — must miss
///   5. resolve "/.." — must miss (".." rejection)
///
/// Panics on any failure with a `duetfs/selftest` subsystem tag so
/// a regression is loud and surfaces in CI grep. Cheap — runs in
/// well under a millisecond.
void DuetFsSelfTest();

} // namespace duetos::fs::duetfs
