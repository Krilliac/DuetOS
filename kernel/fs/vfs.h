#pragma once

#include "util/types.h"
#include "fs/ramfs.h"

/*
 * DuetOS VFS — v0.
 *
 * "VFS" is generous: today the only backend is ramfs (kernel/fs/ramfs.h),
 * and this header's only responsibility is path resolution starting
 * from an explicit root. The abstraction is shaped so the day a real
 * disk-backed FS lands, the lookup primitive doesn't change — only
 * the leaf "read the bytes" path opens up.
 *
 * The path-resolution rules are deliberately strict and jail-friendly:
 *
 *   - Every resolution starts from a caller-supplied root. There is
 *     NO ambient "global filesystem root". A process's root is
 *     `Process::root` (which the kernel picks at spawn based on
 *     the process's trust level).
 *
 *   - Absolute paths ("/foo/bar") are resolved from the root.
 *     Relative paths ("foo/bar") are resolved from the root.
 *     There is no concept of a per-process "cwd" yet — every path
 *     is root-relative. That's a feature: a sandboxed process
 *     literally cannot name anything outside its root.
 *
 *   - ".." is REJECTED, not interpreted as "parent directory".
 *     Allowing ".." to climb would break sandbox containment the
 *     moment the sandbox root is embedded inside a richer tree.
 *     v0 stays safe-by-default; a future "canonical resolve" can
 *     add ".." with explicit anchoring at the process root.
 *
 *   - "." is accepted and skipped.
 *
 *   - Trailing slashes are tolerated.
 *
 *   - Empty components (consecutive slashes, "//") are tolerated
 *     and skipped.
 *
 *   - Lookups never follow a symlink — we don't have symlinks. If
 *     we ever do, a symlink that points outside the jail root
 *     must resolve through the caller's root, not the kernel's.
 *
 *   - Lookups that walk through a file-typed node fail (can't
 *     `cd` into a regular file).
 *
 * Return value is a const pointer to the resolved node, or nullptr
 * if any component is missing / rejected / malformed. Callers MUST
 * NOT mutate the returned node (everything lives in .rodata today).
 *
 * Context: kernel. Safe at any interrupt level — pure pointer walk
 * over constinit data.
 */

namespace duetos::fs
{

/// Resolve `path` starting from `root`. `path` may begin with '/'
/// (absolute against root) or not (relative to root, same effect).
/// Returns the resolved node, or nullptr on any failure.
///
/// `path` must be a kernel-pointer NUL-terminated string. Syscall
/// handlers that accept user-supplied paths MUST first CopyFromUser
/// into a kernel buffer before calling this — VfsLookup does not
/// touch user memory.
///
/// `path_max` bounds the number of bytes we'll scan from `path`
/// before declaring it malformed. Kept explicit (rather than strlen)
/// so a missing NUL doesn't run off into adjacent data.
const RamfsNode* VfsLookup(const RamfsNode* root, const char* path, u64 path_max);

/// Comprehensive self-test of the path resolver against the seeded
/// ramfs trees. Asserts every documented behaviour: positive lookups,
/// jail containment (sandbox root cannot see trusted paths), ".."
/// rejection, "." pass-through, empty-component tolerance, trailing
/// slash tolerance, walk-through-file rejection, null/zero-length
/// guards, and path_max truncation. Panics on any failure.
///
/// Runs at boot from kernel_main, before address-space isolation
/// brings up ring 3 — a VFS regression here is fatal because every
/// later subsystem (sandboxing, file syscalls) layers on these rules.
void VfsSelfTest();

} // namespace duetos::fs
