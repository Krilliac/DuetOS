#pragma once

#include "util/types.h"

/*
 * DuetOS ramfs — v0.
 *
 * A read-only, in-memory tree of directories and files seeded at boot.
 * Purpose: provide the FIRST concrete VFS backend so per-process
 * namespace isolation (Process::root) can be demonstrated end-to-end
 * before a real on-disk filesystem lands.
 *
 * Shape:
 *   - Every node is either a `kDir` (has children) or a `kFile` (has
 *     bytes). No hybrid types.
 *   - Children of a directory are stored as a flat array of node
 *     pointers. Lookup is linear — fine for v0's tiny trees.
 *   - Node data lives in `.rodata`. No allocation, no mutation. This
 *     keeps the teardown story trivial (there is none) and means a
 *     rogue user-mode pointer can't corrupt the tree.
 *
 * Two trees are seeded at init:
 *   - A "trusted root" used by every normal process. Richer layout
 *     (/etc, /bin).
 *   - A "sandbox root" used by the canonical untrusted profile.
 *     Contains exactly ONE file. A sandboxed process's path
 *     resolution starts from here, so it literally cannot name
 *     anything outside this subtree — the rest of the tree does
 *     not exist from its perspective.
 *
 * Both roots are accessible from kernel code via RamfsTrustedRoot()
 * / RamfsSandboxRoot(). Each `core::Process` stores exactly one
 * root pointer; the per-process view of `/` is that pointer.
 *
 * Context: kernel. Safe at any interrupt level (all data is read-
 * only, all traversal is stateless).
 */

namespace duetos::fs
{

enum class RamfsNodeType : u8
{
    kDir = 0,
    kFile = 1,
};

struct RamfsNode
{
    const char* name; // NUL-terminated basename; empty for root
    RamfsNodeType type;
    // For kDir: children is a null-terminated array of child nodes.
    //          file_bytes / file_size are unused.
    // For kFile: children is nullptr. file_bytes points at the
    //            payload; file_size is its length in bytes.
    const RamfsNode* const* children;
    const u8* file_bytes;
    u64 file_size;
};

/// Prime internal state. No-op today (both trees are constinit), but
/// the call site is already wired so future mutable state (dentry
/// cache, ID allocation) has a home.
void RamfsInit();

/// Root of the rich "trusted" tree. Stable pointer for the lifetime
/// of the kernel.
const RamfsNode* RamfsTrustedRoot();

/// Root of the one-file "sandbox" tree. Stable pointer for the
/// lifetime of the kernel.
const RamfsNode* RamfsSandboxRoot();

/// True if `n` is a directory and has at least one child. Cheap
/// sentinel check used by the VFS walker.
bool RamfsIsDir(const RamfsNode* n);

} // namespace duetos::fs
