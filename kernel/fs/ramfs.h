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

/// Capture the current klog ring into the static `/proc/boottrace`
/// buffer. After this returns, `/proc/boottrace` reads the
/// captured bytes via the same path as any other ramfs file —
/// no callback machinery needed in the rest of the VFS.
///
/// Idempotent: each call overwrites the previous snapshot. Buffer
/// is 16 KiB; output truncates if the formatted log is larger.
/// Intended call site: end of boot, just before the login gate
/// or shell prompt, so the trace captures everything up to
/// "system ready".
void RamfsBoottraceSnapshot();

/// Format the native syscall number → name table into the static
/// `/sys/syscalls` buffer. Each line is "<dec_nr>  SYS_FOO\n",
/// in `kSyscallNames[]` order. Idempotent. Buffer is 8 KiB,
/// well above the current ~129-entry table size. Intended call
/// site: once during boot, alongside `RamfsBoottraceSnapshot`.
/// The table is constexpr so the snapshot never goes stale at
/// runtime — re-running it just rewrites the same bytes.
void RamfsSyscallsSnapshot();

/// Materialise `/proc/abi/native` (syscall number→name) and
/// `/proc/abi/win32` (every DLL!Function the Win32 thunks
/// table knows). Both files start with a "#"-prefixed header
/// line so a shell `cat` clearly identifies the dump. The
/// payload below is one entry per line. Idempotent — both
/// underlying tables are constexpr so re-running rewrites
/// the same bytes. Native buffer 8 KiB, Win32 buffer 32 KiB.
void RamfsAbiSnapshot();

/// Push one sample into the `/proc/cpuhist` ring (capacity 60)
/// and re-render the file. The busy % at each sample is the
/// 1 - (idle delta / total delta) ratio against the previous
/// sample. With no timer-driven sampler wired up yet, the
/// ring fills only at calls to this function — the file's
/// header explains the gap. A future slice will hang this
/// off a 1 Hz timer to fill the ring.
void RamfsCpuhistSnapshot();

} // namespace duetos::fs
