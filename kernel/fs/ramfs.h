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

/// Reset every mutable snapshot buffer reachable through /proc
/// and /sys (boottrace, syscalls, abi/native, abi/win32, cpuhist,
/// inspect slots): cursor → 0 so the next Snapshot starts from
/// the head, and the corresponding RamfsNode.file_size → 0 so a
/// `cat` between Teardown and the next Snapshot reads empty.
/// The constinit trusted + sandbox trees are not touched.
/// Idempotent.
void RamfsTeardown();

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

/// Refresh `/proc/dumps` with the current contents of the in-
/// kernel recent-dumps ring owned by
/// `kernel/security/domain_dump.cpp`. Called from the heartbeat
/// thread after `FaultDomainTick` so the userland-visible file
/// is at most one heartbeat stale. Cheap when the ring is empty
/// — one bounded scan + zero copy. Safe from heartbeat / shell
/// context; not safe from a trap handler (the formatter takes
/// a spinlock internally).
void RamfsDumpsSnapshot();

/// Refresh `/proc/fixjournal` from the live `diag::FixJournal*`
/// ring. Tab-separated; header on the first line. Called from the
/// heartbeat alongside `RamfsDumpsSnapshot` so the file's content
/// is at most one tick stale. Used by reviewers (Claude or human)
/// to triage observed gaps without a shell prompt.
void RamfsFixJournalSnapshot();

/// Refresh `/proc/kstat` from the live `diag::KstatRegister`-d
/// registry. One line per entry: `<module>:<name> <kind> <value>`,
/// with a `#`-prefixed header. Called from the heartbeat so the
/// file's content is at most one tick stale; cheap (no allocations,
/// bounded format, one walk over <=128 entries).
void RamfsKstatSnapshot();

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

/// Populate `/sys/inspect/<basename>` for each PE shipped in
/// `/bin`. Each file holds a short summary (image base,
/// entry RVA, image size, section count, exports status)
/// produced by `PeQuickSummaryTo`. 1 KiB per entry is enough
/// for the summary; full PeReport-style disassembly remains
/// serial-only.
void RamfsInspectSnapshot();

/// Borrowed pointer + length of the hand-built userland shell
/// stub ELF. The kernel boot path spawns this at end of init
/// to demonstrate ring-3 + SYS_WRITE + SYS_EXIT end to end.
/// A future slice grows this into a real prompt-driven shell.
const u8* RamfsUsershellElfBytes();
u64 RamfsUsershellElfSize();

/// Embedded UEFI loader bytes (PE32+ EFI Application built by
/// `add_subdirectory(boot/uefi)`). Used by the disk installer to
/// stamp a real BOOTX64.EFI into the freshly-formatted ESP. Bytes
/// live for the kernel's entire lifetime (constexpr `.rodata`).
const u8* RamfsBootX64EfiBytes();
u64 RamfsBootX64EfiSize();

/// Embedded stage-1 kernel ELF bytes for the disk installer.
/// Populated from a `.incbin` directive in
/// `kernel_elf_blob.S` (built by tools/build/gen-kernel-blob.sh).
/// When the build option `DUETOS_INSTALLER_KERNEL_EMBED` is ON,
/// the bytes are the freshly-built `duetos-kernel-stage1.elf` and
/// `RamfsKernelElfSize()` returns its real length (~10 MiB on a
/// debug build). When OFF (default), the bytes are absent and
/// `RamfsKernelElfSize()` returns 0; the installer detects this
/// and skips the kernel-ELF write step with a one-line note.
const u8* RamfsKernelElfBytes();
u64 RamfsKernelElfSize();

/// Portable native ELF demo apps. Built from
/// `userland/native-apps/<name>/<name>.c` via the
/// `duetos_native_app()` CMake helper, embedded into ramfs at
/// build time. Spawned by main.cpp's ring-3 init to prove the
/// portable-app pipeline survives every regression. See
/// `wiki/tooling/Native-Apps.md` for the migration plan that
/// uses this helper to move the in-kernel apps under
/// `kernel/apps/` out into separate ELFs.
const u8* RamfsHelloNativeBytes();
u64 RamfsHelloNativeSize();
const u8* RamfsNatCalcBytes();
u64 RamfsNatCalcSize();
const u8* RamfsNatSysinfoBytes();
u64 RamfsNatSysinfoSize();
// `/bin/netd` — first resident userland network daemon (TCP echo
// server on :7777). Runs as a restart=Always service via the service
// manager; uses the native libc BSD socket wrappers (duet/socket.h).
const u8* RamfsNetdBytes();
u64 RamfsNetdSize();
// `/bin/duet-pkg` — on-target package manager scaffold (slice A of
// the self-sufficiency bundle). v0 ships a SHA-256 selftest + argv
// parser; fetch / verify / install land in follow-on slices.
const u8* RamfsDuetPkgBytes();
u64 RamfsDuetPkgSize();

} // namespace duetos::fs
