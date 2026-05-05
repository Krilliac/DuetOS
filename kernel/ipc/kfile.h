#pragma once

#include "ipc/kobject.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KFile` kernel object.
 *
 * WHAT
 *   Sixth concrete `KObject` subclass (after the IPC quintuplet
 *   KMutex / KEvent / KSemaphore / KMailbox / KWaitable). Wraps
 *   an open file descriptor — the kernel-internal name for the
 *   resource a Linux `int fd` or a Win32 `HANDLE hFile` points
 *   at.
 *
 * MAPS TO
 *   - Linux fd table entries (POSIX `open` returns an int that
 *     indexes into the per-process fd table).
 *   - Win32 NT file handles (`NtCreateFile`, etc.).
 *   - The "open file" abstraction every VFS-shaped operation
 *     ultimately operates on.
 *
 * SCOPE
 *   - Type + create/destroy lifecycle + a self-test that
 *     round-trips through HandleTable.
 *   - Carries a `KFileKind` tag so the destroy callback can
 *     route to the right per-state pool release (pipe / eventfd
 *     / socket / timerfd / signalfd / epoll / inotify / pidfd /
 *     posix_mq / memfd / fanotify / dirfd) without KFile having
 *     to know each pool's API. The Linux fd-table migration
 *     wires a `KFile*` sidecar onto every LinuxFd slot so
 *     every per-fd lifecycle event (close, dup, fork, exec
 *     teardown) goes through the unified handle table instead
 *     of open-coded `*Retain` / `*Release` calls in the syscall
 *     layer.
 *
 * THREADING
 *   Per-instance `pos` field is racy under SMP unless the
 *   caller serialises (most callers do, e.g. POSIX
 *   read/write hold the file's seek lock). v0 doesn't add a
 *   per-file mutex — that lands when the migration starts
 *   exposing concurrent fd accesses.
 */

namespace duetos::ipc
{

enum KFileFlags : u32
{
    kFileReadable = 1u << 0,
    kFileWritable = 1u << 1,
    kFileAppend = 1u << 2, ///< Reserved for POSIX O_APPEND.
};

/// Per-fd kind tag — selects which per-state pool the destroy
/// callback should release the `pool_index` against. Numeric
/// values mirror the historical `LinuxFd::state` u8 (so a future
/// audit can grep them across the migration boundary), but new
/// callers should use the named constants.
///
/// A KFile in `kFileKindNone` state means "no pool ref to drop
/// on destroy" — used for stdin / stdout / stderr (kFileKindTty)
/// and the `KFileSelfTest` synthetic case. New kinds append at
/// the end; never re-use a retired number.
enum class KFileKind : u8
{
    None = 0,         ///< no per-pool ref (test fixture)
    Tty = 1,          ///< stdin / stdout / stderr — no pool
    Fat32File = 2,    ///< regular file (FAT32-backed)
    PipeRead = 3,     ///< pipe read end → pool index = pipe slot
    PipeWrite = 4,    ///< pipe write end → pool index = pipe slot
    Eventfd = 5,      ///< eventfd → pool index
    Socket = 6,       ///< socket → pool index
    Timerfd = 7,      ///< timerfd → pool index
    Signalfd = 8,     ///< signalfd → pool index
    Epoll = 9,        ///< epoll → pool index
    Inotify = 10,     ///< inotify → pool index
    DirSnapshot = 11, ///< directory snapshot (Win32 win32_dirs[] slot)
    Pidfd = 12,       ///< pidfd → pool index = target pid (for now)
    PosixMq = 13,     ///< POSIX MQ → pool index
    Memfd = 14,       ///< memfd → pool index
    Fanotify = 15,    ///< fanotify → pool index
};

/// Per-kind release callback. Invoked by `KFileDestroy` with the
/// `pool_index` field of the file. nullptr = no callback (e.g.
/// `kFileKindNone` / `kFileKindTty`). Lets KFile stay in the IPC
/// layer without having to know each per-state pool's API; the
/// owning subsystem registers (or directly hands in) the callback
/// when it builds the KFile.
using KFilePoolRelease = void (*)(u32 pool_index);

struct KFile
{
    /// MUST be first — `KObject*` ↔ `KFile*` cast shape.
    KObject base;

    /// Tag selecting which per-state pool `pool_index` indexes.
    KFileKind kind;

    /// FD_CLOEXEC bit. Set at open time when O_CLOEXEC was
    /// requested (or via fcntl(F_SETFD, FD_CLOEXEC) — see
    /// LinuxFdSetCloexec). Read by `LinuxFdCloseOnExec` to
    /// drop the matching slots on exec. Independent of the
    /// underlying open-file description (per-fd, not per-file)
    /// — dup() resets cloexec to false on the new fd; dup3()
    /// honours O_CLOEXEC in flags.
    bool cloexec;

    /// Reserved padding so the struct stays 8-byte aligned.
    u8 _pad[2];

    /// Per-state pool index. Meaningful for kinds 3..15;
    /// ignored for None / Tty / Fat32File. The destroy
    /// callback receives this verbatim.
    u32 pool_index;

    /// Per-kind release callback, fired in `KFileDestroy` at
    /// the moment the refcount hits zero. nullptr = no-op.
    KFilePoolRelease release_pool;

    /// Opaque vnode handle — backend-specific (ramfs / fat32 /
    /// future-vfs). Used by `kFileKindFat32File` to point at the
    /// resolved on-disk entry. Other kinds leave it null.
    void* vnode;

    /// Current seek offset (kFileKindFat32File only).
    u64 pos;

    /// Bitwise-OR of `KFileFlags`. Tracks the open mode so a
    /// later `read` / `write` syscall can refuse a wrong-mode
    /// access. Linux-specific per-fd flags
    /// (kLinuxFdFlagPendingCreate / kLinuxFdFlagCanary) live on
    /// the `LinuxFd` struct in process.h — they describe FAT32
    /// backing state, not the unified open-file abstraction.
    u32 flags;

    /// For `kFileKindFat32File`: FAT32 first cluster of the
    /// underlying file. Cached at open time; updated when the
    /// pending-create path turns into a real cluster chain.
    u32 fat32_first_cluster;

    /// For `kFileKindFat32File`: cached file size at open. Hot-
    /// path syscalls update this in lockstep with the FAT32
    /// dir-entry write so subsequent reads see EOF correctly.
    u32 fat32_size;
};

/// Allocate + zero-init + KObjectInit a fresh KFile. Caller
/// hands the returned reference to a HandleTable. `kind` selects
/// which per-state pool `pool_index` indexes; `release` is the
/// callback invoked on destroy (may be nullptr for kinds with
/// no pool ref to drop). Returns `Err{ErrorCode::OutOfMemory}`
/// on heap exhaustion.
::duetos::core::Result<KFile*> KFileCreate(KFileKind kind, u32 pool_index, KFilePoolRelease release, void* vnode,
                                           u32 flags);

/// Read accessors — diagnostic only.
u64 KFilePosition(const KFile* f);
u32 KFileFlagsRead(const KFile* f);
KFileKind KFileKindRead(const KFile* f);
u32 KFilePoolIndex(const KFile* f);

/// Boot-time self-test. Allocates a KFile with kind=None,
/// inserts into a HandleTable, exercises lookup with right +
/// wrong type-tag, removes from the table, asserts destroy
/// fires. Also exercises the per-pool-release callback: builds
/// a KFile with a synthetic release fn + pool_index and asserts
/// the fn fires exactly once with the right index when the
/// refcount drops to zero. Panics on mismatch.
void KFileSelfTest();

} // namespace duetos::ipc
