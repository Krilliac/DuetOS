#pragma once

#include "ipc/kobject.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KFile` kernel object, v0 (plan A3-followup).
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
 * SCOPE FOR v0
 *   - Type + create/destroy lifecycle + a self-test that
 *     round-trips through HandleTable.
 *   - Three pieces of state: the inode/path identifier (`vnode`),
 *     the current file offset (`pos`), and an OR-mask of
 *     "opened for read / write" flags.
 *   - NO actual I/O. The Linux / Win32 fd-table migration
 *     (deferred A3-followup) is what wires the read/write
 *     paths through KFile; this slice lands the type itself.
 *
 * NOT IN SCOPE
 *   - Migrating Process::linux_fds / Process::win32_files
 *     onto a `kobj_handles`-resolvable KFile. Those subsystems
 *     still own their own per-type tables; KFile is the future
 *     unified type they'll converge on.
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

struct KFile
{
    /// MUST be first — `KObject*` ↔ `KFile*` cast shape.
    KObject base;

    /// Opaque vnode handle — backend-specific (ramfs / fat32 /
    /// future-vfs). v0 stores whatever the caller passes; the
    /// fd-table migration formalises the type once a single VFS
    /// vnode shape is canonical.
    void* vnode;

    /// Current seek offset.
    u64 pos;

    /// Bitwise-OR of `KFileFlags`. Tracks the open mode so a
    /// later `read` / `write` syscall can refuse a wrong-mode
    /// access.
    u32 flags;
};

/// Allocate + zero-init + KObjectInit a fresh KFile. Caller
/// hands the returned reference to a HandleTable. Returns
/// `Err{ErrorCode::OutOfMemory}` on heap exhaustion.
::duetos::core::Result<KFile*> KFileCreate(void* vnode, u32 flags);

/// Read accessors — diagnostic only.
u64 KFilePosition(const KFile* f);
u32 KFileFlagsRead(const KFile* f);

/// Boot-time self-test. Allocates a KFile pointing at a
/// synthetic vnode, inserts into a HandleTable, exercises
/// lookup with right + wrong type-tag, removes from the table,
/// asserts destroy fires. Panics on mismatch.
void KFileSelfTest();

} // namespace duetos::ipc
