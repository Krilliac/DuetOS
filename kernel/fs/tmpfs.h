#pragma once

#include "../core/types.h"

/*
 * DuetOS tmpfs — v0.
 *
 * A flat, in-memory, writable file tier exposed at /tmp/. Sits
 * alongside the read-only ramfs tree: paths under /tmp/ are
 * served from this module; every other path still resolves
 * through VfsLookup against RamfsTrustedRoot().
 *
 * Shape:
 *   - 16 named slots, each with a 32-byte name and a 512-byte
 *     content buffer. All storage is .bss (no heap yet) so
 *     boot-time layout is fully static.
 *   - No nested directories. /tmp is one flat namespace.
 *   - No reference counts, no mtime / ctime, no permissions.
 *
 * Design choice: keep the shape deliberately primitive so the
 * first writable tier works end-to-end before a proper VFS
 * write-path abstraction lands. Every later tier (on-disk FS,
 * network mount) will plug into the VFS instead of the shell's
 * direct dispatch.
 *
 * Context: kernel. All operations are task-safe only — NOT
 * IRQ-safe; the name + content buffers have no synchronisation.
 */

namespace duetos::fs
{

constexpr u32 kTmpFsNameMax = 32;
constexpr u32 kTmpFsContentMax = 512;
constexpr u32 kTmpFsSlotCount = 16;

/// Create an empty file with `name` if no file of that name
/// exists. If it already exists, does nothing. Returns true on
/// success (created or already present), false if the slot
/// table is full or the name is invalid.
bool TmpFsTouch(const char* name);

/// Overwrite the named file with `len` bytes from `bytes`.
/// Truncates if len > kTmpFsContentMax. Creates the file if
/// it doesn't already exist. Returns true on success.
bool TmpFsWrite(const char* name, const char* bytes, u32 len);

/// Append `len` bytes to the named file. Creates it if absent.
/// If the existing size + len exceeds kTmpFsContentMax, fills
/// to the cap and drops the rest — matches the "write until
/// the device fills" semantic of a real fs under ENOSPC.
/// Returns true if at least one byte landed.
bool TmpFsAppend(const char* name, const char* bytes, u32 len);

/// Look up a file by name. On success, writes a pointer to the
/// content + its length to the out params and returns true.
/// Returns false if the file doesn't exist.
bool TmpFsRead(const char* name, const char** bytes_out, u32* len_out);

/// Remove a file by name. Returns true if it was present.
bool TmpFsUnlink(const char* name);

/// Enumerate the live slots in allocation order. The callback
/// is invoked for each slot that currently holds a file,
/// receiving (name, length, cookie). Names are guaranteed NUL-
/// terminated inside the 32-byte slot.
using TmpFsEnumCb = void (*)(const char* name, u32 len, void* cookie);
void TmpFsEnumerate(TmpFsEnumCb cb, void* cookie);

} // namespace duetos::fs
