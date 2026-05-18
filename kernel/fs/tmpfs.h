#pragma once

#include "util/types.h"

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

/// Rename a file from `src` to `dst`. v0 semantics:
///   - `src` must exist; otherwise returns false.
///   - `dst` must NOT exist (no implicit overwrite); otherwise
///     returns false.
///   - Both names must pass the same validation TmpFsTouch
///     uses (length, charset).
/// Atomic with respect to other tmpfs callers because tmpfs
/// has no concurrent IRQ-side mutators — the slot's name field
/// flips in one store. Returns true on success.
bool TmpFsRename(const char* src, const char* dst);

/// Enumerate the live slots in allocation order. The callback
/// is invoked for each slot that currently holds a file,
/// receiving (name, length, cookie). Names are guaranteed NUL-
/// terminated inside the 32-byte slot.
using TmpFsEnumCb = void (*)(const char* name, u32 len, void* cookie);
void TmpFsEnumerate(TmpFsEnumCb cb, void* cookie);

/// One-shot self-test: exercises Touch / Write / Append / Read
/// / Unlink / Enumerate, the name-validation rules, append
/// truncation at kTmpFsContentMax, and slot-table exhaustion.
/// Runs on fresh state (intended to be called at boot before
/// any other tmpfs user) and cleans up its own files before
/// returning. Prints one PASS/FAIL line to COM1.
void TmpFsSelfTest();

// ---------------------------------------------------------------------------
// RamVol — frame-backed, hierarchical, quota'd, sealable RAM volume.
//
// This is the writable RAM disk for file-based system services /
// apps that benefit from direct-RAM I/O. It is ADDITIVE to (and
// lives in the same module as) the legacy flat tmpfs above, whose
// API + constants + behaviour are intentionally frozen byte-for-
// byte: ~15 shell call sites do `char buf[kTmpFsContentMax]` on
// the stack, so the legacy cap can never grow without overflowing
// the kernel stack. RamVol is the un-capped path instead.
//
// Storage: file bytes live in whole 4 KiB physical frames from the
// (now SMP-safe) frame allocator; directory/file metadata is
// KMalloc'd. A global byte quota (default 64 MiB, override via the
// `ramfs-mib=<N>` boot cmdline token, clamped at init to <= 25% of
// free physical RAM) bounds total usage so a runaway service can
// never exhaust kernel memory.
//
// Per-file SEAL: a one-way transition to immutable. A sealed file
// rejects write / truncate / unlink — the "Static" purpose (drop a
// service's working set in once, freeze it, read it fast + tamper-
// safe). Unsealed files are normal mutable scratch ("Dynamic").
//
// Concurrency: every public op takes one reentrant SpinLock
// (SMP-safe — APs are online; the reentrant guard lets the public
// ops legitimately call one another without self-deadlock).
//
// This slice is the store + API + seal + quota + self-test only.
// Mounting it into the VFS at /run and teaching `cat` / file_route
// to read it is the agreed immediately-following slice.
// ---------------------------------------------------------------------------

constexpr u32 kRamVolNameMax = 64; // per-component name cap (incl. NUL)
constexpr u64 kRamVolDefaultQuotaMib = 64;

/// Initialise the volume: parse `ramfs-mib=`, clamp the quota to
/// <= 25% of free RAM, create the root and the /run, /run/lock,
/// /tmp directory skeleton. `mb_info_phys` is the Multiboot2 info
/// pointer (for the cmdline). Idempotent; safe to call once at
/// boot after the heap + frame allocator are up.
void RamVolInit(uptr mb_info_phys);

/// Create a directory (parents must already exist). Returns false
/// if the path exists, a parent is missing, or the name is bad.
bool RamVolMkdir(const char* path);

/// Create an empty regular file (parent must exist). Idempotent if
/// the file already exists and is not a directory.
bool RamVolCreate(const char* path);

/// Positioned write; grows the file (allocating frames against the
/// quota) as needed. Creates the file if absent. Returns bytes
/// written, or -1 on bad path / sealed file / quota exhaustion.
i64 RamVolWrite(const char* path, u64 offset, const void* buf, u64 len);

/// Append to end of file (creates if absent). Returns bytes
/// written or -1 (sealed / quota / bad path).
i64 RamVolAppend(const char* path, const void* buf, u64 len);

/// Positioned read. Returns bytes read (0 at/after EOF), or -1 on
/// bad path / not-a-file.
i64 RamVolRead(const char* path, u64 offset, void* buf, u64 len);

/// Shrink/grow a file to `new_size` (frees frames on shrink, zero-
/// fills on grow). Returns false if sealed / missing / a dir.
bool RamVolTruncate(const char* path, u64 new_size);

/// Remove a regular file (frees its frames). False if sealed,
/// missing, or a directory.
bool RamVolUnlink(const char* path);

/// Remove an empty directory. False if missing, not a dir, or
/// non-empty.
bool RamVolRmdir(const char* path);

/// One-way seal: the file becomes permanently immutable (the
/// "Static" mode). False if missing or a directory. Idempotent.
bool RamVolSeal(const char* path);

/// Stat. Any out-param may be null. Returns false if missing.
bool RamVolStat(const char* path, u64* size_out, bool* is_dir_out, bool* sealed_out);

using RamVolEnumCb = void (*)(const char* name, u64 size, bool is_dir, bool sealed, void* cookie);
/// Enumerate the immediate children of a directory.
void RamVolReaddir(const char* path, RamVolEnumCb cb, void* cookie);

/// Volume accounting (bytes). Either out-param may be null.
void RamVolStats(u64* used_bytes_out, u64* quota_bytes_out);

/// One-shot self-test: mkdir/create/write/append/read/truncate,
/// seal immutability, unlink/rmdir, and quota rejection. Cleans up
/// after itself. Emits one `[ramvol] self-test: PASS|FAIL` line.
void RamVolSelfTest();

} // namespace duetos::fs
