#pragma once

/*
 * DuetOS — kernel-side Win32 registry (read-only, v0).
 *
 * Backs the SYS_REGISTRY syscall surface that ntdll.dll's
 * NtOpenKey / NtQueryValueKey / NtClose entry points reach
 * directly, bypassing advapi32. The data tree mirrors the
 * well-known keys advapi32.dll already exposes via Reg*Ex —
 * the duplication is intentional in v0: advapi32 is a
 * standalone freestanding userland DLL that doesn't include
 * kernel headers, and unifying the two sources of truth is a
 * separate refactor.
 *
 * What works:
 *   - NtOpenKey on HKLM\Software\Microsoft\Windows NT\CurrentVersion,
 *     HKLM\Software\Microsoft\Windows\CurrentVersion,
 *     HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings,
 *     HKCU\Volatile Environment.
 *   - NtQueryValueKey for ProductName / CurrentVersion /
 *     CurrentBuild* / BuildLab / EditionID / ProxyEnable /
 *     USERNAME / USERDOMAIN — the values MSVC CRTs and Windows
 *     telemetry probes hit during startup.
 *   - NtClose on a registry handle returns the slot to the pool.
 *
 * What's stubbed (kSysNtNotImpl):
 *   - NtCreateKey / NtDeleteKey (no mutable key tree — only
 *     mutable VALUES on existing static keys via NtSetValueKey /
 *     NtDeleteValueKey).
 *   - NtNotifyChangeKey (no-op tier; no change notifications).
 *
 * What works for enumeration:
 *   - NtEnumerateKey walks the static tree's prefix + terminal
 *     entries to list the direct children of an open key. Each
 *     index produces a unique child component name; the caller
 *     loops until STATUS_NO_MORE_ENTRIES.
 *   - NtEnumerateValueKey walks values of an open terminal key.
 *   - NtQueryKey reports both subkey_count (children walked from
 *     the static tree) and value_count (static + matching
 *     sidecar entries).
 */

#include "arch/x86_64/traps.h"
#include "util/types.h"

namespace duetos::subsystems::win32::registry
{

/// Predefined HKEY sentinels — match the Win32 API's UINT_PTR
/// values. Real Windows passes these directly to NtOpenKey;
/// the kernel-side Open op normalises them into the static tree.
inline constexpr u64 kHkeyClassesRoot = 0x80000000ULL;
inline constexpr u64 kHkeyCurrentUser = 0x80000001ULL;
inline constexpr u64 kHkeyLocalMachine = 0x80000002ULL;
inline constexpr u64 kHkeyUsers = 0x80000003ULL;
inline constexpr u64 kHkeyCurrentConfig = 0x80000005ULL;

/// Registry value types — Win32 REG_*. Matches advapi32.c on the
/// userland side and is part of the on-the-wire shape returned by
/// SYS_REGISTRY op=QueryValue.
inline constexpr u32 kRegNone = 0;
inline constexpr u32 kRegSz = 1;
inline constexpr u32 kRegExpandSz = 2;
inline constexpr u32 kRegBinary = 3;
inline constexpr u32 kRegDword = 4;

/// Op codes for SYS_REGISTRY's first arg (rdi). Stable ABI — once
/// a userland DLL ships with one of these, the value is locked.
inline constexpr u64 kOpOpenKey = 1;
inline constexpr u64 kOpClose = 2;
inline constexpr u64 kOpQueryValue = 3;
inline constexpr u64 kOpSetValue = 4;
inline constexpr u64 kOpDeleteValue = 5;
inline constexpr u64 kOpFlushKey = 6;
inline constexpr u64 kOpEnumerateValue = 7;
inline constexpr u64 kOpQueryKey = 8;
inline constexpr u64 kOpEnumerateKey = 9;

/// SYS_REGISTRY entry point. Routes by op selector to the matching
/// handler. Returns NTSTATUS through frame->rax. Per-op argument
/// layouts live in the matching helper below — keep them in sync
/// with userland/libs/ntdll/ntdll.c (NtOpenKey / NtQueryValueKey /
/// NtClose).
void DoRegistry(arch::TrapFrame* frame);

/// Free the per-Process registry slot for `handle`, if any. Called
/// from DoFileClose's range dispatch when a CloseHandle / NtClose
/// hits the registry handle range. Returns true on a real release
/// (slot was in use), false otherwise.
bool ReleaseHandleForCurrentProcess(u64 handle);

/// Compile-time consistency probes for the static tree —
/// well-known keys can be looked up, value lookups produce the
/// expected types/sizes, predefined-HKEY normalisation works.
/// Panics on any failure. Called from kernel_main self-test
/// gauntlet alongside ProcessSelfTest.
void RegistrySelfTest();

/// Read REGISTRY.HIV from the FAT32 root volume and rebuild the
/// sidecar mutable-value pool from it. No-op when FAT32 isn't
/// mounted or the file doesn't exist (first boot path). Run once
/// after the FAT32 probe and after RegistrySelfTest, so the
/// reload doesn't trample the boot consistency probes.
void RegistryHiveLoad();

/// Serialize the current sidecar state to REGISTRY.HIV. Called
/// from the success leg of DoSetValue / DoDeleteValue so each
/// successful mutation lands on disk before the syscall returns.
/// Throttled internally — a payload identical to the last
/// successful write is skipped.
void RegistryHiveSave();

/// Boot self-test: round-trips a synthetic value through
/// snapshot/restore (no FAT32 write) so the encode + decode
/// path is exercised without touching the operator's hive.
/// Prints PASS / FAIL / SKIP to COM1.
void RegistryHiveSelfTest();

/// Read-only introspection accessor for the debug `monitor`
/// surface (kernel/diag/gdb_monitor). Renders the static key at
/// (`root`, `path`) — its values and immediate child key names —
/// as human-readable text into `out` (NUL-terminated, bounded by
/// `out_cap`). `root` is a kHkey* sentinel; `path` is the
/// backslash-separated subkey path with no leading root (pass ""
/// for a root-level prefix key). Returns false if the key is not
/// in the static tree. No internal pointers escape the subsystem —
/// rendered text only, one source of truth for the registry tree.
bool RegistryQuery(u64 root, const char* path, char* out, u32 out_cap);

namespace detail
{

/// Public POD for the boundary between registry.cpp (which owns
/// the sidecar internals) and registry_hive.cpp (which owns the
/// FAT32 file format). Sized so a Snapshot[] array can be a
/// stack-resident scratch on save.
struct HiveSnapshot
{
    bool active;    // false ⇒ empty slot
    bool tombstone; // true ⇒ explicit deletion shadowing a static value
    u8 _pad[2];
    u64 root;       // kHkey* sentinel
    u32 type;       // REG_*
    u32 size;       // bytes valid in `data`
    char path[128]; // matches a kRegKeys[] entry; NUL-terminated
    char name[64];  // sidecar value name; NUL-terminated
    u8 data[256];   // value payload
};

/// Sidecar pool capacity (== kSidecarValueCap inside registry.cpp).
/// Exposed so registry_hive.cpp can size buffers without including
/// the .cpp's private constants.
inline constexpr u32 kSidecarPoolSize = 32;

/// Read slot `idx`. `out->active` reports occupancy. Pure read —
/// no mutation, safe to call without holding any registry lock.
bool SidecarSnapshotAt(u32 idx, HiveSnapshot* out);

/// Apply one snapshot back into the sidecar. The (root, path)
/// pair is looked up in the static tree; mismatches return false
/// (a hive that references a key the current build doesn't ship
/// is silently skipped — forward-compat for adding/removing
/// well-known keys). Caller is expected to SidecarReset() first
/// when doing a full Load.
bool SidecarRestoreOne(const HiveSnapshot* in);

/// Wipe the entire sidecar pool. Used by RegistryHiveLoad before
/// re-applying snapshots so a stale entry not in the file gets
/// dropped.
void SidecarReset();

} // namespace detail

} // namespace duetos::subsystems::win32::registry
