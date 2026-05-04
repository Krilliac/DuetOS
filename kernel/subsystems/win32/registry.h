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

} // namespace duetos::subsystems::win32::registry
