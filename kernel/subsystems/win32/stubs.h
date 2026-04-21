#pragma once

#include "../../core/types.h"

/*
 * CustomOS Win32 subsystem — user-mode stub page (v0).
 *
 * The kernel hosts a read-only executable page per Win32 process
 * that contains the machine code thunks each resolved IAT entry
 * points to. A stub does one of two things:
 *
 *   1. Translate the Win32 x64 ABI (first arg in RCX) into the
 *      CustomOS native ABI (syscall # in RAX, first arg in RDI),
 *      issue `int 0x80`, done.
 *   2. For Win32 functions without a native equivalent (registry,
 *      file handles, etc.) — in a later slice — call into a tiny
 *      shim routine that implements the semantics.
 *
 * v0 covers exactly the stubs needed to run
 * userland/apps/hello_winapi/hello.c: just ExitProcess.
 *
 * Stubs live at a fixed user VA (kWin32StubsVa = 0x60000000) in
 * every Win32-imports process. Between the PE's code section
 * (ImageBase, typically 0x140000000) and the ring-3 stack
 * (0x7FFFE000). Chosen to not conflict with any ImageBase or
 * stack VA the kernel produces today.
 */

namespace customos::win32
{

inline constexpr u64 kWin32StubsVa = 0x60000000ULL;

/// Copy the compiled stub bytes into `dst`. Caller supplies a
/// kPageSize buffer; we write exactly kWin32StubsCodeSize bytes
/// starting at offset 0, leaving the rest zero. The page must
/// subsequently be mapped R-X at kWin32StubsVa in the process's
/// address space.
void Win32StubsPopulate(u8* dst);

/// Resolve an imported function to its stub's user VA. Returns
/// true and writes to *out_va if the {dll, func} pair is known;
/// returns false otherwise.
///
/// DLL name match is case-insensitive (Win32 convention — the
/// linker capitalizes inconsistently, e.g. "KERNEL32.dll" vs
/// "kernel32.dll"). Function name match is case-sensitive
/// (Win32 convention).
bool Win32StubsLookup(const char* dll, const char* func, u64* out_va);

/// As above, but also reports whether the matched stub is a
/// "safe-ignore" shim — a thunk that returns a constant (0, 1,
/// current process handle) without doing any real work. The PE
/// loader uses this to emit a Warn-level log when an imported
/// symbol lands on such a stub, so one glance at the boot log
/// reveals which Win32 APIs a PE will silently misbehave on. The
/// same `out_va` is populated as the 3-arg form.
bool Win32StubsLookupKind(const char* dll, const char* func, u64* out_va, bool* out_is_noop);

} // namespace customos::win32
