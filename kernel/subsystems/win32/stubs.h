#pragma once

#include "../../core/types.h"

/*
 * DuetOS Win32 subsystem — user-mode stub page (v0).
 *
 * The kernel hosts a read-only executable page per Win32 process
 * that contains the machine code thunks each resolved IAT entry
 * points to. A stub does one of two things:
 *
 *   1. Translate the Win32 x64 ABI (first arg in RCX) into the
 *      DuetOS native ABI (syscall # in RAX, first arg in RDI),
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

namespace duetos::win32
{

inline constexpr u64 kWin32StubsVa = 0x60000000ULL;

// VA of the thread-exit trampoline inside the stubs page.
// SYS_THREAD_CREATE handlers write this to [user_rsp] so a Win32
// thread proc that `ret`s off its entry point lands on the trampoline
// (which issues SYS_EXIT(retcode)) rather than #PF'ing at rip=0.
inline constexpr u64 kWin32ThreadExitTrampVa = kWin32StubsVa + 0x8A6ULL;

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

/// Catch-all stub for any FUNCTION import the table doesn't know.
/// Points at the shared miss-logger thunk, so called-as-a-function
/// it returns 0 after emitting a `[win32-miss]` log line. Used for
/// imports whose names look like functions (no heuristic match for
/// the data pattern — see `IsLikelyDataImport`).
bool Win32StubsLookupCatchAll(u64* out_va);

/// Catch-all landing pad for any DATA import the table doesn't
/// know. Returns the VA inside the proc-env page at
/// `kProcEnvVa + kProcEnvDataMissOff`. Dereferencing the resulting
/// IAT slot reads 0 (clean null), so the next-level `[ptr+offset]`
/// faults at a diagnosable cr2 rather than reading the miss-logger
/// opcode bytes as a pointer.
///
/// Used by the PE loader for imports whose mangled names match the
/// MSVC global-data pattern (`?...@@3...`). Distinct from
/// `Win32StubsLookupCatchAll` so function imports still log through
/// the miss-logger and data imports don't.
bool Win32StubsLookupDataCatchAll(u64* out_va);

/// Heuristic: does the mangled import name look like a DATA import
/// rather than a function import? Used by the PE loader to pick
/// between the two catch-all helpers when an import name isn't in
/// the stub table. True for names matching MSVC's global-variable
/// mangling (`?name@...@@3<type>...`). False for everything else,
/// including plain C names and MSVC function mangling
/// (`?func@...@@QEAA...`).
bool IsLikelyDataImport(const char* func);

} // namespace duetos::win32
