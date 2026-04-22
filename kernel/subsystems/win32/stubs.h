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

/*
 * Per-process "proc-env" page. Holds argc, argv, and the backing
 * argv[] array + string data for the CRT's
 * `__p___argc` / `__p___argv` accessors. One page, R-W + NX,
 * mapped only for PEs with imports (same gate as the TEB page).
 *
 * Layout (offsets inside the page):
 *
 *   0x00  int  argc                      ; value, not pointer
 *   0x08  char** argv                    ; = kProcEnvVa + kProcEnvArgvArrayOff
 *   0x20  char* argv[2]                  ; argv[0], argv[1]=NULL
 *   0x40  char  program_name[...]        ; NUL-terminated, argv[0] string
 *
 * The CRT reads `argc = *__p___argc()` and `argv = *__p___argv()`.
 * `__p___argc` returns `kProcEnvVa + kProcEnvArgcOff` (type `int*`);
 * `__p___argv` returns `kProcEnvVa + kProcEnvArgvPtrOff`
 * (type `char***` — a pointer to `argv`, which itself is `char**`).
 *
 * v0 always reports argc=1; a future slice with a real
 * argv-passing spawn API will extend the layout (more argv
 * slots + a larger string area).
 */
inline constexpr u64 kProcEnvVa = 0x65000000ULL;
inline constexpr u64 kProcEnvArgcOff = 0x00;
inline constexpr u64 kProcEnvArgvPtrOff = 0x08;
inline constexpr u64 kProcEnvArgvArrayOff = 0x20;
inline constexpr u64 kProcEnvStringOff = 0x40;
inline constexpr u64 kProcEnvStringBudget = 256;

/// Populate a freshly-zeroed proc-env page. `proc_env_page` is
/// the kernel-visible direct-map pointer to the 4 KiB frame that
/// will be mapped at `kProcEnvVa`. `program_name` is copied into
/// the page as `argv[0]`; additional args are not supported in
/// v0 (argc always = 1). Truncates `program_name` to
/// `kProcEnvStringBudget - 1` bytes if too long.
void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name);

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

/// Catch-all stub for any import the table doesn't know. Points at
/// the shared "xor eax,eax; ret" thunk, so:
///   - called as a function: returns 0 (the standard Win32 "failed
///     but no-op") and the callsite either tolerates it or faults
///     visibly further down;
///   - dereferenced as a data import: reads the stub bytes (the
///     page is mapped R-X, so no #PF), which is garbage but makes
///     the ensuing misuse loud rather than a silent loader reject.
/// Used by the PE loader when `Win32StubsLookupKind` misses, so a
/// real-world PE never fails to load purely because an obscure
/// import isn't yet implemented.
bool Win32StubsLookupCatchAll(u64* out_va);

} // namespace customos::win32
