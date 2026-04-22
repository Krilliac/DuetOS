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
// _commode global — 4-byte int, value 0 for "default text mode".
// UCRT's __p__commode returns a pointer to this location.
inline constexpr u64 kProcEnvCommodeOff = 0x200;

// Wide command line. Win32 GetCommandLineW returns a LPCWSTR
// pointing at this offset — a UTF-16LE NUL-terminated string
// containing the program name (and, in v0, nothing else). Real
// Windows cmdlines contain the full quoted argv joined with
// spaces; CustomOS hello_winapi-class programs only ever see
// argv[0] so this short-form is faithful enough.
inline constexpr u64 kProcEnvCmdlineWOff = 0x300;
// ANSI command line. Win32 GetCommandLineA returns this. Same
// content as GetCommandLineW but in single-byte ASCII.
inline constexpr u64 kProcEnvCmdlineAOff = 0x380;
// Environment block. Win32 GetEnvironmentStringsW returns this
// pointer; v0 is an empty block — just the two NUL bytes that
// terminate an empty `KEY=VAL\0KEY=VAL\0...\0\0` list. Future
// slices populate real entries (PATH, USERPROFILE, etc.) once a
// process gets its own env namespace.
inline constexpr u64 kProcEnvEnvBlockWOff = 0x400;

/*
 * Data-import catch-all landing pad.
 *
 * PE imports come in two flavours:
 *   - function imports — the IAT slot's value is a function VA
 *     the caller indirects through (`call [IAT+offset]`).
 *   - data imports (e.g. `?cout@std@@3V...` — std::cout) — the
 *     IAT slot's value is a pointer to a global object the
 *     caller dereferences as data (`mov rax, [IAT+offset]; mov
 *     rbx, [rax]; ...`).
 *
 * Prior to this landing pad, unresolved imports of either flavour
 * landed on the miss-logger stub in the R-X stubs page. Data-flavour
 * dereferences then read the miss-logger's opcode bytes as a
 * pointer, yielding something like `0xfc48634824048b4c`, and faulted
 * non-canonically a level or two down.
 *
 * With the landing pad, unresolved DATA imports get the VA of a
 * zero-filled region inside the proc-env page. `mov rax, [data_iat]`
 * now reads 0, and the subsequent `[rax+offset]` faults cleanly at
 * `cr2 = offset` — diagnosable at a glance.
 */
inline constexpr u64 kProcEnvDataMissOff = 0x800;

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

/// Emit a one-line "ntdll bedrock coverage: N/M (P%)" boot log
/// using the auto-generated table in
/// `subsystems/win32/nt_syscall_table_generated.h`. Lets the boot
/// log tell us, at a glance, how much of the universal NT API
/// surface CustomOS can route to internal SYS_* numbers — the
/// scoreboard for any future ntdll shim. Called once from
/// `kernel_main` after the Win32 stubs page is built.
void Win32LogNtCoverage();

} // namespace customos::win32
