#pragma once

#include "../../core/types.h"

/*
 * DuetOS Win32 subsystem — per-process "proc-env" page.
 *
 * One page, R-W + NX, mapped only for PEs with imports (same gate
 * as the TEB page). Holds argc, argv, the backing argv[] array +
 * string data for the CRT's `__p___argc` / `__p___argv`
 * accessors, the wide/ANSI command line, an environment block,
 * the EXE module base for GetModuleHandleW(NULL), the unhandled-
 * exception filter slot, and a data-import catch-all landing
 * pad.
 *
 * Layout (offsets inside the page):
 *
 *   0x00  int   argc                     ; value, not pointer
 *   0x08  char**argv                     ; = kProcEnvVa + kProcEnvArgvArrayOff
 *   0x20  char* argv[2]                  ; argv[0], argv[1]=NULL
 *   0x40  char  program_name[...]        ; NUL-terminated, argv[0] string
 *   0x200 int   _commode                 ; UCRT __p__commode target
 *   0x300 wchar_t cmdlineW[...]          ; UTF-16LE GetCommandLineW
 *   0x380 char  cmdlineA[...]            ; ASCII GetCommandLineA
 *   0x400 wchar_t envBlockW[...]         ; empty env block (\0\0)
 *   0x500 u64   moduleBase               ; HMODULE for the running PE
 *   0x600 u64   unhandledFilter          ; SetUnhandledExceptionFilter slot
 *   0x800 u64   data-miss landing pad    ; see below
 *
 * Lives at a fixed user VA (kProcEnvVa = 0x65000000) in every
 * Win32-imports process. Companion to the R-X stubs page
 * (kWin32ThunksVa, see thunks.h).
 *
 * The CRT reads `argc = *__p___argc()` and `argv = *__p___argv()`.
 * `__p___argc` returns `kProcEnvVa + kProcEnvArgcOff` (type
 * `int*`); `__p___argv` returns `kProcEnvVa + kProcEnvArgvPtrOff`
 * (type `char***` — a pointer to `argv`, which itself is
 * `char**`).
 *
 * v0 always reports argc=1; a future slice with a real
 * argv-passing spawn API will extend the layout (more argv
 * slots + a larger string area).
 */

namespace duetos::win32
{

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
// spaces; DuetOS hello_winapi-class programs only ever see
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

// EXE module base (HMODULE of the running PE). Win32
// GetModuleHandleW(NULL) returns this — the linker sets it to
// kImageBase + ASLR delta at PE load. Stored as a little-endian
// u64 so the GetModuleHandleW stub can do a single
// `mov rax, [kProcEnvVa + kProcEnvModuleBaseOff]` read.
inline constexpr u64 kProcEnvModuleBaseOff = 0x500;

// Unhandled-exception-filter pointer. Per-process top-level
// filter set by SetUnhandledExceptionFilter and invoked (via
// tail-call) by UnhandledExceptionFilter. Stored as a u64 so
// atomic xchg against the slot is a single aligned memory
// operand. Starts zero (no filter) — the UnhandledExceptionFilter
// stub then returns EXCEPTION_EXECUTE_HANDLER (1) as Windows's
// documented default.
inline constexpr u64 kProcEnvUnhandledFilterOff = 0x600;

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
void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name, u64 module_base);

} // namespace duetos::win32
