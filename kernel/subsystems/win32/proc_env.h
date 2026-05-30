#pragma once

#include "util/types.h"

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
 *   0x700 wchar_t** __wargv              ; -> wargv[] @ 0x720
 *   0x710 wchar_t** _wenviron            ; -> wenviron[] @ 0x740
 *   0x720 wchar_t*  wargv[2]             ; { &cmdlineW, NULL }
 *   0x740 wchar_t*  wenviron[1]          ; { NULL }
 *   0x760 char      narrowEnv[2]         ; "\0\0" empty narrow env
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

// _acmdln / _wcmdln POINTER slots. The MSVC CRT globals `char*
// _acmdln` and `wchar_t* _wcmdln` are pointer VARIABLES whose value
// is the address of the command-line string. A PE that imports them
// by name does `mov rax, [_wcmdln]` to load the pointer, then walks
// the string it points at. The resolver must therefore point the IAT
// slot at one of THESE slots (which hold the VA of the string buffer),
// NOT at the string buffer at 0x300 / 0x380 directly — otherwise the
// first load yields the first 8 bytes of the string interpreted as a
// pointer and the next deref #PFs on a wild address (observed as
// cr2 == UTF-16 "WINV..." when winver's __wgetmainargs ran).
inline constexpr u64 kProcEnvAcmdlnPtrOff = 0x520;
inline constexpr u64 kProcEnvWcmdlnPtrOff = 0x528;

// Unhandled-exception-filter pointer. Per-process top-level
// filter set by SetUnhandledExceptionFilter and invoked (via
// tail-call) by UnhandledExceptionFilter. Stored as a u64 so
// atomic xchg against the slot is a single aligned memory
// operand. Starts zero (no filter) — the UnhandledExceptionFilter
// stub then returns EXCEPTION_EXECUTE_HANDLER (1) as Windows's
// documented default.
inline constexpr u64 kProcEnvUnhandledFilterOff = 0x600;

// === wide-CRT (wmainCRTStartup) startup data =================
//
// Wide-entry exes (wmain) run the UCRT's wide startup path, which
// reads `__wargv = *__p___wargv()`, `_wenviron = *__p___wenviron()`
// and `_get_initial_wide_environment()`. Each must hand back a
// VALID, non-NULL pointer chain or the CRT faults dereferencing
// the (previously NULL / errno-scratch) return.
//
//   0x700 wchar_t** __wargv      ; = kProcEnvVa + kProcEnvWargvArrayOff
//   0x710 wchar_t** _wenviron    ; = kProcEnvVa + kProcEnvWenvironArrayOff
//   0x720 wchar_t* wargv[2]      ; { &cmdlineW (program name), NULL }
//   0x740 wchar_t* wenviron[1]   ; { NULL } — empty environment array
//   0x760 char     narrowEnv[2]  ; "\0\0" — empty narrow env block
//
// `__p___wargv` returns &__wargv (a wchar_t***); the CRT does
// `__wargv = *__p___wargv()`, loading the value at 0x700, which is
// the user-VA of the wargv[] array at 0x720. Mirrors how
// `__p___argv` returns &argv (0x08) whose value points at the
// narrow argv[] array at 0x20.
inline constexpr u64 kProcEnvWargvPtrOff = 0x700;
inline constexpr u64 kProcEnvWenvironPtrOff = 0x710;
inline constexpr u64 kProcEnvWargvArrayOff = 0x720;
inline constexpr u64 kProcEnvWenvironArrayOff = 0x740;
inline constexpr u64 kProcEnvNarrowEnvBlockOff = 0x760;

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

// CRT atexit registry — per-process LIFO stack of function
// pointers. _crt_atexit / _register_onexit_function append a
// pointer here and bump the count; _cexit walks the stack in
// reverse order (LIFO, matching MSVC behaviour) and tail-calls
// each handler. Storage lives inside the proc-env page so the
// thunks are syscall-free (single load+store from a fixed VA).
//
// Layout:
//   [0x900] u32 atexit_count       ; 0 .. kProcEnvAtexitMax
//   [0x904] u32 reserved
//   [0x908] u32 app_type           ; _set_app_type stores here
//   [0x90C] u32 narrow_argv_mode   ; _configure_narrow_argv stores here
//   [0x910] u64 atexit_slots[64]   ; 64 * 8 = 512 bytes
//
// 64 slots is generous for v0 — a typical MSVC CRT registers
// 6-12 handlers (locale teardown, stdio flush, onexit chain).
// Hitting the cap returns -1 from the registrar; the surplus
// handler simply isn't called at exit, which matches the
// documented MSVC failure mode.
inline constexpr u64 kProcEnvAtexitCountOff = 0x900;
inline constexpr u64 kProcEnvAppTypeOff = 0x908;
inline constexpr u64 kProcEnvNarrowArgvModeOff = 0x90C;
inline constexpr u64 kProcEnvAtexitSlotsOff = 0x910;
inline constexpr u64 kProcEnvAtexitMax = 64;
static_assert(kProcEnvAtexitSlotsOff + kProcEnvAtexitMax * 8 <= 0x1000, "atexit table must fit in proc-env page");

/// Populate a freshly-zeroed proc-env page. `proc_env_page` is
/// the kernel-visible direct-map pointer to the 4 KiB frame that
/// will be mapped at `kProcEnvVa`. `program_name` is copied into
/// the page as `argv[0]`; additional args are not supported in
/// v0 (argc always = 1). Truncates `program_name` to
/// `kProcEnvStringBudget - 1` bytes if too long.
void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name, u64 module_base);

// KUSER_SHARED_DATA — the read-only system-data page Windows maps at
// the fixed VA 0x7FFE0000 in every process. The MSVC CRT and many
// PEs read fields here inline (no syscall): TickCountQuad, SystemTime,
// InterruptTime, the QPC/perf-counter fast path, NtMajor/MinorVersion.
// An unmapped 0x7FFE0000 #PFs deep in CRT startup. We map a zero page
// and seed the handful of fields a CRT timing/version fast-path reads.
inline constexpr u64 kKuserSharedDataVa = 0x7FFE0000ULL;

// Offsets into KUSER_SHARED_DATA that we populate. Layout per the
// public ntddk KUSER_SHARED_DATA struct (stable Windows ABI).
inline constexpr u64 kKusdTickCountMultiplierOff = 0x004; // ULONG, fixed 0x0FA00000
inline constexpr u64 kKusdInterruptTimeOff = 0x008;       // KSYSTEM_TIME { LowPart, High1Time, High2Time }
inline constexpr u64 kKusdSystemTimeOff = 0x014;          // KSYSTEM_TIME (100ns since 1601)
inline constexpr u64 kKusdTickCountQuadOff = 0x320;       // ULONGLONG TickCountQuad (ms)
inline constexpr u64 kKusdNtMajorVersionOff = 0x26C;      // ULONG
inline constexpr u64 kKusdNtMinorVersionOff = 0x270;      // ULONG

/// Populate a freshly-zeroed KUSER_SHARED_DATA page. `kusd_page` is
/// the kernel-visible direct-map pointer to the 4 KiB frame mapped at
/// kKuserSharedDataVa. Seeds tick count / system time / OS version
/// from the kernel clock so CRT timing fast-paths read sane values.
void Win32KuserSharedDataPopulate(u8* kusd_page);

} // namespace duetos::win32
