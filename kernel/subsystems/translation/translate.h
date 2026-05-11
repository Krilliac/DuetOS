#pragma once

#include "util/types.h"

/*
 * DuetOS ABI translation unit — v0.
 *
 * A small bridge between the Linux and native syscall dispatchers.
 * When the primary dispatcher doesn't handle a number, it hands
 * the TrapFrame to this TU; the TU either:
 *
 *   (a) synthesizes the missing call from existing primitives in
 *       the other (or same) subsystem, OR
 *   (b) routes to a semantically-equivalent operation in a peer
 *       subsystem (e.g. a native kernel primitive), OR
 *   (c) returns a safe no-op when the semantics allow it.
 *
 * Every translation logs a one-line "[translate] <source>/<nr> ->
 * <how>" so the boot-log trail shows exactly what was translated.
 * Unrecognized numbers log "[translate] <source>/<nr> unimplemented
 * — no translation" and leave the primary dispatcher to return
 * -ENOSYS. This makes it obvious from the logs which gaps are real
 * (need implementation) vs. filled.
 *
 * Why user-mode Win32 isn't in the registry today:
 *   Win32 runs as per-process user-mode shims (`kernel32.dll`
 *   equivalents patched into the PE image's IAT) that trampoline
 *   through native int-0x80 syscalls. There's no peer kernel
 *   dispatch to borrow from — anything a Win32 stub "has" is just
 *   a particular native call. When native missing → Linux
 *   translation makes sense, that path works the same way.
 *
 *   A symmetric `Win32ThunkToNative` would only earn its keep if
 *   a Win32 verb genuinely lacked a native call AND a Linux
 *   call could supply the missing semantics. Today every Win32
 *   verb we ship is reachable through either a direct handler
 *   under `kernel/subsystems/win32/` (the per-family
 *   `xxx_syscall.cpp` TUs) or the thunks-bytecode noop. When a
 *   future PE drives demand for a verb that's a Linux primitive
 *   but not a native one, add the entry here.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::translation
{

// Returned by the gap-fill functions.
struct Result
{
    bool handled; // true if the TU produced a value in `rv`
    i64 rv;       // the (already-composed) return value; caller writes to frame->rax
};

// Fill a native syscall the core dispatcher did not handle.
// Translations run native ← Linux primitives / Win32 heap.
// Arguments live in frame->rdi/rsi/rdx/etc; `frame->rax` carries
// the native syscall number.
//
// History: a symmetric `LinuxGapFill` existed when the Linux
// dispatcher's coverage was sparse. The Linux dispatcher now has
// dense 0..462 spec coverage so the gap-fill TU was unreachable
// for valid Linux ELFs; it was removed. The Linux dispatcher's
// default arm now logs a `[linux-miss] unknown syscall nr=...`
// line directly instead of detouring through this TU.
Result NativeGapFill(arch::TrapFrame* frame);

// Translate an NT (Windows kernel) syscall invocation to a Linux
// primitive. Used by the native SYS_NT_INVOKE handler — a future
// user-mode ntdll.dll shim issues SYS_NT_INVOKE with
//   rdi = NT syscall number
//   rsi..r9 = up to five NT-ABI arguments
// and this function dispatches to the nearest Linux handler,
// translating POSIX errno returns to NTSTATUS on the way out.
// `nt_nr` is read from `frame->rdi`; the remaining registers
// are re-interpreted by each NT-specific translator. Returns
// `{true, ntstatus}` on handled, `{false, 0}` to let the caller
// log-and-bail with STATUS_NOT_IMPLEMENTED.
//
// Deliberately small: only the NT calls with a clean 1:1 Linux
// mapping are wired today. Expand alongside the ntdll shim as
// specific Windows binaries reach for specific NT calls.
Result NtTranslateToLinux(arch::TrapFrame* frame);

// Native-direction hit counter. Indexed by the lowest 10 bits of
// the syscall number (native's ~30-entry table fits comfortably).
// Tracks "translation ran AND succeeded." Exposed for a shell
// diagnostic.
struct HitTable
{
    u32 buckets[1024];
};
const HitTable& NativeHitsRead();

/// Emit `[translate-overhead] native …` + `nt …` lines to the
/// serial log. Each line carries raw TSC counts: calls, total
/// cycles, average per call, max seen. Also emits a
/// `[translate-miss-suppressed]` line with cumulative + delta
/// counts for sampled miss logs. Called by the kheartbeat loop
/// so the numbers roll in on the same cadence as the other
/// telemetry; a shell command can call it on demand too.
///
/// Why cycles and not nanoseconds: TSC frequency is CPU-specific;
/// we don't have a reliable TSC→ns calibration in the kernel yet.
/// Operators divide by the host CPU's TSC Hz (dmesg reports it)
/// to convert, or just read the numbers as relative costs.
void TranslatorOverheadDump();

/// One-shot end-of-boot summary line for CI consumption:
///   [smoke] translate_summary native_calls=… native_total_c=…
///           native_max_c=… native_miss_emitted=…
///           native_miss_suppressed=… nt_calls=… nt_total_c=…
///           nt_max_c=… nt_miss_total=…
/// Single line, space-separated key=hexvalue pairs so the smoke
/// harness can grep + awk against it. Keys are stable; adding new
/// keys is backwards-compatible.
void TranslatorBootSummaryEmit();

// Public name-lookup helpers — the generated Linux + NT syscall
// tables are compiled into this TU, so any subsystem that wants
// to log a syscall by name (PE loader miss-logger, shell "trace"
// command, security-guard telemetry) routes through here instead
// of duplicating the tables.

/// x86_64 Linux syscall number -> canonical name, e.g. 0 -> "read",
/// 435 -> "clone3". Returns nullptr for numbers outside the known
/// ABI table (374 entries covering 0..334 + 424..462).
const char* LinuxName(u64 nr);

/// NT syscall number (Win11 25H2 numbering) -> name, e.g. 0x18 ->
/// "NtAllocateVirtualMemory". Returns nullptr for unknown numbers.
/// Covers 489 NT calls — the complete j00ru table for the target
/// Windows version.
const char* NtName(u64 nr);

} // namespace duetos::subsystems::translation
