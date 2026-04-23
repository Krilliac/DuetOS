#pragma once

#include "../../core/types.h"

/*
 * CustomOS ABI translation unit — v0.
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
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::subsystems::translation
{

// Returned by the gap-fill functions.
struct Result
{
    bool handled; // true if the TU produced a value in `rv`
    i64 rv;       // the (already-composed) return value; caller writes to frame->rax
};

// Fill a Linux syscall the main dispatcher did not handle.
// Reads arguments from the TrapFrame; returns {handled, rv} so
// the caller can decide whether to write rv into frame->rax.
Result LinuxGapFill(arch::TrapFrame* frame);

// Fill a native syscall the core dispatcher did not handle.
// Symmetric counterpart of LinuxGapFill — translations run in
// the OTHER direction: native ← Linux primitives / Win32 heap.
// Arguments live in frame->rdi/rsi/rdx/etc; `frame->rax` carries
// the native syscall number.
Result NativeGapFill(arch::TrapFrame* frame);

// Per-direction hit counters. Indexed by the lowest 10 bits of
// the syscall number (covers both Linux's ~400-entry table and
// native's ~30-entry table). Tracks "translation ran AND
// succeeded." Expose for a shell diagnostic.
struct HitTable
{
    u32 buckets[1024];
};
const HitTable& LinuxHitsRead();
const HitTable& NativeHitsRead();

/// Emit `[translate-overhead] linux …` + `native …` lines to the
/// serial log. Each line carries raw TSC counts: calls, total
/// cycles, average per call, max seen. Called by the kheartbeat
/// loop so the numbers roll in on the same cadence as the other
/// telemetry; a shell command can call it on demand too.
///
/// Why cycles and not nanoseconds: TSC frequency is CPU-specific;
/// we don't have a reliable TSC→ns calibration in the kernel yet.
/// Operators divide by the host CPU's TSC Hz (dmesg reports it)
/// to convert, or just read the numbers as relative costs.
void TranslatorOverheadDump();

} // namespace customos::subsystems::translation
