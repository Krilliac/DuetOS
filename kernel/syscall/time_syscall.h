#pragma once

#include "arch/x86_64/rtc.h"
#include "util/types.h"

/*
 * DuetOS — time-family syscall handlers, v0.
 *
 * Extracted from kernel/syscall/syscall.cpp so the dispatcher
 * switch stays a thin router and time logic (calendar math,
 * RTC↔FILETIME↔SYSTEMTIME conversions) lives in one file with
 * its helpers.
 *
 * All handlers consume a `TrapFrame*` and write the result to
 * `frame->rax`. Failure returns `u64(-1)` (same contract as
 * before the extraction — no ABI change).
 *
 * Syscalls covered:
 *   SYS_PERF_COUNTER (13)  — kernel tick counter (100 Hz)
 *   SYS_NOW_NS       (18)  — HPET nanoseconds since boot
 *   SYS_GETTIME_FT   (17)  — FILETIME (100-ns since 1601) in rax
 *   SYS_GETTIME_ST   (40)  — fills caller's SYSTEMTIME buffer
 *   SYS_ST_TO_FT     (41)  — SYSTEMTIME* → FILETIME*
 *   SYS_FT_TO_ST     (42)  — FILETIME* → SYSTEMTIME*
 *
 * Context: kernel. Handlers run under the syscall gate at IRQ-off;
 * safe to call the HPET and RTC readers — both are polling MMIO/
 * legacy IO and bounded.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::core
{

// Pure-math helper exposed for reuse (tests, the taskbar's date
// widget, etc.). Converts an RtcTime to a Windows FILETIME.
u64 RtcToFileTime(const arch::RtcTime& t);

// Dispatch entry points. Each writes to `frame->rax`; the caller
// (the syscall switch in syscall.cpp) just routes SYS_* to these.
void DoPerfCounter(arch::TrapFrame* frame);
void DoNowNs(arch::TrapFrame* frame);
void DoGetTimeFt(arch::TrapFrame* frame);
void DoGetTimeSt(arch::TrapFrame* frame);
void DoStToFt(arch::TrapFrame* frame);
void DoFtToSt(arch::TrapFrame* frame);

} // namespace duetos::core
