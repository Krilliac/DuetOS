#pragma once

#include "types.h"

namespace duetos::core
{

// Two-region trace storage: a sticky-boot region that captures the
// FIRST kCleanroomTraceBootCapacity events and is then locked
// against further writes, plus a rolling tail that wraps over the
// last kCleanroomTraceRollingCapacity events. The boot region
// preserves driver init / PE-loader / firmware-loader events that
// would otherwise be evicted by syscall-heavy ring3 workloads
// before any dump can happen; the rolling region keeps the most
// recent activity for steady-state inspection. Survey readers see
// boot region first (indices 0 .. boot_count) followed by the
// rolling region (boot_count .. boot_count + rolling_count).
inline constexpr u32 kCleanroomTraceBootCapacity = 256;
inline constexpr u32 kCleanroomTraceRollingCapacity = 4096;
inline constexpr u32 kCleanroomTraceTextMax = 31;

struct CleanroomTraceEntry
{
    char subsystem[kCleanroomTraceTextMax + 1];
    char event[kCleanroomTraceTextMax + 1];
    u64 a;
    u64 b;
    u64 c;
};

void CleanroomTraceRecord(const char* subsystem, const char* event, u64 a, u64 b, u64 c);
u32 CleanroomTraceCount();
u32 CleanroomTraceBootCount();
u32 CleanroomTraceRollingCount();
bool CleanroomTraceRead(u32 index, CleanroomTraceEntry* out);
void CleanroomTraceClear();
u64 CleanroomTraceHashToken(const char* text);

} // namespace duetos::core
