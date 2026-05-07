#pragma once

#include "util/types.h"

/*
 * Timezone offset — v0.
 *
 * A signed integer minutes offset from UTC, stored in a single
 * static slot. Settings UI mutates it; consumers (Settings clock
 * readout, taskbar clock, future calendar) compose UTC + offset
 * to render local time.
 *
 * Scope limits:
 *   - No zoneinfo database. Just a bare integer.
 *   - No DST awareness. The user adjusts manually if their
 *     locale has DST.
 *   - The Linux subsystem's CLOCK_REALTIME path is unaffected —
 *     g_realtime_offset_ns lives in syscall_time.cpp and answers
 *     a different question ("kernel-wide wall-clock skew from
 *     monotonic"). This file answers "what offset should the UI
 *     apply to render local time".
 *
 * Context: kernel. Reads are lock-free 32-bit aligned loads;
 * writes are single stores from the keyboard / mouse-driven
 * Settings path under the compositor lock. SMP-safe enough for
 * v0; a future RT-priority calendar service might want a real
 * atomic.
 */

namespace duetos::time
{

inline constexpr i32 kTzMinutesMin = -12 * 60;
inline constexpr i32 kTzMinutesMax = 14 * 60;
inline constexpr i32 kTzStepMinutes = 30; // half-hour steps cover IST etc.

/// Current offset in minutes. Initialised to 0 (UTC) at boot.
i32 TimezoneOffsetMinutes();

/// Set the offset in minutes. Clamps to [kTzMinutesMin,
/// kTzMinutesMax]. Idempotent.
void SetTimezoneOffsetMinutes(i32 minutes);

/// Convenience: nudge the offset by ±kTzStepMinutes. Clamps at
/// the bounds.
void TimezoneStep(bool up);

/// One-shot self-test: exercises set / step / clamp paths and
/// restores the original offset before returning. Prints one
/// PASS/FAIL line to COM1.
void TimezoneSelfTest();

} // namespace duetos::time
