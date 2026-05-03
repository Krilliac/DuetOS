#pragma once

#include "util/types.h"

/*
 * DuetOS — POSIX TZ environment-variable string parser
 * (clean room).
 *
 * Spec: POSIX.1-2008 §8.3 ("Other Environment Variables", TZ).
 *
 * The full grammar is:
 *
 *   std-offset [ dst[-offset] [ , start[/time] , end[/time] ] ]
 *
 *   std, dst : 3-7 letters, OR <quoted-up-to-6> alpha/digit/+/-
 *   offset   : [+-]?h[h][:mm[:ss]]   (hours 0-24, minutes/seconds 0-59)
 *   start    : J<n> | <n> | M<m>.<w>.<d>
 *   time     : h[h][:mm[:ss]]
 *
 * The DST offset defaults to std-offset - 1 hour. The default
 * transition rules approximate "US 2007+" but are unspecified
 * by POSIX, so this parser leaves them at the spec defaults
 * (start = M3.2.0, end = M11.1.0, both at 02:00) only if the
 * caller provided a DST name without rules.
 *
 * Eventual consumers:
 *   - Linux ABI strftime / strptime / mktime / localtime
 *     (currently absent; this primitive lands first).
 *   - Future userland TZ env-var setting.
 *
 * Out of scope (deliberate v0):
 *   - Time-zone *file* parsing (TZif binary, RFC 8536) — that's
 *     its own porting-candidates row.
 *   - Computing the actual UTC offset for a given Y/M/D HH:MM:SS.
 *     The parser exposes the rules; an evaluator is its own
 *     follow-up slice.
 *
 * No allocation, no global state.
 */

namespace duetos::util
{

/// Maximum bytes for an extended (`<...>`) zone name plus NUL.
inline constexpr u32 kPosixTzNameCap = 8;

enum class PosixTzRuleKind : u8
{
    None = 0,
    JulianNoLeap, // "Jn"   1..365 (leap day not counted)
    JulianLeap,   // "n"    0..365
    MonthWeekDay, // "Mm.w.d"
};

struct PosixTzRule
{
    PosixTzRuleKind kind;
    u16 julian;    // for JulianNoLeap / JulianLeap (0..365)
    u8 month;      // 1..12  (MonthWeekDay)
    u8 week;       // 1..5   (5 = "last")
    u8 dow;        // 0..6   (0 = Sunday)
    i32 time_secs; // seconds from local midnight
};

struct PosixTz
{
    char std_name[kPosixTzNameCap];
    char dst_name[kPosixTzNameCap];
    /// Seconds *west* of UTC (POSIX convention — opposite of
    /// `tm_gmtoff`). EST is +18000; UTC is 0; CET is -3600.
    i32 std_offset_secs;
    i32 dst_offset_secs;
    bool has_dst;
    PosixTzRule start;
    PosixTzRule end;
};

/// Parse a TZ string into `out`. Returns true on success.
bool ParsePosixTz(const char* s, u32 len, PosixTz& out);

void PosixTzSelfTest();

} // namespace duetos::util
