#pragma once

#include "util/types.h"

/*
 * DuetOS — Gregorian / Julian-day conversions + ISO 8601 datetime
 * parser and printer (clean room).
 *
 * Specs:
 *   - Fliegel & Van Flandern (1968) — the canonical integer
 *     algorithm for Gregorian ↔ Julian-Day-Number conversion.
 *     Public-domain math; no source code reuse.
 *   - ISO 8601:2019 — extended-format datetime
 *     `YYYY-MM-DDTHH:MM:SSZ` and the related week-date form
 *     `YYYY-Www-D`.
 *
 * Consumers:
 *   - kernel/apps/calendar.{h,cpp} can use IsoYearWeek for
 *     week-of-year display in a future revision.
 *   - kernel/log/klog.{h,cpp} can adopt FormatIso8601 once a
 *     wall-clock RTC source is stable enough for log timestamps
 *     (currently we print uptime ticks).
 *   - Linux ABI `strftime` / `strptime` thunks would sit on
 *     these primitives directly.
 *
 * Out of scope (deliberate, future slices):
 *   - Fractional seconds / nanoseconds beyond the second (the
 *     ISO 8601 string carries optional ".SSS" sub-second; we
 *     parse but don't preserve).
 *   - Time-zone offset parsing other than 'Z' (UTC). POSIX TZ
 *     string parsing is its own porting-candidates row.
 *   - Pre-Gregorian (Julian-calendar) dates. The Fliegel algorithm
 *     extends the Gregorian calendar back to year -4713 (proleptic
 *     Gregorian) which is fine for any modern timestamp.
 *
 * No allocation, no global state.
 */

namespace duetos::util
{

/// Sentinel returned by parse routines on failure.
inline constexpr u64 kJulianDayInvalid = ~u64(0);

struct DateTime
{
    i32 year;  // proleptic Gregorian; 1970..9999 typical, signed for safety
    u8 month;  // 1..12
    u8 day;    // 1..31
    u8 hour;   // 0..23
    u8 minute; // 0..59
    u8 second; // 0..60 (60 permitted for leap second)
};

struct IsoWeekDate
{
    i32 year; // ISO week-numbering year (may differ from calendar year at boundaries)
    u8 week;  // 1..53
    u8 dow;   // 1..7 (Monday=1, Sunday=7)
};

/// Convert Gregorian (year, month, day) to Julian Day Number
/// (whole-day count since -4713-11-24 12:00 UT). Valid for any
/// proleptic Gregorian date that fits a u64. Caller must pass
/// 1 <= month <= 12 and 1 <= day <= 31; out-of-range inputs
/// return `kJulianDayInvalid`.
u64 JulianDayFromYmd(i32 year, u8 month, u8 day);

/// Inverse: decode a Julian Day Number into proleptic Gregorian
/// year/month/day. Writes through the pointers; values are well-
/// defined for any `jdn` that came from `JulianDayFromYmd`.
void YmdFromJulianDay(u64 jdn, i32& year, u8& month, u8& day);

/// Day of week for a Gregorian date. Returns 0 (Sunday) .. 6
/// (Saturday). Returns 7 on invalid input — callers can treat
/// 7 as "invalid" without ambiguity.
u8 DayOfWeekFromYmd(i32 year, u8 month, u8 day);

/// ISO 8601 week-numbering year + week (1..53) + day-of-week
/// (1=Monday..7=Sunday) for a Gregorian date. The ISO year is
/// the year that "owns" the week containing that date; it can
/// differ from the calendar year by 1 in late-December or early-
/// January edge cases.
IsoWeekDate IsoYearWeek(i32 year, u8 month, u8 day);

/// Format `dt` as ISO 8601 extended UTC: `YYYY-MM-DDTHH:MM:SSZ`
/// (exactly 20 ASCII bytes + NUL). Returns the bytes written
/// (excluding NUL), or 0 if `out_cap < 21`. Always NUL-terminates
/// when out_cap >= 1.
u32 FormatIso8601(const DateTime& dt, char* out, u32 out_cap);

/// Parse an ISO 8601 extended-form UTC datetime. Accepts:
///   - `YYYY-MM-DDTHH:MM:SS`           (assume Z)
///   - `YYYY-MM-DDTHH:MM:SSZ`
///   - `YYYY-MM-DDTHH:MM:SS.fffZ`      (fractional seconds parsed but not preserved)
///   - Date-only `YYYY-MM-DD`          (time fields zeroed)
///
/// `len` is the number of bytes available at `s` (the parser
/// does not require NUL termination but stops at the first
/// invalid byte). Returns true on success and writes through
/// `out`. Returns false on any malformed input.
bool ParseIso8601(const char* s, u32 len, DateTime& out);

void DateTimeSelfTest();

} // namespace duetos::util
