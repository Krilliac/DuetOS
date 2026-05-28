#include "util/datetime.h"

#include "core/panic.h"
#include "util/result.h"

namespace duetos::util
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

namespace
{

bool IsLeapYear(i32 y)
{
    if ((y % 4) != 0)
        return false;
    if ((y % 100) != 0)
        return true;
    return (y % 400) == 0;
}

u8 DaysInMonth(i32 y, u8 m)
{
    static const u8 kTable[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m < 1 || m > 12)
        return 0;
    if (m == 2 && IsLeapYear(y))
        return 29;
    return kTable[m - 1];
}

bool DateValid(i32 y, u8 m, u8 d)
{
    if (m < 1 || m > 12)
        return false;
    if (d < 1)
        return false;
    return d <= DaysInMonth(y, m);
}

bool TimeValid(u8 hh, u8 mm, u8 ss)
{
    return hh < 24 && mm < 60 && ss <= 60; // allow leap second
}

} // namespace

u64 JulianDayFromYmd(i32 year, u8 month, u8 day)
{
    if (!DateValid(year, month, day))
        return kJulianDayInvalid;
    // Fliegel & Van Flandern algorithm (1968). Operates entirely
    // in integer arithmetic; valid for the full proleptic Gregorian
    // calendar without floating point.
    const i64 a = (14 - month) / 12;
    const i64 y = i64(year) + 4800 - a;
    const i64 m = i64(month) + 12 * a - 3;
    const i64 jdn = i64(day) + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    if (jdn < 0)
        return kJulianDayInvalid;
    return u64(jdn);
}

void YmdFromJulianDay(u64 jdn, i32& year, u8& month, u8& day)
{
    // Inverse of Fliegel & Van Flandern. Same source.
    i64 j = i64(jdn) + 32044;
    i64 g = j / 146097;
    i64 dg = j % 146097;
    i64 c = (dg / 36524 + 1) * 3 / 4;
    i64 dc = dg - c * 36524;
    i64 b = dc / 1461;
    i64 db = dc % 1461;
    i64 a = (db / 365 + 1) * 3 / 4;
    i64 da = db - a * 365;
    i64 y = g * 400 + c * 100 + b * 4 + a;
    i64 m = (da * 5 + 308) / 153 - 2;
    i64 d = da - (m + 4) * 153 / 5 + 122;
    year = i32(y - 4800 + (m + 2) / 12);
    month = u8(((m + 2) % 12) + 1);
    day = u8(d + 1);
}

u8 DayOfWeekFromYmd(i32 year, u8 month, u8 day)
{
    const u64 jdn = JulianDayFromYmd(year, month, day);
    if (jdn == kJulianDayInvalid)
        return 7;
    // JDN 0 (= -4713-11-24 in proleptic Gregorian) is a Monday;
    // therefore (jdn + 1) % 7 yields Sunday=0..Saturday=6.
    return u8((jdn + 1) % 7);
}

IsoWeekDate IsoYearWeek(i32 year, u8 month, u8 day)
{
    IsoWeekDate out = {0, 0, 0};
    if (!DateValid(year, month, day))
        return out;
    // ISO 8601: weeks start Monday; week 1 is the one containing
    // the first Thursday of the year. Algorithm from the public
    // Wikipedia "ISO week date" page (originally derived in 1988).
    const u64 jdn = JulianDayFromYmd(year, month, day);
    // ISO day-of-week 1=Mon..7=Sun.
    u8 dow = u8((jdn % 7) + 1); // jdn 0 is Monday → 1
    // The Thursday of the week containing this date. Written as
    // `jdn + 4 - dow` (not `jdn + (4 - dow)`): dow is 1..7, so the
    // parenthesised form computes a negative int for dow>4 and
    // relies on the int→u64 wrap. This form keeps every
    // intermediate a well-defined u64 (jdn is ~2.4M, never
    // underflows) and is bit-identical.
    const u64 jdn_thu = jdn + 4 - dow;
    i32 thu_y;
    u8 thu_m, thu_d;
    YmdFromJulianDay(jdn_thu, thu_y, thu_m, thu_d);
    // Week number = (ordinal day of Thursday within thu_y - 1) / 7 + 1.
    const u64 jan1_thu_year = JulianDayFromYmd(thu_y, 1, 1);
    const u64 ordinal = jdn_thu - jan1_thu_year + 1; // 1-based
    out.year = thu_y;
    out.week = u8((ordinal - 1) / 7 + 1);
    out.dow = dow;
    return out;
}

u64 UnixSecsFromDateTime(const DateTime& dt)
{
    const u64 jdn = JulianDayFromYmd(dt.year, dt.month, dt.day);
    if (jdn == kJulianDayInvalid)
        return kJulianDayInvalid;
    if (jdn < kJulianDayUnixEpoch)
        return kJulianDayInvalid; // pre-1970 not representable as u64
    if (!TimeValid(dt.hour, dt.minute, dt.second))
        return kJulianDayInvalid;
    const u64 days = jdn - kJulianDayUnixEpoch;
    return days * 86400ull + u64(dt.hour) * 3600ull + u64(dt.minute) * 60ull + u64(dt.second);
}

DateTime DateTimeFromUnixSecs(u64 secs)
{
    DateTime dt = {};
    const u64 day = secs / 86400ull;
    const u64 sec_in_day = secs % 86400ull;
    const u64 jdn = kJulianDayUnixEpoch + day;
    YmdFromJulianDay(jdn, dt.year, dt.month, dt.day);
    dt.hour = u8(sec_in_day / 3600ull);
    dt.minute = u8((sec_in_day / 60ull) % 60ull);
    dt.second = u8(sec_in_day % 60ull);
    return dt;
}

u32 FormatIso8601(const DateTime& dt, char* out, u32 out_cap)
{
    if (out_cap < 21)
    {
        if (out_cap > 0)
            out[0] = '\0';
        return 0;
    }
    // No printf in kernel — hand-roll the fixed-width formatting.
    auto put2 = [](char* p, u32 v)
    {
        p[0] = char('0' + (v / 10) % 10);
        p[1] = char('0' + v % 10);
    };
    auto put4 = [](char* p, i32 v)
    {
        // Years pinned to non-negative for the canonical timestamp form.
        if (v < 0)
            v = 0;
        p[0] = char('0' + (v / 1000) % 10);
        p[1] = char('0' + (v / 100) % 10);
        p[2] = char('0' + (v / 10) % 10);
        p[3] = char('0' + v % 10);
    };
    put4(&out[0], dt.year);
    out[4] = '-';
    put2(&out[5], dt.month);
    out[7] = '-';
    put2(&out[8], dt.day);
    out[10] = 'T';
    put2(&out[11], dt.hour);
    out[13] = ':';
    put2(&out[14], dt.minute);
    out[16] = ':';
    put2(&out[17], dt.second);
    out[19] = 'Z';
    out[20] = '\0';
    return 20;
}

namespace
{

Result<u32> DigitVal(char c)
{
    if (c < '0' || c > '9')
        return Err{ErrorCode::InvalidArgument};
    return u32(c - '0');
}

Result<u32> ReadFixedDigits(const char* s, u32 n)
{
    u32 v = 0;
    for (u32 i = 0; i < n; ++i)
    {
        const auto d = DigitVal(s[i]);
        if (!d.has_value())
            return Err{d.error(), d.location()};
        v = v * 10 + d.value();
    }
    return v;
}

Result<void> AddSecondsToDateTime(DateTime& dt, i64 delta_secs)
{
    const u64 jdn_u = JulianDayFromYmd(dt.year, dt.month, dt.day);
    if (jdn_u == kJulianDayInvalid)
        return Err{ErrorCode::InvalidArgument};

    i64 total = i64(dt.hour) * 3600 + i64(dt.minute) * 60 + i64(dt.second) + delta_secs;
    i64 day_delta = total / 86400;
    i64 sec_in_day = total % 86400;
    if (sec_in_day < 0)
    {
        sec_in_day += 86400;
        --day_delta;
    }

    const i64 jdn = i64(jdn_u) + day_delta;
    if (jdn < 0)
        return Err{ErrorCode::InvalidArgument};

    YmdFromJulianDay(u64(jdn), dt.year, dt.month, dt.day);
    dt.hour = u8(sec_in_day / 3600);
    dt.minute = u8((sec_in_day / 60) % 60);
    dt.second = u8(sec_in_day % 60);
    return {};
}

Result<void> ParseTimezoneOffsetSeconds(const char* s, u32 len, u32 i, i64& offset_secs)
{
    offset_secs = 0;
    if (i >= len)
        return Err{ErrorCode::InvalidArgument};

    if (s[i] == 'Z')
        return (i + 1 == len) ? Result<void>{} : Result<void>{Err{ErrorCode::InvalidArgument}};

    if (s[i] != '+' && s[i] != '-')
        return Err{ErrorCode::InvalidArgument};
    const i64 sign = (s[i] == '+') ? 1 : -1;
    if (i + 6 != len)
        return Err{ErrorCode::InvalidArgument};

    const auto off_hh_r = ReadFixedDigits(s + i + 1, 2);
    if (!off_hh_r.has_value())
        return Err{off_hh_r.error(), off_hh_r.location()};
    if (s[i + 3] != ':')
        return Err{ErrorCode::InvalidArgument};
    const auto off_mm_r = ReadFixedDigits(s + i + 4, 2);
    if (!off_mm_r.has_value())
        return Err{off_mm_r.error(), off_mm_r.location()};
    const u32 off_hh = off_hh_r.value();
    const u32 off_mm = off_mm_r.value();
    if (off_hh > 23 || off_mm > 59)
        return Err{ErrorCode::InvalidArgument};

    offset_secs = sign * (i64(off_hh) * 3600 + i64(off_mm) * 60);
    return {};
}

} // namespace

Result<void> ParseIso8601(const char* s, u32 len, DateTime& out)
{
    out = {};
    if (len < 10)
        return Err{ErrorCode::InvalidArgument};
    // Local digit-field reader: parses `n` fixed digits at `s+at`
    // into `dst`, returning false on a non-digit. Hoists the
    // repeated has_value()/error() dance into one place so each
    // call site stays a single `if`. (RESULT_TRY_ASSIGN can't be
    // stacked in one scope — its `_resta_##__LINE__` temporary
    // doesn't expand __LINE__, so two uses collide; see result.h.)
    auto read_field = [&](u32 at, u32 n, u32& dst) -> bool
    {
        const auto r = ReadFixedDigits(s + at, n);
        if (!r.has_value())
            return false;
        dst = r.value();
        return true;
    };
    u32 yyyy = 0, mo = 0, dd = 0;
    if (!read_field(0, 4, yyyy))
        return Err{ErrorCode::InvalidArgument};
    if (s[4] != '-')
        return Err{ErrorCode::InvalidArgument};
    if (!read_field(5, 2, mo))
        return Err{ErrorCode::InvalidArgument};
    if (s[7] != '-')
        return Err{ErrorCode::InvalidArgument};
    if (!read_field(8, 2, dd))
        return Err{ErrorCode::InvalidArgument};
    out.year = i32(yyyy);
    out.month = u8(mo);
    out.day = u8(dd);
    if (!DateValid(out.year, out.month, out.day))
        return Err{ErrorCode::InvalidArgument};

    if (len == 10)
    {
        // Date-only form; time fields stay zero.
        return {};
    }
    if (len < 19)
        return Err{ErrorCode::InvalidArgument};
    if (s[10] != 'T' && s[10] != ' ')
        return Err{ErrorCode::InvalidArgument};
    u32 hh = 0, mm = 0, ss = 0;
    if (!read_field(11, 2, hh))
        return Err{ErrorCode::InvalidArgument};
    if (s[13] != ':')
        return Err{ErrorCode::InvalidArgument};
    if (!read_field(14, 2, mm))
        return Err{ErrorCode::InvalidArgument};
    if (s[16] != ':')
        return Err{ErrorCode::InvalidArgument};
    if (!read_field(17, 2, ss))
        return Err{ErrorCode::InvalidArgument};
    if (!TimeValid(u8(hh), u8(mm), u8(ss)))
        return Err{ErrorCode::InvalidArgument};
    out.hour = u8(hh);
    out.minute = u8(mm);
    out.second = u8(ss);

    if (len == 19)
        return {}; // unsuffixed; assume Z

    u32 i = 19;
    if (s[i] == '.')
    {
        // Skip fractional seconds (parsed for tolerance, not preserved).
        ++i;
        u32 frac_digits = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9')
        {
            ++i;
            ++frac_digits;
        }
        if (frac_digits == 0)
            return Err{ErrorCode::InvalidArgument};
    }
    if (i == len)
        return {};

    i64 offset_secs = 0;
    RESULT_TRY(ParseTimezoneOffsetSeconds(s, len, i, offset_secs));

    if (offset_secs == 0)
        return {};

    // ISO 8601 offsets describe local time relative to UTC. Convert
    // to the UTC instant represented by the existing DateTime shape:
    // `14:00+02:00` becomes `12:00Z`, while `23:30-02:00` rolls
    // forward into the next UTC day.
    return AddSecondsToDateTime(out, -offset_secs);
}

void DateTimeSelfTest()
{
    // ----- Gregorian → JDN known-good vectors.
    {
        // 2000-01-01 → JDN 2451545 (Astronomical reference epoch noon = 2451545.0).
        KASSERT(JulianDayFromYmd(2000, 1, 1) == 2451545u, "util/datetime", "JDN 2000-01-01 wrong");
        // 1970-01-01 → JDN 2440588 (Unix epoch).
        KASSERT(JulianDayFromYmd(1970, 1, 1) == 2440588u, "util/datetime", "JDN 1970-01-01 wrong");
        // 2026-05-03 → JDN 2461164.
        KASSERT(JulianDayFromYmd(2026, 5, 3) == 2461164u, "util/datetime", "JDN 2026-05-03 wrong");
        // 2024-02-29 (leap day) → JDN 2460370.
        KASSERT(JulianDayFromYmd(2024, 2, 29) == 2460370u, "util/datetime", "JDN 2024-02-29 wrong");
    }
    // ----- Round-trip JDN → Y/M/D for those same dates.
    {
        i32 y;
        u8 m, d;
        YmdFromJulianDay(2451545, y, m, d);
        KASSERT(y == 2000 && m == 1 && d == 1, "util/datetime", "round-trip 2000-01-01 wrong");
        YmdFromJulianDay(2440588, y, m, d);
        KASSERT(y == 1970 && m == 1 && d == 1, "util/datetime", "round-trip 1970-01-01 wrong");
        YmdFromJulianDay(2460370, y, m, d);
        KASSERT(y == 2024 && m == 2 && d == 29, "util/datetime", "round-trip 2024-02-29 wrong");
    }
    // ----- Day-of-week vectors (0=Sun..6=Sat).
    {
        // 2000-01-01 was a Saturday → 6.
        KASSERT(DayOfWeekFromYmd(2000, 1, 1) == 6, "util/datetime", "DOW 2000-01-01 wrong");
        // 2026-05-03 is a Sunday → 0.
        KASSERT(DayOfWeekFromYmd(2026, 5, 3) == 0, "util/datetime", "DOW 2026-05-03 wrong");
        // 2024-02-29 was a Thursday → 4.
        KASSERT(DayOfWeekFromYmd(2024, 2, 29) == 4, "util/datetime", "DOW 2024-02-29 wrong");
        // Invalid input.
        KASSERT(DayOfWeekFromYmd(2026, 13, 1) == 7, "util/datetime", "invalid month should yield 7");
    }
    // ----- ISO week-date vectors.
    {
        // 2026-05-03 is Sunday of ISO week 18 of 2026.
        IsoWeekDate iw = IsoYearWeek(2026, 5, 3);
        KASSERT(iw.year == 2026 && iw.week == 18 && iw.dow == 7, "util/datetime", "ISO week 2026-05-03 wrong");
        // 2021-01-01 was a Friday and belongs to ISO week 53 of 2020.
        iw = IsoYearWeek(2021, 1, 1);
        KASSERT(iw.year == 2020 && iw.week == 53 && iw.dow == 5, "util/datetime", "ISO week 2021-01-01 wrong");
        // 2026-12-31 — Thursday of ISO week 53 of 2026 (year has 53 ISO weeks).
        iw = IsoYearWeek(2026, 12, 31);
        KASSERT(iw.year == 2026 && iw.week == 53 && iw.dow == 4, "util/datetime", "ISO week 2026-12-31 wrong");
    }
    // ----- ISO 8601 round-trip print + parse.
    {
        const DateTime in = {2026, 5, 3, 14, 7, 30};
        char buf[24];
        const u32 n = FormatIso8601(in, buf, sizeof(buf));
        KASSERT(n == 20, "util/datetime", "format length wrong");
        const char want[] = "2026-05-03T14:07:30Z";
        for (u32 i = 0; i < 21; ++i)
            KASSERT(buf[i] == want[i], "util/datetime", "format content wrong");

        DateTime out;
        KASSERT(ParseIso8601(buf, n, out).has_value(), "util/datetime", "parse round-trip failed");
        KASSERT(out.year == 2026 && out.month == 5 && out.day == 3 && out.hour == 14 && out.minute == 7 &&
                    out.second == 30,
                "util/datetime", "parse round-trip mismatch");
    }
    // ----- Parse tolerances.
    {
        DateTime out;
        // Date-only.
        KASSERT(ParseIso8601("2026-01-15", 10, out).has_value(), "util/datetime", "date-only parse failed");
        KASSERT(out.year == 2026 && out.month == 1 && out.day == 15 && out.hour == 0, "util/datetime",
                "date-only fields wrong");
        // No-Z suffix.
        KASSERT(ParseIso8601("2026-05-03T14:07:30", 19, out).has_value(), "util/datetime", "no-Z parse failed");
        // Fractional seconds.
        KASSERT(ParseIso8601("2026-05-03T14:07:30.123Z", 24, out).has_value(), "util/datetime",
                "frac-sec parse failed");
        KASSERT(out.second == 30, "util/datetime", "frac-sec second field wrong");
        // Numeric UTC offsets are normalised into the UTC DateTime shape.
        KASSERT(ParseIso8601("2026-05-03T14:07:30+02:30", 25, out).has_value(), "util/datetime",
                "positive tz-offset parse failed");
        KASSERT(out.year == 2026 && out.month == 5 && out.day == 3 && out.hour == 11 && out.minute == 37 &&
                    out.second == 30,
                "util/datetime", "positive tz-offset normalisation wrong");
        KASSERT(ParseIso8601("2026-05-03T23:30:00-02:00", 25, out).has_value(), "util/datetime",
                "negative tz-offset parse failed");
        KASSERT(out.year == 2026 && out.month == 5 && out.day == 4 && out.hour == 1 && out.minute == 30 &&
                    out.second == 0,
                "util/datetime", "negative tz-offset day rollover wrong");
        KASSERT(ParseIso8601("2026-01-01T00:15:00+01:00", 25, out).has_value(), "util/datetime",
                "year-boundary tz-offset parse failed");
        KASSERT(out.year == 2025 && out.month == 12 && out.day == 31 && out.hour == 23 && out.minute == 15,
                "util/datetime", "year-boundary tz-offset rollover wrong");
    }
    // ----- Unix epoch round-trips.
    {
        // 1970-01-01T00:00:00Z = unix 0.
        const DateTime epoch = {1970, 1, 1, 0, 0, 0};
        KASSERT(UnixSecsFromDateTime(epoch) == 0, "util/datetime", "Unix epoch should be 0");
        const DateTime back = DateTimeFromUnixSecs(0);
        KASSERT(back.year == 1970 && back.month == 1 && back.day == 1 && back.hour == 0 && back.minute == 0 &&
                    back.second == 0,
                "util/datetime", "Unix epoch round-trip wrong");

        // 2000-01-01T12:00:00Z = unix 946728000.
        const DateTime y2k = {2000, 1, 1, 12, 0, 0};
        const u64 want_y2k = 946728000ull;
        KASSERT(UnixSecsFromDateTime(y2k) == want_y2k, "util/datetime", "Y2K Unix secs wrong");
        const DateTime y2k_back = DateTimeFromUnixSecs(want_y2k);
        KASSERT(y2k_back.year == 2000 && y2k_back.month == 1 && y2k_back.day == 1 && y2k_back.hour == 12,
                "util/datetime", "Y2K round-trip wrong");

        // 2026-05-03T14:07:30Z — used elsewhere as today's reference.
        const DateTime today = {2026, 5, 3, 14, 7, 30};
        const u64 today_secs = UnixSecsFromDateTime(today);
        const DateTime today_back = DateTimeFromUnixSecs(today_secs);
        KASSERT(today_back.year == today.year && today_back.month == today.month && today_back.day == today.day &&
                    today_back.hour == today.hour && today_back.minute == today.minute &&
                    today_back.second == today.second,
                "util/datetime", "today round-trip wrong");

        // Pre-1970 must reject.
        const DateTime old = {1969, 12, 31, 23, 59, 59};
        KASSERT(UnixSecsFromDateTime(old) == kJulianDayInvalid, "util/datetime", "pre-1970 not rejected");
    }

    // ----- Parse rejection.
    {
        DateTime out;
        // Invalid month.
        KASSERT(!ParseIso8601("2026-13-01", 10, out).has_value(), "util/datetime", "month=13 not rejected");
        // Invalid day for Feb non-leap year.
        KASSERT(!ParseIso8601("2025-02-29", 10, out).has_value(), "util/datetime", "non-leap Feb 29 not rejected");
        // Bad separator.
        KASSERT(!ParseIso8601("2026/05/03", 10, out).has_value(), "util/datetime", "slash separator not rejected");
        // Malformed timezone offset.
        KASSERT(!ParseIso8601("2026-05-03T14:07:30+24:00", 25, out).has_value(), "util/datetime",
                "tz offset hour=24 not rejected");
        KASSERT(!ParseIso8601("2026-05-03T14:07:30+02", 22, out).has_value(), "util/datetime",
                "short tz offset not rejected");
        // Empty fractional digits.
        KASSERT(!ParseIso8601("2026-05-03T14:07:30.Z", 21, out).has_value(), "util/datetime",
                "empty frac not rejected");
    }
}

} // namespace duetos::util
