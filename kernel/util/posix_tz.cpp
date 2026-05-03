#include "util/posix_tz.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

bool IsAlpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

struct Cursor
{
    const char* s;
    u32 i;
    u32 len;
};

bool AtEnd(const Cursor& c)
{
    return c.i >= c.len;
}

char Peek(const Cursor& c)
{
    return AtEnd(c) ? '\0' : c.s[c.i];
}

bool Accept(Cursor& c, char ch)
{
    if (Peek(c) == ch)
    {
        ++c.i;
        return true;
    }
    return false;
}

// Read a name into `out` (capacity kPosixTzNameCap, NUL-terminated).
// Two forms:
//   - 3-7 alpha (no quoting needed): consume until non-alpha.
//   - <...>     : consume until matching '>'. The interior is
//                 alpha/digit/'+'/'-' (no length validation; cap
//                 at the buffer).
bool ReadName(Cursor& c, char out[kPosixTzNameCap])
{
    if (Accept(c, '<'))
    {
        u32 i = 0;
        while (!AtEnd(c) && Peek(c) != '>')
        {
            if (i + 1 >= kPosixTzNameCap)
                return false;
            out[i++] = Peek(c);
            ++c.i;
        }
        if (!Accept(c, '>'))
            return false;
        out[i] = '\0';
        return i >= 3;
    }
    u32 i = 0;
    while (!AtEnd(c) && IsAlpha(Peek(c)))
    {
        if (i + 1 >= kPosixTzNameCap)
            return false;
        out[i++] = Peek(c);
        ++c.i;
    }
    out[i] = '\0';
    return i >= 3;
}

// Read an unsigned decimal up to 4 digits.
bool ReadU32(Cursor& c, u32& out)
{
    if (AtEnd(c) || !IsDigit(Peek(c)))
        return false;
    u32 v = 0;
    u32 n = 0;
    while (!AtEnd(c) && IsDigit(Peek(c)) && n < 5)
    {
        v = v * 10 + u32(Peek(c) - '0');
        ++c.i;
        ++n;
    }
    out = v;
    return true;
}

// POSIX offset: [+-]?h[h][:mm[:ss]]. Returns *seconds west of UTC*.
// The sign in the spec is "positive west": "EST5" means UTC-5,
// stored as +18000 seconds.
bool ReadOffsetSecs(Cursor& c, i32& out_secs)
{
    bool negate = false;
    if (Accept(c, '-'))
        negate = true;
    else if (Accept(c, '+'))
        negate = false;

    u32 h = 0;
    if (!ReadU32(c, h))
        return false;
    if (h > 24)
        return false;
    u32 m = 0, s = 0;
    if (Accept(c, ':'))
    {
        if (!ReadU32(c, m) || m > 59)
            return false;
        if (Accept(c, ':'))
        {
            if (!ReadU32(c, s) || s > 59)
                return false;
        }
    }
    i32 total = i32(h * 3600 + m * 60 + s);
    out_secs = negate ? -total : total;
    return true;
}

bool ReadRule(Cursor& c, PosixTzRule& r)
{
    r = {};
    r.time_secs = 2 * 3600; // POSIX default 02:00
    if (Accept(c, 'M'))
    {
        u32 m, w, d;
        if (!ReadU32(c, m) || m < 1 || m > 12)
            return false;
        if (!Accept(c, '.'))
            return false;
        if (!ReadU32(c, w) || w < 1 || w > 5)
            return false;
        if (!Accept(c, '.'))
            return false;
        if (!ReadU32(c, d) || d > 6)
            return false;
        r.kind = PosixTzRuleKind::MonthWeekDay;
        r.month = u8(m);
        r.week = u8(w);
        r.dow = u8(d);
    }
    else if (Accept(c, 'J'))
    {
        u32 n;
        if (!ReadU32(c, n) || n < 1 || n > 365)
            return false;
        r.kind = PosixTzRuleKind::JulianNoLeap;
        r.julian = u16(n);
    }
    else if (IsDigit(Peek(c)))
    {
        u32 n;
        if (!ReadU32(c, n) || n > 365)
            return false;
        r.kind = PosixTzRuleKind::JulianLeap;
        r.julian = u16(n);
    }
    else
    {
        return false;
    }
    if (Accept(c, '/'))
    {
        i32 t;
        if (!ReadOffsetSecs(c, t))
            return false;
        r.time_secs = t;
    }
    return true;
}

void DefaultDstRules(PosixTz& tz)
{
    // Spec leaves these unspecified; we mirror what most platforms
    // assume (US 2007+) so callers get a sensible answer when the
    // user passes a TZ string that names DST without rules.
    tz.start.kind = PosixTzRuleKind::MonthWeekDay;
    tz.start.month = 3;
    tz.start.week = 2;
    tz.start.dow = 0;
    tz.start.time_secs = 2 * 3600;
    tz.end.kind = PosixTzRuleKind::MonthWeekDay;
    tz.end.month = 11;
    tz.end.week = 1;
    tz.end.dow = 0;
    tz.end.time_secs = 2 * 3600;
}

} // namespace

bool ParsePosixTz(const char* s, u32 len, PosixTz& out)
{
    out = {};
    Cursor c = {s, 0, len};
    if (!ReadName(c, out.std_name))
        return false;
    if (!ReadOffsetSecs(c, out.std_offset_secs))
        return false;
    if (AtEnd(c))
        return true;

    // DST name (optional).
    if (Peek(c) != ',')
    {
        if (!ReadName(c, out.dst_name))
            return false;
        out.has_dst = true;
        // Optional DST offset; default = std - 3600 (one hour
        // earlier WEST, one hour LATER local).
        if (!AtEnd(c) && (IsDigit(Peek(c)) || Peek(c) == '+' || Peek(c) == '-'))
        {
            if (!ReadOffsetSecs(c, out.dst_offset_secs))
                return false;
        }
        else
        {
            out.dst_offset_secs = out.std_offset_secs - 3600;
        }
    }

    if (AtEnd(c))
    {
        if (out.has_dst)
            DefaultDstRules(out);
        return true;
    }

    // Rules.
    if (!Accept(c, ','))
        return false;
    if (!ReadRule(c, out.start))
        return false;
    if (!Accept(c, ','))
        return false;
    if (!ReadRule(c, out.end))
        return false;
    return AtEnd(c);
}

namespace
{

bool NameEq(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

} // namespace

void PosixTzSelfTest()
{
    // ----- "EST5EDT,M3.2.0,M11.1.0" — US Eastern, modern rules.
    {
        const char* s = "EST5EDT,M3.2.0,M11.1.0";
        PosixTz tz;
        const bool ok = ParsePosixTz(s, StrLen(s), tz);
        KASSERT(ok, "util/posix_tz", "EST/EDT parse failed");
        KASSERT(NameEq(tz.std_name, "EST"), "util/posix_tz", "std name wrong");
        KASSERT(NameEq(tz.dst_name, "EDT"), "util/posix_tz", "dst name wrong");
        KASSERT(tz.std_offset_secs == 18000, "util/posix_tz", "std offset wrong");
        KASSERT(tz.has_dst, "util/posix_tz", "DST flag wrong");
        KASSERT(tz.dst_offset_secs == 14400, "util/posix_tz", "default DST offset wrong");
        KASSERT(tz.start.kind == PosixTzRuleKind::MonthWeekDay, "util/posix_tz", "start kind wrong");
        KASSERT(tz.start.month == 3 && tz.start.week == 2 && tz.start.dow == 0, "util/posix_tz", "start fields wrong");
        KASSERT(tz.start.time_secs == 7200, "util/posix_tz", "start time default wrong");
        KASSERT(tz.end.month == 11 && tz.end.week == 1 && tz.end.dow == 0, "util/posix_tz", "end fields wrong");
    }

    // ----- "UTC0" — single zone, no DST.
    {
        const char* s = "UTC0";
        PosixTz tz;
        const bool ok = ParsePosixTz(s, StrLen(s), tz);
        KASSERT(ok && NameEq(tz.std_name, "UTC"), "util/posix_tz", "UTC parse failed");
        KASSERT(tz.std_offset_secs == 0, "util/posix_tz", "UTC offset wrong");
        KASSERT(!tz.has_dst, "util/posix_tz", "UTC has_dst should be false");
    }

    // ----- "<+04>-4" — extended-form name, negative offset.
    {
        const char* s = "<+04>-4";
        PosixTz tz;
        const bool ok = ParsePosixTz(s, StrLen(s), tz);
        KASSERT(ok && NameEq(tz.std_name, "+04"), "util/posix_tz", "extended name parse failed");
        KASSERT(tz.std_offset_secs == -14400, "util/posix_tz", "extended offset sign wrong");
    }

    // ----- "CET-1CEST,M3.5.0,M10.5.0/3" — Central European with explicit time.
    {
        const char* s = "CET-1CEST,M3.5.0,M10.5.0/3";
        PosixTz tz;
        const bool ok = ParsePosixTz(s, StrLen(s), tz);
        KASSERT(ok, "util/posix_tz", "CET parse failed");
        KASSERT(tz.std_offset_secs == -3600, "util/posix_tz", "CET std wrong");
        KASSERT(tz.dst_offset_secs == -7200, "util/posix_tz", "CEST default dst wrong");
        KASSERT(tz.start.month == 3 && tz.start.week == 5 && tz.start.dow == 0, "util/posix_tz", "CET start wrong");
        KASSERT(tz.end.month == 10 && tz.end.week == 5 && tz.end.dow == 0, "util/posix_tz",
                "CET end month/week/dow wrong");
        KASSERT(tz.end.time_secs == 3 * 3600, "util/posix_tz", "CET end time wrong");
    }

    // ----- "JST-9" — single zone with offset only.
    {
        const char* s = "JST-9";
        PosixTz tz;
        const bool ok = ParsePosixTz(s, StrLen(s), tz);
        KASSERT(ok && NameEq(tz.std_name, "JST"), "util/posix_tz", "JST parse failed");
        KASSERT(tz.std_offset_secs == -9 * 3600, "util/posix_tz", "JST offset wrong");
        KASSERT(!tz.has_dst, "util/posix_tz", "JST has_dst should be false");
    }

    // ----- "EST5EDT" — DST name without rules → spec-default rules.
    {
        const char* s = "EST5EDT";
        PosixTz tz;
        const bool ok = ParsePosixTz(s, StrLen(s), tz);
        KASSERT(ok, "util/posix_tz", "EST5EDT (no rules) parse failed");
        KASSERT(tz.has_dst, "util/posix_tz", "DST flag wrong without rules");
        KASSERT(tz.start.month == 3 && tz.start.week == 2 && tz.start.dow == 0, "util/posix_tz",
                "default start rule wrong");
        KASSERT(tz.end.month == 11 && tz.end.week == 1 && tz.end.dow == 0, "util/posix_tz", "default end rule wrong");
    }

    // ----- Negative cases.
    {
        const char* bad[] = {
            "X1",                      // name too short (1 char)
            "ABCDEFGH3",               // name too long for 7-char form
            "EST5EDT,X,Y",             // bad rule prefix
            "EST5EDT,M13.2.0,M11.1.0", // bad month
            "EST5EDT,M3.6.0,M11.1.0",  // bad week (6)
            "EST5EDT,M3.2.7,M11.1.0",  // bad dow (7)
            "EST25",                   // bad hour > 24
            "EST5:99",                 // bad minute
            "EST",                     // missing offset
        };
        for (const char* s : bad)
        {
            PosixTz tz;
            const bool ok = ParsePosixTz(s, StrLen(s), tz);
            KASSERT(!ok, "util/posix_tz", "negative case not rejected");
        }
    }
}

} // namespace duetos::util
