#include "util/tzif.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

inline u32 LoadU32Be(const u8* p)
{
    return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}

inline i32 LoadI32Be(const u8* p)
{
    return i32(LoadU32Be(p));
}

constexpr u32 kHeaderBytes = 44;

} // namespace

bool TzifParse(const u8* src, u32 src_len, TzifData& out)
{
    out = {};
    if (src_len < kHeaderBytes)
        return false;
    if (src[0] != 'T' || src[1] != 'Z' || src[2] != 'i' || src[3] != 'f')
        return false;
    // src[4] is the version byte; 0x00, '2', '3', '4' all accepted.
    const u8 v = src[4];
    if (v != 0x00 && v != '2' && v != '3' && v != '4')
        return false;
    // src[5..19] reserved.

    const u32 ttisutcnt = LoadU32Be(src + 20);
    const u32 ttisstdcnt = LoadU32Be(src + 24);
    const u32 leapcnt = LoadU32Be(src + 28);
    const u32 timecnt = LoadU32Be(src + 32);
    const u32 typecnt = LoadU32Be(src + 36);
    const u32 charcnt = LoadU32Be(src + 40);

    if (timecnt > kTzifMaxTransitions)
        return false;
    if (typecnt == 0 || typecnt > kTzifMaxTypes)
        return false;
    if (charcnt > kTzifAbbrPool)
        return false;

    // Body byte layout per RFC 8536 §3.2.
    const u32 transitions_off = kHeaderBytes;
    const u32 transition_types_off = transitions_off + timecnt * 4;
    const u32 ttinfo_off = transition_types_off + timecnt;
    const u32 abbr_off = ttinfo_off + typecnt * 6;
    const u32 leap_off = abbr_off + charcnt;
    const u32 isstd_off = leap_off + leapcnt * 8;
    const u32 isut_off = isstd_off + ttisstdcnt;
    const u32 v1_end = isut_off + ttisutcnt;
    if (v1_end > src_len)
        return false;

    out.transition_count = timecnt;
    for (u32 i = 0; i < timecnt; ++i)
        out.transitions[i] = i64(LoadI32Be(src + transitions_off + i * 4));
    for (u32 i = 0; i < timecnt; ++i)
    {
        const u8 ti = src[transition_types_off + i];
        if (ti >= typecnt)
            return false;
        out.transition_type[i] = ti;
    }
    out.type_count = typecnt;
    for (u32 i = 0; i < typecnt; ++i)
    {
        const u8* t = src + ttinfo_off + i * 6;
        out.types[i].gmtoff_secs = LoadI32Be(t);
        out.types[i].isdst = (t[4] != 0);
        const u8 abbr_idx = t[5];
        if (abbr_idx >= charcnt)
            return false;
        out.types[i].abbr_index = abbr_idx;
    }
    for (u32 i = 0; i < charcnt; ++i)
        out.abbr_pool[i] = char(src[abbr_off + i]);
    out.abbr_pool_bytes = charcnt;

    // (Leap, isstd, isut blocks parsed past but not exposed in v0.)
    out.ok = true;
    return true;
}

namespace
{

// Build a small synthetic TZif blob in `buf`. Returns byte count.
//
// Two transitions:
//   transition 0 at UTC 1234567 → type 0 ("STD", gmtoff +3600, isdst=false)
//   transition 1 at UTC 7654321 → type 1 ("DST", gmtoff +7200, isdst=true)
// Abbreviation pool: "STD\0DST\0"
u32 BuildTzifFixture(u8 buf[256])
{
    for (u32 i = 0; i < 256; ++i)
        buf[i] = 0;
    // Magic + version.
    buf[0] = 'T';
    buf[1] = 'Z';
    buf[2] = 'i';
    buf[3] = 'f';
    buf[4] = 0; // v1
    // 15 reserved bytes already zero.
    auto store_be = [](u8* p, u32 v)
    {
        p[0] = u8(v >> 24);
        p[1] = u8(v >> 16);
        p[2] = u8(v >> 8);
        p[3] = u8(v);
    };
    store_be(buf + 20, 0); // ttisutcnt
    store_be(buf + 24, 0); // ttisstdcnt
    store_be(buf + 28, 0); // leapcnt
    store_be(buf + 32, 2); // timecnt
    store_be(buf + 36, 2); // typecnt
    store_be(buf + 40, 8); // charcnt ("STD\0DST\0")

    // Transitions: 2 × 4 bytes BE.
    store_be(buf + 44, 1234567);
    store_be(buf + 48, 7654321);
    // Transition types: 2 bytes.
    buf[52] = 0;
    buf[53] = 1;
    // ttinfo entries: 2 × 6 bytes (gmtoff BE, isdst, abbr_idx).
    store_be(buf + 54, 3600);
    buf[58] = 0; // isdst=false
    buf[59] = 0; // abbr_idx
    store_be(buf + 60, 7200);
    buf[64] = 1; // isdst=true
    buf[65] = 4; // abbr_idx (offset of "DST" in pool)
    // Abbreviation pool.
    buf[66] = 'S';
    buf[67] = 'T';
    buf[68] = 'D';
    buf[69] = 0;
    buf[70] = 'D';
    buf[71] = 'S';
    buf[72] = 'T';
    buf[73] = 0;
    return 74;
}

} // namespace

void TzifSelfTest()
{
    // ----- Happy path.
    {
        u8 buf[256];
        const u32 n = BuildTzifFixture(buf);
        TzifData d;
        const bool ok = TzifParse(buf, n, d);
        KASSERT(ok, "util/tzif", "happy-path parse failed");
        KASSERT(d.transition_count == 2, "util/tzif", "transition count wrong");
        KASSERT(d.transitions[0] == 1234567 && d.transitions[1] == 7654321, "util/tzif", "transition values wrong");
        KASSERT(d.transition_type[0] == 0 && d.transition_type[1] == 1, "util/tzif", "transition types wrong");
        KASSERT(d.type_count == 2, "util/tzif", "type count wrong");
        KASSERT(d.types[0].gmtoff_secs == 3600 && !d.types[0].isdst, "util/tzif", "type 0 wrong");
        KASSERT(d.types[1].gmtoff_secs == 7200 && d.types[1].isdst, "util/tzif", "type 1 wrong");
        KASSERT(d.abbr_pool_bytes == 8, "util/tzif", "abbr pool size wrong");
        // Verify the abbreviation strings via the index.
        KASSERT(d.abbr_pool[d.types[0].abbr_index] == 'S' && d.abbr_pool[d.types[0].abbr_index + 1] == 'T' &&
                    d.abbr_pool[d.types[0].abbr_index + 2] == 'D',
                "util/tzif", "type 0 abbrev wrong");
        KASSERT(d.abbr_pool[d.types[1].abbr_index] == 'D' && d.abbr_pool[d.types[1].abbr_index + 1] == 'S' &&
                    d.abbr_pool[d.types[1].abbr_index + 2] == 'T',
                "util/tzif", "type 1 abbrev wrong");
    }

    // ----- Bad magic.
    {
        u8 buf[256];
        const u32 n = BuildTzifFixture(buf);
        buf[0] = 'X';
        TzifData d;
        KASSERT(!TzifParse(buf, n, d), "util/tzif", "bad magic not rejected");
    }

    // ----- Truncated buffer.
    {
        u8 buf[256];
        const u32 n = BuildTzifFixture(buf);
        TzifData d;
        KASSERT(!TzifParse(buf, n - 1, d), "util/tzif", "truncated not rejected");
    }

    // ----- transition_type index out of range.
    {
        u8 buf[256];
        const u32 n = BuildTzifFixture(buf);
        buf[53] = 5; // typecnt is 2; index 5 must be rejected
        TzifData d;
        KASSERT(!TzifParse(buf, n, d), "util/tzif", "bad transition type idx not rejected");
    }

    // ----- typecnt = 0 must reject (no types means no valid transitions).
    {
        u8 buf[256];
        const u32 n = BuildTzifFixture(buf);
        buf[36] = 0;
        buf[37] = 0;
        buf[38] = 0;
        buf[39] = 0;
        TzifData d;
        KASSERT(!TzifParse(buf, n, d), "util/tzif", "typecnt=0 not rejected");
    }

    // ----- v2 byte accepted (we still parse the v1 block).
    {
        u8 buf[256];
        const u32 n = BuildTzifFixture(buf);
        buf[4] = '2';
        TzifData d;
        KASSERT(TzifParse(buf, n, d), "util/tzif", "v2 should still parse v1 block");
    }
}

} // namespace duetos::util
