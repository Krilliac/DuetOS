// cookies.cpp — RFC 6265-ish in-kernel cookie jar.
//
// Implements the public API declared in net/cookies.h:
//   CookieSetFromHeader  — parse Set-Cookie, upsert into jar
//   CookieBuildHeader    — build Cookie: header for a request
//   CookieJarLoad/Save   — FAT32-backed persistence
//   CookieSelfTest       — boot self-test (in-memory only)
//
// Design notes:
//   - Fixed-size flat array of CookieEntry (kCookieJarCap = 128).
//     No heap allocation: every entry is embedded in g_jar.
//   - "Oldest" means lowest m_slot_seq. On eviction the entry
//     with the smallest non-zero seq is replaced.
//   - Domain matching follows RFC 6265 §5.1.3:
//       host-only   exact match only
//       domain-cookie  host == domain OR host ends with "."+domain
//                      (the leading dot is stored but not required
//                       in the host suffix check)
//   - Path matching: cookie path is a prefix of the request path.
//   - Secure flag: if cookie.secure, caller must pass is_secure=true.
//   - Expires parsing: RFC 1123 date only ("Day, DD Mon YYYY HH:MM:SS GMT").
//     Max-Age takes precedence over Expires per RFC 6265 §5.2.2.
//   - Persistence: COOKIES.TXT on the first available FAT32 volume,
//     one cookie per line, tab-separated fields.
//
// GAP: public-suffix list (eTLD+1 enforcement); __Secure- / __Host-
//      prefixes; SameSite attribute; third-party policy.

#include "net/cookies.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "util/string.h"
#include "util/types.h"

namespace duetos::net
{

using duetos::core::AppendStr;
using duetos::core::StrEqual;
using duetos::core::StrEqualCaseInsensitive;
using duetos::core::StrLen;

// -----------------------------------------------------------------
// Internal types
// -----------------------------------------------------------------

// Sentinel expiry meaning "session cookie — no absolute deadline".
static constexpr duetos::i64 kExpirySession = duetos::i64(-1);

struct CookieEntry
{
    char m_name[kCookieNameCap];
    char m_value[kCookieValueCap];
    char m_domain[kCookieDomCap]; // stored without leading dot
    char m_path[kCookiePathCap];
    duetos::i64 m_expiry_unix; // kExpirySession = session
    duetos::u32 m_slot_seq;    // insertion order; 0 = empty
    bool m_secure;
    bool m_host_only; // domain was not set → exact match
    bool m_http_only;
};

// -----------------------------------------------------------------
// Global jar
// -----------------------------------------------------------------

static CookieEntry g_jar[kCookieJarCap];
static duetos::u32 g_next_seq = 1; // monotonic slot sequence counter

// -----------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------

namespace
{

static const char* TrimWs(const char* s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    {
        ++s;
    }
    return s;
}

static void StrCopyN(char* dst, const char* src, duetos::u32 cap)
{
    if (cap == 0)
    {
        return;
    }
    duetos::u32 i = 0;
    while (i + 1 < cap && src[i] != '\0')
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

static char ToLower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

// Case-insensitive prefix check: does `haystack` start with `needle`?
static bool StartsWithI(const char* haystack, const char* needle)
{
    while (*needle != '\0')
    {
        if (ToLower(*haystack) != ToLower(*needle))
        {
            return false;
        }
        ++haystack;
        ++needle;
    }
    return true;
}

// Case-insensitive suffix check: does `host` end with "."+`domain`?
static bool HostHasDomainSuffix(const char* host, const char* domain)
{
    const auto hlen = static_cast<duetos::u32>(StrLen(host));
    const auto dlen = static_cast<duetos::u32>(StrLen(domain));
    if (hlen <= dlen || host[hlen - dlen - 1] != '.')
    {
        return false;
    }
    const char* tail = host + hlen - dlen;
    for (duetos::u32 i = 0; i < dlen; ++i)
    {
        if (ToLower(tail[i]) != ToLower(domain[i]))
        {
            return false;
        }
    }
    return true;
}

// Returns true if `cookie_domain` matches `host` per RFC 6265 §5.1.3.
static bool DomainMatches(const char* cookie_domain, bool host_only, const char* host)
{
    if (host_only)
    {
        return StrEqualCaseInsensitive(host, cookie_domain);
    }
    return StrEqualCaseInsensitive(host, cookie_domain) || HostHasDomainSuffix(host, cookie_domain);
}

// Returns true if `cookie_path` is a prefix of `request_path`
// per RFC 6265 §5.1.4.
static bool PathMatches(const char* cookie_path, const char* request_path)
{
    const auto cplen = static_cast<duetos::u32>(StrLen(cookie_path));
    const auto rplen = static_cast<duetos::u32>(StrLen(request_path));
    for (duetos::u32 i = 0; i < cplen; ++i)
    {
        if (request_path[i] != cookie_path[i])
        {
            return false;
        }
    }
    if (cplen == 1 && cookie_path[0] == '/')
    {
        return true;
    }
    return rplen == cplen || request_path[cplen] == '/';
}

// Derive the default Path from the request path per RFC 6265 §5.1.4.
static void DefaultPath(const char* req_path, char* out, duetos::u32 cap)
{
    const char* last_slash = nullptr;
    for (const char* p = req_path; *p != '\0'; ++p)
    {
        if (*p == '/')
        {
            last_slash = p;
        }
    }
    if (last_slash == nullptr || last_slash == req_path)
    {
        StrCopyN(out, "/", cap);
        return;
    }
    const auto len = static_cast<duetos::u32>(last_slash - req_path);
    if (len == 0 || len + 1 > cap)
    {
        StrCopyN(out, "/", cap);
        return;
    }
    duetos::u32 i = 0;
    for (; i < len && i + 1 < cap; ++i)
    {
        out[i] = req_path[i];
    }
    out[i] = '\0';
}

// Parse an ASCII decimal integer (possibly negative) from `s`.
static duetos::i64 ParseDecimal(const char* s, const char** end)
{
    const char* p = TrimWs(s);
    bool neg = false;
    if (*p == '-')
    {
        neg = true;
        ++p;
    }
    else if (*p == '+')
    {
        ++p;
    }
    duetos::i64 v = 0;
    while (*p >= '0' && *p <= '9')
    {
        v = v * 10 + static_cast<duetos::i64>(*p - '0');
        ++p;
    }
    if (end != nullptr)
    {
        *end = p;
    }
    return neg ? -v : v;
}

// Parse a 3-char abbreviated month name to a 1-based month number.
static duetos::u32 ParseMonth3(const char* s)
{
    struct
    {
        const char* name;
        duetos::u32 month;
    } kMonths[] = {
        {"Jan", 1}, {"Feb", 2}, {"Mar", 3}, {"Apr", 4},  {"May", 5},  {"Jun", 6},
        {"Jul", 7}, {"Aug", 8}, {"Sep", 9}, {"Oct", 10}, {"Nov", 11}, {"Dec", 12},
    };
    for (const auto& m : kMonths)
    {
        if (ToLower(s[0]) == ToLower(m.name[0]) && ToLower(s[1]) == ToLower(m.name[1]) &&
            ToLower(s[2]) == ToLower(m.name[2]))
        {
            return m.month;
        }
    }
    return 0;
}

static bool IsLeapYear(duetos::i64 y)
{
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

static duetos::i64 DaysInMonth(duetos::i64 y, duetos::u32 m)
{
    static const duetos::i64 kDays[13] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return (m == 2 && IsLeapYear(y)) ? 29 : kDays[m];
}

// Convert Gregorian date+time to a UNIX timestamp (UTC, no TZ).
static duetos::i64 DateToUnix(duetos::i64 year, duetos::u32 mon, duetos::u32 day, duetos::u32 hour, duetos::u32 min,
                              duetos::u32 sec)
{
    if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 60)
    {
        return -1;
    }
    duetos::i64 days = 0;
    for (duetos::i64 y = 1970; y < year; ++y)
    {
        days += IsLeapYear(y) ? 366 : 365;
    }
    for (duetos::u32 m_idx = 1; m_idx < mon; ++m_idx)
    {
        days += DaysInMonth(year, m_idx);
    }
    days += static_cast<duetos::i64>(day) - 1;
    return days * 86400 + static_cast<duetos::i64>(hour) * 3600 + static_cast<duetos::i64>(min) * 60 +
           static_cast<duetos::i64>(sec);
}

// Parse an RFC 1123 date: "Day, DD Mon YYYY HH:MM:SS GMT". Returns -1 on failure.
static duetos::i64 ParseRfc1123Date(const char* s)
{
    const char* p = s;
    while (*p != '\0' && *p != ',')
    {
        ++p;
    }
    if (*p == ',')
    {
        ++p;
    }
    p = TrimWs(p);

    const char* after;
    const duetos::i64 day = ParseDecimal(p, &after);
    if (after == p)
    {
        return -1;
    }
    p = TrimWs(after);
    if (StrLen(p) < 3)
    {
        return -1;
    }
    const duetos::u32 mon = ParseMonth3(p);
    if (mon == 0)
    {
        return -1;
    }
    p += 3;
    p = TrimWs(p);

    const duetos::i64 year = ParseDecimal(p, &after);
    if (after == p)
    {
        return -1;
    }
    p = TrimWs(after);

    const duetos::i64 hour = ParseDecimal(p, &after);
    if (after == p || *after != ':')
    {
        return -1;
    }
    p = after + 1;
    const duetos::i64 mn = ParseDecimal(p, &after);
    if (after == p || *after != ':')
    {
        return -1;
    }
    p = after + 1;
    const duetos::i64 sc = ParseDecimal(p, nullptr);

    return DateToUnix(year, mon, static_cast<duetos::u32>(day), static_cast<duetos::u32>(hour),
                      static_cast<duetos::u32>(mn), static_cast<duetos::u32>(sc));
}

// ---- Jar helpers ----

// Find a slot by (name, domain, path). Returns nullptr if not found.
static CookieEntry* FindEntry(const char* name, const char* domain, const char* path)
{
    for (duetos::u32 i = 0; i < kCookieJarCap; ++i)
    {
        if (g_jar[i].m_slot_seq == 0)
        {
            continue;
        }
        if (StrEqual(g_jar[i].m_name, name) && StrEqualCaseInsensitive(g_jar[i].m_domain, domain) &&
            StrEqual(g_jar[i].m_path, path))
        {
            return &g_jar[i];
        }
    }
    return nullptr;
}

// Return the index of an empty slot (seq==0), or evict the oldest entry.
static duetos::u32 AllocSlot()
{
    for (duetos::u32 i = 0; i < kCookieJarCap; ++i)
    {
        if (g_jar[i].m_slot_seq == 0)
        {
            return i;
        }
    }
    duetos::u32 oldest_idx = 0;
    duetos::u32 oldest_seq = g_jar[0].m_slot_seq;
    for (duetos::u32 i = 1; i < kCookieJarCap; ++i)
    {
        if (g_jar[i].m_slot_seq < oldest_seq)
        {
            oldest_seq = g_jar[i].m_slot_seq;
            oldest_idx = i;
        }
    }
    return oldest_idx;
}

// Parse the next key[=value] token from a Set-Cookie attribute list.
// Advances *pp past the consumed token and any preceding ';' / whitespace.
// Returns false at end-of-string; true otherwise.
// Hard cap of 4096 chars per scan guards against malformed input.
static bool NextToken(const char** pp, char* key_out, duetos::u32 key_cap, char* val_out, duetos::u32 val_cap)
{
    const char* p = *pp;

    // Skip leading ';' and whitespace.
    for (duetos::u32 g = 0; (*p == ';' || *p == ' ' || *p == '\t') && g < 4096; ++g)
    {
        ++p;
    }
    if (*p == '\0')
    {
        *pp = p;
        return false;
    }

    // Collect key until '=', ';', or end. Always advances p at least once.
    duetos::u32 ki = 0;
    for (duetos::u32 g = 0; *p != '\0' && *p != '=' && *p != ';' && g < 4096; ++g)
    {
        if (ki + 1 < key_cap)
        {
            key_out[ki++] = *p;
        }
        ++p;
    }
    while (ki > 0 && (key_out[ki - 1] == ' ' || key_out[ki - 1] == '\t'))
    {
        --ki;
    }
    key_out[ki] = '\0';

    if (val_out != nullptr)
    {
        val_out[0] = '\0';
    }
    if (*p == '=')
    {
        ++p;
        duetos::u32 vi = 0;
        for (duetos::u32 g = 0; *p != '\0' && *p != ';' && g < 4096; ++g)
        {
            if (val_out != nullptr && vi + 1 < val_cap)
            {
                val_out[vi++] = *p;
            }
            ++p;
        }
        if (val_out != nullptr)
        {
            while (vi > 0 && (val_out[vi - 1] == ' ' || val_out[vi - 1] == '\t'))
            {
                --vi;
            }
            val_out[vi] = '\0';
        }
    }
    *pp = p;
    return true;
}

// Zero all jar slots and reset the sequence counter.
static void JarClear()
{
    for (duetos::u32 i = 0; i < kCookieJarCap; ++i)
    {
        g_jar[i] = CookieEntry{};
        g_jar[i].m_expiry_unix = kExpirySession;
        g_jar[i].m_host_only = true;
    }
    g_next_seq = 1;
}

} // namespace

// -----------------------------------------------------------------
// CookieSetFromHeader
// -----------------------------------------------------------------

void CookieSetFromHeader(const char* host, const char* req_path, const char* set_cookie_hv, duetos::i64 now_unix)
{
    if (host == nullptr || req_path == nullptr || set_cookie_hv == nullptr)
    {
        return;
    }

    const char* p = set_cookie_hv;

    // Parse the name=value pair (first token, before the first ';').
    char name[kCookieNameCap];
    char value[kCookieValueCap];
    {
        duetos::u32 ni = 0;
        while (*p != '\0' && *p != '=' && *p != ';')
        {
            if (ni + 1 < kCookieNameCap)
            {
                name[ni++] = *p;
            }
            ++p;
        }
        while (ni > 0 && (name[ni - 1] == ' ' || name[ni - 1] == '\t'))
        {
            --ni;
        }
        name[ni] = '\0';

        value[0] = '\0';
        if (*p == '=')
        {
            ++p;
            duetos::u32 vi = 0;
            while (*p != '\0' && *p != ';')
            {
                if (vi + 1 < kCookieValueCap)
                {
                    value[vi++] = *p;
                }
                ++p;
            }
            while (vi > 0 && (value[vi - 1] == ' ' || value[vi - 1] == '\t'))
            {
                --vi;
            }
            value[vi] = '\0';
        }
    }

    if (name[0] == '\0')
    {
        return; // unnamed cookie — ignore per RFC 6265 §5.2
    }

    // Parse attributes.
    char attr_domain[kCookieDomCap] = {};
    char attr_path[kCookiePathCap] = {};
    duetos::i64 expiry = kExpirySession;
    bool has_max_age = false;
    bool secure = false;
    bool http_only = false;
    bool has_domain = false;

    char attr_key[64];
    char attr_val[kCookieValueCap];

    while (NextToken(&p, attr_key, sizeof(attr_key), attr_val, sizeof(attr_val)))
    {
        if (StartsWithI(attr_key, "Domain") && StrLen(attr_key) == 6)
        {
            const char* dv = attr_val;
            if (*dv == '.')
            {
                ++dv;
            }
            StrCopyN(attr_domain, dv, kCookieDomCap);
            has_domain = (attr_domain[0] != '\0');
        }
        else if (StartsWithI(attr_key, "Path") && StrLen(attr_key) == 4)
        {
            StrCopyN(attr_path, attr_val, kCookiePathCap);
        }
        else if (StartsWithI(attr_key, "Max-Age") && StrLen(attr_key) == 7)
        {
            const duetos::i64 age = ParseDecimal(attr_val, nullptr);
            expiry = (age <= 0) ? 0 : (now_unix + age);
            has_max_age = true;
        }
        else if (!has_max_age && StartsWithI(attr_key, "Expires") && StrLen(attr_key) == 7)
        {
            const duetos::i64 ts = ParseRfc1123Date(attr_val);
            if (ts >= 0)
            {
                expiry = ts;
            }
        }
        else if (StartsWithI(attr_key, "Secure") && StrLen(attr_key) == 6)
        {
            secure = true;
        }
        else if (StartsWithI(attr_key, "HttpOnly") && StrLen(attr_key) == 8)
        {
            http_only = true;
        }
        // Unknown attributes silently ignored per RFC 6265 §5.2.6.
    }

    // Finalise domain.
    bool host_only = false;
    if (!has_domain || attr_domain[0] == '\0')
    {
        StrCopyN(attr_domain, host, kCookieDomCap);
        host_only = true;
    }

    // Finalise path.
    if (attr_path[0] == '\0' || attr_path[0] != '/')
    {
        DefaultPath(req_path, attr_path, kCookiePathCap);
    }

    // If expiry is in the past (or Max-Age=0), delete the matching entry and return.
    if (expiry != kExpirySession && expiry <= now_unix)
    {
        CookieEntry* existing = FindEntry(name, attr_domain, attr_path);
        if (existing != nullptr)
        {
            existing->m_slot_seq = 0;
        }
        return;
    }

    // Upsert.
    CookieEntry* slot = FindEntry(name, attr_domain, attr_path);
    if (slot == nullptr)
    {
        const duetos::u32 idx = AllocSlot();
        slot = &g_jar[idx];
    }

    StrCopyN(slot->m_name, name, kCookieNameCap);
    StrCopyN(slot->m_value, value, kCookieValueCap);
    StrCopyN(slot->m_domain, attr_domain, kCookieDomCap);
    StrCopyN(slot->m_path, attr_path, kCookiePathCap);
    slot->m_expiry_unix = expiry;
    slot->m_slot_seq = g_next_seq++;
    slot->m_secure = secure;
    slot->m_host_only = host_only;
    slot->m_http_only = http_only;

    KLOG_DEBUG_S("net/cookies", "set-cookie upserted", "name", name);
}

// -----------------------------------------------------------------
// CookieBuildHeader
// -----------------------------------------------------------------

duetos::u32 CookieBuildHeader(const char* host, const char* path, bool secure, duetos::i64 now_unix, char* out,
                              duetos::u32 cap)
{
    if (out == nullptr || cap == 0)
    {
        return 0;
    }
    out[0] = '\0';
    if (host == nullptr || path == nullptr)
    {
        return 0;
    }

    // Collect matching cookies into a local index array (128 × u32 = 512 bytes).
    duetos::u32 idx_buf[kCookieJarCap];
    duetos::u32 idx_count = 0;

    for (duetos::u32 i = 0; i < kCookieJarCap; ++i)
    {
        const CookieEntry& e = g_jar[i];
        if (e.m_slot_seq == 0)
        {
            continue;
        }
        if (e.m_expiry_unix != kExpirySession && e.m_expiry_unix <= now_unix)
        {
            continue;
        }
        if (e.m_secure && !secure)
        {
            continue;
        }
        if (!DomainMatches(e.m_domain, e.m_host_only, host))
        {
            continue;
        }
        if (!PathMatches(e.m_path, path))
        {
            continue;
        }
        idx_buf[idx_count++] = i;
    }

    if (idx_count == 0)
    {
        return 0;
    }

    // Sort: longest path first, then ascending seq within the same path length.
    // Insertion sort (N ≤ 128).
    for (duetos::u32 i = 1; i < idx_count; ++i)
    {
        const duetos::u32 key = idx_buf[i];
        const auto klen = static_cast<duetos::u32>(StrLen(g_jar[key].m_path));
        const duetos::u32 kseq = g_jar[key].m_slot_seq;
        duetos::u32 j = i;
        while (j > 0)
        {
            const duetos::u32 prev = idx_buf[j - 1];
            const auto plen = static_cast<duetos::u32>(StrLen(g_jar[prev].m_path));
            const duetos::u32 pseq = g_jar[prev].m_slot_seq;
            if (!((plen < klen) || (plen == klen && pseq > kseq)))
            {
                break;
            }
            idx_buf[j] = idx_buf[j - 1];
            --j;
        }
        idx_buf[j] = key;
    }

    // Build "name=value; name2=value2; ..."
    duetos::u32 pos = 0;
    for (duetos::u32 i = 0; i < idx_count; ++i)
    {
        const CookieEntry& e = g_jar[idx_buf[i]];
        if (i > 0)
        {
            AppendStr(out, &pos, cap, "; ");
        }
        AppendStr(out, &pos, cap, e.m_name);
        AppendStr(out, &pos, cap, "=");
        AppendStr(out, &pos, cap, e.m_value);
    }
    if (pos < cap)
    {
        out[pos] = '\0';
    }
    else
    {
        out[cap - 1] = '\0';
        pos = cap - 1;
    }
    return pos;
}

// -----------------------------------------------------------------
// Persistence — FAT32 COOKIES.TXT
// -----------------------------------------------------------------
//
// File format: one cookie per line, fields tab-separated:
//   name\tvalue\tdomain\tpath\texpiry_unix\tsecure\thost_only\thttp_only
//
// GAP (disk round-trip): Load/Save only run when a FAT32 volume is
// mounted. The boot self-test exercises the in-memory jar only.

static constexpr const char kCookieFilePath[] = "COOKIES.TXT";

namespace
{

static void AppendI64(char* buf, duetos::u32* pos, duetos::u32 cap, duetos::i64 v)
{
    char tmp[24];
    duetos::u32 ti = 0;
    const bool neg = (v < 0);
    duetos::u64 uv = neg ? static_cast<duetos::u64>(-v) : static_cast<duetos::u64>(v);
    if (uv == 0)
    {
        tmp[ti++] = '0';
    }
    else
    {
        while (uv > 0 && ti < sizeof(tmp) - 1)
        {
            tmp[ti++] = static_cast<char>('0' + (uv % 10));
            uv /= 10;
        }
        if (neg && ti < sizeof(tmp) - 1)
        {
            tmp[ti++] = '-';
        }
        for (duetos::u32 l = 0, r = ti - 1; l < r; ++l, --r)
        {
            const char c = tmp[l];
            tmp[l] = tmp[r];
            tmp[r] = c;
        }
    }
    for (duetos::u32 i = 0; i < ti && *pos + 1 < cap; ++i)
    {
        buf[(*pos)++] = tmp[i];
    }
}

static void AppendCh(char* buf, duetos::u32* pos, duetos::u32 cap, char c)
{
    if (*pos + 1 < cap)
    {
        buf[(*pos)++] = c;
    }
}

} // namespace

void CookieJarSave()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        return;
    }

    // Max ~150 KiB: 128 cookies × (name+value+domain+path+overhead).
    constexpr duetos::u32 kBufSize = 160 * 1024;
    char* buf = static_cast<char*>(mm::KMalloc(kBufSize));
    if (buf == nullptr)
    {
        return;
    }

    duetos::u32 pos = 0;
    for (duetos::u32 i = 0; i < kCookieJarCap; ++i)
    {
        const CookieEntry& e = g_jar[i];
        if (e.m_slot_seq == 0)
        {
            continue;
        }
        AppendStr(buf, &pos, kBufSize, e.m_name);
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendStr(buf, &pos, kBufSize, e.m_value);
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendStr(buf, &pos, kBufSize, e.m_domain);
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendStr(buf, &pos, kBufSize, e.m_path);
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendI64(buf, &pos, kBufSize, e.m_expiry_unix);
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendCh(buf, &pos, kBufSize, e.m_secure ? '1' : '0');
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendCh(buf, &pos, kBufSize, e.m_host_only ? '1' : '0');
        AppendCh(buf, &pos, kBufSize, '\t');
        AppendCh(buf, &pos, kBufSize, e.m_http_only ? '1' : '0');
        AppendCh(buf, &pos, kBufSize, '\n');
    }

    fat::DirEntry probe;
    if (fat::Fat32LookupPath(v, kCookieFilePath, &probe))
    {
        fat::Fat32DeleteAtPath(v, kCookieFilePath);
    }
    fat::Fat32CreateAtPath(v, kCookieFilePath, buf, pos);
    mm::KFree(buf);

    KLOG_DEBUG_S("net/cookies", "jar saved", "path", kCookieFilePath);
}

void CookieJarLoad()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        return;
    }

    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kCookieFilePath, &e) || (e.attributes & 0x10) != 0)
    {
        return;
    }

    constexpr duetos::u32 kBufSize = 160 * 1024;
    char* buf = static_cast<char*>(mm::KMalloc(kBufSize));
    if (buf == nullptr)
    {
        return;
    }

    const duetos::u64 readcap = (e.size_bytes < kBufSize) ? e.size_bytes : kBufSize;
    const duetos::i64 n = fat::Fat32ReadFile(v, &e, buf, readcap);
    if (n <= 0)
    {
        mm::KFree(buf);
        return;
    }

    JarClear();

    const auto nn = static_cast<duetos::u32>(n);
    duetos::u32 line_start = 0;

    for (duetos::u32 i = 0; i <= nn; ++i)
    {
        if (i != nn && buf[i] != '\n')
        {
            continue;
        }
        const duetos::u32 end = i;

        // Split tab-separated fields: name, value, domain, path, expiry, secure, host_only, http_only
        const char* fields[8] = {};
        duetos::u32 f_len[8] = {};
        duetos::u32 fc = 0;
        duetos::u32 fs = line_start;
        for (duetos::u32 j = line_start; j <= end && fc < 8; ++j)
        {
            if (j == end || buf[j] == '\t')
            {
                f_len[fc] = j - fs;
                fields[fc] = buf + fs;
                ++fc;
                fs = j + 1;
            }
        }

        if (fc >= 8 && f_len[0] > 0)
        {
            CookieEntry entry{};
            entry.m_expiry_unix = kExpirySession;
            entry.m_host_only = true;

            auto copy_field = [](char* dst, duetos::u32 cap2, const char* src, duetos::u32 len)
            {
                const duetos::u32 lim = (len + 1 < cap2) ? len : cap2 - 1;
                for (duetos::u32 k = 0; k < lim; ++k)
                {
                    dst[k] = src[k];
                }
                dst[lim] = '\0';
            };

            copy_field(entry.m_name, kCookieNameCap, fields[0], f_len[0]);
            copy_field(entry.m_value, kCookieValueCap, fields[1], f_len[1]);
            copy_field(entry.m_domain, kCookieDomCap, fields[2], f_len[2]);
            copy_field(entry.m_path, kCookiePathCap, fields[3], f_len[3]);

            {
                char tmp[24];
                const duetos::u32 tl = (f_len[4] < 23) ? f_len[4] : 23;
                for (duetos::u32 k = 0; k < tl; ++k)
                {
                    tmp[k] = fields[4][k];
                }
                tmp[tl] = '\0';
                entry.m_expiry_unix = ParseDecimal(tmp, nullptr);
            }

            entry.m_secure = (f_len[5] > 0 && fields[5][0] == '1');
            entry.m_host_only = (f_len[6] > 0 && fields[6][0] == '1');
            entry.m_http_only = (f_len[7] > 0 && fields[7][0] == '1');
            entry.m_slot_seq = g_next_seq++;

            for (duetos::u32 k = 0; k < kCookieJarCap; ++k)
            {
                if (g_jar[k].m_slot_seq == 0)
                {
                    g_jar[k] = entry;
                    break;
                }
            }
        }
        line_start = i + 1;
    }

    mm::KFree(buf);
    KLOG_DEBUG_S("net/cookies", "jar loaded", "path", kCookieFilePath);
}

// -----------------------------------------------------------------
// CookieSelfTest
// -----------------------------------------------------------------
//
// Runs in a clean jar (JarClear at start and exit). Does NOT save
// the pre-test jar state to the stack — CookieEntry is ~1168 bytes
// and 128 of them would overflow the kernel stack (~146 KB). At
// early boot the jar is always empty so there is nothing to restore.

void CookieSelfTest()
{
    using arch::SerialWrite;

    // Helper: scan NUL-terminated `hdr` for the first occurrence of `needle`.
    auto contains = [](const char* hdr, const char* needle) -> bool
    {
        for (const char* p = hdr; *p != '\0'; ++p)
        {
            if (StartsWithI(p, needle))
            {
                return true;
            }
        }
        return false;
    };

    constexpr duetos::i64 kNow = 1748736000; // 2025-06-01 00:00:00 UTC
    char out[512];

    // Helper: build Cookie header for (host, path, secure) into out[512].
    auto get = [&](const char* host, const char* path, bool secure) -> duetos::u32
    { return CookieBuildHeader(host, path, secure, kNow, out, 512); };

    JarClear();

#define STFAIL(phase)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        arch::SerialWrite("[cookie-selftest] FAIL (" phase ")\n");                                                     \
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0xC00Cu);                                               \
        JarClear();                                                                                                    \
        return;                                                                                                        \
    } while (0)

    // Test 1: basic set + exact domain/path match.
    CookieSetFromHeader("example.com", "/app/page.html", "session=abc123; Path=/app; HttpOnly", kNow);
    if (get("example.com", "/app/subdir", false) == 0 || !StrEqual(out, "session=abc123"))
    {
        STFAIL("basic-set-match");
    }

    // Test 2: Secure cookie — omitted over HTTP, present over HTTPS.
    CookieSetFromHeader("example.com", "/", "token=xyz; Secure; Path=/", kNow);
    get("example.com", "/", false);
    if (contains(out, "token="))
    {
        STFAIL("secure-omit-nonhttps");
    }
    if (get("example.com", "/", true) == 0 || !contains(out, "token="))
    {
        STFAIL("secure-include-https");
    }

    // Test 3: Max-Age=0 → deleted immediately, not returned.
    CookieSetFromHeader("example.com", "/", "dead=1; Max-Age=0; Path=/", kNow);
    get("example.com", "/", false);
    if (contains(out, "dead="))
    {
        STFAIL("maxage0-not-returned");
    }

    // Test 4: past Expires → not returned.
    CookieSetFromHeader("example.com", "/", "stale=old; Expires=Thu, 01 Jan 2015 00:00:00 GMT; Path=/", kNow);
    get("example.com", "/", false);
    if (contains(out, "stale="))
    {
        STFAIL("past-expires-not-returned");
    }

    // Test 5: future Expires → returned.
    CookieSetFromHeader("example.com", "/", "future=ok; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Path=/", kNow);
    if (get("example.com", "/", false) == 0 || !contains(out, "future=ok"))
    {
        STFAIL("future-expires-returned");
    }

    // Test 6: same-name overwrite (same domain + path).
    JarClear();
    CookieSetFromHeader("example.com", "/", "counter=1; Path=/", kNow);
    CookieSetFromHeader("example.com", "/", "counter=2; Path=/", kNow);
    get("example.com", "/", false);
    if (contains(out, "counter=1") || !contains(out, "counter=2"))
    {
        STFAIL("same-name-overwrite");
    }

    // Test 7: domain suffix match (.example.com → sub.example.com).
    JarClear();
    CookieSetFromHeader("example.com", "/", "shared=yes; Domain=.example.com; Path=/", kNow);
    if (get("sub.example.com", "/", false) == 0 || !contains(out, "shared=yes"))
    {
        STFAIL("domain-suffix-match");
    }

    // Test 8: domain suffix mismatch (other.com must NOT receive the cookie).
    get("other.com", "/", false);
    if (contains(out, "shared="))
    {
        STFAIL("domain-suffix-mismatch");
    }

    // Test 9: longest-path-first ordering.
    JarClear();
    CookieSetFromHeader("example.com", "/", "a=root; Path=/", kNow);
    CookieSetFromHeader("example.com", "/", "b=app; Path=/app", kNow);
    CookieSetFromHeader("example.com", "/", "c=deep; Path=/app/deep", kNow);
    if (get("example.com", "/app/deep/x", false) == 0)
    {
        STFAIL("ordering-empty");
    }
    {
        const char* pc = nullptr;
        const char* pb = nullptr;
        for (const char* p = out; *p != '\0'; ++p)
        {
            if (pc == nullptr && StartsWithI(p, "c=deep"))
            {
                pc = p;
            }
            if (pb == nullptr && StartsWithI(p, "b=app"))
            {
                pb = p;
            }
        }
        if (pc == nullptr || pb == nullptr || pc > pb)
        {
            STFAIL("ordering-longest-path-first");
        }
    }

    // Test 10: host-only — NOT sent to subdomain, IS sent to exact host.
    JarClear();
    CookieSetFromHeader("exact.com", "/", "ho=1; Path=/", kNow); // no Domain → host-only
    get("sub.exact.com", "/", false);
    if (contains(out, "ho="))
    {
        STFAIL("host-only-no-subdomain");
    }
    if (get("exact.com", "/", false) == 0 || !contains(out, "ho=1"))
    {
        STFAIL("host-only-exact-match");
    }

#undef STFAIL

    JarClear();

    SerialWrite("[cookie-selftest] PASS (set+match, secure-gate, expiry, overwrite, "
                "domain-suffix, ordering, host-only all verified; disk round-trip GAP'd)\n");
}

} // namespace duetos::net
