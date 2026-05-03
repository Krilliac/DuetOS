/*
 * DuetOS — file-canary self-defense: implementation.
 *
 * See canary.h for the threat-model rationale and the public
 * API. This TU owns:
 *
 *   - The static canary registry (`kCanaryPaths`,
 *     `kCanarySuspiciousExtensions`).
 *   - The case-insensitive ASCII matchers used by the syscall
 *     hooks.
 *   - The Trip path that bumps the global stats, the
 *     `CanaryFileTouched` health counter, and flags the current
 *     task for kill.
 */

#include "security/canary.h"

#include "arch/x86_64/serial.h"
#include "diag/runtime_checker.h"
#include "log/klog.h"
#include "sched/sched.h"

namespace duetos::security
{

namespace
{

// Canary path / leaf-name registry. v0 list is a mix of:
//   - High-value-looking filenames a ransomware enumerator is
//     likely to prioritise ("wallet.dat", "passwords.txt").
//   - DuetOS-native sentinel paths nothing legitimate ever
//     touches ("/canary/", "DUETOS_CANARY.DAT").
//   - System-ish names that any ransomware blindly walking
//     directories would hit before getting deep into user data
//     ("DO_NOT_DELETE.txt", "boot.ini.bak", etc).
//
// Match rules: a string matches if (a) it equals a full-path
// entry verbatim, (b) its basename equals a leaf entry, or
// (c) it begins with a prefix entry. Each entry's role is
// recorded in the comment column below; the matcher itself
// doesn't care, it tries all three rules against every entry.
//
// Keeping the list small (≤ 32 entries) so the per-syscall
// O(N) walk stays cheap. A future v1 can grow this to a
// hash-set if the registry expands materially.
constexpr const char* kCanaryPaths[] = {
    // Boot-process canaries (DuetOS-native sentinels)
    "/canary/",
    "DUETOS_CANARY.DAT",
    "DO_NOT_DELETE.TXT",
    // Common ransomware-bait names — short enough to fit FAT32
    // 8.3 plus a few longer-form duplicates.
    "WALLET.DAT",
    "PASSWORDS.TXT",
    "PASSWORD.TXT",
    "BACKUP.ZIP",
    "ID_RSA",
    "PAYROLL.XLS",
    "INVOICES.PDF",
    "SECRET.TXT",
    // ~/Documents/IMPORTANT.* style
    "IMPORTANT.DOC",
    "IMPORTANT.DOCX",
    "IMPORTANT.TXT",
    // Sentinel-only: a path nothing legitimate writes to.
    "DUETOS_HONEY",
};

constexpr u32 kCanaryPathCount = sizeof(kCanaryPaths) / sizeof(kCanaryPaths[0]);

// Suspicious extensions — the trailing `.<ext>` substring of a
// path the canary wall treats as "this is a ransomware encrypt-
// output file". List sourced from observed real-world
// ransomware families (Locky, WannaCry, Crysis, Maze, ...) —
// the common pattern is a non-standard extension that
// legitimate apps never emit.
//
// Lower-case (matcher is case-insensitive). Each entry includes
// the leading dot so a full-path match against "boot.ini" never
// trips ".ini" by accident — only the explicit suffix forms.
constexpr const char* kCanarySuspiciousExtensions[] = {
    ".locked", ".encrypted", ".crypto", ".crypt", ".crypted", ".enc", ".encrypt", ".lock",    ".ransom",
    ".wcry",   ".wncry",     ".cerber", ".thor",  ".aes",     ".rsa", ".pay",     ".paymrts", ".doxxed",
};

constexpr u32 kCanaryExtCount = sizeof(kCanarySuspiciousExtensions) / sizeof(kCanarySuspiciousExtensions[0]);

constinit CanaryStats g_stats = {};

// ---- ASCII helpers (kernel TU; <cctype> is user-land). ----
constexpr char AsciiToLower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

constexpr bool AsciiEqIcase(char a, char b)
{
    return AsciiToLower(a) == AsciiToLower(b);
}

// Length of a NUL-terminated C string, capped to avoid runaway
// walks on a corrupt path. 4 KiB is well above any legitimate
// file path the kernel sees.
u64 BoundedStrlen(const char* s)
{
    constexpr u64 kCap = 4096;
    if (s == nullptr)
        return 0;
    u64 n = 0;
    while (n < kCap && s[n] != '\0')
        ++n;
    return n;
}

// True if `s` equals `t` case-insensitively over their full
// length. Both must be NUL-terminated. nullptrs / empty strings
// never match.
bool StrEqIcase(const char* s, const char* t)
{
    if (s == nullptr || t == nullptr)
        return false;
    while (*s != '\0' && *t != '\0')
    {
        if (!AsciiEqIcase(*s, *t))
            return false;
        ++s;
        ++t;
    }
    return *s == '\0' && *t == '\0';
}

// True if `s` begins with `prefix` case-insensitively. Empty
// prefix matches anything (including empty string); the matcher
// guards against that at registry-level — entries are never
// empty.
bool StartsWithIcase(const char* s, const char* prefix)
{
    if (s == nullptr || prefix == nullptr)
        return false;
    while (*prefix != '\0')
    {
        if (*s == '\0' || !AsciiEqIcase(*s, *prefix))
            return false;
        ++s;
        ++prefix;
    }
    return true;
}

// True if `s` ends with `suffix` case-insensitively. Both must
// be NUL-terminated. Empty suffix returns true (consistent with
// std::string::ends_with on an empty arg); registry never
// supplies empty suffixes, so the corner case is safe.
bool EndsWithIcase(const char* s, const char* suffix)
{
    if (s == nullptr || suffix == nullptr)
        return false;
    const u64 sl = BoundedStrlen(s);
    const u64 sx = BoundedStrlen(suffix);
    if (sx > sl)
        return false;
    const char* tail = s + (sl - sx);
    return StrEqIcase(tail, suffix);
}

// Return a pointer to the basename inside `path` — the bytes
// after the last '/' or '\\'. If the path has no separator the
// path itself is its own basename. Always non-null when `path`
// is non-null.
const char* PathBasename(const char* path)
{
    if (path == nullptr)
        return path;
    const char* base = path;
    for (const char* p = path; *p != '\0'; ++p)
    {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    return base;
}

} // namespace

bool CanaryMatchesPath(const char* path)
{
    if (path == nullptr || path[0] == '\0')
        return false;
    const char* leaf = PathBasename(path);
    for (u32 i = 0; i < kCanaryPathCount; ++i)
    {
        const char* entry = kCanaryPaths[i];
        if (entry == nullptr || entry[0] == '\0')
            continue;
        // Whole-path / whole-leaf compare (covers absolute
        // canaries like "/canary/" used as full path AND short
        // 8.3 leaf forms like "WALLET.DAT").
        if (StrEqIcase(path, entry) || StrEqIcase(leaf, entry))
            return true;
        // Prefix compare (e.g. "/canary/" prefix matches
        // "/canary/anything-here.txt").
        if (StartsWithIcase(path, entry))
            return true;
    }
    return false;
}

bool CanaryMatchesSuspiciousExtension(const char* path)
{
    if (path == nullptr || path[0] == '\0')
        return false;
    for (u32 i = 0; i < kCanaryExtCount; ++i)
    {
        const char* ext = kCanarySuspiciousExtensions[i];
        if (ext == nullptr || ext[0] == '\0')
            continue;
        if (EndsWithIcase(path, ext))
            return true;
    }
    return false;
}

void CanaryTrip(const char* path, const char* op)
{
    ++g_stats.trips_total;
    arch::SerialWrite("[canary] TRIP op=");
    arch::SerialWrite(op != nullptr ? op : "?");
    arch::SerialWrite(" path=\"");
    arch::SerialWrite(path != nullptr ? path : "<null>");
    arch::SerialWrite("\" — terminating caller (canary file touched)\n");
    // Route through the runtime-checker note so the
    // CanaryFileTouched per-issue counter, last-issue tracking
    // and standard log line stay consistent with the periodic-
    // scan detectors. The Report-side log line is at Warn level
    // and includes the HealthIssueName.
    ::duetos::core::RuntimeCheckerNoteCanaryFileTouched();
    sched::FlagCurrentForKill(sched::KillReason::CanaryFileTouched);
}

bool CanaryCheck(const char* path, const char* op)
{
    if (CanaryMatchesPath(path))
    {
        ++g_stats.trips_path;
        CanaryTrip(path, op);
        return true;
    }
    if (CanaryMatchesSuspiciousExtension(path))
    {
        ++g_stats.trips_suspicious;
        CanaryTrip(path, op);
        return true;
    }
    return false;
}

const CanaryStats& CanaryStatsRead()
{
    return g_stats;
}

} // namespace duetos::security
