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
#include "util/random.h"

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

// ===================================================================
// Per-boot dynamic canary names.
// ===================================================================
//
// 4 slots × 32 bytes/slot = 128 bytes of mutable storage. Each
// slot holds a string of the form "DUETOS_HONEY_<8 hex chars>.DAT"
// where the hex bytes come from the kernel entropy pool. Slot
// strings are populated by `CanaryInit`; before that they are
// empty (matchers walk past them harmlessly).
//
// Why four slots: enough to make the attacker's pre-compute
// strategy impractical (4 × 32-bit = 128 bits of canary entropy
// per boot) while keeping the per-syscall match O(1) walks
// short.
constexpr u32 kDynamicCanarySlots = 4;
constexpr u32 kDynamicCanaryNameCap = 32;
constinit char g_dynamic_canary_names[kDynamicCanarySlots][kDynamicCanaryNameCap] = {};
constinit bool g_canary_init_run = false;

void RenderHexNibble(char* out, u8 nibble)
{
    if (nibble < 10)
        *out = static_cast<char>('0' + nibble);
    else
        *out = static_cast<char>('A' + (nibble - 10));
}

void RenderDynamicCanaryName(char* out, u32 cap, u32 slot_random_low)
{
    constexpr const char kPrefix[] = "DUETOS_HONEY_";
    constexpr const char kSuffix[] = ".DAT";
    constexpr u32 kPrefixLen = sizeof(kPrefix) - 1; // 13
    constexpr u32 kHexLen = 8;
    constexpr u32 kSuffixLen = sizeof(kSuffix) - 1; // 4
    if (cap < kPrefixLen + kHexLen + kSuffixLen + 1)
    {
        if (cap > 0)
            out[0] = '\0';
        return;
    }
    u32 oi = 0;
    for (u32 i = 0; i < kPrefixLen; ++i)
        out[oi++] = kPrefix[i];
    for (i32 nb = 7; nb >= 0; --nb)
    {
        const u8 nibble = static_cast<u8>((slot_random_low >> (nb * 4)) & 0x0F);
        RenderHexNibble(&out[oi++], nibble);
    }
    for (u32 i = 0; i < kSuffixLen; ++i)
        out[oi++] = kSuffix[i];
    out[oi] = '\0';
}

// ===================================================================
// Persistence-drop detector state.
// ===================================================================
//
// Persistence-equivalent paths a typical malware survival shim
// drops files into. Format mirrors the canary list — exact path
// or prefix entry, leaf-or-full-path matching. The set covers:
//   - Linux init / systemd lookalikes.
//   - DuetOS native autostart conventions.
//   - Win32 registry "Run" key paths (the registry surface is
//     a path namespace inside DuetOS — see kernel/subsystems/
//     win32/registry.cpp).
//   - Boot-config files that survive reboot.
constexpr const char* kPersistencePaths[] = {
    "/etc/init.d/",
    "/etc/rc.d/",
    "/etc/systemd/",
    "/.duetos/autostart/",
    "/.duetos/services/",
    "/init.cfg",
    "/boot.ini",
    "BOOT.INI",
    "/duetos/run/",
    // Win32 registry-equivalent paths the registry subsystem
    // exposes through the canonical "/registry/<HIVE>/..." VFS
    // overlay. Standard "Run" autostart locations.
    "/registry/HKLM/Software/Microsoft/Windows/CurrentVersion/Run",
    "/registry/HKCU/Software/Microsoft/Windows/CurrentVersion/Run",
    "/registry/HKLM/System/CurrentControlSet/Services/",
    // Sentinel name nothing legitimate writes to.
    "DUETOS_AUTOSTART",
};

constexpr u32 kPersistencePathCount = sizeof(kPersistencePaths) / sizeof(kPersistencePaths[0]);

constinit PersistenceMode g_persistence_mode = PersistenceMode::Advisory;
constinit PersistenceStats g_persistence_stats = {};

} // namespace

bool CanaryMatchesPath(const char* path)
{
    if (path == nullptr || path[0] == '\0')
        return false;
    const char* leaf = PathBasename(path);
    // Static registry first.
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
    // Per-boot dynamic registry. Only meaningful after CanaryInit
    // has run; before that the slots are empty strings and the
    // StrEqIcase guards short-circuit.
    for (u32 i = 0; i < kDynamicCanarySlots; ++i)
    {
        const char* entry = g_dynamic_canary_names[i];
        if (entry[0] == '\0')
            continue;
        if (StrEqIcase(path, entry) || StrEqIcase(leaf, entry))
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

void CanaryInit()
{
    if (g_canary_init_run)
        return;
    // Pull entropy and render it as ASCII into the four dynamic
    // canary slots. We use the LOW 32 bits of two RandomU64
    // draws (one draw per two slots) to keep the entropy
    // budget reasonable. Even if RandomU64 falls back to
    // splitmix64 (no RDRAND/RDSEED) the slot names aren't
    // pre-computable from the kernel binary alone — splitmix64
    // is seeded from TSC / HPET at RandomInit and an attacker
    // doesn't see those values.
    const u64 r0 = ::duetos::core::RandomU64();
    const u64 r1 = ::duetos::core::RandomU64();
    const u32 lows[kDynamicCanarySlots] = {
        static_cast<u32>(r0 & 0xFFFFFFFFu),
        static_cast<u32>((r0 >> 32) & 0xFFFFFFFFu),
        static_cast<u32>(r1 & 0xFFFFFFFFu),
        static_cast<u32>((r1 >> 32) & 0xFFFFFFFFu),
    };
    for (u32 i = 0; i < kDynamicCanarySlots; ++i)
    {
        RenderDynamicCanaryName(g_dynamic_canary_names[i], kDynamicCanaryNameCap, lows[i]);
    }
    g_canary_init_run = true;
    arch::SerialWrite("[canary] CanaryInit: ");
    arch::SerialWriteHex(static_cast<u64>(kDynamicCanarySlots));
    arch::SerialWrite(" dynamic canaries seeded — names withheld from log\n");
}

// ===================================================================
// Persistence-drop detector — implementation.
// ===================================================================

bool PersistenceMatchesPath(const char* path)
{
    if (path == nullptr || path[0] == '\0')
        return false;
    const char* leaf = PathBasename(path);
    for (u32 i = 0; i < kPersistencePathCount; ++i)
    {
        const char* entry = kPersistencePaths[i];
        if (entry == nullptr || entry[0] == '\0')
            continue;
        if (StrEqIcase(path, entry) || StrEqIcase(leaf, entry))
            return true;
        if (StartsWithIcase(path, entry))
            return true;
    }
    return false;
}

bool PersistenceNote(const char* path, const char* op)
{
    ++g_persistence_stats.notes_total;
    arch::SerialWrite("[persistence] ");
    arch::SerialWrite(g_persistence_mode == PersistenceMode::Deny ? "DENY" : "ADVISORY");
    arch::SerialWrite(" op=");
    arch::SerialWrite(op != nullptr ? op : "?");
    arch::SerialWrite(" path=\"");
    arch::SerialWrite(path != nullptr ? path : "<null>");
    arch::SerialWrite("\"\n");
    ::duetos::core::RuntimeCheckerNotePersistenceDrop();
    if (g_persistence_mode == PersistenceMode::Deny)
    {
        ++g_persistence_stats.notes_denied;
        sched::FlagCurrentForKill(sched::KillReason::PersistenceDrop);
        return true;
    }
    ++g_persistence_stats.notes_advisory;
    return false;
}

bool PersistenceCheck(const char* path, const char* op)
{
    if (!PersistenceMatchesPath(path))
        return false;
    return PersistenceNote(path, op);
}

PersistenceMode PersistenceModeRead()
{
    return g_persistence_mode;
}

void PersistenceSetMode(PersistenceMode m)
{
    if (g_persistence_mode == m)
        return;
    arch::SerialWrite("[persistence] mode -> ");
    arch::SerialWrite(m == PersistenceMode::Deny ? "Deny" : "Advisory");
    arch::SerialWrite("\n");
    g_persistence_mode = m;
}

const PersistenceStats& PersistenceStatsRead()
{
    return g_persistence_stats;
}

} // namespace duetos::security
