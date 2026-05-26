#include "loader/apiset_static.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::loader
{

namespace
{

// Static contract → host table. Sorted by contract for binary
// search. The contract field stores the *head* only — no trailing
// "-<major>-<minor>.dll". The lookup strips the version + ".dll"
// suffix from the import name before comparing, so a versioned
// "api-ms-win-core-libraryloader-l1-2-0.dll" import matches the
// table entry "api-ms-win-core-libraryloader-l1".
//
// Coverage matches the api-set surface DuetOS PEs actually import
// today. Adding new contracts is the right shape for landing new
// PE compat work — flip the via-apiset-heuristic boot-log line
// over to via-apiset-table.
//
// Hosts use the canonical DuetOS preload-set names. Two-letter
// stems are reserved (`ntdll.dll`, `kernel32.dll`,
// `kernelbase.dll`, `ucrtbase.dll`) — the api-set surface
// concentrates almost entirely in these four base DLLs. Other
// hosts ("user32.dll", "advapi32.dll", "shell32.dll", etc.) are
// listed as they're confirmed.
struct ApiSetEntry
{
    const char* contract; // sans "-N-N.dll" tail; lowercase
    const char* host;     // canonical preload-set DLL name
};

constexpr ApiSetEntry kApiSetTable[] = {
    {"api-ms-win-core-com", "ole32.dll"},
    {"api-ms-win-core-console-l1", "kernel32.dll"},
    {"api-ms-win-core-datetime-l1", "kernelbase.dll"},
    {"api-ms-win-core-debug-l1", "kernelbase.dll"},
    {"api-ms-win-core-delayload-l1", "kernel32.dll"},
    {"api-ms-win-core-errorhandling-l1", "kernelbase.dll"},
    {"api-ms-win-core-fibers-l1", "kernelbase.dll"},
    {"api-ms-win-core-fibers-l2", "kernelbase.dll"},
    {"api-ms-win-core-file-l1", "kernelbase.dll"},
    {"api-ms-win-core-file-l2", "kernelbase.dll"},
    {"api-ms-win-core-handle-l1", "kernelbase.dll"},
    {"api-ms-win-core-heap-l1", "kernelbase.dll"},
    {"api-ms-win-core-heap-l2", "kernelbase.dll"},
    {"api-ms-win-core-interlocked-l1", "kernelbase.dll"},
    {"api-ms-win-core-io-l1", "kernelbase.dll"},
    {"api-ms-win-core-kernel32-legacy-l1", "kernel32.dll"},
    {"api-ms-win-core-libraryloader-l1", "kernelbase.dll"},
    {"api-ms-win-core-libraryloader-l2", "kernelbase.dll"},
    {"api-ms-win-core-localization-l1", "kernelbase.dll"},
    {"api-ms-win-core-localization-l2", "kernelbase.dll"},
    {"api-ms-win-core-memory-l1", "kernelbase.dll"},
    {"api-ms-win-core-misc-l1", "kernelbase.dll"},
    {"api-ms-win-core-namedpipe-l1", "kernelbase.dll"},
    {"api-ms-win-core-namespace-l1", "kernelbase.dll"},
    {"api-ms-win-core-processenvironment-l1", "kernelbase.dll"},
    {"api-ms-win-core-processthreads-l1", "kernelbase.dll"},
    {"api-ms-win-core-processtopology-l1", "kernelbase.dll"},
    {"api-ms-win-core-profile-l1", "kernelbase.dll"},
    {"api-ms-win-core-psapi-l1", "kernel32.dll"},
    {"api-ms-win-core-realtime-l1", "kernelbase.dll"},
    {"api-ms-win-core-registry-l1", "kernelbase.dll"},
    {"api-ms-win-core-registry-l2", "kernelbase.dll"},
    {"api-ms-win-core-rtlsupport-l1", "ntdll.dll"},
    {"api-ms-win-core-string-l1", "kernelbase.dll"},
    {"api-ms-win-core-string-l2", "kernelbase.dll"},
    {"api-ms-win-core-synch-l1", "kernelbase.dll"},
    {"api-ms-win-core-sysinfo-l1", "kernelbase.dll"},
    {"api-ms-win-core-threadpool-l1", "kernelbase.dll"},
    {"api-ms-win-core-threadpool-legacy-l1", "kernelbase.dll"},
    {"api-ms-win-core-timezone-l1", "kernelbase.dll"},
    {"api-ms-win-core-url-l1", "shlwapi.dll"},
    {"api-ms-win-core-util-l1", "kernelbase.dll"},
    {"api-ms-win-core-version-l1", "version.dll"},
    {"api-ms-win-core-winrt-error-l1", "combase.dll"},
    {"api-ms-win-core-winrt-l1", "combase.dll"},
    {"api-ms-win-core-winrt-string-l1", "combase.dll"},
    {"api-ms-win-core-wow64-l1", "kernel32.dll"},
    {"api-ms-win-crt-conio-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-convert-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-environment-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-filesystem-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-heap-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-locale-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-math-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-multibyte-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-private-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-process-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-runtime-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-stdio-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-string-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-time-l1", "ucrtbase.dll"},
    {"api-ms-win-crt-utility-l1", "ucrtbase.dll"},
    {"api-ms-win-security-base-l1", "advapi32.dll"},
    {"api-ms-win-security-cryptoapi-l1", "advapi32.dll"},
    {"api-ms-win-security-lsalookup-l2", "advapi32.dll"},
    {"api-ms-win-security-provider-l1", "advapi32.dll"},
    {"api-ms-win-security-sddl-l1", "advapi32.dll"},
    {"api-ms-win-service-core-l1", "advapi32.dll"},
    {"api-ms-win-service-management-l1", "advapi32.dll"},
    {"api-ms-win-service-management-l2", "advapi32.dll"},
    {"api-ms-win-service-winsvc-l1", "advapi32.dll"},
    {"api-ms-win-shcore-scaling-l1", "shcore.dll"},
};

constexpr u32 kApiSetTableCount = sizeof(kApiSetTable) / sizeof(kApiSetTable[0]);

// Lowercase a single ASCII byte (A-Z only).
constexpr char Lc(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

// Case-insensitive lexicographic compare of two strings up to
// `len` bytes. Returns <0 / 0 / >0. Treats NULs in either string
// as terminators (so `len` is an upper bound, not a strict count).
int CiCompareN(const char* a, const char* b, u32 len)
{
    for (u32 i = 0; i < len; ++i)
    {
        const char ca = Lc(a[i]);
        const char cb = Lc(b[i]);
        if (ca != cb)
            return (ca < cb) ? -1 : 1;
        if (ca == '\0')
            return 0; // both terminated at same point
    }
    return 0;
}

// Compute the length of the contract HEAD — i.e. the input
// without the trailing "-<major>-<minor>.dll" or trailing ".dll".
//
// Examples:
//   "api-ms-win-core-libraryloader-l1-2-0.dll" → length up to
//     and including "l1" (drop "-2-0.dll").
//   "api-ms-win-core-string-l1.dll" → length up to and
//     including "l1" (drop ".dll").
//   "api-ms-win-core-string-l1-2-0" → length up to and including
//     "l1" (drop "-2-0" — no ".dll" suffix accepted too).
//   "api-ms-win-core-string-l1" → full length (no version, no suffix).
//
// Strategy: walk to end of string. Drop ".dll" if present. Then
// scan back: each trailing "-<digits>" group is a version
// component; drop while the trailing segment matches. Stop after
// at most 2 such drops (the "-<major>-<minor>" pair). This is
// strictly safer than dropping ANY trailing "-<digits>" — table
// entries like "...-l1" must NOT lose the "-l1" tag.
u32 ContractHeadLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    // Drop trailing ".dll" / ".Dll" / ".DLL" / mixed-case.
    if (n >= 4 && Lc(s[n - 4]) == '.' && Lc(s[n - 3]) == 'd' && Lc(s[n - 2]) == 'l' && Lc(s[n - 1]) == 'l')
        n -= 4;
    // Drop up to two trailing "-<digits>" groups.
    for (u32 drops = 0; drops < 2; ++drops)
    {
        // Find the last '-'.
        u32 dash = n;
        while (dash > 0 && s[dash - 1] != '-')
            --dash;
        if (dash == 0)
            break; // no dash, can't be a version suffix
        // Everything between dash and n must be digits.
        bool all_digits = (n > dash); // at least one char
        for (u32 i = dash; i < n; ++i)
        {
            if (s[i] < '0' || s[i] > '9')
            {
                all_digits = false;
                break;
            }
        }
        if (!all_digits)
            break;
        // Drop the "-<digits>" group.
        n = dash - 1;
    }
    return n;
}

} // namespace

bool ApiSetResolveStatic(const char* contract, const char** out_host)
{
    if (contract == nullptr || out_host == nullptr)
        return false;

    const u32 head_len = ContractHeadLen(contract);
    if (head_len == 0)
        return false;

    // Binary search on case-folded head.
    u32 lo = 0;
    u32 hi = kApiSetTableCount;
    while (lo < hi)
    {
        const u32 mid = lo + (hi - lo) / 2u;
        const ApiSetEntry& e = kApiSetTable[mid];
        // Compare head_len chars of contract against the full
        // entry. The entry is case-folded by construction; the
        // contract head may have any case (CiCompareN folds).
        u32 entry_len = 0;
        while (e.contract[entry_len] != '\0')
            ++entry_len;
        const u32 cmp_len = (head_len < entry_len) ? head_len : entry_len;
        int c = CiCompareN(contract, e.contract, cmp_len);
        if (c == 0)
        {
            // Common prefix matches; longer string sorts after.
            if (head_len < entry_len)
                c = -1;
            else if (head_len > entry_len)
                c = 1;
        }
        if (c == 0)
        {
            *out_host = e.host;
            return true;
        }
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return false;
}

void ApiSetSelfTest()
{
    using arch::SerialWrite;

    // (1) Table must be sorted (case-folded contract field).
    for (u32 i = 1; i < kApiSetTableCount; ++i)
    {
        // Both entries are already lowercase by construction, so a
        // straight strcmp via CiCompareN works.
        u32 prev_len = 0;
        while (kApiSetTable[i - 1].contract[prev_len] != '\0')
            ++prev_len;
        u32 this_len = 0;
        while (kApiSetTable[i].contract[this_len] != '\0')
            ++this_len;
        const u32 cmp = (prev_len < this_len) ? prev_len : this_len;
        int c = CiCompareN(kApiSetTable[i - 1].contract, kApiSetTable[i].contract, cmp);
        if (c == 0)
        {
            if (prev_len < this_len)
                c = -1;
            else if (prev_len > this_len)
                c = 1;
        }
        if (c >= 0)
        {
            core::PanicWithValue("apiset-selftest", "table not sorted at index", i);
        }
    }

    // (2) Lookup of a known versioned contract returns the
    // expected host.
    const char* host = nullptr;
    if (!ApiSetResolveStatic("api-ms-win-core-libraryloader-l1-2-0.dll", &host) || host == nullptr)
    {
        core::Panic("apiset-selftest", "known contract lookup miss");
    }
    // Compare host == "kernelbase.dll".
    {
        const char* want = "kernelbase.dll";
        u32 i = 0;
        for (; want[i] != '\0' && host[i] != '\0'; ++i)
        {
            if (want[i] != host[i])
                core::Panic("apiset-selftest", "host string mismatch");
        }
        if (want[i] != '\0' || host[i] != '\0')
            core::Panic("apiset-selftest", "host length mismatch");
    }

    // (3) Case-insensitive lookup (uppercase variant).
    host = nullptr;
    if (!ApiSetResolveStatic("API-MS-WIN-CORE-RTLSUPPORT-L1-1-0.DLL", &host) || host == nullptr)
    {
        core::Panic("apiset-selftest", "case-insensitive lookup miss");
    }
    if (host[0] != 'n' || host[1] != 't' || host[2] != 'd' || host[3] != 'l')
    {
        core::Panic("apiset-selftest", "case-insensitive host wrong");
    }

    // (4) Head-only contract (no version suffix) resolves.
    host = nullptr;
    if (!ApiSetResolveStatic("api-ms-win-core-string-l1", &host) || host == nullptr)
    {
        core::Panic("apiset-selftest", "head-only lookup miss");
    }

    // (5) Trailing ".dll" without version digits is stripped.
    host = nullptr;
    if (!ApiSetResolveStatic("api-ms-win-core-handle-l1.dll", &host) || host == nullptr)
    {
        core::Panic("apiset-selftest", "dll-only suffix lookup miss");
    }

    // (6) Unknown contract returns false without scribbling.
    host = reinterpret_cast<const char*>(0xDEADBEEFu);
    if (ApiSetResolveStatic("api-ms-win-fake-nonexistent-l99-0-0.dll", &host))
    {
        core::Panic("apiset-selftest", "unknown contract spuriously resolved");
    }
    // host remains untouched (sentinel preserved).
    if (host != reinterpret_cast<const char*>(0xDEADBEEFu))
    {
        core::Panic("apiset-selftest", "miss path scribbled out_host");
    }

    // (7) NULL inputs return false.
    if (ApiSetResolveStatic(nullptr, &host) || ApiSetResolveStatic("api-ms-win-core-misc-l1", nullptr))
    {
        core::Panic("apiset-selftest", "null-input guard regressed");
    }

    SerialWrite("[apiset-selftest] PASS\n");
}

} // namespace duetos::loader
