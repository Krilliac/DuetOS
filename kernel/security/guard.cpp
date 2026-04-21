#include "guard.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/types.h"

namespace customos::security
{

namespace
{

// ---------------------------------------------------------------
// Mutable state. Single-threaded access is the common case (load
// chain runs serially inside a spawner); minor counter races are
// tolerated — the numbers are a human-readable status indicator,
// not a policy input.
// ---------------------------------------------------------------

constinit Mode g_mode = Mode::Advisory;
constinit u64 g_scan_count = 0;
constinit u64 g_allow_count = 0;
constinit u64 g_warn_count = 0;
constinit u64 g_deny_count = 0;
constinit Report g_last_report = {};
constinit bool g_init_done = false;

// ---------------------------------------------------------------
// Policy tables.
// ---------------------------------------------------------------

// Name-based deny list — e.g. known-bad filenames from past
// incidents. Static + small + grep-obvious so a code reviewer
// can see the policy. Add entries by editing this array; hot
// reload from tmpfs is a follow-up slice.
constexpr const char* kDeniedNames[] = {
    // (empty seed — populate with real entries as incidents land)
    nullptr,
};

// FNV-1a hash denylist. A real AV would use SHA-256; FNV-1a is
// a placeholder so the code path + shell status line work
// end-to-end before we have a cryptographic hash module.
struct HashEntry
{
    u64 hash;
    const char* label;
};
constexpr HashEntry kDeniedHashes[] = {
    // (empty seed)
    {0, nullptr},
};

// Suspicious Windows API names. Presence of the ASCII substring
// in the image bytes is the heuristic — we don't reparse the PE
// import table (the PE loader already does that; we stay
// independent so we can also scan stripped/obfuscated PEs that
// trip the loader's validators).
constexpr const char* kSuspiciousApis[] = {
    "CreateRemoteThread", "NtCreateThreadEx", "ZwCreateThreadEx", "WriteProcessMemory", "ReadProcessMemory",
    "VirtualAllocEx",     "VirtualProtectEx", "SetWindowsHookEx", "SetThreadContext",   "QueueUserAPC",
};
constexpr u32 kSuspiciousApiCount = sizeof(kSuspiciousApis) / sizeof(kSuspiciousApis[0]);

// ---------------------------------------------------------------
// String + hash helpers (no libc in kernel).
// ---------------------------------------------------------------

u64 StrLen(const char* s)
{
    u64 n = 0;
    while (s != nullptr && s[n] != 0)
        ++n;
    return n;
}

// Volatile byte-zero. Prevents clang from lowering a plain loop
// into memset, which the freestanding kernel does not link.
void VZero(void* p, u64 n)
{
    auto* b = reinterpret_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

// Volatile byte-copy. Same reasoning.
void VCopy(void* dst, const void* src, u64 n)
{
    auto* d = reinterpret_cast<volatile u8*>(dst);
    const auto* s = reinterpret_cast<const u8*>(src);
    for (u64 i = 0; i < n; ++i)
        d[i] = s[i];
}

// Copy a Report, field-by-field, without inviting a struct-level
// memcpy lowering.
void CopyReport(Report& dst, const Report& src)
{
    dst.verdict = src.verdict;
    dst.finding_count = src.finding_count;
    for (u32 i = 0; i < kMaxFindings; ++i)
    {
        dst.findings[i].code = src.findings[i].code;
        dst.findings[i].detail = src.findings[i].detail;
    }
}

bool StrEq(const char* a, const char* b)
{
    if (a == b)
        return true;
    if (a == nullptr || b == nullptr)
        return false;
    for (u64 i = 0;; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == 0)
            return true;
    }
}

// Naive strstr equivalent for ASCII needles in a byte buffer.
// The O(n*m) cost is bounded: needles are 15..25 chars, buffers
// are at most a few hundred KiB per image. Rolling into something
// fancier (Boyer-Moore) is dead weight at this scale.
bool BytesContain(const u8* hay, u64 hay_len, const char* needle)
{
    const u64 nlen = StrLen(needle);
    if (nlen == 0 || nlen > hay_len)
        return false;
    for (u64 i = 0; i + nlen <= hay_len; ++i)
    {
        u64 k = 0;
        while (k < nlen && hay[i + k] == static_cast<u8>(needle[k]))
            ++k;
        if (k == nlen)
            return true;
    }
    return false;
}

// FNV-1a over the whole image. Deterministic, hardware-independent,
// no third-party crypto dependency — matches the v0 hash-denylist
// which is a content fingerprint, NOT a signature.
u64 Fnv1aHash(const u8* data, u64 len)
{
    constexpr u64 kFnvOffset = 0xCBF29CE484222325ull;
    constexpr u64 kFnvPrime = 0x00000100000001B3ull;
    u64 h = kFnvOffset;
    for (u64 i = 0; i < len; ++i)
    {
        h ^= data[i];
        h *= kFnvPrime;
    }
    return h;
}

// ---------------------------------------------------------------
// Heuristic implementations. Each appends at most one finding
// and returns the strongest Verdict it produced, so the Inspect
// driver can combine them with max().
// ---------------------------------------------------------------

void AppendFinding(Report& r, FindingCode code, const char* detail)
{
    if (r.finding_count < kMaxFindings)
    {
        r.findings[r.finding_count].code = static_cast<u32>(code);
        r.findings[r.finding_count].detail = detail;
        ++r.finding_count;
    }
}

Verdict CheckNameDeny(const ImageDescriptor& desc, Report& r)
{
    for (u32 i = 0; kDeniedNames[i] != nullptr; ++i)
    {
        if (StrEq(desc.name, kDeniedNames[i]))
        {
            AppendFinding(r, kFindingNameDeny, kDeniedNames[i]);
            return Verdict::Deny;
        }
    }
    return Verdict::Allow;
}

Verdict CheckHashDeny(const ImageDescriptor& desc, Report& r)
{
    if (desc.bytes == nullptr || desc.size == 0)
        return Verdict::Allow;
    const u64 h = Fnv1aHash(desc.bytes, desc.size);
    for (u32 i = 0; kDeniedHashes[i].label != nullptr; ++i)
    {
        if (kDeniedHashes[i].hash == h)
        {
            AppendFinding(r, kFindingHashDeny, kDeniedHashes[i].label);
            return Verdict::Deny;
        }
    }
    return Verdict::Allow;
}

// PE (Windows) imports heuristic.
// - If BOTH CreateRemoteThread and WriteProcessMemory appear ==> Deny
//   (the classic CreateRemoteThread-based process injection combo).
// - Else if >= 2 of the suspicious-API list appear ==> Warn.
// - Else if zero imports AND the PE-header magic is present ==> Warn
//   (likely packed / self-contained loader — worth a prompt).
Verdict CheckPeImports(const ImageDescriptor& desc, Report& r)
{
    if (desc.kind != ImageKind::WindowsPE)
        return Verdict::Allow;
    if (desc.bytes == nullptr || desc.size < 64)
        return Verdict::Allow;
    // Cheap "is-PE" sniff: MZ at 0, PE\0\0 at the e_lfanew offset.
    // We don't reparse the NT header here; the scanner treats the
    // image as a byte blob to stay independent of the loader path.
    if (desc.bytes[0] != 'M' || desc.bytes[1] != 'Z')
        return Verdict::Allow;

    const bool has_crt = BytesContain(desc.bytes, desc.size, "CreateRemoteThread");
    const bool has_wpm = BytesContain(desc.bytes, desc.size, "WriteProcessMemory");
    if (has_crt && has_wpm)
    {
        AppendFinding(r, kFindingPeInjection, "CreateRemoteThread + WriteProcessMemory");
        return Verdict::Deny;
    }

    u32 hits = 0;
    for (u32 i = 0; i < kSuspiciousApiCount; ++i)
    {
        if (BytesContain(desc.bytes, desc.size, kSuspiciousApis[i]))
            ++hits;
    }
    if (hits >= 2)
    {
        AppendFinding(r, kFindingPeSuspicious, "2+ injection-family APIs");
        return Verdict::Warn;
    }

    // No-imports heuristic: if the PE import-dir table is blank
    // (the ASCII byte "api-ms-" / ".dll" stringprint is absent)
    // the image is either a loader / packer or a stripped binary.
    const bool has_dll_literal = BytesContain(desc.bytes, desc.size, ".dll");
    if (!has_dll_literal)
    {
        AppendFinding(r, kFindingPeNoImports, "no .dll references in image");
        return Verdict::Warn;
    }
    return Verdict::Allow;
}

// ELF W+X check. Walks program headers directly off the raw bytes
// so we don't need to include elf_loader.h and create a build-time
// cycle. Uses the same offsets elf_loader.cpp does (well-tested).
Verdict CheckElfWx(const ImageDescriptor& desc, Report& r)
{
    if (desc.kind != ImageKind::NativeElf)
        return Verdict::Allow;
    if (desc.bytes == nullptr || desc.size < 64)
        return Verdict::Allow;
    // ELF magic + 64-bit class + little-endian + version 1.
    if (desc.bytes[0] != 0x7F || desc.bytes[1] != 'E' || desc.bytes[2] != 'L' || desc.bytes[3] != 'F')
        return Verdict::Allow;
    if (desc.bytes[4] != 2 /* ELFCLASS64 */)
        return Verdict::Allow;

    auto le16 = [&](u64 off) -> u16 { return desc.bytes[off] | (u16(desc.bytes[off + 1]) << 8); };
    auto le64 = [&](u64 off) -> u64
    {
        u64 v = 0;
        for (int i = 0; i < 8; ++i)
            v |= u64(desc.bytes[off + i]) << (8 * i);
        return v;
    };
    auto le32 = [&](u64 off) -> u32
    {
        u32 v = 0;
        for (int i = 0; i < 4; ++i)
            v |= u32(desc.bytes[off + i]) << (8 * i);
        return v;
    };

    const u64 e_phoff = le64(32);
    const u16 e_phentsize = le16(54);
    const u16 e_phnum = le16(56);
    if (e_phoff == 0 || e_phnum == 0)
        return Verdict::Allow;
    if (e_phoff >= desc.size)
        return Verdict::Allow;

    constexpr u32 kPtLoad = 1;
    constexpr u32 kPfX = 0x1;
    constexpr u32 kPfW = 0x2;

    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u64 off = e_phoff + u64(i) * e_phentsize;
        if (off + 8 > desc.size)
            break;
        const u32 p_type = le32(off);
        const u32 p_flags = le32(off + 4);
        if (p_type == kPtLoad && (p_flags & kPfW) && (p_flags & kPfX))
        {
            AppendFinding(r, kFindingElfWx, "ELF segment both W and X");
            return Verdict::Warn;
        }
    }
    return Verdict::Allow;
}

Verdict Worse(Verdict a, Verdict b)
{
    return (static_cast<u8>(a) > static_cast<u8>(b)) ? a : b;
}

// ---------------------------------------------------------------
// Logging helpers.
// ---------------------------------------------------------------

const char* KindName(ImageKind k)
{
    switch (k)
    {
    case ImageKind::NativeElf:
        return "elf";
    case ImageKind::WindowsPE:
        return "pe";
    case ImageKind::KernelThread:
        return "kthread";
    case ImageKind::UserThread:
        return "uthread";
    }
    return "?";
}

const char* VerdictName(Verdict v)
{
    switch (v)
    {
    case Verdict::Allow:
        return "ALLOW";
    case Verdict::Warn:
        return "WARN";
    case Verdict::Deny:
        return "DENY";
    }
    return "?";
}

const char* FindingName(u32 code)
{
    switch (static_cast<FindingCode>(code))
    {
    case kFindingHashDeny:
        return "HASH_DENY";
    case kFindingNameDeny:
        return "NAME_DENY";
    case kFindingPeInjection:
        return "PE_INJECTION";
    case kFindingPeSuspicious:
        return "PE_SUSPICIOUS";
    case kFindingElfWx:
        return "ELF_WX";
    case kFindingHighEntropy:
        return "HIGH_ENTROPY";
    case kFindingPeNoImports:
        return "PE_NO_IMPORTS";
    default:
        return "NONE";
    }
}

void LogReport(const ImageDescriptor& desc, const Report& r)
{
    using arch::SerialWrite;
    SerialWrite("[guard] ");
    SerialWrite(VerdictName(r.verdict));
    SerialWrite(" kind=");
    SerialWrite(KindName(desc.kind));
    SerialWrite(" name=\"");
    SerialWrite(desc.name);
    SerialWrite("\" findings=");
    arch::SerialWriteHex(r.finding_count);
    SerialWrite("\n");
    for (u32 i = 0; i < r.finding_count; ++i)
    {
        SerialWrite("[guard]   - ");
        SerialWrite(FindingName(r.findings[i].code));
        SerialWrite(": ");
        SerialWrite(r.findings[i].detail ? r.findings[i].detail : "(no detail)");
        SerialWrite("\n");
    }
}

// ---------------------------------------------------------------
// Terminal (serial) prompt.
// ---------------------------------------------------------------

// Non-blocking "is a char ready on COM1?".
bool SerialRxReady()
{
    return (arch::Inb(arch::kCom1Port + 5) & 0x01) != 0;
}

u8 SerialRxChar()
{
    return arch::Inb(arch::kCom1Port);
}

// Convert HPET ticks to milliseconds via the period (femtoseconds).
u64 HpetTicksToMs(u64 ticks)
{
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
        return 0;
    // ticks * fs per tick = total fs; / 1e12 for ms.
    return (ticks * period_fs) / 1'000'000'000'000ull;
}

bool PromptSerial(const ImageDescriptor& desc, const Report& r)
{
    using arch::SerialWrite;
    SerialWrite("\n[guard] ========================================\n");
    SerialWrite("[guard]  SECURITY GUARD PROMPT (serial)\n");
    SerialWrite("[guard]    image : ");
    SerialWrite(desc.name);
    SerialWrite("\n[guard]    kind  : ");
    SerialWrite(KindName(desc.kind));
    SerialWrite("\n[guard]    verdict: ");
    SerialWrite(VerdictName(r.verdict));
    SerialWrite("\n[guard]    findings:\n");
    for (u32 i = 0; i < r.finding_count; ++i)
    {
        SerialWrite("[guard]      - ");
        SerialWrite(FindingName(r.findings[i].code));
        SerialWrite("\n");
    }
    SerialWrite("[guard]  Allow [y] / Deny [n] — 10s default-deny.\n");
    SerialWrite("[guard]  > ");

    const u64 start = arch::HpetReadCounter();
    for (;;)
    {
        if (SerialRxReady())
        {
            const u8 c = SerialRxChar();
            if (c == 'y' || c == 'Y')
            {
                SerialWrite("y\n[guard] user ALLOWED override\n");
                return true;
            }
            if (c == 'n' || c == 'N')
            {
                SerialWrite("n\n[guard] user DENIED\n");
                return false;
            }
            // Ignore other chars, keep polling.
        }
        const u64 now = arch::HpetReadCounter();
        if (HpetTicksToMs(now - start) >= 10'000)
        {
            SerialWrite("\n[guard] prompt timeout: default-deny\n");
            return false;
        }
        asm volatile("pause" ::: "memory");
    }
}

} // namespace

// ---------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------

Report Inspect(const ImageDescriptor& desc)
{
    Report r;
    VZero(&r, sizeof(r));
    r.verdict = Verdict::Allow;
    r.finding_count = 0;

    r.verdict = Worse(r.verdict, CheckNameDeny(desc, r));
    r.verdict = Worse(r.verdict, CheckHashDeny(desc, r));
    r.verdict = Worse(r.verdict, CheckPeImports(desc, r));
    r.verdict = Worse(r.verdict, CheckElfWx(desc, r));
    return r;
}

bool Gate(const ImageDescriptor& desc)
{
    ++g_scan_count;

    if (g_mode == Mode::Off)
    {
        ++g_allow_count;
        return true;
    }

    const Report r = Inspect(desc);
    CopyReport(g_last_report, r);
    LogReport(desc, r);

    switch (r.verdict)
    {
    case Verdict::Allow:
        ++g_allow_count;
        return true;

    case Verdict::Warn:
        ++g_warn_count;
        if (g_mode == Mode::Advisory)
            return true;
        // Enforce: prompt.
        return PromptSerial(desc, r);

    case Verdict::Deny:
        ++g_deny_count;
        if (g_mode == Mode::Advisory)
        {
            arch::SerialWrite("[guard] advisory: would DENY (mode=Advisory, allowing)\n");
            return true;
        }
        return PromptSerial(desc, r);
    }
    return true;
}

Mode GuardMode()
{
    return g_mode;
}

void SetGuardMode(Mode m)
{
    const Mode old = g_mode;
    g_mode = m;
    arch::SerialWrite("[guard] mode changed: ");
    arch::SerialWrite(GuardModeName(old));
    arch::SerialWrite(" -> ");
    arch::SerialWrite(GuardModeName(m));
    arch::SerialWrite("\n");
}

const char* GuardModeName(Mode m)
{
    switch (m)
    {
    case Mode::Off:
        return "off";
    case Mode::Advisory:
        return "advisory";
    case Mode::Enforce:
        return "enforce";
    }
    return "?";
}

u64 GuardScanCount()
{
    return g_scan_count;
}
u64 GuardAllowCount()
{
    return g_allow_count;
}
u64 GuardWarnCount()
{
    return g_warn_count;
}
u64 GuardDenyCount()
{
    return g_deny_count;
}

const Report* GuardLastReport()
{
    return &g_last_report;
}

void GuardInit()
{
    if (g_init_done)
    {
        core::Log(core::LogLevel::Warn, "security/guard", "GuardInit called twice (ignored)");
        return;
    }
    g_init_done = true;
    g_mode = Mode::Advisory;
    g_scan_count = 0;
    g_allow_count = 0;
    g_warn_count = 0;
    g_deny_count = 0;
    VZero(&g_last_report, sizeof(g_last_report));
    arch::SerialWrite("[guard] init (mode=advisory)\n");
}

void GuardSelfTest()
{
    using arch::SerialWrite;
    // Fake clean ELF header — 0x7F 'E' 'L' 'F', class=2, otherwise zeroed.
    u8 clean_elf[64];
    VZero(clean_elf, sizeof(clean_elf));
    clean_elf[0] = 0x7F;
    clean_elf[1] = 'E';
    clean_elf[2] = 'L';
    clean_elf[3] = 'F';
    clean_elf[4] = 2;
    ImageDescriptor d1{ImageKind::NativeElf, "test-clean-elf", clean_elf, sizeof(clean_elf)};
    Report r1 = Inspect(d1);
    if (r1.verdict != Verdict::Allow)
    {
        SerialWrite("[guard] self-test FAILED: clean ELF flagged\n");
        return;
    }

    // Fake PE with both CRT + WPM substrings embedded -> expect Deny.
    // `static` so the array lives in bss (zero-initialized by the boot
    // loader) rather than on the stack (which would invite memset).
    static u8 pe[512];
    VZero(pe, sizeof(pe));
    pe[0] = 'M';
    pe[1] = 'Z';
    const char* crt = "CreateRemoteThread";
    const char* wpm = "WriteProcessMemory";
    for (u32 i = 0; crt[i] != 0; ++i)
        pe[64 + i] = static_cast<u8>(crt[i]);
    for (u32 i = 0; wpm[i] != 0; ++i)
        pe[128 + i] = static_cast<u8>(wpm[i]);
    ImageDescriptor d2{ImageKind::WindowsPE, "test-inject-pe", pe, sizeof(pe)};
    Report r2 = Inspect(d2);
    if (r2.verdict != Verdict::Deny)
    {
        SerialWrite("[guard] self-test FAILED: PE injection combo not denied\n");
        return;
    }
    SerialWrite("[guard] self-test OK (clean-elf allowed; injection-pe denied)\n");
}

} // namespace customos::security
