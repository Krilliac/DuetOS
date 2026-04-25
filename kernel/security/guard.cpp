/*
 * DuetOS — security guard: implementation.
 *
 * Companion to guard.h — see there for the guard mode enum
 * (Off / Audit / Enforce), the policy update API, and the
 * subsystem hooks (image-load gate, sensitive-LBA write
 * gate).
 *
 * WHAT
 *   Centralised security policy point. Every PE / ELF load
 *   passes through `GuardCheckImageLoad`; every block-layer
 *   write to a "sensitive" LBA range (boot sector, GPT, NVMe
 *   IDENTIFY mirror) passes through `GuardCheckBlockWrite`.
 *   Each gate either allows, audit-logs, or denies based on
 *   the current mode + the AttackSim escalation state.
 *
 * HOW
 *   Mode is a single atomic enum, mutable from the shell
 *   `guard` command. AttackSim runs flip the mode to Enforce
 *   (image guard) and Deny (block-write guard) so subsequent
 *   adversarial probes hit the same denial path real attacks
 *   would.
 *
 *   Sensitive-LBA table is built at boot from the GPT parser
 *   + a hand-coded list of NVMe/AHCI metadata regions.
 */

#include "guard.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/types.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/video/framebuffer.h"
#include "../fs/tmpfs.h"

namespace duetos::security
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

// Persistent allow-list, keyed by FNV-1a image hash. A hash that
// landed here during a previous boot (because the user answered
// "yes" at a prompt) short-circuits Inspect -> Allow. Capacity is
// static so the allowlist survives the life of the kernel without
// depending on kmalloc.
constexpr u32 kMaxAllowed = 256;
constinit u64 g_allowed_hashes[kMaxAllowed] = {};
constinit u32 g_allowed_count = 0;

// Path the persistent allowlist lives at inside tmpfs. Flat-name
// space, no subdirectories (matches existing tmpfs conventions).
constexpr const char* kAllowlistPath = "guard-allowed";

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
[[maybe_unused]] void VCopy(void* dst, const void* src, u64 n)
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

// ---------------------------------------------------------------
// Persistent allowlist (tmpfs-backed).
// ---------------------------------------------------------------

bool IsHashAllowed(u64 h)
{
    for (u32 i = 0; i < g_allowed_count; ++i)
    {
        if (g_allowed_hashes[i] == h)
            return true;
    }
    return false;
}

void AppendAllowedHash(u64 h)
{
    if (g_allowed_count >= kMaxAllowed)
    {
        arch::SerialWrite("[guard] allowlist full (256 entries); dropping new entry\n");
        return;
    }
    g_allowed_hashes[g_allowed_count++] = h;
}

// Parse a 16-char hex byte into a u64 nibble count; accepts lower
// or upper hex. Returns -1 on any non-hex character.
i32 HexNibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// One line of the allowlist file: 16 hex chars + '\n'. Returns
// the parsed hash in `*out`. False on malformed line.
bool ParseHashLine(const char* line, u64 len, u64* out)
{
    if (len < 16)
        return false;
    u64 h = 0;
    for (u32 i = 0; i < 16; ++i)
    {
        const i32 n = HexNibble(line[i]);
        if (n < 0)
            return false;
        h = (h << 4) | static_cast<u64>(n);
    }
    *out = h;
    return true;
}

void LoadAllowlist()
{
    const char* bytes = nullptr;
    u32 len = 0;
    if (!duetos::fs::TmpFsRead(kAllowlistPath, &bytes, &len))
    {
        arch::SerialWrite("[guard] no persistent allowlist (first boot or cleared)\n");
        return;
    }
    u32 i = 0;
    while (i < len)
    {
        // Find end of line.
        u32 j = i;
        while (j < len && bytes[j] != '\n')
            ++j;
        u64 h = 0;
        if (ParseHashLine(bytes + i, j - i, &h))
        {
            AppendAllowedHash(h);
        }
        i = j + 1;
    }
    arch::SerialWrite("[guard] loaded allowlist: ");
    arch::SerialWriteHex(g_allowed_count);
    arch::SerialWrite(" entries\n");
}

void SaveAllowlist()
{
    // Render the whole list back out. 16 hex chars + '\n' per
    // entry = 17 bytes; cap at kMaxAllowed so the buffer is
    // bounded. tmpfs writes are cheap; we rewrite the whole file
    // rather than tracking diffs.
    static char buf[kMaxAllowed * 17 + 1];
    u32 w = 0;
    for (u32 i = 0; i < g_allowed_count; ++i)
    {
        const u64 h = g_allowed_hashes[i];
        for (u32 k = 0; k < 16; ++k)
        {
            const u32 shift = (15 - k) * 4;
            const u8 nib = static_cast<u8>((h >> shift) & 0xF);
            buf[w++] = static_cast<char>(nib < 10 ? '0' + nib : 'a' + nib - 10);
        }
        buf[w++] = '\n';
    }
    duetos::fs::TmpFsTouch(kAllowlistPath);
    duetos::fs::TmpFsWrite(kAllowlistPath, buf, w);
}

// ---------------------------------------------------------------
// GUI modal. Draws a centered dialog on the framebuffer. Poll
// loop unified with the serial reader so the user can answer
// from either channel.
// ---------------------------------------------------------------

void DrawModal(const ImageDescriptor& desc, const Report& r)
{
    if (!duetos::drivers::video::FramebufferAvailable())
        return;
    const auto info = duetos::drivers::video::FramebufferGet();
    namespace fb = duetos::drivers::video;

    // Modal dimensions: 600x240, centred. 8x8 font so a 70-char
    // line fits in ~560 px. Colours: RED border, dark grey body,
    // white text. Matches the kernel's existing console palette
    // so users read it as "this is a system dialog", not "this
    // is an app".
    constexpr u32 kBorderRgb = 0xCC2222;
    constexpr u32 kBodyRgb = 0x101418;
    constexpr u32 kTextRgb = 0xEEEEEE;
    constexpr u32 kHeaderRgb = 0xFFCC00;

    const u32 mw = 600, mh = 240;
    const u32 mx = (info.width > mw) ? (info.width - mw) / 2 : 0;
    const u32 my = (info.height > mh) ? (info.height - mh) / 2 : 0;

    fb::FramebufferFillRect(mx, my, mw, mh, kBodyRgb);
    fb::FramebufferDrawRect(mx, my, mw, mh, kBorderRgb, 3);

    fb::FramebufferDrawString(mx + 16, my + 12, "!! SECURITY GUARD PROMPT !!", kHeaderRgb, kBodyRgb);
    fb::FramebufferDrawString(mx + 16, my + 40, "image  :", kTextRgb, kBodyRgb);
    fb::FramebufferDrawString(mx + 96, my + 40, desc.name, kTextRgb, kBodyRgb);
    fb::FramebufferDrawString(mx + 16, my + 56, "kind   :", kTextRgb, kBodyRgb);
    fb::FramebufferDrawString(mx + 96, my + 56, KindName(desc.kind), kTextRgb, kBodyRgb);
    fb::FramebufferDrawString(mx + 16, my + 72, "verdict:", kTextRgb, kBodyRgb);
    fb::FramebufferDrawString(mx + 96, my + 72, VerdictName(r.verdict), kBorderRgb, kBodyRgb);

    u32 line_y = my + 100;
    fb::FramebufferDrawString(mx + 16, line_y, "findings:", kTextRgb, kBodyRgb);
    for (u32 i = 0; i < r.finding_count && i < 4; ++i)
    {
        line_y += 16;
        fb::FramebufferDrawString(mx + 32, line_y, FindingName(r.findings[i].code), kTextRgb, kBodyRgb);
    }

    fb::FramebufferDrawString(mx + 16, my + mh - 40, "Allow [y]   Deny [n]   (10s default-deny)", kHeaderRgb, kBodyRgb);
}

void DrawModalDecision(const char* what, u32 rgb)
{
    if (!duetos::drivers::video::FramebufferAvailable())
        return;
    const auto info = duetos::drivers::video::FramebufferGet();
    namespace fb = duetos::drivers::video;
    const u32 mw = 600, mh = 240;
    const u32 mx = (info.width > mw) ? (info.width - mw) / 2 : 0;
    const u32 my = (info.height > mh) ? (info.height - mh) / 2 : 0;
    fb::FramebufferDrawString(mx + 16, my + mh - 20, what, rgb, 0x101418);
}

bool PromptUser(const ImageDescriptor& desc, const Report& r)
{
    // Unified prompt: draws the modal dialog (if framebuffer is
    // live) AND emits the serial text. Answer accepted from
    // whichever channel responds first. 10s default-deny.
    using arch::SerialWrite;
    SerialWrite("\n[guard] ========================================\n");
    SerialWrite("[guard]  SECURITY GUARD PROMPT\n");
    SerialWrite("[guard]    image  : ");
    SerialWrite(desc.name);
    SerialWrite("\n[guard]    kind   : ");
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
    SerialWrite("[guard]  Allow [y] / Deny [n] — 10s default-deny. > ");

    DrawModal(desc, r);

    const u64 start = arch::HpetReadCounter();
    for (;;)
    {
        if (SerialRxReady())
        {
            const u8 c = SerialRxChar();
            if (c == 'y' || c == 'Y')
            {
                SerialWrite("y (serial)\n[guard] user ALLOWED override\n");
                DrawModalDecision("*** ALLOWED BY USER ***", 0x66EE66);
                return true;
            }
            if (c == 'n' || c == 'N')
            {
                SerialWrite("n (serial)\n[guard] user DENIED\n");
                DrawModalDecision("*** DENIED BY USER ***", 0xEE6666);
                return false;
            }
        }
        const char k = duetos::drivers::input::Ps2KeyboardTryReadChar();
        if (k == 'y' || k == 'Y')
        {
            SerialWrite("y (keyboard)\n[guard] user ALLOWED override\n");
            DrawModalDecision("*** ALLOWED BY USER ***", 0x66EE66);
            return true;
        }
        if (k == 'n' || k == 'N')
        {
            SerialWrite("n (keyboard)\n[guard] user DENIED\n");
            DrawModalDecision("*** DENIED BY USER ***", 0xEE6666);
            return false;
        }
        const u64 now = arch::HpetReadCounter();
        if (HpetTicksToMs(now - start) >= 10'000)
        {
            SerialWrite("\n[guard] prompt timeout: default-deny\n");
            DrawModalDecision("*** TIMEOUT: DEFAULT-DENY ***", 0xEE6666);
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

    // Persistent-allowlist short-circuit. A hash the user previously
    // said "yes" to skips heuristics entirely. Saves the prompt on
    // every subsequent boot for apps the user has already vouched for.
    if (desc.bytes != nullptr && desc.size > 0)
    {
        const u64 h = Fnv1aHash(desc.bytes, desc.size);
        if (IsHashAllowed(h))
        {
            ++g_allow_count;
            arch::SerialWrite("[guard] allowlist hit (pre-approved): ");
            arch::SerialWrite(desc.name);
            arch::SerialWrite("\n");
            return true;
        }
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
        // Enforce: prompt, and remember on allow.
        {
            const bool allowed = PromptUser(desc, r);
            if (allowed && desc.bytes != nullptr && desc.size > 0)
            {
                GuardRememberAllow(Fnv1aHash(desc.bytes, desc.size));
            }
            return allowed;
        }

    case Verdict::Deny:
        ++g_deny_count;
        if (g_mode == Mode::Advisory)
        {
            arch::SerialWrite("[guard] advisory: would DENY (mode=Advisory, allowing)\n");
            return true;
        }
        {
            const bool allowed = PromptUser(desc, r);
            if (allowed && desc.bytes != nullptr && desc.size > 0)
            {
                GuardRememberAllow(Fnv1aHash(desc.bytes, desc.size));
            }
            return allowed;
        }
    }
    return true;
}

bool GateThread(ImageKind kind, const char* name)
{
    // Kernel-internal threads (idle-bsp, reaper, smp-apN, future
    // kworkers) are spawned by code we trust as axiomatically as
    // the rest of the kernel. They have no image bytes to inspect
    // and no attacker-controlled provenance — gating them serves
    // no defensive purpose but CAN brick the boot if an operator
    // misconfigures NAME_DENY (e.g. adds "reaper" by mistake,
    // kernel then refuses to spawn its own reaper thread).
    //
    // Give kernel threads an unconditional pass. User threads
    // (spawned by PE/ELF loaders for ring-3 tasks) still run
    // through Inspect's name-deny path — that's the only thread
    // class with attacker-controlled name input.
    if (kind == ImageKind::KernelThread)
    {
        return true;
    }
    ImageDescriptor d{kind, name != nullptr ? name : "(thread)", nullptr, 0};
    return Gate(d);
}

void GuardLoadAllowlist()
{
    LoadAllowlist();
}

void GuardRememberAllow(u64 hash)
{
    if (IsHashAllowed(hash))
        return;
    AppendAllowedHash(hash);
    SaveAllowlist();
    arch::SerialWrite("[guard] allow-remembered: hash added to persistent allowlist\n");
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
    g_allowed_count = 0;
    arch::SerialWrite("[guard] init (mode=advisory)\n");
    LoadAllowlist();
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

} // namespace duetos::security
