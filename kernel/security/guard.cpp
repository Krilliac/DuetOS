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

#include "security/guard.h"

#include "arch/x86_64/cpu.h"
#include "security/event_ring.h"
#include "security/exception_id.h"
#include "security/ir_runbook.h"
#include "core/boot_cmdline.h"
#include "debug/probes.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "time/tick.h"
#include "crypto/sha256.h"
#include "log/klog.h"
#include "util/string.h"
#include "util/types.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "fs/fat32.h"
#include "fs/tmpfs.h"

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

// True while `PromptUser` is blocked on a user decision. Read by
// `GuardPromptActive()` (public). The desktop compositor short-
// circuits while this is set so the prompt's directly-painted
// pixels (the guard modal does NOT use the compose shadow surface
// — it runs synchronously on the kboot/loader thread, not on the
// ui-ticker that owns BeginCompose/EndCompose) are not clobbered
// by an in-flight `DesktopCompose` shadow->live diff blit. Without
// this, ui-ticker-driven redraws race the prompt and the user sees
// terminal / desktop content bleeding through the modal panel.
//
// Single-writer (PromptUser entry/exit RAII guard), many-reader
// (DesktopCompose check). Plain bool is safe: x86 byte stores are
// atomic, the readers tolerate a one-frame stale read either way
// (a frame painted just before the flag is set is fine — the
// prompt's next iteration repaints over it; a frame skipped just
// after the flag is cleared is fine — the next compose paints
// normally).
constinit bool g_prompt_active = false;

// Operator exception list, keyed by SHA-256 image digest. A digest
// that landed here — because the user answered "always" at a
// prompt, or because the operator seeded it on the boot cmdline —
// short-circuits Inspect -> Allow.
//
// Scoped to the digest, never the path: `/UNITYPLA.DLL` is a label
// an attacker can reuse by dropping a different file at that path,
// whereas the digest names the exact bytes the operator saw. See
// `security/exception_id.h` and wiki/security/Security-Exceptions.md.
//
// Capacity is static so the list works without kmalloc.
// 256 entries * 32 bytes = 8 KiB BSS.
constexpr u32 kMaxAllowed = 256;
constinit u8 g_allowed_hashes[kMaxAllowed][32] = {};
constinit u32 g_allowed_count = 0;

// True once a cmdline-seeded exception is in force. `guard status`
// and the boot log surface this so an operator can never mistake a
// pre-authorised boot for a clean one.
constinit u32 g_cmdline_seeded = 0;

// In-memory backing store: RamVol, not the legacy flat tmpfs tier.
//
// tmpfs slots cap at kTmpFsContentMax (512 bytes) — seven 65-byte
// digest lines — while this table holds 256. The previous code
// handed `TmpFsWrite` a 16 KiB buffer and let it truncate, which
// silently dropped every entry past the seventh AND cut the last
// surviving line mid-digest, so the reload skipped it too. RamVol
// is the project's designated un-capped writable RAM tier (see the
// RamVol block in `fs/tmpfs.h`, which says in as many words that
// the legacy cap can never grow and RamVol is the path instead),
// it is quota'd, and `RamVolInit` runs long before `GuardInit`.
//
// Cross-reboot persistence: `GUARD.DAT` on the DuetOS-owned FAT32
// volume (see `SaveDiskExceptions` / `LoadDiskExceptions` below).
// The disk file is loaded by `GuardLoadDiskExceptions()` after FAT32
// is probed, and updated on every `GuardRememberAllow` /
// `GuardForgetException`.
constexpr const char* kAllowlistPath = "/run/guard-allowed";

// On-disk exception file. Simple flat format: raw 32-byte SHA-256
// digests concatenated. No header, no padding — the file size is
// always a multiple of 32. Stored on the first DuetOS-owned FAT32
// volume (kDuetOsVolumeId + "DUETOS" label).
constexpr const char* kDiskAllowlistFile = "GUARD.DAT";

// True once the on-disk file has been loaded. Prevents a second
// load from doubling every entry.
constinit bool g_disk_loaded = false;

// Boot cmdline token that pre-authorises images without a human at
// the console. Repeatable, and each occurrence takes a comma-
// separated list of 64-char hex SHA-256 digests:
//
//   guard-allow=<hex64>[,<hex64>...]
//
// Deliberately NOT a blanket "allow everything" switch: every
// digest names one exact image, unknown images still hit the
// normal heuristics, and a Warn image with no matching digest is
// still default-denied on prompt timeout.
constexpr const char* kCmdlineAllowKey = "guard-allow";

// Prompt deadline, in scheduler ticks. Ten seconds at kTickHz is the
// operator-facing value and the only value production ever uses.
//
// It is a variable rather than a constant purely so `GuardSelfTest`
// can prove the timeout leg without adding ten seconds to every
// boot: the self-test drops it, exercises the real default-deny
// path, and restores it. File-static with no setter, so nothing
// outside this TU — and in particular no guest — can shorten the
// window an operator gets to answer.
constexpr u64 kPromptTimeoutSecs = 10;
constinit u64 g_prompt_timeout_ticks = 0; // 0 => use kPromptTimeoutSecs

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

// SHA-256 hash denylist. Each entry pairs a 32-byte digest with
// a human-readable label rendered to the boot log when the hash
// matches. Seed table starts empty — add entries when an actual
// incident gives us a fingerprint to block. The denylist is
// matched after the cheap name-deny pass and before the
// heuristic checks, so a known-bad hash short-circuits the
// rest of Inspect.
struct HashEntry
{
    u8 hash[32];
    const char* label;
};
constexpr HashEntry kDeniedHashes[] = {
    // (empty seed — sentinel marks end of list)
    {{0}, nullptr},
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

using duetos::core::StrEqual;
using duetos::core::StrLen;

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

// SHA-256 over the whole image. Deterministic, collision-
// resistant, and shares the same hash primitive as the WPA
// stack and the rest of the kernel — one cryptographic hash
// implementation. The caller passes a 32-byte output buffer;
// we zero it on len==0 so an empty image still hashes to a
// well-defined sentinel rather than reading stale stack bytes.
void HashImage(const u8* data, u64 len, u8 out[32])
{
    if (len > 0 && len > 0xFFFFFFFFull)
    {
        // Sha256Update takes u32 length; clamp absurdly-large
        // sizes by hashing the prefix only. Real images never
        // come anywhere near 4 GiB so this is purely defensive.
        len = 0xFFFFFFFFull;
    }
    crypto::Sha256Hash(data != nullptr ? data : reinterpret_cast<const u8*>(""), static_cast<u32>(len), out);
}

// Digest compare lives in exception_id.h so the hosted tests cover
// the same code the kernel runs. Not constant-time, and it does not
// need to be — see the header for why an allowlist has no secret to
// leak.
using duetos::security::DigestEqual;

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
        if (StrEqual(desc.name, kDeniedNames[i]))
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
    u8 h[32];
    HashImage(desc.bytes, desc.size, h);
    for (u32 i = 0; kDeniedHashes[i].label != nullptr; ++i)
    {
        if (DigestEqual(kDeniedHashes[i].hash, h))
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
    default:
        return "?";
    }
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
    default:
        return "?";
    }
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

// HpetTicksToMs lived here until the VBox/HPET-absent compat fix
// moved the guard-prompt timeout off HPET onto TimerTicks. The
// commented-out reference in the call site (search "HpetTicksToMs")
// documents why HPET was abandoned for this path; the function
// itself is dead.

// ---------------------------------------------------------------
// Operator exception list (RamVol-backed; see kAllowlistPath).
// ---------------------------------------------------------------

bool IsHashAllowed(const u8 h[32])
{
    for (u32 i = 0; i < g_allowed_count; ++i)
    {
        if (DigestEqual(g_allowed_hashes[i], h))
            return true;
    }
    return false;
}

void AppendAllowedHash(const u8 h[32])
{
    if (g_allowed_count >= kMaxAllowed)
    {
        // Code-image allowlist saturated — subsequent additions are
        // dropped, which means newly-baked binaries won't load
        // until something is removed. Route through klog (once)
        // so the saturation appears in dmesg + the panic dump
        // replay, not just the boot-only serial line.
        KLOG_ONCE_WARN_V("security/guard", "allowlist full — dropping new entry (cap)", kMaxAllowed);
        return;
    }
    for (u32 i = 0; i < 32; ++i)
        g_allowed_hashes[g_allowed_count][i] = h[i];
    ++g_allowed_count;
}

// ---------------------------------------------------------------
// On-disk persistence (DuetOS-owned FAT32 volume).
//
// File format: raw concatenated 32-byte SHA-256 digests, no header.
// File size is always a multiple of 32. This is the simplest
// format that round-trips without parsing overhead — the hex-text
// form in RamVol is human-readable but costs 2x the bytes and
// needs line-by-line parsing; on disk the binary form is better
// because GUARD.DAT is not meant to be hand-edited (operators use
// the shell `guard except` surface or the interactive prompt).
// ---------------------------------------------------------------

/// Find the first DuetOS-owned FAT32 volume, or nullptr if none
/// has been probed yet. The search runs every time rather than
/// caching, because the volume index can shift if a volume is
/// forgotten (e.g. after the ownership self-test's RAM disk is
/// retracted).
const fs::fat32::Volume* FindDuetOsVolume()
{
    for (u32 i = 0; i < fs::fat32::Fat32VolumeCount(); ++i)
    {
        const auto* v = fs::fat32::Fat32Volume(i);
        if (fs::fat32::Fat32VolumeIsDuetOsOwned(v))
            return v;
    }
    return nullptr;
}

/// Load exceptions from GUARD.DAT on the DuetOS-owned FAT32 volume.
/// Merges into the in-memory table without duplicating entries that
/// the RamVol or cmdline path already installed.
void LoadDiskExceptions()
{
    const auto* vol = FindDuetOsVolume();
    if (vol == nullptr)
    {
        arch::SerialWrite("[guard] no DuetOS-owned FAT32 volume — disk exceptions not loaded\n");
        return;
    }
    fs::fat32::DirEntry entry;
    if (!fs::fat32::Fat32LookupPath(vol, kDiskAllowlistFile, &entry))
    {
        arch::SerialWrite("[guard] GUARD.DAT not found on DuetOS volume — no disk exceptions\n");
        return;
    }
    if (entry.size_bytes == 0)
    {
        arch::SerialWrite("[guard] GUARD.DAT is empty — no disk exceptions\n");
        return;
    }
    // Validate file size is a multiple of 32.
    if (entry.size_bytes % kImageDigestBytes != 0)
    {
        KLOG_WARN_V("security/guard", "GUARD.DAT size not a multiple of 32 — skipping disk load", entry.size_bytes);
        return;
    }
    const u32 count = entry.size_bytes / kImageDigestBytes;
    if (count > kMaxAllowed)
    {
        KLOG_WARN_V("security/guard", "GUARD.DAT has more entries than kMaxAllowed — capping", count);
    }
    // Read the file. Cap at the table capacity.
    const u32 to_read = (count > kMaxAllowed) ? kMaxAllowed : count;
    static u8 disk_buf[kMaxAllowed * kImageDigestBytes];
    const i64 got = fs::fat32::Fat32ReadFile(vol, &entry, disk_buf, to_read * kImageDigestBytes);
    if (got < 0 || static_cast<u64>(got) < to_read * kImageDigestBytes)
    {
        KLOG_WARN("security/guard", "GUARD.DAT read failed or short — disk exceptions not loaded");
        return;
    }
    u32 loaded = 0;
    for (u32 i = 0; i < to_read; ++i)
    {
        const u8* h = disk_buf + i * kImageDigestBytes;
        if (!IsHashAllowed(h))
        {
            AppendAllowedHash(h);
            ++loaded;
        }
    }
    arch::SerialWrite("[guard] loaded ");
    arch::SerialWriteHex(loaded);
    arch::SerialWrite(" disk exceptions from GUARD.DAT (");
    arch::SerialWriteHex(to_read);
    arch::SerialWrite(" on disk, ");
    arch::SerialWriteHex(to_read - loaded);
    arch::SerialWrite(" already known)\n");
}

/// Persist the full in-memory exception list to GUARD.DAT on the
/// DuetOS-owned FAT32 volume. Overwrites the file atomically (delete
/// + create) so a shorter list doesn't leave stale entries. No-op
/// if no DuetOS volume exists — the RamVol copy is still the live
/// authority for the current boot.
void SaveDiskExceptions()
{
    const auto* vol = FindDuetOsVolume();
    if (vol == nullptr)
        return; // no volume — can't persist; RamVol is the fallback
    if (g_allowed_count == 0)
    {
        // Empty list: delete the file if it exists so a reboot doesn't
        // reload stale entries.
        (void)fs::fat32::Fat32DeleteInRoot(vol, kDiskAllowlistFile);
        return;
    }
    // Build the binary blob: kImageDigestBytes per entry.
    static u8 disk_buf[kMaxAllowed * kImageDigestBytes];
    const u32 bytes = g_allowed_count * kImageDigestBytes;
    for (u32 i = 0; i < g_allowed_count; ++i)
    {
        for (u32 k = 0; k < kImageDigestBytes; ++k)
            disk_buf[i * kImageDigestBytes + k] = g_allowed_hashes[i][k];
    }
    // Delete + create rather than in-place overwrite: the file size
    // may have changed (entries added or removed), and
    // Fat32WriteInPlace rejects writes past the existing size.
    (void)fs::fat32::Fat32DeleteInRoot(vol, kDiskAllowlistFile);
    const i64 created = fs::fat32::Fat32CreateInRoot(vol, kDiskAllowlistFile, disk_buf, bytes);
    if (created < 0 || static_cast<u64>(created) != bytes)
    {
        KLOG_WARN("security/guard", "GUARD.DAT write failed — exceptions stored in RamVol only this boot");
    }
    else
    {
        (void)fs::fat32::Fat32Sync(vol);
    }
}

// ---------------------------------------------------------------
// RamVol persistence (in-memory, survives for the boot but not
// across reboots).
// ---------------------------------------------------------------

// One stored line: 64 hex chars + '\n'.
constexpr u32 kAllowlistLineBytes = kImageDigestHexChars + 1;

void LoadAllowlist()
{
    // Read the whole file. Sized for the full table so a saturated
    // list round-trips intact — the old tmpfs path silently truncated
    // at 512 bytes, dropping every entry past the seventh.
    static char buf[kMaxAllowed * kAllowlistLineBytes];
    const i64 got = duetos::fs::RamVolRead(kAllowlistPath, 0, buf, sizeof(buf));
    if (got <= 0)
    {
        arch::SerialWrite("[guard] no stored exception list (first boot or cleared)\n");
        return;
    }
    const u32 len = static_cast<u32>(got);

    u32 malformed = 0;
    u32 i = 0;
    while (i < len)
    {
        u32 j = i;
        while (j < len && buf[j] != '\n')
            ++j;
        u8 h[kImageDigestBytes];
        if (ParseHexDigest(buf + i, j - i, h))
        {
            AppendAllowedHash(h);
        }
        else if (j > i)
        {
            // A line that is not a bare 64-char digest: a truncated
            // write from an older build, or hand-editing. Skipping is
            // the fail-closed choice — a half-parsed digest would
            // vouch for an image nobody approved.
            ++malformed;
        }
        i = j + 1;
    }
    arch::SerialWrite("[guard] loaded exception list: ");
    arch::SerialWriteHex(g_allowed_count);
    arch::SerialWrite(" entries");
    if (malformed > 0)
    {
        arch::SerialWrite(" (");
        arch::SerialWriteHex(malformed);
        arch::SerialWrite(" malformed lines skipped)");
    }
    arch::SerialWrite("\n");
}

void SaveAllowlist()
{
    // Rewrite the whole list; RamVol writes are cheap and diff
    // tracking would buy nothing at this size.
    static char buf[kMaxAllowed * kAllowlistLineBytes];
    u32 w = 0;
    for (u32 i = 0; i < g_allowed_count; ++i)
    {
        FormatHexDigest(g_allowed_hashes[i], buf + w);
        w += kImageDigestHexChars;
        buf[w++] = '\n';
    }
    duetos::fs::RamVolCreate(kAllowlistPath);
    // Truncate first: a shorter list must not leave a stale tail
    // behind, which would resurrect a revoked exception on reload.
    duetos::fs::RamVolTruncate(kAllowlistPath, 0);
    const i64 wrote = duetos::fs::RamVolWrite(kAllowlistPath, 0, buf, w);
    if (wrote != static_cast<i64>(w))
    {
        // Quota exhaustion or a sealed file. The in-memory list is
        // still authoritative for this boot; say so loudly rather
        // than letting the operator believe it was stored.
        KLOG_WARN("security/guard", "exception list not fully stored (quota or sealed) — in-memory only");
    }

    // Persist to disk so exceptions survive reboot. Best-effort:
    // if no DuetOS volume is mounted yet (early boot) or the write
    // fails, the RamVol copy is still authoritative for this boot.
    if (g_disk_loaded)
    {
        SaveDiskExceptions();
    }
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

    fb::FramebufferDrawString(mx + 16, my + mh - 40, "Allow once [y]   Always [a]   Deny [n]   (10s default-deny)",
                              kHeaderRgb, kBodyRgb);
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

// What the operator chose at the prompt.
//
// `AllowOnce` and `AllowAlways` are deliberately separate keys. The
// old prompt had only "allow", and it silently added a permanent
// exception — so an operator who just wanted to get past one load
// left a standing exception behind without ever being asked. Making
// "add an exception" its own keystroke means the durable grant is
// always something the operator typed on purpose.
enum class PromptChoice : u8
{
    Deny,
    AllowOnce,
    AllowAlways,
};

PromptChoice PromptUser(const ImageDescriptor& desc, const Report& r)
{
    // Unified prompt: draws the modal dialog (if framebuffer is
    // live) AND emits the serial text. Answer accepted from
    // whichever channel responds first. 10s default-deny.
    using arch::SerialWrite;

    // Hold the compositor short-circuit flag for the entire prompt
    // lifetime — `DesktopCompose` returns immediately while this is
    // set so the modal's directly-painted pixels aren't clobbered
    // by an in-flight ui-ticker redraw. RAII so an early return on
    // any decision path (serial / keyboard / timeout) clears the
    // flag and the desktop resumes composing. See `g_prompt_active`
    // declaration for the full rationale.
    struct PromptActiveGuard
    {
        PromptActiveGuard() { g_prompt_active = true; }
        ~PromptActiveGuard() { g_prompt_active = false; }
    } prompt_active_guard;
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
    SerialWrite("[guard]  Allow once [y] / Always — add exception [a] / Deny [n] — 10s default-deny. > ");

    DrawModal(desc, r);

    // Timeout source: arch::TimerTicks() (scheduler-tick counter),
    // NOT HpetReadCounter(). HPET is OPTIONAL hardware — VirtualBox
    // omits it by default, and on absent-HPET systems
    // HpetReadCounter() returns 0 forever, leaving the previous
    // `HpetTicksToMs(now - start) >= 10'000` predicate false on
    // every iteration and trapping kboot in this loop indefinitely
    // (observed 2026-05-21: 66+ seconds of `[soft-lockup] task stuck
    // tid=0x4 name="kboot"` because the guard prompt never timed
    // out). TimerTicks is always advancing — driven by either LAPIC
    // timer or the PIT fallback — so the deadline math works on
    // every platform regardless of HPET presence. At kTickHz = 100,
    // 10s == 1000 ticks.
    const u64 start_ticks = arch::TimerTicks();
    const u64 window =
        (g_prompt_timeout_ticks != 0) ? g_prompt_timeout_ticks : (kPromptTimeoutSecs * ::duetos::time::kTickHz);
    const u64 deadline_ticks = start_ticks + window;
    for (;;)
    {
        // Both channels feed the same decision table. `channel` only
        // colours the log line; the mapping from key to choice is
        // identical either way.
        char key = 0;
        const char* channel = "";
        if (SerialRxReady())
        {
            key = static_cast<char>(SerialRxChar());
            channel = " (serial)\n";
        }
        else
        {
            key = duetos::drivers::input::Ps2KeyboardTryReadChar();
            channel = " (keyboard)\n";
        }

        if (key == 'y' || key == 'Y')
        {
            SerialWrite("y");
            SerialWrite(channel);
            SerialWrite("[guard] user ALLOWED once (no exception stored)\n");
            DrawModalDecision("*** ALLOWED ONCE ***", 0x66EE66);
            return PromptChoice::AllowOnce;
        }
        if (key == 'a' || key == 'A')
        {
            SerialWrite("a");
            SerialWrite(channel);
            SerialWrite("[guard] user ALLOWED and added a persistent exception\n");
            DrawModalDecision("*** ALLOWED — EXCEPTION ADDED ***", 0x66EE66);
            return PromptChoice::AllowAlways;
        }
        if (key == 'n' || key == 'N')
        {
            SerialWrite("n");
            SerialWrite(channel);
            SerialWrite("[guard] user DENIED\n");
            DrawModalDecision("*** DENIED BY USER ***", 0xEE6666);
            return PromptChoice::Deny;
        }
        if (arch::TimerTicks() >= deadline_ticks)
        {
            // Default-deny on timeout is the whole point of the
            // feature: an unattended boot must not inherit an
            // approval nobody gave. Pre-authorisation is explicit
            // (`guard-allow=`), never implicit.
            SerialWrite("\n[guard] prompt timeout: default-deny\n");
            DrawModalDecision("*** TIMEOUT: DEFAULT-DENY ***", 0xEE6666);
            return PromptChoice::Deny;
        }
        // `pause` not SchedYield: this loop runs in kboot context
        // (during early image-load gates), and kboot must NEVER
        // voluntarily yield — its `.bss.boot` low-VA stack becomes
        // unreachable the moment Schedule() flips CR3 to a
        // per-process AS (PML4[0..255] zeroed). The timer IRQ still
        // preempts us, which is what advances TimerTicks() above.
        asm volatile("pause" ::: "memory");
    }
}

// Run the prompt and apply the operator's choice. Shared by the
// Warn and Deny legs so the two can never drift apart on what
// "allow" stores.
bool PromptAndApply(const ImageDescriptor& desc, const Report& r)
{
    const PromptChoice choice = PromptUser(desc, r);
    if (choice == PromptChoice::Deny)
        return false;

    if (choice == PromptChoice::AllowAlways)
    {
        if (desc.bytes != nullptr && desc.size > 0)
        {
            u8 h[kImageDigestBytes];
            HashImage(desc.bytes, desc.size, h);
            GuardRememberAllow(h);
        }
        else
        {
            // A thread gate has no image bytes, so there is no
            // digest to key an exception on. Allow this one load
            // and say why nothing was stored, rather than silently
            // discarding the operator's "always".
            arch::SerialWrite("[guard] no image bytes to hash — allowed once, no exception stored\n");
        }
    }
    return true;
}

// Seed exceptions from `guard-allow=` cmdline tokens. Returns the
// number of digests installed.
u32 SeedFromCmdline(const char* cmdline)
{
    u32 installed = 0;
    u32 rejected = 0;
    const char* value = nullptr;
    u32 value_len = 0;
    for (u32 tok = 0; CmdlineFindNthValue(cmdline, kCmdlineAllowKey, tok, &value, &value_len); ++tok)
    {
        const u32 fields = CsvFieldCount(value, value_len);
        for (u32 f = 0; f < fields; ++f)
        {
            const char* field = nullptr;
            u32 field_len = 0;
            if (!CsvField(value, value_len, f, &field, &field_len))
                continue;
            u8 h[kImageDigestBytes];
            if (!ParseHexDigest(field, field_len, h))
            {
                ++rejected;
                continue;
            }
            if (IsHashAllowed(h))
                continue;
            AppendAllowedHash(h);
            ++installed;

            // Echo every seeded digest. An operator reading the boot
            // log must be able to see exactly which images were
            // pre-authorised — an exception that is in force but
            // invisible is indistinguishable from a disabled gate.
            char hex[kImageDigestHexChars + 1];
            FormatHexDigest(h, hex);
            hex[kImageDigestHexChars] = '\0';
            arch::SerialWrite("[guard] cmdline exception seeded: sha256=");
            arch::SerialWrite(hex);
            arch::SerialWrite("\n");
        }
    }

    if (rejected > 0)
    {
        // A malformed digest is an operator typo, and a typo means an
        // image they meant to pre-authorise will be denied instead.
        // Warn rather than pass over it.
        KLOG_WARN_V("security/guard", "guard-allow= entries rejected as malformed", rejected);
    }
    return installed;
}

// Fill `pe` with a synthetic PE whose bytes trip the injection-combo
// heuristic (Deny), made unique by `tag` so two calls produce two
// different SHA-256 digests.
void MakeSuspiciousPe(u8* pe, u32 len, u8 tag)
{
    VZero(pe, len);
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[2] = tag; // the only differing byte: distinct digest, same verdict
    const char* crt = "CreateRemoteThread";
    const char* wpm = "WriteProcessMemory";
    for (u32 i = 0; crt[i] != 0; ++i)
        pe[64 + i] = static_cast<u8>(crt[i]);
    for (u32 i = 0; wpm[i] != 0; ++i)
        pe[128 + i] = static_cast<u8>(wpm[i]);
}

// Prove BOTH directions of the exception mechanism through the real
// `Gate()` in Enforce mode.
//
// A test that only shows the excepted image loading cannot tell a
// working exception apart from a disabled gate — so the excepted
// image and a NON-excepted one of the same verdict are gated on the
// same boot, in the same mode, and the second must still be denied.
// That second half is also the regression test for the constraint
// that matters most: an unattended boot default-denies on timeout.
void ExceptionSelfTest()
{
    using arch::SerialWrite;

    // `static` so these land in bss rather than inviting a memset
    // lowering on a 512-byte stack array (same reasoning as the
    // injection-combo buffer above).
    static u8 pe_excepted[512];
    static u8 pe_control[512];
    MakeSuspiciousPe(pe_excepted, sizeof(pe_excepted), 0xA1);
    MakeSuspiciousPe(pe_control, sizeof(pe_control), 0xB2);

    const ImageDescriptor excepted{ImageKind::WindowsPE, "test-excepted-pe", pe_excepted, sizeof(pe_excepted)};
    const ImageDescriptor control{ImageKind::WindowsPE, "test-control-pe", pe_control, sizeof(pe_control)};

    // Both must be Deny on the merits, or the comparison proves
    // nothing about the exception.
    if (Inspect(excepted).verdict != Verdict::Deny || Inspect(control).verdict != Verdict::Deny)
    {
        SerialWrite("[guard-exception-selftest] FAIL: fixtures are not both Deny\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 1);
        return;
    }

    // GAP: the Enforce flip below is process-global for ~200 ms — no image
    // loader runs this early (GuardSelfTest is on kboot during bringup,
    // well before the ring-3 spawn path), but a future caller that gates
    // an image concurrently would see Enforce. Revisit if the self-test
    // ever moves after the loaders come up.
    const Mode saved_mode = g_mode;
    const u64 saved_timeout = g_prompt_timeout_ticks;
    const u32 saved_count = g_allowed_count;

    // Shorten the prompt window so the control image's default-deny
    // costs ~200 ms instead of 10 s. The leg under test is the
    // timeout leg itself, not its duration.
    g_prompt_timeout_ticks = ::duetos::time::kTickHz / 5;
    g_mode = Mode::Enforce;

    u8 h[kImageDigestBytes];
    HashImage(pe_excepted, sizeof(pe_excepted), h);
    AppendAllowedHash(h); // in-memory only: do not disturb the stored list

    const bool excepted_allowed = Gate(excepted);
    const bool control_allowed = Gate(control);

    g_allowed_count = saved_count;
    g_mode = saved_mode;
    g_prompt_timeout_ticks = saved_timeout;

    if (!excepted_allowed)
    {
        SerialWrite("[guard-exception-selftest] FAIL: excepted image was denied\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 2);
        return;
    }
    if (control_allowed)
    {
        // The dangerous failure: the gate let a Warn/Deny image with
        // NO exception through. That is indistinguishable from the
        // guard being off, and it is exactly what must never regress.
        SerialWrite("[guard-exception-selftest] FAIL: non-excepted image was ALLOWED (gate is not enforcing)\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 3);
        return;
    }

    // Explicit PASS line: the absence of a FAIL is not proof the
    // self-test ran. This one sentence is the grep-able evidence that
    // both directions held on this boot.
    SerialWrite("[guard-exception-selftest] PASS (excepted image allowed; non-excepted image still default-denied)\n");
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
        u8 h[32];
        HashImage(desc.bytes, desc.size, h);
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

    // Publish a structured event for Warn / Deny verdicts so the
    // event ring carries the loader-side signal (the canary +
    // persistence walls publish their own when they fire later
    // in the image's lifetime).
    if (r.verdict == Verdict::Warn)
    {
        EventRingPublishKind(EventKind::ImageWarned, 0, static_cast<u64>(r.finding_count), 0,
                             desc.name != nullptr ? desc.name : "<unnamed>");
        IrRunbookEmit(EventKind::ImageWarned, 0);
    }
    else if (r.verdict == Verdict::Deny)
    {
        EventRingPublishKind(EventKind::ImageRejected, 0, static_cast<u64>(r.finding_count), 0,
                             desc.name != nullptr ? desc.name : "<unnamed>");
        IrRunbookEmit(EventKind::ImageRejected, 0);
    }

    switch (r.verdict)
    {
    case Verdict::Allow:
        ++g_allow_count;
        return true;

    case Verdict::Warn:
        ++g_warn_count;
        if (g_mode == Mode::Advisory)
            return true;
        return PromptAndApply(desc, r);

    case Verdict::Deny:
        ++g_deny_count;
        if (g_mode == Mode::Advisory)
        {
            arch::SerialWrite("[guard] advisory: would DENY (mode=Advisory, allowing)\n");
            return true;
        }
        return PromptAndApply(desc, r);

    default:
        // Verdict enum extension would land here; treat as advisory pass.
        return true;
    }
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

void GuardRememberAllow(const u8 hash[32])
{
    if (IsHashAllowed(hash))
        return;
    AppendAllowedHash(hash);
    SaveAllowlist();

    char hex[kImageDigestHexChars + 1];
    FormatHexDigest(hash, hex);
    hex[kImageDigestHexChars] = '\0';
    arch::SerialWrite("[guard] exception added: sha256=");
    arch::SerialWrite(hex);
    arch::SerialWrite("\n");
    // Also on klog so the addition lands in dmesg and the panic-dump
    // replay, not only on the boot-time serial stream.
    KLOG_WARN_S("security/guard", "operator added an image exception", "sha256", hex);
}

void GuardSeedExceptionsFromCmdline(const char* cmdline)
{
    const u32 n = SeedFromCmdline(cmdline);
    g_cmdline_seeded = n;
    if (n == 0)
        return;

    // Loud on purpose. This is the one path that grants an exception
    // with nobody at the console, so it must be impossible to read a
    // boot log and miss that it happened.
    arch::SerialWrite("[guard] NOTICE: boot cmdline pre-authorised images — guard exceptions ARE in force\n");
    KLOG_WARN_V("security/guard", "cmdline-seeded image exceptions in force (guard-allow=)", n);
}

u32 GuardExceptionCount()
{
    return g_allowed_count;
}

u32 GuardCmdlineSeededCount()
{
    return g_cmdline_seeded;
}

bool GuardExceptionGet(u32 index, u8 out[32])
{
    if (index >= g_allowed_count || out == nullptr)
        return false;
    for (u32 i = 0; i < kImageDigestBytes; ++i)
        out[i] = g_allowed_hashes[index][i];
    return true;
}

bool GuardForgetException(u32 index)
{
    if (index >= g_allowed_count)
        return false;
    // Compact the tail down over the removed slot; order carries no
    // meaning, but keeping the array dense keeps the match loop's
    // bound honest.
    for (u32 i = index; i + 1 < g_allowed_count; ++i)
    {
        for (u32 k = 0; k < kImageDigestBytes; ++k)
            g_allowed_hashes[i][k] = g_allowed_hashes[i + 1][k];
    }
    --g_allowed_count;
    for (u32 k = 0; k < kImageDigestBytes; ++k)
        g_allowed_hashes[g_allowed_count][k] = 0;
    SaveAllowlist();
    KLOG_WARN_V("security/guard", "operator removed an image exception (index)", index);
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
    default:
        return "?";
    }
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

bool GuardPromptActive()
{
    return g_prompt_active;
}

void GuardLoadDiskExceptions()
{
    if (g_disk_loaded)
    {
        arch::SerialWrite("[guard] disk exceptions already loaded (ignored)\n");
        return;
    }
    g_disk_loaded = true;
    LoadDiskExceptions();

    // Now that the disk path is live, persist whatever the RamVol /
    // cmdline path already installed so a first-boot cmdline seed
    // survives into the on-disk file without the operator having to
    // re-approve on the next reboot.
    if (g_allowed_count > 0)
    {
        SaveDiskExceptions();
    }
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
    g_cmdline_seeded = 0;
    arch::SerialWrite("[guard] init (mode=advisory)\n");
    LoadAllowlist();
    // Cmdline seeding runs after the stored list so a `guard-allow=`
    // digest that is already stored is a no-op rather than a
    // duplicate. FindBootCmdline(0) reads the cache populated in
    // early boot — the low Multiboot mapping is long gone by now.
    GuardSeedExceptionsFromCmdline(duetos::core::FindBootCmdline(0));
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

    ExceptionSelfTest();
}

} // namespace duetos::security
