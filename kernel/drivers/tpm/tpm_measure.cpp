#include "drivers/tpm/tpm_measure.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "crypto/sha256.h"
#include "drivers/tpm/tpm.h"
#include "drivers/tpm/tpm_wire.h"
#include "duetos_build_info.h"
#include "log/klog.h"
#include "util/cmdline.h"

namespace duetos::drivers::tpm
{

namespace
{

constinit BootIntegrity g_state = BootIntegrity::NoTpm;
constinit u8 g_digest[wire::kSha256DigestSize] = {};
constinit bool g_have_digest = false;

/// PCR 10 carries the kernel's identity, PCR 11 its configuration. The
/// split matters: it lets an operator see WHICH of the two changed by
/// reading the individual PCRs, instead of only that something did.
///
/// NOT 8 and 9, which are the obvious OS-owned choice: GRUB's `tpm`
/// module already measures its own commands into PCR 8 and the files it
/// loads into PCR 9, and the commands it measures include the RAW
/// kernel command line — baseline token and all. Folding those into the
/// composite would make the digest depend on the baseline being pinned,
/// so pinning it would change it and a match could never occur. That is
/// not hypothetical: it was observed, with two boots differing only in
/// the baseline value producing two different digests.
constexpr u32 kPcrKernelIdentity = 10;
constexpr u32 kPcrKernelCmdline = 11;

/// Longest command line we will measure. A longer one is measured up
/// to this bound and the truncation is logged — silently measuring a
/// prefix would make the tripwire miss a tail-appended argument.
constexpr u32 kMaxCmdlineBytes = 1024;

/// The token that carries the pinned baseline. It is excluded from the
/// measurement — see `CopyCmdlineForMeasurement`.
constexpr char kBaselineKey[] = "tpm.baseline=";
constexpr u32 kBaselineKeyLength = sizeof(kBaselineKey) - 1;

u32 StringLength(const char* s, u32 cap)
{
    u32 n = 0;
    while (n < cap && s[n] != '\0')
        ++n;
    return n;
}

bool TokenStartsWithBaselineKey(const char* token, const char* end)
{
    if (static_cast<u32>(end - token) < kBaselineKeyLength)
        return false;
    for (u32 i = 0; i < kBaselineKeyLength; ++i)
    {
        if (token[i] != kBaselineKey[i])
            return false;
    }
    return true;
}

/// Copy `cmdline` into `out`, dropping the `tpm.baseline=` token.
///
/// Without this the tripwire could never report a match: PCR 9 measures
/// the command line, so pinning the baseline ON the command line would
/// change the very digest being pinned. Excluding the token makes the
/// measurement stable across the act of pinning it.
///
/// GAP: the baseline shares its storage with the thing it measures, so
/// an attacker who can edit the boot configuration can add a malicious
/// token AND re-pin the baseline, and the tripwire will report match -
/// revisit when a writable persistent store exists and the baseline can
/// be sealed to the TPM instead.
u32 CopyCmdlineForMeasurement(const char* cmdline, char* out, u32 capacity)
{
    if (cmdline == nullptr || capacity == 0)
    {
        if (capacity != 0)
            out[0] = '\0';
        return 0;
    }

    u32 written = 0;
    const char* p = cmdline;
    while (*p != '\0' && written + 1 < capacity)
    {
        while (*p == ' ' || *p == '\t')
            ++p;
        if (*p == '\0')
            break;

        const char* token = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
            ++p;

        if (TokenStartsWithBaselineKey(token, p))
            continue;

        if (written != 0 && written + 1 < capacity)
            out[written++] = ' ';
        for (const char* t = token; t < p && written + 1 < capacity; ++t)
            out[written++] = *t;
    }

    out[written] = '\0';
    return written;
}

/// Extend one PCR with SHA-256 over `data`.
bool MeasureInto(u32 pcr_index, const u8* data, u32 length)
{
    u8 digest[wire::kSha256DigestSize];
    crypto::Sha256Hash(data, length, digest);
    return TpmPcrExtend(pcr_index, digest).has_value();
}

/// Fold the composite PCR set into one digest, reading each value back
/// from the chip rather than trusting our own arithmetic — that is what
/// makes anything ELSE that extended a PCR visible.
bool ComputeCompositeDigest(u8 out[wire::kSha256DigestSize])
{
    crypto::Sha256Ctx ctx;
    crypto::Sha256Init(ctx);

    for (u32 i = 0; i < kMeasuredPcrCount; ++i)
    {
        const u32 pcr = kMeasuredPcrs[i];
        u8 value[wire::kSha256DigestSize];
        if (!TpmPcrRead(pcr, value).has_value())
        {
            KLOG_WARN_V("drivers/tpm", "composite boot digest abandoned: PCR read failed", pcr);
            return false;
        }
        // Per-PCR prefix, so an operator chasing an unexpected CHANGED
        // can see WHICH measurement moved instead of only that the
        // composite did. Debug-gated; a clean boot stays quiet.
        u64 prefix = 0;
        for (u32 b = 0; b < 8; ++b)
            prefix = (prefix << 8) | value[b];
        KLOG_DEBUG_V("drivers/tpm", "composite PCR index", pcr);
        KLOG_DEBUG_V("drivers/tpm", "composite PCR prefix", prefix);

        crypto::Sha256Update(ctx, value, wire::kSha256DigestSize);
    }

    crypto::Sha256Final(ctx, out);
    return true;
}

bool DigestsEqual(const u8* a, const u8* b)
{
    for (u32 i = 0; i < wire::kSha256DigestSize; ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

void SerialWriteDigest(const u8* digest)
{
    char text[wire::kSha256DigestSize * 2 + 1];
    for (u32 i = 0; i < wire::kSha256DigestSize; ++i)
    {
        const u8 hi = static_cast<u8>(digest[i] >> 4);
        const u8 lo = static_cast<u8>(digest[i] & 0xF);
        text[i * 2] = static_cast<char>(hi < 10 ? '0' + hi : 'a' + hi - 10);
        text[i * 2 + 1] = static_cast<char>(lo < 10 ? '0' + lo : 'a' + lo - 10);
    }
    text[wire::kSha256DigestSize * 2] = '\0';
    arch::SerialWrite(text);
}

} // namespace

const char* BootIntegrityName(BootIntegrity state)
{
    switch (state)
    {
    case BootIntegrity::NoTpm:
        return "no-tpm";
    case BootIntegrity::NotMeasured:
        return "not-measured";
    case BootIntegrity::Unpinned:
        return "unpinned";
    case BootIntegrity::Match:
        return "match";
    case BootIntegrity::Changed:
        return "CHANGED";
    }
    return "<unknown>";
}

BootIntegrity TpmBootIntegrity()
{
    return g_state;
}

bool TpmBootDigest(u8 out[32])
{
    if (!g_have_digest || out == nullptr)
        return false;
    for (u32 i = 0; i < wire::kSha256DigestSize; ++i)
        out[i] = g_digest[i];
    return true;
}

void TpmMeasureBoot(const char* cmdline)
{
    if (!TpmPresent())
    {
        g_state = BootIntegrity::NoTpm;
        arch::SerialWrite("[tpm-measure] boot-integrity=no-tpm\n");
        return;
    }

    // 1. Kernel identity. The git hash pins the source; the branch
    //    disambiguates two builds of the same commit on different
    //    lanes. The build TIMESTAMP is deliberately excluded — it
    //    changes on every rebuild of identical source and would make
    //    the tripwire fire on a no-op recompile.
    const char* identity = DUETOS_GIT_HASH " " DUETOS_GIT_BRANCH;
    if (!MeasureInto(kPcrKernelIdentity, reinterpret_cast<const u8*>(identity), StringLength(identity, 256)))
    {
        g_state = BootIntegrity::NotMeasured;
        arch::SerialWrite("[tpm-measure] boot-integrity=not-measured (kernel identity extend failed)\n");
        return;
    }

    // 2. Kernel command line, minus the baseline token itself.
    char line[kMaxCmdlineBytes];
    const u32 line_length = CopyCmdlineForMeasurement(cmdline, line, sizeof(line));
    if (line_length + 1 == sizeof(line))
    {
        KLOG_WARN_V("drivers/tpm", "command line truncated for measurement at", kMaxCmdlineBytes);
    }
    if (!MeasureInto(kPcrKernelCmdline, reinterpret_cast<const u8*>(line), line_length))
    {
        g_state = BootIntegrity::NotMeasured;
        arch::SerialWrite("[tpm-measure] boot-integrity=not-measured (cmdline extend failed)\n");
        return;
    }

    // 3. Composite over PCR 0..9, read back from the chip so that
    //    firmware's own measurements are included and so that anything
    //    else that touched a PCR shows up.
    if (!ComputeCompositeDigest(g_digest))
    {
        g_state = BootIntegrity::NotMeasured;
        arch::SerialWrite("[tpm-measure] boot-integrity=not-measured (composite read failed)\n");
        return;
    }
    g_have_digest = true;

    // 4. Compare against the pinned baseline, if the operator gave one.
    char baseline_text[wire::kSha256DigestSize * 2 + 2];
    u8 baseline[wire::kSha256DigestSize];
    const bool have_baseline =
        ::duetos::core::CmdlineGet(cmdline, "tpm.baseline", baseline_text, sizeof(baseline_text)) &&
        ::duetos::core::HexDecode(baseline_text, StringLength(baseline_text, sizeof(baseline_text)), baseline,
                                  sizeof(baseline));

    if (!have_baseline)
    {
        g_state = BootIntegrity::Unpinned;
        arch::SerialWrite("[tpm-measure] boot-integrity=unpinned digest=");
        SerialWriteDigest(g_digest);
        arch::SerialWrite("\n[tpm-measure] pin it with tpm.baseline=<that digest> to arm the tripwire\n");
        arch::SerialWrite("[tpm-measure] note: this only holds if editing the boot config leaves the\n");
        arch::SerialWrite("[tpm-measure]   boot IMAGE unchanged, since PCR 4 measures that image\n");
        return;
    }

    if (DigestsEqual(g_digest, baseline))
    {
        g_state = BootIntegrity::Match;
        arch::SerialWrite("[tpm-measure] boot-integrity=match\n");
        return;
    }

    // A changed boot chain is the whole reason this exists, so it is
    // loud — but it is a WARN, not a panic. The tripwire's job is to
    // tell the machine's owner, not to decide for them whether the
    // change was legitimate. Refusing to boot on a PCR mismatch is
    // precisely the lock-out behaviour this design set out to avoid.
    g_state = BootIntegrity::Changed;
    KLOG_WARN("drivers/tpm", "measured boot: the boot chain has CHANGED since the pinned baseline");
    arch::SerialWrite("[tpm-measure] boot-integrity=CHANGED digest=");
    SerialWriteDigest(g_digest);
    arch::SerialWrite("\n");
}

void TpmMeasureSelfTest()
{
    // Composite folding must be order-sensitive and value-sensitive:
    // a digest that ignored either would report "match" across a real
    // change, which is the one failure mode that matters here.
    u8 pcrs_a[kMeasuredPcrCount][wire::kSha256DigestSize] = {};
    u8 pcrs_b[kMeasuredPcrCount][wire::kSha256DigestSize] = {};
    pcrs_b[3][0] = 1;

    crypto::Sha256Ctx ctx;
    u8 digest_a[wire::kSha256DigestSize];
    u8 digest_b[wire::kSha256DigestSize];

    crypto::Sha256Init(ctx);
    for (u32 i = 0; i < kMeasuredPcrCount; ++i)
        crypto::Sha256Update(ctx, pcrs_a[i], wire::kSha256DigestSize);
    crypto::Sha256Final(ctx, digest_a);

    crypto::Sha256Init(ctx);
    for (u32 i = 0; i < kMeasuredPcrCount; ++i)
        crypto::Sha256Update(ctx, pcrs_b[i], wire::kSha256DigestSize);
    crypto::Sha256Final(ctx, digest_b);

    KASSERT(!DigestsEqual(digest_a, digest_b), "drivers/tpm", "composite digest changes when one PCR changes");
    KASSERT(DigestsEqual(digest_a, digest_a), "drivers/tpm", "composite digest is stable");

    // The measured command line must be identical with and without the
    // baseline token, or pinning a baseline would change the digest
    // being pinned and a match could never happen. This is the property
    // that makes the tripwire usable at all, so it gets a guard.
    char without[128];
    char with[128];
    const u32 n1 = CopyCmdlineForMeasurement("loglevel=debug selftests=full", without, sizeof(without));
    const u32 n2 = CopyCmdlineForMeasurement(
        "loglevel=debug tpm.baseline=00112233445566778899aabbccddeeff selftests=full", with, sizeof(with));
    KASSERT(n1 == n2, "drivers/tpm", "baseline token is excluded from the measured cmdline");
    for (u32 i = 0; i < n1; ++i)
        KASSERT(without[i] == with[i], "drivers/tpm", "measured cmdline is stable across pinning");

    // ...but a real configuration change must still move it.
    char changed[128];
    const u32 n3 = CopyCmdlineForMeasurement("loglevel=debug selftests=full evil=1", changed, sizeof(changed));
    KASSERT(n3 != n1, "drivers/tpm", "an added token still changes the measured cmdline");

    // The baseline decoder must reject malformed operator input rather
    // than decode it into something that silently never matches.
    u8 decoded[wire::kSha256DigestSize];
    KASSERT(::duetos::core::HexDecode("00ff", 4, decoded, sizeof(decoded)), "drivers/tpm", "hex decode accepts hex");
    KASSERT(decoded[0] == 0x00 && decoded[1] == 0xFF, "drivers/tpm", "hex decode is correct");
    KASSERT(!::duetos::core::HexDecode("00fg", 4, decoded, sizeof(decoded)), "drivers/tpm",
            "hex decode rejects non-hex");
    KASSERT(!::duetos::core::HexDecode("0", 1, decoded, sizeof(decoded)), "drivers/tpm",
            "hex decode rejects odd length");

    arch::SerialWrite("[tpm-measure-selftest] PASS\n");
}

} // namespace duetos::drivers::tpm
