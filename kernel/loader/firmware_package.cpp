#include "loader/firmware_package.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::core
{

namespace
{

constexpr u8 kMagic[8] = {'D', 'U', 'E', 'T', 'F', 'W', 'P', 'K'};

u16 ReadLe16(const u8* p, u32 off)
{
    return static_cast<u16>(p[off]) | static_cast<u16>(static_cast<u16>(p[off + 1]) << 8);
}

u32 ReadLe32(const u8* p, u32 off)
{
    return static_cast<u32>(p[off]) | (static_cast<u32>(p[off + 1]) << 8) | (static_cast<u32>(p[off + 2]) << 16) |
           (static_cast<u32>(p[off + 3]) << 24);
}

void WriteLe16(u8* p, u32 off, u16 v)
{
    p[off] = static_cast<u8>(v & 0xFFu);
    p[off + 1] = static_cast<u8>((v >> 8) & 0xFFu);
}

void WriteLe32(u8* p, u32 off, u32 v)
{
    p[off] = static_cast<u8>(v & 0xFFu);
    p[off + 1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[off + 2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[off + 3] = static_cast<u8>((v >> 24) & 0xFFu);
}

bool MagicMatches(const u8* blob, u32 blob_size)
{
    if (blob == nullptr || blob_size < sizeof(kMagic))
        return false;
    for (u32 i = 0; i < sizeof(kMagic); ++i)
    {
        if (blob[i] != kMagic[i])
            return false;
    }
    return true;
}

void CopyFixedString(char* dst, u32 dst_cap, const u8* src, u32 src_len)
{
    if (dst == nullptr || dst_cap == 0)
        return;
    u32 i = 0;
    for (; i + 1 < dst_cap && i < src_len && src[i] != 0; ++i)
        dst[i] = static_cast<char>(src[i]);
    dst[i] = '\0';
}

bool DigestEquals(const u8* a, const u8* b, u32 len)
{
    u8 diff = 0;
    for (u32 i = 0; i < len; ++i)
        diff |= static_cast<u8>(a[i] ^ b[i]);
    return diff == 0;
}

void MakeSelfTestPackage(u8* pkg, u32* pkg_size, bool custom_lab_image)
{
    constexpr u8 kPayload[] = {0x88, 0x54, 0x48, 0x43, 0x01, 0x02, 0x03, 0x04,
                               0x10, 0x20, 0x30, 0x40, 0xA5, 0x5A, 0xC3, 0x3C};
    for (u32 i = 0; i < kDuetFwPackageHeaderBytes + sizeof(kPayload); ++i)
        pkg[i] = 0;
    for (u32 i = 0; i < sizeof(kMagic); ++i)
        pkg[i] = kMagic[i];

    WriteLe16(pkg, 8, static_cast<u16>(kDuetFwPackageVersion));
    WriteLe16(pkg, 10, static_cast<u16>(kDuetFwPackageHeaderBytes));
    WriteLe16(pkg, 12, static_cast<u16>(FwPackageFamily::Ath9kHtc));
    pkg[14] = static_cast<u8>(FwPackageSourceKind::OpenSource);
    pkg[15] = 0;

    u32 flags = kFwPackageFlagSourceRebuildable | kFwPackageFlagMayBundleInTree | kFwPackageFlagRegulatoryLocked |
                kFwPackageFlagOpenFirmware;
    if (custom_lab_image)
        flags |= kFwPackageFlagCustomLabImage | kFwPackageFlagRequiresExplicitOptIn;
    WriteLe32(pkg, 16, flags);
    WriteLe32(pkg, 20, kDuetFwPackageHeaderBytes);
    WriteLe32(pkg, 24, sizeof(kPayload));
    WriteLe32(pkg, 28, 0x20260508u);

    const char name[] = "ath9k-htc-custom";
    for (u32 i = 0; i < sizeof(name) - 1; ++i)
        pkg[64 + i] = static_cast<u8>(name[i]);
    const char upstream[] = "qca/open-ath9k-htc-firmware";
    for (u32 i = 0; i < sizeof(upstream) - 1; ++i)
        pkg[96 + i] = static_cast<u8>(upstream[i]);

    for (u32 i = 0; i < sizeof(kPayload); ++i)
        pkg[kDuetFwPackageHeaderBytes + i] = kPayload[i];
    crypto::Sha256Hash(pkg + kDuetFwPackageHeaderBytes, sizeof(kPayload), pkg + 32);
    *pkg_size = kDuetFwPackageHeaderBytes + sizeof(kPayload);
}

} // namespace

const char* FwPackageFamilyName(FwPackageFamily family)
{
    switch (family)
    {
    case FwPackageFamily::Unknown:
        return "unknown";
    case FwPackageFamily::IntelIwlwifi:
        return "intel-iwlwifi";
    case FwPackageFamily::IntelGpuUc:
        return "intel-gpu-uc";
    case FwPackageFamily::Ath9kHtc:
        return "ath9k-htc";
    case FwPackageFamily::BroadcomB43:
        return "broadcom-b43";
    case FwPackageFamily::BroadcomFullMac:
        return "broadcom-fullmac";
    case FwPackageFamily::RealtekRtl88xx:
        return "realtek-rtl88xx";
    }
    return "unknown";
}

const char* FwPackageSourceKindName(FwPackageSourceKind source_kind)
{
    switch (source_kind)
    {
    case FwPackageSourceKind::Unknown:
        return "unknown";
    case FwPackageSourceKind::OpenSource:
        return "open-source";
    case FwPackageSourceKind::RedistributableBinary:
        return "redistributable-binary";
    case FwPackageSourceKind::ExtractedVendorBinary:
        return "extracted-vendor-binary";
    case FwPackageSourceKind::PatchFramework:
        return "patch-framework";
    }
    return "unknown";
}

bool FwPackageHasFlag(const FwPackageParsed& parsed, FwPackageFlags flag)
{
    return (parsed.flags & static_cast<u32>(flag)) != 0;
}

bool FwPackageLoadAllowed(const FwPackageParsed& parsed, bool allow_custom_lab_image)
{
    if (!parsed.valid || parsed.payload == nullptr || parsed.payload_size == 0)
        return false;
    const bool lab_only = FwPackageHasFlag(parsed, kFwPackageFlagCustomLabImage) ||
                          FwPackageHasFlag(parsed, kFwPackageFlagRequiresExplicitOptIn);
    if (lab_only && !allow_custom_lab_image)
        return false;
    return true;
}

bool FwPackageLooksLike(const u8* blob, u32 blob_size)
{
    return MagicMatches(blob, blob_size);
}

::duetos::core::Result<void> FwPackageParse(const u8* blob, u32 blob_size, FwPackageParsed* parsed)
{
    if (parsed == nullptr)
        return ::duetos::core::Err{ErrorCode::InvalidArgument};
    *parsed = {};
    if (blob == nullptr || blob_size < kDuetFwPackageHeaderBytes)
        return ::duetos::core::Err{ErrorCode::InvalidArgument};
    if (!MagicMatches(blob, blob_size))
        return ::duetos::core::Err{ErrorCode::Corrupt};

    const u16 version = ReadLe16(blob, 8);
    const u16 header_bytes = ReadLe16(blob, 10);
    if (version != kDuetFwPackageVersion || header_bytes < kDuetFwPackageHeaderBytes || header_bytes > blob_size)
        return ::duetos::core::Err{ErrorCode::Corrupt};

    const u32 payload_offset = ReadLe32(blob, 20);
    const u32 payload_size = ReadLe32(blob, 24);
    // Overflow-safe bounds: a crafted package with payload_offset and
    // payload_size both near UINT32_MAX would pass `payload_offset +
    // payload_size > blob_size` after the sum wraps u32 small. Compare
    // the difference instead — `payload_size > blob_size - payload_offset`
    // cannot wrap because the prior `payload_offset > blob_size` check
    // makes the subtraction non-negative. Class M discipline (see
    // wiki/security/Linux-CVE-Audit.md).
    if (payload_offset < header_bytes || payload_offset > blob_size || payload_size == 0 ||
        payload_size > blob_size - payload_offset)
        return ::duetos::core::Err{ErrorCode::Corrupt};

    u8 digest[crypto::kSha256DigestBytes] = {};
    crypto::Sha256Hash(blob + payload_offset, payload_size, digest);
    if (!DigestEquals(digest, blob + 32, crypto::kSha256DigestBytes))
        return ::duetos::core::Err{ErrorCode::Corrupt};

    parsed->valid = true;
    parsed->family = static_cast<FwPackageFamily>(ReadLe16(blob, 12));
    parsed->source_kind = static_cast<FwPackageSourceKind>(blob[14]);
    parsed->flags = ReadLe32(blob, 16);
    parsed->build_id = ReadLe32(blob, 28);
    for (u32 i = 0; i < crypto::kSha256DigestBytes; ++i)
        parsed->payload_sha256[i] = blob[32 + i];
    CopyFixedString(parsed->short_name, sizeof(parsed->short_name), blob + 64, kDuetFwPackageNameBytes);
    CopyFixedString(parsed->upstream, sizeof(parsed->upstream), blob + 96, kDuetFwPackageUpstreamBytes);
    parsed->payload = blob + payload_offset;
    parsed->payload_size = payload_size;
    return ::duetos::core::Result<void>{};
}

void FwPackageSelfTest()
{
    constexpr u32 kBufBytes = 256;
    static u8 pkg[kBufBytes] = {};
    u32 pkg_size = 0;
    MakeSelfTestPackage(pkg, &pkg_size, /*custom_lab_image=*/false);

    FwPackageParsed parsed{};
    auto r = FwPackageParse(pkg, pkg_size, &parsed);
    KASSERT(r.has_value(), "loader/firmware_package", "open package parse failed");
    KASSERT(parsed.valid, "loader/firmware_package", "package valid=false");
    KASSERT(parsed.family == FwPackageFamily::Ath9kHtc, "loader/firmware_package", "wrong family");
    KASSERT(parsed.source_kind == FwPackageSourceKind::OpenSource, "loader/firmware_package", "wrong source kind");
    KASSERT(FwPackageHasFlag(parsed, kFwPackageFlagSourceRebuildable), "loader/firmware_package",
            "source flag missing");
    KASSERT(FwPackageHasFlag(parsed, kFwPackageFlagRegulatoryLocked), "loader/firmware_package",
            "regulatory flag missing");
    KASSERT(FwPackageLoadAllowed(parsed, /*allow_custom_lab_image=*/false), "loader/firmware_package",
            "open package should load by default");
    KASSERT(parsed.payload_size == 16 && parsed.payload[0] == 0x88 && parsed.payload[15] == 0x3C,
            "loader/firmware_package", "payload view mismatch");

    MakeSelfTestPackage(pkg, &pkg_size, /*custom_lab_image=*/true);
    auto lab = FwPackageParse(pkg, pkg_size, &parsed);
    KASSERT(lab.has_value(), "loader/firmware_package", "lab package parse failed");
    KASSERT(!FwPackageLoadAllowed(parsed, /*allow_custom_lab_image=*/false), "loader/firmware_package",
            "lab package loaded without opt-in");
    KASSERT(FwPackageLoadAllowed(parsed, /*allow_custom_lab_image=*/true), "loader/firmware_package",
            "lab package refused with opt-in");

    pkg[kDuetFwPackageHeaderBytes + 3] ^= 0x55;
    FwPackageParsed bad{};
    auto bad_r = FwPackageParse(pkg, pkg_size, &bad);
    KASSERT(!bad_r.has_value() && bad_r.error() == ErrorCode::Corrupt, "loader/firmware_package",
            "tampered payload should fail digest");

    KASSERT(FwPackageFamilyName(FwPackageFamily::Ath9kHtc)[0] == 'a', "loader/firmware_package",
            "family name mismatch");
    KASSERT(FwPackageSourceKindName(FwPackageSourceKind::OpenSource)[0] == 'o', "loader/firmware_package",
            "source kind name mismatch");

    arch::SerialWrite("[fw-package] selftest pass\n");
}

} // namespace duetos::core
