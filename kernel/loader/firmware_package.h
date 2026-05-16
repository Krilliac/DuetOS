#pragma once

#include "crypto/sha256.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — source-aware firmware package envelope.
 *
 * This is NOT a firmware format for a specific NIC/GPU. It is the
 * DuetOS packaging envelope around a raw vendor/open firmware image.
 * The payload bytes remain owned by the per-device parser/upload path
 * (iwlwifi TLVs, b43 records, ath9k_htc target image, Intel GPU uC,
 * ...). The envelope adds the metadata the kernel needs before it
 * decides whether bytes may be staged into DMA:
 *
 *   - stable family/source classification,
 *   - source-rebuildable / bundle / regulatory-lock flags,
 *   - explicit lab-only marker for custom experimental images,
 *   - SHA-256 over the exact payload bytes.
 *
 * Closed vendor blobs may be wrapped by users/distributions for hash
 * pinning, but custom lab firmware must set `CustomLabImage` and is
 * refused unless the caller explicitly opts in. This keeps the normal
 * boot path away from modified regulatory firmware while still giving
 * bring-up labs a concrete, auditable route for source-built images
 * such as ath9k_htc/open-ath9k-htc-firmware.
 *
 * Threading: pure parser/validator. No heap, no global state.
 */

namespace duetos::core
{

inline constexpr u32 kDuetFwPackageVersion = 1;
inline constexpr u32 kDuetFwPackageNameBytes = 32;
inline constexpr u32 kDuetFwPackageUpstreamBytes = 64;
inline constexpr u32 kDuetFwPackageDigestBytes = crypto::kSha256DigestBytes;

// Header is intentionally fixed-size and little-endian so a host tool
// can generate it without C struct packing assumptions.
inline constexpr u32 kDuetFwPackageHeaderBytes = 160;

// u16 is the serialized field width (LE16 at header offset 12, see
// firmware_package.cpp) — deliberate, not a footprint choice.
// NOLINTNEXTLINE(performance-enum-size)
enum class FwPackageFamily : u16
{
    Unknown = 0,
    IntelIwlwifi = 1,
    IntelGpuUc = 2,
    Ath9kHtc = 3,
    BroadcomB43 = 4,
    BroadcomFullMac = 5,
    RealtekRtl88xx = 6,
};

enum class FwPackageSourceKind : u8
{
    Unknown = 0,
    OpenSource = 1,
    RedistributableBinary = 2,
    ExtractedVendorBinary = 3,
    PatchFramework = 4,
};

// u32 is the serialized field width (LE32 bitflag set at header offset 16,
// see firmware_package.cpp) — deliberate, not a footprint choice.
// NOLINTNEXTLINE(performance-enum-size)
enum FwPackageFlags : u32
{
    kFwPackageFlagSourceRebuildable = 1u << 0,
    kFwPackageFlagMayBundleInTree = 1u << 1,
    kFwPackageFlagRegulatoryLocked = 1u << 2,
    kFwPackageFlagCustomLabImage = 1u << 3,
    kFwPackageFlagRequiresExplicitOptIn = 1u << 4,
    kFwPackageFlagOpenFirmware = 1u << 5,
};

struct FwPackageParsed
{
    bool valid;
    FwPackageFamily family;
    FwPackageSourceKind source_kind;
    u32 flags;
    u32 build_id;

    char short_name[kDuetFwPackageNameBytes + 1];
    char upstream[kDuetFwPackageUpstreamBytes + 1];

    u8 payload_sha256[kDuetFwPackageDigestBytes];
    const u8* payload;
    u32 payload_size;
};

const char* FwPackageFamilyName(FwPackageFamily family);
const char* FwPackageSourceKindName(FwPackageSourceKind source_kind);

bool FwPackageHasFlag(const FwPackageParsed& parsed, FwPackageFlags flag);
bool FwPackageLoadAllowed(const FwPackageParsed& parsed, bool allow_custom_lab_image);

/// Parse and verify a DuetOS firmware package. Returns Corrupt for
/// bad magic/version/bounds or a SHA-256 payload mismatch.
::duetos::core::Result<void> FwPackageParse(const u8* blob, u32 blob_size, FwPackageParsed* parsed);

/// True if the byte prefix is a DuetOS firmware package envelope.
bool FwPackageLooksLike(const u8* blob, u32 blob_size);

void FwPackageSelfTest();

} // namespace duetos::core
