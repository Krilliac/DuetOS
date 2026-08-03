// Hostile host tests for the clean-room MT7921 PCI preflight contract.

#include "drivers/net/mt7921_contract.h"
#include "host_test_helper.h"

using namespace duetos;
using namespace duetos::drivers::net::mt7921;

namespace
{

void Clear(u8* bytes, u64 count)
{
    for (u64 i = 0; i < count; ++i)
        bytes[i] = 0;
}

void PutLe16(u8* bytes, u16 value)
{
    bytes[0] = static_cast<u8>(value);
    bytes[1] = static_cast<u8>(value >> 8);
}

void PutLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value);
    bytes[1] = static_cast<u8>(value >> 8);
    bytes[2] = static_cast<u8>(value >> 16);
    bytes[3] = static_cast<u8>(value >> 24);
}

void PutBe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value >> 24);
    bytes[1] = static_cast<u8>(value >> 16);
    bytes[2] = static_cast<u8>(value >> 8);
    bytes[3] = static_cast<u8>(value);
}

PciIdentity ValidIdentity()
{
    return {
        kPciVendorId,  kPciDeviceId, kSubsystemVendorId,       kSubsystemDeviceId,
        kPciBaseClass, kPciSubclass, kPciProgrammingInterface, kRevisionId,
        true,
    };
}

BarResource ValidBar()
{
    return {
        0x0000007C02200000ull, kMinimumBarBytes, kMinimumBarBytes, kRequiredBarIndex, true, true, true, true,
    };
}

constexpr u64 kRamBytes = 196;

void MakeValidRam(u8* bytes)
{
    Clear(bytes, kRamBytes);
    constexpr u32 kTableOffset = 80;
    constexpr u32 kTrailerOffset = 160;

    PutLe32(bytes + kTableOffset + 16, 0x00915000);
    PutLe32(bytes + kTableOffset + 20, 64);
    bytes[kTableOffset + 24] = 0x20;

    PutLe32(bytes + kTableOffset + 40 + 16, 0);
    PutLe32(bytes + kTableOffset + 40 + 20, 16);
    bytes[kTableOffset + 40 + 24] = 0x40;
    bytes[kTableOffset + 40 + 25] = 2;

    bytes[kTrailerOffset] = 0x0D;
    bytes[kTrailerOffset + 1] = 1;
    bytes[kTrailerOffset + 2] = 2;
    bytes[kTrailerOffset + 3] = 2;
    bytes[kTrailerOffset + 4] = 1;
}

constexpr u64 kPatchBytes = 224;

void MakeValidPatch(u8* bytes)
{
    Clear(bytes, kPatchBytes);
    PutBe32(bytes + 32, 0x44332211);
    PutBe32(bytes + 44, 1);
    PutBe32(bytes + 96, 0x00040002);
    PutBe32(bytes + 100, 160);
    PutBe32(bytes + 104, 64);
    PutBe32(bytes + 108, 0x00900000);
    PutBe32(bytes + 112, 64);
}

constexpr u64 kOverlapPatchBytes = 352;

void MakeOverlappingPatch(u8* bytes)
{
    Clear(bytes, kOverlapPatchBytes);
    PutBe32(bytes + 32, 0x44332211);
    PutBe32(bytes + 44, 2);
    PutBe32(bytes + 96, 2);
    PutBe32(bytes + 100, 224);
    PutBe32(bytes + 104, 96);
    PutBe32(bytes + 108, 0x00900000);
    PutBe32(bytes + 112, 96);
    PutBe32(bytes + 160, 2);
    PutBe32(bytes + 164, 288);
    PutBe32(bytes + 168, 64);
    PutBe32(bytes + 172, 0x00910000);
    PutBe32(bytes + 176, 64);
}

void MakePaddingOverlapPatch(u8* bytes)
{
    Clear(bytes, kOverlapPatchBytes);
    PutBe32(bytes + 32, 0x44332211);
    PutBe32(bytes + 44, 2);

    PutBe32(bytes + 96, 2);
    PutBe32(bytes + 100, 224);
    PutBe32(bytes + 104, 96);
    PutBe32(bytes + 108, 0x00900000);
    PutBe32(bytes + 112, 64);
    PutBe32(bytes + 120, 32);

    // The logical first payload ends exactly at 288, but its stored padding
    // extends to 320 and aliases this second section.
    PutBe32(bytes + 160, 2);
    PutBe32(bytes + 164, 288);
    PutBe32(bytes + 168, 64);
    PutBe32(bytes + 172, 0x00910000);
    PutBe32(bytes + 176, 64);
}

u32 McuDescriptor0(u32 byte_count)
{
    return byte_count | (2u << 23) | (0x20u << 25);
}

constexpr u64 kLegacyMcuBytes = 68;

void MakeValidLegacyMcu(u8* bytes)
{
    Clear(bytes, kLegacyMcuBytes);
    PutLe32(bytes, McuDescriptor0(kLegacyMcuBytes));
    PutLe32(bytes + 4, 0x80010000);
    PutLe16(bytes + 32, static_cast<u16>(kLegacyMcuBytes - 32));
    PutLe16(bytes + 34, 0x8000);
    bytes[36] = 1;
    bytes[37] = 0xA0;
    bytes[38] = 3;
    bytes[39] = 1;
}

constexpr u64 kUnifiedMcuBytes = 52;

void MakeValidUnifiedMcu(u8* bytes)
{
    Clear(bytes, kUnifiedMcuBytes);
    PutLe32(bytes, McuDescriptor0(kUnifiedMcuBytes));
    PutLe32(bytes + 4, 0x80010000);
    PutLe16(bytes + 32, static_cast<u16>(kUnifiedMcuBytes - 32));
    PutLe16(bytes + 34, 0x1234);
    bytes[37] = 0xA0;
    bytes[39] = 1;
    bytes[43] = 7;
}

constexpr RingLayout kValidRings[] = {
    {RingKind::DataTx, 0x00100000, 2048, 16},
    {RingKind::McuCommandTx, 0x00108000, 256, 16},
    {RingKind::FirmwareDownloadTx, 0x00109000, 128, 16},
    {RingKind::DataRx, 0x0010A000, 1536, 16},
    {RingKind::McuEventRx, 0x00110000, 8, 16},
    {RingKind::McuWaRx, 0x00111000, 512, 16},
};

void TestIdentity()
{
    PciIdentity identity = ValidIdentity();
    EXPECT_EQ(ValidateIdentity(identity), Status::Ok);

    identity.subsystem_known = false;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciIdentity);
    identity = ValidIdentity();
    identity.subsystem_vendor_id = 0x14C3;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciIdentity);
    identity = ValidIdentity();
    identity.subsystem_device_id = 0xE0B6;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciIdentity);
    identity = ValidIdentity();
    identity.base_class = 0x01;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciClass);
    identity = ValidIdentity();
    identity.subclass = 0x00;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciClass);
    identity = ValidIdentity();
    identity.programming_interface = 1;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciClass);
    identity = ValidIdentity();
    identity.revision_id = 1;
    EXPECT_EQ(ValidateIdentity(identity), Status::WrongPciRevision);
}

void TestBarAndRegisterWindows()
{
    BarResource bar = ValidBar();
    EXPECT_EQ(ValidateBar(bar), Status::Ok);
    bar.index = 1;
    EXPECT_EQ(ValidateBar(bar), Status::WrongBar);
    bar = ValidBar();
    bar.extent_bytes = kMinimumBarBytes - 1;
    EXPECT_EQ(ValidateBar(bar), Status::BarTooSmall);
    bar = ValidBar();
    bar.physical_base = ~0ull - kMinimumBarBytes + 2;
    EXPECT_EQ(ValidateBar(bar), Status::WrongBar);
    bar = ValidBar();
    bar.physical_base = 0xFFFFFFFFFFF00000ull;
    bar.extent_bytes = 2 * kMinimumBarBytes;
    EXPECT_EQ(ValidateBar(bar), Status::AddressOverflow);

    RegisterAccessPlan plan = {};
    EXPECT_EQ(PlanRegisterAccess(kL1RemapRegisterOffset, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::Direct);
    EXPECT_EQ(plan.bar_offset, kL1RemapRegisterOffset);
    EXPECT_EQ(PlanRegisterAccess(0x000FFFFC, 4, &plan), Status::Ok);

    EXPECT_EQ(PlanRegisterAccess(0x18000000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::L1Remap);
    EXPECT_EQ(plan.bar_offset, kL1WindowOffset);
    EXPECT_EQ(plan.remap_selector, 0x1800);
    EXPECT_EQ(PlanRegisterAccess(0x18BFFFFC, 4, &plan), Status::Ok);
    EXPECT_EQ(PlanRegisterAccess(0x18C00000, 4, &plan), Status::UnsupportedRegister);
    EXPECT_EQ(PlanRegisterAccess(0x78000000, 4, &plan), Status::UnsupportedRegister);
    EXPECT_EQ(PlanRegisterAccess(0x7C400000, 4, &plan), Status::UnsupportedRegister);
    EXPECT_EQ(PlanRegisterAccess(0xFFFFFFFF, 4, &plan), Status::AddressOverflow);
    EXPECT_EQ(PlanRegisterAccess(0x70000002, 4, &plan), Status::RegisterMisaligned);
    EXPECT_EQ(PlanRegisterAccess(0x70000000, 8, &plan), Status::InvalidArgument);
    EXPECT_EQ(plan.width_bytes, 0u);
    EXPECT_EQ(plan.generation, 0u);
    EXPECT_EQ(PlanRegisterAccess(0x70000000, 4, nullptr), Status::InvalidArgument);

    bar = ValidBar();
    bar.extent_bytes = 0x180000;
    bar.mapped_bytes = kMinimumBarBytes;
    EXPECT_EQ(ValidateBar(bar), Status::WrongBar);
    bar = ValidBar();
    bar.physical_base = 0x0000007C02300000ull;
    bar.extent_bytes = 2 * kMinimumBarBytes;
    bar.mapped_bytes = kMinimumBarBytes;
    EXPECT_EQ(ValidateBar(bar), Status::WrongBar);
}

void TestFixedRegisterWindows()
{
    FixedRegisterWindow windows[kFixedRegisterWindowCount] = {};
    for (u32 i = 0; i < kFixedRegisterWindowCount; ++i)
    {
        EXPECT_EQ(FixedRegisterWindowAt(i, &windows[i]), Status::Ok);
        EXPECT_TRUE(windows[i].window_bytes != 0);
        EXPECT_TRUE(windows[i].chip_base >= kMinimumBarBytes);
        const u64 bar_end = static_cast<u64>(windows[i].bar_offset) + windows[i].window_bytes;
        EXPECT_TRUE(bar_end <= kMinimumBarBytes);
        EXPECT_FALSE(windows[i].bar_offset < kL1WindowOffset + kL1WindowBytes && kL1WindowOffset < bar_end);
        for (u32 prior = 0; prior < i; ++prior)
        {
            const u64 prior_chip_end = static_cast<u64>(windows[prior].chip_base) + windows[prior].window_bytes;
            const u64 prior_bar_end = static_cast<u64>(windows[prior].bar_offset) + windows[prior].window_bytes;
            const u64 chip_end = static_cast<u64>(windows[i].chip_base) + windows[i].window_bytes;
            EXPECT_FALSE(windows[i].chip_base < prior_chip_end && windows[prior].chip_base < chip_end);
            EXPECT_FALSE(windows[i].bar_offset < prior_bar_end && windows[prior].bar_offset < bar_end);
        }
    }
    FixedRegisterWindow window = {};
    window.chip_base = 0xFFFFFFFFu;
    window.bar_offset = 0xFFFFFFFFu;
    window.window_bytes = 0xFFFFFFFFu;
    EXPECT_EQ(FixedRegisterWindowAt(kFixedRegisterWindowCount, &window), Status::InvalidArgument);
    EXPECT_EQ(window.chip_base, 0u);
    EXPECT_EQ(window.bar_offset, 0u);
    EXPECT_EQ(window.window_bytes, 0u);
    EXPECT_EQ(FixedRegisterWindowAt(0, nullptr), Status::InvalidArgument);

    RegisterAccessPlan plan = {};
    EXPECT_EQ(PlanRegisterAccess(0x820D0000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::FixedMap);
    EXPECT_EQ(plan.bar_offset, 0x30000u);
    EXPECT_EQ(plan.generation, 0u);
    EXPECT_EQ(PlanRegisterAccess(0x820DFFFC, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.bar_offset, 0x3FFFCu);
    EXPECT_EQ(PlanRegisterAccess(0x54000000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::FixedMap);
    EXPECT_EQ(plan.bar_offset, 0x02000u);
    EXPECT_EQ(PlanRegisterAccess(0x00400000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.bar_offset, 0x80000u);
    EXPECT_EQ(PlanRegisterAccess(0x0041FFFC, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.bar_offset, 0x9FFFCu);
    EXPECT_EQ(PlanRegisterAccess(0x820FD7FC, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.bar_offset, 0xA4FFCu);

    EXPECT_EQ(PlanRegisterAccess(0x7C000000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::FixedMap);
    EXPECT_EQ(plan.bar_offset, 0xF0000u);
    EXPECT_EQ(PlanRegisterAccess(0x74030000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::FixedMap);
    EXPECT_EQ(plan.bar_offset, 0x10000u);
    EXPECT_EQ(PlanRegisterAccess(0x7C010000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::L1Remap);
    EXPECT_EQ(plan.remap_selector, 0x7C01);
    EXPECT_EQ(plan.bar_offset, kL1WindowOffset);
    EXPECT_EQ(PlanRegisterAccess(0x74040000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::L1Remap);
    EXPECT_EQ(plan.remap_selector, 0x7404);

    EXPECT_EQ(PlanRegisterAccess(0x820C4000, 4, &plan), Status::UnsupportedRegister);
    EXPECT_EQ(PlanRegisterAccess(0x00420000, 4, &plan), Status::UnsupportedRegister);
    EXPECT_EQ(PlanRegisterAccess(0x820FD800, 4, &plan), Status::UnsupportedRegister);
}

void TestFirmwareContainers()
{
    u8 ram[kRamBytes];
    u8 patch[kPatchBytes];
    FirmwareSummary summary = {};
    MakeValidRam(ram);
    MakeValidPatch(patch);

    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, ram, sizeof(ram), &summary), Status::Ok);
    EXPECT_EQ(summary.kind, FirmwareKind::WifiRam);
    EXPECT_EQ(summary.region_count, 2u);
    EXPECT_EQ(summary.download_region_count, 1u);
    EXPECT_EQ(summary.metadata_region_count, 1u);
    EXPECT_EQ(summary.payload_bytes, 80u);
    EXPECT_EQ(summary.table_offset, 80u);
    EXPECT_EQ(summary.start_override_address, 0x00915000u);
    EXPECT_FALSE(summary.requires_encrypted_download);

    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, patch, sizeof(patch), &summary), Status::Ok);
    EXPECT_EQ(summary.kind, FirmwareKind::RomPatch);
    EXPECT_EQ(summary.region_count, 1u);
    EXPECT_EQ(summary.payload_bytes, 64u);

    u8 bad_ram[kRamBytes];
    MakeValidRam(bad_ram);
    PutLe32(bad_ram + 80 + 20, 81);
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, bad_ram, sizeof(bad_ram), &summary),
              Status::FirmwareRegionOutOfBounds);

    MakeValidRam(bad_ram);
    bad_ram[162] = 5;
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, bad_ram, sizeof(bad_ram), &summary),
              Status::FirmwareTableOutOfBounds);

    MakeValidRam(bad_ram);
    bad_ram[163] = 3;
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, bad_ram, sizeof(bad_ram), &summary),
              Status::UnsupportedFirmwareFormat);

    MakeValidRam(bad_ram);
    bad_ram[80 + 24] = 0x28;
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, bad_ram, sizeof(bad_ram), &summary),
              Status::FirmwareRegionInvalid);

    // A later-region rejection must not expose the first region's partially
    // accumulated counts or override address through the output summary.
    MakeValidRam(bad_ram);
    PutLe32(bad_ram + 80 + 40 + 20, 0);
    summary.region_count = 0xFFFFFFFFu;
    summary.download_region_count = 0xFFFFFFFFu;
    summary.start_override_address = 0xFFFFFFFFu;
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, bad_ram, sizeof(bad_ram), &summary),
              Status::FirmwareRegionInvalid);
    EXPECT_EQ(summary.region_count, 0u);
    EXPECT_EQ(summary.download_region_count, 0u);
    EXPECT_EQ(summary.start_override_address, 0u);

    u8 overlap[kOverlapPatchBytes];
    MakeOverlappingPatch(overlap);
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, overlap, sizeof(overlap), &summary),
              Status::FirmwareRegionOverlap);

    MakePaddingOverlapPatch(overlap);
    PutBe32(overlap + 96 + 20, 0x01000000);
    summary.requires_encrypted_download = true;
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, overlap, sizeof(overlap), &summary),
              Status::FirmwareRegionOverlap);
    EXPECT_FALSE(summary.requires_encrypted_download);
    EXPECT_EQ(summary.region_count, 0u);
    EXPECT_EQ(summary.payload_bytes, 0u);

    u8 truncated[159];
    Clear(truncated, sizeof(truncated));
    PutBe32(truncated + 32, 0x44332211);
    PutBe32(truncated + 44, 1);
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, truncated, sizeof(truncated), &summary),
              Status::FirmwareTableOutOfBounds);

    u8 bad_patch[kPatchBytes];
    MakeValidPatch(bad_patch);
    PutBe32(bad_patch + 100, 200);
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, bad_patch, sizeof(bad_patch), &summary),
              Status::FirmwareRegionOutOfBounds);

    MakeValidPatch(bad_patch);
    PutBe32(bad_patch + 32, 0x11223344);
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, bad_patch, sizeof(bad_patch), &summary),
              Status::UnsupportedFirmwareFormat);

    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, nullptr, sizeof(ram), &summary),
              Status::InvalidArgument);
    EXPECT_EQ(summary.region_count, 0u);
    EXPECT_EQ(summary.payload_bytes, 0u);
    summary.region_count = 0xFFFFFFFFu;
    summary.payload_bytes = 0xFFFFFFFFu;
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, ram, sizeof(ram), nullptr), Status::InvalidArgument);
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, ram, kMaximumFirmwareBytes + 1, &summary),
              Status::FirmwareTooLarge);
    EXPECT_EQ(summary.region_count, 0u);
    EXPECT_EQ(summary.payload_bytes, 0u);
}

void TestCurrentLinuxFirmwareMetadataShape()
{
    // linux-firmware metadata observed 2026-08-01. Payload bytes remain zero:
    // this pins the public container geometry without redistributing firmware.
    constexpr u32 kCurrentRamBytes = 792036;
    constexpr u32 kCurrentRamTrailer = 792000;
    constexpr u32 kCurrentRamTable = 791800;
    static u8 ram[kCurrentRamBytes];
    Clear(ram, sizeof(ram));

    constexpr u32 kAddresses[] = {0x00915000, 0x02015C00, 0x00404400, 0xE0270000, 0};
    constexpr u32 kLengths[] = {363536, 272400, 15376, 51920, 88416};
    for (u32 i = 0; i < 5; ++i)
    {
        const u32 region = kCurrentRamTable + i * 40;
        PutLe32(ram + region + 16, kAddresses[i]);
        PutLe32(ram + region + 20, kLengths[i]);
    }
    ram[kCurrentRamTable + 24] = 0x20;
    ram[kCurrentRamTable + 4 * 40 + 24] = 0x40;
    ram[kCurrentRamTable + 4 * 40 + 25] = 2;
    ram[kCurrentRamTrailer] = 0x0D;
    ram[kCurrentRamTrailer + 1] = 1;
    ram[kCurrentRamTrailer + 2] = 5;
    ram[kCurrentRamTrailer + 3] = 2;
    ram[kCurrentRamTrailer + 4] = 1;

    FirmwareSummary summary = {};
    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::WifiRam, ram, sizeof(ram), &summary), Status::Ok);
    EXPECT_EQ(summary.region_count, 5u);
    EXPECT_EQ(summary.download_region_count, 4u);
    EXPECT_EQ(summary.metadata_region_count, 1u);
    EXPECT_EQ(summary.payload_bytes, 791648u);
    EXPECT_EQ(summary.metadata_bytes, 152u);
    EXPECT_EQ(summary.start_override_address, 0x00915000u);

    constexpr u32 kCurrentPatchBytes = 92192;
    static u8 patch[kCurrentPatchBytes];
    Clear(patch, sizeof(patch));
    PutBe32(patch + 32, 0x44332211);
    PutBe32(patch + 44, 1);
    PutBe32(patch + 96, 0x00040002);
    PutBe32(patch + 100, 160);
    PutBe32(patch + 104, 92032);
    PutBe32(patch + 108, 0x00900000);
    PutBe32(patch + 112, 92032);

    EXPECT_EQ(ValidateFirmwareContainer(FirmwareKind::RomPatch, patch, sizeof(patch), &summary), Status::Ok);
    EXPECT_EQ(summary.region_count, 1u);
    EXPECT_EQ(summary.payload_bytes, 92032u);
    EXPECT_EQ(summary.metadata_bytes, 160u);
}

void TestMcuEnvelopes()
{
    u8 legacy[kLegacyMcuBytes];
    u8 unified[kUnifiedMcuBytes];
    McuSummary summary = {};
    MakeValidLegacyMcu(legacy);
    MakeValidUnifiedMcu(unified);

    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, legacy, sizeof(legacy), &summary), Status::Ok);
    EXPECT_EQ(summary.descriptor_bytes, 64u);
    EXPECT_EQ(summary.payload_bytes, 4u);
    EXPECT_EQ(summary.sequence, 1u);
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Unified, unified, sizeof(unified), &summary), Status::Ok);
    EXPECT_EQ(summary.descriptor_bytes, 48u);

    u8 bad_legacy[kLegacyMcuBytes];
    MakeValidLegacyMcu(bad_legacy);
    PutLe16(bad_legacy + 32, 1);
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, bad_legacy, sizeof(bad_legacy), &summary),
              Status::McuLengthMismatch);
    MakeValidLegacyMcu(bad_legacy);
    bad_legacy[39] = 0;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, bad_legacy, sizeof(bad_legacy), &summary),
              Status::McuFieldInvalid);
    MakeValidLegacyMcu(bad_legacy);
    bad_legacy[38] = 2;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, bad_legacy, sizeof(bad_legacy), &summary),
              Status::McuFieldInvalid);
    MakeValidLegacyMcu(bad_legacy);
    bad_legacy[63] = 1;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, bad_legacy, sizeof(bad_legacy), &summary),
              Status::McuFieldInvalid);

    u8 bad_unified[kUnifiedMcuBytes];
    MakeValidUnifiedMcu(bad_unified);
    PutLe32(bad_unified, McuDescriptor0(kUnifiedMcuBytes - 1));
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Unified, bad_unified, sizeof(bad_unified), &summary),
              Status::McuLengthMismatch);
    MakeValidUnifiedMcu(bad_unified);
    bad_unified[39] = 16;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Unified, bad_unified, sizeof(bad_unified), &summary),
              Status::McuFieldInvalid);
    MakeValidUnifiedMcu(bad_unified);
    bad_unified[43] = 0x82;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Unified, bad_unified, sizeof(bad_unified), &summary),
              Status::McuFieldInvalid);
    MakeValidUnifiedMcu(bad_unified);
    bad_unified[47] = 1;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Unified, bad_unified, sizeof(bad_unified), &summary),
              Status::McuFieldInvalid);

    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, legacy, 63, &summary), Status::McuEnvelopeTooSmall);
    EXPECT_EQ(summary.descriptor_bytes, 0u);
    EXPECT_EQ(summary.payload_bytes, 0u);
    summary.descriptor_bytes = 0xFFFFu;
    summary.payload_bytes = 0xFFFFu;
    EXPECT_EQ(ValidateMcuEnvelope(McuEnvelopeKind::Legacy, nullptr, sizeof(legacy), &summary), Status::InvalidArgument);
    EXPECT_EQ(summary.descriptor_bytes, 0u);
    EXPECT_EQ(summary.payload_bytes, 0u);
}

void TestRingLayouts()
{
    for (const RingLayout& ring : kValidRings)
    {
        u64 ring_bytes = 0;
        EXPECT_EQ(ValidateRingLayout(ring, &ring_bytes), Status::Ok);
        EXPECT_EQ(ring_bytes, ring.descriptor_count * ring.descriptor_bytes);
    }

    u64 ring_bytes = 0;
    RingLayout bad = kValidRings[0];
    bad.descriptor_dma_base += 1;
    EXPECT_EQ(ValidateRingLayout(bad, &ring_bytes), Status::RingDmaAddressInvalid);

    bad = kValidRings[0];
    bad.descriptor_count = ~0ull;
    bad.descriptor_bytes = 16;
    EXPECT_EQ(ValidateRingLayout(bad, &ring_bytes), Status::RingByteCountOverflow);

    bad = kValidRings[0];
    bad.descriptor_count = 2047;
    EXPECT_EQ(ValidateRingLayout(bad, &ring_bytes), Status::RingCountInvalid);

    bad = kValidRings[0];
    bad.descriptor_bytes = 32;
    EXPECT_EQ(ValidateRingLayout(bad, &ring_bytes), Status::RingDescriptorInvalid);

    bad = kValidRings[0];
    bad.descriptor_dma_base = 0xFFFF8010ull;
    EXPECT_EQ(ValidateRingLayout(bad, &ring_bytes), Status::RingDmaAddressInvalid);

    bad = kValidRings[0];
    bad.kind = static_cast<RingKind>(0xFF);
    EXPECT_EQ(ValidateRingLayout(bad, &ring_bytes), Status::RingKindInvalid);
    EXPECT_EQ(ValidateRingLayout(kValidRings[0], nullptr), Status::InvalidArgument);
}

void AdvanceToFirmware(ContractState* state, const u8* patch, const u8* ram)
{
    EXPECT_EQ(ContractAcceptIdentity(state, ValidIdentity()), Status::Ok);
    EXPECT_EQ(ContractAcceptBar(state, ValidBar()), Status::Ok);
    EXPECT_EQ(ContractAcceptFirmwareSet(state, patch, kPatchBytes, ram, kRamBytes), Status::Ok);
}

void TestRingSetDmaAliasing()
{
    u8 patch[kPatchBytes];
    u8 ram[kRamBytes];
    MakeValidPatch(patch);
    MakeValidRam(ram);

    RingLayout rings[static_cast<u32>(RingKind::Count)];
    for (u32 i = 0; i < static_cast<u32>(RingKind::Count); ++i)
        rings[i] = kValidRings[i];

    // End-exclusive adjacency is valid and must not be treated as overlap.
    rings[1].descriptor_dma_base = rings[0].descriptor_dma_base + rings[0].descriptor_count * rings[0].descriptor_bytes;
    ContractState adjacent = {};
    AdvanceToFirmware(&adjacent, patch, ram);
    EXPECT_EQ(ContractAcceptRingSet(&adjacent, rings, static_cast<u64>(RingKind::Count)), Status::Ok);

    rings[1].descriptor_dma_base = rings[0].descriptor_dma_base;
    ContractState exact_alias = {};
    AdvanceToFirmware(&exact_alias, patch, ram);
    EXPECT_EQ(ContractAcceptRingSet(&exact_alias, rings, static_cast<u64>(RingKind::Count)),
              Status::RingDmaAddressInvalid);
    EXPECT_EQ(exact_alias.phase, ContractPhase::Failed);

    rings[1].descriptor_dma_base = rings[0].descriptor_dma_base +
                                   rings[0].descriptor_count * rings[0].descriptor_bytes - rings[1].descriptor_bytes;
    ContractState partial_alias = {};
    AdvanceToFirmware(&partial_alias, patch, ram);
    EXPECT_EQ(ContractAcceptRingSet(&partial_alias, rings, static_cast<u64>(RingKind::Count)),
              Status::RingDmaAddressInvalid);
    EXPECT_EQ(partial_alias.phase, ContractPhase::Failed);
}

void TestContractRegisterPlanning()
{
    u8 patch[kPatchBytes];
    u8 ram[kRamBytes];
    MakeValidPatch(patch);
    MakeValidRam(ram);

    // Generation zero is reserved for stateless plans. A normal first
    // lifecycle mints generation one before any contract-stamped plan can be
    // returned, and a forged active phase with generation zero fails closed.
    ContractState first_lifecycle = {};
    EXPECT_EQ(ContractAcceptIdentity(&first_lifecycle, ValidIdentity()), Status::Ok);
    EXPECT_EQ(first_lifecycle.generation, 1u);
    EXPECT_EQ(ContractAcceptBar(&first_lifecycle, ValidBar()), Status::Ok);
    RegisterAccessPlan first_plan = {};
    EXPECT_EQ(ContractPlanRegisterAccess(&first_lifecycle, 0x820D0000, 4, &first_plan), Status::Ok);
    EXPECT_EQ(first_plan.generation, 1u);
    EXPECT_EQ(ContractBeginTeardown(&first_lifecycle), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&first_lifecycle), Status::Ok);
    EXPECT_EQ(first_lifecycle.generation, 2u);

    ContractState forged_zero_generation = {ContractPhase::BarAccepted, Status::Ok, 0};
    RegisterAccessPlan poisoned_plan = {RegisterPath::L1Remap, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFu, 0xFFFFu,
                                        0xFFFFFFFFFFFFFFFFull};
    EXPECT_EQ(ContractPlanRegisterAccess(&forged_zero_generation, 0x820D0000, 4, &poisoned_plan),
              Status::InvalidStateTransition);
    EXPECT_EQ(forged_zero_generation.phase, ContractPhase::Failed);
    EXPECT_EQ(poisoned_plan.bar_offset, 0u);
    EXPECT_EQ(poisoned_plan.generation, 0u);

    ContractState state = {};
    RegisterAccessPlan plan = {};
    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x820D0000, 4, &plan), Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);

    EXPECT_EQ(ContractAcceptIdentity(&state, ValidIdentity()), Status::Ok);
    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x820D0000, 4, &plan), Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);

    EXPECT_EQ(ContractAcceptIdentity(&state, ValidIdentity()), Status::Ok);
    EXPECT_EQ(ContractAcceptBar(&state, ValidBar()), Status::Ok);
    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x820D0000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::FixedMap);
    EXPECT_EQ(plan.generation, state.generation);
    const u64 stale_generation = plan.generation;
    EXPECT_EQ(ContractAcceptFirmwareSet(&state, patch, kPatchBytes, ram, kRamBytes), Status::Ok);
    EXPECT_EQ(ContractPlanRegisterAccess(&state, kL1RemapRegisterOffset, 4, &plan), Status::Ok);
    EXPECT_EQ(ContractAcceptRingSet(&state, kValidRings, static_cast<u64>(RingKind::Count)), Status::Ok);
    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x7C010000, 4, &plan), Status::Ok);
    EXPECT_EQ(plan.path, RegisterPath::L1Remap);

    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x820C4000, 4, &plan), Status::UnsupportedRegister);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x820D0000, 4, &plan), Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);

    EXPECT_EQ(ContractAcceptIdentity(&state, ValidIdentity()), Status::Ok);
    EXPECT_EQ(ContractAcceptBar(&state, ValidBar()), Status::Ok);
    RegisterAccessPlan fresh = {};
    EXPECT_EQ(ContractPlanRegisterAccess(&state, 0x820D0000, 4, &fresh), Status::Ok);
    EXPECT_TRUE(fresh.generation != stale_generation);
    EXPECT_EQ(fresh.generation, state.generation);

    fresh.generation = 0xFFFFFFFFFFFFFFFFull;
    fresh.bar_offset = 0xFFFFFFFFu;
    EXPECT_EQ(ContractPlanRegisterAccess(nullptr, 0x820D0000, 4, &fresh), Status::InvalidArgument);
    EXPECT_EQ(fresh.generation, 0u);
    EXPECT_EQ(fresh.bar_offset, 0u);
}

void TestStateMachine()
{
    u8 patch[kPatchBytes];
    u8 ram[kRamBytes];
    MakeValidPatch(patch);
    MakeValidRam(ram);

    ContractState state = {};
    EXPECT_EQ(state.phase, ContractPhase::Cold);
    EXPECT_EQ(ContractAcceptBar(&state, ValidBar()), Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);
    EXPECT_EQ(state.phase, ContractPhase::Cold);
    EXPECT_EQ(state.generation, 1u);

    EXPECT_EQ(ContractAcceptIdentity(&state, ValidIdentity()), Status::Ok);
    EXPECT_EQ(ContractAcceptIdentity(&state, ValidIdentity()), Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);

    AdvanceToFirmware(&state, patch, ram);
    EXPECT_EQ(ContractAcceptRingSet(&state, kValidRings, static_cast<u64>(RingKind::Count)), Status::Ok);
    EXPECT_EQ(state.phase, ContractPhase::ReadyForHardwareBringUp);
    EXPECT_EQ(ContractAcceptRingSet(&state, kValidRings, static_cast<u64>(RingKind::Count)),
              Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);

    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);
    const u64 reuse_generation = state.generation;
    AdvanceToFirmware(&state, patch, ram);

    RingLayout duplicate[static_cast<u32>(RingKind::Count)];
    for (u32 i = 0; i < static_cast<u32>(RingKind::Count); ++i)
        duplicate[i] = kValidRings[i];
    duplicate[5] = duplicate[4];
    EXPECT_EQ(ContractAcceptRingSet(&state, duplicate, static_cast<u64>(RingKind::Count)), Status::RingSetIncomplete);
    EXPECT_EQ(state.phase, ContractPhase::Failed);

    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);
    EXPECT_EQ(state.generation, reuse_generation + 1);
    AdvanceToFirmware(&state, patch, ram);
    EXPECT_EQ(ContractAcceptRingSet(&state, kValidRings, static_cast<u64>(RingKind::Count)), Status::Ok);
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(state.phase, ContractPhase::TeardownPending);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::Ok);
    EXPECT_EQ(state.phase, ContractPhase::Cold);

    EXPECT_EQ(ContractFinishTeardown(&state), Status::InvalidStateTransition);
    EXPECT_EQ(state.phase, ContractPhase::Failed);
    state.generation = ~0ull;
    EXPECT_EQ(ContractBeginTeardown(&state), Status::Ok);
    EXPECT_EQ(ContractFinishTeardown(&state), Status::AddressOverflow);
    EXPECT_EQ(state.phase, ContractPhase::Failed);

    EXPECT_EQ(ContractAcceptIdentity(nullptr, ValidIdentity()), Status::InvalidArgument);
    EXPECT_STREQ(StatusName(static_cast<Status>(0xFF)), "unknown");
}

} // namespace

int main()
{
    TestIdentity();
    TestBarAndRegisterWindows();
    TestFixedRegisterWindows();
    TestFirmwareContainers();
    TestCurrentLinuxFirmwareMetadataShape();
    TestMcuEnvelopes();
    TestRingLayouts();
    TestRingSetDmaAliasing();
    TestContractRegisterPlanning();
    TestStateMachine();
    return duetos_host_test::finish_main("mt7921_contract");
}
