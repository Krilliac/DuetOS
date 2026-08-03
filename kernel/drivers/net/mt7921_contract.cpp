#include "drivers/net/mt7921_contract.h"

namespace duetos::drivers::net::mt7921
{

namespace
{

constexpr u64 kU64Maximum = ~0ull;
constexpr u64 kU32AddressSpaceBytes = 0x100000000ull;
constexpr u32 kPatchHeaderBytes = 96;
constexpr u32 kPatchRegionBytes = 64;
constexpr u32 kRamTrailerBytes = 36;
constexpr u32 kRamRegionBytes = 40;
constexpr u32 kMaximumRegions = 32;
constexpr u8 kRamFormatVersion = 2;
constexpr u32 kPatchDescriptorVersion = 0x44332211;
constexpr u32 kPatchRegionTypeInformation = 2;
constexpr u8 kRamFeatureKnownMask = 0x77;
constexpr u8 kRamFeatureEncryptedMask = 0x11;
constexpr u8 kRamFeatureOverrideAddress = 0x20;
constexpr u8 kRamFeatureNonDownload = 0x40;
constexpr u32 kDmaDescriptorBytes = 16;
constexpr u32 kMcuPacketType = 0xA0;

u16 ReadLe16(const u8* bytes)
{
    return static_cast<u16>(bytes[0]) | static_cast<u16>(static_cast<u16>(bytes[1]) << 8);
}

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8) | (static_cast<u32>(bytes[2]) << 16) |
           (static_cast<u32>(bytes[3]) << 24);
}

u32 ReadBe32(const u8* bytes)
{
    return (static_cast<u32>(bytes[0]) << 24) | (static_cast<u32>(bytes[1]) << 16) | (static_cast<u32>(bytes[2]) << 8) |
           static_cast<u32>(bytes[3]);
}

bool IsZero(const u8* bytes, u32 count)
{
    for (u32 i = 0; i < count; ++i)
    {
        if (bytes[i] != 0)
            return false;
    }
    return true;
}

bool AddOverflows(u64 first, u64 second)
{
    return second > kU64Maximum - first;
}

bool IsL1PhysicalAddress(u32 address)
{
    return (address >= 0x18000000 && address < 0x18C00000) || (address >= 0x70000000 && address < 0x78000000) ||
           (address >= 0x7C000000 && address < 0x7C400000);
}

// Exact BAR0 fixed decode of the MT7921 host bridge. Re-derived from the
// public upstream mt76 MT7921 PCI implementation; fixed windows take
// precedence over L1 remap where their chip-address ranges overlap.
constexpr FixedRegisterWindow kFixedWindows[kFixedRegisterWindowCount] = {
    {0x00400000, 0x80000, 0x10000}, // WF_MCU_SYSRAM
    {0x00410000, 0x90000, 0x10000}, // WF_MCU_SYSRAM configuration
    {0x40000000, 0x70000, 0x10000}, // WF_UMAC_SYSRAM
    {0x54000000, 0x02000, 0x01000}, // WFDMA PCIE0 MCU DMA0
    {0x55000000, 0x03000, 0x01000}, // WFDMA PCIE0 MCU DMA1
    {0x58000000, 0x06000, 0x01000}, // WFDMA PCIE1 MCU DMA0
    {0x59000000, 0x07000, 0x01000}, // WFDMA PCIE1 MCU DMA1
    {0x74030000, 0x10000, 0x10000}, // PCIE_MAC_IREG
    {0x7C000000, 0xF0000, 0x10000}, // CONN_INFRA
    {0x7C020000, 0xD0000, 0x10000}, // CONN_INFRA WFDMA
    {0x7C060000, 0xE0000, 0x10000}, // CONN_INFRA host CSR
    {0x80020000, 0xB0000, 0x10000}, // WF_TOP_MISC_OFF
    {0x81020000, 0xC0000, 0x10000}, // WF_TOP_MISC_ON
    {0x820C0000, 0x08000, 0x04000}, // WF_UMAC_TOP PLE
    {0x820C8000, 0x0C000, 0x02000}, // WF_UMAC_TOP PSE
    {0x820CC000, 0x0E000, 0x01000}, // WF_UMAC_TOP PP
    {0x820CD000, 0x0F000, 0x01000}, // WF_MDP_TOP
    {0x820CE000, 0x21C00, 0x00200}, // WF_LMAC_TOP WF_SEC
    {0x820CF000, 0x22000, 0x01000}, // WF_LMAC_TOP WF_PF
    {0x820D0000, 0x30000, 0x10000}, // WF_LMAC_TOP WF_WTBLON
    {0x820E0000, 0x20000, 0x00400}, // WF_LMAC_TOP BN0 WF_CFG
    {0x820E1000, 0x20400, 0x00200}, // WF_LMAC_TOP BN0 WF_TRB
    {0x820E2000, 0x20800, 0x00400}, // WF_LMAC_TOP BN0 WF_AGG
    {0x820E3000, 0x20C00, 0x00400}, // WF_LMAC_TOP BN0 WF_ARB
    {0x820E4000, 0x21000, 0x00400}, // WF_LMAC_TOP BN0 WF_TMAC
    {0x820E5000, 0x21400, 0x00800}, // WF_LMAC_TOP BN0 WF_RMAC
    {0x820E7000, 0x21E00, 0x00200}, // WF_LMAC_TOP BN0 WF_DMA
    {0x820E9000, 0x23400, 0x00200}, // WF_LMAC_TOP BN0 WF_WTBLOFF
    {0x820EA000, 0x24000, 0x00200}, // WF_LMAC_TOP BN0 WF_ETBF
    {0x820EB000, 0x24200, 0x00400}, // WF_LMAC_TOP BN0 WF_LPON
    {0x820EC000, 0x24600, 0x00200}, // WF_LMAC_TOP BN0 WF_INT
    {0x820ED000, 0x24800, 0x00800}, // WF_LMAC_TOP BN0 WF_MIB
    {0x820F0000, 0xA0000, 0x00400}, // WF_LMAC_TOP BN1 WF_CFG
    {0x820F1000, 0xA0600, 0x00200}, // WF_LMAC_TOP BN1 WF_TRB
    {0x820F2000, 0xA0800, 0x00400}, // WF_LMAC_TOP BN1 WF_AGG
    {0x820F3000, 0xA0C00, 0x00400}, // WF_LMAC_TOP BN1 WF_ARB
    {0x820F4000, 0xA1000, 0x00400}, // WF_LMAC_TOP BN1 WF_TMAC
    {0x820F5000, 0xA1400, 0x00800}, // WF_LMAC_TOP BN1 WF_RMAC
    {0x820F7000, 0xA1E00, 0x00200}, // WF_LMAC_TOP BN1 WF_DMA
    {0x820F9000, 0xA3400, 0x00200}, // WF_LMAC_TOP BN1 WF_WTBLOFF
    {0x820FA000, 0xA4000, 0x00200}, // WF_LMAC_TOP BN1 WF_ETBF
    {0x820FB000, 0xA4200, 0x00400}, // WF_LMAC_TOP BN1 WF_LPON
    {0x820FC000, 0xA4600, 0x00200}, // WF_LMAC_TOP BN1 WF_INT
    {0x820FD000, 0xA4800, 0x00800}, // WF_LMAC_TOP BN1 WF_MIB
};

constexpr bool FixedWindowsWellFormed()
{
    for (u32 i = 0; i < kFixedRegisterWindowCount; ++i)
    {
        const FixedRegisterWindow& window = kFixedWindows[i];
        if (window.window_bytes == 0 || (window.chip_base % sizeof(u32)) != 0 ||
            (window.bar_offset % sizeof(u32)) != 0 || (window.window_bytes % sizeof(u32)) != 0)
        {
            return false;
        }
        const u64 chip_end = static_cast<u64>(window.chip_base) + window.window_bytes;
        const u64 bar_end = static_cast<u64>(window.bar_offset) + window.window_bytes;
        if (window.chip_base < kMinimumBarBytes || chip_end > kU32AddressSpaceBytes || bar_end > kMinimumBarBytes)
            return false;
        if (window.bar_offset < kL1WindowOffset + kL1WindowBytes && kL1WindowOffset < bar_end)
            return false;
        for (u32 prior_index = 0; prior_index < i; ++prior_index)
        {
            const FixedRegisterWindow& prior = kFixedWindows[prior_index];
            const u64 prior_chip_end = static_cast<u64>(prior.chip_base) + prior.window_bytes;
            const u64 prior_bar_end = static_cast<u64>(prior.bar_offset) + prior.window_bytes;
            if (window.chip_base < prior_chip_end && prior.chip_base < chip_end)
                return false;
            if (window.bar_offset < prior_bar_end && prior.bar_offset < bar_end)
                return false;
        }
    }
    return true;
}

static_assert(FixedWindowsWellFormed(), "MT7921 fixed window table must be disjoint and inside the BAR aperture");

u64 ExpectedRingCount(RingKind kind)
{
    switch (kind)
    {
    case RingKind::DataTx:
        return 2048;
    case RingKind::McuCommandTx:
        return 256;
    case RingKind::FirmwareDownloadTx:
        return 128;
    case RingKind::DataRx:
        return 1536;
    case RingKind::McuEventRx:
        return 8;
    case RingKind::McuWaRx:
        return 512;
    case RingKind::Count:
    default:
        return 0;
    }
}

Status LatchFailure(ContractState* state, Status status)
{
    if (state != nullptr)
    {
        state->phase = ContractPhase::Failed;
        state->last_status = status;
    }
    return status;
}

Status ValidateWifiRam(const u8* bytes, u64 byte_count, FirmwareSummary* summary);
Status ValidateRomPatch(const u8* bytes, u64 byte_count, FirmwareSummary* summary);

} // namespace

Status ValidateRingLayout(const RingLayout& layout, u64* ring_bytes)
{
    if (ring_bytes == nullptr)
        return Status::InvalidArgument;
    *ring_bytes = 0;

    const u64 expected_count = ExpectedRingCount(layout.kind);
    if (expected_count == 0)
        return Status::RingKindInvalid;
    if (layout.descriptor_count != 0 && layout.descriptor_bytes > kU64Maximum / layout.descriptor_count)
        return Status::RingByteCountOverflow;

    const u64 bytes = layout.descriptor_count * layout.descriptor_bytes;
    if (layout.descriptor_bytes != kDmaDescriptorBytes)
        return Status::RingDescriptorInvalid;
    if (layout.descriptor_count != expected_count)
        return Status::RingCountInvalid;
    if (layout.descriptor_dma_base == 0 || (layout.descriptor_dma_base & (kDmaDescriptorBytes - 1)) != 0 ||
        AddOverflows(layout.descriptor_dma_base, bytes) || layout.descriptor_dma_base + bytes > kU32AddressSpaceBytes)
    {
        return Status::RingDmaAddressInvalid;
    }

    *ring_bytes = bytes;
    return Status::Ok;
}

Status ContractAcceptIdentity(ContractState* state, const PciIdentity& identity)
{
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase != ContractPhase::Cold)
        return LatchFailure(state, Status::InvalidStateTransition);
    const Status status = ValidateIdentity(identity);
    if (status != Status::Ok)
        return LatchFailure(state, status);
    if (state->generation == 0)
        state->generation = 1;
    state->phase = ContractPhase::IdentityAccepted;
    state->last_status = Status::Ok;
    return Status::Ok;
}

Status ContractAcceptBar(ContractState* state, const BarResource& bar)
{
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase != ContractPhase::IdentityAccepted || state->generation == 0)
        return LatchFailure(state, Status::InvalidStateTransition);
    const Status status = ValidateBar(bar);
    if (status != Status::Ok)
        return LatchFailure(state, status);
    state->phase = ContractPhase::BarAccepted;
    state->last_status = Status::Ok;
    return Status::Ok;
}

Status ContractAcceptFirmwareSet(ContractState* state, const u8* patch_bytes, u64 patch_byte_count, const u8* ram_bytes,
                                 u64 ram_byte_count)
{
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase != ContractPhase::BarAccepted || state->generation == 0)
        return LatchFailure(state, Status::InvalidStateTransition);

    FirmwareSummary patch = {};
    FirmwareSummary ram = {};
    Status status = ValidateFirmwareContainer(FirmwareKind::RomPatch, patch_bytes, patch_byte_count, &patch);
    if (status == Status::Ok)
        status = ValidateFirmwareContainer(FirmwareKind::WifiRam, ram_bytes, ram_byte_count, &ram);
    if (status == Status::Ok && (patch.requires_encrypted_download || ram.requires_encrypted_download))
        status = Status::UnsupportedFirmwareFormat;
    if (status != Status::Ok)
        return LatchFailure(state, status);

    state->phase = ContractPhase::FirmwareAccepted;
    state->last_status = Status::Ok;
    return Status::Ok;
}

Status ValidateFirmwareContainer(FirmwareKind kind, const u8* bytes, u64 byte_count, FirmwareSummary* summary)
{
    if (summary != nullptr)
        *summary = {};
    if (bytes == nullptr || summary == nullptr)
        return Status::InvalidArgument;
    if (byte_count > kMaximumFirmwareBytes)
        return Status::FirmwareTooLarge;

    FirmwareSummary staged = {};
    Status status = Status::UnsupportedFirmwareFormat;
    switch (kind)
    {
    case FirmwareKind::RomPatch:
        status = ValidateRomPatch(bytes, byte_count, &staged);
        break;
    case FirmwareKind::WifiRam:
        status = ValidateWifiRam(bytes, byte_count, &staged);
        break;
    default:
        break;
    }
    if (status == Status::Ok)
        *summary = staged;
    return status;
}

namespace
{

Status ValidateMcuHardwarePrefix(const u8* bytes, u64 byte_count)
{
    if (byte_count > 0xFFFFu)
        return Status::McuLengthMismatch;

    const u32 descriptor0 = ReadLe32(bytes);
    const u32 descriptor1 = ReadLe32(bytes + 4);
    const u32 declared_bytes = descriptor0 & 0xFFFFu;
    const u32 packet_format = (descriptor0 >> 23) & 0x3u;
    const u32 queue_index = (descriptor0 >> 25) & 0x7Fu;
    if (declared_bytes != byte_count)
        return Status::McuLengthMismatch;
    if (packet_format != 2 || queue_index != 0x20 || descriptor1 != 0x80010000u)
        return Status::McuFieldInvalid;
    return Status::Ok;
}

Status ValidateLegacyMcu(const u8* bytes, u64 byte_count, McuSummary* summary)
{
    constexpr u32 kDescriptorBytes = 64;
    if (byte_count < kDescriptorBytes)
        return Status::McuEnvelopeTooSmall;
    const Status prefix = ValidateMcuHardwarePrefix(bytes, byte_count);
    if (prefix != Status::Ok)
        return prefix;
    if (ReadLe16(bytes + 32) != byte_count - 32)
        return Status::McuLengthMismatch;

    const u16 queue_id = ReadLe16(bytes + 34);
    const u8 packet_type = bytes[37];
    const u8 set_query = bytes[38];
    const u8 sequence = bytes[39];
    const u8 ext_command = bytes[41];
    const u8 destination = bytes[42];
    const u8 wants_ext_ack = bytes[43];
    if (queue_id != 0x8000 || packet_type != kMcuPacketType || set_query == 2 || sequence == 0 || sequence > 15 ||
        bytes[40] != 0 || (destination != 0 && destination != 2) || wants_ext_ack > 1 ||
        ((ext_command == 0) != (wants_ext_ack == 0)) || !IsZero(bytes + 44, 20))
    {
        return Status::McuFieldInvalid;
    }

    summary->kind = McuEnvelopeKind::Legacy;
    summary->descriptor_bytes = kDescriptorBytes;
    summary->payload_bytes = static_cast<u16>(byte_count - kDescriptorBytes);
    summary->command_id = bytes[36];
    summary->sequence = sequence;
    summary->destination = destination;
    return Status::Ok;
}

Status ValidateUnifiedMcu(const u8* bytes, u64 byte_count, McuSummary* summary)
{
    constexpr u32 kDescriptorBytes = 48;
    if (byte_count < kDescriptorBytes)
        return Status::McuEnvelopeTooSmall;
    const Status prefix = ValidateMcuHardwarePrefix(bytes, byte_count);
    if (prefix != Status::Ok)
        return prefix;
    if (ReadLe16(bytes + 32) != byte_count - 32)
        return Status::McuLengthMismatch;

    const u8 packet_type = bytes[37];
    const u8 sequence = bytes[39];
    const u8 destination = bytes[42];
    const u8 options = bytes[43];
    if (bytes[36] != 0 || packet_type != kMcuPacketType || bytes[38] != 0 || sequence == 0 || sequence > 15 ||
        ReadLe16(bytes + 40) != 0 || destination != 0 || (options & ~7u) != 0 || (options & 2u) == 0 ||
        !IsZero(bytes + 44, 4))
    {
        return Status::McuFieldInvalid;
    }

    summary->kind = McuEnvelopeKind::Unified;
    summary->descriptor_bytes = kDescriptorBytes;
    summary->payload_bytes = static_cast<u16>(byte_count - kDescriptorBytes);
    summary->command_id = ReadLe16(bytes + 34);
    summary->sequence = sequence;
    summary->destination = destination;
    return Status::Ok;
}

} // namespace

Status ValidateMcuEnvelope(McuEnvelopeKind kind, const u8* bytes, u64 byte_count, McuSummary* summary)
{
    if (summary != nullptr)
        *summary = {};
    if (bytes == nullptr || summary == nullptr)
        return Status::InvalidArgument;
    McuSummary staged = {};
    Status status = Status::McuFieldInvalid;
    switch (kind)
    {
    case McuEnvelopeKind::Legacy:
        status = ValidateLegacyMcu(bytes, byte_count, &staged);
        break;
    case McuEnvelopeKind::Unified:
        status = ValidateUnifiedMcu(bytes, byte_count, &staged);
        break;
    default:
        break;
    }
    if (status == Status::Ok)
        *summary = staged;
    return status;
}

const char* StatusName(Status status)
{
    constexpr const char* kNames[] = {
        "ok",
        "invalid-argument",
        "wrong-pci-identity",
        "wrong-pci-class",
        "wrong-pci-revision",
        "wrong-bar",
        "bar-too-small",
        "address-overflow",
        "register-misaligned",
        "unsupported-register",
        "register-crosses-window",
        "firmware-too-small",
        "firmware-too-large",
        "unsupported-firmware-format",
        "firmware-region-count-invalid",
        "firmware-table-out-of-bounds",
        "firmware-region-out-of-bounds",
        "firmware-region-invalid",
        "firmware-region-overlap",
        "mcu-envelope-too-small",
        "mcu-length-mismatch",
        "mcu-field-invalid",
        "ring-kind-invalid",
        "ring-count-invalid",
        "ring-descriptor-invalid",
        "ring-byte-count-overflow",
        "ring-dma-address-invalid",
        "ring-set-incomplete",
        "invalid-state-transition",
    };
    static_assert(sizeof(kNames) / sizeof(kNames[0]) == static_cast<u32>(Status::InvalidStateTransition) + 1,
                  "StatusName table must cover every Status value");
    const u32 index = static_cast<u32>(status);
    if (index >= sizeof(kNames) / sizeof(kNames[0]))
        return "unknown";
    return kNames[index];
}

Status ValidateIdentity(const PciIdentity& identity)
{
    if (!identity.subsystem_known || identity.vendor_id != kPciVendorId || identity.device_id != kPciDeviceId ||
        identity.subsystem_vendor_id != kSubsystemVendorId || identity.subsystem_device_id != kSubsystemDeviceId)
    {
        return Status::WrongPciIdentity;
    }
    if (identity.base_class != kPciBaseClass || identity.subclass != kPciSubclass ||
        identity.programming_interface != kPciProgrammingInterface)
    {
        return Status::WrongPciClass;
    }
    if (identity.revision_id != kRevisionId)
        return Status::WrongPciRevision;
    return Status::Ok;
}

Status ValidateBar(const BarResource& bar)
{
    if (!bar.present || !bar.memory_space || !bar.is_64_bit || !bar.mapped_uncached || bar.index != kRequiredBarIndex ||
        bar.physical_base == 0)
    {
        return Status::WrongBar;
    }
    if (bar.extent_bytes < kMinimumBarBytes || bar.mapped_bytes < kMinimumBarBytes)
        return Status::BarTooSmall;
    if (bar.mapped_bytes > bar.extent_bytes || (bar.physical_base & (kMinimumBarBytes - 1)) != 0)
        return Status::WrongBar;
    if (AddOverflows(bar.physical_base, bar.extent_bytes - 1))
        return Status::AddressOverflow;
    if ((bar.extent_bytes & (bar.extent_bytes - 1)) != 0 || (bar.physical_base & (bar.extent_bytes - 1)) != 0)
        return Status::WrongBar;
    return Status::Ok;
}

Status PlanRegisterAccess(u32 physical_register, u32 width_bytes, RegisterAccessPlan* plan)
{
    if (plan != nullptr)
        *plan = {};
    if (plan == nullptr || width_bytes != sizeof(u32))
        return Status::InvalidArgument;

    const u64 end = static_cast<u64>(physical_register) + width_bytes;
    if (end > kU32AddressSpaceBytes)
        return Status::AddressOverflow;
    if ((physical_register & (sizeof(u32) - 1)) != 0)
        return Status::RegisterMisaligned;

    if (physical_register < kMinimumBarBytes)
    {
        if (end > kMinimumBarBytes)
            return Status::RegisterCrossesWindow;
        plan->path = RegisterPath::Direct;
        plan->bar_offset = physical_register;
        plan->width_bytes = static_cast<u16>(width_bytes);
        return Status::Ok;
    }

    for (u32 i = 0; i < kFixedRegisterWindowCount; ++i)
    {
        const FixedRegisterWindow& window = kFixedWindows[i];
        if (physical_register < window.chip_base || end > static_cast<u64>(window.chip_base) + window.window_bytes)
            continue;
        plan->path = RegisterPath::FixedMap;
        plan->bar_offset = window.bar_offset + (physical_register - window.chip_base);
        plan->width_bytes = static_cast<u16>(width_bytes);
        return Status::Ok;
    }

    if (!IsL1PhysicalAddress(physical_register))
        return Status::UnsupportedRegister;

    const u32 window_offset = physical_register & (kL1WindowBytes - 1);
    if (static_cast<u64>(window_offset) + width_bytes > kL1WindowBytes)
        return Status::RegisterCrossesWindow;

    plan->path = RegisterPath::L1Remap;
    plan->bar_offset = kL1WindowOffset + window_offset;
    plan->remap_register_offset = kL1RemapRegisterOffset;
    plan->remap_selector = static_cast<u16>(physical_register >> 16);
    plan->width_bytes = static_cast<u16>(width_bytes);
    return Status::Ok;
}

Status FixedRegisterWindowAt(u32 index, FixedRegisterWindow* window)
{
    if (window != nullptr)
        *window = {};
    if (window == nullptr || index >= kFixedRegisterWindowCount)
        return Status::InvalidArgument;
    *window = kFixedWindows[index];
    return Status::Ok;
}

Status ContractPlanRegisterAccess(ContractState* state, u32 physical_register, u32 width_bytes,
                                  RegisterAccessPlan* plan)
{
    if (plan != nullptr)
        *plan = {};
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase != ContractPhase::BarAccepted && state->phase != ContractPhase::FirmwareAccepted &&
        state->phase != ContractPhase::ReadyForHardwareBringUp)
    {
        return LatchFailure(state, Status::InvalidStateTransition);
    }
    if (state->generation == 0)
        return LatchFailure(state, Status::InvalidStateTransition);

    const Status status = PlanRegisterAccess(physical_register, width_bytes, plan);
    if (status != Status::Ok)
        return LatchFailure(state, status);
    plan->generation = state->generation;
    state->last_status = Status::Ok;
    return Status::Ok;
}

namespace
{

Status ValidateWifiRam(const u8* bytes, u64 byte_count, FirmwareSummary* summary)
{
    if (byte_count < kRamTrailerBytes)
        return Status::FirmwareTooSmall;

    const u64 trailer_offset = byte_count - kRamTrailerBytes;
    const u8* trailer = bytes + trailer_offset;
    const u32 region_count = trailer[2];
    if (region_count == 0 || region_count > kMaximumRegions)
        return Status::FirmwareRegionCountInvalid;
    if (trailer[3] != kRamFormatVersion || (trailer[4] & ~1u) != 0 || trailer[5] != 0 || trailer[6] != 0)
        return Status::UnsupportedFirmwareFormat;

    const u64 table_bytes = static_cast<u64>(region_count) * kRamRegionBytes;
    if (table_bytes > trailer_offset)
        return Status::FirmwareTableOutOfBounds;
    const u64 table_offset = trailer_offset - table_bytes;

    u64 payload_offset = 0;
    u32 override_address = 0;
    bool saw_override = false;
    for (u32 i = 0; i < region_count; ++i)
    {
        const u8* region = bytes + table_offset + static_cast<u64>(i) * kRamRegionBytes;
        const u32 address = ReadLe32(region + 16);
        const u32 length = ReadLe32(region + 20);
        const u8 features = region[24];
        const bool non_download = (features & kRamFeatureNonDownload) != 0;

        if (length == 0 || (features & ~kRamFeatureKnownMask) != 0)
            return Status::FirmwareRegionInvalid;
        if (AddOverflows(payload_offset, length) || payload_offset + length > table_offset)
            return Status::FirmwareRegionOutOfBounds;

        if (non_download)
        {
            ++summary->metadata_region_count;
        }
        else
        {
            if (address == 0 || static_cast<u64>(address) + length > kU32AddressSpaceBytes)
                return Status::FirmwareRegionInvalid;
            ++summary->download_region_count;
        }

        if ((features & kRamFeatureOverrideAddress) != 0)
        {
            if (non_download || address == 0 || saw_override)
                return Status::FirmwareRegionInvalid;
            saw_override = true;
            override_address = address;
        }
        if ((features & kRamFeatureEncryptedMask) != 0)
            summary->requires_encrypted_download = true;
        payload_offset += length;
    }

    if (summary->download_region_count == 0)
        return Status::FirmwareRegionInvalid;

    summary->kind = FirmwareKind::WifiRam;
    summary->region_count = region_count;
    summary->payload_bytes = static_cast<u32>(payload_offset);
    summary->table_offset = static_cast<u32>(table_offset);
    summary->metadata_bytes = static_cast<u32>(table_offset - payload_offset);
    summary->start_override_address = override_address;
    return Status::Ok;
}

bool PatchRegionsOverlap(const u8* bytes, u32 first_index, u32 second_index)
{
    const u8* first = bytes + kPatchHeaderBytes + static_cast<u64>(first_index) * kPatchRegionBytes;
    const u8* second = bytes + kPatchHeaderBytes + static_cast<u64>(second_index) * kPatchRegionBytes;
    const u64 first_offset = ReadBe32(first + 4);
    const u64 first_stored_size = ReadBe32(first + 8);
    const u64 second_offset = ReadBe32(second + 4);
    const u64 second_stored_size = ReadBe32(second + 8);
    return first_offset < second_offset + second_stored_size && second_offset < first_offset + first_stored_size;
}

Status ValidateRomPatch(const u8* bytes, u64 byte_count, FirmwareSummary* summary)
{
    if (byte_count < kPatchHeaderBytes)
        return Status::FirmwareTooSmall;
    if (ReadBe32(bytes + 32) != kPatchDescriptorVersion)
        return Status::UnsupportedFirmwareFormat;

    const u32 region_count = ReadBe32(bytes + 44);
    if (region_count == 0 || region_count > kMaximumRegions)
        return Status::FirmwareRegionCountInvalid;
    const u64 table_end = kPatchHeaderBytes + static_cast<u64>(region_count) * kPatchRegionBytes;
    if (table_end > byte_count)
        return Status::FirmwareTableOutOfBounds;

    u64 payload_bytes = 0;
    for (u32 i = 0; i < region_count; ++i)
    {
        const u8* region = bytes + kPatchHeaderBytes + static_cast<u64>(i) * kPatchRegionBytes;
        const u32 type = ReadBe32(region);
        const u64 offset = ReadBe32(region + 4);
        const u64 stored_size = ReadBe32(region + 8);
        const u32 address = ReadBe32(region + 12);
        const u64 length = ReadBe32(region + 16);
        const u32 security = ReadBe32(region + 20);
        const u64 alignment_bytes = ReadBe32(region + 24);

        if ((type & 0xFFFFu) != kPatchRegionTypeInformation || length == 0 || address == 0 || stored_size < length ||
            alignment_bytes > stored_size - length || offset < table_end)
        {
            return Status::FirmwareRegionInvalid;
        }
        if (AddOverflows(offset, stored_size) || offset + stored_size > byte_count ||
            static_cast<u64>(address) + length > kU32AddressSpaceBytes)
        {
            return Status::FirmwareRegionOutOfBounds;
        }

        if (security != 0xFFFFFFFFu)
        {
            const u8 encryption_type = static_cast<u8>(security >> 24);
            if (encryption_type > 2)
                return Status::FirmwareRegionInvalid;
            if (encryption_type != 0)
                summary->requires_encrypted_download = true;
        }

        for (u32 prior = 0; prior < i; ++prior)
        {
            if (PatchRegionsOverlap(bytes, prior, i))
                return Status::FirmwareRegionOverlap;
        }
        if (AddOverflows(payload_bytes, length))
            return Status::FirmwareRegionOutOfBounds;
        payload_bytes += length;
    }

    summary->kind = FirmwareKind::RomPatch;
    summary->region_count = region_count;
    summary->download_region_count = region_count;
    summary->payload_bytes = static_cast<u32>(payload_bytes);
    summary->table_offset = kPatchHeaderBytes;
    summary->metadata_bytes = static_cast<u32>(byte_count - payload_bytes);
    return Status::Ok;
}

} // namespace

Status ContractAcceptRingSet(ContractState* state, const RingLayout* rings, u64 ring_count)
{
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase != ContractPhase::FirmwareAccepted || state->generation == 0)
        return LatchFailure(state, Status::InvalidStateTransition);
    if (rings == nullptr || ring_count != static_cast<u64>(RingKind::Count))
        return LatchFailure(state, Status::RingSetIncomplete);

    constexpr u32 kRingCount = static_cast<u32>(RingKind::Count);
    u64 dma_starts[kRingCount] = {};
    u64 dma_ends[kRingCount] = {};
    u32 accepted_count = 0;
    u32 seen = 0;
    for (u64 i = 0; i < ring_count; ++i)
    {
        const u32 kind = static_cast<u32>(rings[i].kind);
        if (kind >= static_cast<u32>(RingKind::Count) || (seen & (1u << kind)) != 0)
            return LatchFailure(state, Status::RingSetIncomplete);

        u64 ring_bytes = 0;
        const Status status = ValidateRingLayout(rings[i], &ring_bytes);
        if (status != Status::Ok)
            return LatchFailure(state, status);

        const u64 dma_start = rings[i].descriptor_dma_base;
        const u64 dma_end = dma_start + ring_bytes;
        for (u32 prior = 0; prior < accepted_count; ++prior)
        {
            if (dma_start < dma_ends[prior] && dma_starts[prior] < dma_end)
                return LatchFailure(state, Status::RingDmaAddressInvalid);
        }
        dma_starts[accepted_count] = dma_start;
        dma_ends[accepted_count] = dma_end;
        ++accepted_count;
        seen |= 1u << kind;
    }

    const u32 complete = (1u << static_cast<u32>(RingKind::Count)) - 1u;
    if (seen != complete)
        return LatchFailure(state, Status::RingSetIncomplete);

    state->phase = ContractPhase::ReadyForHardwareBringUp;
    state->last_status = Status::Ok;
    return Status::Ok;
}

Status ContractBeginTeardown(ContractState* state)
{
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase == ContractPhase::Cold || state->phase == ContractPhase::TeardownPending)
        return LatchFailure(state, Status::InvalidStateTransition);
    state->phase = ContractPhase::TeardownPending;
    state->last_status = Status::Ok;
    return Status::Ok;
}

Status ContractFinishTeardown(ContractState* state)
{
    if (state == nullptr)
        return Status::InvalidArgument;
    if (state->phase != ContractPhase::TeardownPending)
        return LatchFailure(state, Status::InvalidStateTransition);
    if (state->generation == kU64Maximum)
        return LatchFailure(state, Status::AddressOverflow);

    ++state->generation;
    state->phase = ContractPhase::Cold;
    state->last_status = Status::Ok;
    return Status::Ok;
}

} // namespace duetos::drivers::net::mt7921
