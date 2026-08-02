#pragma once

#include "util/types.h"

/*
 * Clean-room MT7921 PCI preflight contract.
 *
 * Public Linux mt76 and linux-firmware sources were studied only for hardware
 * facts: PCI identity, BAR aperture, register window geometry, firmware field
 * endianness, MCU envelope sizes, and WFDMA descriptor counts.  This interface
 * is independently shaped around DuetOS's fail-closed bring-up boundary.  It
 * owns no device resources and contains no register, PCI, DMA, or IRQ effects.
 *
 * Stateless validators: [any context, reentrant].
 * ContractState mutation: [single owning init/teardown context], not thread-safe.
 * The future hardware backend owns MMIO, IRQs, and DMA allocations; inputs here
 * are borrowed for the duration of each call.  This kernel contract is not
 * hot-reloadable unless the owner has completed teardown first.
 */

namespace duetos::drivers::net::mt7921
{

inline constexpr u16 kPciVendorId = 0x14C3;
inline constexpr u16 kPciDeviceId = 0x7961;
inline constexpr u16 kSubsystemVendorId = 0x105B;
inline constexpr u16 kSubsystemDeviceId = 0xE0B7;
inline constexpr u8 kRevisionId = 0x00;
inline constexpr u8 kPciBaseClass = 0x02;
inline constexpr u8 kPciSubclass = 0x80;
inline constexpr u8 kPciProgrammingInterface = 0x00;

inline constexpr u8 kRequiredBarIndex = 0;
inline constexpr u64 kMinimumBarBytes = 0x100000;
inline constexpr u32 kL1RemapRegisterOffset = 0x000FE24C;
inline constexpr u32 kL1WindowOffset = 0x00040000;
inline constexpr u32 kL1WindowBytes = 0x00010000;
inline constexpr u32 kFixedRegisterWindowCount = 44;
inline constexpr u64 kMaximumFirmwareBytes = 4ull * 1024ull * 1024ull;

inline constexpr char kWifiRamFirmwarePath[] = "mediatek/WIFI_RAM_CODE_MT7961_1.bin";
inline constexpr char kRomPatchFirmwarePath[] = "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin";

enum class Status : u8
{
    Ok = 0,
    InvalidArgument,
    WrongPciIdentity,
    WrongPciClass,
    WrongPciRevision,
    WrongBar,
    BarTooSmall,
    AddressOverflow,
    RegisterMisaligned,
    UnsupportedRegister,
    RegisterCrossesWindow,
    FirmwareTooSmall,
    FirmwareTooLarge,
    UnsupportedFirmwareFormat,
    FirmwareRegionCountInvalid,
    FirmwareTableOutOfBounds,
    FirmwareRegionOutOfBounds,
    FirmwareRegionInvalid,
    FirmwareRegionOverlap,
    McuEnvelopeTooSmall,
    McuLengthMismatch,
    McuFieldInvalid,
    RingKindInvalid,
    RingCountInvalid,
    RingDescriptorInvalid,
    RingByteCountOverflow,
    RingDmaAddressInvalid,
    RingSetIncomplete,
    InvalidStateTransition,
};

const char* StatusName(Status status);

struct PciIdentity
{
    u16 vendor_id;
    u16 device_id;
    u16 subsystem_vendor_id;
    u16 subsystem_device_id;
    u8 base_class;
    u8 subclass;
    u8 programming_interface;
    u8 revision_id;
    bool subsystem_known;
};

struct BarResource
{
    u64 physical_base;
    u64 extent_bytes;
    u64 mapped_bytes;
    u8 index;
    bool present;
    bool memory_space;
    bool is_64_bit;
    bool mapped_uncached;
};

enum class RegisterPath : u8
{
    Direct = 0,
    FixedMap,
    L1Remap,
};

// One hardware-decoded BAR0 window: [chip_base, chip_base + window_bytes)
// appears at [bar_offset, bar_offset + window_bytes) with no remap write.
struct FixedRegisterWindow
{
    u32 chip_base;
    u32 bar_offset;
    u32 window_bytes;
};

struct RegisterAccessPlan
{
    RegisterPath path;
    u32 bar_offset;
    u32 remap_register_offset;
    u16 remap_selector;
    u16 width_bytes;
    u64 generation; // 0 from the stateless planner; contract-stamped otherwise.
};

enum class FirmwareKind : u8
{
    RomPatch = 0,
    WifiRam,
};

struct FirmwareSummary
{
    FirmwareKind kind;
    u32 region_count;
    u32 download_region_count;
    u32 metadata_region_count;
    u32 payload_bytes;
    u32 table_offset;
    u32 metadata_bytes;
    u32 start_override_address;
    bool requires_encrypted_download;
};

enum class McuEnvelopeKind : u8
{
    Legacy = 0,
    Unified,
};

struct McuSummary
{
    McuEnvelopeKind kind;
    u16 descriptor_bytes;
    u16 payload_bytes;
    u16 command_id;
    u8 sequence;
    u8 destination;
};

enum class RingKind : u8
{
    DataTx = 0,
    McuCommandTx,
    FirmwareDownloadTx,
    DataRx,
    McuEventRx,
    McuWaRx,
    Count,
};

struct RingLayout
{
    RingKind kind;
    u64 descriptor_dma_base;
    u64 descriptor_count;
    u64 descriptor_bytes;
};

enum class ContractPhase : u8
{
    Cold = 0,
    IdentityAccepted,
    BarAccepted,
    FirmwareAccepted,
    ReadyForHardwareBringUp,
    TeardownPending,
    Failed,
};

struct ContractState
{
    ContractPhase phase;
    Status last_status;
    u64 generation; // 0 until first identity acceptance; active lifecycles are nonzero.
};

// [any context, reentrant] Exact host profile only.
Status ValidateIdentity(const PciIdentity& identity);

// [any context, reentrant] Validates BAR0 and the full mapped aperture.
Status ValidateBar(const BarResource& bar);

// [any context, reentrant] Plans a 32-bit register access without executing it.
// Resolution order matches the hardware decode: direct BAR offsets below
// kMinimumBarBytes, then the exact fixed window table, then L1 remap. A
// non-null output is cleared before every validation result.
Status PlanRegisterAccess(u32 physical_register, u32 width_bytes, RegisterAccessPlan* plan);

// [any context, reentrant] Enumerates the exact fixed window table so callers
// and tests can independently re-derive its disjointness and aperture bounds.
// A non-null output is cleared before every validation result.
Status FixedRegisterWindowAt(u32 index, FixedRegisterWindow* window);

// [any context, reentrant] Parses bounds and metadata; never uploads bytes.
// Non-null summaries are cleared before every validation result.
Status ValidateFirmwareContainer(FirmwareKind kind, const u8* bytes, u64 byte_count, FirmwareSummary* summary);

// [any context, reentrant] Validates an already-constructed command envelope.
// Non-null summaries are cleared before every validation result.
Status ValidateMcuEnvelope(McuEnvelopeKind kind, const u8* bytes, u64 byte_count, McuSummary* summary);

// [any context, reentrant] Validates one descriptor ring and returns its bytes.
Status ValidateRingLayout(const RingLayout& layout, u64* ring_bytes);

// [single owner] These calls latch Failed on validation or ordering errors.
Status ContractAcceptIdentity(ContractState* state, const PciIdentity& identity);
Status ContractAcceptBar(ContractState* state, const BarResource& bar);
Status ContractAcceptFirmwareSet(ContractState* state, const u8* patch_bytes, u64 patch_byte_count, const u8* ram_bytes,
                                 u64 ram_byte_count);
Status ContractAcceptRingSet(ContractState* state, const RingLayout* rings, u64 ring_count);

// [single owner] Register planning is only legal once the BAR is accepted and
// before teardown begins. Any planning error latches Failed: a request the
// exact map cannot express is a driver bug, not a probe to retry. Successful
// plans are stamped with the state's generation so a plan from a previous
// bring-up cannot be replayed after teardown.
Status ContractPlanRegisterAccess(ContractState* state, u32 physical_register, u32 width_bytes,
                                  RegisterAccessPlan* plan);

// [single owner] Teardown is explicit; FinishTeardown is the sole reuse path.
Status ContractBeginTeardown(ContractState* state);
Status ContractFinishTeardown(ContractState* state);

} // namespace duetos::drivers::net::mt7921
