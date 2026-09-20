#pragma once

#include "util/types.h"

namespace duetos::drivers::net::rtl8125::contract
{

inline constexpr u16 kVendorRealtek = 0x10EC;
inline constexpr u16 kDevice = 0x8125;
inline constexpr u16 kSubsystemVendor = 0x10EC;
inline constexpr u16 kSubsystemDevice = 0x0123;
inline constexpr u8 kRevision = 0x05;
inline constexpr u32 kRingSlots = 256;
inline constexpr u32 kBufferBytes = 16 * 1024 - 1;
inline constexpr u32 kMinimumFrameBytes = 60;
inline constexpr u32 kMaximumFrameBytes = 1518;
inline constexpr u32 kEthernetFcsBytes = 4;
inline constexpr u16 kPciCommandMemorySpace = 0x0002;
inline constexpr u16 kPciCommandBusMaster = 0x0004;

// Values are from Linux drivers/net/ethernet/realtek/r8169_main.c. The
// v0 path uses only the generic descriptor bits shared by RTL8125.
inline constexpr u32 kDescOwn = 1u << 31;
inline constexpr u32 kDescRingEnd = 1u << 30;
inline constexpr u32 kDescFirst = 1u << 29;
inline constexpr u32 kDescLast = 1u << 28;
inline constexpr u32 kRxCrcError = 1u << 19;
inline constexpr u32 kRxRunt = 1u << 20;
inline constexpr u32 kRxFrameError = 1u << 21;

constexpr bool IsExactHardware(u16 vendor, u16 device, u16 subsystem_vendor, u16 subsystem_device, u8 revision)
{
    return vendor == kVendorRealtek && device == kDevice && subsystem_vendor == kSubsystemVendor &&
           subsystem_device == kSubsystemDevice && revision == kRevision;
}

constexpr u16 PciPreflightCommand(u16 original)
{
    return static_cast<u16>((original | kPciCommandMemorySpace) & ~kPciCommandBusMaster);
}

constexpr bool PciPreflightReadbackValid(u16 observed)
{
    return (observed & (kPciCommandMemorySpace | kPciCommandBusMaster)) == kPciCommandMemorySpace;
}

constexpr u16 PciSafeRestoreCommand(u16 original)
{
    return static_cast<u16>(original & ~kPciCommandBusMaster);
}

constexpr bool PciSafeRestoreReadbackValid(u16 original, u16 observed)
{
    const u16 relevant = kPciCommandMemorySpace | kPciCommandBusMaster;
    return (observed & relevant) == (PciSafeRestoreCommand(original) & relevant);
}

enum class PciPreflightResult : u8
{
    ReadyForMmio,
    RestoredSafe,
    QuarantinePciOnly,
};

template <typename WriteCommand, typename ReadCommand>
constexpr bool RunPciSafeRestore(u16 original, WriteCommand write_command, ReadCommand read_command)
{
    write_command(PciSafeRestoreCommand(original));
    return PciSafeRestoreReadbackValid(original, read_command());
}

template <typename WriteCommand, typename ReadCommand>
constexpr PciPreflightResult RunPciPreflight(u16 original, WriteCommand write_command, ReadCommand read_command)
{
    write_command(PciPreflightCommand(original));
    if (PciPreflightReadbackValid(read_command()))
        return PciPreflightResult::ReadyForMmio;
    return RunPciSafeRestore(original, write_command, read_command) ? PciPreflightResult::RestoredSafe
                                                                    : PciPreflightResult::QuarantinePciOnly;
}

constexpr bool DescriptorAddressValid(u64 address, u64 aperture_bytes)
{
    return address != 0 && (address & 0xFu) == 0 && address <= 0xFFFFFFFFu && aperture_bytes != 0 &&
           address <= 0xFFFFFFFFu - aperture_bytes;
}

constexpr bool RingBaseValid(u64 address, u64 ring_bytes)
{
    return DescriptorAddressValid(address, ring_bytes) && (address & 0xFFu) == 0;
}

constexpr u16 PrepareTxLength(u64 length)
{
    if (length == 0 || length > kMaximumFrameBytes)
        return 0;
    return static_cast<u16>(length < kMinimumFrameBytes ? kMinimumFrameBytes : length);
}

constexpr u32 EncodeTx(u64 address, u16 length, bool first, bool last, bool ring_end)
{
    if (!DescriptorAddressValid(address, length) || length == 0 || length > kMaximumFrameBytes)
        return 0;
    return static_cast<u32>(length) | (first ? kDescFirst : 0u) | (last ? kDescLast : 0u) |
           (ring_end ? kDescRingEnd : 0u);
}

constexpr u32 EncodeRx(u64 address, u16 buffer_bytes, bool ring_end)
{
    if (!DescriptorAddressValid(address, buffer_bytes) || buffer_bytes == 0 || buffer_bytes > kBufferBytes)
        return 0;
    return kDescOwn | (ring_end ? kDescRingEnd : 0u) | buffer_bytes;
}

enum class RxDisposition : u8
{
    NotReady,
    Drop,
    Deliver,
};

constexpr u16 RxPayloadLength(u16 wire_length)
{
    return wire_length >= kMinimumFrameBytes + kEthernetFcsBytes ? static_cast<u16>(wire_length - kEthernetFcsBytes)
                                                                 : 0;
}

constexpr RxDisposition ValidateRx(u32 options, u16 length, u32 buffer_bytes)
{
    if ((options & kDescOwn) != 0)
        return RxDisposition::NotReady;
    if ((options & (kRxCrcError | kRxRunt | kRxFrameError)) != 0 || (options & kDescFirst) == 0 ||
        (options & kDescLast) == 0 || length < kMinimumFrameBytes || length > buffer_bytes || length > kBufferBytes)
        return RxDisposition::Drop;
    return RxDisposition::Deliver;
}

struct TxCursor
{
    u32 producer = 0;
    u32 clean = 0;
    u32 in_flight = 0;
};

constexpr bool TxPublish(TxCursor& cursor)
{
    if (cursor.in_flight >= kRingSlots - 1)
        return false;
    cursor.producer = (cursor.producer + 1) % kRingSlots;
    ++cursor.in_flight;
    return true;
}

constexpr bool TxReclaim(TxCursor& cursor, bool descriptor_done)
{
    if (!descriptor_done || cursor.in_flight == 0)
        return false;
    cursor.clean = (cursor.clean + 1) % kRingSlots;
    --cursor.in_flight;
    return true;
}

constexpr bool TxReclaimAfterCpuSync(TxCursor& cursor, bool cpu_synced, bool descriptor_done)
{
    return cpu_synced && TxReclaim(cursor, descriptor_done);
}

enum class TeardownAction : u8
{
    CloseOperations,
    JoinWorker,
    DisableDatapath,
    DisableBusMaster,
    FreeDma,
};

struct TeardownState
{
    u8 completed = 0;
};

constexpr bool TeardownProof(bool gate_closed, bool worker_joined, bool unbound, bool stopped, bool bus_master_off)
{
    return gate_closed && worker_joined && unbound && stopped && bus_master_off;
}

constexpr bool TeardownStep(TeardownState& state, TeardownAction action)
{
    const u8 expected = state.completed;
    if (static_cast<u8>(action) != expected)
        return false;
    ++state.completed;
    return true;
}

} // namespace duetos::drivers::net::rtl8125::contract
