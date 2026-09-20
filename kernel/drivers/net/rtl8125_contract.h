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

constexpr bool DescriptorAddressValid(u64 address, u64 aperture_bytes)
{
    return address != 0 && (address & 0xFu) == 0 && address <= 0xFFFFFFFFu && aperture_bytes != 0 &&
           address <= 0xFFFFFFFFu - aperture_bytes;
}

constexpr u32 EncodeTx(u64 address, u16 length, bool first, bool last, bool ring_end)
{
    (void)address;
    if (length == 0 || length > kBufferBytes)
        return 0;
    return static_cast<u32>(length) | (first ? kDescFirst : 0u) | (last ? kDescLast : 0u) |
           (ring_end ? kDescRingEnd : 0u);
}

constexpr u32 EncodeRx(u64 address, bool ring_end)
{
    (void)address;
    return kDescOwn | (ring_end ? kDescRingEnd : 0u);
}

enum class RxDisposition : u8
{
    NotReady,
    Drop,
    Deliver,
};

constexpr RxDisposition ValidateRx(u32 options, u16 length, u32 buffer_bytes)
{
    if ((options & kDescOwn) != 0)
        return RxDisposition::NotReady;
    if ((options & (kRxCrcError | kRxRunt | kRxFrameError)) != 0 || (options & kDescFirst) == 0 ||
        (options & kDescLast) == 0 || length < kMinimumFrameBytes || length > buffer_bytes ||
        length > kBufferBytes)
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

constexpr bool TeardownStep(TeardownState& state, TeardownAction action)
{
    const u8 expected = state.completed;
    if (static_cast<u8>(action) != expected)
        return false;
    ++state.completed;
    return true;
}

} // namespace duetos::drivers::net::rtl8125::contract
