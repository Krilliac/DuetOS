#pragma once

#include "util/types.h"

namespace duetos::drivers::net
{

struct NicInfo;

namespace pcnet_contract
{

inline constexpr u32 kRxRingSlots = 8;
inline constexpr u32 kTxRingSlots = 8;
inline constexpr u32 kBufferBytes = 2048;
inline constexpr u32 kEthernetHeaderBytes = 14;
inline constexpr u32 kEthernetFcsBytes = 4;
inline constexpr u32 kMaximumFrameBytes = 1514;

inline constexpr u16 kCsr0Init = 0x0001;
inline constexpr u16 kCsr0Start = 0x0002;
inline constexpr u16 kCsr0Stop = 0x0004;
inline constexpr u16 kCsr0TransmitDemand = 0x0008;
inline constexpr u16 kCsr0TxOn = 0x0010;
inline constexpr u16 kCsr0RxOn = 0x0020;
inline constexpr u16 kCsr0InitDone = 0x0100;
// CSR0 bits 14:9 are runtime W1C causes. IDON is deliberately excluded:
// some 79C974-compatible parts have an IDON-clear erratum.
inline constexpr u16 kCsr0RuntimeW1c = 0x7E00;

inline constexpr u16 kDescriptorOwn = 0x8000;
inline constexpr u16 kDescriptorError = 0x4000;
inline constexpr u16 kDescriptorStart = 0x0200;
inline constexpr u16 kDescriptorEnd = 0x0100;

struct alignas(16) PcnetDescriptor
{
    u32 address;
    u16 buffer_count;
    u16 status;
    u32 message;
    u32 reserved;
};
static_assert(sizeof(PcnetDescriptor) == 16);

struct alignas(16) PcnetInitBlock
{
    u16 mode;
    u8 rx_ring_length;
    u8 tx_ring_length;
    u8 physical_address[6];
    u16 reserved;
    u32 logical_filter_low;
    u32 logical_filter_high;
    u32 rx_ring_address;
    u32 tx_ring_address;
    u32 padding;
};
static_assert(sizeof(PcnetInitBlock) == 32);

constexpr u16 EncodeBufferCount(u32 bytes)
{
    return static_cast<u16>((0u - bytes) & 0x0FFFu) | 0xF000u;
}

constexpr u16 Csr0RuntimeAckValue(u16 status)
{
    return static_cast<u16>(status & kCsr0RuntimeW1c);
}

enum class RxDisposition : u8
{
    NotReady,
    Deliver,
    Drop,
};

struct RxInspection
{
    RxDisposition disposition;
    u32 frame_bytes;
    bool discard_until_end;
};

constexpr RxInspection InspectRx(u16 status, u32 message, bool discarding)
{
    if ((status & kDescriptorOwn) != 0)
        return {RxDisposition::NotReady, 0, discarding};

    const bool start = (status & kDescriptorStart) != 0;
    const bool end = (status & kDescriptorEnd) != 0;
    if (discarding || (status & kDescriptorError) != 0 || !start || !end)
        return {RxDisposition::Drop, 0, !end};

    const u32 wire_bytes = message & 0x0FFFu;
    if (wire_bytes < kEthernetHeaderBytes + kEthernetFcsBytes || wire_bytes > kMaximumFrameBytes + kEthernetFcsBytes ||
        wire_bytes > kBufferBytes)
        return {RxDisposition::Drop, 0, false};
    return {RxDisposition::Deliver, wire_bytes - kEthernetFcsBytes, false};
}

struct TxCursor
{
    u32 producer;
    u32 clean;
    u32 in_flight;
};

constexpr bool TxRingFull(const TxCursor& cursor)
{
    return cursor.in_flight >= kTxRingSlots;
}

constexpr u32 TxProducerSlot(const TxCursor& cursor)
{
    return cursor.producer % kTxRingSlots;
}

constexpr bool TxCommit(TxCursor& cursor)
{
    if (TxRingFull(cursor))
        return false;
    cursor.producer = (cursor.producer + 1) % kTxRingSlots;
    ++cursor.in_flight;
    return true;
}

constexpr bool TxReclaimOne(TxCursor& cursor)
{
    if (cursor.in_flight == 0)
        return false;
    cursor.clean = (cursor.clean + 1) % kTxRingSlots;
    --cursor.in_flight;
    return true;
}

} // namespace pcnet_contract

bool PcnetBringUp(NicInfo& nic, u32 iface_index);
bool PcnetQuiesceAll();

} // namespace duetos::drivers::net
