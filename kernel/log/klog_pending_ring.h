#pragma once

#include "util/types.h"

/*
 * Fixed-size MPMC handoff for persistent klog records.
 *
 * A klog producer can run on any CPU, in an interrupt, or while kernel locks
 * make sleeping and filesystem entry illegal.  It therefore performs only a
 * bounded payload copy plus atomic publication.  The periodic process-context
 * persistence task is the normal single consumer, although the sequence-slot
 * protocol is safe for multiple consumers and is exercised that way by the
 * hosted ThreadSanitizer test.
 *
 * This is the bounded queue described by Dmitry Vyukov's per-slot sequence
 * algorithm.  A producer owns a slot only after advancing enqueue_position;
 * its release-store of sequence publishes the copied record.  A consumer's
 * acquire-load observes that payload, and its final release-store makes the
 * slot reusable by the next lap.  Full/empty paths never wait.
 */

namespace duetos::core::klog_pending
{

// Hosted KVM profiles can emit bursts just under 190 records before the 1 Hz
// consumer gets its first turn. 256 keeps that measured peak below 75% while
// retaining a small, fixed (~100 KiB) BSS footprint.
inline constexpr u32 kCapacity = 256;
inline constexpr u32 kLineBytes = 384;
inline constexpr u32 kClaimAttempts = 8;
static_assert((kCapacity & (kCapacity - 1U)) == 0U, "klog pending capacity must be a power of two");

struct Record
{
    u32 area_bits;
    u32 length;
    char bytes[kLineBytes];
};

struct Slot
{
    u64 sequence;
    Record record;
};

struct Ring
{
    alignas(64) Slot slots[kCapacity];
    alignas(64) u64 enqueue_position;
    alignas(64) u64 dequeue_position;
};

// Queue positions and slot sequences stay within kCapacity of each other. The
// queue is initialized once per boot and cannot approach a 2^63 separation,
// so decode the modular unsigned delta without relying on implementation-
// defined unsigned-to-signed conversion.
inline i64 SequenceDifference(u64 sequence, u64 expected)
{
    constexpr u64 kSignBit = u64{1} << 63U;
    constexpr u64 kSignedMax = kSignBit - 1U;
    const u64 delta = sequence - expected;
    if ((delta & kSignBit) == 0)
    {
        return static_cast<i64>(delta);
    }
    const u64 magnitude = (~delta) + 1U;
    if (magnitude > kSignedMax)
    {
        return -static_cast<i64>(kSignedMax) - 1;
    }
    return -static_cast<i64>(magnitude);
}

/// Initialize before publishing the ring to producers. Not safe to race with
/// Enqueue or Dequeue; the persistence installer calls it before registering
/// the line sink.
inline void Initialize(Ring* ring)
{
    if (ring == nullptr)
    {
        return;
    }
    for (u32 i = 0; i < kCapacity; ++i)
    {
        ring->slots[i].sequence = i;
        ring->slots[i].record.area_bits = 0;
        ring->slots[i].record.length = 0;
    }
    ring->enqueue_position = 0;
    ring->dequeue_position = 0;
}

/// Try to publish one record. Returns false immediately when the queue is full
/// or the input is invalid. Oversized lines are deterministically truncated to
/// the same 384-byte ceiling used by klog's line sink.
inline bool Enqueue(Ring* ring, u32 area_bits, const char* line, u32 line_length)
{
    if (ring == nullptr || line == nullptr || line_length == 0)
    {
        return false;
    }

    u64 position = __atomic_load_n(&ring->enqueue_position, __ATOMIC_RELAXED);
    Slot* slot = nullptr;
    bool claimed = false;
    for (u32 attempt = 0; attempt < kClaimAttempts; ++attempt)
    {
        slot = &ring->slots[position & (kCapacity - 1U)];
        const u64 sequence = __atomic_load_n(&slot->sequence, __ATOMIC_ACQUIRE);
        const i64 difference = SequenceDifference(sequence, position);
        if (difference == 0)
        {
            u64 expected = position;
            if (__atomic_compare_exchange_n(&ring->enqueue_position, &expected, position + 1U, false, __ATOMIC_RELAXED,
                                            __ATOMIC_RELAXED))
            {
                claimed = true;
                break;
            }
            position = expected;
            continue;
        }
        if (difference < 0)
        {
            return false;
        }
        position = __atomic_load_n(&ring->enqueue_position, __ATOMIC_RELAXED);
    }

    if (!claimed)
    {
        return false;
    }

    const u32 copy_length = line_length < kLineBytes ? line_length : kLineBytes;
    slot->record.area_bits = area_bits;
    slot->record.length = copy_length;
    for (u32 i = 0; i < copy_length; ++i)
    {
        slot->record.bytes[i] = line[i];
    }
    __atomic_store_n(&slot->sequence, position + 1U, __ATOMIC_RELEASE);
    return true;
}

/// Try to consume one record. The payload is copied out before the slot is
/// released, so a slow filesystem consumer never pins ring capacity.
inline bool Dequeue(Ring* ring, Record* record_out)
{
    if (ring == nullptr || record_out == nullptr)
    {
        return false;
    }

    u64 position = __atomic_load_n(&ring->dequeue_position, __ATOMIC_RELAXED);
    Slot* slot = nullptr;
    bool claimed = false;
    for (u32 attempt = 0; attempt < kClaimAttempts; ++attempt)
    {
        slot = &ring->slots[position & (kCapacity - 1U)];
        const u64 sequence = __atomic_load_n(&slot->sequence, __ATOMIC_ACQUIRE);
        const i64 difference = SequenceDifference(sequence, position + 1U);
        if (difference == 0)
        {
            u64 expected = position;
            if (__atomic_compare_exchange_n(&ring->dequeue_position, &expected, position + 1U, false, __ATOMIC_RELAXED,
                                            __ATOMIC_RELAXED))
            {
                claimed = true;
                break;
            }
            position = expected;
            continue;
        }
        if (difference < 0)
        {
            return false;
        }
        position = __atomic_load_n(&ring->dequeue_position, __ATOMIC_RELAXED);
    }

    if (!claimed)
    {
        return false;
    }

    record_out->area_bits = slot->record.area_bits;
    record_out->length = slot->record.length;
    for (u32 i = 0; i < slot->record.length; ++i)
    {
        record_out->bytes[i] = slot->record.bytes[i];
    }
    __atomic_store_n(&slot->sequence, position + kCapacity, __ATOMIC_RELEASE);
    return true;
}

} // namespace duetos::core::klog_pending
