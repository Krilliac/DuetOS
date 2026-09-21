// Hosted concurrency coverage for the fixed-size klog persistence handoff.
//
// The live producer runs on arbitrary CPUs and cannot block, allocate, or enter
// FAT32.  The periodic persistence task is the consumer.  Exercise the exact
// freestanding ring with multiple producers and consumers so the hosted TSan
// lane catches publication, reuse, or payload-copy races.

#include "host_test_helper.h"

#include "log/klog_pending_ring.h"

#include <array>
#include <atomic>
#include <cstring>
#include <thread>
#include <vector>

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::core::klog_pending::Dequeue;
using duetos::core::klog_pending::Enqueue;
using duetos::core::klog_pending::Initialize;
using duetos::core::klog_pending::kCapacity;
using duetos::core::klog_pending::kLineBytes;
using duetos::core::klog_pending::Record;
using duetos::core::klog_pending::Ring;

struct Payload
{
    u32 producer;
    u32 sequence;
    u64 checksum;
};

constexpr u64 kChecksumSalt = 0xD03E70C0A55A5AA5ULL;

Payload MakePayload(u32 producer, u32 sequence)
{
    const u64 identity = (static_cast<u64>(producer) << 32U) | sequence;
    return Payload{producer, sequence, identity ^ kChecksumSalt};
}

bool ValidPayload(const Payload& payload, u32 producer_count, u32 per_producer)
{
    if (payload.producer >= producer_count || payload.sequence >= per_producer)
    {
        return false;
    }
    const u64 identity = (static_cast<u64>(payload.producer) << 32U) | payload.sequence;
    return payload.checksum == (identity ^ kChecksumSalt);
}

} // namespace

int main()
{
    // Empty/full/FIFO/reuse behavior, including the exact capacity edge.
    {
        Ring ring{};
        Initialize(&ring);
        Record out{};
        EXPECT_FALSE(Dequeue(&ring, &out));
        EXPECT_FALSE(Enqueue(&ring, 1, nullptr, 1));
        EXPECT_FALSE(Enqueue(&ring, 1, "", 0));

        for (u32 i = 0; i < kCapacity; ++i)
        {
            const Payload payload = MakePayload(0, i);
            EXPECT_TRUE(Enqueue(&ring, i + 1, reinterpret_cast<const char*>(&payload), sizeof(payload)));
        }
        const Payload overflow = MakePayload(0, kCapacity);
        EXPECT_FALSE(Enqueue(&ring, 1, reinterpret_cast<const char*>(&overflow), sizeof(overflow)));

        for (u32 i = 0; i < kCapacity; ++i)
        {
            EXPECT_TRUE(Dequeue(&ring, &out));
            EXPECT_EQ(out.area_bits, i + 1);
            EXPECT_EQ(out.length, static_cast<u32>(sizeof(Payload)));
            Payload payload{};
            std::memcpy(&payload, out.bytes, sizeof(payload));
            EXPECT_EQ(payload.producer, 0u);
            EXPECT_EQ(payload.sequence, i);
        }
        EXPECT_FALSE(Dequeue(&ring, &out));

        // Reuse every slot after a complete wrap.
        for (u32 i = 0; i < kCapacity; ++i)
        {
            const Payload payload = MakePayload(1, i);
            EXPECT_TRUE(Enqueue(&ring, 7, reinterpret_cast<const char*>(&payload), sizeof(payload)));
            EXPECT_TRUE(Dequeue(&ring, &out));
        }
    }

    // A stale/contended position must consume only the fixed claim-attempt
    // budget and return false. These synthetic sequence values force the
    // positive-difference retry branch deterministically; an unbounded loop
    // would hang this test.
    {
        Ring producer_contended{};
        Initialize(&producer_contended);
        producer_contended.slots[0].sequence = 1;
        const Payload payload = MakePayload(0, 0);
        EXPECT_FALSE(Enqueue(&producer_contended, 1, reinterpret_cast<const char*>(&payload), sizeof(payload)));

        Ring consumer_contended{};
        Initialize(&consumer_contended);
        consumer_contended.slots[0].sequence = 2;
        Record out{};
        EXPECT_FALSE(Dequeue(&consumer_contended, &out));
    }

    // Oversized input is bounded to the record payload without reading or
    // publishing beyond the fixed slot.
    {
        Ring ring{};
        Initialize(&ring);
        std::array<char, kLineBytes + 17> long_line{};
        for (u32 i = 0; i < long_line.size(); ++i)
        {
            long_line[i] = static_cast<char>('A' + (i % 23));
        }
        EXPECT_TRUE(Enqueue(&ring, 9, long_line.data(), static_cast<u32>(long_line.size())));
        Record out{};
        EXPECT_TRUE(Dequeue(&ring, &out));
        EXPECT_EQ(out.length, kLineBytes);
        EXPECT_EQ(std::memcmp(out.bytes, long_line.data(), kLineBytes), 0);
    }

    // Real MPMC stress. The production consumer gate intentionally admits one
    // consumer, but proving the ring itself with two consumers catches a wider
    // class of sequence/reuse bugs at essentially no runtime cost.
    {
        constexpr u32 kProducers = 4;
        constexpr u32 kConsumers = 2;
        constexpr u32 kPerProducer = 4000;
        constexpr u32 kTotal = kProducers * kPerProducer;

        Ring ring{};
        Initialize(&ring);
        std::vector<std::atomic<u32>> seen(kTotal);
        for (auto& value : seen)
        {
            value.store(0, std::memory_order_relaxed);
        }
        std::atomic<u32> consumed{0};
        std::atomic<bool> valid{true};

        std::array<std::thread, kConsumers> consumers;
        for (u32 consumer = 0; consumer < kConsumers; ++consumer)
        {
            consumers[consumer] = std::thread(
                [&]()
                {
                    Record record{};
                    while (consumed.load(std::memory_order_acquire) < kTotal)
                    {
                        if (!Dequeue(&ring, &record))
                        {
                            std::this_thread::yield();
                            continue;
                        }
                        if (record.length != sizeof(Payload))
                        {
                            valid.store(false, std::memory_order_relaxed);
                        }
                        Payload payload{};
                        std::memcpy(&payload, record.bytes, sizeof(payload));
                        if (!ValidPayload(payload, kProducers, kPerProducer))
                        {
                            valid.store(false, std::memory_order_relaxed);
                        }
                        else
                        {
                            const u32 index = payload.producer * kPerProducer + payload.sequence;
                            if (seen[index].fetch_add(1, std::memory_order_relaxed) != 0)
                            {
                                valid.store(false, std::memory_order_relaxed);
                            }
                        }
                        consumed.fetch_add(1, std::memory_order_release);
                    }
                });
        }

        std::array<std::thread, kProducers> producers;
        for (u32 producer = 0; producer < kProducers; ++producer)
        {
            producers[producer] = std::thread(
                [&, producer]()
                {
                    for (u32 sequence = 0; sequence < kPerProducer; ++sequence)
                    {
                        const Payload payload = MakePayload(producer, sequence);
                        while (
                            !Enqueue(&ring, 1U << producer, reinterpret_cast<const char*>(&payload), sizeof(payload)))
                        {
                            std::this_thread::yield();
                        }
                    }
                });
        }
        for (auto& producer : producers)
        {
            producer.join();
        }
        for (auto& consumer : consumers)
        {
            consumer.join();
        }

        EXPECT_TRUE(valid.load(std::memory_order_relaxed));
        EXPECT_EQ(consumed.load(std::memory_order_relaxed), kTotal);
        for (const auto& value : seen)
        {
            EXPECT_EQ(value.load(std::memory_order_relaxed), 1u);
        }
        Record out{};
        EXPECT_FALSE(Dequeue(&ring, &out));
    }

    return duetos_host_test::finish_main("klog_pending_ring");
}
