// tests/host/test_sched_sample_ring.cpp
//
// Hosted unit tests for `kernel/sched/sched_sample_ring.h`, the 60-sample
// CPU-utilisation ring that backs the gadget column sparkline and the
// taskbar stats pill sparkline.
//
// Covers:
//   1. Empty ring returns 0 for any age and Count() == 0.
//   2. Push advances Count() and Read(0) returns the latest sample.
//   3. Ordering: Read(0) is newest, Read(count-1) is oldest.
//   4. Wrap: after 60+ pushes the ring stops growing and the oldest
//      samples are silently overwritten.
//   5. Out-of-range Read returns 0, never crashes.
//   6. Full ring: all 60 slots are readable and ordered correctly.

#include "host_test_helper.h"

#include "sched/sched_sample_ring.h"

using duetos::u32;
using duetos::u8;
using duetos::sched::CpuSampleRing;

int main()
{
    // --- empty ring: nothing to read -----------------------------------
    {
        CpuSampleRing r{};
        EXPECT_EQ(r.Count(), 0u);
        EXPECT_EQ(r.Read(0), static_cast<u8>(0));
        EXPECT_EQ(r.Read(1), static_cast<u8>(0));
        EXPECT_EQ(r.Read(59), static_cast<u8>(0));
        EXPECT_EQ(r.Read(100), static_cast<u8>(0));
    }

    // --- single push ---------------------------------------------------
    {
        CpuSampleRing r{};
        r.Push(42);
        EXPECT_EQ(r.Count(), 1u);
        EXPECT_EQ(r.Read(0), static_cast<u8>(42));
        // age past count returns 0
        EXPECT_EQ(r.Read(1), static_cast<u8>(0));
    }

    // --- ordering: newest first ----------------------------------------
    {
        CpuSampleRing r{};
        r.Push(10);
        r.Push(20);
        r.Push(30);
        EXPECT_EQ(r.Count(), 3u);
        EXPECT_EQ(r.Read(0), static_cast<u8>(30)); // newest
        EXPECT_EQ(r.Read(1), static_cast<u8>(20));
        EXPECT_EQ(r.Read(2), static_cast<u8>(10)); // oldest
        EXPECT_EQ(r.Read(3), static_cast<u8>(0));  // past valid
    }

    // --- fill to capacity (60) -----------------------------------------
    {
        CpuSampleRing r{};
        for (u32 i = 0; i < 60; ++i)
        {
            r.Push(static_cast<u8>(i + 1));
        }
        EXPECT_EQ(r.Count(), 60u);
        EXPECT_EQ(r.Read(0), static_cast<u8>(60)); // newest
        EXPECT_EQ(r.Read(59), static_cast<u8>(1)); // oldest
        // every slot is the value we pushed
        for (u32 i = 0; i < 60; ++i)
        {
            EXPECT_EQ(r.Read(i), static_cast<u8>(60 - i));
        }
        // past capacity: still 0
        EXPECT_EQ(r.Read(60), static_cast<u8>(0));
    }

    // --- wrap: push past capacity overwrites oldest --------------------
    {
        CpuSampleRing r{};
        for (u32 i = 0; i < 60; ++i)
        {
            r.Push(static_cast<u8>(i));
        }
        EXPECT_EQ(r.Count(), 60u);
        // Now push one more — oldest (0) is lost
        r.Push(99);
        EXPECT_EQ(r.Count(), 60u);                 // count stays at 60
        EXPECT_EQ(r.Read(0), static_cast<u8>(99)); // newest is 99
        EXPECT_EQ(r.Read(1), static_cast<u8>(59)); // previous newest
        EXPECT_EQ(r.Read(59), static_cast<u8>(1)); // oldest is now 1, not 0
    }

    // --- deep wrap: 120 pushes -----------------------------------------
    {
        CpuSampleRing r{};
        for (u32 i = 0; i < 120; ++i)
        {
            r.Push(static_cast<u8>(i % 100));
        }
        EXPECT_EQ(r.Count(), 60u);
        // Newest is push #119 -> 119 % 100 = 19
        EXPECT_EQ(r.Read(0), static_cast<u8>(19));
        // Oldest is push #60 -> 60 % 100 = 60
        EXPECT_EQ(r.Read(59), static_cast<u8>(60));
    }

    // --- boundary values: 0% and 100% ---------------------------------
    {
        CpuSampleRing r{};
        r.Push(0);
        r.Push(100);
        EXPECT_EQ(r.Read(0), static_cast<u8>(100));
        EXPECT_EQ(r.Read(1), static_cast<u8>(0));
    }

    return duetos_host_test::finish_main("sched_sample_ring");
}
