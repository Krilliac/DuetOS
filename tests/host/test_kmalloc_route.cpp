// tests/host/test_kmalloc_route.cpp
//
// Hosted unit tests for kernel/mm/kmalloc_route.h — the pure decision
// logic behind KMalloc small-allocation slab routing. The header is
// freestanding constexpr code, so every boundary the live kernel
// depends on (size-class mapping, route-header encode/decode, the
// KFree discrimination verdicts) is pinned here natively, under
// sanitizers, on every PR. The stateful half (cache wiring, header
// writes, fallback) is covered by KMallocRouteSelfTest at boot.
//
// Contracts pinned:
//   SizeToRouteClass:
//     - 0 and > 512 -> kRouteNoClass
//     - exact class boundaries and the byte on either side of each
//   EncodeRouteHeader / DecodeRouteClass:
//     - roundtrip for all 8 classes
//     - magic with an out-of-range class byte does NOT decode
//   kSlabRouteMagicFreed:
//     - distinct from every live header and never decodes as a class
//   RouteWordClassify:
//     - 0 -> Kheap (the live classic-chunk discriminator)
//     - live headers -> RoutedLive; freed tag -> RoutedFreed
//     - kheap chunk magics / slab poison / arbitrary words -> Garbage

#include "host_test_helper.h"
#include "mm/kmalloc_route.h"

using duetos::u32;
using duetos::u64;
using duetos::mm::DecodeRouteClass;
using duetos::mm::EncodeRouteHeader;
using duetos::mm::kRouteNoClass;
using duetos::mm::kSlabRouteClassBytes;
using duetos::mm::kSlabRouteClassCount;
using duetos::mm::kSlabRouteMagic;
using duetos::mm::kSlabRouteMagicFreed;
using duetos::mm::kSlabRouteMaxBytes;
using duetos::mm::RouteWord;
using duetos::mm::RouteWordClassify;
using duetos::mm::SizeToRouteClass;

int main()
{
    // ---- Size-class mapping: degenerate inputs ----
    EXPECT_EQ(SizeToRouteClass(0), kRouteNoClass);
    EXPECT_EQ(SizeToRouteClass(kSlabRouteMaxBytes + 1), kRouteNoClass); // 513
    EXPECT_EQ(SizeToRouteClass(1024), kRouteNoClass);
    EXPECT_EQ(SizeToRouteClass(~0ull), kRouteNoClass);

    // ---- Size-class mapping: every boundary ----
    // Class i serves (prev_class_bytes, class_bytes]; class 0 starts at 1.
    EXPECT_EQ(SizeToRouteClass(1), 0u);
    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        const u64 upper = kSlabRouteClassBytes[i];
        EXPECT_EQ(SizeToRouteClass(upper), i);     // top of class i
        EXPECT_EQ(SizeToRouteClass(upper - 1), i); // still class i (all classes span >= 2 bytes)
        if (i + 1 < kSlabRouteClassCount)
        {
            EXPECT_EQ(SizeToRouteClass(upper + 1), i + 1); // first byte of the next class
        }
    }
    EXPECT_EQ(SizeToRouteClass(kSlabRouteMaxBytes), kSlabRouteClassCount - 1); // 512 -> class 7

    // Spot-check the documented table: 1..32->0, 33..64->1, ..., 385..512->7.
    EXPECT_EQ(SizeToRouteClass(32), 0u);
    EXPECT_EQ(SizeToRouteClass(33), 1u);
    EXPECT_EQ(SizeToRouteClass(96), 2u);
    EXPECT_EQ(SizeToRouteClass(97), 3u);
    EXPECT_EQ(SizeToRouteClass(192), 4u);
    EXPECT_EQ(SizeToRouteClass(193), 5u);
    EXPECT_EQ(SizeToRouteClass(384), 6u);
    EXPECT_EQ(SizeToRouteClass(385), 7u);

    // ---- Header encode/decode roundtrip for all classes ----
    for (u32 i = 0; i < kSlabRouteClassCount; ++i)
    {
        const u64 header = EncodeRouteHeader(i);
        EXPECT_EQ(DecodeRouteClass(header), i);
        EXPECT_EQ(header & ~0xFFull, kSlabRouteMagic); // class confined to the low byte
        EXPECT_TRUE(RouteWordClassify(header) == RouteWord::RoutedLive);
        EXPECT_NE(header, kSlabRouteMagicFreed); // freed tag distinct from every live header
    }

    // Magic with an out-of-range class byte must NOT decode.
    EXPECT_EQ(DecodeRouteClass(kSlabRouteMagic | kSlabRouteClassCount), kRouteNoClass);
    EXPECT_EQ(DecodeRouteClass(kSlabRouteMagic | 0xFFull), kRouteNoClass);

    // The freed tag never decodes as a live class.
    EXPECT_EQ(DecodeRouteClass(kSlabRouteMagicFreed), kRouteNoClass);

    // ---- Discrimination verdicts ----
    // 0 is the live classic-kheap discriminator (ChunkHeader::next ==
    // nullptr on every live chunk — kheap.cpp static_asserts the offset).
    EXPECT_TRUE(RouteWordClassify(0) == RouteWord::Kheap);
    EXPECT_TRUE(RouteWordClassify(kSlabRouteMagicFreed) == RouteWord::RoutedFreed);

    // Words KFree can plausibly encounter at ptr-16 that must fall to
    // the classic path's own magic checks: kheap chunk magics, the
    // slab freed-object poison word, a heap-pool pointer (freelist
    // link written over a freed routed object), and a route magic
    // whose class byte is out of range.
    EXPECT_TRUE(RouteWordClassify(0xDEADBEEFCAFEBABEull) == RouteWord::Garbage); // kHeapMagicLive
    EXPECT_TRUE(RouteWordClassify(0xFEEDFACE5A5A5A5Aull) == RouteWord::Garbage); // kHeapMagicFree
    EXPECT_TRUE(RouteWordClassify(0xCCCCCCCCCCCCCCCCull) == RouteWord::Garbage); // slab poison
    EXPECT_TRUE(RouteWordClassify(0xFFFF800000123450ull) == RouteWord::Garbage); // freelist link
    EXPECT_TRUE(RouteWordClassify(kSlabRouteMagic | 0x42ull) == RouteWord::Garbage);

    return ::duetos_host_test::finish_main("kmalloc_route");
}
