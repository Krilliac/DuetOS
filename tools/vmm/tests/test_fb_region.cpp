#include "test_main.h"
#include "guest_memory.h"

using duetos::vmm::ComputeFbRegion;

// GuestMemory requires a live WHP Partition so we test the pure
// ComputeFbRegion helper directly (the fallback path described in the
// task spec).  ReserveFramebuffer() delegates to ComputeFbRegion
// internally, so these assertions cover the alignment/sizing/
// idempotency contract without needing a real hypervisor partition.

TEST(fb_region_is_page_aligned_and_below_ram_top)
{
    constexpr uint64_t kRam = 64ull * 1024 * 1024;
    uint64_t gpa   = 0;
    uint64_t bytes = 0;
    bool ok = ComputeFbRegion(kRam, 1280, 1024, gpa, bytes);
    CHECK(ok);
    CHECK(gpa != 0);
    CHECK_EQ(gpa % 4096, 0u);
    CHECK_EQ(bytes, uint64_t(1280) * 1024 * 4); // raw pixel bytes — rounded up (already page-multiple)
    CHECK(gpa + bytes <= kRam);
}

TEST(fb_region_idempotent)
{
    constexpr uint64_t kRam = 64ull * 1024 * 1024;
    uint64_t gpa1 = 0, bytes1 = 0;
    uint64_t gpa2 = 0, bytes2 = 0;
    ComputeFbRegion(kRam, 1280, 1024, gpa1, bytes1);
    ComputeFbRegion(kRam, 1280, 1024, gpa2, bytes2);
    CHECK_EQ(gpa1, gpa2);
    CHECK_EQ(bytes1, bytes2);
}

TEST(fb_region_bytes_page_rounded)
{
    // 800x600x4 = 1 920 000 bytes, not a page multiple → must round up.
    constexpr uint64_t kRam = 64ull * 1024 * 1024;
    uint64_t gpa = 0, bytes = 0;
    bool ok = ComputeFbRegion(kRam, 800, 600, gpa, bytes);
    CHECK(ok);
    CHECK_EQ(bytes % 4096, 0u);
    CHECK(bytes >= uint64_t(800) * 600 * 4);
}
