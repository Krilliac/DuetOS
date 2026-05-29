#include "drivers/iommu/vtd_paging.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"

namespace duetos::drivers::iommu::vtd_paging
{

namespace
{

constinit VtdPagingState g_state{};
constinit bool g_initialized = false;

// Zero a freshly-allocated 4 KiB frame via the direct map. Every
// VT-d table entry whose Present bit is 0 means "fault on access,"
// so zero is the safe default.
void ZeroFrame(u64 phys)
{
    auto* p = static_cast<volatile u64*>(mm::PhysToVirt(phys));
    for (u32 i = 0; i < kPageBytes / sizeof(u64); ++i)
        p[i] = 0;
}

void* PhysToWritable(u64 phys)
{
    return mm::PhysToVirt(phys);
}

} // namespace

::duetos::core::Result<VtdPagingState> VtdPagingInit()
{
    if (g_initialized)
        return g_state;

    // Allocate the three frames we need. If any allocation fails
    // we MUST free the prior ones — otherwise an OOM on the second
    // call leaks the first frame forever. Tracking by local
    // variables (vs g_state) means a failure leaves g_initialized
    // false and a retry starts fresh.
    auto root_phys_r = mm::AllocateFrame();
    if (!root_phys_r)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    const mm::PhysAddr root_phys = root_phys_r.value();

    auto ctx_phys_r = mm::AllocateFrame();
    if (!ctx_phys_r)
    {
        mm::FreeFrame(root_phys);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    const mm::PhysAddr ctx_phys = ctx_phys_r.value();

    auto pdpt_phys_r = mm::AllocateFrame();
    if (!pdpt_phys_r)
    {
        mm::FreeFrame(root_phys);
        mm::FreeFrame(ctx_phys);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    const mm::PhysAddr pdpt_phys = pdpt_phys_r.value();

    ZeroFrame(root_phys);
    ZeroFrame(ctx_phys);
    ZeroFrame(pdpt_phys);

    // PDPT: 512 entries, each a 1 GiB identity-mapping leaf.
    //   bit 0 (R), bit 1 (W), bit 7 (PageSize=1 → leaf at this level),
    //   bits 30..(physaddr-1): the 1 GiB-aligned base address.
    auto* pdpt = static_cast<volatile u64*>(PhysToWritable(pdpt_phys));
    for (u32 i = 0; i < kPdptEntries; ++i)
    {
        const u64 leaf_base = static_cast<u64>(i) * kGiB;
        pdpt[i] = leaf_base | kPteRead | kPteWrite | kPtePageSize;
    }

    // Context table: 256 entries (indexed by 8-bit dev:func). All
    // entries point to the SAME PDPT. Translation Type = 00
    // (untranslated + translation requests → SLPT), AW = 3-level,
    // Domain ID = 0.
    //
    // Each CTE is 16 bytes: low u64 + high u64. The low half
    // carries Present + TT + SLPTPTR; the high half carries AW +
    // Domain ID.
    auto* ctx = static_cast<volatile u64*>(PhysToWritable(ctx_phys));
    for (u32 i = 0; i < kContextTableEntries; ++i)
    {
        const u64 lo = kCteLowPresent | kCteLowTtUntranslatedSlpt | pdpt_phys;
        const u64 hi = kCteHighAw3Level; // AW=1 (3-level), Domain=0
        ctx[i * 2 + 0] = lo;
        ctx[i * 2 + 1] = hi;
    }

    // Root table: 256 entries (indexed by 8-bit bus). All entries
    // point to the SAME context table. Each RTE is 16 bytes:
    // low u64 (Present + CTP) + high u64 (reserved).
    auto* root = static_cast<volatile u64*>(PhysToWritable(root_phys));
    for (u32 i = 0; i < kRootTableEntries; ++i)
    {
        root[i * 2 + 0] = kRteLowPresent | ctx_phys;
        root[i * 2 + 1] = 0;
    }

    g_state.root_table_phys = root_phys;
    g_state.context_table_phys = ctx_phys;
    g_state.pdpt_phys = pdpt_phys;
    g_state.agaw_levels = 3;
    g_initialized = true;

    return g_state;
}

::duetos::core::Result<VtdPagingState> VtdPagingGet()
{
    if (!g_initialized)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    return g_state;
}

::duetos::core::Result<u64> VtdWalk(u8 bus, u8 dev, u8 func, u64 iova)
{
    if (!g_initialized)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

    if (dev >= 32 || func >= 8)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // 1. Source-id (bus:dev:func) → root table[bus] → context table.
    const auto* root = static_cast<const volatile u64*>(PhysToWritable(g_state.root_table_phys));
    const u64 rte_lo = root[bus * 2 + 0];
    if ((rte_lo & kRteLowPresent) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    const u64 ctx_phys = rte_lo & ~static_cast<u64>(0xFFF); // strip flags

    // 2. context table[(dev<<3)|func] → SLPT root + AW.
    const u32 ctx_idx = (static_cast<u32>(dev) << 3) | func;
    const auto* ctx = static_cast<const volatile u64*>(PhysToWritable(ctx_phys));
    const u64 cte_lo = ctx[ctx_idx * 2 + 0];
    const u64 cte_hi = ctx[ctx_idx * 2 + 1];
    if ((cte_lo & kCteLowPresent) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    const u64 aw = cte_hi & 0x7;
    if (aw != kCteHighAw3Level)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    const u64 slpt_phys = cte_lo & ~static_cast<u64>(0xFFF);

    // 3. 3-level walk. IOVA bits split as 9 (PDPT) + 9 (PD) + 9
    //    (PT) + 12 (offset). v0 has only one level populated (PDPT
    //    with PS=1 leaves), so the PDPT entry must have kPtePageSize
    //    set; the offset is the low 30 bits of the IOVA.
    if ((iova >> 39) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    const u32 pdpt_idx = static_cast<u32>((iova >> 30) & 0x1FF);
    const auto* pdpt = static_cast<const volatile u64*>(PhysToWritable(slpt_phys));
    const u64 pdpte = pdpt[pdpt_idx];
    if ((pdpte & kPteRead) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    if ((pdpte & kPtePageSize) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported}; // we only build 1 GiB leaves

    const u64 leaf_base = pdpte & ~static_cast<u64>((1ULL << 30) - 1);
    const u64 page_offset = iova & ((1ULL << 30) - 1);
    return leaf_base + page_offset;
}

void VtdPagingSelfTest()
{
    // VtdPagingInit is allocation-only — no side effects beyond
    // grabbing 3 frames. Idempotent. If we don't already have a
    // state, build one for the duration of the test and DO NOT
    // free it (the next slice's enable path will own these frames).
    const bool was_initialized = g_initialized;
    auto init_result = VtdPagingInit();
    KASSERT(init_result.has_value(), "drivers/iommu/vtd_paging", "VtdPagingInit failed (frame OOM?)");
    const VtdPagingState state = init_result.value();
    KASSERT(state.agaw_levels == 3, "drivers/iommu/vtd_paging", "expected 3-level (39-bit) AGAW");
    KASSERT(state.root_table_phys != 0, "drivers/iommu/vtd_paging", "root table phys is zero");
    KASSERT(state.context_table_phys != 0, "drivers/iommu/vtd_paging", "context table phys is zero");
    KASSERT(state.pdpt_phys != 0, "drivers/iommu/vtd_paging", "PDPT phys is zero");

    // Identity walk at IOVA 0 from (0,0,0) — exercises the
    // happy path through every level.
    auto walk0 = VtdWalk(0, 0, 0, 0x0);
    KASSERT(walk0.has_value() && walk0.value() == 0x0, "drivers/iommu/vtd_paging",
            "walk(0,0,0, 0x0) should be identity");

    // Mid-1G-leaf offset — checks page_offset reconstruction.
    auto walk1 = VtdWalk(0, 0, 0, 0x123456);
    KASSERT(walk1.has_value() && walk1.value() == 0x123456ULL, "drivers/iommu/vtd_paging",
            "walk identity broke at offset within first GiB");

    // PDPT index 1 — exercises the >>30 shift / second leaf.
    auto walk2 = VtdWalk(0, 0, 0, 0x40000000ULL);
    KASSERT(walk2.has_value() && walk2.value() == 0x40000000ULL, "drivers/iommu/vtd_paging",
            "walk identity broke at 1 GiB boundary");

    // Last PDPT index (511) + offset.
    auto walk3 = VtdWalk(0, 0, 0, (511ULL << 30) | 0xDEAD);
    KASSERT(walk3.has_value() && walk3.value() == ((511ULL << 30) | 0xDEAD), "drivers/iommu/vtd_paging",
            "walk identity broke at last PDPT entry");

    // Different source-id (bus=1, dev=5, func=3) — must still
    // resolve identity because all root + context entries share
    // the same PDPT.
    auto walk4 = VtdWalk(1, 5, 3, 0xABCDEF);
    KASSERT(walk4.has_value() && walk4.value() == 0xABCDEFULL, "drivers/iommu/vtd_paging",
            "walk identity broke for non-zero source-id");

    // Out-of-AGAW IOVA — bit 39 set is beyond 39-bit AGAW.
    auto walk5 = VtdWalk(0, 0, 0, 1ULL << 39);
    KASSERT(!walk5.has_value() && walk5.error() == ::duetos::core::ErrorCode::InvalidArgument,
            "drivers/iommu/vtd_paging", "IOVA beyond AGAW should be InvalidArgument");

    // Out-of-range device function.
    auto walk6 = VtdWalk(0, 32, 0, 0);
    KASSERT(!walk6.has_value() && walk6.error() == ::duetos::core::ErrorCode::InvalidArgument,
            "drivers/iommu/vtd_paging", "dev>=32 should be InvalidArgument");

    arch::SerialWrite("[vtd-paging-selftest] PASS root=");
    char buf[19] = {'0', 'x'};
    for (int i = 0; i < 16; ++i)
    {
        const u8 nibble = (state.root_table_phys >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = nibble < 10 ? ('0' + nibble) : ('A' + nibble - 10);
    }
    buf[18] = 0;
    arch::SerialWrite(buf);
    arch::SerialWrite(" pdpt=");
    for (int i = 0; i < 16; ++i)
    {
        const u8 nibble = (state.pdpt_phys >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = nibble < 10 ? ('0' + nibble) : ('A' + nibble - 10);
    }
    arch::SerialWrite(buf);
    arch::SerialWrite("\n");

    (void)was_initialized;
}

} // namespace duetos::drivers::iommu::vtd_paging
