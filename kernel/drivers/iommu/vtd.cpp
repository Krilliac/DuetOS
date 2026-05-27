#include "drivers/iommu/vtd.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/iommu/dmar.h"
#include "drivers/iommu/vtd_regs.h"
#include "mm/paging.h"

namespace duetos::drivers::iommu
{

namespace
{

constexpr u32 kMaxIommus = 16;                  // matches dmar_rust's DMAR_MAX_DRHDS
constexpr u32 kVtdRegisterWindowBytes = 0x1000; // 4 KiB MMIO window per Intel VT-d spec

constinit VtdIommuInfo g_iommus[kMaxIommus]{};
constinit u32 g_iommu_count = 0;
constinit bool g_initialized = false;

// MMIO accessors. The register window is mapped uncached (MapMmio
// uses kKernelMmio attributes), so volatile reads / writes are
// sufficient — no fence needed on x86.
inline u32 ReadReg32(void* base, u32 offset)
{
    return *reinterpret_cast<volatile u32*>(reinterpret_cast<u8*>(base) + offset);
}

inline u64 ReadReg64(void* base, u32 offset)
{
    return *reinterpret_cast<volatile u64*>(reinterpret_cast<u8*>(base) + offset);
}

void SerialWriteHex64(u64 v)
{
    char buf[19] = {'0', 'x'};
    for (int i = 0; i < 16; ++i)
    {
        const u8 nibble = (v >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = nibble < 10 ? ('0' + nibble) : ('A' + nibble - 10);
    }
    buf[18] = 0;
    arch::SerialWrite(buf);
}

void SerialWriteDec(u32 v)
{
    char buf[12] = {0};
    if (v == 0)
    {
        buf[0] = '0';
        arch::SerialWrite(buf);
        return;
    }
    char rev[12];
    int rl = 0;
    while (v)
    {
        rev[rl++] = '0' + (v % 10);
        v /= 10;
    }
    int bi = 0;
    while (rl > 0)
        buf[bi++] = rev[--rl];
    arch::SerialWrite(buf);
}

// Decode the Version / CAP / ECAP registers into the typed
// VtdIommuInfo. Pure; no side effects beyond writing `*info`.
// Exposed as a free function so the self-test can hit it with a
// synthesised register window without going through MapMmio.
void DecodeFromMmio(VtdIommuInfo* info, void* mmio)
{
    using namespace vtd;

    const u32 ver = ReadReg32(mmio, kRegVer);
    info->version_major = static_cast<u8>((ver & kVerMaxMajor) >> 4);
    info->version_minor = static_cast<u8>(ver & kVerMaxMinor);

    const u64 cap = ReadReg64(mmio, kRegCap);
    const u64 ecap = ReadReg64(mmio, kRegEcap);
    info->cap_raw = cap;
    info->ecap_raw = ecap;

    info->sagaw_mask = static_cast<u8>((cap & kCapSagawMask) >> kCapSagawShift);
    info->max_gaw_minus_1 = static_cast<u8>((cap & kCapMgawMask) >> kCapMgawShift);
    info->num_fault_records = static_cast<u8>((cap & kCapNfrMask) >> kCapNfrShift) + 1;
    info->fault_record_offset = static_cast<u32>(((cap & kCapFroMask) >> kCapFroShift) * 16);
    info->caching_mode = (cap & kCapCm) != 0;
    info->plmr_supported = (cap & kCapPlmr) != 0;
    info->phmr_supported = (cap & kCapPhmr) != 0;
    info->sllps_2m_supported = (cap & kCapSllps2M) != 0;
    info->sllps_1g_supported = (cap & kCapSllps1G) != 0;
    info->fl5lp_supported = (cap & kCapFl5lp) != 0;

    info->coherency = (ecap & kEcapC) != 0;
    info->queued_invalidation = (ecap & kEcapQi) != 0;
    info->device_tlb = (ecap & kEcapDt) != 0;
    info->intr_remap = (ecap & kEcapIr) != 0;
    info->extended_intr_mode = (ecap & kEcapEim) != 0;
    info->pass_through = (ecap & kEcapPt) != 0;
    info->snoop_control = (ecap & kEcapSc) != 0;
    info->iotlb_register_offset = static_cast<u32>(((ecap & kEcapIroMask) >> kEcapIroShift) * 16);
}

void LogIommuSummary(u32 idx, const VtdIommuInfo& info)
{
    arch::SerialWrite("[vtd] iommu[");
    SerialWriteDec(idx);
    arch::SerialWrite("] base=");
    SerialWriteHex64(info.register_base_phys);
    arch::SerialWrite(" ver=");
    SerialWriteDec(info.version_major);
    arch::SerialWrite(".");
    SerialWriteDec(info.version_minor);
    arch::SerialWrite(" mgaw=");
    SerialWriteDec(info.max_gaw_minus_1 + 1);
    arch::SerialWrite(" sagaw=");
    SerialWriteHex64(info.sagaw_mask);
    arch::SerialWrite(" cap=");
    SerialWriteHex64(info.cap_raw);
    arch::SerialWrite(" ecap=");
    SerialWriteHex64(info.ecap_raw);
    arch::SerialWrite(" features=");
    if (info.intr_remap)
        arch::SerialWrite("IR+");
    if (info.queued_invalidation)
        arch::SerialWrite("QI+");
    if (info.pass_through)
        arch::SerialWrite("PT+");
    if (info.snoop_control)
        arch::SerialWrite("SC+");
    if (info.sllps_2m_supported)
        arch::SerialWrite("2M+");
    if (info.sllps_1g_supported)
        arch::SerialWrite("1G+");
    if (info.caching_mode)
        arch::SerialWrite("CM+");
    arch::SerialWrite("\n");
}

} // namespace

void VtdInit()
{
    if (g_initialized)
        return;
    g_initialized = true;

    if (!DmarPresent())
    {
        // QEMU-default / VirtualBox path. DmarInit's log already
        // recorded the absence; nothing more to do here.
        return;
    }

    const u32 n = DmarDrhdCount();
    for (u32 i = 0; i < n && g_iommu_count < kMaxIommus; ++i)
    {
        const auto* drhd = DmarDrhd(i);
        if (drhd == nullptr || drhd->register_base == 0)
            continue;

        void* mmio = mm::MapMmio(drhd->register_base, kVtdRegisterWindowBytes);
        if (mmio == nullptr)
        {
            arch::SerialWrite("[vtd] iommu[");
            SerialWriteDec(i);
            arch::SerialWrite("] map failed (base=");
            SerialWriteHex64(drhd->register_base);
            arch::SerialWrite(")\n");
            continue;
        }

        VtdIommuInfo* info = &g_iommus[g_iommu_count];
        *info = VtdIommuInfo{};
        info->register_base_phys = drhd->register_base;
        info->register_mmio = mmio;
        info->segment = drhd->segment;
        info->drhd_flags = drhd->flags;
        DecodeFromMmio(info, mmio);
        LogIommuSummary(g_iommu_count, *info);
        ++g_iommu_count;
    }
}

bool VtdAvailable()
{
    return g_initialized && g_iommu_count > 0;
}

u32 VtdIommuCount()
{
    return g_iommu_count;
}

const VtdIommuInfo* VtdGetIommu(u32 index)
{
    if (!VtdAvailable() || index >= g_iommu_count)
        return nullptr;
    return &g_iommus[index];
}

void VtdSelfTest()
{
    // Build a synthetic 4 KiB register window in stack memory, fill
    // the registers we decode with deterministic non-trivial values,
    // run the decode, and assert every field round-trips.
    //
    // alignas(8) is required: ReadReg64 dereferences a u64* at
    // offset kRegCap = 0x008 and kRegEcap = 0x010.

    alignas(8) static u8 fake_window[kVtdRegisterWindowBytes];
    for (u32 i = 0; i < sizeof(fake_window); ++i)
        fake_window[i] = 0;

    // Version 1.0 — what every shipping VT-d implementation reports.
    *reinterpret_cast<volatile u32*>(fake_window + vtd::kRegVer) = (1u << 4) | 0u;

    // CAP — set fields with distinct, identifiable values so a wrong
    // shift produces a visibly wrong decode:
    //   ND=4 (32 domains), CM=1, SAGAW=0x6 (39+48-bit AGAW),
    //   MGAW=46 (47-bit physical), FRO=0x40 (=> offset 0x400),
    //   SLLPS_2M=1, SLLPS_1G=1, NFR=15 (=> 16 records).
    u64 cap = 0;
    cap |= 4ULL;                            // ND
    cap |= vtd::kCapCm;                     // CM
    cap |= (0x6ULL << vtd::kCapSagawShift); // SAGAW = bits 1+2
    cap |= (46ULL << vtd::kCapMgawShift);   // MGAW = 46
    cap |= (0x40ULL << vtd::kCapFroShift);  // FRO = 0x40 (16-byte units)
    cap |= vtd::kCapSllps2M;
    cap |= vtd::kCapSllps1G;
    cap |= (15ULL << vtd::kCapNfrShift); // NFR = 15
    *reinterpret_cast<volatile u64*>(fake_window + vtd::kRegCap) = cap;

    // ECAP — IR + QI + EIM + PT + SC + IRO=0x80 (=> offset 0x800).
    u64 ecap = 0;
    ecap |= vtd::kEcapQi;
    ecap |= vtd::kEcapIr;
    ecap |= vtd::kEcapEim;
    ecap |= vtd::kEcapPt;
    ecap |= vtd::kEcapSc;
    ecap |= (0x80ULL << vtd::kEcapIroShift);
    *reinterpret_cast<volatile u64*>(fake_window + vtd::kRegEcap) = ecap;

    VtdIommuInfo info{};
    DecodeFromMmio(&info, fake_window);

    KASSERT(info.version_major == 1, "drivers/iommu/vtd", "version major decode wrong");
    KASSERT(info.version_minor == 0, "drivers/iommu/vtd", "version minor decode wrong");
    KASSERT(info.cap_raw == cap, "drivers/iommu/vtd", "cap raw not preserved");
    KASSERT(info.ecap_raw == ecap, "drivers/iommu/vtd", "ecap raw not preserved");
    KASSERT(info.sagaw_mask == 0x6, "drivers/iommu/vtd", "SAGAW field decode wrong");
    KASSERT(info.max_gaw_minus_1 == 46, "drivers/iommu/vtd", "MGAW field decode wrong");
    KASSERT(info.num_fault_records == 16, "drivers/iommu/vtd", "NFR field decode wrong (off-by-one?)");
    KASSERT(info.fault_record_offset == 0x400, "drivers/iommu/vtd", "FRO scale wrong (should be *16)");
    KASSERT(info.caching_mode, "drivers/iommu/vtd", "CM bit decode wrong");
    KASSERT(info.sllps_2m_supported, "drivers/iommu/vtd", "SLLPS_2M decode wrong");
    KASSERT(info.sllps_1g_supported, "drivers/iommu/vtd", "SLLPS_1G decode wrong");
    KASSERT(!info.plmr_supported, "drivers/iommu/vtd", "PLMR false-positive");
    KASSERT(info.queued_invalidation, "drivers/iommu/vtd", "QI decode wrong");
    KASSERT(info.intr_remap, "drivers/iommu/vtd", "IR decode wrong");
    KASSERT(info.extended_intr_mode, "drivers/iommu/vtd", "EIM decode wrong");
    KASSERT(info.pass_through, "drivers/iommu/vtd", "PT decode wrong");
    KASSERT(info.snoop_control, "drivers/iommu/vtd", "SC decode wrong");
    KASSERT(!info.device_tlb, "drivers/iommu/vtd", "DT false-positive");
    KASSERT(info.iotlb_register_offset == 0x800, "drivers/iommu/vtd", "IRO scale wrong (should be *16)");

    // SAGAW bit → AGAW value lookup. SAGAW=0x6 means bits 1+2 set:
    // 39-bit AGAW (bit 1) and 48-bit AGAW (bit 2).
    KASSERT(vtd::SagawBitToAgawBits(1) == 39, "drivers/iommu/vtd", "SAGAW bit 1 should map to AGAW 39");
    KASSERT(vtd::SagawBitToAgawBits(2) == 48, "drivers/iommu/vtd", "SAGAW bit 2 should map to AGAW 48");
    KASSERT(vtd::SagawBitToAgawBits(0) == 30, "drivers/iommu/vtd", "SAGAW bit 0 should map to AGAW 30");
    KASSERT(vtd::SagawBitToAgawBits(5) == 0, "drivers/iommu/vtd", "SAGAW bit 5 should be invalid");

    arch::SerialWrite("[vtd-selftest] PASS\n");
}

} // namespace duetos::drivers::iommu
