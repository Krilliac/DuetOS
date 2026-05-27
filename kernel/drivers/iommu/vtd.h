#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel VT-d IOMMU register access + capability decode.
 *
 * Reads each DRHD's MMIO register window (mapped via mm::MapMmio)
 * and decodes the Version / Capability / Extended Capability
 * registers into a typed VtdIommuInfo so later slices can program
 * the IOMMU without re-decoding every time.
 *
 * Slice 27b — READ-ONLY. No control bits written. No translation
 * enabled. No page-table allocation. The output is data the next
 * slice (27c, page-table + enable) will consume.
 *
 * Context: kernel. VtdInit runs once after DmarInit() — needs the
 * DRHD list to know which register windows to map.
 */

namespace duetos::drivers::iommu
{

struct VtdIommuInfo
{
    u64 register_base_phys; // From DRHD; the physical MMIO base.
    void* register_mmio;    // Mapped virtual address (page-aligned + base offset).
    u16 segment;            // PCI segment number from DRHD.
    u8 drhd_flags;          // DRHD entry flags (INCLUDE_PCI_ALL etc.).

    // Decoded from the Version register.
    u8 version_major;
    u8 version_minor;

    // Raw capability registers, in case a caller needs a bit we
    // haven't decoded yet.
    u64 cap_raw;
    u64 ecap_raw;

    // Decoded from CAP.
    u8 sagaw_mask;           // 5-bit SAGAW field — bit i ↔ AGAW value (30/39/48/57/64)
    u8 max_gaw_minus_1;      // MGAW field (physical address width - 1)
    u8 num_fault_records;    // NFR + 1
    u32 fault_record_offset; // FRO * 16
    bool caching_mode;       // CM bit
    bool plmr_supported;     // Protected Low Memory Region
    bool phmr_supported;     // Protected High Memory Region
    bool sllps_2m_supported; // Second-level 2 MiB pages
    bool sllps_1g_supported; // Second-level 1 GiB pages
    bool fl5lp_supported;    // First-level 5-level paging

    // Decoded from ECAP.
    bool coherency;            // C
    bool queued_invalidation;  // QI
    bool device_tlb;           // DT
    bool intr_remap;           // IR
    bool extended_intr_mode;   // EIM
    bool pass_through;         // PT
    bool snoop_control;        // SC
    u32 iotlb_register_offset; // IRO * 16
};

/// Map each DRHD's MMIO window and decode its capability
/// registers. Idempotent. No-op if DmarPresent() is false.
///
/// Emits `[vtd] iommu[i] base=... ver=Major.Minor cap=... ecap=...`
/// for every successfully decoded IOMMU, and
/// `[vtd] iommu[i] map failed` for any that couldn't be mapped.
void VtdInit();

/// True if at least one IOMMU was discovered + mapped.
bool VtdAvailable();

/// Number of IOMMU register windows successfully decoded.
u32 VtdIommuCount();

/// Get the i-th IOMMU's info. Returns nullptr if out of range or
/// VtdAvailable() is false.
const VtdIommuInfo* VtdGetIommu(u32 index);

/// Boot-time self-test. Synthesises a 4 KiB register window in
/// stack memory + decodes it through the same path VtdInit uses
/// + asserts every field round-trips. Saves/restores live cached
/// state so re-runs are idempotent. Emits `[vtd-selftest] PASS`.
void VtdSelfTest();

/// True iff the kernel was built with DUETOS_IOMMU_ENABLE=1. The
/// flag is OFF by default — a regression in the enable path would
/// otherwise brick all device DMA at boot. Operators turn it on
/// per-build via `cmake -DDUETOS_IOMMU_ENABLE=ON`.
bool VtdEnableRequested();

/// Program every discovered IOMMU with the identity-passthrough
/// page tables built by VtdPagingInit, invalidate context cache +
/// IOTLB, then flip GCMD.TE to turn translation on. Idempotent:
/// IOMMUs already showing GSTS.TES are skipped.
///
/// Returns:
///   - InvalidArgument if VtdAvailable() is false (no IOMMU found)
///   - BadState if VtdPagingInit hasn't run
///   - Timeout if GSTS.RTPS or GSTS.TES doesn't flip within the
///     hardware-recommended bound (1ms / ~10000 reads)
///   - Ok otherwise. Every IOMMU's TES bit is now set.
///
/// Caller is responsible for gating on VtdEnableRequested() —
/// VtdProgramAndEnable does NOT consult the build flag itself.
::duetos::core::Result<void> VtdProgramAndEnable();

} // namespace duetos::drivers::iommu
