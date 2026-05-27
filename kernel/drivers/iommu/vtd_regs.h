#pragma once

#include "util/types.h"

/*
 * DuetOS — Intel VT-d register layout + capability bit definitions.
 *
 * From Intel Virtualization Technology for Directed I/O
 * Architecture Specification, §10 ("Register Descriptions").
 *
 * Each VT-d IOMMU exposes a 4 KiB MMIO register window at the
 * physical base address reported by the DMAR table's DRHD entry.
 * Register offsets below are bytes from that base.
 *
 * Slice 27b uses these for read-only decode. Write registers (GCMD,
 * RTADDR, IOTLB invalidate) come in slice 27c when we wire up
 * translation enable.
 */

namespace duetos::drivers::iommu::vtd
{

// Register offsets from MMIO base.
inline constexpr u32 kRegVer = 0x000;     // 32-bit Version
inline constexpr u32 kRegCap = 0x008;     // 64-bit Capability
inline constexpr u32 kRegEcap = 0x010;    // 64-bit Extended Capability
inline constexpr u32 kRegGcmd = 0x018;    // 32-bit Global Command (write-only)
inline constexpr u32 kRegGsts = 0x01C;    // 32-bit Global Status (read-only)
inline constexpr u32 kRegRtaddr = 0x020;  // 64-bit Root Table Address
inline constexpr u32 kRegCcmd = 0x028;    // 64-bit Context Command
inline constexpr u32 kRegFsts = 0x034;    // 32-bit Fault Status
inline constexpr u32 kRegFectl = 0x038;   // 32-bit Fault Event Control
inline constexpr u32 kRegFedata = 0x03C;  // 32-bit Fault Event Data
inline constexpr u32 kRegFeaddr = 0x040;  // 32-bit Fault Event Address
inline constexpr u32 kRegFeuaddr = 0x044; // 32-bit Fault Event Upper Address

// Version register fields.
inline constexpr u32 kVerMaxMajor = 0xF0; // bits 4..7
inline constexpr u32 kVerMaxMinor = 0x0F; // bits 0..3

// Capability Register (CAP) — Intel VT-d §10.4.2.
// 64-bit value. Decoded into VtdIommuInfo fields by VtdDecodeCapabilities.
inline constexpr u64 kCapNd_Mask = 0x7ULL;         // bits 0..2: Number of Domains exponent
inline constexpr u64 kCapAfl = 1ULL << 3;          // Advanced Fault Logging
inline constexpr u64 kCapRwbf = 1ULL << 4;         // Required Write Buffer Flushing
inline constexpr u64 kCapPlmr = 1ULL << 5;         // Protected Low Memory Region
inline constexpr u64 kCapPhmr = 1ULL << 6;         // Protected High Memory Region
inline constexpr u64 kCapCm = 1ULL << 7;           // Caching Mode (TLB-style cache that needs
                                                   // explicit invalidate on map/unmap)
inline constexpr u64 kCapSagawMask = 0x1FULL << 8; // bits 8..12: Supported AGAW bitmask
inline constexpr u64 kCapSagawShift = 8;
//   bit 0 of SAGAW => 30-bit AGAW (2-level page tables)
//   bit 1          => 39-bit AGAW (3-level)
//   bit 2          => 48-bit AGAW (4-level)
//   bit 3          => 57-bit AGAW (5-level)
//   bit 4          => 64-bit AGAW (reserved by hardware today)
inline constexpr u64 kCapMgawMask = 0x3FULL << 16; // bits 16..21: Max Guest Address Width - 1
inline constexpr u64 kCapMgawShift = 16;
inline constexpr u64 kCapZlr = 1ULL << 22;         // Zero-Length Reads
inline constexpr u64 kCapFroMask = 0x3FFULL << 24; // bits 24..33: Fault Record Offset (16-byte units)
inline constexpr u64 kCapFroShift = 24;
inline constexpr u64 kCapSllps2M = 1ULL << 34;    // 2 MiB second-level pages
inline constexpr u64 kCapSllps1G = 1ULL << 35;    // 1 GiB second-level pages
inline constexpr u64 kCapPsiMask = 0xFULL << 36;  // bits 36..39: page-selective invalidation
inline constexpr u64 kCapNfrMask = 0xFFULL << 40; // bits 40..47: Number of Fault Records - 1
inline constexpr u64 kCapNfrShift = 40;
inline constexpr u64 kCapMamvMask = 0x3FULL << 48; // bits 48..53: Max Address Mask Value
inline constexpr u64 kCapDwd = 1ULL << 54;         // Write Draining
inline constexpr u64 kCapDrd = 1ULL << 55;         // Read Draining
inline constexpr u64 kCapFl1gp = 1ULL << 56;       // First-Level 1 GiB Page
inline constexpr u64 kCapPi = 1ULL << 57;          // Posted Interrupts
inline constexpr u64 kCapFl5lp = 1ULL << 58;       // First-Level 5-Level Paging

// Extended Capability Register (ECAP) — Intel VT-d §10.4.3.
inline constexpr u64 kEcapC = 1ULL << 0;           // Coherency
inline constexpr u64 kEcapQi = 1ULL << 1;          // Queued Invalidation
inline constexpr u64 kEcapDt = 1ULL << 2;          // Device-TLB support
inline constexpr u64 kEcapIr = 1ULL << 3;          // Interrupt Remapping
inline constexpr u64 kEcapEim = 1ULL << 4;         // Extended Interrupt Mode (x2APIC)
inline constexpr u64 kEcapPt = 1ULL << 6;          // Pass-Through translation
inline constexpr u64 kEcapSc = 1ULL << 7;          // Snoop Control
inline constexpr u64 kEcapIroMask = 0x3FFULL << 8; // bits 8..17: IOTLB Register Offset (16-byte units)
inline constexpr u64 kEcapIroShift = 8;

// Global Status Register (GSTS) — Intel VT-d §10.4.5.
// 32-bit; bit set => corresponding feature is enabled.
inline constexpr u32 kGstsTes = 1U << 31;   // Translation Enable Status
inline constexpr u32 kGstsRtps = 1U << 30;  // Root Table Pointer Status
inline constexpr u32 kGstsFls = 1U << 29;   // Fault Log Status
inline constexpr u32 kGstsAfls = 1U << 28;  // Advanced Fault Log Status
inline constexpr u32 kGstsWbfs = 1U << 27;  // Write Buffer Flush Status
inline constexpr u32 kGstsQies = 1U << 26;  // Queued Invalidation Enable Status
inline constexpr u32 kGstsIres = 1U << 25;  // Interrupt Remap Enable Status
inline constexpr u32 kGstsIrtps = 1U << 24; // IRT Pointer Status
inline constexpr u32 kGstsCfis = 1U << 23;  // Compatibility Format Interrupt Status

// Decoded SAGAW level → AGAW value lookup.
// Returns 0 for "not advertised in SAGAW bitmask."
inline constexpr u32 SagawBitToAgawBits(u8 sagaw_bit_index)
{
    // Mapping per Intel VT-d §10.4.2:
    //   SAGAW bit 0 = 30, bit 1 = 39, bit 2 = 48, bit 3 = 57, bit 4 = 64
    constexpr u32 lookup[5] = {30, 39, 48, 57, 64};
    return sagaw_bit_index < 5 ? lookup[sagaw_bit_index] : 0;
}

} // namespace duetos::drivers::iommu::vtd
