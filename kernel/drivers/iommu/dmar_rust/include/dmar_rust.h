// DuetOS Intel VT-d DMAR (DMA Remapping Reporting) ACPI-table
// parser C FFI — hand-written.
// Mirrors kernel/drivers/iommu/dmar_rust/src/lib.rs.

#pragma once

#include "util/types.h"

namespace duetos::drivers::iommu::dmar
{

inline constexpr u16 kDmarTypeDrhd = 0;
inline constexpr u16 kDmarTypeRmrr = 1;
inline constexpr u16 kDmarTypeAtsr = 2;
inline constexpr u16 kDmarTypeRhsa = 3;
inline constexpr u16 kDmarTypeAndd = 4;
inline constexpr u16 kDmarTypeSatc = 5;

inline constexpr u8 kDmarDrhdFlagIncludePciAll = 1u << 0;
inline constexpr u8 kDmarDrhdFlagAtsRequired = 1u << 1;

inline constexpr u8 kDmarHeaderFlagIntrRemap = 1u << 0;
inline constexpr u8 kDmarHeaderFlagX2ApicOptOut = 1u << 1;
inline constexpr u8 kDmarHeaderFlagDmaCtrlPlatformOptIn = 1u << 2;

inline constexpr u32 kDmarMaxDrhds = 16;
inline constexpr u32 kDmarMaxRmrrs = 16;

struct DuetosDmarDrhd
{
    u8 flags;
    u8 _pad0;
    u16 segment;
    u32 _pad1;
    u64 register_base;
};

struct DuetosDmarRmrr
{
    u16 segment;
    u8 _pad[6];
    u64 base_address;
    u64 limit_address;
};

struct DuetosDmar
{
    u8 host_address_width;
    u8 flags;
    u8 _pad0[2];
    u32 n_drhds;
    u32 n_rmrrs;
    DuetosDmarDrhd drhds[kDmarMaxDrhds];
    DuetosDmarRmrr rmrrs[kDmarMaxRmrrs];
    u8 ok;
    u8 _pad1[7];
};

extern "C"
{
    /// Decode the DMAR ACPI table. `buf` points at the start of the
    /// 36-byte SDT header (signature "DMAR"); `len` is the full
    /// buffer length the caller provides. Returns true on success;
    /// `out->ok` is also set to 1. `out` is fully overwritten on
    /// every call.
    bool duetos_dmar_parse(const u8* buf, usize len, DuetosDmar* out);

    /// Reset `out` to a default-constructed DuetosDmar (every field
    /// zero, `ok=0`). Idempotent; safe on a partially populated
    /// struct.
    void duetos_dmar_zero(DuetosDmar* out);
}

} // namespace duetos::drivers::iommu::dmar
