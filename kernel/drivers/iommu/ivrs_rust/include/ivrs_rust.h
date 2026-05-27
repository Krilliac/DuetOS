// DuetOS AMD-Vi IVRS (I/O Virtualization Reporting Structure)
// ACPI-table parser C FFI — hand-written.
// Mirrors kernel/drivers/iommu/ivrs_rust/src/lib.rs.

#pragma once

#include "util/types.h"

namespace duetos::drivers::iommu::ivrs
{

inline constexpr u8 kIvrsTypeIvhdFixed = 0x10;
inline constexpr u8 kIvrsTypeIvhdExtended = 0x11;
inline constexpr u8 kIvrsTypeIvhdFull = 0x40;
inline constexpr u8 kIvrsTypeIvmdAll = 0x20;
inline constexpr u8 kIvrsTypeIvmdSingle = 0x21;
inline constexpr u8 kIvrsTypeIvmdRange = 0x22;

inline constexpr u32 kIvrsMaxIvhds = 8;
inline constexpr u32 kIvrsMaxIvmds = 8;

struct DuetosIvrsIvhd
{
    u8 block_type;
    u8 flags;
    u16 device_id;
    u16 capability_offset;
    u16 pci_segment;
    u32 _pad0;
    u64 iommu_base_address;
    u16 iommu_info;
    u8 _pad1[6];
    u32 feature_information;
    u32 _pad2;
    u64 efr_register_image; // valid for type 0x11/0x40; 0 for 0x10
};

struct DuetosIvrsIvmd
{
    u8 block_type;
    u8 flags;
    u16 device_id_start;
    u16 aux_data;
    u8 _pad[6];
    u64 start_address;
    u64 memory_length;
};

struct DuetosIvrs
{
    u32 iv_info;
    u32 _pad0;
    u32 n_ivhds;
    u32 n_ivmds;
    DuetosIvrsIvhd ivhds[kIvrsMaxIvhds];
    DuetosIvrsIvmd ivmds[kIvrsMaxIvmds];
    u8 ok;
    u8 _pad1[7];
};

extern "C"
{
    /// Decode the IVRS ACPI table. `buf` points at the start of the
    /// 36-byte SDT header (signature "IVRS"); `len` is the full
    /// buffer length. `out` is fully overwritten on every call.
    bool duetos_ivrs_parse(const u8* buf, usize len, DuetosIvrs* out);

    /// Reset `out` to default-constructed (zero) state.
    void duetos_ivrs_zero(DuetosIvrs* out);
}

} // namespace duetos::drivers::iommu::ivrs
