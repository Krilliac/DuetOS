#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — AMD GFX9-GFX11 GPUVM PTE groundwork.
 *
 * This file owns the pure part of the AMD page-table contract: encoding a
 * system-memory leaf PTE for the generations covered by the current AMD
 * driver. It deliberately does not allocate a page table, write BAR5, touch
 * VM_CONTEXT registers, or submit a VM update packet. Those operations remain
 * gated on a future VMID/PSP bring-up slice.
 *
 * The layout follows the public amdgpu GPUVM contract:
 *   bit 0       VALID
 *   bit 1       SYSTEM (page is in host memory)
 *   bit 2       SNOOPED (coherent system-memory access)
 *   bit 4       EXECUTABLE
 *   bit 5       READABLE
 *   bit 6       WRITEABLE
 *   bits 47:12  48-bit page-aligned physical address
 *   GFX9        MTYPE_CC in bits 59:57
 *   GFX10/GFX11 MTYPE_CC in bits 50:48
 *
 * A request is rejected instead of being silently aligned or truncated. That
 * is important for the eventual page-table writer: an accidental alias or a
 * PTE whose permission bits were lost is worse than a refused mapping.
 */

namespace duetos::drivers::gpu::amd
{

enum class AmdGpuVmGeneration : u8
{
    kGfx9,
    kGfx10,
    kGfx11,
};

enum class AmdGpuVmAccess : u8
{
    kNone = 0,
    kRead = 1u << 0,
    kWrite = 1u << 1,
    kExecute = 1u << 2,
};

constexpr AmdGpuVmAccess operator|(AmdGpuVmAccess lhs, AmdGpuVmAccess rhs)
{
    return static_cast<AmdGpuVmAccess>(static_cast<u8>(lhs) | static_cast<u8>(rhs));
}

constexpr bool HasAmdGpuVmAccess(AmdGpuVmAccess access, AmdGpuVmAccess bit)
{
    return (static_cast<u8>(access) & static_cast<u8>(bit)) != 0;
}

enum class AmdGpuVmReject : u8
{
    kUnknownGeneration,
    kMissingAccess,
    kUnknownAccessBits,
    kPhysicalAddressUnaligned,
    kPhysicalAddressOutOfRange,
};

struct AmdGpuVmPteRequest
{
    AmdGpuVmGeneration generation;
    u64 physical_address;
    AmdGpuVmAccess access;
};

inline constexpr u64 kAmdGpuVmPageMask = ~0xFFFull;
inline constexpr u64 kAmdGpuVmAddressMask = 0x0000FFFFFFFFF000ull;

inline constexpr u64 kAmdGpuVmPteValid = 1ull << 0;
inline constexpr u64 kAmdGpuVmPteSystem = 1ull << 1;
inline constexpr u64 kAmdGpuVmPteSnooped = 1ull << 2;
inline constexpr u64 kAmdGpuVmPteExecutable = 1ull << 4;
inline constexpr u64 kAmdGpuVmPteReadable = 1ull << 5;
inline constexpr u64 kAmdGpuVmPteWriteable = 1ull << 6;

inline constexpr u64 kAmdGpuVmMtypeCc = 2;
inline constexpr u32 kAmdGpuVmGfx9MtypeShift = 57;
inline constexpr u32 kAmdGpuVmGfx10MtypeShift = 48;
inline constexpr u64 kAmdGpuVmMtypeMask = 0x7ull;

/// Encode one validated system-memory leaf PTE. No MMIO or page-table write
/// occurs here; the returned value is only a hardware-format data word.
::duetos::core::Result<u64, AmdGpuVmReject> EncodeAmdGpuVmSystemPte(const AmdGpuVmPteRequest& request);

/// Pure boot self-test for the generation-specific PTE encoders. It is safe
/// without AMD hardware and checks both the happy path and reject paths.
void AmdGpuVmSelfTest();

} // namespace duetos::drivers::gpu::amd
