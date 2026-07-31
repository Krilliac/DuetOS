#include "drivers/gpu/amd_gpu_vm.h"

#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "debug/probes.h"
#include "util/build_config.h"

namespace duetos::drivers::gpu::amd
{

namespace
{

inline constexpr u8 kKnownAccessBits = static_cast<u8>(AmdGpuVmAccess::kRead) |
                                       static_cast<u8>(AmdGpuVmAccess::kWrite) |
                                       static_cast<u8>(AmdGpuVmAccess::kExecute);

constexpr bool IsKnownGeneration(AmdGpuVmGeneration generation)
{
    switch (generation)
    {
    case AmdGpuVmGeneration::kGfx9:
    case AmdGpuVmGeneration::kGfx10:
    case AmdGpuVmGeneration::kGfx11:
        return true;
    }
    return false;
}

constexpr u32 MtypeShift(AmdGpuVmGeneration generation)
{
    return (generation == AmdGpuVmGeneration::kGfx9) ? kAmdGpuVmGfx9MtypeShift : kAmdGpuVmGfx10MtypeShift;
}

constexpr u64 EncodeValidatedPte(AmdGpuVmGeneration generation, u64 physical_address, AmdGpuVmAccess access)
{
    u64 pte = (physical_address & kAmdGpuVmAddressMask) | kAmdGpuVmPteValid | kAmdGpuVmPteSystem | kAmdGpuVmPteSnooped;
    if (HasAmdGpuVmAccess(access, AmdGpuVmAccess::kExecute))
        pte |= kAmdGpuVmPteExecutable;
    if (HasAmdGpuVmAccess(access, AmdGpuVmAccess::kRead))
        pte |= kAmdGpuVmPteReadable;
    if (HasAmdGpuVmAccess(access, AmdGpuVmAccess::kWrite))
        pte |= kAmdGpuVmPteWriteable;
    pte |= (kAmdGpuVmMtypeCc & kAmdGpuVmMtypeMask) << MtypeShift(generation);
    return pte;
}

static_assert(EncodeValidatedPte(AmdGpuVmGeneration::kGfx9, 0x12345000ull,
                                 AmdGpuVmAccess::kRead | AmdGpuVmAccess::kWrite) == 0x0400000012345067ull,
              "GFX9 system PTE encoding changed");
static_assert(EncodeValidatedPte(AmdGpuVmGeneration::kGfx10, 0x12345000ull,
                                 AmdGpuVmAccess::kRead | AmdGpuVmAccess::kWrite) == 0x0002000012345067ull,
              "GFX10 system PTE encoding changed");
static_assert(EncodeValidatedPte(AmdGpuVmGeneration::kGfx11, 0x12345000ull,
                                 AmdGpuVmAccess::kRead | AmdGpuVmAccess::kExecute) == 0x0002000012345037ull,
              "GFX11 system PTE encoding changed");

bool ExpectReject(const AmdGpuVmPteRequest& request, AmdGpuVmReject expected)
{
    const auto result = EncodeAmdGpuVmSystemPte(request);
    return !result.has_value() && result.error() == expected;
}

::duetos::core::Result<void> RegisterAmdGpuVmSelfTest()
{
    if constexpr (::duetos::core::kBootSelfTests)
        AmdGpuVmSelfTest();
    return {};
}

} // namespace

::duetos::core::Result<u64, AmdGpuVmReject> EncodeAmdGpuVmSystemPte(const AmdGpuVmPteRequest& request)
{
    if (!IsKnownGeneration(request.generation))
        return ::duetos::core::Err{AmdGpuVmReject::kUnknownGeneration};

    const u8 access_bits = static_cast<u8>(request.access);
    if ((access_bits & ~kKnownAccessBits) != 0)
        return ::duetos::core::Err{AmdGpuVmReject::kUnknownAccessBits};
    if ((access_bits & kKnownAccessBits) == 0)
        return ::duetos::core::Err{AmdGpuVmReject::kMissingAccess};
    if ((request.physical_address & ~kAmdGpuVmPageMask) != 0)
        return ::duetos::core::Err{AmdGpuVmReject::kPhysicalAddressUnaligned};
    if ((request.physical_address & ~kAmdGpuVmAddressMask) != 0)
        return ::duetos::core::Err{AmdGpuVmReject::kPhysicalAddressOutOfRange};

    return EncodeValidatedPte(request.generation, request.physical_address, request.access);
}

void AmdGpuVmSelfTest()
{
    constexpr u64 kPhysicalAddress = 0x12345000ull;
    constexpr AmdGpuVmAccess kReadWrite = AmdGpuVmAccess::kRead | AmdGpuVmAccess::kWrite;
    constexpr AmdGpuVmAccess kReadExecute = AmdGpuVmAccess::kRead | AmdGpuVmAccess::kExecute;

    const auto gfx9 = EncodeAmdGpuVmSystemPte({AmdGpuVmGeneration::kGfx9, kPhysicalAddress, kReadWrite});
    const auto gfx10 = EncodeAmdGpuVmSystemPte({AmdGpuVmGeneration::kGfx10, kPhysicalAddress, kReadWrite});
    const auto gfx11 = EncodeAmdGpuVmSystemPte({AmdGpuVmGeneration::kGfx11, kPhysicalAddress, kReadExecute});

    const bool happy_paths = gfx9.has_value() && gfx9.value() == 0x0400000012345067ull && gfx10.has_value() &&
                             gfx10.value() == 0x0002000012345067ull && gfx11.has_value() &&
                             gfx11.value() == 0x0002000012345037ull;
    const bool reject_paths =
        ExpectReject({static_cast<AmdGpuVmGeneration>(0xFFu), kPhysicalAddress, kReadWrite},
                     AmdGpuVmReject::kUnknownGeneration) &&
        ExpectReject({AmdGpuVmGeneration::kGfx9, kPhysicalAddress, AmdGpuVmAccess::kNone},
                     AmdGpuVmReject::kMissingAccess) &&
        ExpectReject({AmdGpuVmGeneration::kGfx9, kPhysicalAddress,
                      static_cast<AmdGpuVmAccess>(static_cast<u8>(AmdGpuVmAccess::kRead) | 0x80u)},
                     AmdGpuVmReject::kUnknownAccessBits) &&
        ExpectReject({AmdGpuVmGeneration::kGfx10, kPhysicalAddress + 1, kReadWrite},
                     AmdGpuVmReject::kPhysicalAddressUnaligned) &&
        ExpectReject({AmdGpuVmGeneration::kGfx11, 0x0001000000000000ull, kReadWrite},
                     AmdGpuVmReject::kPhysicalAddressOutOfRange);

    if (happy_paths && reject_paths)
    {
        arch::SerialWrite("[gpu/amd/vm] selftest PASS (GFX9/GFX10/GFX11 PTE encode + 5 reject paths)\n");
        return;
    }

    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0xA9D1u);
    arch::SerialWrite("[gpu/amd/vm] selftest FAIL (PTE encoding or reject path)\n");
}

KERNEL_INITCALL(Drivers, "drivers/gpu.amd-vm-pte", RegisterAmdGpuVmSelfTest)

} // namespace duetos::drivers::gpu::amd
