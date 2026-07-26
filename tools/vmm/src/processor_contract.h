// Guest-visible processor identity contract for the WHP partition.
//
// Keep this separate from Partition so the exact synthetic feature bank can
// be host-tested without creating a live partition.
#pragma once

#include <windows.h>
#include <WinHvPlatform.h>

namespace duetos::vmm
{

// DuetOS must be told that it is running under a hypervisor.  The kernel uses
// CPUID.1.ECX[31] to avoid probing host-only telemetry MSRs (RAPL, thermal,
// frequency) that WHP may not expose to the partition.
[[nodiscard]] WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS
MakeSyntheticProcessorFeatures();

} // namespace duetos::vmm
