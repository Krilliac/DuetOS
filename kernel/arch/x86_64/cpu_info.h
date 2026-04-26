#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU-info probe, v0.
 *
 * Runs CPUID at boot, decodes the vendor string, brand string,
 * family/model/stepping, and a curated set of feature bits. The
 * result is cached in a global so later code can query
 * `CpuHas(feature)` without re-running CPUID.
 *
 * Minimal by design — we only pick the bits that drive
 * kernel-level decisions today (SMEP/SMAP/NX were already
 * gated in PagingInit; this is the out-of-band dump). A future
 * slice will grow the list as more subsystems come online
 * (AVX/AVX-512 for SSE-fallback paths, AES-NI for crypto,
 * RDRAND/RDSEED for entropy).
 */

namespace duetos::arch
{

enum CpuFeature : u32
{
    // CPUID leaf 1, ECX bits
    kCpuFeatSse3 = 0,
    kCpuFeatSsse3,
    kCpuFeatSse4_1,
    kCpuFeatSse4_2,
    kCpuFeatAesNi,
    kCpuFeatAvx,
    kCpuFeatF16c,
    kCpuFeatRdrand,
    // CPUID leaf 1, EDX bits
    kCpuFeatFpu,
    kCpuFeatTsc,
    kCpuFeatMsr,
    kCpuFeatPae,
    kCpuFeatApic,
    kCpuFeatSep,
    kCpuFeatMmx,
    kCpuFeatSse,
    kCpuFeatSse2,
    // CPUID leaf 7, EBX bits
    kCpuFeatSmep,
    kCpuFeatSmap,
    kCpuFeatBmi1,
    kCpuFeatBmi2,
    kCpuFeatAvx2,
    kCpuFeatAvx512f,
    kCpuFeatRdseed,
    // Sentinel
    kCpuFeatCount,
};

struct CpuInfo
{
    char vendor[13]; // "GenuineIntel", "AuthenticAMD", ...
    char brand[49];  // e.g. "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz"
    u32 family;
    u32 model;
    u32 stepping;
    u32 feature_bits; // packed bit per CpuFeature slot
    u32 logical_cpus; // CPUID leaf 1, EBX[23:16]
    bool valid;
};

/// Run CPUID leaves 0, 1, 7, and 0x80000002-4. Populate the
/// global CpuInfo. Safe to call exactly once at boot; double-init
/// is a KASSERT.
void CpuInfoProbe();

/// Accessor for the cached CpuInfo. `valid=false` until
/// CpuInfoProbe has run.
const CpuInfo& CpuInfoGet();

/// Query a single feature bit. Returns false if CpuInfoProbe
/// hasn't run or the bit is out of range.
bool CpuHas(CpuFeature feat);

} // namespace duetos::arch
