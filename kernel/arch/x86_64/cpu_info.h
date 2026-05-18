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
    // CPUID leaf 0x80000001, EDX bits
    kCpuFeatNx,       // bit 20 — NX/XD; required for EFER.NXE
    kCpuFeatPdpe1Gb,  // bit 26 — 1 GiB superpages
    kCpuFeatLongMode, // bit 29 — IA-32e (we always run with this set)
    // CPUID leaf 1, ECX bit 21 — x2APIC. We currently bring up only
    // MMIO-based xAPIC; this bit is probed so LapicInit can detect
    // when firmware left the CPU in x2APIC mode and refuse / recover.
    kCpuFeatX2Apic,
    // CPUID leaf 1, ECX bit 24 — TSC-Deadline mode. Lets the LAPIC
    // timer fire at an absolute TSC value instead of a periodic
    // reload; future tickless slice will gate on this.
    kCpuFeatTscDeadline,
    // CPUID leaf 1, ECX bit 31 — hypervisor present (synthetic; set
    // by every popular hypervisor). Drives hypervisor-quirk paths
    // and toggles a few "is this a VM?" diagnostics.
    kCpuFeatHypervisor,
    // CPUID leaf 1, ECX bit 3 — MONITOR/MWAIT. Gates the
    // low-power MWAIT idle path; falls back to HLT when absent.
    kCpuFeatMonitor,
    // Sentinel
    kCpuFeatCount,
};
static_assert(static_cast<u32>(kCpuFeatCount) <= 32, "feature_bits is u32 — extend if more features are added");

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

/// Verify every CPU feature this kernel depends on at runtime is
/// actually advertised by CPUID. Anything missing is a hard-stop —
/// the kernel cannot run safely on the box. Panics with a clear
/// list of missing features so an operator on real hardware knows
/// exactly which CPU baseline is unmet, instead of triple-faulting
/// later when the first dependent code path runs.
///
/// Today's baseline (matches what the rest of the kernel actually
/// uses):
///   FPU MMX SSE SSE2  — part of x86_64; needed by the FPU init +
///                       any SSE codegen the compiler emits
///   TSC               — used by every deadline / calibration loop
///   MSR               — every MSR read in the codebase
///   APIC              — the entire interrupt path
///   PAE               — required for long mode anyway
///   NX                — paging.cpp sets EFER.NXE; without NX, that
///                       write #GPs the kernel before main() returns
///   LongMode          — always set on the CPU we run on; the gate
///                       is here for symmetry + future cross-arch
///                       work
///
/// Optional-but-recommended features (SMEP, SMAP, RDRAND/RDSEED,
/// AES-NI, x2APIC handling) are NOT gated here — the kernel adapts
/// at the call sites. Anything that is "we assume it" lives here.
[[noreturn]] void CpuMinimumFeatureGateFail(const char* missing);
void CpuMinimumFeatureGate();

} // namespace duetos::arch
