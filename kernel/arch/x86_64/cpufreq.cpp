#include "arch/x86_64/cpufreq.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_sensor_math.h"
#include "arch/x86_64/cpufreq_msr.h"
#include "arch/x86_64/msr_safe.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "time/timekeeper.h"

namespace duetos::arch
{

namespace
{

namespace csm = ::duetos::arch::cpu_sensor_math;
namespace msr = ::duetos::arch::cpufreq_msr;


/// Does this part ADVERTISE readable APERF/MPERF?
///
/// The CPUID bit matters as much as the read succeeding: QEMU's TCG
/// interpreter answers 0 for MSRs it does not model instead of
/// faulting, so "the read returned" alone would let us claim counters
/// that are permanently frozen at zero. Requiring the advertisement
/// too means we only claim the counters where the platform says they
/// are real.
// Which of this platform's frequency MSRs actually answered, resolved
// on first use and then believed.
//
// Caching is not an optimisation. A declined read costs a full trap
// plus one `[extable] recovered kernel trap` line, and CpuFreqRead is
// on the Task Manager sampling path — re-probing per call would emit
// several of those lines per second on any host that declines the
// MSRs. Observed live: a KVM boot on a Zen host logged two recovered
// traps for every CpuFreqRead, because KVM exposes neither the AMD
// P-state MSRs nor APERF/MPERF.
//
// What is cached is availability, never a VALUE: the operating point
// and the counters are re-read every call.
struct MsrAvail
{
    bool resolved;
    bool perf_status;   // Intel IA32_PERF_STATUS
    bool platform_info; // Intel MSR_PLATFORM_INFO
    bool pstate;        // AMD MSR_PSTATE_DEF / MSR_PSTATE_STATUS
    bool counters;      // IA32_MPERF / IA32_APERF
};

constinit MsrAvail g_avail = {};

bool CountersAdvertised()
{
    if (CpuVendorIsIntel())
    {
        // Leaf 6 ECX bit 0 — "hardware coordination feedback
        // capability" (IA32_MPERF / IA32_APERF).
        return (msr::Cpuid(6).ecx & 0x1u) != 0;
    }
    if (CpuVendorIsAmd())
    {
        // CPUID 0x80000007 EDX bit 10 — EffFreqRO.
        return (msr::Cpuid(0x80000007).edx & (1u << 10)) != 0;
    }
    return false;
}

void ResolveAvail(bool intel, bool amd)
{
    u64 scratch = 0;
    if (intel)
    {
        g_avail.perf_status = ReadMsrSafe(msr::kIa32PerfStatus, &scratch);
        g_avail.platform_info = ReadMsrSafe(msr::kPlatformInfo, &scratch);
    }
    else if (amd && csm::ZenFamilySupported(CpuInfoGet().family))
    {
        // One probe covers the whole P-state block: the definitions
        // and the status register live in the same MSR range, so a
        // platform either models them or it does not.
        g_avail.pstate = ReadMsrSafe(msr::kAmdPstateDef0, &scratch);
    }
    g_avail.counters =
        CountersAdvertised() && ReadMsrSafe(msr::kIa32Mperf, &scratch) && ReadMsrSafe(msr::kIa32Aperf, &scratch);
    g_avail.resolved = true;
}

void EnsureAvailResolved(bool intel, bool amd)
{
    if (!g_avail.resolved)
        ResolveAvail(intel, amd);
}

void ReadIntel(CpuFreqReading& r)
{
    r.bclk_mhz = msr::kBclkMhz;

    // IA32_PERF_STATUS bits 15:8 = current operating ratio.
    u64 perf = 0;
    if (g_avail.perf_status && ReadMsrSafe(msr::kIa32PerfStatus, &perf))
    {
        const u32 cur_ratio = csm::IntelPerfStatusRatio(perf);
        if (cur_ratio != 0)
        {
            r.current_valid = true;
            r.current_mhz = cur_ratio * msr::kBclkMhz;
        }
    }

    // MSR_PLATFORM_INFO bits 15:8 = base ratio, bits 47:40 =
    // max-efficiency (lowest) ratio. Absent SKUs read 0.
    u64 info = 0;
    if (g_avail.platform_info && ReadMsrSafe(msr::kPlatformInfo, &info) && info != 0 && info != ~0ULL)
    {
        const u32 base_ratio = csm::IntelPlatformInfoBaseRatio(info);
        const u32 min_ratio = csm::IntelPlatformInfoMinRatio(info);
        if (base_ratio != 0)
        {
            r.ratios_valid = true;
            r.base_mhz = base_ratio * msr::kBclkMhz;
            r.min_mhz = min_ratio * msr::kBclkMhz;
        }
    }
}

void ReadAmd(CpuFreqReading& r)
{
    // The FID/DID encoding below is Zen-specific; pre-Zen parts use a
    // different one, so an unrecognised family reports nothing rather
    // than a confidently-wrong MHz. `pstate` also folds in whether the
    // platform answered the probe at all.
    if (!g_avail.pstate)
        return;

    // P0 is the base (guaranteed) frequency; walk the rest to find the
    // lowest enabled state, which is the max-efficiency point.
    u32 lowest = 0;
    for (u32 i = 0; i < msr::kAmdPstateCount; ++i)
    {
        u64 def = 0;
        if (!ReadMsrSafe(msr::kAmdPstateDef0 + i, &def))
            break;
        const u32 mhz = csm::ZenPstateMhz(def);
        if (mhz == 0)
            continue;
        if (i == 0)
        {
            r.ratios_valid = true;
            r.base_mhz = mhz;
        }
        if (lowest == 0 || mhz < lowest)
            lowest = mhz;
    }
    r.min_mhz = lowest;

    // MSR_PSTATE_STATUS bits 2:0 name the state the core is running in
    // right now — the AMD equivalent of IA32_PERF_STATUS.
    u64 status = 0;
    if (ReadMsrSafe(msr::kAmdPstateStatus, &status))
    {
        const u32 idx = static_cast<u32>(status & 0x7u);
        u64 def = 0;
        if (ReadMsrSafe(msr::kAmdPstateDef0 + idx, &def))
        {
            const u32 mhz = csm::ZenPstateMhz(def);
            if (mhz != 0)
            {
                r.current_valid = true;
                r.current_mhz = mhz;
            }
        }
    }
}

} // namespace

CpuFreqReading CpuFreqRead()
{
    CpuFreqReading r = {};
    if (!CpuHas(kCpuFeatMsr))
        return r;

    const bool intel = CpuVendorIsIntel();
    const bool amd = CpuVendorIsAmd();
    if (!intel && !amd)
        return r;
    r.is_intel = intel;
    EnsureAvailResolved(intel, amd);

    if (intel)
        ReadIntel(r);
    else
        ReadAmd(r);

    // Counters are a separate capability from the static ratios: a
    // machine can expose one without the other, and the effective-
    // frequency path needs both.
    r.counters_valid = g_avail.counters;

    // `valid` means "something real came back". Reporting valid with
    // every field zero is exactly the lie a UI renders as an idle
    // 0 MHz CPU.
    r.valid = r.current_valid || r.ratios_valid || r.counters_valid;
    if (!r.valid)
        return CpuFreqReading{};
    return r;
}

u32 CpuFreqSampleEffectiveMhz(u32 window_ms)
{
    if (window_ms == 0)
        return 0;
    const CpuFreqReading first = CpuFreqRead();
    // Effective frequency needs BOTH a base to scale against and live
    // counters. Without either we return 0, which callers render as
    // "no reading" rather than as a stalled CPU.
    if (!first.valid || !first.counters_valid || !first.ratios_valid || first.base_mhz == 0)
        return 0;

    u64 mperf0 = 0;
    u64 aperf0 = 0;
    if (!ReadMsrSafe(msr::kIa32Mperf, &mperf0) || !ReadMsrSafe(msr::kIa32Aperf, &aperf0))
        return 0;

    const u64 start_ns = time::MonotonicNs();
    const u64 window_ns = static_cast<u64>(window_ms) * 1000000ULL;
    while (time::MonotonicNs() - start_ns < window_ns)
        asm volatile("pause" ::: "memory");

    u64 mperf1 = 0;
    u64 aperf1 = 0;
    if (!ReadMsrSafe(msr::kIa32Mperf, &mperf1) || !ReadMsrSafe(msr::kIa32Aperf, &aperf1))
        return 0;
    return csm::EffectiveMhz(first.base_mhz, mperf0, aperf0, mperf1, aperf1);
}

void CpuFreqProbe()
{
    const CpuFreqReading r = CpuFreqRead();

    // The control probe runs on EVERY boot, including one where no
    // telemetry MSR answered and one with tune mode locked. Two
    // reasons: an operator can see whether `cpufreq=tune` would give
    // them anything before rebooting with it, and the control read
    // path gets exercised under emulation, where it would otherwise
    // never run at all (QEMU answers none of these MSRs, so the write
    // side stays silicon-unverified either way — but a fault in the
    // READ path would still show up here).
    const CpuFreqControlCaps caps = CpuFreqControlRead();

    if (!r.valid)
    {
        KLOG_WARN("arch/cpufreq", "no readable frequency interface - reporting unsupported, not 0 MHz");
        SerialLineGuard unsupported_guard;
        SerialWrite("[cpufreq] source=none freq=unsupported control=");
        SerialWrite(CpuFreqMechanismName(caps.mechanism));
        SerialWrite(CpuFreqTuneEnabled() ? " tune=on\n" : " tune=off\n");
        return;
    }

    SerialLineGuard guard;
    SerialWrite("[cpufreq] ");
    SerialWrite(r.is_intel ? "Intel" : "AMD");
    SerialWrite(" cur_mhz=");
    if (r.current_valid)
        SerialWriteHex(r.current_mhz);
    else
        SerialWrite("unsupported");
    SerialWrite(" base_mhz=");
    if (r.ratios_valid)
        SerialWriteHex(r.base_mhz);
    else
        SerialWrite("unsupported");
    SerialWrite(" min_mhz=");
    if (r.ratios_valid && r.min_mhz != 0)
        SerialWriteHex(r.min_mhz);
    else
        SerialWrite("unsupported");
    SerialWrite(r.counters_valid ? " aperf_mperf=live" : " aperf_mperf=absent");

    SerialWrite(" control=");
    SerialWrite(CpuFreqMechanismName(caps.mechanism));
    if (caps.valid)
    {
        SerialWrite(" window=");
        SerialWriteHex(caps.lowest);
        SerialWrite("..");
        SerialWriteHex(caps.highest);
    }
    SerialWrite(CpuFreqTuneEnabled() ? " tune=on\n" : " tune=off\n");
}

void CpuFreqSelfTest()
{
    using core::PanicWithValue;

    // Ratio decode: a base ratio of 0x1C (28) at 100 MHz BCLK is 2.8 GHz.
    const u32 base = 28u * msr::kBclkMhz;
    if (base != 2800u)
        PanicWithValue("arch/cpufreq", "base ratio decode != 2800", base);

    // Effective frequency: at base 2800 MHz with APERF advancing at the
    // same rate as MPERF (idle/at-base), effective == base.
    if (csm::EffectiveMhz(2800, 0, 0, 1000, 1000) != 2800u)
        PanicWithValue("arch/cpufreq", "effective at-base != 2800", 1);

    // Half the APERF advance (deep idle / heavy throttling) => half freq.
    if (csm::EffectiveMhz(2800, 0, 0, 1000, 500) != 1400u)
        PanicWithValue("arch/cpufreq", "effective half != 1400", 2);

    // Turbo: APERF advancing 1.5x MPERF => 1.5x base.
    if (csm::EffectiveMhz(2800, 0, 0, 1000, 1500) != 4200u)
        PanicWithValue("arch/cpufreq", "effective turbo != 4200", 3);

    // Degenerate inputs return 0, never divide-by-zero or wrap.
    if (csm::EffectiveMhz(2800, 100, 0, 100, 0) != 0u)
        PanicWithValue("arch/cpufreq", "non-advancing mperf != 0", 4);

    // AMD P-state decode: FID 0x98 (152) / DID 8 => 152 * 200 / 8 =
    // 3800 MHz, with the enable bit set.
    if (csm::ZenPstateMhz((1ULL << 63) | (8ULL << 8) | 0x98ULL) != 3800u)
        PanicWithValue("arch/cpufreq", "Zen P0 decode != 3800", 5);
    // A disabled P-state is unknown (0), not a frequency.
    if (csm::ZenPstateMhz((8ULL << 8) | 0x98ULL) != 0u)
        PanicWithValue("arch/cpufreq", "disabled P-state decoded to a frequency", 6);

    // Live-reading invariant: an unsupported reading must be entirely
    // empty, so a caller that only checks `valid` cannot pick a
    // plausible-looking zero out of the record.
    const CpuFreqReading live = CpuFreqRead();
    if (!live.valid && (live.current_mhz != 0 || live.base_mhz != 0 || live.counters_valid))
        PanicWithValue("arch/cpufreq", "unsupported reading carries data", live.current_mhz);
    if (live.valid && !live.current_valid && live.current_mhz != 0)
        PanicWithValue("arch/cpufreq", "current_mhz set without current_valid", live.current_mhz);

    SerialWrite("[cpufreq-selftest] PASS (ratio->MHz + Zen P-state + APERF/MPERF effective freq)\n");
}

} // namespace duetos::arch
