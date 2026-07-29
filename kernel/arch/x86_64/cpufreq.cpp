#include "arch/x86_64/cpufreq.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_sensor_math.h"
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

constexpr u32 kMsrPlatformInfo = 0xCE;
constexpr u32 kMsrIa32PerfStatus = 0x198;
constexpr u32 kMsrIa32Mperf = 0xE7;
constexpr u32 kMsrIa32Aperf = 0xE8;

// AMD family 17h+ P-state interface.
constexpr u32 kMsrAmdPstateStatus = 0xC0010063; // bits 2:0 = live index
constexpr u32 kMsrAmdPstateDef0 = 0xC0010064;   // +n for P-state n
constexpr u32 kAmdPstateCount = 8;

// Reference clock. 100 MHz BCLK on every Nehalem-and-later Intel part.
// The AMD path decodes MHz directly out of the P-state FID/DID and
// never touches this.
constexpr u32 kBclkMhz = 100;

struct CpuidRegs
{
    u32 eax, ebx, ecx, edx;
};

CpuidRegs DoCpuid(u32 leaf)
{
    CpuidRegs r;
    asm volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx) : "a"(leaf), "c"(0));
    return r;
}

/// Does this part ADVERTISE readable APERF/MPERF?
///
/// The CPUID bit matters as much as the read succeeding: QEMU's TCG
/// interpreter answers 0 for MSRs it does not model instead of
/// faulting, so "the read returned" alone would let us claim counters
/// that are permanently frozen at zero. Requiring the advertisement
/// too means we only claim the counters where the platform says they
/// are real.
bool CountersAdvertised()
{
    if (CpuVendorIsIntel())
    {
        // Leaf 6 ECX bit 0 — "hardware coordination feedback
        // capability" (IA32_MPERF / IA32_APERF).
        return (DoCpuid(6).ecx & 0x1u) != 0;
    }
    if (CpuVendorIsAmd())
    {
        // CPUID 0x80000007 EDX bit 10 — EffFreqRO.
        return (DoCpuid(0x80000007).edx & (1u << 10)) != 0;
    }
    return false;
}

void ReadIntel(CpuFreqReading& r)
{
    r.bclk_mhz = kBclkMhz;

    // IA32_PERF_STATUS bits 15:8 = current operating ratio.
    u64 perf = 0;
    if (ReadMsrSafe(kMsrIa32PerfStatus, &perf))
    {
        const u32 cur_ratio = static_cast<u32>((perf >> 8) & 0xFF);
        if (cur_ratio != 0)
        {
            r.current_valid = true;
            r.current_mhz = cur_ratio * kBclkMhz;
        }
    }

    // MSR_PLATFORM_INFO bits 15:8 = base ratio, bits 47:40 =
    // max-efficiency (lowest) ratio. Absent SKUs read 0.
    u64 info = 0;
    if (ReadMsrSafe(kMsrPlatformInfo, &info) && info != 0 && info != ~0ULL)
    {
        const u32 base_ratio = static_cast<u32>((info >> 8) & 0xFF);
        const u32 min_ratio = static_cast<u32>((info >> 40) & 0xFF);
        if (base_ratio != 0)
        {
            r.ratios_valid = true;
            r.base_mhz = base_ratio * kBclkMhz;
            r.min_mhz = min_ratio * kBclkMhz;
        }
    }
}

void ReadAmd(CpuFreqReading& r)
{
    // The FID/DID encoding below is Zen-specific; pre-Zen parts use a
    // different one, so an unrecognised family reports nothing rather
    // than a confidently-wrong MHz.
    if (!csm::ZenFamilySupported(CpuInfoGet().family))
        return;

    // P0 is the base (guaranteed) frequency; walk the rest to find the
    // lowest enabled state, which is the max-efficiency point.
    u32 lowest = 0;
    for (u32 i = 0; i < kAmdPstateCount; ++i)
    {
        u64 def = 0;
        if (!ReadMsrSafe(kMsrAmdPstateDef0 + i, &def))
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
    if (ReadMsrSafe(kMsrAmdPstateStatus, &status))
    {
        const u32 idx = static_cast<u32>(status & 0x7u);
        u64 def = 0;
        if (ReadMsrSafe(kMsrAmdPstateDef0 + idx, &def))
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

    if (intel)
        ReadIntel(r);
    else
        ReadAmd(r);

    // Counters are a separate capability from the static ratios: a
    // machine can expose one without the other, and the effective-
    // frequency path needs both.
    if (CountersAdvertised())
    {
        u64 mperf = 0;
        u64 aperf = 0;
        r.counters_valid = ReadMsrSafe(kMsrIa32Mperf, &mperf) && ReadMsrSafe(kMsrIa32Aperf, &aperf);
    }

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
    if (!ReadMsrSafe(kMsrIa32Mperf, &mperf0) || !ReadMsrSafe(kMsrIa32Aperf, &aperf0))
        return 0;

    const u64 start_ns = time::MonotonicNs();
    const u64 window_ns = static_cast<u64>(window_ms) * 1000000ULL;
    while (time::MonotonicNs() - start_ns < window_ns)
        asm volatile("pause" ::: "memory");

    u64 mperf1 = 0;
    u64 aperf1 = 0;
    if (!ReadMsrSafe(kMsrIa32Mperf, &mperf1) || !ReadMsrSafe(kMsrIa32Aperf, &aperf1))
        return 0;
    return csm::EffectiveMhz(first.base_mhz, mperf0, aperf0, mperf1, aperf1);
}

void CpuFreqProbe()
{
    const CpuFreqReading r = CpuFreqRead();
    if (!r.valid)
    {
        KLOG_WARN("arch/cpufreq", "no readable frequency interface - reporting unsupported, not 0 MHz");
        SerialWrite("[cpufreq] source=none freq=unsupported\n");
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
    SerialWrite(r.counters_valid ? " aperf_mperf=live\n" : " aperf_mperf=absent\n");
}

void CpuFreqSelfTest()
{
    using core::PanicWithValue;

    // Ratio decode: a base ratio of 0x1C (28) at 100 MHz BCLK is 2.8 GHz.
    const u32 base = 28u * kBclkMhz;
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
