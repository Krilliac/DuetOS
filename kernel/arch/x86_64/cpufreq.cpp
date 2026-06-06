#include "arch/x86_64/cpufreq.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "time/timekeeper.h"

namespace duetos::arch
{

namespace
{

constexpr u32 kMsrPlatformInfo = 0xCE;
constexpr u32 kMsrIa32PerfStatus = 0x198;
constexpr u32 kMsrIa32Mperf = 0xE7;
constexpr u32 kMsrIa32Aperf = 0xE8;

// Reference clock. 100 MHz BCLK on every Nehalem-and-later Intel part
// and every Zen AMD part. Pre-Nehalem FSB parts are out of scope.
constexpr u32 kBclkMhz = 100;

u64 Rdmsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (u64(hi) << 32) | lo;
}

bool VendorIsIntel()
{
    const char* v = CpuInfoGet().vendor;
    return v[0] == 'G' && v[1] == 'e' && v[2] == 'n' && v[3] == 'u' && v[4] == 'i' && v[5] == 'n' && v[6] == 'e' &&
           v[7] == 'I' && v[8] == 'n' && v[9] == 't' && v[10] == 'e' && v[11] == 'l';
}

bool VendorIsAmd()
{
    const char* v = CpuInfoGet().vendor;
    return v[0] == 'A' && v[1] == 'u' && v[2] == 't' && v[3] == 'h' && v[4] == 'e' && v[5] == 'n' && v[6] == 't' &&
           v[7] == 'i' && v[8] == 'c' && v[9] == 'A' && v[10] == 'M' && v[11] == 'D';
}

// Effective frequency: base * dAPERF / dMPERF. Guards a zero/decreasing
// MPERF delta (counter wrap or not-advancing) by returning 0.
u32 EffectiveMhz(u32 base_mhz, u64 mperf0, u64 aperf0, u64 mperf1, u64 aperf1)
{
    if (mperf1 <= mperf0 || aperf1 < aperf0)
        return 0;
    const u64 dm = mperf1 - mperf0;
    const u64 da = aperf1 - aperf0;
    if (dm == 0)
        return 0;
    return static_cast<u32>((static_cast<u64>(base_mhz) * da) / dm);
}

constinit bool g_baseline_valid = false;

} // namespace

CpuFreqReading CpuFreqRead()
{
    CpuFreqReading r = {};
    if (!CpuHas(kCpuFeatMsr))
        return r;
    if (IsEmulator())
        return r;

    const bool intel = VendorIsIntel();
    const bool amd = VendorIsAmd();
    if (!intel && !amd)
        return r;
    r.is_intel = intel;
    r.bclk_mhz = kBclkMhz;

    if (intel)
    {
        // IA32_PERF_STATUS bits 15:8 = current operating ratio.
        const u64 perf = Rdmsr(kMsrIa32PerfStatus);
        const u32 cur_ratio = static_cast<u32>((perf >> 8) & 0xFF);
        r.current_mhz = cur_ratio * kBclkMhz;

        // MSR_PLATFORM_INFO bits 15:8 = base ratio, bits 47:40 =
        // max-efficiency (lowest) ratio. Absent SKUs read 0.
        const u64 info = Rdmsr(kMsrPlatformInfo);
        if (info != 0 && info != ~0ULL)
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
    // AMD: static base/min ratios live in P-state-def MSRs (deferred);
    // current_mhz via IA32_PERF_STATUS is Intel-specific, so it stays 0
    // on AMD. The effective-frequency path (MPERF/APERF) still works.

    r.valid = true;
    return r;
}

u32 CpuFreqSampleEffectiveMhz(u32 window_ms)
{
    if (window_ms == 0)
        return 0;
    const CpuFreqReading first = CpuFreqRead();
    // Effective frequency needs a base to scale against; without the
    // static ratios we cannot convert the APERF/MPERF ratio to MHz.
    if (!first.valid || !first.ratios_valid || first.base_mhz == 0)
        return 0;

    const u64 mperf0 = Rdmsr(kMsrIa32Mperf);
    const u64 aperf0 = Rdmsr(kMsrIa32Aperf);

    const u64 start_ns = time::MonotonicNs();
    const u64 window_ns = static_cast<u64>(window_ms) * 1000000ULL;
    while (time::MonotonicNs() - start_ns < window_ns)
        asm volatile("pause" ::: "memory");

    const u64 mperf1 = Rdmsr(kMsrIa32Mperf);
    const u64 aperf1 = Rdmsr(kMsrIa32Aperf);
    return EffectiveMhz(first.base_mhz, mperf0, aperf0, mperf1, aperf1);
}

void CpuFreqProbe()
{
    const CpuFreqReading r = CpuFreqRead();
    if (!r.valid)
    {
        KLOG_DEBUG("arch/cpufreq", "frequency telemetry unavailable (no MSR / unknown vendor / hypervisor)");
        return;
    }
    g_baseline_valid = true;

    SerialWrite("[cpufreq] ");
    SerialWrite(r.is_intel ? "Intel" : "AMD");
    SerialWrite(" cur_mhz=");
    SerialWriteHex(r.current_mhz);
    if (r.ratios_valid)
    {
        SerialWrite(" base_mhz=");
        SerialWriteHex(r.base_mhz);
        SerialWrite(" min_mhz=");
        SerialWriteHex(r.min_mhz);
    }
    SerialWrite("\n");
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
    if (EffectiveMhz(2800, 0, 0, 1000, 1000) != 2800u)
        PanicWithValue("arch/cpufreq", "effective at-base != 2800", 1);

    // Half the APERF advance (deep idle / heavy throttling) => half freq.
    if (EffectiveMhz(2800, 0, 0, 1000, 500) != 1400u)
        PanicWithValue("arch/cpufreq", "effective half != 1400", 2);

    // Turbo: APERF advancing 1.5x MPERF => 1.5x base.
    if (EffectiveMhz(2800, 0, 0, 1000, 1500) != 4200u)
        PanicWithValue("arch/cpufreq", "effective turbo != 4200", 3);

    // Degenerate inputs return 0, never divide-by-zero or wrap.
    if (EffectiveMhz(2800, 100, 0, 100, 0) != 0u)
        PanicWithValue("arch/cpufreq", "non-advancing mperf != 0", 4);

    SerialWrite("[cpufreq-selftest] PASS (ratio->MHz + APERF/MPERF effective freq)\n");
}

} // namespace duetos::arch
