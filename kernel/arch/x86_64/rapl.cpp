#include "arch/x86_64/rapl.h"

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

// Intel RAPL MSRs (architectural since Sandy Bridge).
constexpr u32 kMsrIntelRaplPowerUnit = 0x606;
constexpr u32 kMsrIntelPkgEnergyStatus = 0x611;
constexpr u32 kMsrIntelPkgPowerInfo = 0x614;
constexpr u32 kMsrIntelDramEnergyStatus = 0x619;

// AMD RAPL MSRs (family 17h+). Same unit-field layout; no PKG_POWER_INFO.
constexpr u32 kMsrAmdRaplPwrUnit = 0xC0010299;
constexpr u32 kMsrAmdPkgEnergyStat = 0xC001029B;

// rdmsr wrapper. Mirrors thermal.cpp — we only issue these against
// MSRs the vendor gate below has confirmed the platform implements,
// because an unimplemented-MSR rdmsr raises a #GP the trap dispatcher
// does not recover from.
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

// Energy unit = 1 / 2^EU joules. Convert a raw RAPL energy count to
// microjoules: uj = raw * 1e6 / 2^EU. A 32-bit raw count times 1e6
// fits comfortably in u64, so the multiply-then-shift never overflows.
u64 EnergyToMicrojoules(u64 raw_count, u8 eu)
{
    return (raw_count * 1000000ULL) >> eu;
}

// Power unit = 1 / 2^PU watts. Convert a RAPL power field to
// milliwatts: mW = field * 1000 / 2^PU.
u32 PowerFieldToMilliwatts(u32 field, u8 pu)
{
    return static_cast<u32>((static_cast<u64>(field) * 1000ULL) >> pu);
}

// Baseline captured at RaplProbe() so an average-power-since-boot view
// is available without a second timed sample.
constinit bool g_baseline_valid = false;
constinit u64 g_baseline_energy_uj = 0;
constinit u64 g_baseline_ns = 0;

} // namespace

RaplReading RaplRead()
{
    RaplReading r = {};
    if (!CpuHas(kCpuFeatMsr))
        return r;
    // KVM/TCG do not reliably expose RAPL; a rdmsr there either #GPs
    // (KVM) or returns 0 (TCG). Bail under any hypervisor — same
    // envelope as ThermalRead.
    if (IsEmulator())
        return r;

    const bool intel = VendorIsIntel();
    const bool amd = VendorIsAmd();
    if (!intel && !amd)
        return r;
    r.is_intel = intel;

    const u32 unit_msr = intel ? kMsrIntelRaplPowerUnit : kMsrAmdRaplPwrUnit;
    const u64 units = Rdmsr(unit_msr);
    // POWER_UNIT layout (both vendors): PU = bits 3:0, EU = bits 12:8,
    // time unit = bits 19:16. A units register that reads back all-zero
    // or all-ones means the MSR is not really there (returned garbage).
    if (units == 0 || units == ~0ULL)
        return r;
    r.power_unit_exp = static_cast<u8>(units & 0xF);
    r.energy_unit_exp = static_cast<u8>((units >> 8) & 0x1F);

    const u32 energy_msr = intel ? kMsrIntelPkgEnergyStatus : kMsrAmdPkgEnergyStat;
    const u64 pkg_raw = Rdmsr(energy_msr) & 0xFFFFFFFFULL; // 32-bit counter
    r.pkg_energy_uj = EnergyToMicrojoules(pkg_raw, r.energy_unit_exp);

    if (intel)
    {
        // PKG_POWER_INFO: TSP bits 14:0, min bits 30:16, max bits 46:32,
        // all in power units. Absent on some SKUs (reads 0).
        const u64 info = Rdmsr(kMsrIntelPkgPowerInfo);
        if (info != 0 && info != ~0ULL)
        {
            r.tdp_valid = true;
            r.tdp_mw = PowerFieldToMilliwatts(static_cast<u32>(info & 0x7FFF), r.power_unit_exp);
            r.min_power_mw = PowerFieldToMilliwatts(static_cast<u32>((info >> 16) & 0x7FFF), r.power_unit_exp);
            r.max_power_mw = PowerFieldToMilliwatts(static_cast<u32>((info >> 32) & 0x7FFF), r.power_unit_exp);
        }
        // DRAM domain is present on server parts + some client SKUs.
        const u64 dram_raw = Rdmsr(kMsrIntelDramEnergyStatus) & 0xFFFFFFFFULL;
        if (dram_raw != 0)
        {
            r.dram_valid = true;
            r.dram_energy_uj = EnergyToMicrojoules(dram_raw, r.energy_unit_exp);
        }
    }

    r.valid = true;
    return r;
}

u32 RaplSamplePackagePowerMw(u32 window_ms)
{
    if (window_ms == 0)
        return 0;
    const RaplReading first = RaplRead();
    if (!first.valid)
        return 0;

    // Busy-wait the window on the monotonic clock — no sleep primitive
    // needed, and this is only ever called interactively.
    const u64 start_ns = time::MonotonicNs();
    const u64 window_ns = static_cast<u64>(window_ms) * 1000000ULL;
    while (time::MonotonicNs() - start_ns < window_ns)
        asm volatile("pause" ::: "memory");
    const u64 elapsed_ms = (time::MonotonicNs() - start_ns) / 1000000ULL;
    if (elapsed_ms == 0)
        return 0;

    const RaplReading second = RaplRead();
    if (!second.valid || second.pkg_energy_uj < first.pkg_energy_uj)
        return 0; // counter wrapped across the window — skip this sample

    // microjoules / milliseconds == milliwatts.
    const u64 delta_uj = second.pkg_energy_uj - first.pkg_energy_uj;
    return static_cast<u32>(delta_uj / elapsed_ms);
}

void RaplProbe()
{
    const RaplReading r = RaplRead();
    if (!r.valid)
    {
        KLOG_DEBUG("arch/rapl", "RAPL telemetry unavailable (no MSR / unknown vendor / hypervisor)");
        return;
    }
    g_baseline_valid = true;
    g_baseline_energy_uj = r.pkg_energy_uj;
    g_baseline_ns = time::MonotonicNs();

    SerialWrite("[rapl] ");
    SerialWrite(r.is_intel ? "Intel" : "AMD");
    SerialWrite(" EU=2^-");
    SerialWriteHex(r.energy_unit_exp);
    SerialWrite(" PU=2^-");
    SerialWriteHex(r.power_unit_exp);
    SerialWrite(" pkg_energy_uj=");
    SerialWriteHex(r.pkg_energy_uj);
    if (r.tdp_valid)
    {
        SerialWrite(" tdp_mw=");
        SerialWriteHex(r.tdp_mw);
        SerialWrite(" max_mw=");
        SerialWriteHex(r.max_power_mw);
    }
    SerialWrite("\n");
}

void RaplSelfTest()
{
    using core::PanicWithValue;

    // Energy decode: with EU = 14 (energy unit = 1/16384 J ≈ 61.035 µJ),
    // a raw count of 16384 is exactly 1 J = 1_000_000 µJ.
    const u64 uj_one_joule = EnergyToMicrojoules(16384ULL, 14);
    if (uj_one_joule != 1000000ULL)
        PanicWithValue("arch/rapl", "EnergyToMicrojoules(16384,14) != 1e6", uj_one_joule);

    // raw 0 → 0 µJ.
    if (EnergyToMicrojoules(0, 14) != 0)
        PanicWithValue("arch/rapl", "EnergyToMicrojoules(0) != 0", 1);

    // Power decode: with PU = 3 (power unit = 1/8 W = 125 mW), a TSP
    // field of 224 is 224/8 = 28 W = 28_000 mW (a typical 28 W TDP).
    const u32 mw_28w = PowerFieldToMilliwatts(224, 3);
    if (mw_28w != 28000u)
        PanicWithValue("arch/rapl", "PowerFieldToMilliwatts(224,3) != 28000", mw_28w);

    // microjoules / milliseconds == milliwatts: 28000 µJ over 1 ms = 28 W.
    const u64 delta_uj = 28000ULL;
    const u64 elapsed_ms = 1ULL;
    if (static_cast<u32>(delta_uj / elapsed_ms) != 28000u)
        PanicWithValue("arch/rapl", "uj/ms != mw", static_cast<u64>(delta_uj / elapsed_ms));

    SerialWrite("[rapl-selftest] PASS (energy+power unit decode, uj/ms->mw)\n");
}

} // namespace duetos::arch
