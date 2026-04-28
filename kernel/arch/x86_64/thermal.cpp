#include "arch/x86_64/thermal.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"

namespace duetos::arch
{

namespace
{

constexpr u32 kMsrIa32ThermStatus = 0x19C;
constexpr u32 kMsrTemperatureTarget = 0x1A2;
constexpr u32 kMsrIa32PackageThermStatus = 0x1B1;

// rdmsr wrapper. The kernel may access MSRs from ring 0
// unconditionally; we guard by CpuHas(kCpuFeatMsr) anyway for
// defensive-programming value (reading an unimplemented MSR on
// some emulators raises #GP instead of returning 0).
u64 Rdmsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (u64(hi) << 32) | lo;
}

// IA32_THERM_STATUS / TEMPERATURE_TARGET / PACKAGE_THERM_STATUS
// are Intel-defined MSRs. AMD CPUs implement no architectural
// thermal MSRs at the same numbers — under TCG, QEMU silently
// returns 0 for unimplemented MSRs (which is why the prior code
// looked correct), but real hardware and KVM-presented vCPUs
// raise #GP, hanging the boot in the kernel's #GP path. Gate the
// reads on the vendor string so we never issue a `rdmsr` against
// an MSR the CPU doesn't define.
bool VendorIsIntel()
{
    const char* v = CpuInfoGet().vendor;
    return v[0] == 'G' && v[1] == 'e' && v[2] == 'n' && v[3] == 'u' && v[4] == 'i' && v[5] == 'n' && v[6] == 'e' &&
           v[7] == 'I' && v[8] == 'n' && v[9] == 't' && v[10] == 'e' && v[11] == 'l';
}

} // namespace

ThermalReading ThermalRead()
{
    ThermalReading r = {};
    if (!CpuHas(kCpuFeatMsr))
        return r;
    if (!VendorIsIntel())
        return r;
    // KVM hypervisors don't always expose IA32_THERM_STATUS /
    // TEMPERATURE_TARGET / IA32_PACKAGE_THERM_STATUS. A `rdmsr`
    // against an unsupported MSR raises #GP that the kernel's
    // trap dispatcher dumps but doesn't recover from. Bail before
    // the OUT. Bare-metal Intel still works (no IsEmulator gate
    // there); TCG silently returns 0 either way. Observed live as
    // a CI-only #GP crash with backtrace
    //   ThermalRead+0x58 -> PowerInit+0x179 -> kernel_main+0x150c
    // on a GitHub Actions Intel Xeon Platinum 8370C runner under
    // KVM that doesn't expose the thermal MSRs.
    //
    // The gate must live in ThermalRead, not just ThermalProbe —
    // PowerInit calls ThermalRead directly through PopulateThermal
    // (drivers/power/power.cpp), so the prior ThermalProbe-only
    // gate was bypassed.
    if (duetos::arch::IsEmulator())
        return r;

    // TJMax. If the MSR is unsupported, QEMU returns 0 — use
    // the 100 °C default.
    const u64 tj = Rdmsr(kMsrTemperatureTarget);
    u8 tj_max = u8((tj >> 16) & 0xFF);
    if (tj_max == 0)
        tj_max = 100;
    r.tj_max_c = tj_max;

    const u64 ts = Rdmsr(kMsrIa32ThermStatus);
    if (ts & (1u << 31))
    {
        r.core_valid = true;
        const u8 dist = u8((ts >> 16) & 0x7F);
        r.core_temp_c = (tj_max > dist) ? u8(tj_max - dist) : 0;
        if (ts & 1)
            r.thermal_throttle_hit = true;
    }

    const u64 pkg = Rdmsr(kMsrIa32PackageThermStatus);
    if (pkg & (1u << 31))
    {
        r.package_valid = true;
        const u8 dist = u8((pkg >> 16) & 0x7F);
        r.package_temp_c = (tj_max > dist) ? u8(tj_max - dist) : 0;
    }

    r.valid = r.core_valid || r.package_valid;
    return r;
}

void ThermalProbe()
{
    if (!CpuHas(kCpuFeatMsr))
    {
        core::Log(core::LogLevel::Warn, "arch/thermal", "no MSR support (CpuFeatMsr) — skipping");
        return;
    }
    if (!VendorIsIntel())
    {
        core::Log(core::LogLevel::Warn, "arch/thermal", "non-Intel vendor — Intel thermal MSRs would #GP, skipping");
        return;
    }
    // Even on Intel hardware, KVM hypervisors do not always expose the
    // thermal MSRs to guests — IA32_THERM_STATUS / TEMPERATURE_TARGET /
    // IA32_PACKAGE_THERM_STATUS are NOT in KVM's default user-visible
    // MSR set. A `rdmsr` against an unsupported MSR raises #GP. The
    // kernel's trap dispatcher does NOT have an extable entry for the
    // thermal-probe rdmsr sites, so the #GP loops or wedges the boot.
    // Observed live on a GitHub Actions ubuntu-24.04 runner with an
    // Intel Xeon Platinum 8370C (Ice Lake-SP) host and KVM accel: the
    // boot log printed `[boot] Reading MSR thermals.` and never
    // emitted another byte until the 480s smoke wall-budget killed
    // QEMU. Sister profiles on a different runner (with thermal MSRs
    // exposed by KVM) finished bringup-complete in ~1s of guest. So
    // thermal probing is presence-of-hardware sensitive even within
    // the "Intel under KVM" subset.
    //
    // Gate on IsEmulator: bare-metal Intel + TCG (silently returns 0)
    // both keep working as before. Under any KVM/HVM hypervisor we
    // skip the probe entirely. The boot-smoke critical path doesn't
    // assert on thermal output, so this is observability-only loss.
    if (duetos::arch::IsEmulator())
    {
        core::Log(core::LogLevel::Warn, "arch/thermal",
                  "hypervisor present — Intel thermal MSRs may #GP under KVM, skipping");
        return;
    }
    const ThermalReading r = ThermalRead();
    if (!r.valid)
    {
        core::Log(core::LogLevel::Warn, "arch/thermal",
                  "MSRs present but thermal sensors report invalid (likely emulator)");
        return;
    }
    arch::SerialWrite("[thermal] tj_max=");
    arch::SerialWriteHex(r.tj_max_c);
    arch::SerialWrite(" core=");
    if (r.core_valid)
    {
        arch::SerialWriteHex(r.core_temp_c);
        arch::SerialWrite("C");
    }
    else
    {
        arch::SerialWrite("?");
    }
    arch::SerialWrite(" package=");
    if (r.package_valid)
    {
        arch::SerialWriteHex(r.package_temp_c);
        arch::SerialWrite("C");
    }
    else
    {
        arch::SerialWrite("?");
    }
    arch::SerialWrite(r.thermal_throttle_hit ? " throttle=HIT\n" : " throttle=clear\n");
}

} // namespace duetos::arch
