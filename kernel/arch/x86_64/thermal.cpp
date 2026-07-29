#include "arch/x86_64/thermal.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_sensor_math.h"
#include "arch/x86_64/msr_safe.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "sync/spinlock.h"

namespace duetos::arch
{

namespace
{

namespace csm = ::duetos::arch::cpu_sensor_math;

constexpr u32 kMsrIa32ThermStatus = 0x19C;
constexpr u32 kMsrTemperatureTarget = 0x1A2;
constexpr u32 kMsrIa32PackageThermStatus = 0x1B1;

// AMD SMN index/data pair in PCI config space on the root complex
// (device 0:0.0), and the Zen reported-temperature register address
// within the SMN aperture.
constexpr u8 kSmnIndexReg = 0x60;
constexpr u8 kSmnDataReg = 0x64;
constexpr u32 kSmnZenReportedTemp = 0x00059800;
constexpr u16 kPciVendorAmd = 0x1022;

// The SMN index/data pair is a two-step non-atomic sequence: write the
// address, then read the data. Two CPUs interleaving would hand each
// other the wrong register's contents. PciConfigRead32 locks each
// individual access; this lock spans the pair.
constinit sync::SpinLock g_smn_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassSmn};

// Vendor probe result, resolved on first use. Caching matters: on a
// part that does not implement the Intel thermal MSRs the probe read
// takes a recovered #GP, and the trap dispatcher prints one
// "[extable] recovered kernel trap" line each time. Once is
// diagnostic; once per ThermalRead would be a log flood.
enum class Probe : u8
{
    Unresolved = 0,
    None,
    IntelMsr,
    AmdSmn,
};

constinit Probe g_probe = Probe::Unresolved;

/// Read a 32-bit SMN register through the root complex's index/data
/// pair. Returns false when the host bridge is not AMD (so we never
/// write 0x60 on someone else's device — on an Intel MCH that offset
/// is a DRAM-configuration register) or when the aperture answers
/// all-ones, which is what an unpopulated config read looks like.
bool SmnRead32(u32 smn_addr, u32* out)
{
    const drivers::pci::DeviceAddress root = {0, 0, 0, 0};
    if (drivers::pci::PciConfigRead16(root, 0x00) != kPciVendorAmd)
        return false;

    sync::SpinLockGuard guard(g_smn_lock);
    drivers::pci::PciConfigWrite32(root, kSmnIndexReg, smn_addr);
    const u32 value = drivers::pci::PciConfigRead32(root, kSmnDataReg);
    if (value == 0xFFFFFFFFu)
        return false;
    *out = value;
    return true;
}

/// Decide once which sensor this machine has. Probing means actually
/// touching the sensor: predicting from the vendor string alone is
/// what used to leave an AMD box with no temperature at all and an
/// Intel box under KVM wedged on a #GP.
Probe ResolveProbe()
{
    if (!CpuHas(kCpuFeatMsr))
        return Probe::None;

    if (CpuVendorIsIntel())
    {
        // Ask. A hypervisor that declines to expose IA32_THERM_STATUS
        // answers with a #GP that ReadMsrSafe turns into `false`; a
        // part that has it answers with the register.
        u64 ts = 0;
        if (ReadMsrSafe(kMsrIa32ThermStatus, &ts) && ts != 0)
            return Probe::IntelMsr;
        return Probe::None;
    }

    if (CpuVendorIsAmd())
    {
        if (!csm::ZenFamilySupported(CpuInfoGet().family))
            return Probe::None;
        u32 raw = 0;
        if (SmnRead32(kSmnZenReportedTemp, &raw) && raw != 0)
            return Probe::AmdSmn;
        return Probe::None;
    }

    return Probe::None;
}

Probe CurrentProbe()
{
    if (g_probe == Probe::Unresolved)
        g_probe = ResolveProbe();
    return g_probe;
}

ThermalReading ReadIntel()
{
    ThermalReading r = {};
    r.source = ThermalSource::IntelMsr;

    // TJMax. Absent on some SKUs; the architectural default is 100 C.
    // Flagged so a caller can tell the measured limit from the
    // fallback rather than believing every part is a 100 C part.
    u8 tj_max = 100;
    u64 tj = 0;
    if (ReadMsrSafe(kMsrTemperatureTarget, &tj))
    {
        const u8 reported = u8((tj >> 16) & 0xFF);
        if (reported != 0)
        {
            tj_max = reported;
            r.tj_max_valid = true;
        }
    }
    r.tj_max_c = tj_max;

    u64 ts = 0;
    if (ReadMsrSafe(kMsrIa32ThermStatus, &ts) && (ts & (1u << 31)) != 0)
    {
        r.core_valid = true;
        const u8 dist = u8((ts >> 16) & 0x7F);
        r.core_temp_c = (tj_max > dist) ? u8(tj_max - dist) : 0;
        if ((ts & 1) != 0)
            r.thermal_throttle_hit = true;
    }

    u64 pkg = 0;
    if (ReadMsrSafe(kMsrIa32PackageThermStatus, &pkg) && (pkg & (1u << 31)) != 0)
    {
        r.package_valid = true;
        const u8 dist = u8((pkg >> 16) & 0x7F);
        r.package_temp_c = (tj_max > dist) ? u8(tj_max - dist) : 0;
    }

    r.valid = r.core_valid || r.package_valid;
    return r;
}

ThermalReading ReadAmd()
{
    ThermalReading r = {};
    r.source = ThermalSource::AmdSmn;

    u32 raw = 0;
    if (!SmnRead32(kSmnZenReportedTemp, &raw))
        return r;

    r.core_valid = true;
    r.core_temp_c = csm::MilliCToWholeC(csm::ZenTempMilliC(raw));
    r.valid = true;

    // GAP: no package figure and no junction limit on this path — the
    // Zen SMN register carries neither, and the per-CCD sensors sit at
    // different SMN addresses that vary by family and model. Revisit
    // when a multi-CCD part is under test. `tj_max_valid` stays false
    // so callers render the limit as unknown rather than as 0 C.
    return r;
}

const char* SourceName(ThermalSource s)
{
    switch (s)
    {
    case ThermalSource::IntelMsr:
        return "intel-msr";
    case ThermalSource::AmdSmn:
        return "amd-smn";
    case ThermalSource::None:
        break;
    }
    return "none";
}

} // namespace

ThermalReading ThermalRead()
{
    ThermalReading r = {};
    switch (CurrentProbe())
    {
    case Probe::IntelMsr:
        r = ReadIntel();
        break;
    case Probe::AmdSmn:
        r = ReadAmd();
        break;
    case Probe::None:
    case Probe::Unresolved:
        break;
    }
    // A sensor that answered the probe can still decline an individual
    // read (Intel clears IA32_THERM_STATUS bit 31 while the sensor
    // settles). Collapse that to the plain unsupported record so
    // `source` never advertises a path that produced no figure — the
    // caller has exactly one thing to test.
    if (!r.valid)
        return ThermalReading{};
    return r;
}

void ThermalProbe()
{
    const ThermalReading r = ThermalRead();
    if (!r.valid)
    {
        // Say WHY, and never print a number. The three reasons a
        // machine lands here are materially different to an operator:
        // no MSR support at all, a vendor whose sensor we do not know
        // how to reach, or a sensor that is there but declined to
        // answer (a hypervisor, typically).
        if (!CpuHas(kCpuFeatMsr))
            KLOG_WARN("arch/thermal", "no MSR support (CpuFeatMsr) - no CPU temperature on this machine");
        else if (CpuVendorIsAmd() && !cpu_sensor_math::ZenFamilySupported(CpuInfoGet().family))
            KLOG_WARN("arch/thermal", "AMD family outside 17h/19h/1Ah - SMN temperature layout unknown, unsupported");
        else
            KLOG_WARN("arch/thermal", "no readable CPU temperature sensor (probe declined) - reporting unsupported");
        SerialWrite("[thermal] source=none temp=unsupported\n");
        return;
    }

    SerialLineGuard guard;
    SerialWrite("[thermal] source=");
    SerialWrite(SourceName(r.source));
    SerialWrite(" core=");
    if (r.core_valid)
    {
        SerialWriteHex(r.core_temp_c);
        SerialWrite("C");
    }
    else
    {
        SerialWrite("unsupported");
    }
    SerialWrite(" package=");
    if (r.package_valid)
    {
        SerialWriteHex(r.package_temp_c);
        SerialWrite("C");
    }
    else
    {
        SerialWrite("unsupported");
    }
    SerialWrite(" tj_max=");
    if (r.tj_max_valid)
    {
        SerialWriteHex(r.tj_max_c);
        SerialWrite("C");
    }
    else
    {
        SerialWrite("unknown");
    }
    SerialWrite(r.thermal_throttle_hit ? " throttle=HIT\n" : " throttle=clear\n");
}

void ThermalSelfTest()
{
    using core::PanicWithValue;

    // --- decode math (runs identically everywhere) ----------------
    // 0x37 (55) counts at 0.125 C: 55 * 125 = 6875 mC.
    if (csm::ZenTempMilliC(0x37u << csm::kZenCurTempShift) != 6875)
        PanicWithValue("arch/thermal", "Zen temp decode != 6875 mC", 1);
    // Same count with the range-select bit set is 49 C lower.
    if (csm::ZenTempMilliC((0x37u << csm::kZenCurTempShift) | csm::kZenCurTempRangeSelBit) != 6875 - 49000)
        PanicWithValue("arch/thermal", "Zen range-select offset not applied", 2);
    // Sub-zero Tctl clamps to 0 rather than wrapping through u8.
    if (csm::MilliCToWholeC(-1000) != 0)
        PanicWithValue("arch/thermal", "negative Tctl did not clamp to 0", 3);
    // Pre-Zen and post-Zen5 families must report unsupported.
    if (csm::ZenFamilySupported(0x15) || csm::ZenFamilySupported(0x06))
        PanicWithValue("arch/thermal", "non-Zen family reported as supported", 4);
    if (!csm::ZenFamilySupported(0x19))
        PanicWithValue("arch/thermal", "Zen3/4 family reported as unsupported", 5);

    // --- unsupported-vs-zero invariant on the live reading --------
    const ThermalReading r = ThermalRead();
    if (!r.valid && r.source != ThermalSource::None)
        PanicWithValue("arch/thermal", "invalid reading carries a sensor source", u32(r.source));
    if (r.valid && r.source == ThermalSource::None)
        PanicWithValue("arch/thermal", "valid reading carries no sensor source", 0);
    // A valid reading must have at least one populated figure, or the
    // `valid` flag is claiming more than the record carries.
    if (r.valid && !r.core_valid && !r.package_valid)
        PanicWithValue("arch/thermal", "valid reading with no populated figure", 0);
    // The AMD path knows no junction limit; asserting it here stops a
    // future edit from quietly reintroducing a 100 C default there.
    if (r.source == ThermalSource::AmdSmn && r.tj_max_valid)
        PanicWithValue("arch/thermal", "AMD path claimed a junction limit", r.tj_max_c);

    SerialLineGuard guard;
    SerialWrite("[thermal-selftest] PASS (Zen decode + unsupported-vs-zero; source=");
    SerialWrite(SourceName(r.source));
    SerialWrite(")\n");
}

} // namespace duetos::arch
