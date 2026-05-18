#include "drivers/power/power.h"

#include "acpi/acpi.h"
#include "acpi/acpi_power.h"
#include "acpi/ec.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/thermal.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::drivers::power
{

namespace
{

PowerSnapshot g_snapshot = {};

void PopulateThermal(PowerSnapshot& s)
{
    const arch::ThermalReading t = arch::ThermalRead();
    s.tj_max_c = t.tj_max_c;
    s.cpu_temp_c = t.core_valid ? t.core_temp_c : 0;
    s.package_temp_c = t.package_valid ? t.package_temp_c : 0;
    s.thermal_throttle_hit = t.thermal_throttle_hit;
}

BatteryState MapBatStatus(acpi::AcpiBatStatus s)
{
    switch (s)
    {
    case acpi::AcpiBatStatus::Charging:
        return kBatCharging;
    case acpi::AcpiBatStatus::Discharging:
        return kBatDischarging;
    case acpi::AcpiBatStatus::Full:
        return kBatFull;
    case acpi::AcpiBatStatus::NotPresent:
        return kBatNotPresent;
    default:
        return kBatUnknown;
    }
}

// Pull live battery / AC / lid state from ACPI via the AML
// interpreter. Returns true iff any real datum was obtained (so the
// caller can clear backend_is_stub). On a platform with no power
// AML (QEMU) this leaves the SMBIOS-derived fields untouched.
bool PopulateAcpiPower(PowerSnapshot& s)
{
    bool any = false;

    acpi::AcpiBatteryReading b{};
    if (acpi::AcpiReadBattery(&b))
    {
        s.battery.state = MapBatStatus(b.status);
        s.battery.percent = b.percent;
        s.battery.rate_mw = b.rate_mw;
        s.battery.voltage_mv = b.voltage_mv;
        s.battery.design_capacity_mwh = b.design_mwh;
        s.battery.full_capacity_mwh = b.full_mwh;
        any = true;
    }

    bool online = false;
    if (acpi::AcpiReadAcOnline(&online))
    {
        s.ac = online ? kAcOnline : kAcOffline;
        any = true;
    }

    bool lid_open = false;
    if (acpi::AcpiReadLid(&lid_open))
    {
        s.lid_present = true;
        s.lid_open = lid_open;
        any = true;
    }
    return any;
}

} // namespace

void PowerInit()
{
    KLOG_TRACE_SCOPE("drivers/power", "PowerInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/power", "PowerInit called twice");
    s_done = true;

    g_snapshot.chassis_is_laptop = arch::SmbiosIsLaptopChassis();

    // Sensible defaults; ACPI overrides what it can read.
    g_snapshot.ac = kAcUnknown;
    g_snapshot.battery.state = kBatUnknown;
    g_snapshot.battery.percent = 255;
    g_snapshot.battery.rate_mw = 0;
    g_snapshot.battery.voltage_mv = 0;
    g_snapshot.battery.design_capacity_mwh = 0;
    g_snapshot.battery.full_capacity_mwh = 0;
    g_snapshot.lid_present = false;
    g_snapshot.lid_open = true;

    // Bring up the ACPI EC first so battery `_BST` methods that read
    // EmbeddedControl FieldUnits resolve, then pull live state.
    acpi::AcpiEcInit();
    const bool acpi_live = PopulateAcpiPower(g_snapshot);

    if (!acpi_live)
    {
        // No ACPI power AML (e.g. QEMU). Fall back to the SMBIOS /
        // AML-name heuristic for battery *presence* only.
        const bool aml_bat = acpi::AmlContainsName("BAT0") || acpi::AmlContainsName("BAT1");
        if (aml_bat || g_snapshot.chassis_is_laptop)
        {
            g_snapshot.ac = kAcUnknown;
            g_snapshot.battery.state = kBatUnknown;
            g_snapshot.battery.percent = 255;
        }
        else
        {
            g_snapshot.ac = kAcOnline;
            g_snapshot.battery.state = kBatNotPresent;
            g_snapshot.battery.percent = 0;
        }
    }
    // "stub" now means: no live ACPI power backend on this platform.
    g_snapshot.backend_is_stub = !acpi_live;

    PopulateThermal(g_snapshot);

    arch::SerialWrite("[power] chassis=");
    arch::SerialWrite(g_snapshot.chassis_is_laptop ? "laptop-like" : "desktop/server");
    arch::SerialWrite(" acpi=");
    arch::SerialWrite(acpi_live ? "live" : "absent");
    arch::SerialWrite(" ec=");
    arch::SerialWrite(acpi::AcpiEcPresent() ? "present" : "absent");
    arch::SerialWrite(" ac=");
    arch::SerialWrite(AcStateName(g_snapshot.ac));
    arch::SerialWrite(" battery=");
    arch::SerialWrite(BatteryStateName(g_snapshot.battery.state));
    arch::SerialWrite(" lid=");
    arch::SerialWrite(g_snapshot.lid_present ? (g_snapshot.lid_open ? "open" : "closed") : "n/a");
    arch::SerialWrite(" cpu_temp=");
    if (g_snapshot.cpu_temp_c != 0)
    {
        arch::SerialWriteHex(g_snapshot.cpu_temp_c);
        arch::SerialWrite("C");
    }
    else
    {
        arch::SerialWrite("?");
    }
    arch::SerialWrite("\n");

    if (g_snapshot.backend_is_stub)
        core::Log(core::LogLevel::Warn, "drivers/power",
                  "no live ACPI power backend on this platform — battery/AC unknown; thermal is real MSR data");
    else
        core::Log(core::LogLevel::Info, "drivers/power", "live ACPI power backend — battery/AC/lid from AML");
}

PowerSnapshot PowerSnapshotRead()
{
    PopulateThermal(g_snapshot);
    // Re-poll ACPI so battery percent / AC / lid track changes.
    if (!g_snapshot.backend_is_stub)
        (void)PopulateAcpiPower(g_snapshot);
    return g_snapshot;
}

const char* AcStateName(AcState s)
{
    switch (s)
    {
    case kAcOnline:
        return "online";
    case kAcOffline:
        return "offline";
    default:
        return "unknown";
    }
}

const char* BatteryStateName(BatteryState s)
{
    switch (s)
    {
    case kBatCharging:
        return "charging";
    case kBatDischarging:
        return "discharging";
    case kBatFull:
        return "full";
    case kBatUnknown:
        return "unknown";
    default:
        return "not-present";
    }
}

} // namespace duetos::drivers::power
