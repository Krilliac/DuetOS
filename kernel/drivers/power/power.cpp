#include "power.h"

#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/smbios.h"
#include "../../arch/x86_64/thermal.h"
#include "../../core/klog.h"
#include "../../core/panic.h"

namespace customos::drivers::power
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

} // namespace

void PowerInit()
{
    KLOG_TRACE_SCOPE("drivers/power", "PowerInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/power", "PowerInit called twice");
    s_done = true;

    g_snapshot.backend_is_stub = true;
    g_snapshot.chassis_is_laptop = arch::SmbiosIsLaptopChassis();

    // Without AML we can't read _PSR / _BIF / _BST, so the best
    // we can do today is: if the chassis is laptop-like, assume
    // battery HARDWARE is present but report "unknown" for its
    // state. Desktop chassis → no battery, AC-online.
    if (g_snapshot.chassis_is_laptop)
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
    g_snapshot.battery.rate_mw = 0;
    g_snapshot.battery.voltage_mv = 0;
    g_snapshot.battery.design_capacity_mwh = 0;
    g_snapshot.battery.full_capacity_mwh = 0;

    PopulateThermal(g_snapshot);

    arch::SerialWrite("[power] chassis=");
    arch::SerialWrite(g_snapshot.chassis_is_laptop ? "laptop-like" : "desktop/server");
    arch::SerialWrite(" ac=");
    arch::SerialWrite(AcStateName(g_snapshot.ac));
    arch::SerialWrite(" battery=");
    arch::SerialWrite(BatteryStateName(g_snapshot.battery.state));
    arch::SerialWrite("  cpu_temp=");
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

    core::Log(core::LogLevel::Warn, "drivers/power",
              "power backend is a stub — real battery/AC needs AML interpreter; thermal is real MSR data");
}

PowerSnapshot PowerSnapshotRead()
{
    PopulateThermal(g_snapshot);
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

} // namespace customos::drivers::power
