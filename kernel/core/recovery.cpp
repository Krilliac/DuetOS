#include "recovery.h"

#include "klog.h"

namespace customos::core
{

namespace
{

constinit u64 g_driver_fault_count = 0;

const char* ReasonString(DriverFaultReason reason)
{
    switch (reason)
    {
    case DriverFaultReason::DeviceTimeout:
        return "device timeout";
    case DriverFaultReason::UnexpectedStatus:
        return "unexpected status";
    case DriverFaultReason::DmaError:
        return "dma error";
    case DriverFaultReason::FirmwareLied:
        return "firmware lied";
    case DriverFaultReason::InternalInvariant:
        return "internal invariant violated";
    case DriverFaultReason::Hung:
        return "driver hung (watchdog)";
    case DriverFaultReason::Unknown:
        return "unknown";
    }
    return "unknown";
}

} // namespace

void DriverFault(const char* driver_name, DriverFaultReason reason)
{
    ++g_driver_fault_count;

    // v0: log + count. Driver-restart machinery arrives with the
    // driver model; until then call sites are just reporting to
    // the audit stream.
    LogWithValue(LogLevel::Error, driver_name, ReasonString(reason), g_driver_fault_count);
}

u64 DriverFaultCount()
{
    return g_driver_fault_count;
}

void OnTaskExited()
{
    // Scheduler wakes its reaper separately (so this symbol can live
    // in core/ without pulling sched/ includes into every driver).
    // When ring-3 process-kill lands, THIS function grows to do the
    // address-space teardown, fd close, capability revocation, etc.
    // For now, no-op — the reaper gets woken by sched::SchedExit.
}

} // namespace customos::core
