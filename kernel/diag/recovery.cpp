#include "diag/recovery.h"

#include "diag/fault_react.h"
#include "log/klog.h"

namespace duetos::core
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
    default:
        KLOG_ONCE_WARN("diag/recovery", "ReasonString: unrecognised DriverFaultReason");
        return "unknown";
    }
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

namespace
{

::duetos::diag::FaultKind ReasonToKind(DriverFaultReason r)
{
    switch (r)
    {
    case DriverFaultReason::DeviceTimeout:
        return ::duetos::diag::FaultKind::DeviceTimeout;
    case DriverFaultReason::UnexpectedStatus:
        return ::duetos::diag::FaultKind::UnexpectedStatus;
    case DriverFaultReason::DmaError:
        return ::duetos::diag::FaultKind::DmaError;
    case DriverFaultReason::FirmwareLied:
        return ::duetos::diag::FaultKind::FirmwareLied;
    case DriverFaultReason::InternalInvariant:
        return ::duetos::diag::FaultKind::InternalInvariant;
    case DriverFaultReason::Hung:
        return ::duetos::diag::FaultKind::Hung;
    case DriverFaultReason::Unknown:
        return ::duetos::diag::FaultKind::Unknown;
    }
    return ::duetos::diag::FaultKind::Unknown;
}

::duetos::diag::FaultSeverity ReasonToSeverity(DriverFaultReason r)
{
    switch (r)
    {
    case DriverFaultReason::DeviceTimeout:
    case DriverFaultReason::UnexpectedStatus:
    case DriverFaultReason::DmaError:
        return ::duetos::diag::FaultSeverity::Recoverable;
    case DriverFaultReason::FirmwareLied:
    case DriverFaultReason::Hung:
        return ::duetos::diag::FaultSeverity::Degraded;
    case DriverFaultReason::InternalInvariant:
        return ::duetos::diag::FaultSeverity::Critical;
    case DriverFaultReason::Unknown:
        return ::duetos::diag::FaultSeverity::Recoverable;
    }
    return ::duetos::diag::FaultSeverity::Recoverable;
}

} // namespace

void DriverFault(const char* driver_name, DriverFaultReason reason, FaultDomainId domain_id)
{
    ++g_driver_fault_count;

    ::duetos::diag::FaultEvidence ev = {};
    ev.source = driver_name;
    ev.kind = ReasonToKind(reason);
    ev.severity = ReasonToSeverity(reason);
    ev.attempt_count = 0;
    ev.faulting_rip = 0;
    ev.aux = g_driver_fault_count;

    // Dispatch chooses + executes the reaction. May not return
    // (Halt path); when it does, the chosen reaction is the
    // dispatcher's clamped result, not the policy's raw choice.
    (void)::duetos::diag::FaultReactDispatch(domain_id, ev);
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

} // namespace duetos::core
