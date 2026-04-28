/*
 * DuetOS — per-driver fault-domain extension, v0 (plan E3).
 *
 * See `driver_domain.h` for the contract. Wrapper around
 * `core::FaultDomain*` with driver-specific tagging. Today the
 * only difference vs. plain FaultDomain is the registration
 * counter + the shell-friendly Restart wrapper; the day driver
 * domains gain auto-restart-on-fault semantics, this TU is the
 * only place that needs to change.
 */

#include "security/driver_domain.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "security/fault_domain.h"

namespace duetos::security
{

namespace
{

constinit u32 g_driver_domain_count = 0;

} // namespace

core::FaultDomainId RegisterDriverDomain(const char* name, ::duetos::core::Result<void> (*init)(),
                                         ::duetos::core::Result<void> (*teardown)())
{
    const core::FaultDomainId id = core::FaultDomainRegister(name, init, teardown);
    if (id != core::kFaultDomainInvalid)
    {
        ++g_driver_domain_count;
        KLOG_INFO_S("driver-domain", "registered", "name", name);
    }
    return id;
}

::duetos::core::Result<void> RestartDriverDomain(const char* name)
{
    KLOG_INFO_S("driver-domain", "restart", "name", name);
    const core::FaultDomainId id = core::FaultDomainFind(name);
    if (id == core::kFaultDomainInvalid)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    }
    return core::FaultDomainRestart(id);
}

u32 DriverDomainCount()
{
    return g_driver_domain_count;
}

namespace
{

constinit u32 g_test_init_count = 0;
constinit u32 g_test_teardown_count = 0;

::duetos::core::Result<void> TestInit()
{
    ++g_test_init_count;
    return {};
}

::duetos::core::Result<void> TestTeardown()
{
    ++g_test_teardown_count;
    return {};
}

} // namespace

void DriverDomainSelfTest()
{
    arch::SerialWrite("[driver-domain] self-test: register + restart\n");

    g_test_init_count = 0;
    g_test_teardown_count = 0;
    const u32 baseline = g_driver_domain_count;

    const core::FaultDomainId id = RegisterDriverDomain("dd-test", &TestInit, &TestTeardown);
    if (id == core::kFaultDomainInvalid)
    {
        core::Panic("security/driver-domain", "self-test: registration failed");
    }
    if (g_driver_domain_count != baseline + 1)
    {
        core::Panic("security/driver-domain", "self-test: count didn't advance");
    }

    // Two restarts — each invokes teardown then init, so the
    // counters should each advance by 2.
    auto r1 = RestartDriverDomain("dd-test");
    if (!r1.has_value())
    {
        core::Panic("security/driver-domain", "self-test: first restart failed");
    }
    auto r2 = RestartDriverDomain("dd-test");
    if (!r2.has_value())
    {
        core::Panic("security/driver-domain", "self-test: second restart failed");
    }
    if (g_test_init_count != 2 || g_test_teardown_count != 2)
    {
        core::Panic("security/driver-domain", "self-test: hook counters did not advance by 2");
    }

    // Lookup-by-name miss returns NotFound.
    auto miss = RestartDriverDomain("dd-does-not-exist");
    if (miss.has_value())
    {
        core::Panic("security/driver-domain", "self-test: missing-name lookup succeeded");
    }
    if (miss.error() != ::duetos::core::ErrorCode::NotFound)
    {
        core::Panic("security/driver-domain", "self-test: missing-name returned wrong error");
    }

    arch::SerialWrite("[driver-domain] self-test OK (register + restart × 2 + missing-lookup verified).\n");
}

} // namespace duetos::security
