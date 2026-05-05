/*
 * DuetOS — synthetic per-domain fault injection.
 *
 * Behind the build-time flag `DUETOS_INJECT_DOMAIN_FAULT`. When
 * enabled, this TU registers a synthetic fault domain
 * "selftest.inject" and exposes `InjectDomainFault()` which
 * dereferences a known-bad pointer inside an `EXTABLE_BIND`
 * region. The trap dispatcher fixes up the RIP, marks the
 * domain for restart, fires the dump path through
 * `FaultReactDrainPending`, and the heartbeat ticks in the
 * restart on the next beat. End-to-end proof of the
 * extable -> domain-dump -> watchdog-restart chain without
 * a real driver bug.
 *
 * NOT included in default builds. CI runs MAY opt in via the
 * cmake flag if and when the smoke harness has a hook for the
 * shell command (`fault-inject` is the proposed verb but is
 * deliberately left unwired here — adding it is a follow-up
 * once the synthetic injection is observed working from a
 * test driver).
 *
 * Context: kernel. The injection itself runs from heartbeat /
 * shell context — never from a trap handler.
 */

#ifdef DUETOS_INJECT_DOMAIN_FAULT

#include "core/panic.h"
#include "debug/extable_bind.h"
#include "log/klog.h"
#include "security/driver_domain.h"
#include "security/fault_domain.h"
#include "util/result.h"

namespace duetos::test
{

namespace
{

constinit ::duetos::core::FaultDomainId g_inject_domain = ::duetos::core::kFaultDomainInvalid;
constinit u32 g_inject_init_calls = 0;
constinit u32 g_inject_teardown_calls = 0;

::duetos::core::Result<void> InjectInit()
{
    ++g_inject_init_calls;
    KLOG_INFO("test/inject", "selftest.inject init");
    return {};
}

::duetos::core::Result<void> InjectTeardown()
{
    ++g_inject_teardown_calls;
    KLOG_INFO("test/inject", "selftest.inject teardown");
    return {};
}

// Fixup: returned-to RIP after the trap dispatcher sees the
// faulting RIP land inside the bound region. The fixup runs in
// the same stack frame as the bound code and acts as a "the
// bracketed region returned a failure sentinel" path.
[[gnu::noinline]] u64 InjectFixup()
{
    KLOG_WARN("test/inject", "extable fixup ran (synthetic fault recovered)");
    return 0;
}

} // namespace

void RegisterInjectDomain()
{
    if (g_inject_domain != ::duetos::core::kFaultDomainInvalid)
        return;
    g_inject_domain = ::duetos::security::RegisterDriverDomain("selftest.inject", InjectInit, InjectTeardown);
    if (g_inject_domain == ::duetos::core::kFaultDomainInvalid)
    {
        KLOG_ERROR("test/inject", "register fault domain failed");
        return;
    }
    EXTABLE_BIND_REGISTER(inject_region, g_inject_domain, reinterpret_cast<u64>(&InjectFixup), "test/inject.region");
    KLOG_INFO("test/inject", "synthetic injection domain ready");
}

// Trip the synthetic fault. Caller observes the fixup path
// returning 0 (the sentinel) instead of dereferencing the bad
// pointer. The domain marks itself for deferred restart; the
// heartbeat drains it on the next beat. The dump path emits
// a per-domain record to serial + the recent-dumps ring.
[[gnu::noinline]] u64 InjectDomainFault()
{
    if (g_inject_domain == ::duetos::core::kFaultDomainInvalid)
    {
        KLOG_ERROR("test/inject", "injection domain not registered");
        return 0;
    }
    EXTABLE_BIND_BEGIN(inject_region);
    // Dereference a known-bad kernel address. The page tables
    // never map page 0, so this is guaranteed to trip a kernel
    // mode #PF that the extable catches.
    volatile u64* bad = reinterpret_cast<volatile u64*>(0x10);
    const u64 v = *bad;
    EXTABLE_BIND_END(inject_region);
    return v;
}

u32 InjectInitCalls()
{
    return g_inject_init_calls;
}

u32 InjectTeardownCalls()
{
    return g_inject_teardown_calls;
}

::duetos::core::FaultDomainId InjectDomainId()
{
    return g_inject_domain;
}

} // namespace duetos::test

#endif // DUETOS_INJECT_DOMAIN_FAULT
