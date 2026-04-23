#include "fault_domain.h"

#include "../arch/x86_64/serial.h"
#include "../sched/sched.h"
#include "klog.h"
#include "panic.h"

namespace customos::core
{

namespace
{

constinit FaultDomain g_domains[kMaxFaultDomains] = {};
constinit u32 g_domain_count = 0;

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a && *b && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

} // namespace

FaultDomainId FaultDomainRegister(const char* name, Result<void> (*init)(), Result<void> (*teardown)())
{
    if (name == nullptr || init == nullptr || teardown == nullptr)
        return kFaultDomainInvalid;
    if (g_domain_count >= kMaxFaultDomains)
    {
        arch::SerialWrite("[fault-domain] registry full; refused name=");
        arch::SerialWrite(name);
        arch::SerialWrite("\n");
        return kFaultDomainInvalid;
    }
    const FaultDomainId id = g_domain_count++;
    FaultDomain& d = g_domains[id];
    d.name = name;
    d.init = init;
    d.teardown = teardown;
    d.restart_count = 0;
    d.last_restart_ticks = 0;
    d.alive = true; // assume the subsystem's own Init ran already
    arch::SerialWrite("[fault-domain] register id=");
    arch::SerialWriteHex(id);
    arch::SerialWrite(" name=");
    arch::SerialWrite(name);
    arch::SerialWrite("\n");
    return id;
}

u32 FaultDomainCount()
{
    return g_domain_count;
}

const FaultDomain* FaultDomainGet(FaultDomainId id)
{
    if (id >= g_domain_count)
        return nullptr;
    return &g_domains[id];
}

FaultDomainId FaultDomainFind(const char* name)
{
    for (u32 i = 0; i < g_domain_count; ++i)
    {
        if (StrEq(g_domains[i].name, name))
            return i;
    }
    return kFaultDomainInvalid;
}

Result<void> FaultDomainRestart(FaultDomainId id)
{
    if (id >= g_domain_count)
        return Err{ErrorCode::NotFound};
    FaultDomain& d = g_domains[id];

    arch::SerialWrite("[fault-domain] restart begin name=");
    arch::SerialWrite(d.name);
    arch::SerialWrite(" prev_count=");
    arch::SerialWriteHex(d.restart_count);
    arch::SerialWrite("\n");

    // Teardown phase — subsystem is considered dead the moment we
    // call it, regardless of outcome. A half-tore-down domain is
    // expected to land here on its next restart and self-heal.
    d.alive = false;
    const auto td = d.teardown();
    if (!td)
    {
        arch::SerialWrite("[fault-domain] teardown failed name=");
        arch::SerialWrite(d.name);
        arch::SerialWrite(" err=");
        arch::SerialWrite(ErrorCodeName(td.error()));
        arch::SerialWrite("\n");
        return Err{td.error()};
    }

    // Init phase — brings the subsystem back to a live state.
    const auto in = d.init();
    if (!in)
    {
        arch::SerialWrite("[fault-domain] init failed name=");
        arch::SerialWrite(d.name);
        arch::SerialWrite(" err=");
        arch::SerialWrite(ErrorCodeName(in.error()));
        arch::SerialWrite("\n");
        return Err{in.error()};
    }

    d.alive = true;
    ++d.restart_count;
    d.last_restart_ticks = sched::SchedNowTicks();
    arch::SerialWrite("[fault-domain] restart ok name=");
    arch::SerialWrite(d.name);
    arch::SerialWrite(" count=");
    arch::SerialWriteHex(d.restart_count);
    arch::SerialWrite("\n");
    return {};
}

// ----------------------------------------------------------------
// Self-test: register a toy domain with counters, restart it, and
// verify the bookkeeping.
// ----------------------------------------------------------------

namespace
{

constinit u32 g_selftest_init_calls = 0;
constinit u32 g_selftest_teardown_calls = 0;

Result<void> SelfTestInit()
{
    ++g_selftest_init_calls;
    return {};
}

Result<void> SelfTestTeardown()
{
    ++g_selftest_teardown_calls;
    return {};
}

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[fault-domain-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    PanicWithValue("core/fault-domain", "self-test mismatch", 0);
}

} // namespace

void FaultDomainSelfTest()
{
    KLOG_TRACE_SCOPE("core/fault-domain", "SelfTest");

    g_selftest_init_calls = 0;
    g_selftest_teardown_calls = 0;
    const FaultDomainId id = FaultDomainRegister("selftest.synth", SelfTestInit, SelfTestTeardown);
    Expect(id != kFaultDomainInvalid, "register returns valid id");

    // First restart: teardown = 1, init = 1.
    const auto r1 = FaultDomainRestart(id);
    Expect(bool(r1), "first restart ok");
    Expect(g_selftest_teardown_calls == 1, "teardown count after r1");
    Expect(g_selftest_init_calls == 1, "init count after r1");

    // Second restart: teardown = 2, init = 2; count on the domain = 2.
    const auto r2 = FaultDomainRestart(id);
    Expect(bool(r2), "second restart ok");
    Expect(g_selftest_teardown_calls == 2, "teardown count after r2");
    Expect(g_selftest_init_calls == 2, "init count after r2");
    Expect(FaultDomainGet(id)->restart_count == 2, "domain.restart_count == 2");

    // Lookup by name round-trips.
    Expect(FaultDomainFind("selftest.synth") == id, "find by name round-trip");
    Expect(FaultDomainFind("nonexistent") == kFaultDomainInvalid, "missing name -> invalid");

    arch::SerialWrite("[fault-domain-selftest] PASS (");
    arch::SerialWriteHex(g_domain_count);
    arch::SerialWrite(" domains; toy restarted 2x)\n");
}

} // namespace customos::core
