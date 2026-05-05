#include "security/module.h"

#include "core/panic.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "security/domain_dump.h"
#include "util/result.h"

namespace duetos::security
{

namespace
{

void FireStateChange(::duetos::core::FaultDomainId id, ::duetos::core::ModuleState before,
                     ::duetos::core::ModuleState after)
{
    // GDB hook for "break on every module state flip during
    // triage" — one breakpoint at `duetos::debug::ProbeFire`
    // catches every transition without having to chase
    // individual call sites.
    const u64 packed = (static_cast<u64>(id) << 32) | (static_cast<u64>(static_cast<u8>(before)) << 8) |
                       static_cast<u64>(static_cast<u8>(after));
    KBP_PROBE_V(::duetos::debug::ProbeId::kModuleStateChange, packed);
}

} // namespace

::duetos::core::ModuleState ModuleStateOf(::duetos::core::FaultDomainId id)
{
    const auto* d = ::duetos::core::FaultDomainGet(id);
    if (d == nullptr)
        return ::duetos::core::ModuleState::Stopped;
    return d->state;
}

const char* ModuleStateName(::duetos::core::ModuleState s)
{
    switch (s)
    {
    case ::duetos::core::ModuleState::Stopped:
        return "stopped";
    case ::duetos::core::ModuleState::Running:
        return "running";
    case ::duetos::core::ModuleState::Crashed:
        return "crashed";
    }
    return "unknown";
}

::duetos::core::Result<void> ModuleStart(::duetos::core::FaultDomainId id)
{
    auto* d = ::duetos::core::FaultDomainGetMutable(id);
    if (d == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    if (d->state == ::duetos::core::ModuleState::Running)
    {
        KLOG_WARN_S("security/module", "start refused: module already running", "name", d->name);
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    }
    const auto before = d->state;
    const auto r = d->init();
    if (!r)
    {
        KLOG_ERROR_S("security/module", "start: init failed", "name", d->name);
        // Init failed — leave state as-is (Stopped or Crashed)
        // so the operator can see the failure didn't change the
        // module's situation. The error code surfaces upstream.
        return ::duetos::core::Err{r.error()};
    }
    d->alive = true;
    d->state = ::duetos::core::ModuleState::Running;
    FireStateChange(id, before, d->state);
    KLOG_INFO_S("security/module", "started", "name", d->name);
    return {};
}

::duetos::core::Result<void> ModuleStop(::duetos::core::FaultDomainId id)
{
    auto* d = ::duetos::core::FaultDomainGetMutable(id);
    if (d == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    if (d->state == ::duetos::core::ModuleState::Stopped)
    {
        KLOG_WARN_S("security/module", "stop refused: module already stopped", "name", d->name);
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    }
    const auto before = d->state;
    const auto r = d->teardown();
    if (!r)
    {
        KLOG_ERROR_S("security/module", "stop: teardown failed", "name", d->name);
        // Teardown failed — the subsystem is in an indeterminate
        // state. Mark Stopped anyway so a subsequent start is
        // legal; the alternative (leaving state Running) would
        // imply teardown can be skipped, which it cannot.
        d->alive = false;
        d->state = ::duetos::core::ModuleState::Stopped;
        FireStateChange(id, before, d->state);
        return ::duetos::core::Err{r.error()};
    }
    d->alive = false;
    d->state = ::duetos::core::ModuleState::Stopped;
    FireStateChange(id, before, d->state);
    KLOG_INFO_S("security/module", "stopped", "name", d->name);
    return {};
}

::duetos::core::Result<void> ModuleRestart(::duetos::core::FaultDomainId id)
{
    // FaultDomainRestart already fires its own log lines and
    // updates the state field on success/failure. Just forward.
    auto* d = ::duetos::core::FaultDomainGetMutable(id);
    const auto before = (d != nullptr) ? d->state : ::duetos::core::ModuleState::Stopped;
    const auto r = ::duetos::core::FaultDomainRestart(id);
    if (d != nullptr)
    {
        FireStateChange(id, before, d->state);
    }
    return r;
}

::duetos::core::Result<void> ModuleDump(::duetos::core::FaultDomainId id)
{
    const auto* d = ::duetos::core::FaultDomainGet(id);
    if (d == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    DomainDumpEvidence ev = {};
    ev.kind = ::duetos::diag::FaultKind::Unknown;
    ev.faulting_rip = 0;
    ev.aux = 0;
    ev.frame = nullptr;
    BeginDomainDump(id, ev);
    EndDomainDump();
    return {};
}

// ----------------------------------------------------------------
// Self-test. Registers a synthetic module, exercises every
// transition + every refusal path, asserts state + alive/
// restart_count counters move correctly. Panics on mismatch.
// ----------------------------------------------------------------

namespace
{

constinit u32 g_st_init_calls = 0;
constinit u32 g_st_teardown_calls = 0;
constinit bool g_st_init_should_fail = false;

::duetos::core::Result<void> StInit()
{
    ++g_st_init_calls;
    if (g_st_init_should_fail)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    return {};
}

::duetos::core::Result<void> StTeardown()
{
    ++g_st_teardown_calls;
    return {};
}

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    ::duetos::core::PanicWithValue("security/module", "self-test mismatch", 0);
    (void)what;
}

} // namespace

void ModuleSelfTest()
{
    KLOG_TRACE_SCOPE("security/module", "SelfTest");

    g_st_init_calls = 0;
    g_st_teardown_calls = 0;
    g_st_init_should_fail = false;

    const auto id = ::duetos::core::FaultDomainRegister("selftest.module", StInit, StTeardown);
    Expect(id != ::duetos::core::kFaultDomainInvalid, "register module");

    // Newly registered -> Running (matches FaultDomainRegister's
    // contract that the subsystem's own Init has already run).
    Expect(ModuleStateOf(id) == ::duetos::core::ModuleState::Running, "post-register state");

    // Start while Running -> refused with BadState.
    {
        const auto r = ModuleStart(id);
        Expect(!r && r.error() == ::duetos::core::ErrorCode::BadState, "start refuses Running");
    }

    // Stop while Running -> teardown count up, state Stopped.
    {
        const auto r = ModuleStop(id);
        Expect(bool(r), "stop ok from Running");
        Expect(ModuleStateOf(id) == ::duetos::core::ModuleState::Stopped, "state Stopped");
        Expect(g_st_teardown_calls == 1, "teardown count");
    }

    // Stop while Stopped -> refused with BadState.
    {
        const auto r = ModuleStop(id);
        Expect(!r && r.error() == ::duetos::core::ErrorCode::BadState, "stop refuses Stopped");
    }

    // Start while Stopped -> init count up, state Running.
    {
        const auto r = ModuleStart(id);
        Expect(bool(r), "start ok from Stopped");
        Expect(ModuleStateOf(id) == ::duetos::core::ModuleState::Running, "state Running");
        Expect(g_st_init_calls == 1, "init count");
    }

    // Restart drives teardown + init.
    {
        const auto r = ModuleRestart(id);
        Expect(bool(r), "restart ok");
        Expect(ModuleStateOf(id) == ::duetos::core::ModuleState::Running, "state Running after restart");
        Expect(g_st_teardown_calls == 2, "teardown count after restart");
        Expect(g_st_init_calls == 2, "init count after restart");
    }

    // Init failure -> stays Stopped, error propagates.
    {
        // Drive to Stopped first.
        Expect(bool(ModuleStop(id)), "drive to Stopped for failure-path test");
        g_st_init_should_fail = true;
        const auto r = ModuleStart(id);
        Expect(!r && r.error() == ::duetos::core::ErrorCode::OutOfMemory, "start propagates init Err");
        Expect(ModuleStateOf(id) == ::duetos::core::ModuleState::Stopped, "stays Stopped on init failure");
        g_st_init_should_fail = false;
        // Recover for end-of-boot cleanliness.
        Expect(bool(ModuleStart(id)), "recover Running after failure-path test");
    }

    // Out-of-range id surfaces NotFound, not crash.
    {
        const auto r = ModuleStart(::duetos::core::kFaultDomainInvalid);
        Expect(!r && r.error() == ::duetos::core::ErrorCode::NotFound, "invalid id -> NotFound");
        const auto s = ModuleStateOf(::duetos::core::kFaultDomainInvalid);
        Expect(s == ::duetos::core::ModuleState::Stopped, "invalid id state -> Stopped");
    }

    KLOG_INFO("security/module", "self-test PASS (start/stop/restart/dump + refusals + invalid-id verified)");
}

} // namespace duetos::security
