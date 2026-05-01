#include "diag/fault_react.h"

#include "core/panic.h"
#include "log/klog.h"
#include "security/fault_domain.h"

namespace duetos::diag
{

namespace
{

// One slot per fault domain. Indexed by FaultDomainId. nullptr
// means "no override registered, use the default policy."
//
// The size mirrors core::kMaxFaultDomains; we don't pull the
// constant transitively here to avoid a header-cycle and instead
// assert at the call site that the id fits.
constexpr u32 kPolicySlotCount = 16; // == core::kMaxFaultDomains
constinit FaultReactionFn g_policies[kPolicySlotCount] = {};

constinit u64 g_dispatch_count = 0;
constinit u64 g_reaction_counts[5] = {0, 0, 0, 0, 0}; // indexed by FaultReaction

bool StrStartsWith(const char* s, const char* prefix)
{
    if (s == nullptr || prefix == nullptr)
        return false;
    while (*prefix)
    {
        if (*s != *prefix)
            return false;
        ++s;
        ++prefix;
    }
    return true;
}

FaultReaction Stricter(FaultReaction a, FaultReaction b)
{
    return (static_cast<u8>(a) > static_cast<u8>(b)) ? a : b;
}

} // namespace

const char* FaultKindName(FaultKind k)
{
    switch (k)
    {
    case FaultKind::DeviceTimeout:
        return "device-timeout";
    case FaultKind::DmaError:
        return "dma-error";
    case FaultKind::UnexpectedStatus:
        return "unexpected-status";
    case FaultKind::FirmwareLied:
        return "firmware-lied";
    case FaultKind::InternalInvariant:
        return "internal-invariant";
    case FaultKind::Hung:
        return "hung";
    case FaultKind::RetryExhausted:
        return "retry-exhausted";
    case FaultKind::KernelPageFault:
        return "kernel-page-fault";
    case FaultKind::UserPageFault:
        return "user-page-fault";
    case FaultKind::MemoryCorruption:
        return "memory-corruption";
    case FaultKind::StackCanaryFailed:
        return "stack-canary-failed";
    case FaultKind::SoftLockup:
        return "soft-lockup";
    case FaultKind::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* FaultReactionName(FaultReaction r)
{
    switch (r)
    {
    case FaultReaction::Continue:
        return "continue";
    case FaultReaction::RetryNow:
        return "retry-now";
    case FaultReaction::RestartDomain:
        return "restart-domain";
    case FaultReaction::KillProcess:
        return "kill-process";
    case FaultReaction::Halt:
        return "halt";
    }
    return "unknown";
}

FaultReaction DefaultReactionPolicy(const FaultEvidence& ev)
{
    // Conservative defaults — every entry is documented in
    // docs/knowledge/runtime-recovery-strategy.md (Class A-F).
    // Subsystems that want different behaviour register an
    // override via FaultReactSetPolicy.
    switch (ev.kind)
    {
    case FaultKind::DeviceTimeout:
    case FaultKind::DmaError:
    case FaultKind::UnexpectedStatus:
    case FaultKind::FirmwareLied:
    case FaultKind::Hung:
        return FaultReaction::RestartDomain; // Class B.
    case FaultKind::RetryExhausted:
        return FaultReaction::RestartDomain; // Class B fallback after Class D.
    case FaultKind::InternalInvariant:
    case FaultKind::SoftLockup:
        return FaultReaction::RestartDomain; // Subsystem-local; floor may upgrade to Halt.
    case FaultKind::UserPageFault:
        return FaultReaction::KillProcess; // Class C.
    case FaultKind::KernelPageFault:
    case FaultKind::MemoryCorruption:
    case FaultKind::StackCanaryFailed:
        return FaultReaction::Halt; // Class A floor anyway.
    case FaultKind::Unknown:
        return FaultReaction::Continue; // Floor still applies.
    }
    return FaultReaction::Continue;
}

FaultReaction FaultReactPolicyFloor(const FaultEvidence& ev)
{
    // Kernel-critical sources: any fault that originated inside
    // the memory manager is by definition not recoverable in
    // place — the data structures the rest of the kernel relies
    // on are suspect.
    if (StrStartsWith(ev.source, "kernel/mm") || StrStartsWith(ev.source, "mm/"))
        return FaultReaction::Halt;

    // Kernel-critical kinds — these mean the kernel's own
    // invariants are violated, no subsystem policy is allowed
    // to demote them.
    switch (ev.kind)
    {
    case FaultKind::MemoryCorruption:
    case FaultKind::StackCanaryFailed:
    case FaultKind::KernelPageFault:
        return FaultReaction::Halt;
    default:
        break;
    }

    // Severity-based floor — Critical evidence at least gets a
    // domain restart even if the policy said "Continue".
    if (ev.severity == FaultSeverity::Critical)
        return FaultReaction::RestartDomain;

    return FaultReaction::Continue;
}

void FaultReactSetPolicy(::duetos::core::FaultDomainId domain_id, FaultReactionFn fn)
{
    if (domain_id >= kPolicySlotCount)
    {
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn, "diag/fault-react",
                                     "set-policy refused: domain id out of range", static_cast<u64>(domain_id));
        return;
    }
    if (domain_id >= ::duetos::core::FaultDomainCount())
    {
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn, "diag/fault-react",
                                     "set-policy refused: domain id not registered", static_cast<u64>(domain_id));
        return;
    }
    g_policies[domain_id] = fn; // nullptr is meaningful: "revert to default"
}

FaultReactionFn FaultReactGetPolicy(::duetos::core::FaultDomainId domain_id)
{
    if (domain_id >= kPolicySlotCount)
        return &DefaultReactionPolicy;
    FaultReactionFn fn = g_policies[domain_id];
    return (fn != nullptr) ? fn : &DefaultReactionPolicy;
}

FaultReaction FaultReactDispatch(::duetos::core::FaultDomainId domain_id, const FaultEvidence& ev)
{
    ++g_dispatch_count;

    const FaultReactionFn policy = FaultReactGetPolicy(domain_id);
    const FaultReaction policy_choice = policy(ev);
    const FaultReaction floor = FaultReactPolicyFloor(ev);
    FaultReaction chosen = Stricter(policy_choice, floor);

    // RestartDomain is meaningless without an actual domain to
    // restart. Decay to Continue when the reporter didn't bind
    // a domain — the alternative would be to silently lose the
    // recovery signal, which is worse.
    if (chosen == FaultReaction::RestartDomain && domain_id == ::duetos::core::kFaultDomainInvalid)
        chosen = FaultReaction::Continue;

    if (static_cast<u32>(chosen) < 5)
        ++g_reaction_counts[static_cast<u32>(chosen)];

    switch (chosen)
    {
    case FaultReaction::Continue:
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     static_cast<u64>(domain_id));
        break;

    case FaultReaction::RetryNow:
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Info,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     static_cast<u64>(ev.attempt_count));
        break;

    case FaultReaction::RestartDomain:
        ::duetos::core::FaultDomainMarkRestart(domain_id);
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Error,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     static_cast<u64>(domain_id));
        break;

    case FaultReaction::KillProcess:
        // STUB: no ring-3 process model to kill into yet. When
        // userland lands, this branch teardown's the offending
        // process's address space + caps + fds. Until then we
        // log loudly so a real hit is obvious in the boot log.
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Error,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     ev.faulting_rip);
        break;

    case FaultReaction::Halt:
        ::duetos::core::PanicWithValue(ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                       ev.faulting_rip);
        // Never returns.
    }

    return chosen;
}

u64 FaultReactDispatchCount()
{
    return g_dispatch_count;
}

u64 FaultReactReactionCount(FaultReaction r)
{
    const u32 idx = static_cast<u32>(r);
    if (idx >= 5)
        return 0;
    return g_reaction_counts[idx];
}

// ----------------------------------------------------------------
// Self-test. Registers a toy domain, exercises permissive +
// strict policies, verifies the floor clamps kernel-critical
// kinds even when policy says "Continue".
// ----------------------------------------------------------------

namespace
{

constinit u32 g_selftest_init_calls = 0;
constinit u32 g_selftest_teardown_calls = 0;

::duetos::core::Result<void> SelfTestInit()
{
    ++g_selftest_init_calls;
    return {};
}

::duetos::core::Result<void> SelfTestTeardown()
{
    ++g_selftest_teardown_calls;
    return {};
}

FaultReaction PermissiveAlwaysContinue(const FaultEvidence&)
{
    return FaultReaction::Continue;
}

FaultReaction StrictAlwaysRestart(const FaultEvidence&)
{
    return FaultReaction::RestartDomain;
}

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    ::duetos::core::PanicWithValue("diag/fault-react", "self-test mismatch", 0);
    (void)what;
}

} // namespace

void FaultReactSelfTest()
{
    KLOG_TRACE_SCOPE("diag/fault-react", "SelfTest");

    g_selftest_init_calls = 0;
    g_selftest_teardown_calls = 0;

    const ::duetos::core::FaultDomainId id =
        ::duetos::core::FaultDomainRegister("selftest.fault-react", SelfTestInit, SelfTestTeardown);
    Expect(id != ::duetos::core::kFaultDomainInvalid, "register domain");

    const u64 dispatched_before = FaultReactDispatchCount();

    // Case 1 — strict policy + recoverable kind. Policy says
    // RestartDomain, floor says Continue (the source is a
    // selftest, not kernel/mm). Result: RestartDomain.
    FaultReactSetPolicy(id, &StrictAlwaysRestart);
    {
        FaultEvidence ev = {};
        ev.source = "selftest.fault-react";
        ev.kind = FaultKind::DeviceTimeout;
        ev.severity = FaultSeverity::Recoverable;
        const FaultReaction r = FaultReactDispatch(id, ev);
        Expect(r == FaultReaction::RestartDomain, "case1 reaction");
    }

    // Drain the deferred restart so the domain is alive again.
    ::duetos::core::FaultDomainTick();
    Expect(g_selftest_init_calls == 1, "case1 init ran");
    Expect(g_selftest_teardown_calls == 1, "case1 teardown ran");

    // Case 2 — permissive policy + recoverable kind. Policy
    // says Continue, floor says Continue. Result: Continue.
    FaultReactSetPolicy(id, &PermissiveAlwaysContinue);
    {
        FaultEvidence ev = {};
        ev.source = "selftest.fault-react";
        ev.kind = FaultKind::DeviceTimeout;
        ev.severity = FaultSeverity::Recoverable;
        const FaultReaction r = FaultReactDispatch(id, ev);
        Expect(r == FaultReaction::Continue, "case2 reaction");
    }

    // Case 3 — permissive policy + Critical severity. Floor
    // upgrades to RestartDomain even though policy said Continue.
    {
        FaultEvidence ev = {};
        ev.source = "selftest.fault-react";
        ev.kind = FaultKind::DeviceTimeout;
        ev.severity = FaultSeverity::Critical;
        const FaultReaction r = FaultReactDispatch(id, ev);
        Expect(r == FaultReaction::RestartDomain, "case3 floor upgrade");
    }
    ::duetos::core::FaultDomainTick();
    Expect(g_selftest_init_calls == 2, "case3 init ran");

    // Case 4 — clear override, default policy is in effect.
    FaultReactSetPolicy(id, nullptr);
    Expect(FaultReactGetPolicy(id) == &DefaultReactionPolicy, "case4 reverts to default");

    // Case 5 — RestartDomain decays to Continue when no domain
    // is bound. Floor still applies; Recoverable + DeviceTimeout
    // wouldn't normally be a halt.
    {
        FaultEvidence ev = {};
        ev.source = "selftest.fault-react";
        ev.kind = FaultKind::DeviceTimeout;
        ev.severity = FaultSeverity::Recoverable;
        const FaultReaction r = FaultReactDispatch(::duetos::core::kFaultDomainInvalid, ev);
        Expect(r == FaultReaction::Continue, "case5 unbound decay");
    }

    // Case 6 — counters incremented for each dispatch.
    Expect(FaultReactDispatchCount() == dispatched_before + 4, "dispatch count tally");

    // Floor-only spot checks (no execution; just the floor table).
    {
        FaultEvidence ev = {};
        ev.source = "kernel/mm/kheap";
        ev.kind = FaultKind::Unknown;
        ev.severity = FaultSeverity::Recoverable;
        Expect(FaultReactPolicyFloor(ev) == FaultReaction::Halt, "floor mm prefix -> halt");
    }
    {
        FaultEvidence ev = {};
        ev.source = "drivers/usb/xhci";
        ev.kind = FaultKind::MemoryCorruption;
        ev.severity = FaultSeverity::Recoverable;
        Expect(FaultReactPolicyFloor(ev) == FaultReaction::Halt, "floor MemoryCorruption -> halt");
    }
    {
        FaultEvidence ev = {};
        ev.source = "drivers/usb/xhci";
        ev.kind = FaultKind::DeviceTimeout;
        ev.severity = FaultSeverity::Recoverable;
        Expect(FaultReactPolicyFloor(ev) == FaultReaction::Continue, "floor recoverable -> none");
    }

    ::duetos::core::Log(::duetos::core::LogLevel::Info, "diag/fault-react",
                        "self-test PASS (4 dispatches; floor + policy + decay verified)");
}

} // namespace duetos::diag
