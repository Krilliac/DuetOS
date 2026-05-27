#include "diag/fault_react.h"

#include "core/panic.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "security/domain_dump.h"
#include "security/fault_domain.h"
#include "util/saturating.h"

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
constexpr u32 kPolicySlotCount = 48; // == core::kMaxFaultDomains
constinit FaultReactionFn g_policies[kPolicySlotCount] = {};

// Per-domain pending fault, written by trap handlers via
// FaultReactReportFromTrap and drained by the heartbeat thread
// via FaultReactDrainPending. The `valid` flag is the producer/
// consumer signal — write order is `kind/rip first`, `valid =
// true` last on the producer side; consumer reads `valid` first
// and only consults the rest if it was set. On x86_64 plain
// stores have release semantics within the same CPU, and the
// trap handler runs with IF=0 so a single CPU cannot observe
// its own torn write. Cross-CPU races on this slot are bounded:
// the heartbeat thread is single-threaded, so the only contender
// is a second trap on the SAME CPU before drain — handled by the
// overwrite counter.
struct PendingFault
{
    FaultKind kind;
    u64 faulting_rip;
    bool valid;
};
constinit PendingFault g_pending[kPolicySlotCount] = {};
// Lifetime tallies — saturating per class BB. Read by inspect /
// shell health; never used in modular arithmetic.
constinit util::SatU64 g_pending_overwrites = 0;

constinit util::SatU64 g_dispatch_count = 0;
constinit util::SatU64 g_reaction_counts[5] = {}; // indexed by FaultReaction

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
    case FaultKind::PoisonGuardHit:
        return "poison-guard-hit";
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
    // wiki/security/Runtime-Recovery.md (Class A-F).
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
    case FaultKind::PoisonGuardHit:
        return FaultReaction::Halt; // Catching the bug at the write site IS the point.
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
    case FaultKind::PoisonGuardHit:
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

    // KillProcess is meaningless without a Process to kill. The
    // executor below targets `CurrentProcess()` (the offending
    // user task). When current is kernel-only (boot, heartbeat
    // drain, kernel reporter), there's no valid victim — escalate
    // to Halt rather than silently dropping the request. A
    // reporter that returns KillProcess from a kernel context is
    // a category mismatch, and the kernel-owned floor errs strict.
    if (chosen == FaultReaction::KillProcess && ::duetos::core::CurrentProcess() == nullptr)
        chosen = FaultReaction::Halt;

    if (static_cast<u32>(chosen) < 5)
        ++g_reaction_counts[static_cast<u32>(chosen)];

    switch (chosen)
    {
    case FaultReaction::Continue:
    {
        // For a domain-less reporter (soft-lockup, kheap OOM,
        // sandbox-cap denial, …) the domain_id is the kFaultDomainInvalid
        // sentinel and tells the reader nothing — surface the
        // reporter's `aux` instead (TID, address, syscall #), which
        // is the actionable signal. When a real domain is bound,
        // the domain id remains the more useful identifier.
        const u64 aux_val = static_cast<u64>(ev.aux);
        const bool aux_actionable = (domain_id == ::duetos::core::kFaultDomainInvalid) && (aux_val != 0);
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     aux_actionable ? aux_val : static_cast<u64>(domain_id));
        break;
    }

    case FaultReaction::RetryNow:
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Info,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     static_cast<u64>(ev.attempt_count));
        // Journal the recovery: the dispatcher told the caller to
        // retry, which the policy + floor agreed is safe. ctx_a is
        // the FaultKind so the off-line patch generator can group by
        // failure mode; ctx_b carries the attempt_count so a flake
        // that stays under cap is distinguishable from one that
        // never converges. RetryNow is the "the workaround
        // succeeded if the caller retries" branch — pinning the
        // record on the reporter's `source` string keeps dedup
        // tight per call site.
        (void)::duetos::diag::FixJournalRecordSev(
            ::duetos::diag::FixDetector::SoftFaultRecov, ev.source != nullptr ? ev.source : "diag/fault-react",
            "fault-react: caller-retry advised; investigate the flake", static_cast<u64>(ev.kind),
            static_cast<u64>(ev.attempt_count), /*severity=*/static_cast<u16>(ev.severity));
        break;

    case FaultReaction::RestartDomain:
        ::duetos::core::FaultDomainMarkRestart(domain_id);
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Error,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     static_cast<u64>(domain_id));
        // Journal the recovery: a domain restart is the bounded
        // workaround for a per-subsystem fault. ctx_a is the
        // FaultKind, ctx_b is the domain id. Dedup on (source,
        // detector) groups repeated restarts of the same subsystem
        // into a single record with repeat_count rising, which is
        // exactly the signal that a driver is going through restart-
        // loops and needs source-level attention.
        (void)::duetos::diag::FixJournalRecordSev(
            ::duetos::diag::FixDetector::SoftFaultRecov, ev.source != nullptr ? ev.source : "diag/fault-react",
            "fault-react: domain restarted; recurrence implies bug", static_cast<u64>(ev.kind),
            static_cast<u64>(domain_id), /*severity=*/static_cast<u16>(ev.severity));
        break;

    case FaultReaction::KillProcess:
    {
        // The offending task is the current task. Trap-context
        // dispatch (UserPageFault floor / explicit user-mode
        // reporter) reaches this branch with current = the user
        // task that just trapped. The decay rule above
        // guarantees current has a Process by the time we get
        // here — kernel-only contexts escalated to Halt.
        //
        // FlagCurrentForKill sets the kill_requested flag and
        // need_resched; the next Schedule() converts it into a
        // Dead transition, the reaper drops the Process ref, the
        // address space tears down, fds + handles + caps go away
        // through ProcessRelease's existing teardown chain. The
        // dispatcher returns to its caller in the meantime — by
        // design, since the trap handler still needs to unwind
        // its own frame before the schedule fires.
        ::duetos::core::Process* victim = ::duetos::core::CurrentProcess();
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Error,
                                     ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                     victim->pid);
        ::duetos::sched::FlagCurrentForKill(::duetos::sched::KillReason::UserKill);
        // Journal the recovery: KillProcess is the bounded workaround
        // for a Class-C user-task fault. The kernel "recovered" by
        // signalling the offending task for termination — the next
        // Schedule() unwinds it through ProcessRelease and the
        // kernel keeps running. ctx_a is the FaultKind, ctx_b is the
        // victim pid. Dedup on (source, FaultKind) groups repeated
        // kills of the same caller into a single record with rising
        // repeat_count; that pattern is the signal that a user task
        // is in a kill-loop (e.g. a respawning service that hits the
        // same wild pointer every cycle). The off-line patch
        // generator's HIGH-priority bucket flags the loop.
        (void)::duetos::diag::FixJournalRecordSev(
            ::duetos::diag::FixDetector::SoftFaultRecov, ev.source != nullptr ? ev.source : "diag/fault-react",
            "fault-react: process killed; recurrence implies user-task loop", static_cast<u64>(ev.kind), victim->pid,
            /*severity=*/static_cast<u16>(ev.severity));
        break;
    }

    case FaultReaction::Halt:
        ::duetos::core::PanicWithValue(ev.source != nullptr ? ev.source : "diag/fault-react", FaultKindName(ev.kind),
                                       ev.faulting_rip);
        // Never returns.
    }

    return chosen;
}

void FaultReactReportFromTrap(::duetos::core::FaultDomainId domain_id, FaultKind kind, u64 faulting_rip)
{
    if (domain_id >= kPolicySlotCount)
    {
        // Out-of-range — silently ignored (trap-handler contract:
        // never panic from inside the handler). The lossless
        // backbone via MarkRestart is also a no-op for invalid
        // ids, so caller behaviour stays consistent with the
        // status-quo path.
        return;
    }
    if (g_pending[domain_id].valid)
    {
        // Track overwrites so an audit can tell whether the
        // single-slot model is undersized for the actual fault
        // rate. The first fault's MarkRestart already fired —
        // the bool is still set — so the restart will still
        // happen; only the kind/rip from the first fault is
        // lost.
        ++g_pending_overwrites;
    }
    // Order of writes matters for the heartbeat-side reader:
    // populate kind + rip first, set `valid` last. On x86_64
    // single-CPU all stores are release within the CPU and the
    // trap handler runs with IF=0; cross-CPU drain reads only
    // happen from the heartbeat thread which is single-threaded.
    g_pending[domain_id].kind = kind;
    g_pending[domain_id].faulting_rip = faulting_rip;
    g_pending[domain_id].valid = true;

    // Lossless backbone — even if the heartbeat drain misses a
    // slot for any reason, FaultDomainTick will still run the
    // restart from the bool.
    ::duetos::core::FaultDomainMarkRestart(domain_id);
}

void FaultReactDrainPending()
{
    const u32 dn = ::duetos::core::FaultDomainCount();
    for (u32 i = 0; i < dn; ++i)
    {
        if (!g_pending[i].valid)
            continue;

        // Snapshot + clear before dispatch, so a fault that lands
        // during the dispatch's own logging doesn't get lost or
        // silently overwritten.
        const FaultKind kind = g_pending[i].kind;
        const u64 rip = g_pending[i].faulting_rip;
        g_pending[i].valid = false;

        const auto* d = ::duetos::core::FaultDomainGet(i);
        FaultEvidence ev = {};
        ev.source = (d != nullptr && d->name != nullptr) ? d->name : "diag/fault-react";
        ev.kind = kind;
        // Trap-recorded faults are by definition kernel-side
        // recovery events; severity stays at Recoverable so the
        // floor doesn't auto-escalate beyond what the policy +
        // kind already imply.
        ev.severity = FaultSeverity::Recoverable;
        ev.attempt_count = 0;
        ev.faulting_rip = rip;
        ev.aux = 0;

        // Per-domain crash dump — non-fatal, emitted on serial
        // and into the in-kernel recent-dumps ring before the
        // dispatcher decides on a reaction. We dump unconditionally
        // for trap-recorded faults: by the time we're here the
        // domain's code has tripped a kernel-mode #PF/#GP that the
        // extable caught, and the dump is the operator's only
        // window into "what was the subsystem doing the moment
        // before it tripped." If the dispatcher subsequently
        // halts (Halt floor), the dump is already on serial; if
        // it restarts the domain, the dump is the receipt.
        ::duetos::security::DomainDumpEvidence dde = {};
        dde.kind = kind;
        dde.faulting_rip = rip;
        dde.aux = 0;
        dde.frame = nullptr;
        ::duetos::security::BeginDomainDump(i, dde);
        ::duetos::security::EndDomainDump();

        // Dispatch may panic; if it does, that's the right
        // outcome (the floor decided the kind warrants Halt).
        // Otherwise it logs + may re-call FaultDomainMarkRestart,
        // which is idempotent.
        (void)FaultReactDispatch(i, ev);
    }
}

u64 FaultReactPendingOverwriteCount()
{
    return g_pending_overwrites;
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

    // Case 7 — deferred trap path. Reset the toy domain to use
    // a permissive policy so the drain doesn't restart anything,
    // then synthesise a trap-side report and verify the drain
    // dispatches it.
    FaultReactSetPolicy(id, &PermissiveAlwaysContinue);
    const u64 before_trap_dispatch = FaultReactDispatchCount();
    FaultReactReportFromTrap(id, FaultKind::DeviceTimeout, 0xCAFE);
    Expect(g_pending[id].valid, "case7 trap-report sets pending");
    Expect(g_pending[id].faulting_rip == 0xCAFE, "case7 rip recorded");
    Expect(::duetos::core::FaultDomainGet(id)->restart_pending, "case7 lossless backbone armed");
    FaultReactDrainPending();
    Expect(!g_pending[id].valid, "case7 drain clears pending");
    Expect(FaultReactDispatchCount() == before_trap_dispatch + 1, "case7 drain dispatched once");

    // Case 8 — overwrite counter increments when a domain hits
    // twice before the heartbeat drains.
    const u64 before_overwrites = FaultReactPendingOverwriteCount();
    FaultReactReportFromTrap(id, FaultKind::DeviceTimeout, 0x1111);
    FaultReactReportFromTrap(id, FaultKind::DmaError, 0x2222);
    Expect(FaultReactPendingOverwriteCount() == before_overwrites + 1, "case8 overwrite counted");
    Expect(g_pending[id].faulting_rip == 0x2222, "case8 second write wins");
    FaultReactDrainPending(); // clean up so subsequent drains are no-ops
    // Drain the bool re-arm from the previous restart-class
    // dispatches so the toy domain is left alive for the rest
    // of boot.
    ::duetos::core::FaultDomainTick();

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

    // KillProcess policy + decay spot checks. We can't dispatch a
    // KillProcess-class evidence directly in the self-test — the
    // boot task has no Process, so the decay rule would escalate
    // to Halt and panic the boot. Instead verify the two pure
    // pieces: the default policy maps UserPageFault to KillProcess,
    // and the boot-test context has no Process (which is what the
    // decay rule keys on).
    {
        FaultEvidence ev = {};
        ev.source = "diag/fault-react/test";
        ev.kind = FaultKind::UserPageFault;
        ev.severity = FaultSeverity::Recoverable;
        Expect(DefaultReactionPolicy(ev) == FaultReaction::KillProcess, "default policy UserPageFault -> kill-process");
    }
    Expect(::duetos::core::CurrentProcess() == nullptr,
           "boot self-test runs with no current Process — decay rule would escalate to Halt");

    ::duetos::core::Log(::duetos::core::LogLevel::Info, "diag/fault-react",
                        "self-test PASS (dispatch + floor + decay + trap-defer + overwrite + kill verified)");
}

} // namespace duetos::diag
