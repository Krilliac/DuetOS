/*
 * DuetOS — policy engine: implementation.
 *
 * One spinlock-protected snapshot of the resolved per-subsystem
 * modes + a small constexpr table of "what does each profile
 * map each subsystem to?" Apply walks the table, calls each
 * subsystem's setter, and records the outcome.
 */

#include "security/policy.h"

#include "arch/x86_64/serial.h"
#include "security/event_ring.h"
#include "sync/spinlock.h"
#include "time/timekeeper.h"

namespace duetos::security
{

namespace
{

struct ProfileTable
{
    PolicyProfile profile;
    Mode guard;
    PersistenceMode persistence;
    drivers::storage::WriteGuardMode write_guard;
};

// Default has no static target — it's a snapshot of whatever each
// subsystem chose at boot, captured in PolicyInit. Listing the
// other three profiles here keeps PolicyResolve cheap.
constexpr ProfileTable kProfiles[] = {
    {PolicyProfile::Lab, Mode::Advisory, PersistenceMode::Advisory, drivers::storage::WriteGuardMode::Advisory},
    {PolicyProfile::Production, Mode::Enforce, PersistenceMode::Deny, drivers::storage::WriteGuardMode::Deny},
    {PolicyProfile::Forensic, Mode::Enforce, PersistenceMode::Deny, drivers::storage::WriteGuardMode::Deny},
};

constexpr u32 kProfileCount = sizeof(kProfiles) / sizeof(kProfiles[0]);

constinit sync::SpinLock g_lock{};
constinit PolicySnapshot g_snapshot{};

const char* const kProfileNames[] = {
    "Default",
    "Lab",
    "Production",
    "Forensic",
};

static_assert(sizeof(kProfileNames) / sizeof(kProfileNames[0]) == static_cast<u32>(PolicyProfile::Count),
              "PolicyProfile name table out of sync");

PolicySnapshot SampleCurrentSubsystems(PolicyProfile profile, u32 actor_pid)
{
    PolicySnapshot s{};
    s.profile = profile;
    s.guard_mode = GuardMode();
    s.persistence_mode = PersistenceModeRead();
    s.write_guard_mode = drivers::storage::BlockWriteGuardMode();
    s.applied_at_uptime_ns = time::MonotonicNs();
    s.applied_by_pid = actor_pid;
    return s;
}

} // namespace

const char* PolicyProfileName(PolicyProfile p)
{
    const u32 i = static_cast<u32>(p);
    if (i >= static_cast<u32>(PolicyProfile::Count))
    {
        return "<bad>";
    }
    return kProfileNames[i];
}

PolicySnapshot PolicyResolve(PolicyProfile profile)
{
    if (profile == PolicyProfile::Default)
    {
        // Default is "whatever each subsystem chose for itself";
        // the resolved view is the live sample.
        return SampleCurrentSubsystems(PolicyProfile::Default, 0);
    }
    for (u32 i = 0; i < kProfileCount; ++i)
    {
        if (kProfiles[i].profile != profile)
        {
            continue;
        }
        PolicySnapshot s{};
        s.profile = profile;
        s.guard_mode = kProfiles[i].guard;
        s.persistence_mode = kProfiles[i].persistence;
        s.write_guard_mode = kProfiles[i].write_guard;
        s.applied_at_uptime_ns = 0;
        s.applied_by_pid = 0;
        return s;
    }
    // Unknown profile — fall back to current.
    return SampleCurrentSubsystems(PolicyProfile::Default, 0);
}

PolicySnapshot PolicyCurrent()
{
    sync::SpinLockGuard guard{g_lock};
    return g_snapshot;
}

PolicyProfile PolicyCurrentProfileHint()
{
    sync::SpinLockGuard guard{g_lock};
    return g_snapshot.profile;
}

void PolicyInit()
{
    PolicySnapshot s = SampleCurrentSubsystems(PolicyProfile::Default, 0);
    {
        sync::SpinLockGuard guard{g_lock};
        g_snapshot = s;
    }
    arch::SerialWrite("[policy] init profile=Default guard=");
    arch::SerialWrite(GuardModeName(s.guard_mode));
    arch::SerialWrite("\n");
}

void PolicySet(PolicyProfile profile, u32 actor_pid)
{
    PolicySnapshot before;
    {
        sync::SpinLockGuard guard{g_lock};
        before = g_snapshot;
    }

    if (profile == PolicyProfile::Default)
    {
        // Default-as-snapshot just re-reads the live state and
        // doesn't drive any subsystem. This makes "policy set
        // default" a way to forget the profile name without
        // perturbing modes.
        PolicySnapshot s = SampleCurrentSubsystems(PolicyProfile::Default, actor_pid);
        {
            sync::SpinLockGuard guard{g_lock};
            g_snapshot = s;
        }
        EventRingPublishKind(EventKind::PolicyChanged, actor_pid, static_cast<u64>(profile),
                             static_cast<u64>(before.profile), "Default");
        arch::SerialWrite("[policy] set Default (snapshot of current subsystems)\n");
        return;
    }

    PolicySnapshot target = PolicyResolve(profile);

    if (target.guard_mode != before.guard_mode)
    {
        SetGuardMode(target.guard_mode);
        EventRingPublishKind(EventKind::GuardModeChanged, actor_pid, static_cast<u64>(target.guard_mode),
                             static_cast<u64>(before.guard_mode), GuardModeName(target.guard_mode));
    }
    if (target.persistence_mode != before.persistence_mode)
    {
        PersistenceSetMode(target.persistence_mode);
        EventRingPublishKind(EventKind::PersistenceModeChanged, actor_pid, static_cast<u64>(target.persistence_mode),
                             static_cast<u64>(before.persistence_mode),
                             target.persistence_mode == PersistenceMode::Deny ? "Deny" : "Advisory");
    }
    if (target.write_guard_mode != before.write_guard_mode)
    {
        drivers::storage::BlockWriteGuardSetMode(target.write_guard_mode);
        const char* tag = target.write_guard_mode == drivers::storage::WriteGuardMode::Deny       ? "Deny"
                          : target.write_guard_mode == drivers::storage::WriteGuardMode::Advisory ? "Advisory"
                                                                                                  : "Off";
        EventRingPublishKind(EventKind::BlockguardModeChanged, actor_pid, static_cast<u64>(target.write_guard_mode),
                             static_cast<u64>(before.write_guard_mode), tag);
    }

    PolicySnapshot s = SampleCurrentSubsystems(profile, actor_pid);
    {
        sync::SpinLockGuard guard{g_lock};
        g_snapshot = s;
    }

    EventRingPublishKind(EventKind::PolicyChanged, actor_pid, static_cast<u64>(profile),
                         static_cast<u64>(before.profile), PolicyProfileName(profile));

    arch::SerialWrite("[policy] set ");
    arch::SerialWrite(PolicyProfileName(profile));
    arch::SerialWrite(" — guard=");
    arch::SerialWrite(GuardModeName(s.guard_mode));
    arch::SerialWrite(" persistence=");
    arch::SerialWrite(s.persistence_mode == PersistenceMode::Deny ? "Deny" : "Advisory");
    arch::SerialWrite(" blockguard=");
    arch::SerialWrite(s.write_guard_mode == drivers::storage::WriteGuardMode::Deny       ? "Deny"
                      : s.write_guard_mode == drivers::storage::WriteGuardMode::Advisory ? "Advisory"
                                                                                         : "Off");
    arch::SerialWrite("\n");
}

namespace
{

bool MatchesTarget(const PolicySnapshot& got, const PolicySnapshot& want)
{
    return got.guard_mode == want.guard_mode && got.persistence_mode == want.persistence_mode &&
           got.write_guard_mode == want.write_guard_mode;
}

} // namespace

void PolicySelfTest()
{
    const PolicySnapshot original = PolicyCurrent();
    bool ok = true;

    const PolicyProfile to_test[] = {PolicyProfile::Lab, PolicyProfile::Production, PolicyProfile::Forensic};
    for (PolicyProfile p : to_test)
    {
        PolicySet(p, 0);
        const PolicySnapshot after = PolicyCurrent();
        const PolicySnapshot want = PolicyResolve(p);
        if (!MatchesTarget(after, want) || after.profile != p)
        {
            arch::SerialWrite("[policy] self-test FAIL on profile=");
            arch::SerialWrite(PolicyProfileName(p));
            arch::SerialWrite("\n");
            ok = false;
        }
    }

    // Restore: explicitly drive each subsystem back to original
    // values, then snapshot Default.
    SetGuardMode(original.guard_mode);
    PersistenceSetMode(original.persistence_mode);
    drivers::storage::BlockWriteGuardSetMode(original.write_guard_mode);
    PolicySet(PolicyProfile::Default, 0);

    arch::SerialWrite(ok ? "[policy] self-test PASS\n" : "[policy] self-test FAIL\n");
}

} // namespace duetos::security
