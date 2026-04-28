#include "test/smoke_profile.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "sched/sched.h"

namespace duetos::test
{

namespace
{

SmokeProfile g_profile = SmokeProfile::None;
bool g_initialised = false;

/// Match a `key=value` token in `cmdline`. Same semantics as
/// kernel/core/main.cpp's CmdlineMatches but the result is the
/// matched value's first character so we can dispatch by string.
/// Returns nullptr if no match.
const char* CmdlineFindValue(const char* cmdline, const char* key)
{
    if (cmdline == nullptr || key == nullptr)
    {
        return nullptr;
    }
    const char* p = cmdline;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t')
        {
            ++p;
        }
        if (*p == '\0')
        {
            break;
        }
        const char* token = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
        {
            ++p;
        }
        // [token, p) is the current token.
        const char* k = key;
        const char* t = token;
        while (*k != '\0' && t < p && *t == *k)
        {
            ++k;
            ++t;
        }
        if (*k == '\0' && t < p && *t == '=')
        {
            return t + 1;
        }
    }
    return nullptr;
}

/// strncmp-equivalent for the profile-name test below. Returns true
/// iff `text[0..len-1]` matches `expected[0..len-1]` exactly AND
/// `expected[len]` is '\0' (so we don't accept "pe-hello-foo" for
/// "pe-hello").
bool TokenMatches(const char* text, const char* end, const char* expected)
{
    while (text < end && *expected != '\0')
    {
        if (*text != *expected)
        {
            return false;
        }
        ++text;
        ++expected;
    }
    return text == end && *expected == '\0';
}

/// Per-profile *deadline* in scheduler ticks (10ms each at 100Hz).
/// SleepAndExit polls `tasks_exited` against a captured baseline
/// and exits as soon as the profile's spawned tasks have run + been
/// reaped, OR when the deadline elapses (whichever comes first).
/// The deadline only matters if the scenario hangs; in the happy
/// path we exit within milliseconds of the PE / ring3 task exit.
constexpr u64 kTicksPerSecond = 100;
u64 ProfileDeadlineTicks(SmokeProfile profile)
{
    switch (profile)
    {
    case SmokeProfile::None:
        return 0; // never reached
    case SmokeProfile::Bringup:
        return kTicksPerSecond * 1; // nothing spawned, just settle
    case SmokeProfile::Ring3:
        return kTicksPerSecond * 10; // 3 short ring3 tasks
    case SmokeProfile::PeHello:
        return kTicksPerSecond * 10; // tiny freestanding PE
    case SmokeProfile::PeWinapi:
        return kTicksPerSecond * 30; // comprehensive PE + many probes
    case SmokeProfile::PeWinkill:
        return kTicksPerSecond * 20; // real-world MSVC PE w/ DLL preload
    case SmokeProfile::Linux:
        return kTicksPerSecond * 20; // 7 Linux smokes serially
    }
    return kTicksPerSecond * 10;
}

/// How many tasks are ALWAYS live in the post-bringup steady state,
/// independent of any smoke profile spawn. Used by the polling loop
/// below: once `tasks_live` drops back to the baseline, the smoke
/// profile's spawned tasks have all exited and we can sentinel-exit.
/// The baseline counts: idle (1) + reaper (1) + kbd-reader (1) +
/// ui-ticker (1) + mouse-reader (1) + win-timer (1) + worker-A/B/C
/// (3) + the kernel-main thread (1) = ~10. Loose upper bound to
/// allow for any threads spawned during bringup we haven't tracked
/// here; the polling tolerates being ABOVE this number, only the
/// "still has spawned PE/ring3/Linux tasks" case matters.
constexpr u64 kPostBringupBaseline = 16;

} // namespace

SmokeProfile SmokeProfileInit(const char* cmdline)
{
    if (g_initialised)
    {
        return g_profile;
    }
    g_initialised = true;
    g_profile = SmokeProfile::None;

    const char* value = CmdlineFindValue(cmdline, "smoke");
    if (value == nullptr)
    {
        return g_profile;
    }
    // Find end-of-token (whitespace or NUL).
    const char* end = value;
    while (*end != '\0' && *end != ' ' && *end != '\t')
    {
        ++end;
    }
    // Each known profile name. Order doesn't matter; comparison is exact.
    if (TokenMatches(value, end, "none"))
    {
        g_profile = SmokeProfile::None;
    }
    else if (TokenMatches(value, end, "bringup"))
    {
        g_profile = SmokeProfile::Bringup;
    }
    else if (TokenMatches(value, end, "ring3"))
    {
        g_profile = SmokeProfile::Ring3;
    }
    else if (TokenMatches(value, end, "pe-hello"))
    {
        g_profile = SmokeProfile::PeHello;
    }
    else if (TokenMatches(value, end, "pe-winapi"))
    {
        g_profile = SmokeProfile::PeWinapi;
    }
    else if (TokenMatches(value, end, "pe-winkill"))
    {
        g_profile = SmokeProfile::PeWinkill;
    }
    else if (TokenMatches(value, end, "linux"))
    {
        g_profile = SmokeProfile::Linux;
    }
    // Unknown values fall through to None — full boot. Logged below.

    arch::SerialWrite("[smoke] profile=");
    arch::SerialWrite(SmokeProfileName(g_profile));
    arch::SerialWrite(" selected\n");
    return g_profile;
}

SmokeProfile SmokeProfileGet()
{
    return g_profile;
}

const char* SmokeProfileName(SmokeProfile profile)
{
    switch (profile)
    {
    case SmokeProfile::None:
        return "none";
    case SmokeProfile::Bringup:
        return "bringup";
    case SmokeProfile::Ring3:
        return "ring3";
    case SmokeProfile::PeHello:
        return "pe-hello";
    case SmokeProfile::PeWinapi:
        return "pe-winapi";
    case SmokeProfile::PeWinkill:
        return "pe-winkill";
    case SmokeProfile::Linux:
        return "linux";
    }
    return "unknown";
}

bool SmokeProfileShouldSpawn(SmokeTarget target)
{
    const SmokeProfile p = g_profile;

    if (p == SmokeProfile::Bringup)
    {
        // Nothing user-facing runs; just bringup + sentinel + exit.
        return false;
    }

    if (p == SmokeProfile::None)
    {
        // Profile=None is "no smoke harness" — full bare-metal coverage.
        // Under an emulator, default-None is the local-dev / `tools/qemu/
        // run.sh` path; the Linux ABI smokes and the four "other" PEs
        // (thread-stress, syscall-stress, customdll-test, reg-fopen-test)
        // are MMIO-emulation-heavy and slow boot to a crawl. Skip them
        // there; bare metal still runs everything.
        switch (target)
        {
        case SmokeTarget::Ring3:
        case SmokeTarget::PeHello:
        case SmokeTarget::PeWinapi:
        case SmokeTarget::PeWinkill:
            return true;
        case SmokeTarget::PeOther:
        case SmokeTarget::Linux:
            return !duetos::arch::IsEmulator();
        }
        return true;
    }

    // Specific profile selected — run only its target.
    switch (target)
    {
    case SmokeTarget::Ring3:
        return p == SmokeProfile::Ring3;
    case SmokeTarget::PeHello:
        return p == SmokeProfile::PeHello;
    case SmokeTarget::PeWinapi:
        return p == SmokeProfile::PeWinapi;
    case SmokeTarget::PeWinkill:
        return p == SmokeProfile::PeWinkill;
    case SmokeTarget::PeOther:
        return false; // never under a smoke profile
    case SmokeTarget::Linux:
        return p == SmokeProfile::Linux;
    }
    return false;
}

void SmokeProfileSleepAndExit()
{
    if (g_profile == SmokeProfile::None)
    {
        return;
    }

    const u64 deadline = ProfileDeadlineTicks(g_profile);
    if (g_profile == SmokeProfile::Bringup)
    {
        // No tasks spawned. A short settle is enough.
        if (deadline > 0)
        {
            sched::SchedSleepTicks(deadline);
        }
    }
    else
    {
        // Capture the post-spawn baseline. Each iteration sleeps
        // 10 ticks (~100ms guest), then re-reads `tasks_live`.
        // Once the count drops back to the steady-state baseline
        // (or to whatever it was BEFORE the spawn — whichever is
        // smaller), every spawned smoke task has exited and the
        // reaper has reclaimed its frames; we can sentinel + exit
        // immediately. If `tasks_live` never drops (because a
        // spawned task wedged), the deadline catches it after
        // ProfileDeadlineTicks ticks of guest time and we sentinel
        // anyway — the CI signature-grep then either passes
        // (the wedge was after the required prints landed) or
        // shows a precise MISSING-signature diagnostic.
        u64 elapsed = 0;
        constexpr u64 kPollSliceTicks = 10;
        const u64 baseline = kPostBringupBaseline;
        while (elapsed < deadline)
        {
            const u64 live = sched::SchedStatsRead().tasks_live;
            if (live <= baseline)
            {
                break;
            }
            sched::SchedSleepTicks(kPollSliceTicks);
            elapsed += kPollSliceTicks;
        }
        // One last short settle so any stragglers (the reaper
        // KFree'ing the last AS) have time to flush their final
        // log lines before we cut the serial port.
        sched::SchedSleepTicks(kPollSliceTicks);
    }

    // Sentinel that the CI script greps for. The "complete" suffix
    // is the only thing the assertion list checks under a smoke
    // profile — every other expected line came from the scenario.
    arch::SerialWrite("[smoke] profile=");
    arch::SerialWrite(SmokeProfileName(g_profile));
    arch::SerialWrite(" complete\n");

    // Hand off to QEMU's isa-debug-exit device. Equivalent to a
    // "test passed" exit; the QEMU process terminates with an
    // exit status `(0x10 << 1) | 1 = 0x21`, which the smoke
    // wrapper script treats as a successful sentinel-was-reached
    // signal. The signature-grep step then runs against the
    // captured serial log as before.
    arch::TestExit(0x10);
}

} // namespace duetos::test
