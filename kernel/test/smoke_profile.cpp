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

/// Sleep budget per profile, in scheduler ticks (10ms each at 100Hz).
/// Sized so spawned tasks have a window to run, print sentinels, and
/// be reaped. A profile that needs more time can bump its slot.
constexpr u64 kTicksPerSecond = 100;
u64 ProfileSleepTicks(SmokeProfile profile)
{
    switch (profile)
    {
    case SmokeProfile::None:
        return 0; // never reached — None doesn't go through the sleep path
    case SmokeProfile::Bringup:
        return kTicksPerSecond * 1; // nothing to wait for, but settle the log
    case SmokeProfile::Ring3:
        return kTicksPerSecond * 5; // 3 short ring3 tasks, ~1s each under TCG
    case SmokeProfile::PeHello:
        return kTicksPerSecond * 5; // tiny freestanding PE
    case SmokeProfile::PeWinapi:
        return kTicksPerSecond * 15; // comprehensive PE — many heap/calc/clock probes
    case SmokeProfile::PeWinkill:
        return kTicksPerSecond * 10; // real-world MSVC PE w/ DLL preload
    case SmokeProfile::Linux:
        return kTicksPerSecond * 10; // 7 Linux smokes serially
    }
    return kTicksPerSecond * 5;
}

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

    // Yield long enough for the profile's spawned tasks to run +
    // print + exit + be reaped. Sized per-profile in ProfileSleepTicks.
    const u64 ticks = ProfileSleepTicks(g_profile);
    if (ticks > 0)
    {
        sched::SchedSleepTicks(ticks);
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
