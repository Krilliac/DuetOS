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

/// Per-profile fixed sleep before sentinel, in scheduler ticks
/// (10ms each at 100Hz). The earlier polling-based approach was
/// abandoned: a SUCCESS pe-winapi run finished in 67s wall,
/// proving the framework works, but other identical configurations
/// hung for the full 480s wall budget without ever sentinelling.
/// The fixed sleep is dumb but reliable — no race window between
/// spawned-task exit accounting and the polling loop, no per-CPU
/// timing assumptions about when SchedSleepTicks wakes back up
/// versus when the spawned task gets a scheduler slice. The
/// spawned task gets a fixed window to run, then we sentinel +
/// TestExit unconditionally.
constexpr u64 kTicksPerSecond = 100;
u64 ProfileSleepTicks(SmokeProfile profile)
{
    switch (profile)
    {
    case SmokeProfile::None:
        return 0; // never reached
    case SmokeProfile::Bringup:
        return kTicksPerSecond * 1; // nothing spawned, just settle
    case SmokeProfile::Ring3:
        return kTicksPerSecond * 5; // 3 short ring3 tasks, ~1s each
    case SmokeProfile::PeHello:
        return kTicksPerSecond * 5; // tiny freestanding PE
    case SmokeProfile::PeWinapi:
        return kTicksPerSecond * 12; // comprehensive PE + many probes
    case SmokeProfile::PeWinkill:
        return kTicksPerSecond * 10; // real-world MSVC PE w/ DLL preload
    case SmokeProfile::PeSevenZip:
        return kTicksPerSecond * 30; // 1.29 MiB PE: load + reloc + 138 imports + run
    case SmokeProfile::PeBusyBox:
        return kTicksPerSecond * 30; // 717 KiB PE: load + reloc + 313 imports + run
    case SmokeProfile::PeNasm:
        return kTicksPerSecond * 30; // 1.57 MiB UCRT-based PE: load + reloc + 117 imports + run
    case SmokeProfile::Linux:
        return kTicksPerSecond * 5; // single Linux ABI smoke
    default:
        return kTicksPerSecond * 5;
    }
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
    else if (TokenMatches(value, end, "pe-sevenzip"))
    {
        g_profile = SmokeProfile::PeSevenZip;
    }
    else if (TokenMatches(value, end, "pe-busybox"))
    {
        g_profile = SmokeProfile::PeBusyBox;
    }
    else if (TokenMatches(value, end, "pe-nasm"))
    {
        g_profile = SmokeProfile::PeNasm;
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
    case SmokeProfile::PeSevenZip:
        return "pe-sevenzip";
    case SmokeProfile::PeBusyBox:
        return "pe-busybox";
    case SmokeProfile::PeNasm:
        return "pe-nasm";
    case SmokeProfile::Linux:
        return "linux";
    default:
        return "unknown";
    }
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
        case SmokeTarget::PeSevenZip:
            // 1.29 MiB load + 138 imports under TCG is ~10s extra
            // wall on default boot. Skip on emulator; bare metal runs.
            return !duetos::arch::IsEmulator();
        case SmokeTarget::PeBusyBox:
            // 717 KiB load + 313 imports — same TCG cost story as
            // 7-Zip. Bare metal runs both.
            return !duetos::arch::IsEmulator();
        case SmokeTarget::PeNasm:
            // 1.57 MiB load + 117 imports + UCRT init.
            return !duetos::arch::IsEmulator();
        case SmokeTarget::PeOther:
        case SmokeTarget::Linux:
            return !duetos::arch::IsEmulator();
        default:
            return true;
        }
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
    case SmokeTarget::PeSevenZip:
        return p == SmokeProfile::PeSevenZip;
    case SmokeTarget::PeBusyBox:
        return p == SmokeProfile::PeBusyBox;
    case SmokeTarget::PeNasm:
        return p == SmokeProfile::PeNasm;
    case SmokeTarget::PeOther:
        return false; // never under a smoke profile
    case SmokeTarget::Linux:
        return p == SmokeProfile::Linux;
    default:
        return false;
    }
}

void SmokeProfileSleepAndExit()
{
    if (g_profile == SmokeProfile::None)
    {
        return;
    }

    // Diagnostic boundary marker — confirms we reached
    // SmokeProfileSleepAndExit. Multiple historical CI failures
    // hung at the full 480s budget with no sentinel; this
    // line is the boundary marker the next-iteration analysis
    // greps for to localise "before SleepAndExit" vs
    // "inside SleepAndExit".
    arch::SerialWrite("[smoke] entered SleepAndExit profile=");
    arch::SerialWrite(SmokeProfileName(g_profile));
    arch::SerialWrite("\n");

    // Log the live scheduler stats AT entry so a CI failure
    // shows what state we were in. Intentionally verbose —
    // the .claude/knowledge/kmalloc-zero-init-pattern entry
    // documents that latent uninit-state bugs manifest as
    // silent hangs that only diagnostic logs can localise.
    {
        const auto stats = sched::SchedStatsRead();
        arch::SerialWrite("[smoke] sched stats at entry: live=");
        arch::SerialWriteHex(stats.tasks_live);
        arch::SerialWrite(" sleeping=");
        arch::SerialWriteHex(stats.tasks_sleeping);
        arch::SerialWrite(" blocked=");
        arch::SerialWriteHex(stats.tasks_blocked);
        arch::SerialWrite(" created=");
        arch::SerialWriteHex(stats.tasks_created);
        arch::SerialWrite(" exited=");
        arch::SerialWriteHex(stats.tasks_exited);
        arch::SerialWrite(" reaped=");
        arch::SerialWriteHex(stats.tasks_reaped);
        arch::SerialWrite("\n");
    }

    const u64 ticks = ProfileSleepTicks(g_profile);
    arch::SerialWrite("[smoke] sleeping ticks=");
    arch::SerialWriteHex(ticks);
    arch::SerialWrite("\n");

    // Sleep in 1-second slices and log progress between them.
    // A CI failure now shows EXACTLY how far the sleep got + the
    // current scheduler state at each second — if the kernel
    // hangs mid-sleep, the last visible log line pinpoints the
    // tick at which forward progress stopped.
    constexpr u64 kSliceTicks = 100; // 1 second guest at 100Hz
    u64 elapsed = 0;
    while (elapsed < ticks)
    {
        const u64 this_slice = (ticks - elapsed) < kSliceTicks ? (ticks - elapsed) : kSliceTicks;
        sched::SchedSleepTicks(this_slice);
        elapsed += this_slice;
        const auto stats = sched::SchedStatsRead();
        arch::SerialWrite("[smoke] tick=");
        arch::SerialWriteHex(elapsed);
        arch::SerialWrite("/");
        arch::SerialWriteHex(ticks);
        arch::SerialWrite(" live=");
        arch::SerialWriteHex(stats.tasks_live);
        arch::SerialWrite(" exited=");
        arch::SerialWriteHex(stats.tasks_exited);
        arch::SerialWrite(" ctx_sw=");
        arch::SerialWriteHex(stats.context_switches);
        arch::SerialWrite("\n");
    }

    // Sentinel that the CI script greps for. The "complete" suffix
    // is the only thing the assertion list checks under a smoke
    // profile — every other expected line came from the scenario.
    arch::SerialWrite("[smoke] profile=");
    arch::SerialWrite(SmokeProfileName(g_profile));
    arch::SerialWrite(" complete\n");

    // Hand off to QEMU's isa-debug-exit device. Writing 0x10 to
    // port 0xf4 terminates QEMU with exit status (0x10<<1)|1 = 0x21.
    // The smoke wrapper script treats QEMU's clean exit as the
    // signal that the sentinel was reached; the signature-grep
    // step then runs against the captured serial log.
    arch::SerialWrite("[smoke] calling TestExit(0x10)\n");
    arch::TestExit(0x10);
}

} // namespace duetos::test
