#include "test/smoke_profile.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "diag/boot_observe.h"
#include "diag/fix_journal.h"
#include "sched/sched.h"
#include "subsystems/translation/translate.h"

namespace duetos::test
{

namespace
{

SmokeProfile g_profile = SmokeProfile::None;
bool g_initialised = false;

// True if the boot cmdline carried `boot=desktop` — i.e. the user
// asked for the interactive GUI, not a smoke or TTY profile.
// Under an emulator we use this to gate off the Ring3 / PE smoke
// spawns that would otherwise add tens of seconds of TCG-emulated
// guest time before the desktop becomes interactive. Bare metal
// keeps the full coverage; explicit `smoke=<profile>` keeps the
// full coverage. `pe-smokes=1` on the cmdline opts the desktop
// boot back IN to running the smokes (debug / regression workflow).
bool g_desktop_boot = false;
bool g_force_pe_smokes = false;

// Debug injection: `boot-stall=smoke-tail` makes SmokeProfileSleepAndExit
// busy-spin instead of sleeping, to prove the init-wedge → structured
// STUCK + TestExit path end-to-end (see SmokeProfileInit).
bool g_stall_smoke_tail = false;

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

    // Detect `boot=desktop` and the `pe-smokes=1` opt-back-in,
    // independent of the smoke profile. The intent is "if the user
    // asked for an interactive GUI under an emulator, prioritise
    // time-to-interactive over running the regression smokes that
    // a CI job would normally invoke via smoke=<profile>".
    const char* boot_val = CmdlineFindValue(cmdline, "boot");
    if (boot_val != nullptr)
    {
        const char* end = boot_val;
        while (*end != '\0' && *end != ' ' && *end != '\t')
        {
            ++end;
        }
        if (TokenMatches(boot_val, end, "desktop"))
        {
            g_desktop_boot = true;
        }
    }
    const char* pe_val = CmdlineFindValue(cmdline, "pe-smokes");
    if (pe_val != nullptr && pe_val[0] == '1')
    {
        g_force_pe_smokes = true;
    }

    // `boot-stall=<phase>` — debug injection. Two flavours, both
    // reusing the existing cmdline helpers (no new parser):
    //   * `<phase>` (earlycon..userland): wedge that phase's
    //     BootPhaseEnter. Demonstrates ladder localisation — the log
    //     stops at `[boot] phase=<phase> begin` with no `complete`.
    //   * `smoke-tail`: spin in SmokeProfileSleepAndExit instead of
    //     sleeping. This is the watchdog proof: it is post-`sti` and
    //     the init-wedge detector is still armed (a smoke profile
    //     never reaches MarkInitComplete), so ~15 s of no serial
    //     progress trips diag::BootWatchdogOnWedge → structured STUCK
    //     + TestExit. (A plain `<phase>` can't prove the watchdog: no
    //     post-`sti` phase is reached before the smoke sentinel.)
    const char* stall_val = CmdlineFindValue(cmdline, "boot-stall");
    if (stall_val != nullptr)
    {
        const char* stall_end = stall_val;
        while (*stall_end != '\0' && *stall_end != ' ' && *stall_end != '\t')
        {
            ++stall_end;
        }
        if (TokenMatches(stall_val, stall_end, "smoke-tail"))
        {
            g_stall_smoke_tail = true;
            arch::SerialWrite("[smoke] boot-stall armed for smoke-tail\n");
        }
        else
        {
            for (u32 i = 0; i < static_cast<u32>(core::Phase::kPhaseCount); ++i)
            {
                if (TokenMatches(stall_val, stall_end, core::PhaseName(static_cast<core::Phase>(i))))
                {
                    diag::BootObserveSetStallPhase(static_cast<core::Phase>(i));
                    arch::SerialWrite("[smoke] boot-stall armed for phase=");
                    arch::SerialWrite(core::PhaseName(static_cast<core::Phase>(i)));
                    arch::SerialWrite("\n");
                    break;
                }
            }
        }
    }

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
        //
        // Additional gate: if `boot=desktop` was passed under an
        // emulator and the user did NOT opt back in via `pe-smokes=1`,
        // skip the four PE/Ring3 smokes too. The desktop boot is for
        // interactive use; the smokes would add ~30 s of TCG-emulated
        // guest time (= many minutes of wall time) before the user
        // can actually click anything. CI invokes the smokes through
        // explicit `smoke=<profile>` and is unaffected.
        const bool interactive_emu_boot = duetos::arch::IsEmulator() && g_desktop_boot && !g_force_pe_smokes;
        switch (target)
        {
        case SmokeTarget::Ring3:
        case SmokeTarget::PeHello:
        case SmokeTarget::PeWinapi:
        case SmokeTarget::PeWinkill:
            return !interactive_emu_boot;
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

    // Debug injection (boot-stall=smoke-tail): deterministically
    // exercise the structured wedge → STUCK → TestExit → harness
    // decode path. We call BootWatchdogOnWedge() directly rather than
    // recreating the byte-delta init-wedge's trigger condition: that
    // detector fires only on TOTAL serial silence, which a one-thread
    // stall can't produce here (the scheduler keeps background
    // threads — soft-lockup, fix-journal — logging every second). The
    // trigger wiring is one reviewed line at the detector's existing
    // fire point in arch/x86_64/timer.cpp; what this proves is the
    // genuinely-new surface: the STUCK line format, the EncodeExit
    // byte, arch::TestExit, and profile-boot-smoke.sh's decode.
    if (g_stall_smoke_tail)
    {
        arch::SerialWrite("[smoke] boot-stall=smoke-tail: invoking BootWatchdogOnWedge\n");
        ::duetos::diag::BootWatchdogOnWedge();
        // If not under a smoke profile, OnWedge only warns; fall
        // through to the normal sleep+sentinel so a bare run still
        // terminates cleanly.
    }

    // Log the live scheduler stats AT entry so a CI failure
    // shows what state we were in. Intentionally verbose —
    // latent uninit-state bugs manifest as silent hangs that
    // only diagnostic logs can localise (see the kmalloc
    // zero-init pattern documented in
    // wiki/tooling/Coding-Standards.md).
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

    // Fix-journal boot summary — emits per-detector tallies + total
    // record count so a CI grep can spot drift between runs without
    // pulling KERNEL.FIX off the disk image. Cheap (single ring
    // walk under the journal lock) and the lines are structured so
    // tools/qemu/run-fix-cycle.sh can pick them up alongside the
    // standard sentinel.
    ::duetos::diag::FixJournalEmitBootSummary();

    // Translator boot summary — one-line key=hexvalue snapshot of
    // native + NT translator activity for the same CI-grep pattern.
    // Cheap (a few atomic reads); useful for catching unexpected
    // miss-spikes or pathological per-call overheads between runs.
    ::duetos::subsystems::translation::TranslatorBootSummaryEmit();

    // Machine-readable boot report: one structured artifact that
    // replaces the harness's fragile multi-signature grep. Emitted
    // here so it sits right after the fix-journal / translator
    // summaries and just before the sentinel.
    ::duetos::diag::BootReportEmit();

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
