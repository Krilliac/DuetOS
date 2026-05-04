#pragma once

#include "util/types.h"

/*
 * DuetOS — qemu-smoke test profile dispatcher.
 *
 * Background: the original qemu-smoke job booted the entire kernel
 * (every driver init, every self-test, every Linux/Win32 PE smoke)
 * inside a single QEMU run and grepped a flat signature list out of
 * the serial log. That run had to reach Phase::Userland and the
 * full ring3-spawn chain before any required signature appeared,
 * so it took ~40s of guest time even with everything emulator-gated.
 * Under TCG / oversubscribed-KVM the runner's 30-40:1 wall:guest
 * ratio made one job take 1500s+ wall — long, fragile, and a single
 * latent hang masked every other smoke check.
 *
 * Redesign: split the smoke into independently-bootable profiles.
 * Each profile boots the kernel through the SAME bringup phase,
 * then runs ONE focused scenario, prints its sentinel, and calls
 * `arch::TestExit(0)` — which writes to QEMU's isa-debug-exit
 * device and shuts the VM down cleanly. CI runs the profiles in
 * parallel as a job matrix.
 *
 * Selection: kernel cmdline arg `smoke=<profile>`. Default (no arg
 * or `smoke=none`) is "full boot", identical to the pre-redesign
 * behavior — existing grub menu entries (boot=desktop, boot=tty)
 * stay unchanged.
 */

namespace duetos::test
{

enum class SmokeProfile : duetos::u8
{
    /// Full boot. CI matrix doesn't run this; kept for bare-metal
    /// `run.sh` invocations and dev workflows that want the whole
    /// desktop up.
    None = 0,

    /// `smoke=bringup`: boot through bringup-complete, sentinel, exit.
    Bringup,

    /// `smoke=ring3`: spawn ring3-smoke-A/B/sandbox; verify
    /// "Hello from ring 3!"; sentinel + exit.
    Ring3,

    /// `smoke=pe-hello`: spawn ring3-hello-pe (freestanding PE).
    /// Sentinel + exit.
    PeHello,

    /// `smoke=pe-winapi`: spawn ring3-hello-winapi (the comprehensive
    /// Win32 PE that prints every [vcruntime140] / [strings] / [heap]
    /// / [advapi] / [perf-counter] / [calc] / [files] / [clock] /
    /// [block] line). Sentinel + exit.
    PeWinapi,

    /// `smoke=pe-winkill`: spawn ring3-winkill (real-world MSVC PE).
    /// Verifies "pe spawn name=ring3-winkill" + std::cout output
    /// "Windows Kill ". Sentinel + exit.
    PeWinkill,

    /// `smoke=pe-sevenzip`: spawn ring3-7za (7-Zip 23.01 x64
    /// standalone — "really complicated" real-world MSVC PE,
    /// 1.29 MiB, 138 imports across KERNEL32 / msvcrt / ADVAPI32 /
    /// OLEAUT32 / USER32). Sentinel + exit.
    PeSevenZip,

    /// `smoke=pe-busybox`: spawn ring3-busybox (busybox-w32 x64,
    /// 717 KiB, 313 imports across msvcrt / KERNEL32 / WS2_32 /
    /// ADVAPI32 / USER32 — heavy POSIX-style CRT surface
    /// complementary to 7-Zip). Sentinel + exit.
    PeBusyBox,

    /// `smoke=pe-nasm`: spawn ring3-nasm (NASM 2.16.03 x64,
    /// 1.57 MiB, 117 imports against the modern UCRT apisets
    /// — `api-ms-win-crt-*` surface complementary to 7-Zip's
    /// classic msvcrt and busybox's MinGW msvcrt). Sentinel +
    /// exit.
    PeNasm,

    /// `smoke=linux`: spawn the seven Linux ABI smokes. Sentinel + exit.
    Linux,
};

/// Targets a particular spawn site can ask about. Values mirror
/// SmokeProfile but are kept conceptually separate: a "Target" is
/// what the call site is, a "Profile" is what the user asked for.
enum class SmokeTarget : duetos::u8
{
    Ring3,      // ring3-smoke-A/B/sandbox
    PeHello,    // ring3-hello-pe
    PeWinapi,   // ring3-hello-winapi
    PeWinkill,  // ring3-winkill
    PeSevenZip, // ring3-7za (7-Zip 23.01 x64 standalone)
    PeBusyBox,  // ring3-busybox (busybox-w32 x64)
    PeNasm,     // ring3-nasm (NASM 2.16.03 x64, UCRT apisets)
    PeOther,    // ring3-thread-stress, ring3-customdll-test, etc.
                //   (only enabled in profile=None bare-metal full boot)
    Linux,      // SpawnRing3LinuxSmoke and friends
};

/// Parse `smoke=<profile>` from the boot cmdline once. Returns the
/// cached value on subsequent calls.
SmokeProfile SmokeProfileInit(const char* cmdline);

/// Const-time accessor. Returns SmokeProfile::None if Init never ran.
SmokeProfile SmokeProfileGet();

/// Lower-case kebab-case name for the serial banner / sentinel.
const char* SmokeProfileName(SmokeProfile profile);

/// Predicate every spawn site queries: "should I run my scenario
/// under the active profile?" The matrix:
///   - None    -> every target runs (full bare-metal coverage)
///   - Bringup -> nothing runs (reach idle, sentinel, exit)
///   - Ring3   -> only Ring3 runs
///   - PeHello -> only PeHello runs
///   - PeWinapi -> only PeWinapi runs
///   - PeWinkill -> only PeWinkill runs
///   - Linux   -> only Linux runs
bool SmokeProfileShouldSpawn(SmokeTarget target);

/// Called from the boot tail just past the kernel-built reader
/// threads. If the profile is None, returns and the caller
/// continues into the regular boot tail (SmpStartAps,
/// Phase::Userland self-tests, idle loop). Otherwise sleeps long
/// enough for the profile-specific spawned tasks to run + print +
/// exit, prints `[smoke] profile=<name> complete`, and calls
/// `arch::TestExit(0)` — never returns in that branch.
void SmokeProfileSleepAndExit();

} // namespace duetos::test
