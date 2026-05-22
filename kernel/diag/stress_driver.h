#pragma once

/*
 * DuetOS — boot-time stress driver.
 *
 * Lets an operator boot the system with a `stress=` cmdline token and
 * have the kernel auto-run a CPU / memory / mixed stress test against
 * the live scheduler and heap, without needing to log in and type at
 * the shell. Same code path as the interactive `loadtest` command, but
 * driven from a dedicated kernel task spawned once the scheduler and
 * heap are online.
 *
 * Cmdline tokens (consumed by ParseAndArm):
 *   stress=cpu  | stress=mem | stress=mix | stress=spin
 *   stress-secs=<N>     — wall-clock window (default 10)
 *   stress-workers=<N>  — CPU worker count for cpu/mix (default 8)
 *   stress-mib=<N>      — MiB to allocate for mem/mix (default 32)
 *
 * The driver task emits its progress via the shell's ConsoleWrite path,
 * which is teed to serial — so a headless QEMU boot captures the full
 * transcript in its serial log. A final `[stress] done` sentinel is
 * written via SerialWrite so CI / smoke harnesses can grep for the
 * end-of-run marker without consulting the framebuffer.
 *
 * Context: kernel. Reachable only when the boot cmdline asks for it;
 * a normal boot pays nothing for the driver being compiled in.
 */

namespace duetos::core::diag
{

/// Inspect the boot cmdline; if a stress= token is present, spawn the
/// stress driver task. No-op when the token is absent. Called from
/// main.cpp once the scheduler + heap + shell are up.
void StressDriverArm(const char* cmdline);

/// Early cmdline pre-scan that only STAGES the stress mode (no task
/// spawn). Called from boot_bringup before `env::AutonomicInit` so the
/// autonomic engine sees `StressDriverArmed() == true` from its very
/// first tick. Without this pre-stage, on x86_64-debug the autonomic
/// engine fires SecurityEscalate at ~t=30s (UBSAN/red-zone audit
/// raises a kernel-integrity finding before StressDriverArm runs in
/// the bringup tail at ~t=50s), flips guard mode to Enforce, and the
/// ring3-hello-pe smoke that follows traps on the 10s default-deny
/// guard prompt — the outer wall budget then eats the stress window.
/// Idempotent: a later StressDriverArm call sees `g_cfg.mode != None`
/// and skips re-parsing.
void StressDriverStageMode(const char* cmdline);

/// True iff `StressDriverArm` (or `StressDriverStageMode`) accepted a
/// stress= token this boot. Used by the autonomic engine to suppress
/// interactive escalations (e.g. SecurityEscalate -> Enforce mode ->
/// guard prompt) that would block a headless stress run on the
/// `Allow [y] / Deny [n]` modal — same gate the smoke-profile path
/// uses. Stays false on a normal boot.
bool StressDriverArmed();

} // namespace duetos::core::diag
