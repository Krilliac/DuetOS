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

} // namespace duetos::core::diag
