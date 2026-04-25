#pragma once

/*
 * DuetOS Win32 subsystem — ntdll bedrock-coverage scoreboard.
 *
 * One-shot boot-log helper that walks the auto-generated tables
 * in `nt_syscall_table_generated.h` and prints how many of the
 * universal NT API calls DuetOS routes to internal SYS_*. Lets
 * the boot log act as a regression detector — if a future
 * refactor breaks a SYS_* used in the mapping, the count drops
 * and the change is visible.
 */

namespace duetos::win32
{

/// Emit a one-line "ntdll bedrock coverage: N/M (P%)" boot log
/// using the auto-generated table in
/// `subsystems/win32/nt_syscall_table_generated.h`. Lets the boot
/// log tell us, at a glance, how much of the universal NT API
/// surface DuetOS can route to internal SYS_* numbers — the
/// scoreboard for any future ntdll shim. Called once from
/// `kernel_main` after the Win32 stubs page is built.
void Win32LogNtCoverage();

} // namespace duetos::win32
