#pragma once

#include "util/types.h"

/*
 * kernel/diag/panic_wait.h
 *
 * "Wait for debugger" gate that the panic / triple-fault paths
 * consult instead of immediately calling arch::Halt(). When the
 * boot cmdline contains `panic_wait=gdb`, the kernel emits a
 * loud sentinel + INT3 instead of halting, so an attached GDB
 * stub (QEMU `-s` or the kernel's own KGDB) catches the panic
 * state interactively. After the GDB session continues, the
 * fallback HALT loop keeps the box from rebooting.
 *
 * Cost of the feature when disabled: a single byte-load on the
 * panic path — irrelevant compared to the serial-dump work
 * that already happens before this gate.
 *
 * Used by: core/panic.cpp (Panic / PanicWithValue / recursive
 * panic short-circuit), arch/x86_64/traps.cpp (triple-fault /
 * unhandled-vector terminal paths).
 */

namespace duetos::diag
{

/// Parse the boot cmdline for `panic_wait=gdb` and latch the
/// flag. Called once during boot from the cmdline-consumer in
/// kernel/core/main.cpp (or boot_bringup.cpp), AFTER
/// FindBootCmdline has cached the pointer. Idempotent. Safe to
/// call before serial is initialised — only sets a bool, no
/// I/O.
void PanicWaitInitFromCmdline(const char* cmdline);

/// True iff the panic-wait gate is armed. Read by the panic
/// paths. Always false on a default boot. Branchlessly cheap.
bool PanicWaitArmed();

/// Wait-for-debugger entry. Emits a sentinel line to the panic-
/// mode serial console, executes INT3 once so an attached GDB
/// stub gets control, then falls through into a cli/hlt loop
/// (which the user's `gdb continue` will resume out of).
///
/// NEVER returns. Safe at any interrupt level. Idempotent —
/// recursive panic short-circuits via PanicInProgress already.
[[noreturn]] void PanicWaitForDebugger();

} // namespace duetos::diag
