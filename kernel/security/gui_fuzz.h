#pragma once

/*
 * GUI fuzz driver — a self-driving stress harness that pumps a
 * seeded, randomised stream of keyboard + mouse events through the
 * live desktop dispatch (kbd-reader / mouse-reader in
 * kernel/core/boot_tasks.cpp) to shake out crashes in the window
 * manager, widgets, menus, calendar, console and hotkey paths.
 *
 *   - Armed only when the kernel cmdline contains `gui-fuzz` (or
 *     `gui-fuzz=<seconds>`; default 20s). Optional `gui-fuzz-seed=
 *     <n>` makes a failing run byte-for-byte reproducible.
 *   - No-op on a normal boot — a missing token costs nothing.
 *   - Waits for the login session to open (pair with `autologin=1`)
 *     before injecting, so events land on the desktop, not the
 *     login gate.
 *   - Emits `[gui-fuzz] start ...`, periodic `[gui-fuzz] t=...`
 *     progress, and a terminal `[gui-fuzz] complete iters=...`
 *     sentinel, then exits QEMU via the isa-debug-exit device so a
 *     headless run terminates deterministically. A panic / oops /
 *     triple-fault during the run is caught by the normal
 *     boot-log regression scan.
 */

namespace duetos::security
{

/// Parse the cmdline; if `gui-fuzz` is present, spawn the fuzz
/// runner task. Call AFTER the kbd-reader + mouse-reader tasks are
/// live (otherwise the injection rings have no drainer). Idempotent.
void GuiFuzzArm(const char* cmdline);

} // namespace duetos::security
