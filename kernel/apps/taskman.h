#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Task Manager — v1.
 *
 * Replaces the original 7-row aggregate-stats panel with a real
 * Windows Task Manager / htop style per-task list. Each row shows
 * the task's PID, name, state, since-boot CPU%, and on-CPU tick
 * count. The header line shows the system-wide CPU%, MEM
 * MiB free / total, and live task count.
 *
 * Input (only fires when this is the active window):
 *   - ↑ / ↓               move selection up / down by one row
 *   - PgUp / PgDn         page-step the selection
 *   - Home / End          jump to first / last row
 *   - 's' / 'S'           cycle sort: CPU% → PID → NAME → STATE
 *   - 'k' / 'K' / Del     open the kill-confirm dialog for the
 *                         selected task (no-op if it's a kernel-
 *                         only task or PID 0 / 1)
 *   - 'r' / 'R'           force a snapshot rebuild on next paint
 *
 * Snapshot layout: SchedEnumerate is invoked from inside DrawFn
 * to fill a fixed-size local array. Sorting + drawing happen
 * after the enumerate returns, so the CLI window the kernel
 * holds during the walk is short and free of framebuffer work.
 *
 * Context: kernel. Mutates state under the compositor lock —
 * same discipline as the other content-drawer apps.
 */

namespace duetos::apps::taskman
{

/// Hard cap on the number of tasks the snapshot can hold. Task
/// snapshots beyond this are silently dropped from the listing
/// (the header's TASKS count still reflects the live total).
/// 128 is well above the steady-state count (~30 today) and
/// keeps the on-stack snapshot bounded at ~6 KiB.
inline constexpr duetos::u32 kMaxRows = 128;

/// Install the content-draw callback on `handle`. No other
/// state — every redraw rebuilds the snapshot from
/// `SchedEnumerate` so newly-spawned tasks appear without an
/// explicit refresh.
void TaskmanInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Task Manager window. Returned for input-routing
/// in main.cpp.
duetos::drivers::video::WindowHandle TaskmanWindow();

/// Printable-character handler. Returns true iff consumed.
bool TaskmanFeedChar(char c);

/// Non-printable key handler (arrows / Page / Home / End / Del).
/// Returns true iff consumed.
bool TaskmanFeedKey(duetos::u16 keycode);

/// Mouse-wheel handler. Positive `dz` scrolls the selection
/// toward row 0; negative steps it toward the listing tail.
void TaskmanOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Boot-time self-test. Builds a synthetic SchedTaskInfo array,
/// runs the comparator for every sort mode, and asserts the
/// resulting order. Prints PASS / FAIL to COM1.
void TaskmanSelfTest();

} // namespace duetos::apps::taskman
