#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * DuetOS — native interactive debugger app.
 *
 * A 700x500 compositor window organised as a tab bar over the
 * existing kernel debug primitives:
 *
 *   Processes — pick a target PID (the rest of the tabs operate
 *               on this current target).
 *   Memory    — hex+ASCII viewer/editor; respects the target's
 *               address space via the `dbg_core` read/write path.
 *   Regs      — TrapFrame view + edit for the task currently
 *               suspended on the active breakpoint.
 *   Breakpoints — list + add + remove + resume + step.
 *   Watch     — up to 32 user rows polled every ~250 ms (Cheat-
 *               Engine-style live-value display).
 *   Scan      — first-pass byte-pattern scanner over a target's
 *               user regions; "next-scan" filters survivors.
 *   Disasm    — full textual disassembly via `debug::disasm`.
 *
 * The non-GUI path lives in `kernel/shell/shell_dbg.cpp` (`dbg`
 * shell command); both surfaces dispatch through the same
 * `dbg_core` helpers so they never drift.
 *
 * Context: kernel. The app runs in kernel context the same way
 * the calculator/notes/gfxdemo apps do, mediated through the
 * compositor + the per-window message queue. Cap-gating still
 * applies — read-only operations are visible without
 * `kCapDebug`, but Add-BP / Resume / Step / Memory-Write require
 * the calling shell session to hold the cap.
 */

namespace duetos::apps::dbg
{

/// Logical tab index. Stored on the app's state struct and
/// driven by mouse clicks on the tab bar / Ctrl+Tab keystrokes.
enum class Tab : u8
{
    Processes = 0,
    Memory,
    Regs,
    Breakpoints,
    Watch,
    Scan,
    Disasm,
    Count,
};

/// Register the debugger window in the compositor. Must be called
/// after the framebuffer is online and the window manager is up
/// (same constraints as `CalculatorInit`). Idempotent.
void DbgInit();

/// Handle of the debugger window, or `kWindowInvalid` until
/// `DbgInit` has run. The active-window keyboard router (in
/// `main.cpp`) compares against this to decide whether to feed
/// keystrokes here.
duetos::drivers::video::WindowHandle DbgWindow();

/// Keyboard handler. Receives one decoded character per call (the
/// same shape `NotesFeedChar` / `CalculatorFeedChar` already use).
/// Returns true iff the character was consumed (caller should
/// then skip the kernel-shell input path).
bool DbgFeedChar(char c);

/// Mouse / widget click handler. `id` is a widget ID returned by
/// `WidgetRouteMouse`; if it falls outside this app's reserved
/// ID range, this is a no-op + returns false. Returns true iff
/// the ID was claimed by the debugger.
bool DbgOnWidgetEvent(u32 id);

/// Polling tick — called by the kernel timer at ~250 ms cadence
/// to refresh the Watch tab's live values and to repaint the
/// debugger window when its current target's state has changed.
/// No-op if the window has never been registered.
void DbgTick();

/// Boot-time self-test. Runs a short integration check:
///   - Ensures `DbgInit` registered a valid window.
///   - Decodes a known disassembler fixture (delegates to
///     `disasm::SelfTest` so a single FAIL line points at the
///     decoder, not the GUI).
///   - Walks the process enumerator, asserts at least one row.
///   - Builds a small watch entry, refreshes it.
/// Emits `[smoke] dbg=ok rows=N` on success or
/// `[smoke] dbg=FAIL stage=<which>` on miss.
void DbgSelfTest();

/// Widget-ID base. Every widget the debugger registers in the
/// compositor carries `kIdBase + index` so the mouse-router can
/// identify which app to route the click to. Must not overlap
/// the calculator's `0x1000..0x100F` range.
inline constexpr u32 kIdBase = 0x2000;
inline constexpr u32 kIdCount = 64;

} // namespace duetos::apps::dbg
