#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Terminal — windowed view of the kernel shell.
 *
 * A windowed terminal emulator that hosts a character-cell grid,
 * parses VT/ANSI escape sequences via `kernel/util/vt_parser`,
 * and mirrors the live kernel shell session by attaching to the
 * framebuffer console's mirror hook (see
 * `kernel/drivers/video/console.h`). Sister surface to the
 * framebuffer console — they show the SAME shell I/O byte-for-
 * byte, by design.
 *
 * The merge:
 *   - The framebuffer console (`kernel/drivers/video/console.cpp`)
 *     is the kernel shell's output sink. Slice 1 of the ToaruOS
 *     port built this Terminal as a windowed mirror; slice 3a
 *     completed the merge by routing keystrokes here through
 *     `ShellFeedChar` / `ShellSubmit` / `ShellHistoryPrev/Next` so
 *     this window is a fully-functional shell session.
 *   - The framebuffer console region is hidden by default once
 *     this window is up (paint toggle off, set by main.cpp).
 *     Ctrl+Alt+L (or a shell `console show` command) flips it
 *     visible again on demand for debugging.
 *
 * Cell-grid model:
 *   - Fixed-size character cells (up to kMaxCols × kMaxRows,
 *     clamped to whatever fits the window's client rect).
 *   - Each cell stores a UTF-32 codepoint plus an attribute byte.
 *   - The painter walks every cell on every compose (the
 *     compositor's WindowContentFn already only runs on
 *     repaint).
 *
 * What this slice handles:
 *   - Plain print of codepoints (UTF-8 input via the parser).
 *   - C0 controls: BS, HT, LF (with implicit CR), CR (BEL is
 *     ignored).
 *   - CSI 'H' / 'f' (CUP), 'A'/'B'/'C'/'D' (cursor motion),
 *     'J' (ED), 'K' (EL), 'm' (SGR; bold / underline / reverse).
 *   - Live mirror of shell output via
 *     `ConsoleRegisterMirror(&MirrorFromConsole)`.
 *   - Keystroke → shell input via `ShellFeedChar` /
 *     `ShellBackspace` / `ShellSubmit`. Up/Down cycle shell
 *     history.
 *
 * Out of scope (recorded in Toaru-Port-Plan, not as `// GAP:`
 * markers — no callers today):
 *   - Routing Win32 console PEs through the widget. Slice 3+.
 *   - Mouse selection / clipboard / scrollback navigation
 *     beyond what the cell grid holds.
 *   - Full SGR colour palette (monochrome v0).
 *   - ESC ( / ) charset switching, DCS, OSC 52 clipboard.
 *
 * Context: kernel. DrawFn runs under the compositor lock from
 * WindowDrawAllOrdered. Keyboard handlers are called from the
 * kernel keyboard dispatcher in core/main.cpp.
 */

namespace duetos::apps::terminal
{

/// Default grid dimensions. The widget clamps cells to whatever
/// fits the current window's client rect; these are the maxima
/// the backing store can hold.
inline constexpr duetos::u32 kMaxCols = 100;
inline constexpr duetos::u32 kMaxRows = 36;

/// Install Terminal state on `handle`. Seeds the grid from the
/// current framebuffer-console shell buffer (boot log + the most
/// recent prompt) and registers a mirror so subsequent shell
/// output is replayed here. Keystrokes routed in via
/// `TerminalFeedChar` / `TerminalFeedArrow` drive the kernel
/// shell directly (`ShellFeedChar` / `ShellBackspace` /
/// `ShellSubmit` / `ShellHistoryPrev` / `ShellHistoryNext`).
void TerminalInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Terminal window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle TerminalWindow();

/// Keyboard handlers — return true iff consumed. Mirrors the
/// (FeedChar, FeedArrow) shape used by the other in-kernel apps
/// so the dispatcher in core/main.cpp routes uniformly.
bool TerminalFeedChar(char c);
bool TerminalFeedArrow(duetos::u16 keycode);

/// Public byte-feed for future producers (kernel shell output,
/// Win32 WriteConsoleA, network shell server). Each byte goes
/// through the VT parser; printable codepoints land in the grid
/// at the current cursor and trigger a recompose by the
/// painter's next pass.
void TerminalFeedBytes(const duetos::u8* bytes, duetos::u32 len);

/// Reset the grid + cursor to a fresh state. Useful when an
/// upstream session restarts (slice-2 will call this on shell
/// re-launch). Currently exposed for the self-test only.
void TerminalReset();

/// Boot self-test. Drives the parser through the FeedBytes
/// path and verifies cursor placement + cell contents. Pure
/// compute, no I/O side effects beyond serial on failure.
void TerminalSelfTest();

} // namespace duetos::apps::terminal
