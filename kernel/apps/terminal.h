#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Terminal — v0.
 *
 * A windowed terminal emulator that hosts a fixed-cell character
 * grid, parses a useful subset of VT/ANSI escape sequences via
 * `kernel/util/vt_parser`, and renders the grid into the active
 * compositor window. Sister to the kernel's framebuffer console
 * (`kernel/drivers/video/console.cpp`), which is the boot-time
 * single-instance text surface this widget cannot displace —
 * but unlike that surface, the terminal lives inside a normal
 * window managed by `kernel/drivers/video/widget`.
 *
 * Why this exists:
 *   - The kernel shell prints to the framebuffer console
 *     directly. Operators who want to run shell commands without
 *     dropping out of the windowed desktop currently cannot. A
 *     windowed terminal fixes that, even before the shell is
 *     plumbed through an output abstraction (separate slice).
 *   - PE binaries that call WriteConsoleA / WriteConsoleW
 *     currently log to the boot serial. A future slice will
 *     route those into a Terminal window so console-mode Win32
 *     programs show up on the desktop.
 *
 * Cell-grid model:
 *   - Fixed (cols × rows) character cells; each cell stores a
 *     UTF-32 codepoint plus an inverted-attribute bit.
 *   - The grid is double-buffered as one contiguous array; the
 *     parser writes to a cursor position, the painter walks
 *     every cell on every compose. No dirty tracking in v0 —
 *     the compositor's WindowContentFn already runs only on
 *     repaint requests.
 *
 * What slice 1 handles:
 *   - Plain print of codepoints (UTF-8 input via the parser).
 *   - C0 controls: BEL ignored, BS, HT, LF (with implicit CR
 *     for sanity), CR.
 *   - CSI 'H' / 'f' (CUP — cursor position), 'A'/'B'/'C'/'D'
 *     (cursor up/down/right/left), 'J' (ED), 'K' (EL), 'm' (SGR;
 *     bold / underline / reverse — colour palette deliberately
 *     deferred since the compositor uses theme colours).
 *   - Demo loop: keys typed into the focused window echo into
 *     the grid (with a leading prompt). This proves the round-
 *     trip without requiring shell-integration plumbing.
 *
 * Out of scope for slice 1 (recorded in Toaru-Port-Plan):
 *   - Hosting the kernel shell (refactor of ~20k LoC of
 *     ConsoleWrite* calls is its own slice).
 *   - Routing Win32 console PEs through the widget.
 *   - Mouse selection / clipboard / scrollback navigation.
 *   - Full SGR colour palette (we ship monochrome v0).
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

/// Install Terminal state on `handle`. Initial paint shows a
/// banner + prompt. Subsequent input flows through FeedChar /
/// FeedArrow.
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
