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
 *     'J' (ED), 'K' (EL), 'm' (SGR; bold / underline / reverse;
 *     16-colour fg/bg via SGR 30..37 / 40..47 / 90..97 / 100..107
 *     and 38;5;N / 38;2;R;G;B consumption so trailing attrs aren't
 *     mis-parsed; 256-colour and 24-bit rendering remain deferred).
 *   - Live mirror of shell output via
 *     `ConsoleRegisterMirror(&MirrorFromConsole)`.
 *   - Keystroke → shell input via `ShellFeedChar` /
 *     `ShellBackspace` / `ShellSubmit`. Up/Down cycle shell
 *     history.
 *   - Scrollback ring (128 retired rows): PgUp / PgDn move the
 *     viewport by one screen, Home / End jump to oldest / live,
 *     wheel notches scroll one row each. Any shell input snaps
 *     back to the live viewport.
 *   - Viewport-to-clipboard copy via `TerminalCopyVisibleViewport`
 *     (Ctrl+Shift+C from the kernel keyboard dispatcher). Whatever
 *     the painter would render right now lands in the clipboard,
 *     trailing whitespace trimmed per row.
 *
 * Out of scope (recorded in Toaru-Port-Plan, not as `// GAP:`
 * markers — no callers today):
 *   - Routing Win32 console PEs through the widget. Slice 3+.
 *   - Drag-selection. The widget layer has no per-window in-content
 *     mouse-press hook yet; landing one is a kernel-wide plumbing
 *     change. The Ctrl+Shift+C "copy visible viewport" path above
 *     is the substitute until that hook exists.
 *   - 256-colour and 24-bit SGR colour rendering (params are
 *     consumed so they don't corrupt trailing SGR codes, but
 *     the cell only stores the 16-colour palette index today).
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

/// Snapshot the currently visible viewport (live grid mixed with
/// any active scrollback) into the system clipboard via
/// `WindowClipboardSetText`. Trailing whitespace per row is
/// trimmed before the row is appended; rows are joined with '\n'.
/// Bound to Ctrl+Shift+C in the kernel keyboard dispatcher — the
/// stop-gap until the widget API grows a per-window in-content
/// mouse-press hook for true drag-selection.
void TerminalCopyVisibleViewport();

/// Boot self-test. Drives the parser through the FeedBytes
/// path and verifies cursor placement + cell contents. Pure
/// compute, no I/O side effects beyond serial on failure.
void TerminalSelfTest();

} // namespace duetos::apps::terminal
