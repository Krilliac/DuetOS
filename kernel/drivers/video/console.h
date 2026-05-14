#pragma once

#include "util/types.h"

/*
 * Framebuffer text console — v0.
 *
 * A fixed-size character grid rendered as bitmap text. Accepts
 * stream-style writes (chars and NUL-terminated strings), handles
 * line breaks, and scrolls the oldest line off the top once the
 * bottom row is reached. Re-rendered from the stored char buffer
 * on every repaint, so layering under / over other surfaces (a
 * window dragged across the console) is a simple question of
 * draw order in DesktopCompose.
 *
 * Scope limits:
 *   - ASCII only; the font driver maps lowercase to uppercase.
 *   - No colour-per-character. One fg + one bg for the whole
 *     console. ANSI escape handling is a follow-up.
 *   - Cursor is always at the tail — no arrow-key navigation,
 *     no cursor-positioning escapes, no line editing.
 *   - Not thread-safe. Call from one task; v0 has the mouse
 *     reader + kernel_main writing, and they're coordinated by
 *     boot sequencing.
 *   - Fixed 80x40 grid. Expanding requires either heap-allocated
 *     buffer or a resize API — neither warranted until we have
 *     a use case beyond "show the boot log on screen."
 *
 * Context: kernel. Init after FramebufferInit. Draws any time
 * after that from task context.
 */

namespace duetos::drivers::video
{

constexpr u32 kConsoleCols = 80;
constexpr u32 kConsoleRows = 40;

/// Anchor the console at `(x, y)` in framebuffer pixels with the
/// given foreground + background colours. Zeros the character
/// buffer and does NOT render — callers must invoke `ConsoleRedraw`
/// (or trigger a DesktopCompose, which calls it) to paint.
void ConsoleInit(u32 x, u32 y, u32 fg, u32 bg);

/// Clear the character buffer to spaces and reset the cursor to
/// (0, 0). Does NOT repaint — pair with `ConsoleRedraw` / a
/// DesktopCompose if visible update is wanted.
void ConsoleClear();

/// Append one character at the cursor position and advance.
/// '\n' moves to the next row + column 0. '\r' moves to column 0
/// without changing row. Any other non-printable is rendered as
/// the font's placeholder box. Scrolls the contents one row up
/// if the cursor would advance past the bottom.
///
/// Does NOT repaint — callers either batch into a single redraw
/// or trigger DesktopCompose on a cadence that suits them.
void ConsoleWriteChar(char c);

/// Stream a NUL-terminated string via repeated WriteChar. Returns
/// nothing; silently no-ops on nullptr.
void ConsoleWrite(const char* s);

/// Stream a string followed by a newline.
void ConsoleWriteln(const char* s);

/// Fill the console's bounding rect with the bg colour, then draw
/// every character in the buffer. Safe to call repeatedly; called
/// from DesktopCompose so the console survives window-drag redraws.
void ConsoleRedraw();

/// Re-anchor the console to a new framebuffer origin. Useful for
/// switching between "docked" desktop mode (compact, inside the
/// window stack) and "fullscreen" TTY mode (top-left of the
/// surface). Does NOT clear the char buffer — the scrollback
/// persists across mode flips.
void ConsoleSetOrigin(u32 x, u32 y);

/// Replace the foreground / background colours. Takes effect on
/// the next ConsoleRedraw.
void ConsoleSetColours(u32 fg, u32 bg);

// ---------------------------------------------------------------
// Multi-console routing — v0 has two buffers:
//   - Shell console (the interactive prompt, output, scrollback).
//   - Klog console (kernel log-line tee target, read-only view).
// Both share the same origin + geometry; `ConsoleRedraw` paints
// whichever is currently selected. Ctrl+Alt+F1 selects the shell,
// Ctrl+Alt+F2 selects klog. Writes to ConsoleWrite / ConsoleWriteChar
// / ConsoleClear always target the shell regardless of the render
// target; ConsoleWriteKlog targets the klog buffer.
// ---------------------------------------------------------------

/// Forward a string to the klog console's buffer. Primary
/// consumer is the klog tee registered from main.cpp.
void ConsoleWriteKlog(const char* s);

/// Render-target selectors. The console module picks which
/// buffer ConsoleRedraw paints; neither the shell nor the klog
/// tee pays attention — their writes go where they go.
void ConsoleSelectShell();
void ConsoleSelectKlog();

/// True iff the klog buffer is currently selected for render.
bool ConsoleIsKlogActive();

// ---------------------------------------------------------------
// Capture mode — divert shell-console writes into a buffer
// instead of the scrollback. Used by the shell's pipe machinery:
// during `A | B`, segment A's output is captured, then fed back
// as a path argument to B. Klog writes are unaffected.
// ---------------------------------------------------------------

/// Begin capturing subsequent shell-console writes into `buf`
/// (capped at `cap` bytes), writing the running count into
/// `*len_out`. Overflow silently drops the excess. Safe to
/// nest conceptually only by re-entering after End — there's
/// one global slot.
void ConsoleBeginCapture(char* buf, u32 cap, u32* len_out);

/// End capture — subsequent shell-console writes go back to
/// the scrollback.
void ConsoleEndCapture();

/// Toggle COM1 mirroring of the shell console. When on, every
/// byte the shell writes to its scrollback also goes out the
/// 16550 — a host terminal connected via QEMU's `-serial stdio`
/// then sees the shell's responses (otherwise the framebuffer
/// is the only sink and `-display none` makes it invisible).
/// Idempotent; safe to call before or after the framebuffer is
/// online. The serial-input pump (core/serial_input.cpp) flips
/// this on at startup.
void ConsoleEnableSerialMirror(bool on);

// ---------------------------------------------------------------
// Paint toggle — when off, `ConsoleRedraw` is a no-op so the
// console's 80x40 region is reclaimed for the desktop. The
// character buffer keeps receiving writes regardless; any
// registered mirror (see below) still fires. Default = on, so
// boot-time logging shows up on the framebuffer until a later
// boot phase explicitly toggles it.
// ---------------------------------------------------------------

void ConsoleSetPaintEnabled(bool enabled);
bool ConsoleIsPaintEnabled();

// ---------------------------------------------------------------
// Mirror hook — invoked for every character written to the SHELL
// buffer (not the klog buffer). Lets a windowed terminal app
// duplicate the kernel shell's I/O without parsing the existing
// 80x40 grid. The callback runs synchronously inside
// `ConsoleWriteChar`/`ConsoleWrite`/`ConsoleWriteln`; it must not
// re-enter the console module. Registering nullptr clears the
// mirror.
// ---------------------------------------------------------------

using ConsoleMirrorFn = void (*)(char c);
void ConsoleRegisterMirror(ConsoleMirrorFn fn);

// ---------------------------------------------------------------
// Read-only access to the SHELL buffer's last contents. Used by
// the windowed Terminal app to populate its grid with whatever
// kernel boot output the user missed before opening the window.
// The buffer is a fixed (rows × cols) ASCII grid; entries are
// space (0x20) where nothing has been written. Callers that want
// to consume the buffer one cell at a time use the row/col
// accessors below.
// ---------------------------------------------------------------

char ConsoleShellCharAt(u32 row, u32 col);
u32 ConsoleShellCursorRow();
u32 ConsoleShellCursorCol();

} // namespace duetos::drivers::video
