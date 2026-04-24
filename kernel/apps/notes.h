#pragma once

#include "../core/types.h"
#include "../drivers/video/widget.h"

/*
 * DuetOS Notes — v0.
 *
 * The first user-facing application in the tree. A simple
 * notepad: a ring-free linear text buffer, a content-draw
 * callback the window system invokes during DesktopCompose,
 * and a keyboard-feed entry point the kbd-reader thread
 * calls when the notes window is active.
 *
 * Scope limits (v0):
 *   - Single document. No save/load — there is no persistent
 *     storage yet.
 *   - Single-line printable-ASCII input plus Enter (newline)
 *     and Backspace. No arrow-key navigation, no selection,
 *     no clipboard.
 *   - Hard buffer cap (kNotesBufCap). Inputs past the cap
 *     are dropped silently — a ring would be wrong for a
 *     notes app (oldest content is not less important than
 *     newest).
 *   - Draw path does not word-wrap mid-word. It wraps at
 *     column count derived from the window's client width.
 *
 * Context: kernel. All state mutated under CompositorLock —
 * NotesFeedChar is invoked with the lock held by kbd-reader,
 * and the draw callback is invoked under the same lock by
 * DesktopCompose. No reentrancy concerns.
 */

namespace duetos::apps::notes
{

/// Install the content-draw callback on `handle` and seed the
/// buffer with a short greeting. Called once at boot after the
/// notes window is registered.
void NotesInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the notes window, or `kWindowInvalid` until Init.
/// Used by the keyboard router to decide when to redirect keys
/// from the shell into the notes buffer.
duetos::drivers::video::WindowHandle NotesWindow();

/// Feed one character into the notes buffer. Accepts printable
/// ASCII (0x20-0x7E), newline (0x0A), and backspace (0x08).
/// Returns true iff the character was consumed — other codes
/// return false so callers can fall through to the next input
/// consumer.
///
/// MUST be called with the compositor lock held — the notes
/// buffer is read by the content-draw callback invoked from
/// DesktopCompose under the same lock.
bool NotesFeedChar(char c);

} // namespace duetos::apps::notes
