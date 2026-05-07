#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * DuetOS Notes — v1.
 *
 * The first user-facing application in the tree. A simple
 * notepad: a ring-free linear text buffer, a content-draw
 * callback the window system invokes during DesktopCompose,
 * and keyboard-feed entry points the kbd-reader thread calls
 * when the notes window is active.
 *
 * v1 adds a cursor model: insertion happens at a tracked
 * position, arrow keys move the cursor, Home/End jump to
 * line edges, Delete removes the char to the right of the
 * cursor. v0's append-only discipline is gone — the caret
 * is now authoritative.
 *
 * Scope limits:
 *   - Single document. Save / load round-trip lives at
 *     `NOTES.TXT` on the FAT32 root volume (Ctrl+S / Ctrl+O,
 *     wired in `kernel/core/main.cpp`); v0 has no journaling
 *     and no atomic-rename, so a power loss mid-save can
 *     truncate the file. Documented as a // GAP in
 *     notes_persist.cpp.
 *   - Printable ASCII (0x20..0x7E), Enter, Backspace, Delete,
 *     arrow keys, Home, End. No selection, no clipboard, no
 *     undo.
 *   - Hard buffer cap (kNotesBufCap). Inputs past the cap
 *     are dropped silently — a ring would be wrong for a
 *     notes app (oldest content is not less important than
 *     newest).
 *   - Draw path wraps at the column count derived from the
 *     window's client width (mid-word, no hyphenation).
 *   - Arrow Up / Down move by LOGICAL lines (delimited by
 *     '\n'), not visual wrap lines. The caller's column
 *     within the logical line is preserved when the target
 *     line is long enough, clamped otherwise.
 *
 * Context: kernel. All state mutated under CompositorLock —
 * NotesFeedChar / NotesFeedKey are invoked with the lock held
 * by kbd-reader, and the draw callback is invoked under the
 * same lock by DesktopCompose. No reentrancy concerns.
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
/// Inserts at the cursor position; Backspace deletes the char
/// immediately to the left of the cursor. Returns true iff the
/// character was consumed.
///
/// MUST be called with the compositor lock held.
bool NotesFeedChar(char c);

/// Feed a non-ASCII key (arrows, Home, End, Delete, PageUp,
/// PageDown) into the notes buffer. `keycode` is one of the
/// kKey* values from `drivers/input/ps2kbd.h`. `modifiers` is a
/// bitmask of `kKeyMod*` values: Shift extends a selection
/// range from a remembered anchor; Ctrl turns Left/Right into
/// word-wise navigation and Home/End into document-wise jumps.
/// Returns true iff the key was consumed (i.e. matched a
/// navigation binding).
///
/// MUST be called with the compositor lock held.
bool NotesFeedKey(duetos::u16 keycode, duetos::u8 modifiers = 0);

/// Undo the last text mutation. Pops the most recent frame
/// off the 16-entry undo ring, restoring buffer contents,
/// length, cursor position, and selection anchor. Returns
/// true iff an undo step was taken. No-op if the ring is
/// empty. Bound to Ctrl+Z by the kbd-reader.
bool NotesUndo();

/// True iff the live buffer has been edited since the last
/// successful Save / Load. The "discard unsaved changes?"
/// close-prompt path reads this to decide whether the second
/// Alt+F4 press needs a confirmation toast.
bool NotesIsDirty();

/// Mouse-wheel handler. `dz` is the clamped wheel-tick delta
/// (positive = scroll up). v1 maps wheel motion to cursor
/// stepping (one logical line per tick) — keeps the buffer
/// small enough for v0 (`kBufCap = 4096`) to render the cursor
/// in view without separate viewport state. Registered as the
/// Notes window's WindowWheelFn at NotesInit time.
void NotesOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Mouse double-click on the Notes window — currently a no-op
/// (Notes has no list / icon model that benefits from double-
/// click). Reserved entry point so the kernel's compositor-side
/// dispatch can fan to every native app uniformly without
/// per-app conditionals. Returns true iff the click was
/// consumed.
bool NotesOnDoubleClick(duetos::u32 cx, duetos::u32 cy);

/// Copy the entire buffer contents to the kernel clipboard
/// (`WindowClipboardSetText`). Truncates at the clipboard cap
/// — no separate selection model in v0, so "copy" always means
/// "copy everything". Returns the number of bytes published.
duetos::u32 NotesCopyToClipboard();

/// Insert the current kernel clipboard text at the cursor,
/// expanding the buffer in place. Newlines and printable ASCII
/// are accepted; anything else is dropped. Caller holds the
/// compositor lock. Returns the number of bytes inserted.
duetos::u32 NotesPasteFromClipboard();

/// Persist the current buffer to the FAT32 root volume as
/// `NOTES.TXT`. Existing content is replaced (delete-then-
/// create — non-atomic; v0 has no journaling). Returns true
/// on success. Returns false and leaves on-disk state alone if
/// no FAT32 volume is mounted.
///
/// Caller MUST hold the compositor lock — the buffer is read
/// directly without a copy.
bool NotesSave();

/// Replace the current buffer with the contents of `NOTES.TXT`
/// from the FAT32 root volume. Bytes outside printable ASCII
/// + newline are dropped (mirrors NotesPasteFromClipboard).
/// Cursor lands at end-of-buffer. Returns true on success;
/// false if there's no FAT32 volume, no NOTES.TXT, or read
/// I/O fails. The live buffer is untouched on failure.
///
/// Caller MUST hold the compositor lock.
bool NotesLoad();

/// Same as NotesLoad but reads from an arbitrary FAT32 path
/// (used by the Files app's Enter-on-`.TXT` dispatch). The
/// path is interpreted by Fat32LookupPath, so a leading '/'
/// is tolerated and the format is the 8.3-component form. On
/// success, the live buffer is replaced with the file's
/// printable bytes; on failure, the live buffer is untouched.
bool NotesLoadFile(const char* path);

/// One-shot self-test: exercises insert / backspace / delete
/// and every navigation binding on a scratch state, asserts
/// each step, then restores the pre-test buffer. Prints one
/// PASS/FAIL line to COM1. Safe to call after NotesInit.
void NotesSelfTest();

/// Round-trip self-test for NotesSave / NotesLoad. Plants a
/// known marker into a scratch buffer, saves, clears, loads,
/// and verifies the bytes match. Cleans up the test file at
/// the end. Skipped silently if no FAT32 volume is mounted or
/// if `NOTES.TXT` already exists on disk (so a real save isn't
/// trampled). Prints one PASS / FAIL / SKIP line to COM1.
void NotesPersistSelfTest();

/// Set the Find query and step to the first case-insensitive
/// match at or after the cursor. The query is stored across
/// calls so `NotesFindNext()` can step through subsequent
/// matches. On a successful find, the caret jumps to the
/// match's tail and the selection anchors at the match's head
/// so the band is visually highlighted by the existing
/// selection painter. Empty / nullptr query clears the stored
/// query and selection. Returns true iff a match was found.
///
/// MUST be called with the compositor lock held.
bool NotesFindSet(const char* query);

/// Step to the next case-insensitive match of the stored query,
/// starting one byte past the current cursor. Wraps to the
/// document head once the tail runs out (mirrors most editors'
/// "Find / find next" wrap-around behaviour). Returns true iff
/// a match was found; returns false and clears the selection
/// if no match exists or no query has been set.
///
/// MUST be called with the compositor lock held.
bool NotesFindNext();

/// Total matches of the stored query in the live buffer + the
/// 1-based ordinal of the currently-highlighted match. Either
/// pointer may be null. Returns false when no query is set or
/// no matches exist; the out-params are zeroed in that case so
/// the status footer can render a stable "—" placeholder.
///
/// MUST be called with the compositor lock held.
bool NotesFindStats(duetos::u32* total_out, duetos::u32* current_out);

/// Pointer to the stored query string (NUL-terminated, never
/// longer than `kDialogInputMax`). Returns "" when no query is
/// set so the status footer can concat unconditionally. Caller
/// must NOT mutate the returned pointer.
const char* NotesFindQuery();

/// Replace every case-insensitive occurrence of `query` in the
/// live buffer with `replacement`. Updates the cursor to the
/// position of the first replacement (or end-of-buffer if no
/// matches existed). Sets the dirty flag if any replacement
/// was made. Returns the count of substitutions performed.
///
/// `query` empty / nullptr is a no-op (returns 0). `replacement`
/// nullptr is treated as the empty string (delete-all-matches).
/// If the post-replace buffer would exceed kBufCap, replacement
/// stops at the first overflow point and the returned count
/// reflects what was actually applied.
///
/// MUST be called with the compositor lock held.
duetos::u32 NotesReplaceAll(const char* query, const char* replacement);

} // namespace duetos::apps::notes
