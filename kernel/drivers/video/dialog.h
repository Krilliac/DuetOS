#pragma once

#include "util/types.h"

/*
 * Modal dialog primitive — v0.
 *
 * MessageBox + InputBox without the synchronous-spin trap. The
 * dispatcher that opens a dialog is almost always running in the
 * keyboard- or mouse-reader thread; blocking those threads to
 * wait for input would deadlock the dialog itself. So the API is
 * fire-and-forget: the caller hands in a continuation callback
 * + an opaque user pointer; the kbd / mouse readers route input
 * to the active dialog; on OK / Cancel the callback fires with
 * the result and any typed text. The dialog dismisses itself.
 *
 * Single-instance: only one dialog is active at a time. A second
 * Open call while one is live cancels the new request silently
 * (returns false from the Open API). Callers that need queued
 * dialogs must serialise themselves.
 *
 * Modal painting: the active dialog draws a 50% theme-coloured
 * dim over the desktop and a centred panel on top, both painted
 * by `DialogCompose` from inside `DesktopCompose`. Mouse / kbd
 * routing in `kernel/core/main.cpp` skips its usual targets
 * while a dialog is active.
 *
 * Context: kernel. All state mutated under the compositor lock —
 * Open / FeedKey / FeedClick / Compose / Dismiss are invoked
 * with the caller already holding it (matching the Menu /
 * Notify discipline).
 */

namespace duetos::drivers::video
{

enum class DialogResult : u8
{
    Ok = 0,
    Cancel = 1,
};

/// Maximum text the user can type into an InputBox prompt
/// (NUL-included). One screen-line is plenty for v0 (rename, URL
/// edit, find-in-text); a fuller editor would need its own
/// state.
constexpr u32 kDialogInputMax = 64;

/// Continuation called when the user resolves the dialog. For
/// MessageBox: only `result` is meaningful, `text` is nullptr.
/// For InputBox: on `Ok`, `text` points at the typed string
/// (NUL-terminated, ≤ kDialogInputMax bytes). On `Cancel`,
/// `text` is nullptr.
///
/// The callback fires from the input-reader thread that
/// resolved the dialog (typically kbd-reader). It MUST NOT call
/// back into MessageBoxOpen / InputBoxOpen — re-entry is
/// detected and rejected. Anything heavier should defer via
/// SchedCreate.
using DialogResultFn = void (*)(DialogResult result, const char* text, void* user);

/// Open a Yes/No-shaped MessageBox. Returns true if the dialog
/// was registered, false if another dialog is already active.
/// The caller's `body` and `title` strings are stored by
/// reference — they MUST stay alive until `cb` fires.
/// `ok_label` / `cancel_label` override the default "OK" /
/// "CANCEL" button text. Null means use the default. The strings
/// must stay alive until `cb` fires (static literals are fine).
bool MessageBoxOpen(const char* title, const char* body, DialogResultFn cb, void* user, const char* ok_label = nullptr,
                    const char* cancel_label = nullptr);

/// Open a single-line InputBox. `default_text` (nullable)
/// pre-populates the edit field; the user can clear / edit /
/// extend it. Returns true on registration success.
bool InputBoxOpen(const char* title, const char* prompt, const char* default_text, DialogResultFn cb, void* user);

/// True iff a dialog is currently active. Mouse / kbd routers
/// consult this to redirect input.
bool DialogIsActive();

/// Feed a key-event to the active dialog. Returns true if the
/// dialog consumed the key (caller skips its normal app
/// dispatch for this event). False when no dialog is open or
/// the key is unhandled (e.g. Alt+F4 with a dialog up — the
/// caller still ignores Alt+F4 because the active-dialog
/// guard runs before the close path).
///
/// `keycode`: VK / printable ASCII. `is_release`: true on key
/// release. `modifiers`: bitmask of `kKeyMod*`.
bool DialogFeedKey(u16 keycode, bool is_release, u8 modifiers);

/// Feed a printable char (post-shift / post-modifier) to the
/// dialog's edit field. No-op for MessageBox-kind dialogs.
/// Returns true if consumed.
bool DialogFeedChar(char c);

/// Fire the callback for a dialog that a feed/press handler
/// resolved. The feed/press handlers only RECORD the resolution
/// (they run under the caller's CompositorLock); this drains it.
/// MUST be called with no global lock held — the callback may
/// take any lock (e.g. FAT32). Returns true if a callback fired.
/// Call it after CompositorUnlock on every input path that may
/// have fed a dialog.
bool DialogDrainResolved();

/// Feed a press-edge mouse click. (cx, cy) is in framebuffer
/// coords. Returns true if the click landed inside the dialog
/// (panel or its OK / Cancel buttons) — caller suppresses its
/// normal click routing in that case.
bool DialogOnPress(u32 cx, u32 cy);

/// Render the dialog (dim overlay + panel + buttons + caret)
/// into the framebuffer. Called by `DesktopCompose` after the
/// last z-ordered window paints, before the cursor sprite. No-op
/// if no dialog is active.
void DialogCompose();

/// Dismiss any active dialog without firing the callback.
/// Used by the boot reaper / fault path to clear a stuck
/// dialog. Production callers should let the user resolve
/// the dialog through OK / Cancel.
void DialogDismiss();

} // namespace duetos::drivers::video
