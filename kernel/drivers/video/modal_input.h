#pragma once

#include "drivers/video/cursor.h"
#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * Modal-input infrastructure — v0.
 *
 * A general-purpose "captured-cursor" mode for gestures that
 * need to follow the cursor across multiple frames without
 * an active mouse button: window Move (one-shot click-to-place),
 * window Size, future eye-dropper / measure tools.
 *
 * Distinct from the existing `WindowSetCapture` (which routes
 * all mouse events to a captured window via the Win32 surface)
 * — this one captures gestural intent. Only one modal-input
 * session is live at a time. While live:
 *   - mouse motion calls the registered `MotionFn`
 *   - mouse press / release fires `CommitFn`
 *   - keyboard Esc fires `CancelFn`
 *
 * The mouse / kbd readers in main.cpp consult `ModalInputIsActive()`
 * before their normal routing and skip every other branch when
 * it returns true.
 *
 * Context: kernel. Mutated under the compositor lock.
 */

namespace duetos::drivers::video
{

using ModalMotionFn = void (*)(u32 cx, u32 cy, void* user);
using ModalCommitFn = void (*)(u32 cx, u32 cy, void* user);
using ModalCancelFn = void (*)(void* user);

struct ModalInputCallbacks
{
    ModalMotionFn motion;
    ModalCommitFn commit;
    ModalCancelFn cancel;
    void* user;
    // Cursor shape held while modal-input is live. The mouse
    // loop's normal hit-test is suspended; the caller picks
    // (e.g. ResizeNS for vertical Size, Hand for Move).
    CursorShape cursor;
};

/// Begin a modal-input session. Returns false if one is
/// already live. The compositor switches to `cb.cursor` and
/// suspends the regular hit-test until the session ends.
bool ModalInputBegin(const ModalInputCallbacks& cb);

/// True iff a session is live.
bool ModalInputIsActive();

/// Mouse-motion hook. The mouse loop calls this every packet
/// while a session is live.
void ModalInputOnMotion(u32 cx, u32 cy);

/// Mouse press / release hook. v1 commits on press_edge;
/// release_edge is ignored (Move semantics: one click places
/// the window). Future Size mode could commit on release.
void ModalInputOnPress(u32 cx, u32 cy);

/// Keyboard Esc hook. Cancels the session without committing.
void ModalInputOnCancel();

} // namespace duetos::drivers::video
