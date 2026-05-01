#pragma once

#include "util/types.h"

/*
 * Magnifier — v0 accessibility primitive.
 *
 * A 200×150-pixel inset painted at the top-right of the desktop
 * showing a 2× zoom of the 100×75-pixel region around the cursor.
 * Toggleable via Ctrl+Alt+M.
 *
 * Implementation: reads pixels straight out of the framebuffer
 * arena via FramebufferGet().virt + pitch arithmetic. Each output
 * pixel samples one source pixel (nearest-neighbour) — fast,
 * avoids the cost of a real bilinear filter, and the user's
 * intent ("read pixel-art glyphs at small sizes") is what nearest
 * neighbour preserves.
 *
 * Scope limits:
 *   - Single zoom factor (2×). Cycling through more steps is a
 *     future slice.
 *   - Fixed inset position (top-right). User-draggable inset
 *     would need a real cursor-driven drag layer.
 *   - Cursor is also magnified — the inset re-reads pixels after
 *     CursorShow paints the cursor, so the user sees their own
 *     pointer enlarged. Useful as a focus indicator.
 *
 * Context: kernel. Toggle via the keyboard router under
 * compositor lock; redraw via DesktopCompose under the same
 * lock. No state besides the bool.
 */

namespace duetos::drivers::video
{

/// Toggle the magnifier on/off. Returns the new state.
bool MagnifierToggle();

/// True iff the magnifier is currently displayed.
bool MagnifierIsActive();

/// Paint the inset over the framebuffer if active. Called by
/// DesktopCompose after the cursor is rendered. No-op when
/// inactive or when the framebuffer dimensions are too small
/// to host the inset.
void MagnifierRedraw();

/// One-shot self-test: toggles the state machine and asserts
/// state transitions match. Restores idle state before returning.
/// Prints one PASS/FAIL line to COM1.
void MagnifierSelfTest();

} // namespace duetos::drivers::video
