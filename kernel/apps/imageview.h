#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Image Viewer — v0.
 *
 * Reads 32-bpp uncompressed BMP files (mirroring the Screenshot
 * writer's `SHOTNNNN.BMP` format) and Truevision TGA 2.0
 * uncompressed 24/32-bpp files from the FAT32 root volume, then
 * paints them in a window.
 *
 * Format support:
 *   - BMP: BITMAPFILEHEADER + 40-byte BITMAPINFOHEADER + raw BGRA
 *     rows, top-down or bottom-up. Streamed cluster-by-cluster
 *     so a 1024×768 (~3 MiB) screenshot doesn't need to fit in
 *     the kheap budget.
 *   - TGA: image type 2 (uncompressed True-color) at 24 or 32
 *     bpp, top-down or bottom-up, right-to-left bit honoured.
 *     Decoded in-memory after a full-file load (capped at 4 MiB
 *     so a malformed header can't exhaust the heap). RLE
 *     (image type 10) is deferred to a future slice — the
 *     parser currently rejects it cleanly.
 *
 * Scope:
 *   - One window, one image at a time.
 *   - Input: every `.BMP` and `.TGA` file in the FAT32 root
 *     (no subdirectory walk yet). Filenames cached at scan
 *     time; navigation steps the index, then reloads.
 *   - Display: nearest-neighbour downscale into a content-area-
 *     sized scratch buffer. No upscaling — small images render
 *     1:1 centred.
 *
 * Out of scope (explicitly):
 *   - 24/16-bpp / palette / RLE BMPs. The parser flags these
 *     and the status line shows the reason.
 *   - TGA RLE (type 10), colormapped (type 1), or grayscale
 *     (type 3). All rejected.
 *   - PNG / JPEG / GIF (each needs its own parser; would belong in
 *     its own TU, with this app dispatching).
 *   - Subdirectory walk; thumbnail strip; rotate / zoom controls.
 *
 * Input keys (when ImageView is the focused window):
 *   - 'n' / 'N' / Right     — next image
 *   - 'p' / 'P' / Left      — previous image
 *   - 'r' / 'R'             — re-scan root for new images
 *   - '+' / '=' / '-' / '_' — zoom in / out by 25 percentage points
 *   - '0'                   — reset zoom to fit-to-window + pan to 0,0
 *   - Ctrl + mouse wheel    — zoom in / out by 25 percentage points
 *   - Left / Right          — at fit-to-window: prev / next image.
 *                             Zoomed in (> 100%): pan left / right
 *   - Up / Down             — pan up / down when zoomed in (no-op
 *                             at fit-to-window)
 *
 * Zoom + pan are state on the app, NOT the window. Resizing the
 * window changes how much of the image fits on screen at 100%
 * but does NOT change the zoom factor — that's owned by the
 * '+/-/0' keys and Ctrl+wheel. Zoom is clamped to [25, 400]%.
 *
 * Context: kernel. Caller MUST hold the compositor lock — same
 * discipline as the other content-draw apps (Notes, Calculator,
 * Settings). The decode path runs on the keyboard-reader thread
 * during FeedChar; rendering runs on the compositor tick.
 */

namespace duetos::apps::imageview
{

/// Install ImageView state on `handle`. Performs the initial root-
/// directory scan, queues the first BMP (if any) for decode on the
/// next paint, and registers the content-draw callback.
void ImageViewInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the ImageView window, or `kWindowInvalid` until Init.
/// The keyboard router compares against this to know when keys
/// belong to ImageView.
duetos::drivers::video::WindowHandle ImageViewWindow();

/// Keyboard handler. Accepts the characters documented above plus
/// the four arrow-key codes (mapped to next/prev). Returns true
/// iff the key was consumed.
bool ImageViewFeedChar(char c);

/// Arrow-key handler. The keyboard reader dispatches arrows
/// separately because they're not ASCII. `keycode` is one of
/// `kKeyArrow{Left,Right,Up,Down}` (any other keycode is a no-op
/// returning false). Semantics depend on the current zoom:
///   - At fit-to-window (zoom == 100%): Left / Right step prev /
///     next image; Up / Down are no-ops.
///   - Zoomed in (zoom > 100%): all four arrows pan the visible
///     slice of the image by 32 px.
/// Returns true iff the key was consumed.
bool ImageViewFeedArrow(duetos::u16 keycode);

/// Mouse-wheel handler. Each wheel tick steps to the next /
/// previous image — wheel-down advances forward (matches the
/// "scroll through a list" mental model), wheel-up steps back.
/// v0 has no zoom state, so wheel does not zoom; a future
/// slice can add a Ctrl+wheel branch. Registered as the
/// ImageView window's WindowWheelFn at ImageViewInit time.
void ImageViewOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Re-scan the FAT32 root, find an image whose 8.3 name matches
/// `name` (case-insensitive, supports `.BMP` and `.TGA`), and
/// select it as the current image. Used by the Files app's
/// "open with ImageView" hand-off when a user hits Enter on a
/// `.BMP` or `.TGA` entry — the caller still has to raise the
/// ImageView window separately (e.g. via
/// `WindowRaise(ImageViewWindow())`). Returns true iff the file
/// was found and queued for decode on the next paint.
bool ImageViewSelectByName(const char* name);

/// Boot self-test. Synthesises a 4×4 32-bpp BMP in memory through
/// the same byte layout the Screenshot app writes, parses it via
/// the in-process header decoder, and asserts width/height/bpp
/// round-trip, plus (Pass D) the toolbar widget dispatch path.
/// Prints PASS/FAIL to COM1. SKIPped silently if FAT32 isn't
/// mounted, since the on-disk path is what production uses.
void ImageViewSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// ImageViewSelfTest() invocation ran every check (including
/// the synthetic toolbar button click) without error.
bool ImageViewSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every
/// motion packet. Edge-detects left-button press / release
/// internally and dispatches MouseMove / MouseDown / MouseUp
/// into the WidgetGroup so AppButton hover state tracks the
/// cursor on tactility themes. The image canvas band stays
/// raw paint (carve-out) — toolbar clicks are the only
/// widget-dispatched events; the canvas's wheel / keyboard
/// paths remain untouched. No-op before ImageViewInit has
/// wired a window.
void ImageViewMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

/// Currently-selected image filename, or `""` when no image is
/// loaded. The pointer references in-app storage and stays valid
/// until the next RescanRoot — callers that need to retain the
/// name must copy it. Used by the session-restore subsystem to
/// snapshot which image the user was viewing across reboot;
/// ImageViewSelectByName is the matching restore entry.
const char* ImageViewCurrentName();

} // namespace duetos::apps::imageview
