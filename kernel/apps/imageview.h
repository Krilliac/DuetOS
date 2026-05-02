#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Image Viewer — v0.
 *
 * Reads 32-bpp uncompressed BMP files from the FAT32 root volume
 * and paints them in a window. The format choice mirrors what the
 * Screenshot app already writes: every Ctrl+Alt+P capture lands as
 * a `SHOTNNNN.BMP` whose layout this viewer accepts byte-for-byte
 * (BITMAPFILEHEADER + 40-byte BITMAPINFOHEADER + raw BGRA rows,
 * top-down DIB height supported, also bottom-up via positive
 * height).
 *
 * Scope:
 *   - One window, one image at a time.
 *   - Input: the BMP files in the FAT32 root (no subdirectory walk
 *     yet). Filenames cached at scan time; navigation steps the
 *     index, then reloads.
 *   - Decoding: uses Fat32ReadFileStream to walk clusters without
 *     buffering the whole file (a 1024×768 screenshot is ~3 MiB,
 *     larger than the kernel heap budget).
 *   - Display: nearest-neighbour downscale into a content-area-sized
 *     scratch buffer. No upscaling — small images render 1:1
 *     centred.
 *
 * Out of scope (explicitly):
 *   - 24-bpp / 16-bpp / palette / RLE BMPs. The selftest emits a
 *     classification line for each unsupported subformat so future
 *     slices know what to add.
 *   - PNG / JPEG / GIF (each needs its own parser; would belong in
 *     its own TU, with this app dispatching).
 *   - Subdirectory walk; thumbnail strip; rotate / zoom controls.
 *
 * Input keys (when ImageView is the focused window):
 *   - 'n' / 'N' / Right     — next image
 *   - 'p' / 'P' / Left      — previous image
 *   - 'r' / 'R'             — re-scan root for new BMPs
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
/// separately because they're not ASCII. Returns true iff
/// consumed (i.e. we have at least one image to navigate).
bool ImageViewFeedArrow(bool left);

/// Boot self-test. Synthesises a 4×4 32-bpp BMP in memory through
/// the same byte layout the Screenshot app writes, parses it via
/// the in-process header decoder, and asserts width/height/bpp
/// round-trip. Prints PASS/FAIL to COM1. SKIPped silently if
/// FAT32 isn't mounted, since the on-disk path is what production
/// uses.
void ImageViewSelfTest();

} // namespace duetos::apps::imageview
