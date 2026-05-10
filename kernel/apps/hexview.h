#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Hex Viewer — v0.
 *
 * Read-only hex / ASCII inspector for files on the FAT32 root.
 * Complements ImageView (which decodes structured formats) by
 * showing the raw bytes of anything else — boot sectors, PE
 * headers, screenshots' BMP file structure, dump files,
 * unknown-format files dropped by the operator.
 *
 * Layout per 16-byte row:
 *
 *   00000000  4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
 *   ^ offset  ^ hex bytes (group of 8 + space + group of 8)     ^ ASCII gutter
 *
 * Why classic 16-bytes-per-row + ASCII gutter — every operator
 * with an `xxd` reflex reads this layout instantly. The gutter
 * folds non-printable bytes to '.' so a row of binary still
 * paints a fixed-width line.
 *
 * Controls (when this window is focused):
 *   J / Down            — scroll down by one row (16 bytes)
 *   K / Up              — scroll up by one row
 *   PageUp / PageDown   — scroll by one page (rows-per-screen)
 *   Home                — jump to start of file
 *   End                 — jump to last page
 *   N / Right           — next file in /  (FAT32 root scan)
 *   P / Left            — previous file
 *   R                   — re-scan / reload current file
 *   G                   — jump to a hex offset typed via InputBox
 *
 * Storage: lazy-load on selection — the current file's bytes
 * are read into a single kheap buffer (capped so a malformed
 * 100 GiB file can't exhaust memory). Wheel and arrow keys
 * advance the byte offset in 16-byte (or page) steps.
 *
 * Context: kernel. DrawFn runs under the compositor lock from
 * WindowDrawAllOrdered.
 */

namespace duetos::apps::hexview
{

/// Cap on a single file's byte count. 1 MiB covers boot sectors,
/// kernel ELFs (release stripped), small dumps, ramfs assets;
/// larger files load truncated and the status line says so.
inline constexpr duetos::u32 kHexViewMaxFileBytes = 1u * 1024 * 1024;

/// Install HexView state on `handle`. Initial scan + lazy
/// decode happen on the next paint.
void HexViewInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the HexView window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle HexViewWindow();

/// Keyboard handlers — one for printable chars, one for arrow
/// / nav keys. Both return true iff consumed.
bool HexViewFeedChar(char c);
bool HexViewFeedArrow(duetos::u16 keycode);

/// Mouse-wheel handler. Each tick scrolls one row. With Ctrl
/// held, scrolls one page (16 rows).
void HexViewOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Hand-off path used by Files double-click on an unknown
/// extension — load `name` (case-insensitive) and select it
/// as current. Returns true iff the file was found and queued
/// for decode on the next paint.
bool HexViewSelectByName(const char* name);

/// Boot self-test. Round-trips the offset-format helpers and
/// the printable-byte filter; pure compute, runs unconditionally.
void HexViewSelfTest();

} // namespace duetos::apps::hexview
