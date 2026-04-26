#pragma once

#include "util/types.h"

/*
 * Minimal 8x8 bitmap font — v0.
 *
 * One byte per row, 8 rows per glyph, bit 7 = leftmost pixel.
 * Glyphs are drawn in a 5x7 cell inside the 8x8 bounding box
 * (rightmost 3 columns + bottom row blank) so characters kern
 * against each other at 8-pixel cell advance without touching.
 *
 * Coverage (v0):
 *   - ASCII 0x20 (space)
 *   - Digits 0x30..0x39
 *   - Uppercase A..Z (0x41..0x5A)
 *   - Lowercase a..z aliased to uppercase at lookup time
 *   - Common punctuation: . , : ; - _ / \ ! ? ( ) [ ] < > = + * "
 *
 * Every other ASCII code renders as a filled-box placeholder so
 * unmapped characters are visible-but-clearly-unmapped. Extending
 * coverage is drop-in: add bytes to the table + index.
 *
 * Context: kernel. Font data lives in .rodata; lookup is a pure
 * table read, safe from any context.
 */

namespace duetos::drivers::video
{

constexpr u32 kGlyphWidth = 8;
constexpr u32 kGlyphHeight = 8;

/// Return a pointer to the 8-byte glyph bitmap for `ch`. Lowercase
/// ASCII letters map to their uppercase equivalents. Unmapped
/// codes return a "filled box" placeholder. Never returns nullptr.
const u8* Font8x8Lookup(char ch);

} // namespace duetos::drivers::video
