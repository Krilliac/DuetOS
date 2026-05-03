#pragma once

#include "util/types.h"

/*
 * DuetOS — Linux PSF1 / PSF2 console-font parser (clean room).
 *
 * Specs:
 *   - PSF1: a 4-byte header followed by N×glyph_bytes of raw
 *     1-bpp glyph rows. Width is always 8 px (one byte per row).
 *     Either 256 or 512 glyphs depending on a header bit.
 *     Documentation: linux/Documentation/fb/, kbd-tools README.
 *   - PSF2: an extensible header plus N glyphs of
 *     `charsize` bytes each. Width is variable (rows are
 *     ceil(width/8) bytes); height + width recorded in the
 *     header. Documentation: linux/lib/fonts/font_kbd.c
 *     header comments.
 *
 * Optional Unicode tables follow the glyph data on both formats.
 * v0 surfaces the offset + length of the Unicode region but
 * does not parse it.
 *
 * Eventual consumer: a future "console font picker" / `setfont`-
 * style userland app that lets the user load a different bitmap
 * font for the kernel shell.
 *
 * No allocation, no global state.
 */

namespace duetos::util
{

inline constexpr u32 kPsf1Magic0 = 0x36;
inline constexpr u32 kPsf1Magic1 = 0x04;
inline constexpr u32 kPsf2Magic0 = 0x72;
inline constexpr u32 kPsf2Magic1 = 0xB5;
inline constexpr u32 kPsf2Magic2 = 0x4A;
inline constexpr u32 kPsf2Magic3 = 0x86;

enum class PsfVersion : u8
{
    Psf1 = 1,
    Psf2 = 2,
};

struct PsfInfo
{
    PsfVersion version;
    u32 glyph_count;
    u32 glyph_bytes; // bytes per glyph
    u32 width_px;    // 8 for PSF1; variable for PSF2
    u32 height_px;
    u32 glyph_data_offset; // byte offset of first glyph in source
    u32 glyph_data_bytes;  // glyph_count * glyph_bytes
    u32 unicode_offset;    // byte offset of optional Unicode table (0 if none)
    u32 unicode_bytes;     // size of Unicode table (0 if none)
    bool has_unicode;
    bool ok;
};

/// Parse the PSF header at `src` (`src_len` bytes) into `out`.
PsfInfo PsfParse(const u8* src, u32 src_len);

/// Convenience: get a pointer to glyph `index` within `src`. Caller
/// has already validated `info` and `src_len`. Returns nullptr if
/// index is out of range.
const u8* PsfGlyph(const u8* src, const PsfInfo& info, u32 index);

void PsfSelfTest();

} // namespace duetos::util
