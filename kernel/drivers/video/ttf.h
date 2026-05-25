#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — TrueType / OpenType font parser, v0.
 *
 * Bounded reader over an in-memory font file. Parses the sfnt table
 * directory, the subset of tables needed to look up a Unicode
 * codepoint, retrieve its advance metric, and walk its outline:
 *
 *   - `head` — units per em + index_to_loc_format (loca offset width)
 *   - `maxp` — glyph count
 *   - `hhea` — number of HMetrics in `hmtx`
 *   - `hmtx` — per-glyph advance + lsb
 *   - `cmap` — char→glyph index (format 4, BMP coverage, the universal
 *     baseline format every TrueType / OpenType font ships)
 *   - `loca` — glyph offset table (16- or 32-bit per index_to_loc_format)
 *   - `glyf` — glyph outline data (TrueType-flavour fonts)
 *
 * Scope limits intentional to v0:
 *   - Composite glyphs (`number_of_contours < 0`) decode the glyph
 *     header but the outline is reported as "compound — needs
 *     decomposition" via `Result::ErrorCode::NotImplemented`. The
 *     rasterizer's first cut handles only simple glyphs.
 *   - cmap formats 0, 6, 12, 14 are not parsed. Format 4 covers the
 *     Basic Multilingual Plane, which is everything the chrome paint
 *     path needs for a slate / amber / Duet build.
 *   - OpenType CFF outlines (`CFF` / `CFF2` table) are out of scope —
 *     this parser reads `glyf`-flavour fonts only. CFF would need a
 *     separate Type-2 charstring decoder.
 *   - No kerning (`kern` / `GPOS`). Advance comes from `hmtx` only.
 *   - No name-table parsing. Fonts are identified by their bytes,
 *     not by metadata.
 *
 * Memory model: the parser keeps a span pointer + length to the input
 * bytes; returned `TtfGlyph` structs reference contour data inside
 * the original buffer. The font bytes must outlive the `TtfFont`
 * handle. The parser itself does NOT allocate.
 *
 * Context: kernel. Init runs once after the font bytes are mapped
 * into the kernel address space (typically a `.rodata` byte array
 * embedded in the kernel image, or a ramfs file mapped into kernel
 * VA). All ops are read-only and IRQ-safe in principle (no locks),
 * but the rasterizer that consumes the parser output is not — see
 * `ttf_raster.h`.
 */

namespace duetos::drivers::video
{

/// One contour point as decoded from `glyf`. Coordinates are in font
/// design units; the rasterizer scales to pixels via `units_per_em`.
struct TtfPoint
{
    i16 x;
    i16 y;
    bool on_curve; // true = endpoint, false = quadratic Bezier control
};

/// One simple-glyph outline. `endpoints[i]` is the index into
/// `points[]` of the LAST point of contour i; the FIRST point of
/// contour i is `endpoints[i-1] + 1` (or 0 for i == 0).
struct TtfGlyph
{
    i16 x_min;
    i16 y_min;
    i16 x_max;
    i16 y_max;

    // Pointers into the source font buffer; lifetime tied to
    // `TtfFont::bytes`. Each is `count` long.
    const u16* endpoints;
    u16 contour_count;

    const TtfPoint* points; // `total_points` long
    u16 total_points;
};

/// Per-glyph horizontal metric from `hmtx`. Both in font design units.
struct TtfHMetric
{
    u16 advance_width; // pen advance after this glyph
    i16 lsb;           // left side bearing
};

/// Resolved font handle. Cheap to copy (pointers + small ints).
/// Construct via `TtfLoad`. Outlives the parser; readers are
/// IRQ-safe so long as the underlying byte buffer is.
struct TtfFont
{
    const u8* bytes;
    u32 size;

    u32 head_offset;
    u32 hhea_offset;
    u32 hmtx_offset;
    u32 maxp_offset;
    u32 cmap_offset;    // start of the table
    u32 cmap_fmt4_off;  // start of the format-4 subtable inside cmap
    u32 cmap_fmt4_size; // length of format-4 subtable
    u32 loca_offset;
    u32 glyf_offset;

    u16 units_per_em; // from `head`
    u16 num_glyphs;   // from `maxp`
    u16 num_hmetrics; // from `hhea` — `hmtx` has this many full entries

    // 0 = short (offsets in `loca` are u16 and stored / 2),
    // 1 = long (offsets in `loca` are u32). From `head`.
    u16 index_to_loc_format;
};

/// Parse a font's table directory + every required table header.
/// Validates the sfnt version, table count bounds, and that every
/// referenced offset+length stays inside `bytes_size`. On any
/// inconsistency returns ErrorCode::InvalidArgument with no
/// partial state escaped.
::duetos::core::Result<TtfFont> TtfLoad(const u8* bytes, u32 size);

/// Look up the glyph index for a codepoint via the cached format-4
/// cmap subtable. Returns 0 (.notdef glyph) on a miss; that's the
/// TrueType convention, not an error. Codepoints outside the BMP
/// (> 0xFFFF) are not representable in format 4 and resolve to 0.
u16 TtfGlyphIndex(const TtfFont& font, u32 codepoint);

/// Look up `glyph_index`'s horizontal metric. Glyphs past
/// `num_hmetrics - 1` use the LAST hmtx full entry's advance and
/// their own lsb (TrueType convention for monospace tail
/// optimization). Returns ErrorCode::InvalidArgument if
/// `glyph_index >= num_glyphs`.
::duetos::core::Result<TtfHMetric> TtfGetHMetric(const TtfFont& font, u16 glyph_index);

/// Decode `glyph_index`'s outline. Output points + endpoints arrays
/// are written into `*out`; their backing storage is the caller-
/// supplied scratch buffers (so the parser does not allocate). The
/// scratch must be sized for at least `max_points` and
/// `max_contours`; if either is too small returns
/// ErrorCode::OutOfMemory and writes nothing.
///
/// Returns ErrorCode::NotImplemented for composite glyphs and
/// "empty" (no contours) glyphs return success with
/// contour_count == 0 + total_points == 0.
::duetos::core::Result<TtfGlyph> TtfDecodeGlyph(const TtfFont& font, u16 glyph_index, TtfPoint* points_scratch,
                                                u32 max_points, u16* endpoints_scratch, u16 max_contours);

/// Boot-time self-test. Validates a hand-encoded test font (4 glyphs:
/// .notdef, space, A, B) embedded in the kernel image so the parser's
/// happy paths are exercised at every boot. Logs the result line and
/// returns true on success.
bool TtfSelfTest();

/// Register `font` as the active chrome font. The rasterizer's
/// `TtfDrawString` consults this on every call; passing nullptr
/// disables the TTF path so chrome falls back to the bitmap font.
/// The caller retains ownership of the font bytes — see
/// `TtfFont::bytes` lifetime contract above.
void TtfChromeFontSet(const TtfFont* font);

/// Read the active chrome font (or nullptr if none registered).
/// Used by the chrome paint path to gate the TTF dispatch.
const TtfFont* TtfChromeFontGet();

/// Bold companion to TtfChromeFontSet. The ChromeText module's
/// `Bold` weight dispatches to this font when registered. No-op if
/// `font` is nullptr (caller can deregister by passing nullptr).
/// Caller retains ownership; the parser stores a borrowed pointer
/// (same contract as TtfChromeFontSet).
void TtfChromeBoldSet(const TtfFont* font);

/// Returns the bold chrome font, or nullptr if unregistered.
/// Used by chrome_text.cpp to decide whether the Bold weight has
/// a real bold font or must degrade to a synthesized form
/// (double-paint with 1px x-offset for bitmap, fall back to
/// Regular for TTF when the bold font failed to load).
const TtfFont* TtfChromeBoldGet();

} // namespace duetos::drivers::video
