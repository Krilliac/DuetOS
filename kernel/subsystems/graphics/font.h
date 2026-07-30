#pragma once

#include "util/types.h"

/*
 * DuetOS — font registry, v0.
 *
 * Central registry for bitmap fonts used by the GDI text-drawing
 * path and the compositor. Fonts are registered at boot time (the
 * existing 8x8 font as "System" + "Fixedsys", a VGA 8x16 font as
 * "Terminal") and looked up by name + height + weight via
 * FontRegistryLookup, which implements a simplified Win32 font-
 * matching algorithm.
 *
 * The registry is a fixed-capacity array (16 slots); fonts are
 * identified by index. GDI font handles carry a kGdiTagFont tag
 * and an index into the registry so SelectObject + GetTextMetrics
 * can resolve the font cheaply.
 *
 * Memory model: glyph data pointers reference .rodata — no
 * allocations, no ownership. The registry itself is global mutable
 * state protected by the compositor lock (all GDI callers already
 * hold it).
 *
 * Context: kernel. FontRegistryInit runs once at GdiInit time.
 */

namespace duetos::subsystems::graphics
{

inline constexpr u32 kFontNameMax = 32;
inline constexpr u32 kFontRegistryCapacity = 16;

// Win32 font weight constants (subset).
inline constexpr u32 kFwDontCare = 0;
inline constexpr u32 kFwNormal = 400;
inline constexpr u32 kFwBold = 700;

// Win32 charset constants (subset).
inline constexpr u8 kAnsiCharset = 0;
inline constexpr u8 kDefaultCharset = 1;
inline constexpr u8 kOemCharset = 255;

struct FontEntry
{
    bool alive;
    char name[kFontNameMax]; // NUL-terminated face name
    const u8* glyph_data;    // pointer to glyph bitmap data (.rodata)
    u32 glyph_width;         // pixel width of each glyph cell
    u32 glyph_height;        // pixel height of each glyph cell
    u32 weight;              // kFwNormal or kFwBold
    bool italic;
    u8 charset; // kAnsiCharset, kDefaultCharset, kOemCharset

    // Lookup helper: return glyph data for a character, using the
    // font's own glyph table layout. For 8x8 fonts this delegates
    // to Font8x8Lookup; for 8x16 fonts to the VGA table.
    // Returns nullptr only if the font entry itself is dead.
    const u8* LookupGlyph(char ch) const;
};

/// One-time init. Registers the built-in fonts (System 8x8,
/// Terminal 8x16). Safe to call multiple times (idempotent).
void FontRegistryInit();

/// Register a font. Returns the slot index (0..kFontRegistryCapacity-1)
/// on success, or u32(-1) if the registry is full.
u32 FontRegistryAdd(const char* name, const u8* glyph_data, u32 glyph_width, u32 glyph_height, u32 weight, bool italic,
                    u8 charset);

/// Look up the best-matching font. Simplified Win32 matching:
///   1. Exact name match (case-insensitive) with closest height.
///   2. Fallback to "System" (the 8x8 font).
/// Returns a pointer to the matched FontEntry (never nullptr after
/// FontRegistryInit has run — the System font is always slot 0).
const FontEntry* FontRegistryLookup(const char* name, u32 height, u32 weight, bool italic, u8 charset);

/// Look up by slot index. Returns nullptr for out-of-range or dead
/// slots.
const FontEntry* FontRegistryGet(u32 index);

/// Return the number of alive entries (for EnumFontFamilies).
u32 FontRegistryCount();

/// Draw a single character from a font entry onto a BGRA8888 pixel
/// buffer. `stride` is the row stride in pixels (not bytes).
/// Clips to the surface bounds (surf_w x surf_h).
void FontDrawChar(const FontEntry* font, u32* pixels, u32 stride, u32 surf_w, u32 surf_h, i32 x, i32 y, char ch, u32 fg,
                  u32 bg, bool opaque);

} // namespace duetos::subsystems::graphics
