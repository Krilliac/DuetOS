#pragma once

#include "util/types.h"

/*
 * DuetOS chrome text — unified TTF/bitmap dispatcher.
 *
 * Single owner of "render chrome text with the right role under the
 * active theme". Every chrome paint site that previously called
 * FramebufferDrawString / FramebufferDrawStringScaled / TtfDrawString
 * directly migrates to ChromeTextDraw(role, ...) — the dispatch to
 * TTF (Liberation Sans Regular/Bold) or 8x8 bitmap (integer-scaled,
 * with double-paint bold) happens internally based on
 * ThemeCurrent().font_kind + TtfChromeFontGet() / TtfChromeBoldGet()
 * registration state.
 *
 * Four type roles per the design spec; mono path (terminal, kernel
 * shell, hex viewer) stays on the bitmap font intentionally and does
 * NOT route through this API.
 *
 * Scope limits:
 *   - GUI chrome only; mono paths route directly to FramebufferDrawString.
 *   - Integer pixel positions; TTF advances rounded to pixel grid.
 *   - Regular + Bold only; italic / additional weights are YAGNI for v0.
 *   - No bidi / RTL / no glyph cache / no HiDPI scaling.
 *
 * See docs/superpowers/specs/2026-05-24-duetos-pass-c-design.md.
 */

namespace duetos::drivers::video
{

enum class ChromeTextRole : u8
{
    Display = 0,   // ~72 px TTF / scale 8 bitmap — hero numerals (clock, hero metrics)
    Title   = 1,   // ~16 px TTF / scale 2 bitmap — window titlebars, modal titles, card name
    Body    = 2,   // ~13 px TTF / scale 1 bitmap — menu rows, button labels, dialog text
    Caption = 3,   // ~11 px TTF / scale 1 bitmap — hints, status, tooltips, timestamps
};

enum class ChromeTextWeight : u8
{
    Regular = 0,
    Bold    = 1,   // TTF: Liberation Sans Bold (if loaded). Bitmap: double-paint with 1px x-offset.
};

/// Draw chrome text at (x, y). Dispatches internally based on the
/// active theme's font_kind and the registered chrome fonts.
/// Caller holds compositor lock. No-op if text is null/empty or the
/// framebuffer is unavailable.
void ChromeTextDraw(ChromeTextRole role,
                    u32 x, u32 y,
                    const char* text,
                    u32 fg, u32 bg,
                    ChromeTextWeight weight = ChromeTextWeight::Regular);

/// Pixel width the string occupies at the role under the active theme.
/// TTF path sums per-glyph advances; bitmap path returns
/// strlen * scale * 8. Returns 0 for null/empty text.
u32 ChromeTextMeasure(ChromeTextRole role, const char* text);

/// Pixel height (ascent + descent) for the role under the active theme.
u32 ChromeTextRoleHeight(ChromeTextRole role);

/// Boot-time self-test: validates role pixel sizes match the design
/// table, dispatch returns the right path per font_kind, and Measure
/// is deterministic. Emits `[chrome-text-selftest] PASS` on success
/// or a FAIL line + KBP_PROBE_V on failure.
void ChromeTextSelfTest();

/// Accessor for the Pass C umbrella aggregator.
bool ChromeTextSelfTestPassed();

} // namespace duetos::drivers::video
