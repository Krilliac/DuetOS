#pragma once

#include "drivers/video/chrome_text.h"
#include "util/types.h"

/*
 * Aurora app-interior *content* type — docs/aurora-theme/IMPLEMENTATION.md §4.
 *
 * The shell chrome moved to proportional TTF a while ago
 * (`ChromeTextDraw` / `ChromeTextRole`); the app *content* — file
 * names, process names, column labels — stayed on the fixed 8x8 ROM
 * font because every list view computed its column origins as
 * `chars * 8`. That was the dominant remaining tell against the
 * reference screenshots: the chrome read as Instrument Sans and the
 * table under it read as a terminal.
 *
 * This header is the one home for the three things a list view needs
 * once its columns are pixel-measured instead of cell-counted:
 *
 *   1. **Measure that matches paint.** Every helper here routes
 *      through `ChromeTextMeasure` / `ChromeTextDraw`, which share the
 *      same `TtfMeasureString` pen-advance sum. A column table built
 *      from `AppTextMeasure` and hit-tested against the same table
 *      cannot drift the way `paint = col*8` / `hit = col*8+4` did.
 *   2. **Fitting.** Proportional names overflow their column at
 *      unpredictable character counts, so `AppTextFit` truncates on a
 *      measured width, not a character budget.
 *   3. **Badges.** The reference's `NATIVE` / `WIN32 PE` pills and the
 *      per-row status dot. Both are pure paint helpers so Files and
 *      Task Manager render an identical chip instead of two.
 *
 * Everything here is opt-in the same way `app_palette` is: an app
 * calls it on the Aurora branch and keeps its historical
 * `FramebufferDrawString` literals on the flat-palette branch, so
 * Classic / Slate10 / Amber / DuetClassic / HighContrast stay
 * pixel-identical.
 *
 * Mono content that is genuinely tabular — the kernel-log body, hex
 * dumps, disassembly — deliberately does NOT route through here. It
 * keeps the fixed-width font and takes only the Aurora ink ramp.
 *
 * Caller holds the compositor lock for every Draw entry point.
 */

namespace duetos::drivers::video::app_widgets
{

/// Row pitch a list needs to lead `role` content comfortably: the
/// role's line box plus 5 px of air. Body under a TTF theme gives 18;
/// under a bitmap theme it gives 13. Apps that must stay
/// pixel-identical on the flat palettes keep their own literal and
/// only call this on the Aurora branch.
u32 AppRowHeight(ChromeTextRole role);

/// Top-left y that vertically centres `role` text inside the
/// `row_h`-tall band starting at `y`. Reproduces the historical
/// `(row_h - 8) / 2` exactly on the bitmap path.
u32 AppTextRowY(ChromeTextRole role, u32 y, u32 row_h);

/// Pixel width `text` occupies at `role` under the active theme.
/// Thin pass-through to `ChromeTextMeasure` so callers building a
/// column table don't have to include chrome_text.h transitively.
u32 AppTextMeasure(ChromeTextRole role, const char* text);

/// Copy `src` into `dst` (always NUL-terminated), truncating with a
/// trailing ".." when the measured width would exceed `max_px`.
/// Returns the measured width of the result — 0 for empty input or
/// when not even ".." fits. `dst_cap` includes the terminator.
u32 AppTextFit(ChromeTextRole role, const char* src, char* dst, u32 dst_cap, u32 max_px);

/// Left-aligned cell: `text`'s left edge lands on `x`, vertically
/// centred in the row band. No-op for null/empty text.
void AppTextCell(ChromeTextRole role, u32 x, u32 y, u32 row_h, const char* text, u32 fg, u32 bg,
                 ChromeTextWeight weight = ChromeTextWeight::Regular);

/// Right-aligned cell: `text`'s RIGHT edge lands on `x_right`. Uses
/// the same measurement the paint will advance by, so a numeric
/// column stays flush no matter which glyphs the value happens to
/// use. No-op when the measured run would start left of `x_min`.
void AppTextCellRight(ChromeTextRole role, u32 x_right, u32 x_min, u32 y, u32 row_h, const char* text, u32 fg, u32 bg,
                      ChromeTextWeight weight = ChromeTextWeight::Regular);

/// Width the ABI pill occupies for `label` (chip padding included).
/// Returns 0 for null/empty labels so a "no badge" row costs nothing.
u32 AppPillWidth(const char* label);

/// Paint the ABI pill: a rounded chip filled with `ink` at ~18 %
/// over `bg`, the label in `ink` at Caption size. Vertically centred
/// in the row band. The framebuffer has no per-pixel alpha, so the
/// tint is resolved against `bg` up front — pass the row's *resolved*
/// background (zebra wash / selection fill), not the client body.
void AppPillDraw(u32 x, u32 y, u32 row_h, const char* label, u32 ink, u32 bg);

/// 4-px status dot, left edge at `x`, vertically centred in the row.
/// The reference's per-row liveness marker.
u32 AppRowDotWidth();
void AppRowDotDraw(u32 x, u32 y, u32 row_h, u32 rgb);

/// Boot-time self-test: pins the invariants the column tables depend
/// on — Fit never returns a width above its budget, Fit is monotone
/// in budget, RowY keeps text inside the band, and a pill is always
/// wider than its label. Emits `[app-text-selftest] PASS` / `FAIL`.
void AppTextSelfTest();
bool AppTextSelfTestPassed();

} // namespace duetos::drivers::video::app_widgets
