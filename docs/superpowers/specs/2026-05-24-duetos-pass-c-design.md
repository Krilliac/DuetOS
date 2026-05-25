# DuetOS Pass C — Typography &amp; Hierarchy — Design Spec

**Status:** Approved, pending implementation plan
**Date:** 2026-05-24
**Branch context:** `claude/pass-c-typography`
**Companion docs:** `docs/duet-theme/prototype/` (design source of truth for desktop), `docs/superpowers/specs/2026-05-24-duetos-chrome-tactility-design.md` (Pass A — primitives), `docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md` (Pass B — first-impression moments, merged via 171f5732)
**Sequencing:** This is **pass C** of four. Pass A (chrome tactility) is in `main` via PR #338; Pass B (first-impression moments) is in `main` via merge `171f5732`. Pass D (app-level redesigns) sequences after this lands.

---

## 1. Summary

Replace the kernel's universal 8×8 ROM font with Liberation Sans (Regular + Bold) across every chrome surface that earned the visual upgrade, anchored on a four-tier hierarchy (Display / Title / Body / Caption). The terminal, kernel shell, hex viewer, and other character-cell-mandatory surfaces stay on the bitmap font intentionally.

The TTF infrastructure (`kernel/drivers/video/ttf.{h,cpp}` parser + `ttf_raster.{h,cpp}` rasterizer + `TtfChromeFontSet` registration) is already in tree from Pass B prep. Today it serves exactly one call site — window titles in `widget.cpp:2182`. Pass C extends it to ~25 chrome paint sites via a new unified `ChromeText` module so every caller dispatches through one role-based API instead of manually picking bitmap-vs-TTF.

Engineering target: one new module (`chrome_text.{h,cpp}`, ~250 LOC), Liberation Sans Bold baked into the kernel image (~140 KB), ~25 mechanical call-site migrations across existing chrome files, one hosted test, one self-test, one screenshot-matrix mode. No new subsystems, no new syscalls, no layout-engine refactor.

## 2. Goals

- **Four type roles, one API.** `ChromeTextRole::{Display, Title, Body, Caption}` × `ChromeTextWeight::{Regular, Bold}`. Every chrome paint site calls one function; the dispatch to TTF or bitmap is internal.
- **Per-theme opt-in preserved.** The five Duet-family themes (`Duet`, `DuetLight`, `DuetBlue`, `DuetViolet`, `DuetGreen`) get the full TTF hierarchy. `Classic`, `Slate10`, `Amber`, `HighContrast`, `DuetClassic` stay bitmap with a degenerate scale-based hierarchy.
- **No layout regressions.** A new `ChromeTextMeasure(role, text)` returns the pixel width every caller needs for variable-width TTF layout; every site that previously did `chars * 8` migrates to call it.
- **Pass A / Pass B invariants intact.** HighContrast renders bit-for-bit identical to pre-spec; Pass B's animated wallpaper and Pass B's login GUI continue to work; no probe fires from existing self-tests.
- **No CPU regression beyond budget.** TTF rasterization is more expensive than bitmap byte-copy; budget allows up to 12% CPU avg over a 30 s text-heavy soak (vs Pass B's 8% ambient-motion budget).

## 3. Non-goals

- **No mono path conversion.** Terminal, kernel shell, hex viewer, console body, and the framebuffer console stay on the 8×8 font. Character cells are load-bearing for grid-aligned content; switching to a proportional font breaks the visual contract.
- **No new themes.** The existing ten themes cover the surface.
- **No layout-engine refactor.** Manual rect arithmetic per-call-site stays; a proper layout pass with constraints / ellipsis-on-overflow / line wrapping is Pass D territory.
- **No glyph cache.** Each TTF rasterize is fresh through the existing edge-tracker. If a future profile shows the rasterizer is hot, a cache lands as a follow-on slice — not Pass C.
- **No font-size cmdline override.** Sizes are fixed per role; a UX-preferences-driven override could land later if a Settings panel calls for it.
- **No HiDPI scaling.** Everything renders at fixed pixel sizes against today's 1024×768 baseline. If HiDPI surfaces (multi-monitor work, real-HW high-density display), the per-role pixel table becomes per-DPI — out of scope here.
- **No bidirectional text / RTL.** No Hebrew or Arabic in chrome strings v0.
- **No sub-pixel positioning.** Integer pixel positions only; TTF advances rounded to pixel grid.
- **No italic.** Regular + Bold only; italic is rare in OS chrome and YAGNI for v0.
- **No accent-aware text contrast.** Each theme keeps its hand-picked `banner_fg`; future work could derive contrast-correct ink from background luminance, but not here.

## 4. The four type roles

| Role | TTF pixel size | Bitmap scale fallback | Weights | Where |
|---|---|---|---|---|
| **Display** | 72 px | scale 8 (64 px effective) | Regular | Pass B clock, login hero numerals, future hero metrics (Sysmon big CPU%, Clock app face) |
| **Title** | 16 px | scale 2 (16 px effective) | Regular + Bold (Bold = active window) | Window titlebars, modal/dialog titles, login card name |
| **Body** | 13 px | scale 1 (8 px effective) | Regular + Bold (Bold = primary button) | Menu rows, button labels, dialog text, taskbar tab labels, taskbar clock+date, calendar text, settings panel labels |
| **Caption** | 11 px | scale 1 (8 px effective — same as Body on bitmap themes) | Regular | Hints, status messages, tooltips, timestamps, footnotes, login default-account hint |

**Why these sizes:** Display at ~72 px is the visually-dominant number-character at 1024×768 (~9% of screen height). Title at 16 px is the legibility floor for proportional text on a 1024×768 framebuffer (12-14 px reads thin; 18+ feels heavy on titlebars). Body at 13 px is the standard chrome-text size in mature desktop OSs (macOS uses 13, Windows ~12-14). Caption at 11 px is the floor implementation will target — drop to 10 px if the rasterizer's edge-tracker still produces clean glyphs at that size on the project's super-sampling configuration; if not, raise to 12 px and accept the visual collision with Body.

**The bitmap-theme Body/Caption collision is accepted v0 behavior.** Bitmap themes (Classic, Amber, HighContrast, DuetClassic) intentionally use the pixel-grid aesthetic; collapsing Body and Caption to the same scale matches the look. Themes that want a distinct caption must opt into TTF.

## 5. API — the `ChromeText` module

**File:** `kernel/drivers/video/chrome_text.{h,cpp}` (new)

```cpp
namespace duetos::drivers::video
{

enum class ChromeTextRole : u8
{
    Display = 0,   // ~72 px TTF / scale 8 bitmap
    Title   = 1,   // ~16 px TTF / scale 2 bitmap
    Body    = 2,   // ~13 px TTF / scale 1 bitmap
    Caption = 3,   // ~11 px TTF / scale 1 bitmap (same as Body on bitmap themes)
};

enum class ChromeTextWeight : u8
{
    Regular = 0,
    Bold    = 1,   // TTF: Liberation Sans Bold. Bitmap: double-paint with 1px x-offset.
};

/// Draw chrome text at (x, y) using the active theme's font kind.
/// TTF themes with chrome+bold fonts registered dispatch to
/// TtfDrawString at the role's pixel size. Bitmap themes (or TTF
/// themes whose font hasn't loaded) fall back to
/// FramebufferDrawStringScaled at the role's bitmap scale.
///
/// `fg` is the text colour; `bg` is the glyph background (used by
/// the bitmap path; ignored by TTF which composites via src-over).
/// Bold weight maps to Liberation Sans Bold on TTF themes and to
/// "double-paint with 1 px x-offset" on bitmap themes (cheap visual
/// bold without a second bitmap font).
///
/// Caller holds compositor lock. No-op if framebuffer is unavailable
/// or text is null/empty.
void ChromeTextDraw(ChromeTextRole role,
                    u32 x, u32 y,
                    const char* text,
                    u32 fg, u32 bg,
                    ChromeTextWeight weight = ChromeTextWeight::Regular);

/// Pixel width the string occupies at the given role under the
/// active theme. TTF path sums per-glyph advances; bitmap path
/// returns `strlen(text) * scale * 8`. Used to right-align, centre,
/// or ellipsis-on-overflow variable-width text without measuring
/// twice through the rasterizer.
u32 ChromeTextMeasure(ChromeTextRole role, const char* text);

/// Pixel height (ascent + descent) for the role under the active
/// theme. Callers that need to size containers around text (button
/// padding, menu row height, dialog body line gap) read this.
u32 ChromeTextRoleHeight(ChromeTextRole role);

/// Boot-time self-test: validates role pixel sizes match the
/// design table (within 1 px tolerance for TTF rounding); confirms
/// dispatch returns the right path per theme; checks that
/// Measure(role, text) is deterministic (same call returns same
/// value). Emits `[chrome-text-selftest] PASS` on success or a
/// FAIL line + ProbeFire on failure.
void ChromeTextSelfTest();
bool ChromeTextSelfTestPassed();

} // namespace duetos::drivers::video
```

**Internal dispatch.** A small static lookup table maps `(role, theme.font_kind)` to a paint function:

```cpp
struct RoleSpec {
    u32 ttf_px;        // 72, 16, 13, 11
    u32 bitmap_scale;  //  8,  2,  1,  1
};
constexpr RoleSpec kRoles[] = {
    {72, 8}, {16, 2}, {13, 1}, {11, 1},
};
```

At runtime, `ChromeTextDraw`:
1. Reads `ThemeCurrent().font_kind` and `TtfChromeFontGet()` / `TtfChromeBoldGet()` registration state
2. If TTF + font registered: `TtfDrawString(x, y, text, fg, kRoles[role].ttf_px)` (Bold variant for `Bold` weight)
3. Else: `FramebufferDrawStringScaled(x, y, text, fg, bg, kRoles[role].bitmap_scale)` (double-paint at `(x+1, y)` for `Bold` on bitmap)

**Bold support requires a second font.** `kernel/drivers/video/ttf.{h,cpp}` gains `TtfChromeBoldSet(const TtfFont*)` and `TtfChromeBoldGet()` paired with the existing Regular accessors. `boot_bringup.cpp` loads Liberation Sans Bold via the same path the Regular font uses (`generated_chrome_font_bold.h` baked at build time).

## 6. Per-theme behaviour

Existing `Theme::font_kind` field gates dispatch:

| Theme | `font_kind` | Effective hierarchy |
|---|---|---|
| Duet, DuetLight, DuetBlue, DuetViolet, DuetGreen | `Ttf` | Full TTF: Display 72 px / Title 16 px / Body 13 px / Caption 11 px; Bold available |
| Classic | `Bitmap8x8` | Bitmap: Display scale 8 (64 px) / Title scale 2 (16 px) / Body scale 1 (8 px) / Caption scale 1 (8 px = Body); Bold = double-paint |
| Slate10 | `Bitmap8x8` | Same as Classic |
| Amber | `Bitmap8x8` | Same as Classic (CRT aesthetic intentional) |
| HighContrast | `Bitmap8x8` | Same as Classic (accessibility tuning intentional) |
| DuetClassic | `Bitmap8x8` | Same as Classic (bridge theme by design) |

`Theme::tactility_enabled` is independent of font_kind — a TTF theme can opt out of tactility (none do today, but the dimensions are orthogonal).

## 7. Module layout

| File | New / Edit | Role | Size estimate |
|---|---|---|---|
| `kernel/drivers/video/chrome_text.h` | **new** | Public API: enums + draw / measure / role-height / self-test | ~50 LOC |
| `kernel/drivers/video/chrome_text.cpp` | **new** | Dispatch table + paint helpers + self-test body | ~200 LOC |
| `kernel/drivers/video/ttf.h` | edit | `TtfChromeBoldSet` / `TtfChromeBoldGet` declarations | +6 LOC |
| `kernel/drivers/video/ttf.cpp` | edit | Bold-font storage + accessors (mirror existing Regular path) | +24 LOC |
| `kernel/core/boot_bringup.cpp` | edit | Bake-time chrome-bold byte array reference + `TtfLoad` + `TtfChromeBoldSet` registration; call `ChromeTextSelfTest` | +30 LOC |
| `tools/build/gen_chrome_font_bold.py` (or amend existing chrome-font generator) | **new/edit** | Build-time `xxd -i`-equivalent for Liberation Sans Bold bytes into a `generated_chrome_font_bold.h` | ~40 LOC |
| `kernel/CMakeLists.txt` | edit | Codegen target + dependency on the bold-font asset | +10 LOC |
| **Call-site migrations:** | edit | Each replaces `FramebufferDrawString*` with `ChromeTextDraw(role, ...)` + uses `ChromeTextMeasure` where layout depended on `chars * 8` | ~5-10 LOC per file × ~10 files |
| `kernel/drivers/video/widget.cpp` | edit | Window titlebars (Title weight); existing `TtfDrawString` call migrates to `ChromeTextDraw` | +5 LOC, -3 LOC |
| `kernel/drivers/video/taskbar.cpp` | edit | Tab labels (Body), clock+date (Body) | +10 LOC, -4 LOC |
| `kernel/drivers/video/menu.cpp` | edit | Menu rows (Body) | +5 LOC, -3 LOC |
| `kernel/drivers/video/dialog.cpp` | edit | Dialog title (Title), body text (Body), button labels (Body Bold for primary, Body Regular otherwise) | +12 LOC, -6 LOC |
| `kernel/drivers/video/start_menu_apps.cpp` | edit | Tile labels (Body) | +5 LOC, -3 LOC |
| `kernel/drivers/video/splash.cpp` | edit | Phase ticker (Caption) | +3 LOC, -2 LOC |
| `kernel/security/login.cpp` | edit | Clock (Display), card name (Title), password placeholder (Body), default-admin hint (Caption), status text (Caption Bold for errors), sign-in button (Body Bold) | +15 LOC, -10 LOC |
| `kernel/drivers/video/calendar.cpp` | edit | Day labels (Body), week numbers (Caption) | +5 LOC, -3 LOC |
| `kernel/apps/settings.cpp` | edit | Panel labels (Body), section titles (Title) | +8 LOC, -4 LOC |
| `kernel/apps/about.cpp` | edit | Section titles (Title), body text (Body) | +5 LOC, -2 LOC |
| `tests/host/test_chrome_text_measure.cpp` | **new** | Hosted unit test: literal Liberation Sans advance widths for known strings | ~80 LOC |
| `tests/host/CMakeLists.txt` | edit | Register `test_chrome_text_measure` | +2 LOC |
| `tools/test/boot-log-analyze.sh` | edit | `PASS C (typography)` umbrella section | +20 LOC |
| `tools/test/tactility-screenshot-matrix.sh` | edit | New `--typography` surface mode | +30 LOC |
| `tools/test/pass-c-soak.sh` | **new** | 30 s text-heavy soak (open menus, switch tabs, scroll) | ~80 LOC |
| `wiki/subsystems/Compositor.md` | edit | Add Pass C section | +50 LOC |

**Total:** ~900 LOC across ~22 files; 5 new files (`chrome_text.{h,cpp}`, hosted test, soak script, codegen script); 1 new auto-generated header (`generated_chrome_font_bold.h`, produced at build time); kernel-image growth ~140 KB (Liberation Sans Bold).

### 7.1 Boot sequencing

1. Pre-FB boot unchanged
2. `FramebufferInit()` lands
3. Drivers phase (already in tree) loads chrome font Regular + calls `TtfChromeFontSet`
4. Drivers phase **(new)** loads chrome font Bold + calls `TtfChromeBoldSet`
5. `ChromeTextSelfTest()` runs in the boot self-test umbrella (alongside Pass A `[blend/shadow/theme/tactility-selftest]` and Pass B `[splash/wallpaper-motion/login-gui/pass-b-selftest]`)
6. Pass C umbrella `[pass-c-selftest] PASS (chrome-text=ok)` emits when `ChromeTextSelfTestPassed()` returns true

### 7.2 Migration order — incremental commits per call site

The migration is purely mechanical (one paint-call form swapped for another). To keep the build green per commit:

1. Land `chrome_text.{h,cpp}` + Bold font baking + self-test — nothing CALLS the new API yet, build stays clean
2. Migrate sites one at a time, each a separate commit, build clean after each:
   - `widget.cpp` window title (smallest delta; already TTF; just renames)
   - `taskbar.cpp` (largest single delta; clock + date + tab labels)
   - `menu.cpp`, `dialog.cpp`, `start_menu_apps.cpp`
   - `splash.cpp`, `login.cpp` (Pass B surfaces)
   - `calendar.cpp`, `apps/settings.cpp`, `apps/about.cpp`
3. Final audit pass: grep for `FramebufferDrawString` / `FramebufferDrawStringScaled` calls in chrome files that should have migrated, fix or document why not

## 8. Testing &amp; verification

### 8.1 Self-tests

| Test | What it asserts | Sentinel |
|---|---|---|
| `ChromeTextSelfTest()` | Role pixel sizes match design table (±1 px TTF tolerance); `Measure(role, text)` deterministic across calls; dispatch returns correct path per `font_kind`; bold weight uses bold font when available | `[chrome-text-selftest] PASS` |
| `boot-log-analyze.sh` Pass C umbrella | All sub-tests passed + no probe fires in 0xC0-0xC7 range | `[pass-c-selftest] PASS (chrome-text=ok)` |

Self-tests run silently on PASS (one `[<n>-selftest] PASS` line each); FAIL emits a verbose `[<n>-selftest] FAIL <reason>` line and fires a gated probe (see `kernel/debug/probes.h`).

### 8.2 Hosted unit test

`tests/host/test_chrome_text_measure.cpp` — independent of QEMU. Exercises the measure math with Liberation Sans advance widths for a known string set (`"OK"`, `"Cancel"`, `"Sign in"`, `"FILES — Documents"`, the literal Pass B `"04:18"`). The advance values are computed once via `ttx` (FontTools dump) and baked as literal expectations. Test fails if the rasterizer's measure path drifts.

### 8.3 HighContrast invariant

HighContrast is `Bitmap8x8`. Pass C's dispatch falls through to the bitmap path for HighContrast — no TTF code runs. The existing `tools/test/hc-invariant-check.sh` (extended in Pass B for motion=on/off) re-verifies the bit-for-bit pixel diff stays below the 333-px noise floor under HighContrast both with and without Pass C's changes loaded. Catches any regression where the new dispatch accidentally branches into TTF for a bitmap theme.

### 8.4 Screenshot matrix

`tools/test/tactility-screenshot-matrix.sh` gains a `--typography` mode that boots each theme, opens a representative chrome surface (a window with title + menu + dialog + button + caption), and captures via QMP screendump. Per-theme PPMs land at `build/shots/typography-<theme>-debug-fast.ppm`. Visual comparison catches per-theme rendering surprises (e.g., a Title at 16 px on Slate10 reading too tall against the smaller titlebar height).

### 8.5 Soak harness

`tools/test/pass-c-soak.sh` — new. 30 s text-heavy interaction: opens start menu repeatedly, switches taskbar tabs, scrolls a file list, opens / closes a dialog. All operations exercise the TTF rasterizer. Asserts:
- Avg CPU < 12% over the soak window
- No compositor missed-tick warnings
- No new error lines from `chrome_text/ttf`

Looser CPU bound than Pass B (8%) because TTF rasterization legitimately costs more than bitmap byte-copy and chrome paint is more frequent under heavy interaction than wallpaper motion is.

### 8.6 VBox visual verification

Pairs with the existing Pass A and Pass B VBox residuals (`wiki/reference/Roadmap.md`). Per-theme typography rendering wants a real GUI boot to validate Title weight readability, Caption legibility, Bold contrast. Same approach: boot the matrix under VirtualBox after QEMU verification.

## 9. Acceptance criteria

Observable success — every one must hold before Pass C is considered landed:

1. **`ChromeTextSelfTest` PASS sentinel** fires on boot for all themes (Duet* and bitmap themes alike).
2. **`boot-log-analyze.sh` reports** `[pass-c-selftest] PASS (chrome-text=ok)` plus the existing Pass A / Pass B umbrella lines.
3. **No Pass A / Pass B regressions** — `blend / shadow / theme-matrix / tactility / splash / wallpaper-motion / login-gui / pass-b` umbrella sentinels all still fire.
4. **HighContrast pixel diff** (pre-Pass-C vs post-Pass-C boot) below the 333-px noise floor — proves the bitmap dispatch is untouched.
5. **`pass-c-soak.sh` reports** avg CPU < 12% over 30 s text-heavy window.
6. **Screenshot matrix produces** one PPM per (theme × typography) combination at `build/shots/typography-*-debug-fast.ppm`.
7. **Roadmap residual entry** for any deferred items surfaced during implementation (per Pass A/B policy: file if surfaced; clean landing produces no entry).
8. **Visual verification under VBox** of Title legibility + Caption readability + Bold contrast for at least one TTF theme (Duet) — pairs with Pass A/B VBox residual.

## 10. Sequencing — what comes after

Pass C unlocks the final pass:

**Pass D — app-level redesigns.** With `ChromeTextDraw(role, ...)` available system-wide, Pass D apps (Settings / About / Files / Sysmon candidates) can compose their internal layouts using the same hierarchy chrome uses. The `Display` role is available for app-level hero numerics (Sysmon big CPU%, Clock app face) — closing the loop from the Pass B clock through Pass C body text through Pass D app metrics. Pass D will likely justify a shared animation primitive (Pass B deliberately did not extract one) and may surface the layout-engine refactor that Pass C deferred (constraints, line wrap, ellipsis-on-overflow).

Per the Roadmap policy, any residuals surfaced by Pass C implementation get a new "Chrome tactility (Pass C) — residual polish" entry in `wiki/reference/Roadmap.md`, modelled on the existing Pass A and Pass B residual sections. Items landed in this slice get **deleted from the Roadmap in the same commit**, not added as "shipped" paragraphs.
