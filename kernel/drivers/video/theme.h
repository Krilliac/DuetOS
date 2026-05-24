#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * Desktop theming, v0.
 *
 * A theme is a flat palette of 32-bit ARGB (really 0x00RRGGBB —
 * the framebuffer driver discards the alpha byte) colours keyed
 * by role. Every piece of desktop chrome that previously held a
 * hardcoded colour now samples its value from the active theme:
 *
 *   - desktop fill / banner ink          (DesktopCompose)
 *   - taskbar strip, start-button fill,
 *     active / inactive tab fills, the
 *     thin top-edge border line          (taskbar.cpp)
 *   - each app window's title bar,
 *     client fill, border, close-btn     (main.cpp, via ThemeRoleChrome)
 *   - framebuffer console ink + bg       (main.cpp, via ConsoleSetColours)
 *
 * Three themes ship today:
 *
 *   - Classic : the teal / slate blue palette the first GUI slice
 *               hardcoded (preserved bit-for-bit so a user who
 *               doesn't touch anything sees exactly what they saw
 *               before themes existed).
 *   - Slate10 : a Windows 10 × Unreal Engine "Slate" UI hybrid.
 *               Dark charcoal / slate desktop, flat Win10-blue
 *               accent, Slate-amber highlight on notes, Win10-red
 *               close button. Title bars stay role-coloured so
 *               individual apps are still distinguishable at a
 *               glance, just in a much flatter / darker register.
 *   - Amber   : a single-hue retro-CRT tribute. Every surface is a
 *               shade of warm amber on near-black, in the spirit of
 *               1980s IBM / Wyse monochrome terminals. Doubles as a
 *               stress test for the theme system — any code that
 *               silently assumes multi-hue contrast shows up here
 *               first.
 *   - Duet    : the in-progress redesigned palette. Slate-charcoal
 *               canvas, dual-accent (teal = native ABI, amber =
 *               Win32 PE peer) so ABI distinctions read at a glance.
 *               Translates the React/Babel prototype under
 *               docs/duet-theme/prototype/ — slate mode only — into
 *               the same flat-token shape the other three themes
 *               use. See docs/duet-theme-spec.md for the per-token
 *               source-of-truth.
 *   - DuetLight : the light-mode sibling of Duet. Same dual-
 *               accent vocabulary on a near-white canvas, sourced
 *               from the prototype's `light` mode tokens. The
 *               cursor + chrome adapt to the inverted contrast
 *               budget so dark-on-light text reads cleanly.
 *   - DuetBlue / DuetViolet / DuetGreen :
 *               three accent variants of the slate Duet, each
 *               swapping the teal accent for a different brand
 *               hue (Win10 blue, modern violet, and a deep
 *               forest green). The amber accent for
 *               document-style apps stays — keeps the dual-
 *               accent "duet" identity intact across variants.
 *   - DuetClassic : Duet's "classic mode" sibling — Win9x grey
 *               panels (#C0C0C0) with the dual-accent teal /
 *               amber title hues retained. The intentional
 *               retro-grey contrast against the modern Duet
 *               story is the point of the variant.
 *
 * Switching themes is a runtime operation (Ctrl+Alt+Y cycles, the
 * `theme` shell command switches or cycles by name, or
 * `theme=slate10` / `theme=classic` / `theme=amber` / `theme=duet`
 * on the kernel cmdline picks at boot). ThemeApplyToAll re-publishes every chrome
 * colour into the window registry + taskbar + console + cursor
 * backing, then the caller triggers a DesktopCompose to paint the
 * result.
 *
 * Context: kernel. Not thread-safe on its own — the switch path
 * is called from the keyboard-reader thread inside a
 * CompositorLock bracket. No ring-3 exposure yet (no syscall).
 */

namespace duetos::drivers::video
{

enum class ThemeId : u8
{
    Classic = 0,
    Slate10 = 1,
    Amber = 2,
    Duet = 3,
    DuetLight = 4,
    DuetBlue = 5,
    DuetViolet = 6,
    DuetGreen = 7,
    DuetClassic = 8,
    HighContrast = 9,
    kCount = 10,
};

/// Stable role tag for each application window whose chrome is
/// themed. Ordering is arbitrary — callers register a window
/// against a role at boot and the theme module consults the
/// current palette when painting. New apps extend this enum;
/// tables in theme.cpp must be extended in lock-step.
enum class ThemeRole : u8
{
    Calculator = 0,
    Notes = 1,
    TaskManager = 2,
    LogView = 3,
    Files = 4,
    Clock = 5,
    GfxDemo = 6,
    Settings = 7,
    ImageView = 8,
    About = 9,
    Help = 10,
    Browser = 11,
    Calendar = 12,
    NotifyCenter = 13,
    Sysmon = 14,   // System Monitor — rolling CPU / heap / window stats
    HexView = 15,  // Hex Viewer — binary file inspector
    CharMap = 16,  // Character Map — codepoint picker
    Terminal = 17, // Terminal — windowed shell host with VT/ANSI parsing
    kCount = 18,
};

struct Theme
{
    const char* name;

    // Desktop chrome
    u32 desktop_bg;
    u32 banner_fg;

    // Taskbar
    u32 taskbar_bg;
    u32 taskbar_fg;
    u32 taskbar_accent;       // start button + active tab fill
    u32 taskbar_tab_inactive; // idle tab fill
    u32 taskbar_border;       // 1-px top edge + tab / start outlines

    // Windows — shared across all roles
    u32 window_border;
    u32 window_close;

    // Per-role title + client — indexed by ThemeRole
    u32 role_title[static_cast<u32>(ThemeRole::kCount)];
    u32 role_client[static_cast<u32>(ThemeRole::kCount)];

    // Framebuffer console
    u32 console_fg;
    u32 console_bg;

    // Mouse cursor sprite. `cursor_outline` paints the
    // 1-px black-by-default border around the arrow shape;
    // `cursor_fill` paints the interior. Theme-tuned so the
    // cursor matches the surrounding chrome (e.g. Amber cursors
    // on the amber CRT theme, slate-ink on the Duet theme).
    u32 cursor_outline;
    u32 cursor_fill;

    // Chrome dimensions. Per-theme so the Duet family can
    // ship the prototype's larger titlebar (26 px vs the
    // existing 22 px) without breaking other themes' layouts.
    // Windows whose `WindowChrome.title_height` is 0 (the
    // common case — main.cpp leaves it 0 at registration)
    // sample this. Explicit per-window heights still win.
    u32 title_bar_height;

    // Taskbar strip height in pixels. The Duet family ships
    // 36 px (the prototype's "compact 38 minus 2 for the
    // accent line"); non-Duet themes + DuetClassic stay at
    // 28 px. main.cpp seeds the taskbar with this value at
    // boot. Live re-init on theme cycle is deferred —
    // changing taskbar height mid-session would shift the
    // console anchor and the maximize reserve in ways the
    // current chrome can't unwind without a re-compose
    // pass.
    u32 taskbar_height;

    // Title-bar control button width in pixels (the close /
    // maximize / minimize trio). Height is always
    // `title_bar_height - 2 * btn_pad` so the buttons fit
    // inside the gradient strip vertically; width is
    // independent so the Duet family can ship the prototype's
    // 46-px-wide chrome trio. 0 = "derive from height" (square
    // buttons sized off `title_bar_height`), the historical
    // pre-spec behaviour.
    u32 title_button_width;

    // Title-bar text scale factor for `FramebufferDrawStringScaled`
    // (1..8). 0 collapses to 1 (compact bitmap). Duet family
    // ships 2 so the larger 30-px title bar carries a readable
    // 16-px title; compact themes stay at 1 (8-px). Subtitle +
    // separator pick this up too so the layout scales as a unit.
    u32 title_text_scale;

    // Which font path the chrome should attempt for title / subtitle
    // text. `Bitmap8x8` always uses the existing 8×8 ROM font (and
    // its integer-scaled variant via title_text_scale). `Ttf` asks
    // the chrome paint path to dispatch through the TTF rasterizer
    // — which only succeeds if a font has been registered via
    // `TtfChromeFontSet`; otherwise it falls back to the bitmap
    // path automatically. Themes opt in independently so a future
    // font asset can light up Duet without changing Classic.
    enum class FontKind : u8
    {
        Bitmap8x8 = 0,
        Ttf = 1,
    };
    FontKind font_kind;

    // ----- Chrome tactility (depth + materiality, Pass A) -----
    //
    // Master switch. When false, ALL alpha-blend chrome
    // primitives (drop shadow, hover lift, press, focus glow,
    // cursor microshadow) bypass and the theme falls back to
    // the existing solid-colour paint paths. The HighContrast
    // and Amber palettes set this false intentionally — the
    // high-contrast use-case can't afford the legibility hit,
    // and the amber-CRT aesthetic reads wrong with soft
    // shadows. Duet variants inherit true.
    bool tactility_enabled;

    // Per-effect intensity bytes (0..255). 0 disables that
    // effect even when tactility_enabled. Active vs inactive
    // shadow intensity follows the chrome focus state — the
    // active window casts a fuller shadow than the inactive
    // siblings on the same desktop. See the per-theme matrix
    // in docs/superpowers/specs/2026-05-24-duetos-chrome-
    // tactility-design.md §7.2.
    u8 shadow_intensity_active;
    u8 shadow_intensity_inactive;
    u8 hover_lift_alpha;
    u8 press_alpha;

    // Colour of the focus-glow ring (the 1-px inner stroke
    // painted by RenderSoftShadowWithStroke). Most Duet
    // variants set this to their primary accent; some route
    // to a secondary (DuetGreen). Win32-role windows override
    // to amber at paint time regardless. `0` is "no glow"
    // (DuetClassic) — the paint path treats 0 as opt-out for
    // the stroke independent of tactility_enabled.
    u32 focus_glow_colour;

    // Optional 2-px micro-shadow rendered under the cursor
    // sprite. Subtle and theme-tuned; opt-out (false) for
    // themes that already pay enough cursor-vs-bg contrast
    // without it. Independent of tactility_enabled so a
    // tactility=off boot still gets a crisp cursor.
    bool cursor_microshadow_enabled;
};

/// Read-only snapshot of the active theme. Valid for as long as
/// no ThemeSet call races with the read (callers in the keyboard
/// reader hold CompositorLock across the whole repaint; callers
/// that just want to sample a colour at init time run before any
/// theme-switch hotkey is armed).
const Theme& ThemeCurrent();

/// Id of the active theme.
ThemeId ThemeCurrentId();

/// Switch the active theme. Does NOT repaint — call ThemeApplyToAll
/// afterwards to publish the new colours into the window registry,
/// taskbar, console, and cursor backing.
void ThemeSet(ThemeId id);

/// Convenience: advance to the next theme (wraps). Same caveat
/// as ThemeSet re: repaint.
void ThemeCycle();

/// Map a theme name ("classic" / "slate10") to an id. Matching is
/// case-insensitive. Returns false + leaves `out` untouched if
/// the string is unknown.
bool ThemeIdFromName(const char* s, ThemeId* out);

/// Human-readable name for an id ("classic", "slate10", "unknown").
const char* ThemeIdName(ThemeId id);

/// Register a window handle against a role so ThemeApplyToAll
/// knows which window to re-chrome when the theme changes. The
/// handle must be valid (WindowIsAlive == true) at call time.
/// Re-registering the same role overwrites the previous handle.
/// Passing kWindowInvalid clears the slot.
void ThemeRegisterWindow(ThemeRole role, WindowHandle h);

/// Look up the window handle previously registered for `role`.
/// Returns `kWindowInvalid` if no handle was registered, or the
/// stored handle is no longer alive (caller still gets a
/// well-defined sentinel rather than a stale reference). Used
/// by the Start menu / launcher dispatch to raise an app
/// window by name without touching kernel-internal tables.
WindowHandle ThemeRoleWindow(ThemeRole role);

/// Reverse of ThemeRoleWindow: look up the role registered for
/// `h`. Returns true + writes the role on hit, false otherwise.
/// Used by the taskbar to paint per-role app glyphs in each tab
/// (Calculator → `=`, Notes → ruled rows, etc.) so users can
/// identify the app from the taskbar by its icon shape, not just
/// the title text.
bool ThemeRoleForWindow(WindowHandle h, ThemeRole* out);

/// Re-publish every themed colour into the live UI:
///   - every registered window's chrome (border, title, client,
///     close button)
///   - the taskbar bg / fg / accent / tab-inactive / border
///   - the console foreground + background
///   - the cursor-backing's "desktop fallback" colour
/// Caller is responsible for calling DesktopCompose afterwards
/// to paint the result. Safe to call before any window has been
/// registered (no-ops the window loop).
void ThemeApplyToAll();

/// One-shot self-test: walks the palette table asserting that
/// (a) every ThemeId maps to a non-null Theme with a non-null
/// name, (b) ThemeIdFromName / ThemeIdName round-trip every id,
/// and (c) ThemeCycle visits every id exactly once across
/// kCount calls. Saves and restores the active theme. Prints
/// one PASS/FAIL line to COM1. Called from main.cpp right after
/// ThemeSet is wired up at boot.
void ThemeSelfTest();

/// Returns true iff the last ThemeSelfTest() call passed. Used by
/// the boot bringup's tactility umbrella aggregator to emit a
/// single [tactility-selftest] PASS line when every sub-test
/// passed (spec §8.2). False until ThemeSelfTest has run.
bool ThemeSelfTestPassed();

// ----- Tactility runtime override -----
//
// The compile-time tactility settings live in each Theme literal
// (tactility_enabled + the 5 intensity bytes). The runtime
// override lets an operator force tactility off (e.g. when
// debugging chrome regressions, or on a slow display where the
// shadow paint is visibly slow). Three-state: -1 = "follow theme
// default" (the boot default), 0 = "force off", 1 = "force on".
// Set via the `tactility=` kernel cmdline at boot OR the
// `tactility on|off|default` shell command at runtime.
i8 ThemeTactilityOverride();
void ThemeSetTactilityOverride(i8 v);

/// Resolved tactility setting for the active theme. Equivalent to
/// `(override == -1) ? current_theme.tactility_enabled
///                   : bool(override)`. Use this from every
/// tactility-aware chrome paint path so the override takes
/// effect uniformly.
bool ThemeTactilityEffective();

/// When the runtime tactility override is "force on" (override=1)
/// but the active theme advertises an intensity byte of 0 (Amber /
/// HighContrast opt out by zeroing every tactility intensity
/// field), substitute a sensible default so the override actually
/// renders visible chrome. Required for the documented
/// `tactility on` screenshot / debug workflow — without this the
/// override would set ThemeTactilityEffective() true but every
/// paint site's intensity-driven opacity would still resolve to
/// zero, making the force-on a silent no-op.
///
/// Passes through unchanged in every other case: with override=-1
/// (follow theme) the theme's 0 is honoured (opt-out themes stay
/// flat); with override=0 (force off) ThemeTactilityEffective()
/// is already false and the caller's `effective` guard short-
/// circuits before reaching here.
///
/// Default value 128 is a deliberate mid-intensity — strong
/// enough to read as "tactility is on" but not so loud that an
/// operator capturing a debug screenshot mistakes it for the
/// theme's natural look. Mirrors the average of the per-theme
/// matrix's non-zero intensities (Classic 80, Duet 255, DuetLight
/// 100, DuetClassic 160).
inline constexpr u8 kThemeForceOnDefaultIntensity = 128;
u8 ThemeIntensityEffective(u8 raw);

} // namespace duetos::drivers::video
