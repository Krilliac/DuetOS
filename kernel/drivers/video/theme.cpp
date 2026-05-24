#include "drivers/video/theme.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/calendar.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/menu.h"
#include "drivers/video/netpanel.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/tray_flyout.h"
#include "drivers/video/widget.h"
#include "util/string.h"

namespace duetos::drivers::video
{

namespace
{

using duetos::core::StrEqualCaseInsensitive;

// ---------------------------------------------------------------
// Theme palettes.
//
// Colours are stored as 0x00RRGGBB (the framebuffer uses the top
// byte for padding). Each Theme is a compile-time aggregate so
// the whole table sits in .rodata.
//
// Classic preserves the exact values the first GUI slice used,
// bit-for-bit, so a user who never touches the theme hotkey sees
// the same desktop that shipped with the initial compositor.
//
// Slate10 mixes the Windows 10 desktop language (dark chrome,
// bright single-colour accent, flat rectangles, red close-btn)
// with Unreal Engine's Slate UI (deep charcoal panels, amber-ish
// highlights, minimal borders) — the "where are Notes and where
// is the clock" distinction is carried by title-bar hue rather
// than client-fill hue, so most client areas land on the same
// dark Slate panel colour.
// ---------------------------------------------------------------

constexpr Theme kClassic = {
    .name = "classic",

    .desktop_bg = 0x00204868,
    .banner_fg = 0x00FFFFFF,

    .taskbar_bg = 0x00202838,
    .taskbar_fg = 0x00FFFFFF,
    .taskbar_accent = 0x00406090,
    .taskbar_tab_inactive = 0x00303848,
    .taskbar_border = 0x00101828,

    .window_border = 0x00101828,
    .window_close = 0x00E04020,

    .role_title =
        {
            0x00205080, // Calculator
            0x00306838, // Notes
            0x00803020, // TaskManager
            0x00407080, // LogView
            0x00606020, // Files
            0x00203040, // Clock
            0x00702070, // GfxDemo — magenta to flag "this paints pixels"
            0x00405060, // Settings — slate-grey, matches "tools" convention
            0x00306070, // ImageView — muted blue-teal, "viewer" affinity
            0x00405838, // About    — neutral muted green, "info" affinity
            0x00405838, // Help     — same as About; shared "info panel" identity
            0x00305880, // Browser  — sky blue, "online" hue
            0x00305880, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00101828, // Calculator — dark blue-black
            0x00E0E0D8, // Notes      — cream (the only light client)
            0x00101828, // TaskManager
            0x00101020, // LogView
            0x00101828, // Files
            0x00081008, // Clock
            0x00000000, // GfxDemo — black; the demo overpaints every pixel
            0x00181828, // Settings
            0x00080808, // ImageView — near-black so any image reads cleanly
            0x00121828, // About — same "info panel" hue as Settings
            0x00121828, // Help  — same as About
            0x00101828, // Browser — dark blue ground for plain-text reading
            0x00101828, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x0080F088,
    .console_bg = 0x00181028,

    .cursor_outline = 0x00000000, // classic black outline
    .cursor_fill = 0x00FFFFFF,    // classic white fill

    .title_bar_height = 22,
    .taskbar_height = 28,
    .title_button_width = 0,
    .title_text_scale = 1,
    .font_kind = Theme::FontKind::Bitmap8x8,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 80,
    .shadow_intensity_inactive = 40,
    .hover_lift_alpha = 100,
    .press_alpha = 100,
    .focus_glow_colour = 0x245EDC,
    .cursor_microshadow_enabled = false,

    // Pass B - motion_intensity: Classic is subdued (≈ 0.3 × 255, see spec §7)
    .motion_intensity = 77,
};

// Amber is a deliberate retro exercise — a single-hue amber palette
// inspired by 1980s IBM / Wyse monochrome terminals. Every surface
// is a shade of warm amber on near-black, with the brightest hues
// reserved for the focus points (taskbar accent, banner, console
// ink, Notes title). Useful both as a distinctive third option and
// as a stress test for the theme system: anything that hard-coded a
// multi-hue assumption (e.g. "title must contrast with client") will
// break visibly here first.
constexpr Theme kAmber = {
    .name = "amber",

    .desktop_bg = 0x000A0500,
    .banner_fg = 0x00FFB040,

    .taskbar_bg = 0x00140A00,
    .taskbar_fg = 0x00E09030,
    .taskbar_accent = 0x00FF9020,
    .taskbar_tab_inactive = 0x001A1004,
    .taskbar_border = 0x00402010,

    .window_border = 0x00603018,
    .window_close = 0x00E05020, // amber-red — still distinguishable as "close"

    .role_title =
        {
            0x00804020, // Calculator
            0x00A06830, // Notes — brightest title; the focus app
            0x00703018, // TaskManager
            0x00502010, // LogView
            0x00805030, // Files
            0x00402010, // Clock
            0x00A06030, // GfxDemo
            0x00604018, // Settings — muted amber-bronze
            0x00805024, // ImageView — bronze, image-viewer hue
            0x00503818, // About    — deeper bronze, info hue
            0x00503818, // Help     — same as About
            0x00604024, // Browser  — amber-tinted bronze
            0x00604024, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00100800, // Calculator
            0x001A0E00, // Notes — slightly lifted so amber ink reads
            0x00100800, // TaskManager
            0x00080400, // LogView — deepest so amber log colours pop
            0x00100800, // Files
            0x00050200, // Clock — near-black ground for "LEDs"
            0x00000000, // GfxDemo — black; overpainted every frame
            0x00100800, // Settings
            0x00040200, // ImageView — near-black ground for image
            0x00100800, // About
            0x00100800, // Help
            0x00100800, // Browser
            0x00100800, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x00FFA830,
    .console_bg = 0x00080400,

    // Amber cursor: deep CRT brown outline with a bright phosphor
    // interior — preserves the monochrome aesthetic.
    .cursor_outline = 0x00301008,
    .cursor_fill = 0x00FFB840,

    .title_bar_height = 22,
    .taskbar_height = 28,
    .title_button_width = 0,
    .title_text_scale = 1,
    .font_kind = Theme::FontKind::Bitmap8x8,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = false,
    .shadow_intensity_active = 0,
    .shadow_intensity_inactive = 0,
    .hover_lift_alpha = 0,
    .press_alpha = 0,
    .focus_glow_colour = 0xF5B73A,
    .cursor_microshadow_enabled = false,

    // Pass B - motion_intensity: full (tactility_enabled=false gates motion at runtime)
    .motion_intensity = 255,
};

constexpr Theme kSlate10 = {
    .name = "slate10",

    // Desktop: deep Slate charcoal with a faint blue cast so the
    // windows read as "panels on a dark surface" rather than
    // "black screen with popups."
    .desktop_bg = 0x001F1F28,
    .banner_fg = 0x00DDDDE2,

    // Taskbar: Win10-style near-black strip with a single bright
    // blue accent (start + active tab). Inactive tabs are a
    // half-step lighter than the strip so they read without a
    // border. The border constant is used for the thin top-edge
    // line; 0 renders as black in the framebuffer, which is what
    // Slate does for its divider lines.
    .taskbar_bg = 0x0017171C,
    .taskbar_fg = 0x00F0F0F0,
    .taskbar_accent = 0x000078D7, // Win10 system blue
    .taskbar_tab_inactive = 0x002D2D33,
    .taskbar_border = 0x00000000,

    // Windows: minimal dark-slate border, Win10-red close button.
    .window_border = 0x002D2D33,
    .window_close = 0x00E81123, // Win10 close-button red

    .role_title =
        {
            0x000078D7, // Calculator   — Win10 blue (primary accent)
            0x00C5860B, // Notes        — Unreal Slate amber
            0x00B52525, // TaskManager  — dark red
            0x00008CBA, // LogView      — VSCode-ish teal
            0x008B6914, // Files        — dark amber / goldenrod
            0x002D2D33, // Clock        — flat dark slate
            0x008B2C8B, // GfxDemo      — magenta accent
            0x004A4A52, // Settings     — Slate panel grey
            0x00266288, // ImageView    — desaturated blue, "media" affinity
            0x00404048, // About        — neutral Slate, info panel
            0x00404048, // Help         — same as About
            0x000078D7, // Browser      — Win10 system blue, "browser" hue
            0x000078D7, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00252529, // Calculator
            0x00F3F3F3, // Notes — light panel, like Win10 apps
            0x00252529, // TaskManager
            0x001A1A20, // LogView — deepest Slate so log colours pop
            0x00252529, // Files
            0x00101014, // Clock — near-black so 7-seg reads bright
            0x00000000, // GfxDemo — black ground (overpainted)
            0x00252529, // Settings — Slate panel
            0x00141418, // ImageView — deep slate so any image reads cleanly
            0x00252529, // About — Slate panel
            0x00252529, // Help  — Slate panel
            0x00252529, // Browser — Slate panel
            0x00252529, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x00D4D4D4, // VSCode default editor ink
    .console_bg = 0x001A1A20, // Slate panel

    // Slate10 cursor: dark slate outline + bright Win10-blue
    // interior so the pointer reads as a brand-tinted ink on
    // dark slate.
    .cursor_outline = 0x00101015,
    .cursor_fill = 0x00DDE6F0,

    .title_bar_height = 22,
    .taskbar_height = 28,
    .title_button_width = 0,
    .title_text_scale = 1,
    .font_kind = Theme::FontKind::Bitmap8x8,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 200,
    .shadow_intensity_inactive = 100,
    .hover_lift_alpha = 255,
    .press_alpha = 255,
    .focus_glow_colour = 0x0078D4,
    .cursor_microshadow_enabled = true,

    // Pass B - motion_intensity: full
    .motion_intensity = 255,
};

// Duet — the redesigned palette. Slate-charcoal canvas, dual-accent
// (teal = native DuetOS ABI, amber = Win32 PE peer). Sourced from
// docs/duet-theme/prototype/ slate mode and documented per-token in
// docs/duet-theme-spec.md.
//
// The two-accent "duet" story shows up in the per-role title hues:
// utility / telemetry roles (Calculator, TaskManager, Clock, LogView)
// land on the cool / chrome side; document-style roles (Notes, Files)
// land on the warm side. GfxDemo keeps its magenta tag so it reads as
// "this paints pixels" the same way it does in every other palette.
constexpr Theme kDuet = {
    .name = "duet",

    // Desktop: deep Slate canvas (`--bg-1` from the prototype).
    .desktop_bg = 0x000B0E13,
    .banner_fg = 0x00E8EDF2, // `--ink`

    // Taskbar: surface = `--chrome-2`, ink = `--ink-2`,
    // accent = `--accent` (teal #2dd4bf), recess panel = `--chrome-3`,
    // and a hairline border that's `--line-2` flattened over chrome.
    .taskbar_bg = 0x001C222B,
    .taskbar_fg = 0x00AEB7C2,
    .taskbar_accent = 0x002DD4BF,
    .taskbar_tab_inactive = 0x000F1319,
    .taskbar_border = 0x001E2530,

    // Windows: subtle slate border, prototype-matched red close hover.
    .window_border = 0x002A323C,
    .window_close = 0x00E3413C, // `TitleBtn` close hover

    .role_title =
        {
            0x00207A6F, // Calculator   — teal-tinted chrome (utility, native primary)
            0x00805E20, // Notes        — amber-tinted chrome (paper / document analogue)
            0x00164D45, // TaskManager  — deeper teal (telemetry primary)
            0x00161B23, // LogView      — flat slate panel (mono content, no hue)
            0x00604818, // Files        — amber-tinted chrome (document storage)
            0x00141822, // Clock        — slate panel (passive widget)
            0x00702070, // GfxDemo      — magenta to flag "this paints pixels"
            0x002A323C, // Settings     — `--chrome-2` slate
            0x00264858, // ImageView    — deeper teal-slate, "viewer" hue
            0x002A323C, // About        — same `--chrome-2` slate as Settings
            0x002A323C, // Help         — same as About
            0x002A323C, // Browser      — slate panel (matches About/Help)
            0x002A323C, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00141A22, // Calculator
            0x00F3F0E6, // Notes — cream paper, the only light client
            0x00141A22, // TaskManager
            0x000F1319, // LogView — `--chrome-3` so log colours pop
            0x00141A22, // Files
            0x000B0E13, // Clock — near-black canvas ground for clock face
            0x00000000, // GfxDemo — black; the demo overpaints every pixel
            0x00141A22, // Settings — slate canvas
            0x00080A0E, // ImageView — deep canvas so an image reads cleanly
            0x00141A22, // About
            0x00141A22, // Help
            0x00141A22, // Browser
            0x00141A22, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x00E8EDF2, // `--ink` — JetBrains-Mono ink in the prototype
    .console_bg = 0x000F1319, // `--chrome-3` — slate panel ground

    // Duet cursor: slate ink on near-charcoal outline. Lifts the
    // cursor off the dark gradient without competing with the
    // teal / amber accents reserved for the duet-arcs identity.
    .cursor_outline = 0x000B0E13, // matches `desktop_bg`
    .cursor_fill = 0x00E8EDF2,    // matches `--ink`

    // Duet ships the prototype's full 30-px title bar + 44-px
    // taskbar so the chrome buttons, subtitle slot, and tray
    // cells get the breathing room the design calls for.
    .title_bar_height = 30,
    .taskbar_height = 44,
    .title_button_width = 46,
    .title_text_scale = 2,
    .font_kind = Theme::FontKind::Ttf,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 255,
    .shadow_intensity_inactive = 128,
    .hover_lift_alpha = 255,
    .press_alpha = 255,
    .focus_glow_colour = 0x2DD4BF,
    .cursor_microshadow_enabled = true,

    // Pass B - motion_intensity: full
    .motion_intensity = 255,
};

// DuetLight — light-mode sibling of Duet, sourced from the
// prototype's `light` token set. Inverts the contrast budget:
// near-white canvas with the same dual-accent (teal + amber)
// vocabulary on top. Per-role chrome keeps its identity hue
// from the slate variant so the same window reads as "the same
// app" across both modes; the title hues are slightly brighter
// versions of the slate ones so they survive the light client
// fills, and the client fills lift to off-white panels.
constexpr Theme kDuetLight = {
    .name = "duetlight",

    // Light canvas — `--bg-1` (light mode) ≈ near-white slate.
    .desktop_bg = 0x00EDEFF2,
    .banner_fg = 0x00161A20, // ink on light canvas

    // Taskbar: warm-white surface with subtle dividers.
    .taskbar_bg = 0x00DDE1E6,
    .taskbar_fg = 0x00161A20,
    .taskbar_accent = 0x000F8C80,       // deeper teal so it reads against light bg
    .taskbar_tab_inactive = 0x00CFD4DA, // slightly recessed panel
    .taskbar_border = 0x00BCC2C9,

    // Windows: subtle slate-ink border, prototype-matched red close hover.
    .window_border = 0x00B5BCC4,
    .window_close = 0x00E3413C,

    .role_title =
        {
            0x000F8C80, // Calculator   — teal accent (deeper for light bg)
            0x00B5751A, // Notes        — amber accent
            0x00086E64, // TaskManager  — deeper teal
            0x00343A44, // LogView      — neutral chrome
            0x008C5810, // Files        — amber accent
            0x002C323C, // Clock        — slate panel
            0x008B2C8B, // GfxDemo      — magenta marker (kept across themes)
            0x00343A44, // Settings     — neutral chrome (matches LogView)
            0x00086A60, // ImageView    — deeper teal so it reads on light bg
            0x00343A44, // About        — neutral chrome
            0x00343A44, // Help         — same as About
            0x00086A60, // Browser      — deeper teal (matches ImageView accent)
            0x00086A60, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00F4F5F7, // Calculator   — off-white panel
            0x00FBF8EE, // Notes        — cream paper, the only "warm" client
            0x00F4F5F7, // TaskManager
            0x00ECEEF1, // LogView
            0x00F4F5F7, // Files
            0x00E5E8EC, // Clock        — light canvas ground
            0x00000000, // GfxDemo      — black; overpainted every frame
            0x00ECEEF1, // Settings     — light panel
            0x00161A20, // ImageView    — dark canvas (only dark client in light theme — images need contrast ground regardless of theme)
            0x00ECEEF1, // About
            0x00ECEEF1, // Help
            0x00ECEEF1, // Browser
            0x00ECEEF1, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x00161A20,
    .console_bg = 0x00ECEEF1,

    // DuetLight cursor: slate-ink outline + theme accent fill so
    // the pointer reads as a brand-tinted ink on a light surface.
    .cursor_outline = 0x00161A20,
    .cursor_fill = 0x000F8C80,

    .title_bar_height = 30,
    .taskbar_height = 44,
    .title_button_width = 46,
    .title_text_scale = 2,
    .font_kind = Theme::FontKind::Ttf,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 100,
    .shadow_intensity_inactive = 50,
    .hover_lift_alpha = 200,
    .press_alpha = 200,
    .focus_glow_colour = 0x0F9B8A,
    .cursor_microshadow_enabled = true,

    // Pass B - motion_intensity: full
    .motion_intensity = 255,
};

// Duet accent variants. Each one duplicates the slate Duet
// palette and swaps the primary `taskbar_accent` (teal in slate
// Duet) for the variant's brand hue. The amber accent for
// document-style apps (Notes, Files) stays — the dual-accent
// "duet" identity is preserved; only the cool side swings.
//
// To keep the table readable we extract the per-variant overrides
// into a small `MakeDuetAccent()` macro-style aggregate
// initializer, repeating just the deltas. Per-role title hues
// pick a single representative shade per variant.

constexpr Theme kDuetBlue = {
    .name = "duetblue",
    .desktop_bg = 0x000B0E13,
    .banner_fg = 0x00E8EDF2,
    .taskbar_bg = 0x001C222B,
    .taskbar_fg = 0x00AEB7C2,
    .taskbar_accent = 0x000078D7, // Win10 system blue
    .taskbar_tab_inactive = 0x000F1319,
    .taskbar_border = 0x001E2530,
    .window_border = 0x002A323C,
    .window_close = 0x00E3413C,
    .role_title =
        {
            0x00204D80, // Calculator   — blue-tinted chrome
            0x00805E20, // Notes        — amber-tinted chrome (preserved)
            0x00163A66, // TaskManager  — deeper blue
            0x00161B23, // LogView      — slate panel
            0x00604818, // Files        — amber-tinted (preserved)
            0x00141822, // Clock        — slate panel
            0x00702070, // GfxDemo      — magenta marker
            0x002A323C, // Settings     — slate panel
            0x00204D80, // ImageView    — blue-tinted (matches accent)
            0x002A323C, // About        — slate panel
            0x002A323C, // Help         — same as About
            0x002A323C, // Browser      — slate panel
            0x002A323C, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00141A22, 0x00F3F0E6, 0x00141A22, 0x000F1319, 0x00141A22, 0x000B0E13, 0x00000000,
            0x00141A22, // Settings
            0x00080A0E, // ImageView
            0x00141A22, // About
            0x00141A22, // Help
            0x00141A22, // Browser
            0x00141A22, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .console_fg = 0x00E8EDF2,
    .console_bg = 0x000F1319,
    .cursor_outline = 0x000B0E13,
    .cursor_fill = 0x00E8EDF2,
    .title_bar_height = 30,
    .taskbar_height = 44,
    .title_button_width = 46,
    .title_text_scale = 2,
    .font_kind = Theme::FontKind::Ttf,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 255,
    .shadow_intensity_inactive = 128,
    .hover_lift_alpha = 255,
    .press_alpha = 255,
    .focus_glow_colour = 0x0078D4,
    .cursor_microshadow_enabled = true,

    // Pass B - motion_intensity: full
    .motion_intensity = 255,
};

constexpr Theme kDuetViolet = {
    .name = "duetviolet",
    .desktop_bg = 0x000B0E13,
    .banner_fg = 0x00E8EDF2,
    .taskbar_bg = 0x001C222B,
    .taskbar_fg = 0x00AEB7C2,
    .taskbar_accent = 0x008B5CF6, // tailwind violet-500
    .taskbar_tab_inactive = 0x000F1319,
    .taskbar_border = 0x001E2530,
    .window_border = 0x002A323C,
    .window_close = 0x00E3413C,
    .role_title =
        {
            0x00553788, // Calculator   — violet-tinted chrome
            0x00805E20, // Notes        — amber (preserved)
            0x00402568, // TaskManager  — deeper violet
            0x00161B23, // LogView
            0x00604818, // Files        — amber (preserved)
            0x00141822, // Clock
            0x00702070, // GfxDemo
            0x002A323C, // Settings
            0x00553788, // ImageView    — violet-tinted
            0x002A323C, // About        — slate panel
            0x002A323C, // Help         — same as About
            0x002A323C, // Browser      — slate panel
            0x002A323C, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00141A22, 0x00F3F0E6, 0x00141A22, 0x000F1319, 0x00141A22, 0x000B0E13, 0x00000000,
            0x00141A22, // Settings
            0x00080A0E, // ImageView
            0x00141A22, // About
            0x00141A22, // Help
            0x00141A22, // Browser
            0x00141A22, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .console_fg = 0x00E8EDF2,
    .console_bg = 0x000F1319,
    .cursor_outline = 0x000B0E13,
    .cursor_fill = 0x00E8EDF2,
    .title_bar_height = 30,
    .taskbar_height = 44,
    .title_button_width = 46,
    .title_text_scale = 2,
    .font_kind = Theme::FontKind::Ttf,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 255,
    .shadow_intensity_inactive = 128,
    .hover_lift_alpha = 255,
    .press_alpha = 255,
    .focus_glow_colour = 0x9B59B6,
    .cursor_microshadow_enabled = true,

    // Pass B - motion_intensity: full
    .motion_intensity = 255,
};

constexpr Theme kDuetGreen = {
    .name = "duetgreen",
    .desktop_bg = 0x000B0E13,
    .banner_fg = 0x00E8EDF2,
    .taskbar_bg = 0x001C222B,
    .taskbar_fg = 0x00AEB7C2,
    .taskbar_accent = 0x0034C759, // forest / mint green
    .taskbar_tab_inactive = 0x000F1319,
    .taskbar_border = 0x001E2530,
    .window_border = 0x002A323C,
    .window_close = 0x00E3413C,
    .role_title =
        {
            0x00256B36, // Calculator   — green-tinted chrome
            0x00805E20, // Notes        — amber (preserved)
            0x00184A24, // TaskManager  — deeper green
            0x00161B23, // LogView
            0x00604818, // Files        — amber (preserved)
            0x00141822, // Clock
            0x00702070, // GfxDemo
            0x002A323C, // Settings
            0x00256B36, // ImageView    — green-tinted
            0x002A323C, // About        — slate panel
            0x002A323C, // Help         — same as About
            0x002A323C, // Browser      — slate panel
            0x002A323C, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00141A22, 0x00F3F0E6, 0x00141A22, 0x000F1319, 0x00141A22, 0x000B0E13, 0x00000000,
            0x00141A22, // Settings
            0x00080A0E, // ImageView
            0x00141A22, // About
            0x00141A22, // Help
            0x00141A22, // Browser
            0x00141A22, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .console_fg = 0x00E8EDF2,
    .console_bg = 0x000F1319,
    .cursor_outline = 0x000B0E13,
    .cursor_fill = 0x00E8EDF2,
    .title_bar_height = 30,
    .taskbar_height = 44,
    .title_button_width = 46,
    .title_text_scale = 2,
    .font_kind = Theme::FontKind::Ttf,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 255,
    .shadow_intensity_inactive = 128,
    .hover_lift_alpha = 255,
    .press_alpha = 255,
    .focus_glow_colour = 0xF5B73A,
    .cursor_microshadow_enabled = true,

    // Pass B - motion_intensity: full
    .motion_intensity = 255,
};

// DuetClassic — the prototype's "classic mode" sibling.
// Win9x-era grey panels (#C0C0C0) carrying Duet's dual-accent
// teal/amber title hues, so the layout / role identity story
// is preserved while the surface palette swings into retro
// territory. Useful as a stress-test for the chrome paths
// against a light client + dark title combination, and as a
// nostalgic option distinct from the modern slate.
constexpr Theme kDuetClassic = {
    .name = "duetclassic",

    // Desktop: Win9x teal — the iconic 256-colour "Teal" the
    // base PC desktop shipped with through the late '90s.
    .desktop_bg = 0x00008080,
    .banner_fg = 0x00FFFFFF,

    // Taskbar: classic light-grey panel with a dark border —
    // maps to the Win98 chrome language but uses Duet's accent
    // for the active-tab indicator + START fill.
    .taskbar_bg = 0x00C0C0C0,
    .taskbar_fg = 0x00000000,
    .taskbar_accent = 0x002DD4BF, // teal — Duet's primary accent
    .taskbar_tab_inactive = 0x00A8A8A8,
    .taskbar_border = 0x00404040,

    // Window border: Win9x dark-grey 3D bevel approximation;
    // close button takes the Duet red so it reads as the same
    // affordance across the family.
    .window_border = 0x00808080,
    .window_close = 0x00E3413C,

    .role_title =
        {
            0x00207A6F, // Calculator   — teal-tinted (utility)
            0x00805E20, // Notes        — amber-tinted (paper)
            0x00164D45, // TaskManager  — deeper teal
            0x00404040, // LogView      — flat grey panel
            0x00604818, // Files        — amber-tinted
            0x00404040, // Clock        — flat grey
            0x00702070, // GfxDemo      — magenta marker
            0x00404040, // Settings     — flat grey panel
            0x00204878, // ImageView    — Win9x dark blue, "viewer" hue
            0x00404040, // About        — flat grey panel
            0x00404040, // Help         — flat grey panel
            0x00204878, // Browser      — Win9x dark blue (matches ImageView)
            0x00204878, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00C0C0C0, // Calculator   — Win9x panel grey
            0x00FFFFFF, // Notes        — paper white
            0x00C0C0C0, // TaskManager
            0x00DCDCDC, // LogView      — light off-white for log readability
            0x00C0C0C0, // Files
            0x00000000, // Clock        — black ground for retro 7-seg
            0x00000000, // GfxDemo
            0x00C0C0C0, // Settings     — Win9x panel grey
            0x00000000, // ImageView    — black ground for image
            0x00C0C0C0, // About        — Win9x panel grey
            0x00C0C0C0, // Help         — Win9x panel grey
            0x00FFFFFF, // Browser      — paper white for readability
            0x00FFFFFF, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x00000000,
    .console_bg = 0x00FFFFFF,

    // Cursor: classic black on white — matches the Win9x
    // pointer the chrome evokes.
    .cursor_outline = 0x00000000,
    .cursor_fill = 0x00FFFFFF,

    // Classic mode keeps the smaller 22-px title bar — the
    // cosier proportions match the era's UI.
    .title_bar_height = 22,
    .taskbar_height = 28,
    .title_button_width = 0,
    .title_text_scale = 1,
    .font_kind = Theme::FontKind::Bitmap8x8,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = true,
    .shadow_intensity_active = 160,
    .shadow_intensity_inactive = 80,
    .hover_lift_alpha = 200,
    .press_alpha = 200,
    .focus_glow_colour = 0,
    .cursor_microshadow_enabled = false,

    // Pass B - motion_intensity: full (Duet variant)
    .motion_intensity = 255,
};

// HighContrast — accessibility-first theme. Pure black bg,
// pure white text, pure cyan / yellow accents picked for
// maximum luminance contrast against black per WCAG AAA.
// Every role uses the SAME title hue (yellow) so users with
// colour-blindness aren't relying on hue distinction;
// per-role differentiation falls back to title-text content.
// 2-px+ borders on every chrome element, no gradients.
constexpr Theme kHighContrast = {
    .name = "highcontrast",

    .desktop_bg = 0x00000000,
    .banner_fg = 0x00FFFFFF,

    .taskbar_bg = 0x00000000,
    .taskbar_fg = 0x00FFFFFF,
    .taskbar_accent = 0x00FFFF00, // bright yellow start button
    .taskbar_tab_inactive = 0x00202020,
    .taskbar_border = 0x00FFFFFF, // 1-px white top edge

    .window_border = 0x00FFFFFF, // crisp white border on every window
    .window_close = 0x00FFFF00,  // yellow close — high contrast on black

    .role_title =
        {
            0x00FFFF00, // Calculator   — yellow on black, max contrast
            0x00FFFF00, // Notes
            0x00FFFF00, // TaskManager
            0x00FFFF00, // LogView
            0x00FFFF00, // Files
            0x00FFFF00, // Clock
            0x00FFFF00, // GfxDemo
            0x00FFFF00, // Settings
            0x00FFFF00, // ImageView
            0x00FFFF00, // About
            0x00FFFF00, // Help
            0x00FFFF00, // Browser
            0x00FFFF00, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },
    .role_client =
        {
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, // Settings
            0x00000000, // ImageView
            0x00000000, // About
            0x00000000, // Help
            0x00000000, // Browser
            0x00000000, // Calendar  — same as Browser/About/Help (info-panel family)
            0x00305880, // NotifyCenter
            0x00306070, // Sysmon  — teal "monitor" hue, shared across themes pending tuning
            0x00404858, // HexView — slate "tool" hue
            0x00604070, // CharMap — muted-purple "utility" hue
            0x00202830, // Terminal — near-black slate "console" hue
        },

    .console_fg = 0x00FFFFFF,
    .console_bg = 0x00000000,

    // Cursor: pure white outline + fill — visible on every
    // background including the all-black chrome.
    .cursor_outline = 0x00FFFFFF,
    .cursor_fill = 0x00FFFF00,

    // Compact dimensions — high-contrast users often run on
    // smaller / lower-res displays, so the chrome stays
    // tight rather than chunky.
    .title_bar_height = 22,
    .taskbar_height = 28,
    .title_button_width = 0,
    .title_text_scale = 1,
    .font_kind = Theme::FontKind::Bitmap8x8,

    // chrome tactility (Pass A) - per-theme matrix
    .tactility_enabled = false,
    .shadow_intensity_active = 0,
    .shadow_intensity_inactive = 0,
    .hover_lift_alpha = 0,
    .press_alpha = 0,
    .focus_glow_colour = 0xFFFFFF,
    .cursor_microshadow_enabled = false,

    // Pass B - motion_intensity: 0 (double-gated: tactility_enabled=false + motion=0)
    .motion_intensity = 0,
};

const Theme* const kThemes[static_cast<u32>(ThemeId::kCount)] = {
    &kClassic,  &kSlate10,    &kAmber,     &kDuet,        &kDuetLight,
    &kDuetBlue, &kDuetViolet, &kDuetGreen, &kDuetClassic, &kHighContrast,
};

// ---------------------------------------------------------------
// Live state. A single theme id + a handle-per-role table. The
// handle table is populated by main.cpp during boot after each
// WindowRegister returns; subsequent theme switches walk it to
// re-chrome every live window in one pass.
// ---------------------------------------------------------------

// Duet is the default — the redesigned palette is now the primary
// face of DuetOS. Classic / Slate10 / Amber / DuetLight / the accent
// variants stay reachable through Ctrl+Alt+Y or the kernel cmdline,
// but a fresh boot lands in the dual-accent slate world the
// prototype calls home.
constinit ThemeId g_current = ThemeId::Duet;
constinit WindowHandle g_role_window[static_cast<u32>(ThemeRole::kCount)] = {
    kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid,
    kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid, kWindowInvalid,
};

} // namespace

const Theme& ThemeCurrent()
{
    return *kThemes[static_cast<u32>(g_current)];
}

ThemeId ThemeCurrentId()
{
    return g_current;
}

void ThemeSet(ThemeId id)
{
    if (static_cast<u32>(id) >= static_cast<u32>(ThemeId::kCount))
    {
        return;
    }
    g_current = id;
}

void ThemeCycle()
{
    const u32 next = (static_cast<u32>(g_current) + 1) % static_cast<u32>(ThemeId::kCount);
    g_current = static_cast<ThemeId>(next);
}

bool ThemeIdFromName(const char* s, ThemeId* out)
{
    if (s == nullptr || out == nullptr)
        return false;
    for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
    {
        if (StrEqualCaseInsensitive(s, kThemes[i]->name))
        {
            *out = static_cast<ThemeId>(i);
            return true;
        }
    }
    return false;
}

const char* ThemeIdName(ThemeId id)
{
    if (static_cast<u32>(id) >= static_cast<u32>(ThemeId::kCount))
        return "unknown";
    return kThemes[static_cast<u32>(id)]->name;
}

WindowHandle ThemeRoleWindow(ThemeRole role)
{
    const u32 idx = static_cast<u32>(role);
    if (idx >= static_cast<u32>(ThemeRole::kCount))
        return kWindowInvalid;
    const WindowHandle h = g_role_window[idx];
    if (h == kWindowInvalid || !WindowIsAlive(h))
        return kWindowInvalid;
    return h;
}

bool ThemeRoleForWindow(WindowHandle h, ThemeRole* out)
{
    if (out == nullptr || h == kWindowInvalid)
    {
        return false;
    }
    for (u32 i = 0; i < static_cast<u32>(ThemeRole::kCount); ++i)
    {
        if (g_role_window[i] == h)
        {
            *out = static_cast<ThemeRole>(i);
            return true;
        }
    }
    return false;
}

void ThemeRegisterWindow(ThemeRole role, WindowHandle h)
{
    const u32 idx = static_cast<u32>(role);
    if (idx >= static_cast<u32>(ThemeRole::kCount))
        return;
    g_role_window[idx] = h;
    // Role-tracked windows are the kernel's permanent boot apps —
    // Calculator / Notes / TaskManager / LogView / Files / Clock /
    // GfxDemo. These are always-present from the user's
    // perspective, so we mark them pinned so the taskbar paints
    // a smaller (8-px) active-tab focus dot than running ring-3
    // PE windows get (14-px). Ring-3 windows registered via
    // SYS_WIN_CREATE never call ThemeRegisterWindow, so this
    // automatically gives the right hint for both classes.
    WindowSetPinned(h, true);
}

void ThemeApplyToAll()
{
    const Theme& t = ThemeCurrent();

    // Windows: each registered role gets its chrome re-published.
    for (u32 i = 0; i < static_cast<u32>(ThemeRole::kCount); ++i)
    {
        const WindowHandle h = g_role_window[i];
        if (h == kWindowInvalid || !WindowIsAlive(h))
            continue;
        WindowSetColours(h, t.window_border, t.role_title[i], t.role_client[i], t.window_close);
    }

    // Taskbar colours + console ink / bg + cursor backing all get
    // refreshed. The caller triggers DesktopCompose afterwards —
    // these calls only update state, they don't paint.
    TaskbarSetColours(t.taskbar_bg, t.taskbar_fg, t.taskbar_accent, t.taskbar_tab_inactive, t.taskbar_border);
    ConsoleSetColours(t.console_fg, t.console_bg);
    CursorSetDesktopBackground(t.desktop_bg);
    CursorSetColours(t.cursor_outline, t.cursor_fill);

    // Start menu / popup palette: body = inactive-tab recess panel
    // (taskbar's "darkest" surface so the menu reads as a deeper
    // layer than the bar), border + accent map directly, ink uses
    // the bright `taskbar_fg` so labels are legible against the
    // recess body.
    MenuSetColours(t.taskbar_tab_inactive, t.taskbar_border, t.taskbar_fg, t.taskbar_accent);

    // Calendar popup: same body / border / ink as the menu so the
    // two popups feel like siblings; header takes the taskbar
    // accent so the month name reads with the brand colour.
    CalendarSetColours(t.taskbar_tab_inactive, t.taskbar_border, t.taskbar_accent, t.taskbar_fg);

    // Network flyout panel: same chrome language as the calendar /
    // start menu, with a button colour that matches the title-bar
    // accent (the RENEW button reads as a callable affordance).
    NetPanelSetColours(t.taskbar_tab_inactive, t.taskbar_border, t.taskbar_accent, t.taskbar_fg, t.taskbar_accent);

    // Tray flyout (chevron-up popup): shares the menu / calendar
    // body palette so all popups feel like siblings. Both
    // accents (primary + secondary) flow through so the row
    // values can highlight in the appropriate hue (online =
    // primary teal, dhcp pending = secondary amber, etc.).
    {
        // The Duet-family theme stores its secondary accent as
        // a fixed amber across all variants — pick it up from the
        // taskbar_accent when the variant isn't a Duet (so
        // non-Duet themes get a sensible fallback that doesn't
        // clash with their primary). On Duet-family palettes the
        // secondary accent is always 0x00F5B73A; we encode that
        // as a constant here rather than threading another field
        // through Theme.
        const ThemeId tid = ThemeCurrentId();
        const bool is_duet_family = tid == ThemeId::Duet || tid == ThemeId::DuetLight || tid == ThemeId::DuetBlue ||
                                    tid == ThemeId::DuetViolet || tid == ThemeId::DuetGreen ||
                                    tid == ThemeId::DuetClassic;
        const u32 accent_2 = is_duet_family ? 0x00F5B73A : t.taskbar_accent;
        TrayFlyoutSetColours(t.taskbar_tab_inactive, t.taskbar_border, t.taskbar_fg,
                             // Dim ink — derived from `taskbar_fg` by mixing toward
                             // the chrome bg. Same approximation the prototype uses
                             // for `--ink-3`.
                             ((t.taskbar_fg >> 1) & 0x007F7F7F) + ((t.taskbar_bg >> 1) & 0x007F7F7F), t.taskbar_accent,
                             accent_2);
    }
}

namespace
{
// File-scope PASS tracker for the boot umbrella aggregator. Set
// by the success branch of ThemeSelfTest; read by
// ThemeSelfTestPassed(). Initially false so an absent or
// FAILed self-test never lights up the umbrella line.
bool s_theme_passed = false;
} // namespace

void ThemeSelfTest()
{
    using duetos::arch::SerialWrite;

    s_theme_passed = false;
    const ThemeId saved = g_current;
    bool pass = true;
    u32 failed_step = 0;
    auto mark_fail = [&](u32 step)
    {
        if (pass)
        {
            pass = false;
            failed_step = step;
        }
    };

    // 1. Every id maps to a non-null Theme with a non-null name.
    for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
    {
        if (kThemes[i] == nullptr)
        {
            mark_fail(1);
            break;
        }
        if (kThemes[i]->name == nullptr || kThemes[i]->name[0] == '\0')
        {
            mark_fail(1);
            break;
        }
    }

    // 2. ThemeIdName is in-range for every id and returns the
    // matching palette's .name.
    if (pass)
    {
        for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
        {
            const auto id = static_cast<ThemeId>(i);
            const char* n = ThemeIdName(id);
            if (n == nullptr || !StrEqualCaseInsensitive(n, kThemes[i]->name))
            {
                mark_fail(2);
                break;
            }
        }
    }

    // 3. ThemeIdFromName round-trips every registered name.
    if (pass)
    {
        for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
        {
            ThemeId got = ThemeId::Classic;
            if (!ThemeIdFromName(kThemes[i]->name, &got) || static_cast<u32>(got) != i)
            {
                mark_fail(3);
                break;
            }
        }
    }

    // 4. ThemeIdFromName rejects unknown strings.
    if (pass)
    {
        ThemeId dummy = ThemeId::Classic;
        if (ThemeIdFromName("not-a-theme", &dummy) || ThemeIdFromName(nullptr, &dummy))
        {
            mark_fail(4);
        }
    }

    // 5. ThemeCycle visits every id exactly once over kCount
    // calls, returning to the starting point. Use a bit-mask
    // to detect duplicates or missed ids.
    if (pass)
    {
        g_current = ThemeId::Classic;
        u32 seen = 0;
        for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
        {
            seen |= (1u << static_cast<u32>(g_current));
            ThemeCycle();
        }
        const u32 expected = (1u << static_cast<u32>(ThemeId::kCount)) - 1u;
        if (seen != expected || g_current != ThemeId::Classic)
        {
            mark_fail(5);
        }
    }

    g_current = saved;

    // Tactility-matrix invariants (chrome tactility, Pass A spec §8.2).
    // Every theme that advertises tactility_enabled must populate the
    // shadow-intensity bytes (otherwise the chrome paints flat — a
    // silent "I'm enabled but nothing happens" regression). Active
    // shadow must be >= inactive (focused window should never look
    // dimmer than a sibling on the same desktop). And HighContrast +
    // Amber MUST stay opted out — the high-contrast use-case can't
    // afford the legibility hit, the amber-CRT aesthetic breaks with
    // soft shadows.
    if (pass)
    {
        for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
        {
            const Theme& t = *kThemes[i];
            if (t.tactility_enabled)
            {
                if (t.shadow_intensity_active == 0)
                {
                    SerialWrite("[theme-selftest] FAIL (tactility enabled but shadow intensity zero)\n");
                    KBP_PROBE_V(debug::ProbeId::kTactilityThemeMismatch, i);
                    mark_fail(6);
                    break;
                }
                if (t.shadow_intensity_active < t.shadow_intensity_inactive)
                {
                    SerialWrite("[theme-selftest] FAIL (active shadow dimmer than inactive)\n");
                    KBP_PROBE_V(debug::ProbeId::kTactilityThemeMismatch, i);
                    mark_fail(6);
                    break;
                }
            }
        }
    }
    if (pass)
    {
        if (kThemes[static_cast<u32>(ThemeId::HighContrast)]->tactility_enabled ||
            kThemes[static_cast<u32>(ThemeId::Amber)]->tactility_enabled)
        {
            SerialWrite("[theme-selftest] FAIL (HighContrast/Amber must opt out)\n");
            KBP_PROBE(debug::ProbeId::kTactilityThemeMismatch);
            mark_fail(7);
        }
    }

    // Pass B invariants — motion_intensity.
    //
    // (1) HighContrast must have motion_intensity == 0 AND tactility_enabled == false.
    //     Double-gate is intentional: tactility_enabled is the master,
    //     motion_intensity is the per-effect knob. Either alone disables motion.
    if (pass)
    {
        const Theme& hc = *kThemes[static_cast<u32>(ThemeId::HighContrast)];
        if (hc.tactility_enabled || hc.motion_intensity != 0)
        {
            SerialWrite("[theme-selftest] FAIL HighContrast motion gate broken\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB0);
            mark_fail(8);
        }
    }
    // (2) Classic must have motion_intensity < 128 (subdued — see spec §7).
    if (pass)
    {
        const Theme& cl = *kThemes[static_cast<u32>(ThemeId::Classic)];
        if (cl.motion_intensity >= 128)
        {
            SerialWrite("[theme-selftest] FAIL Classic motion_intensity not subdued\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB1);
            mark_fail(9);
        }
    }
    // (3) Every other theme with tactility_enabled must have motion_intensity == 255.
    if (pass)
    {
        for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
        {
            if (i == static_cast<u32>(ThemeId::HighContrast) || i == static_cast<u32>(ThemeId::Classic))
                continue;
            const Theme& t = *kThemes[i];
            if (t.tactility_enabled && t.motion_intensity != 255)
            {
                SerialWrite("[theme-selftest] FAIL non-classic non-hc not full motion\n");
                KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB2);
                mark_fail(10);
                break;
            }
        }
    }

    if (pass)
    {
        SerialWrite("[theme] self-test OK (palette table + name round-trip + cycle)\n");
        SerialWrite("[theme-selftest] tactility-matrix PASS (10/10, hc-amber-opt-out=verified)\n");
        SerialWrite("[theme-selftest] motion-intensity PASS (hc-double-gate + classic-subdued + others-full)\n");
        s_theme_passed = true;
    }
    else
    {
        char msg[64] = "[theme] self-test FAILED at step ";
        u32 o = 33;
        msg[o++] = static_cast<char>('0' + (failed_step % 10));
        msg[o++] = '\n';
        msg[o] = '\0';
        SerialWrite(msg);
    }
}

// ----- Tactility runtime override -----
//
// `-1` = follow active theme's compile-time tactility_enabled.
// `0` = force OFF (every chrome path reads ThemeTactilityEffective
//       as false, falls back to solid-colour paint).
// `1` = force ON (overrides HighContrast / Amber opt-out — useful
//       for screenshot capture but cosmetically wrong; expected to
//       be a debugging affordance only).
constinit i8 g_tactility_override = -1;

i8 ThemeTactilityOverride()
{
    return g_tactility_override;
}

void ThemeSetTactilityOverride(i8 v)
{
    // Clamp to {-1, 0, 1}; any other value collapses to -1
    // (the "follow theme default" state), so a typo in a
    // cmdline never leaves the system in a wedged third state.
    if (v == 0 || v == 1 || v == -1)
    {
        g_tactility_override = v;
    }
    else
    {
        g_tactility_override = -1;
    }
}

bool ThemeTactilityEffective()
{
    const i8 ov = g_tactility_override;
    if (ov == 0)
    {
        return false;
    }
    if (ov == 1)
    {
        return true;
    }
    return ThemeCurrent().tactility_enabled;
}

u8 ThemeIntensityEffective(u8 raw)
{
    if (raw == 0 && g_tactility_override == 1)
    {
        return kThemeForceOnDefaultIntensity;
    }
    return raw;
}

bool ThemeSelfTestPassed()
{
    return s_theme_passed;
}

} // namespace duetos::drivers::video
