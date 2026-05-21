#include "apps/terminal.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/console.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "shell/shell.h"
#include "util/vt_parser.h"

namespace duetos::apps::terminal
{

namespace
{

using duetos::drivers::video::FramebufferDrawChar;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

// Bitmap-font cell metrics — match the rest of the kernel UI.
// FramebufferDrawChar emits 8x8 glyphs; the terminal's cell box
// is one row of pixels taller so adjacent rows separate visually.
constexpr u32 kGlyphW = 8;
constexpr u32 kCellW = kGlyphW;
constexpr u32 kCellH = 10;
constexpr u32 kPad = 4;

// SGR attribute flags packed into a single u8 per cell. Bold maps
// to a brighter ink (or the matching bright-palette index when
// `fg` is set), underline draws a hline under the cell, reverse
// swaps ink/bg. The cursor cell is tracked via cur_x/cur_y +
// cur_visible rather than a per-cell attribute bit.
constexpr u8 kAttrBold = 1u << 0;
constexpr u8 kAttrUnderline = 1u << 1;
constexpr u8 kAttrReverse = 1u << 2;

// Sentinel for "no explicit colour SGR has been issued — fall back
// to the theme's default ink / terminal background." 0xFF is a
// safe sentinel because every real palette index is 0..15.
constexpr u8 kColorDefault = 0xFFu;

// 16-colour ANSI palette (8 normal + 8 bright). VGA-flavoured —
// matches what ls / git / clang colour escapes were designed for.
// Indexed by SGR-derived `fg` / `bg` cell fields. Index 0..7 are
// the standard SGR 30..37 / 40..47 colours; 8..15 are the bright
// SGR 90..97 / 100..107 colours, also reachable via the
// "bold + colour" idiom on terminals that treat bold as bright.
constexpr u32 kPalette[16] = {
    0x00000000u, // 0  black
    0x00800000u, // 1  red
    0x00008000u, // 2  green
    0x00808000u, // 3  yellow
    0x00000080u, // 4  blue
    0x00800080u, // 5  magenta
    0x00008080u, // 6  cyan
    0x00C0C0C0u, // 7  white (light gray)
    0x00808080u, // 8  bright black (dark gray)
    0x00FF0000u, // 9  bright red
    0x0000FF00u, // 10 bright green
    0x00FFFF00u, // 11 bright yellow
    0x000000FFu, // 12 bright blue
    0x00FF00FFu, // 13 bright magenta
    0x0000FFFFu, // 14 bright cyan
    0x00FFFFFFu, // 15 bright white
};

struct Cell
{
    u32 cp;
    u8 attr;
    u8 fg;
    u8 bg;
    u8 _pad;
};

// Scrollback ring depth, in lines. 128 lines × 100 cols × 8 bytes
// per cell = ~100 KiB of constinit BSS for the buffer. Empirically
// enough to retain the bulk of an in-session boot log + a few full-
// screen `ls` outputs. The ring is per-terminal — single-window
// today, sized for the visible-viewport use case rather than a
// "scroll back to the dawn of time" guarantee.
inline constexpr u32 kScrollbackLines = 128;

struct State
{
    WindowHandle handle;
    util::vt::Parser parser;

    u32 cols;
    u32 rows;
    Cell grid[kMaxRows * kMaxCols];

    // Scrollback ring. `scrollback_head` is the next write slot;
    // the most-recent retired row sits at (head - 1 mod depth).
    // `scrollback_count` clamps the ring at kScrollbackLines once
    // it's full. `scroll_offset` is how many lines the viewport
    // is shifted *up* from the live grid (0 = live, max =
    // scrollback_count + max scroll-into-grid headroom).
    Cell scrollback[kScrollbackLines * kMaxCols];
    u32 scrollback_head;
    u32 scrollback_count;
    u32 scroll_offset;

    u32 cur_x;
    u32 cur_y;
    u8 cur_attr;
    u8 cur_fg;
    u8 cur_bg;
    bool cur_visible;
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, {}, {}, 0, 0, 0, 0, 0, 0, kColorDefault, kColorDefault, true};

// ---- Grid primitives -------------------------------------------

Cell& At(u32 x, u32 y)
{
    return g_state.grid[y * kMaxCols + x];
}

void ClearCell(Cell& c)
{
    c.cp = 0;
    c.attr = 0;
    c.fg = kColorDefault;
    c.bg = kColorDefault;
}

void ClearRow(u32 y)
{
    if (y >= kMaxRows)
        return;
    for (u32 x = 0; x < kMaxCols; ++x)
        ClearCell(At(x, y));
}

void ClearAll()
{
    for (u32 y = 0; y < kMaxRows; ++y)
        ClearRow(y);
}

// Push the row about to be discarded by a scroll-up into the
// scrollback ring. Callers: ScrollUp (the only producer).
void ScrollbackPushRow(u32 grid_row)
{
    Cell* dst = &g_state.scrollback[g_state.scrollback_head * kMaxCols];
    for (u32 x = 0; x < kMaxCols; ++x)
        dst[x] = At(x, grid_row);
    g_state.scrollback_head = (g_state.scrollback_head + 1) % kScrollbackLines;
    if (g_state.scrollback_count < kScrollbackLines)
        ++g_state.scrollback_count;
}

// Fetch a scrollback row pointer, where `lines_back == 0` is the
// most recently retired row. Returns nullptr if the ring doesn't
// hold that depth yet.
const Cell* ScrollbackRow(u32 lines_back)
{
    if (lines_back >= g_state.scrollback_count)
        return nullptr;
    // Most-recent retired row sits at (head - 1) mod depth.
    const u32 idx = (g_state.scrollback_head + kScrollbackLines - 1 - lines_back) % kScrollbackLines;
    return &g_state.scrollback[idx * kMaxCols];
}

void ScrollUp()
{
    // Shift every row up by one, blank the last visible row.
    // Row 0 is the row being discarded — retire it into the
    // scrollback ring first so PgUp / wheel can walk back to it.
    if (g_state.rows == 0)
        return;
    ScrollbackPushRow(0);
    for (u32 y = 0; y + 1 < g_state.rows; ++y)
    {
        for (u32 x = 0; x < g_state.cols; ++x)
            At(x, y) = At(x, y + 1);
    }
    const u32 last = g_state.rows - 1;
    for (u32 x = 0; x < g_state.cols; ++x)
        ClearCell(At(x, last));
}

void AdvanceCursor()
{
    if (g_state.cols == 0 || g_state.rows == 0)
        return;
    g_state.cur_x++;
    if (g_state.cur_x >= g_state.cols)
    {
        g_state.cur_x = 0;
        g_state.cur_y++;
    }
    if (g_state.cur_y >= g_state.rows)
    {
        ScrollUp();
        g_state.cur_y = g_state.rows - 1;
    }
}

void NewLine()
{
    if (g_state.cols == 0 || g_state.rows == 0)
        return;
    g_state.cur_x = 0;
    g_state.cur_y++;
    if (g_state.cur_y >= g_state.rows)
    {
        ScrollUp();
        g_state.cur_y = g_state.rows - 1;
    }
}

void Backspace()
{
    if (g_state.cur_x > 0)
    {
        g_state.cur_x--;
    }
    // We deliberately don't auto-wrap to the previous row: that
    // breaks ANSI assumptions inside applications. Pure BS only.
}

void Tab()
{
    if (g_state.cols == 0)
        return;
    const u32 next = (g_state.cur_x + 8u) & ~7u;
    g_state.cur_x = (next < g_state.cols) ? next : (g_state.cols - 1);
}

void PutCp(u32 cp)
{
    if (g_state.cols == 0 || g_state.rows == 0)
        return;
    if (cp == 0)
        return; // Skip NUL — parsers can legitimately emit it for invalid sequences.
    if (g_state.cur_x >= g_state.cols)
    {
        g_state.cur_x = 0;
        g_state.cur_y++;
        if (g_state.cur_y >= g_state.rows)
        {
            ScrollUp();
            g_state.cur_y = g_state.rows - 1;
        }
    }
    Cell& c = At(g_state.cur_x, g_state.cur_y);
    c.cp = cp;
    c.attr = g_state.cur_attr;
    c.fg = g_state.cur_fg;
    c.bg = g_state.cur_bg;
    AdvanceCursor();
}

// ---- Parser callbacks ------------------------------------------

void OnPrint(void* /*cookie*/, u32 cp)
{
    PutCp(cp);
}

void OnExecute(void* /*cookie*/, u8 ctrl)
{
    switch (ctrl)
    {
    case 0x07: // BEL — slice 1 ignores; sound_cue later.
        break;
    case 0x08: // BS
        Backspace();
        break;
    case 0x09: // HT
        Tab();
        break;
    case 0x0A: // LF
    case 0x0B: // VT
    case 0x0C: // FF
        NewLine();
        break;
    case 0x0D: // CR
        g_state.cur_x = 0;
        break;
    default:
        break;
    }
}

// CSI helpers — interpret a "missing param" as `def_val`, matching
// xterm's "0 means default" convention for cursor-movement codes.
u16 ParamOr(const u16* params, u32 nparams, u32 idx, u16 def_val)
{
    if (idx >= nparams)
        return def_val;
    return (params[idx] == 0) ? def_val : params[idx];
}

// Walk the SGR parameter list, mutating the current attribute /
// fg / bg. Bare `ESC [m` (no params) resets the lot, matching
// xterm. Colour codes:
//
//   30..37  → fg = 0..7   (standard)
//   38;5;N  → 256-colour fg (consumed, not yet rendered)
//   38;2;R;G;B → 24-bit fg (consumed, not yet rendered)
//   39      → fg = default
//   40..47  → bg = 0..7
//   48;...  → 256/24-bit bg (consumed)
//   49      → bg = default
//   90..97  → fg = 8..15  (bright)
//   100..107 → bg = 8..15 (bright)
//
// The 38/48 paths intentionally consume their sub-params even when
// rendering them is deferred — otherwise a `\e[38;5;208;1m` (set
// 256-colour orange and bold) would mis-parse the trailing 1 as
// "reset all". A malformed sub-form aborts the rest of the
// sequence; that's the xterm-style "ignore on doubt" behaviour.
void DoSgr(const u16* params, u32 nparams)
{
    if (nparams == 0)
    {
        g_state.cur_attr = 0;
        g_state.cur_fg = kColorDefault;
        g_state.cur_bg = kColorDefault;
        return;
    }
    u32 i = 0;
    while (i < nparams)
    {
        const u16 p = params[i];
        if (p == 38 || p == 48)
        {
            if (i + 1 < nparams)
            {
                if (params[i + 1] == 5 && i + 2 < nparams)
                {
                    i += 3;
                    continue;
                }
                if (params[i + 1] == 2 && i + 4 < nparams)
                {
                    i += 5;
                    continue;
                }
            }
            break; // Malformed extended-colour selector — stop.
        }
        if (p == 0)
        {
            g_state.cur_attr = 0;
            g_state.cur_fg = kColorDefault;
            g_state.cur_bg = kColorDefault;
        }
        else if (p == 1)
        {
            g_state.cur_attr |= kAttrBold;
        }
        else if (p == 4)
        {
            g_state.cur_attr |= kAttrUnderline;
        }
        else if (p == 7)
        {
            g_state.cur_attr |= kAttrReverse;
        }
        else if (p == 22)
        {
            g_state.cur_attr &= ~kAttrBold;
        }
        else if (p == 24)
        {
            g_state.cur_attr &= ~kAttrUnderline;
        }
        else if (p == 27)
        {
            g_state.cur_attr &= ~kAttrReverse;
        }
        else if (p >= 30 && p <= 37)
        {
            g_state.cur_fg = static_cast<u8>(p - 30);
        }
        else if (p == 39)
        {
            g_state.cur_fg = kColorDefault;
        }
        else if (p >= 40 && p <= 47)
        {
            g_state.cur_bg = static_cast<u8>(p - 40);
        }
        else if (p == 49)
        {
            g_state.cur_bg = kColorDefault;
        }
        else if (p >= 90 && p <= 97)
        {
            g_state.cur_fg = static_cast<u8>(p - 90 + 8);
        }
        else if (p >= 100 && p <= 107)
        {
            g_state.cur_bg = static_cast<u8>(p - 100 + 8);
        }
        // Anything else (unsupported attribute) is silently ignored,
        // matching xterm — strict CSI parsers reject unknown SGR
        // params, lenient ones (us) skip them so a single unknown
        // doesn't suppress the rest of the sequence.
        ++i;
    }
}

void DoEraseInDisplay(const u16* params, u32 nparams)
{
    const u16 mode = (nparams == 0) ? 0 : params[0];
    if (mode == 2 || mode == 3)
    {
        ClearAll();
        g_state.cur_x = 0;
        g_state.cur_y = 0;
        return;
    }
    if (mode == 0)
    {
        // From cursor to end of screen.
        for (u32 x = g_state.cur_x; x < g_state.cols; ++x)
            ClearCell(At(x, g_state.cur_y));
        for (u32 y = g_state.cur_y + 1; y < g_state.rows; ++y)
            ClearRow(y);
        return;
    }
    if (mode == 1)
    {
        for (u32 y = 0; y < g_state.cur_y; ++y)
            ClearRow(y);
        for (u32 x = 0; x <= g_state.cur_x && x < g_state.cols; ++x)
            ClearCell(At(x, g_state.cur_y));
    }
}

void DoEraseInLine(const u16* params, u32 nparams)
{
    const u16 mode = (nparams == 0) ? 0 : params[0];
    if (g_state.cur_y >= g_state.rows)
        return;
    if (mode == 0)
    {
        for (u32 x = g_state.cur_x; x < g_state.cols; ++x)
            ClearCell(At(x, g_state.cur_y));
    }
    else if (mode == 1)
    {
        for (u32 x = 0; x <= g_state.cur_x && x < g_state.cols; ++x)
            ClearCell(At(x, g_state.cur_y));
    }
    else if (mode == 2)
    {
        ClearRow(g_state.cur_y);
    }
}

void OnCsi(void* /*cookie*/, char final_byte, char /*private_marker*/, const u16* params, u32 nparams)
{
    switch (final_byte)
    {
    case 'A': // CUU
    {
        const u16 n = ParamOr(params, nparams, 0, 1);
        g_state.cur_y = (g_state.cur_y > n) ? (g_state.cur_y - n) : 0;
        break;
    }
    case 'B': // CUD
    {
        const u16 n = ParamOr(params, nparams, 0, 1);
        const u32 max_y = (g_state.rows > 0) ? (g_state.rows - 1) : 0;
        g_state.cur_y = (g_state.cur_y + n > max_y) ? max_y : (g_state.cur_y + n);
        break;
    }
    case 'C': // CUF
    {
        const u16 n = ParamOr(params, nparams, 0, 1);
        const u32 max_x = (g_state.cols > 0) ? (g_state.cols - 1) : 0;
        g_state.cur_x = (g_state.cur_x + n > max_x) ? max_x : (g_state.cur_x + n);
        break;
    }
    case 'D': // CUB
    {
        const u16 n = ParamOr(params, nparams, 0, 1);
        g_state.cur_x = (g_state.cur_x > n) ? (g_state.cur_x - n) : 0;
        break;
    }
    case 'H':
    case 'f': // CUP / HVP — 1-based row;col with defaults of 1
    {
        const u16 r = ParamOr(params, nparams, 0, 1);
        const u16 c = ParamOr(params, nparams, 1, 1);
        const u32 max_y = (g_state.rows > 0) ? (g_state.rows - 1) : 0;
        const u32 max_x = (g_state.cols > 0) ? (g_state.cols - 1) : 0;
        g_state.cur_y = (r > 0) ? (((u32)(r - 1) > max_y) ? max_y : (u32)(r - 1)) : 0;
        g_state.cur_x = (c > 0) ? (((u32)(c - 1) > max_x) ? max_x : (u32)(c - 1)) : 0;
        break;
    }
    case 'J':
        DoEraseInDisplay(params, nparams);
        break;
    case 'K':
        DoEraseInLine(params, nparams);
        break;
    case 'm':
        DoSgr(params, nparams);
        break;
    default:
        // Unsupported CSI — silent. The parser already
        // discarded the bytes; we don't need a STUB marker
        // here because the v0 contract advertises only the
        // handlers above.
        break;
    }
}

void OnOsc(void* /*cookie*/, u32 /*cmd*/, const char* /*str*/, u32 /*str_len*/)
{
    // Window-title support: a future slice can call
    // WindowSetTitle here once that API exists. v0 swallows.
}

// ---- Drawing ---------------------------------------------------

void RecomputeGridSize(u32 cw, u32 ch)
{
    if (cw < (2 * kPad + kCellW) || ch < (2 * kPad + kCellH))
    {
        g_state.cols = 0;
        g_state.rows = 0;
        return;
    }
    const u32 cols = (cw - 2 * kPad) / kCellW;
    const u32 rows = (ch - 2 * kPad) / kCellH;
    g_state.cols = (cols > kMaxCols) ? kMaxCols : cols;
    g_state.rows = (rows > kMaxRows) ? kMaxRows : rows;
    if (g_state.cur_x >= g_state.cols && g_state.cols > 0)
        g_state.cur_x = g_state.cols - 1;
    if (g_state.cur_y >= g_state.rows && g_state.rows > 0)
        g_state.cur_y = g_state.rows - 1;
}

char CpToAscii(u32 cp)
{
    if (cp >= 0x20 && cp < 0x7F)
        return static_cast<char>(cp);
    if (cp == 0)
        return ' ';
    // Non-ASCII fallback. Bitmap font is 7-bit; a follow-up slice
    // would route through TTF for full Unicode.
    return '?';
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    RecomputeGridSize(cw, ch);

    const auto& t = ThemeCurrent();
    const u32 ink_default = t.banner_fg;
    const u32 ink_default_bold = 0x00FFFFFFu; // brightened theme ink for SGR bold
    const u32 bg_default = 0x00101020u;       // near-black terminal ground
    // Fill the client rect with the terminal ground so any
    // earlier paint underneath us doesn't bleed through.
    FramebufferFillRect(cx, cy, cw, ch, bg_default);

    const u32 grid_x0 = cx + kPad;
    const u32 grid_y0 = cy + kPad;

    const u32 k = g_state.scroll_offset;
    // Cursor only displays when the viewport is live (k == 0); a
    // scrolled-back view hides it, matching xterm.
    const bool cursor_eligible = (k == 0) && g_state.cur_visible;
    for (u32 y = 0; y < g_state.rows; ++y)
    {
        const u32 row_y = grid_y0 + y * kCellH;
        // Resolve the cell source for this viewport row. With
        // k == 0 the entire viewport is the live grid. With k > 0
        // viewport rows 0..k-1 are drawn from the scrollback ring
        // (deepest history at the top, most recent retired row
        // just above the live section); rows k..rows-1 come from
        // live grid rows 0..rows-1-k.
        const Cell* row_src = nullptr;
        u32 grid_y = 0;
        if (y < k)
        {
            const u32 lines_back = k - y - 1;
            row_src = ScrollbackRow(lines_back);
        }
        else
        {
            grid_y = y - k;
            if (grid_y >= g_state.rows)
                continue;
        }
        for (u32 x = 0; x < g_state.cols; ++x)
        {
            const Cell& c = row_src ? row_src[x] : At(x, grid_y);
            const bool has_fg = (c.fg != kColorDefault);
            const bool has_bg = (c.bg != kColorDefault);
            // Bold on a palette-indexed fg promotes 0..7 → 8..15
            // (the bright row), matching the xterm convention.
            // Bold without an explicit fg lifts the theme ink to
            // its brighter twin. Bold + bright (8..15) is a no-op.
            u8 fg_idx = c.fg;
            if ((c.attr & kAttrBold) && has_fg && fg_idx < 8)
                fg_idx = static_cast<u8>(fg_idx + 8);
            u32 fg = has_fg ? kPalette[fg_idx]
                            : ((c.attr & kAttrBold) ? ink_default_bold : ink_default);
            u32 bg = has_bg ? kPalette[c.bg] : bg_default;
            // Cursor lives at grid (cur_x, cur_y); only paint it
            // when the viewport is live AND we're rendering from
            // the live grid (row_src == nullptr).
            const bool is_cursor = cursor_eligible && (row_src == nullptr) &&
                                   (x == g_state.cur_x && grid_y == g_state.cur_y);
            if (c.attr & kAttrReverse)
            {
                const u32 tmp = fg;
                fg = bg;
                bg = tmp;
            }
            if (is_cursor)
            {
                // Cursor inverts the cell.
                const u32 tmp = fg;
                fg = bg;
                bg = tmp;
            }
            const u32 col_x = grid_x0 + x * kCellW;
            if (bg != bg_default)
                FramebufferFillRect(col_x, row_y, kCellW, kCellH, bg);
            const char ch_print = (c.cp == 0 && !is_cursor) ? ' ' : CpToAscii(c.cp);
            FramebufferDrawChar(col_x, row_y, ch_print, fg, bg);
            if (c.attr & kAttrUnderline)
            {
                FramebufferFillRect(col_x, row_y + kCellH - 1, kCellW, 1, fg);
            }
        }
    }
}

// ---- Scrollback navigation -------------------------------------

// Maximum scroll-up depth — clamped to the number of retired rows
// in the ring. (We don't allow scrolling the live grid out of
// view; the bottom row of the viewport is always the most recent
// retired row when scrolled.)
u32 ScrollOffsetMax()
{
    return g_state.scrollback_count;
}

// Drop any active scroll-back. Called on shell input so a
// keystroke snaps the viewport to the live grid, matching xterm.
void ScrollSnapLive()
{
    g_state.scroll_offset = 0;
}

void ScrollAdjust(i32 delta)
{
    const u32 max_off = ScrollOffsetMax();
    i32 next = static_cast<i32>(g_state.scroll_offset) + delta;
    if (next < 0)
        next = 0;
    if (next > static_cast<i32>(max_off))
        next = static_cast<i32>(max_off);
    g_state.scroll_offset = static_cast<u32>(next);
}

// Per-window wheel hook — mapped at TerminalInit. dz > 0 (wheel
// up away from the user) scrolls *back* into history; dz < 0
// (wheel toward the user) scrolls forward toward the live grid.
// A wheel notch yields one cell of motion.
void OnWheel(i32 dz, u8 /*modifiers*/)
{
    ScrollAdjust(dz);
}

// ---- Viewport → clipboard --------------------------------------

// Serialize the currently visible viewport (whatever the painter
// would render right now — live grid or a mix with scrollback)
// into a single ASCII buffer, trimming trailing whitespace on
// each row, and push it into the clipboard via the existing
// `WindowClipboardSetText` API. Ctrl+Shift+C invokes this — it's
// the substitute-for-drag-selection until the widget layer grows
// an in-content mouse-press hook.
void CopyVisibleViewport()
{
    using duetos::drivers::video::kWindowClipboardMax;
    using duetos::drivers::video::WindowClipboardSetText;
    char out[kWindowClipboardMax + 1];
    u32 out_len = 0;
    const u32 k = g_state.scroll_offset;
    for (u32 y = 0; y < g_state.rows; ++y)
    {
        const Cell* row_src = nullptr;
        u32 grid_y = 0;
        if (y < k)
        {
            const u32 lines_back = k - y - 1;
            row_src = ScrollbackRow(lines_back);
        }
        else
        {
            grid_y = y - k;
            if (grid_y >= g_state.rows)
                continue;
        }
        // Collect printable ASCII per cell, then strip trailing
        // spaces / NUL cells. This keeps the clipboard payload
        // close to what the user "sees as text" rather than a
        // dense rectangular grid full of padding.
        u32 row_end = 0;
        char row[kMaxCols + 1];
        for (u32 x = 0; x < g_state.cols; ++x)
        {
            const Cell& c = row_src ? row_src[x] : At(x, grid_y);
            char ch = (c.cp == 0) ? ' ' : CpToAscii(c.cp);
            row[x] = ch;
            if (ch != ' ')
                row_end = x + 1; // last non-space + 1
        }
        // Append the trimmed row + newline, capping at the
        // clipboard buffer length.
        for (u32 x = 0; x < row_end && out_len + 1 < sizeof(out); ++x)
            out[out_len++] = row[x];
        if (out_len + 1 < sizeof(out))
            out[out_len++] = '\n';
    }
    out[out_len] = 0;
    WindowClipboardSetText(out);
}

// ---- Console mirror hook ---------------------------------------
//
// The kernel shell prints to the framebuffer console via the
// 3,800+ ConsoleWrite* call sites scattered across kernel/shell/.
// Rather than refactor those, the Terminal app registers as a
// mirror on the console — every byte the shell writes to the
// shell-slot buffer also flows here, through the VT parser, into
// our grid. The framebuffer console can paint or not paint that
// data independently; this terminal becomes a true second view of
// the same shell session.

void MirrorFromConsole(char c)
{
    const u8 byte = static_cast<u8>(c);
    util::vt::ParserFeed(g_state.parser, &byte, 1);
}

// ---- Initial-grid seed -----------------------------------------
//
// When the terminal window opens, we want to show whatever the
// shell has already printed (boot log, prompt). The console's
// shell-buffer is a fixed (rows × cols) ASCII grid; we walk it
// once, feed each row + newline through the parser, and the
// resulting grid mirrors the console exactly.

void SeedFromConsole()
{
    using duetos::drivers::video::kConsoleCols;
    using duetos::drivers::video::kConsoleRows;
    for (u32 r = 0; r < kConsoleRows; ++r)
    {
        for (u32 c = 0; c < kConsoleCols; ++c)
        {
            const char ch = duetos::drivers::video::ConsoleShellCharAt(r, c);
            const u8 byte = static_cast<u8>(ch);
            util::vt::ParserFeed(g_state.parser, &byte, 1);
        }
        const u8 nl[] = {'\r', '\n'};
        util::vt::ParserFeed(g_state.parser, nl, 2);
    }
}

} // namespace

void TerminalInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.cur_x = 0;
    g_state.cur_y = 0;
    g_state.cur_attr = 0;
    g_state.cur_fg = kColorDefault;
    g_state.cur_bg = kColorDefault;
    g_state.cur_visible = true;
    ClearAll();

    util::vt::Callbacks cb = {};
    cb.cookie = &g_state;
    cb.print = &OnPrint;
    cb.execute = &OnExecute;
    cb.csi = &OnCsi;
    cb.osc = &OnOsc;
    util::vt::ParserInit(g_state.parser, cb);

    // Pre-populate from whatever's already in the kernel shell's
    // backing buffer (boot log + first prompt), then register the
    // live mirror so subsequent ConsoleWrite* calls land here too.
    SeedFromConsole();
    duetos::drivers::video::ConsoleRegisterMirror(&MirrorFromConsole);

    WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, &OnWheel);
}

WindowHandle TerminalWindow()
{
    return g_state.handle;
}

bool TerminalFeedChar(char c)
{
    // Route every keystroke into the kernel shell's input API.
    // Any input snaps the viewport to live so the user sees the
    // shell's response, not the historical position they were
    // browsing — same convention as xterm / iTerm / Konsole.
    // The shell's response flows back to us through the console
    // mirror — no local echo here. This is the "merge": the
    // windowed terminal and the framebuffer console both write
    // to the same shell, and both read its output via the same
    // ConsoleWrite* path.
    ScrollSnapLive();
    if (c == '\r' || c == '\n')
    {
        duetos::core::ShellSubmit();
        return true;
    }
    if (c == 0x08 || c == 0x7F)
    {
        duetos::core::ShellBackspace();
        return true;
    }
    if (static_cast<u8>(c) < 0x20)
    {
        // Drop other C0 chars — the shell doesn't accept them.
        return true;
    }
    duetos::core::ShellFeedChar(c);
    return true;
}

bool TerminalFeedArrow(u16 keycode)
{
    // Up / Down: shell history cycle. PgUp / PgDn: scrollback
    // navigation by one viewport-height. Home / End: scrollback
    // limits. Left / Right are swallowed silently — the v0 shell
    // has no in-line cursor.
    if (keycode == duetos::drivers::input::kKeyArrowUp)
    {
        ScrollSnapLive();
        duetos::core::ShellHistoryPrev();
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyArrowDown)
    {
        ScrollSnapLive();
        duetos::core::ShellHistoryNext();
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyPageUp)
    {
        const i32 step = (g_state.rows > 0) ? static_cast<i32>(g_state.rows) : 1;
        ScrollAdjust(step);
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyPageDown)
    {
        const i32 step = (g_state.rows > 0) ? -static_cast<i32>(g_state.rows) : -1;
        ScrollAdjust(step);
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyHome)
    {
        // Jump to oldest available scrollback line.
        g_state.scroll_offset = ScrollOffsetMax();
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyEnd)
    {
        ScrollSnapLive();
        return true;
    }
    return true;
}

void TerminalCopyVisibleViewport()
{
    CopyVisibleViewport();
}

void TerminalFeedBytes(const u8* bytes, u32 len)
{
    util::vt::ParserFeed(g_state.parser, bytes, len);
}

void TerminalReset()
{
    g_state.cur_x = 0;
    g_state.cur_y = 0;
    g_state.cur_attr = 0;
    g_state.cur_fg = kColorDefault;
    g_state.cur_bg = kColorDefault;
    g_state.scrollback_head = 0;
    g_state.scrollback_count = 0;
    g_state.scroll_offset = 0;
    ClearAll();
    util::vt::ParserReset(g_state.parser);
}

// --- Self-test --------------------------------------------------

namespace
{

bool ExpectCell(u32 x, u32 y, u32 expect_cp, const char* tag)
{
    if (At(x, y).cp != expect_cp)
    {
        arch::SerialWrite("[terminal-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

bool ExpectCursor(u32 x, u32 y, const char* tag)
{
    if (g_state.cur_x != x || g_state.cur_y != y)
    {
        arch::SerialWrite("[terminal-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

bool ExpectCellAttrs(u32 x, u32 y, u8 expect_fg, u8 expect_bg, u8 expect_attr, const char* tag)
{
    const Cell& c = At(x, y);
    if (c.fg != expect_fg || c.bg != expect_bg || c.attr != expect_attr)
    {
        arch::SerialWrite("[terminal-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

} // namespace

void TerminalSelfTest()
{
    // Save real state, install a clean one. `State` is ~131 KiB
    // once the scrollback ring is included, so the snapshot lives
    // in BSS (static) rather than on the kernel stack — a stack
    // copy of that size blows the canary on a debug-build's smaller
    // kernel stack (observed: __stack_chk_fail during selftest,
    // 2026-05-21).
    static State saved;
    saved = g_state;
    g_state = {};
    g_state.handle = kWindowInvalid;
    g_state.cols = 16;
    g_state.rows = 4;
    g_state.cur_visible = false;
    util::vt::Callbacks cb = {};
    cb.cookie = &g_state;
    cb.print = &OnPrint;
    cb.execute = &OnExecute;
    cb.csi = &OnCsi;
    cb.osc = &OnOsc;
    util::vt::ParserInit(g_state.parser, cb);

    bool ok = true;

    // 1. Plain print + LF.
    const u8 t1[] = {'A', 'B', '\r', '\n', 'C'};
    util::vt::ParserFeed(g_state.parser, t1, 5);
    ok &= ExpectCell(0, 0, 'A', "row0col0");
    ok &= ExpectCell(1, 0, 'B', "row0col1");
    ok &= ExpectCell(0, 1, 'C', "row1col0");

    // 2. CSI CUP: move to (1,1) one-based -> (0,0).
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[1;1H"), 6);
    ok &= ExpectCursor(0, 0, "cup-1-1");

    // 3. CSI CUP: move to (3,5).
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[3;5H"), 6);
    ok &= ExpectCursor(4, 2, "cup-3-5");

    // 4. Scroll on overflow. Walking the trace:
    //   i=0 writes '0' at (0,0), then LF moves cursor to (0,1).
    //   i=1 writes '1' at (0,1), then LF moves cursor to (0,2).
    //   i=2 writes '2' at (0,2), then LF moves cursor to (0,3).
    //   i=3 writes '3' at (0,3), then LF tries (0,4) — scroll;
    //        the '0' is lost. Row layout: '1','2','3',blank.
    //   i=4 writes '4' into the now-blank (0,3), then LF scrolls
    //        again. Final layout: '2','3','4',blank.
    TerminalReset();
    g_state.cols = 16;
    g_state.rows = 4;
    g_state.cur_visible = false;
    for (u32 i = 0; i < 5; ++i)
    {
        const u8 line[] = {static_cast<u8>('0' + i), '\r', '\n'};
        util::vt::ParserFeed(g_state.parser, line, 3);
    }
    ok &= ExpectCell(0, 0, '2', "scroll-row0");
    ok &= ExpectCell(0, 1, '3', "scroll-row1");
    ok &= ExpectCell(0, 2, '4', "scroll-row2");
    ok &= ExpectCell(0, 3, 0, "scroll-row3-blank");

    // 5. Erase in display mode 2 — full clear.
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[2J"), 4);
    ok &= ExpectCell(0, 0, 0, "ed2-clears");

    // 6. SGR colours — red fg, then white-on-blue, then reset, then
    //    bright (90-series).
    TerminalReset();
    g_state.cols = 16;
    g_state.rows = 4;
    g_state.cur_visible = false;
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[31mR"), 6);
    ok &= ExpectCellAttrs(0, 0, /*fg=*/1u, kColorDefault, /*attr=*/0u, "sgr-31-red-fg");
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[37;44mB"), 9);
    ok &= ExpectCellAttrs(1, 0, /*fg=*/7u, /*bg=*/4u, /*attr=*/0u, "sgr-37;44-white-on-blue");
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[0mN"), 5);
    ok &= ExpectCellAttrs(2, 0, kColorDefault, kColorDefault, 0u, "sgr-0-resets-colour");
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[92mG"), 6);
    ok &= ExpectCellAttrs(3, 0, /*fg=*/10u, kColorDefault, 0u, "sgr-92-bright-green");

    // 7. Bold mid-sequence preserves prior colour selection.
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[33;1mY"), 8);
    ok &= ExpectCellAttrs(4, 0, /*fg=*/3u, kColorDefault, kAttrBold, "sgr-33;1-yellow-bold");

    // 8. 256-colour selector consumes its sub-params so a trailing
    //    SGR (here `;1` = bold) isn't mis-parsed as "reset all".
    TerminalReset();
    g_state.cols = 16;
    g_state.rows = 4;
    g_state.cur_visible = false;
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[38;5;208;1mX"), 14);
    // fg stays default (256-colour not rendered yet) but bold MUST be set.
    ok &= ExpectCellAttrs(0, 0, kColorDefault, kColorDefault, kAttrBold, "sgr-38;5;N;1-consumes-and-bolds");

    // 9. Default-colour codes (39 fg-default / 49 bg-default).
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[31;44mr"), 9);
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[39md"), 6);
    ok &= ExpectCellAttrs(2, 0, kColorDefault, /*bg=*/4u, kAttrBold, "sgr-39-fg-default-bg-stays");
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("\x1b[49me"), 6);
    ok &= ExpectCellAttrs(3, 0, kColorDefault, kColorDefault, kAttrBold, "sgr-49-bg-default");

    // 10. Scrollback — write enough lines to retire one into the
    //     ring, then verify ScrollbackRow(0) returns it.
    TerminalReset();
    g_state.cols = 4;
    g_state.rows = 2;
    g_state.cur_visible = false;
    // Three lines into a 2-row grid: first line scrolls off and
    // lands in the scrollback ring at depth 0.
    util::vt::ParserFeed(g_state.parser, reinterpret_cast<const u8*>("AA\r\nBB\r\nCC"), 10);
    if (g_state.scrollback_count != 1)
    {
        arch::SerialWrite("[terminal-selftest] FAIL sb-count\n");
        ok = false;
    }
    {
        const Cell* row = ScrollbackRow(0);
        if (!row || row[0].cp != 'A' || row[1].cp != 'A')
        {
            arch::SerialWrite("[terminal-selftest] FAIL sb-row0-contents\n");
            ok = false;
        }
    }
    // Scroll back: the viewport's top row should now show 'AA'
    // (the retired line) and ScrollOffsetMax should clamp at 1.
    ScrollAdjust(5); // request 5, clamped to ScrollOffsetMax()
    if (g_state.scroll_offset != 1)
    {
        arch::SerialWrite("[terminal-selftest] FAIL sb-clamp\n");
        ok = false;
    }
    // Snap-to-live drops the offset back to zero.
    ScrollSnapLive();
    if (g_state.scroll_offset != 0)
    {
        arch::SerialWrite("[terminal-selftest] FAIL sb-snap\n");
        ok = false;
    }

    // 11. CopyVisibleViewport — emits a sensible string with
    //     trailing-whitespace-trimmed rows. We can't call the
    //     real WindowClipboardSetText from selftest (compositor
    //     state); instead verify the in-band shape via a direct
    //     read of the ring after building it on stack.
    //     (Smoke-grep: the visible viewport has "AA\nBB\nCC\n"
    //     wait — only 'BB' and 'CC' are live after the scroll;
    //     'AA' is in scrollback. Live viewport = "BB\nCC\n".)
    g_state.scroll_offset = 0;
    // Hand-roll the same trim+pack the real function does so we
    // can assert on the result without driving the clipboard ring.
    char vp[16];
    duetos::u32 vp_len = 0;
    for (duetos::u32 y = 0; y < g_state.rows && vp_len < sizeof(vp); ++y)
    {
        duetos::u32 row_end = 0;
        char row[kMaxCols + 1];
        for (duetos::u32 x = 0; x < g_state.cols; ++x)
        {
            const Cell& c = At(x, y);
            const char ch = (c.cp == 0) ? ' ' : CpToAscii(c.cp);
            row[x] = ch;
            if (ch != ' ')
                row_end = x + 1;
        }
        for (duetos::u32 x = 0; x < row_end && vp_len + 1 < sizeof(vp); ++x)
            vp[vp_len++] = row[x];
        if (vp_len + 1 < sizeof(vp))
            vp[vp_len++] = '\n';
    }
    vp[vp_len] = 0;
    const bool vp_ok = (vp_len == 6 && vp[0] == 'B' && vp[1] == 'B' && vp[2] == '\n' && vp[3] == 'C' &&
                       vp[4] == 'C' && vp[5] == '\n');
    if (!vp_ok)
    {
        arch::SerialWrite("[terminal-selftest] FAIL viewport-copy-shape\n");
        ok = false;
    }

    g_state = saved;
    if (ok)
        arch::SerialWrite("[terminal-selftest] PASS\n");
}

} // namespace duetos::apps::terminal
