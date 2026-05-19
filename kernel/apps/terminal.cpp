#include "apps/terminal.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/console.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
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

// SGR attribute flags packed into a single u8 per cell. We only
// honour bits that the v0 painter can render with a monochrome
// fg/bg pair: bold maps to a brighter ink, underline draws a
// hline under the cell, reverse swaps ink/bg. The cursor cell is
// tracked via g_state.cur_x/cur_y + cur_visible rather than a
// per-cell attribute bit.
constexpr u8 kAttrBold = 1u << 0;
constexpr u8 kAttrUnderline = 1u << 1;
constexpr u8 kAttrReverse = 1u << 2;

struct Cell
{
    u32 cp;
    u8 attr;
    u8 _pad[3];
};

struct State
{
    WindowHandle handle;
    util::vt::Parser parser;

    u32 cols;
    u32 rows;
    Cell grid[kMaxRows * kMaxCols];

    u32 cur_x;
    u32 cur_y;
    u8 cur_attr;
    bool cur_visible;
    u8 _pad[2];
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, {}, 0, 0, 0, true, {}};

// ---- Grid primitives -------------------------------------------

Cell& At(u32 x, u32 y)
{
    return g_state.grid[y * kMaxCols + x];
}

void ClearCell(Cell& c)
{
    c.cp = 0;
    c.attr = 0;
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

void ScrollUp()
{
    // Shift every row up by one, blank the last visible row.
    if (g_state.rows == 0)
        return;
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

void DoSgr(const u16* params, u32 nparams)
{
    if (nparams == 0)
    {
        g_state.cur_attr = 0;
        return;
    }
    for (u32 i = 0; i < nparams; ++i)
    {
        const u16 p = params[i];
        switch (p)
        {
        case 0:
            g_state.cur_attr = 0;
            break;
        case 1:
            g_state.cur_attr |= kAttrBold;
            break;
        case 4:
            g_state.cur_attr |= kAttrUnderline;
            break;
        case 7:
            g_state.cur_attr |= kAttrReverse;
            break;
        case 22:
            g_state.cur_attr &= ~kAttrBold;
            break;
        case 24:
            g_state.cur_attr &= ~kAttrUnderline;
            break;
        case 27:
            g_state.cur_attr &= ~kAttrReverse;
            break;
        default:
            // Colours are deferred. v0 is monochrome; ignore.
            break;
        }
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
    const u32 ink_normal = t.banner_fg;
    const u32 ink_bold = 0x00FFFFFFu;   // brightened ink for SGR bold
    const u32 bg_default = 0x00101020u; // a near-black terminal ground
    // Fill the client rect with the terminal ground so any
    // earlier paint underneath us doesn't bleed through.
    FramebufferFillRect(cx, cy, cw, ch, bg_default);

    const u32 grid_x0 = cx + kPad;
    const u32 grid_y0 = cy + kPad;

    for (u32 y = 0; y < g_state.rows; ++y)
    {
        const u32 row_y = grid_y0 + y * kCellH;
        for (u32 x = 0; x < g_state.cols; ++x)
        {
            const Cell& c = At(x, y);
            u32 fg = (c.attr & kAttrBold) ? ink_bold : ink_normal;
            u32 bg = bg_default;
            const bool is_cursor = (x == g_state.cur_x && y == g_state.cur_y && g_state.cur_visible);
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
}

WindowHandle TerminalWindow()
{
    return g_state.handle;
}

bool TerminalFeedChar(char c)
{
    // Route every keystroke into the kernel shell's input API.
    // The shell's response flows back to us through the console
    // mirror — no local echo here. This is the "merge": the
    // windowed terminal and the framebuffer console both write
    // to the same shell, and both read its output via the same
    // ConsoleWrite* path.
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
    // Forward up/down to the shell's history cycle. Left/right
    // line editing inside the input buffer is not supported by
    // the v0 shell, so we swallow those silently.
    if (keycode == duetos::drivers::input::kKeyArrowUp)
    {
        duetos::core::ShellHistoryPrev();
        return true;
    }
    if (keycode == duetos::drivers::input::kKeyArrowDown)
    {
        duetos::core::ShellHistoryNext();
        return true;
    }
    return true;
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

} // namespace

void TerminalSelfTest()
{
    // Save real state, install a clean one.
    State saved = g_state;
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

    g_state = saved;
    if (ok)
        arch::SerialWrite("[terminal-selftest] PASS\n");
}

} // namespace duetos::apps::terminal
