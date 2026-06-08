#include "apps/help.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::apps::help
{

namespace
{

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowGetBounds;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;
using duetos::drivers::video::WindowSetScrollHandler;
using duetos::drivers::video::WindowSetWheelHandler;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

constexpr u32 kRowH = 11;
constexpr u32 kSectionGap = 6;

// One row in the help table. `is_section` flips the formatter to
// paint the line as a section header (banner-fg colour, no
// indentation) instead of a normal binding row (indented + dim).
struct Row
{
    const char* text;
    bool is_section;
};

// Reference list. Must stay in lock-step with PrintShortcutHelp
// in kernel/core/menu_dispatch.cpp — both surfaces document the
// same bindings; if one drifts the other is wrong.
constexpr Row kRows[] = {
    {"GETTING STARTED", true},
    {"  CLICK [START] OR PRESS CTRL+ESC TO LAUNCH APPS", false},
    {"  CLICK A TASKBAR TAB TO RAISE THAT WINDOW", false},
    {"  DRAG A TITLE BAR TO MOVE A WINDOW", false},
    {"  [X] OR ALT+F4 TO CLOSE", false},
    {"WINDOWS", true},
    {"  ALT+TAB           CYCLE ACTIVE WINDOW", false},
    {"  CTRL+ALT+UP       MAXIMISE / RESTORE", false},
    {"  CTRL+ALT+DOWN     RESTORE / MINIMISE", false},
    {"  CTRL+ALT+LEFT/R   SNAP HALF-SCREEN", false},
    {"  CTRL+ALT+, / .    OPACITY DOWN / UP", false},
    {"DESKTOP / SYSTEM", true},
    {"  F1                THIS HELP", false},
    {"  CTRL+ALT+T        TOGGLE DESKTOP / TTY", false},
    {"  CTRL+ALT+L        LOCK / UNLOCK TASKBAR", false},
    {"  CTRL+ALT+K        LOCK SCREEN", false},
    {"  CTRL+ALT+Y        CYCLE THEME", false},
    {"  CTRL+ALT+1..9     PICK THEME DIRECTLY", false},
    {"  CTRL+ALT+P        SCREENSHOT TO SHOTNNNN.BMP", false},
    {"  CTRL+ALT+M        TOGGLE MAGNIFIER", false},
    {"  CTRL+C            INTERRUPT SHELL CMD", false},
    {"  CTRL+SHIFT+V      ROTATE CLIP HISTORY", false},
    {"NOTES", true},
    {"  CTRL+C / CTRL+V   COPY / PASTE CLIPBOARD", false},
    {"  CTRL+S / CTRL+O   SAVE / LOAD NOTES.TXT", false},
    {"  CTRL+F            FIND (case-insensitive)", false},
    {"  F3                FIND NEXT (wraps to start)", false},
    {"  CTRL+H            FIND-AND-REPLACE (two prompts)", false},
    {"  CTRL+A            SELECT ALL", false},
    {"  CTRL+G            GO TO LINE", false},
    {"  STATUS FOOTER     L:line C:col + word/char count", false},
    {"  *MOD              UNSAVED CHANGES", false},
    {"FILES", true},
    {"  UP / DN           MOVE SELECTION", false},
    {"  ENTER             OPEN (DESCEND / DISPATCH)", false},
    {"  B                 UP ONE LEVEL (RAM MODE)", false},
    {"  D / M / T         DISK / RAM / TRASH VIEW", false},
    {"  R                 RESCAN (DISK) / RESTORE (TRASH)", false},
    {"  S                 CYCLE SORT (NAME -> SIZE -> TYPE)", false},
    {"  X THEN Y          DISK: TO TRASH; TRASH: PERM-DEL", false},
    {"  E THEN Y          EMPTY TRASH (TRASH VIEW ONLY)", false},
    {"IMAGE VIEWER", true},
    {"  N / P / LEFT/RT   NEXT / PREV IMAGE", false},
    {"  R                 RESCAN DISK FOR IMAGES", false},
    {"  + / -             ZOOM IN / OUT (resize window)", false},
    {"  CTRL+WHEEL        ZOOM IN / OUT (mouse)", false},
    {"CALCULATOR", true},
    {"  0..9 + - * / =    BASIC ARITHMETIC", false},
    {"  C                 CLEAR", false},
    {"  %                 PERCENT", false},
    {"  N / _             SIGN TOGGLE", false},
    {"  BACKSPACE         REMOVE LAST DIGIT", false},
    {"  M / S             MEMORY RECALL / STORE", false},
    {"  A / B             MEMORY ADD / SUBTRACT", false},
    {"  L                 MEMORY CLEAR", false},
    {"  Q / X / Y / R / ! SQRT / SQUARE / ABS / 1OVERN / FACTORIAL", false},
    {"  & | ^             BITWISE AND / OR / XOR (binary)", false},
    {"  < / >             SHIFT LEFT / RIGHT (binary)", false},
    {"  ~                 BITWISE NOT (unary)", false},
    {"  HEX / BIN / OCT   shown live below decimal display", false},
    {"TASK MANAGER", true},
    {"  TAB               CYCLE PROCESSES / PERFORMANCE", false},
    {"  UP / DN PG/PG     MOVE SELECTION (PROCESSES TAB)", false},
    {"  S                 CYCLE SORT (CPU/PID/NAME/STATE)", false},
    {"  K / DEL           KILL SELECTED PROCESS (CONFIRM)", false},
    {"  R                 FORCE SNAPSHOT REBUILD", false},
    {"BROWSER", true},
    {"  U / TAB           URL EDIT", false},
    {"  ENTER             FETCH (in URL edit)", false},
    {"  B / F             BACK / FORWARD", false},
    {"  R                 RELOAD", false},
    {"  H / L             HISTORY / BOOKMARKS LIST", false},
    {"  M                 BOOKMARK CURRENT", false},
    {"  S                 SAVE TO DLNNNN.HTM", false},
    {"  J / K / UP / DN   SCROLL", false},
    {"CALENDAR", true},
    {"  [ ] LEFT/RT       PREV / NEXT MONTH", false},
    {"  { } UP / DN       PREV / NEXT YEAR", false},
    {"  T                 JUMP TO TODAY", false},
    {"  SHIFT+LEFT/RT     STEP SELECTION 1 DAY", false},
    {"  SHIFT+UP/DN       STEP SELECTION 7 DAYS", false},
    {"  ENTER             ADD EVENT (selected date)", false},
    {"  DEL               REMOVE EVENT (selected date)", false},
    {"  CTRL+S / CTRL+O   SAVE / LOAD CALENDAR.TXT", false},
    {"  *DOT*             cell carries an event", false},
    {"SETTINGS", true},
    {"  THEME / OPACITY / TZ / LOG OUT", false},
    {"  REBOOT / SHUTDOWN", false},
};

constexpr u32 kRowCount = sizeof(kRows) / sizeof(kRows[0]);

struct State
{
    WindowHandle handle;
};

constinit State g_state = {kWindowInvalid};

// Live filter — appended to by HelpFeedChar. Section headers
// pass through whenever at least one of their following rows
// matches, so the rendered output stays grouped.
constexpr u32 kFilterCap = 31;
constinit char g_filter[kFilterCap + 1] = {};
constinit u32 g_filter_len = 0;

// Scroll offset — number of matching rows skipped at the top.
// Reset to 0 when the filter changes so the result set always
// starts at the top of the visible band.
constinit u32 g_scroll_offset = 0;

char ToUpperAscii(char c)
{
    if (c >= 'a' && c <= 'z')
        return static_cast<char>(c - 32);
    return c;
}

// Case-insensitive substring search. Returns true iff `hay`
// contains `needle`. Empty needle matches everything.
bool ContainsCi(const char* hay, const char* needle)
{
    if (needle == nullptr || needle[0] == '\0')
        return true;
    if (hay == nullptr)
        return false;
    u32 nlen = 0;
    while (needle[nlen] != '\0')
        ++nlen;
    u32 hlen = 0;
    while (hay[hlen] != '\0')
        ++hlen;
    if (nlen > hlen)
        return false;
    for (u32 i = 0; i + nlen <= hlen; ++i)
    {
        bool ok = true;
        for (u32 j = 0; j < nlen; ++j)
        {
            if (ToUpperAscii(hay[i + j]) != ToUpperAscii(needle[j]))
            {
                ok = false;
                break;
            }
        }
        if (ok)
            return true;
    }
    return false;
}

// Resolve "should this row be drawn under the active filter?"
// for index `i`. Section headers (kRows[i].is_section) survive
// when at least one row following them (until the next section)
// matches; non-section rows must match directly.
bool ShouldRenderRow(u32 i)
{
    if (g_filter_len == 0)
        return true;
    if (kRows[i].is_section)
    {
        for (u32 j = i + 1; j < kRowCount && !kRows[j].is_section; ++j)
        {
            if (ContainsCi(kRows[j].text, g_filter))
                return true;
        }
        return false;
    }
    return ContainsCi(kRows[i].text, g_filter);
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 1 AppButton (CLEAR) + 3
// AppLabels (header "DUETOS QUICK REFERENCE", live filter
// readout, footer hint). The CLEAR toolbar action wipes the
// live filter — the only mutable state Help carries, and the
// keyboard-only filter affordance from v0 wasn't discoverable
// without reading the in-window hint.
//
// Carve-out that stays raw paint:
//   - The reference list itself (kRows): variable-length, with
//     section headers (banner_fg, no indent) interleaved with
//     binding rows (console_fg, indented). AppListRow has no
//     section-header model and no per-row colour split, and the
//     "(no match — Backspace to clear)" hint + "..." truncation
//     tail have no AppLabel equivalent in a list context. The
//     list paints inside the band DrawFn carves out between
//     the (toolbar + header + filter row) at the top and the
//     AppLabel footer at the bottom.

constexpr u32 kHelpToolbarH = 22U;
constexpr u32 kHelpToolbarBtnW = 56U;
constexpr u32 kHelpToolbarBtnH = 18U;
constexpr u32 kHelpToolbarBtnGap = 4U;
constexpr u32 kHelpToolbarPadX = 4U;
constexpr u32 kHelpToolbarPadY = 2U;
constexpr u32 kHelpHeaderH = kRowH + 4U;
constexpr u32 kHelpFilterH = kRowH + 4U;
constexpr u32 kHelpFooterH = kRowH + 2U;

// AppLabel stores text by pointer so the buffers must outlive
// every Paint. DrawFn re-renders them each frame.
constinit char g_header_text[40] = {};
constinit char g_filter_text[kFilterCap + 16] = {};
constinit char g_footer_text[64] = {};

// Forward decl for the toolbar click trampoline (defined below;
// it has to live above the constinit g_help that captures it
// by function-pointer value).
void ClickClear();

// Toolbar (back), then 1 action AppButton, then 3 AppLabels
// (header, filter readout, footer). Reverse declaration order
// is dispatch order — buttons get first refusal on clicks.
constinit auto g_help = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppLabel{}, AppLabel{}, AppLabel{});

constinit bool g_help_bound = false;
constinit bool g_help_prev_left_down = false;
constinit bool g_help_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to the action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 1 button -> 3
// labels).
AppButton* HelpActionButton()
{
    return &g_help.chain.tail.head; // toolbar -> btn[0]
}

// AppLabel accessors — header / filter / footer sit at chain
// positions 2, 3, 4 (zero-indexed) after the 1 toolbar + 1
// button.
AppLabel& HelpHeaderLabel()
{
    return g_help.chain.tail.tail.head;
}
AppLabel& HelpFilterLabel()
{
    return g_help.chain.tail.tail.tail.head;
}
AppLabel& HelpFooterLabel()
{
    return g_help.chain.tail.tail.tail.tail.head;
}

void BindHelpOnce()
{
    if (g_help_bound)
        return;
    g_help_bound = true;

    auto& toolbar = g_help.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    AppButton* btn = HelpActionButton();
    btn->label = "CLEAR";
    btn->on_click = ClickClear;
    btn->weight = ChromeTextWeight::Regular;
    btn->bg_rgb = 0; // theme role default
    btn->fg_rgb = 0x00101828U;

    const auto& th = ThemeCurrent();
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Help)];

    auto& header = HelpHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Body;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = dim;
    header.bg_rgb = bg;
    header.align_left = true;

    auto& filter = HelpFilterLabel();
    filter.text = g_filter_text;
    filter.role = ChromeTextRole::Body;
    filter.weight = ChromeTextWeight::Regular;
    filter.fg_rgb = fg;
    filter.bg_rgb = bg;
    filter.align_left = true;

    auto& footer = HelpFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = bg;
    footer.align_left = true;
}

// Re-anchor the toolbar + button + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// HelpMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindHelpBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_help.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kHelpToolbarH};

    {
        constexpr u32 i = 0U;
        const u32 bx = cx + kHelpToolbarPadX + i * (kHelpToolbarBtnW + kHelpToolbarBtnGap);
        HelpActionButton()->bounds = Rect{bx, cy + kHelpToolbarPadY, kHelpToolbarBtnW, kHelpToolbarBtnH};
    }

    // Header sits directly below the toolbar. Spans the client
    // width with an 8-px x-pad to match the legacy raw-paint
    // x-offset.
    const u32 header_y = cy + kHelpToolbarH;
    constexpr u32 kHeaderXPad = 8U;
    HelpHeaderLabel().bounds =
        Rect{cx + kHeaderXPad, header_y, (cw > kHeaderXPad) ? cw - kHeaderXPad : cw, kHelpHeaderH};

    // Filter readout sits directly below the header row.
    const u32 filter_y = header_y + kHelpHeaderH;
    HelpFilterLabel().bounds =
        Rect{cx + kHeaderXPad, filter_y, (cw > kHeaderXPad) ? cw - kHeaderXPad : cw, kHelpFilterH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kHelpFooterH) ? cy + ch - kHelpFooterH : cy;
    const u32 fw = (cw > kHeaderXPad) ? cw - kHeaderXPad : cw;
    HelpFooterLabel().bounds = Rect{cx + kHeaderXPad, fy, fw, kHelpFooterH};
}

void RefreshHelpHeader()
{
    static const char kHeader[] = "DUETOS QUICK REFERENCE";
    u32 i = 0;
    for (; kHeader[i] != '\0' && i + 1 < sizeof(g_header_text); ++i)
        g_header_text[i] = kHeader[i];
    g_header_text[i] = '\0';
}

void RefreshHelpFilter()
{
    // Live filter readout. "FIND: <chars>" when active, "TYPE
    // TO FILTER" placeholder otherwise. Matches the legacy raw-
    // paint right-aligned filter line, but rendered as an
    // AppLabel so theme + tactility-aware paint applies.
    const char* lead = (g_filter_len > 0) ? "FIND: " : "TYPE TO FILTER";
    u32 o = 0;
    for (u32 i = 0; lead[i] != '\0' && o + 1 < sizeof(g_filter_text); ++i)
        g_filter_text[o++] = lead[i];
    for (u32 i = 0; i < g_filter_len && o + 1 < sizeof(g_filter_text); ++i)
        g_filter_text[o++] = g_filter[i];
    g_filter_text[o] = '\0';
}

void RefreshHelpFooter()
{
    static const char kHint[] = "TYPE:filter  BKSP:undo  CLEAR:wipe  UP/DN/PG:scroll";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_help above captures it by function-pointer value. CLEAR
// wipes the live filter — a discoverable affordance for users
// who landed on the Help window without realising they could
// type into it.

void ClickClear()
{
    g_filter_len = 0;
    g_filter[0] = '\0';
    g_scroll_offset = 0;
}

// Count matching rows (section headers that pass because of
// their children are counted as virtual rows for scroll
// purposes). Returns the total number of rows that would be
// drawn if the window were infinitely tall, along with the
// number of full kRowH slots each match occupies (section
// headers consume 1 + kSectionGap/kRowH extra logical slots).
// For simplicity we count each passing entry as 1 row unit;
// section gaps are treated as fractional and ignored in the
// scroll ledger — the user scrolls by logical row index, not
// pixel.
u32 CountMatchingRows()
{
    u32 count = 0;
    for (u32 i = 0; i < kRowCount; ++i)
    {
        if (ShouldRenderRow(i))
            ++count;
    }
    return count;
}

// Paint the raw reference list (carve-out) inside the band
// DrawFn carves out between the (toolbar + header + filter row)
// at the top and the AppLabel footer at the bottom.
// Supports scrolling via g_scroll_offset (logical row index of
// the first visible row). A scrollbar is painted at the right
// edge when the content overflows the band.
void PaintHelpContent(u32 cx, u32 cy, u32 cw, u32 ch)
{
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Help)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    if (cw < 220 || ch < kRowH)
    {
        FramebufferDrawString(cx + 4, cy + 4, "(window too small)", dim, bg);
        return;
    }

    // Count how many rows are visible in the band and how many
    // rows pass the current filter. The scroll offset is clamped
    // here so paint + HelpFeedArrow always agree on bounds.
    const u32 max_rows = ch / kRowH; // full rows that fit
    const u32 total = CountMatchingRows();
    if (total == 0)
    {
        FramebufferDrawString(cx + 8, cy + 2, "(no match - Backspace to clear)", dim, bg);
        return;
    }
    if (max_rows > 0 && g_scroll_offset + max_rows > total && total > max_rows)
        g_scroll_offset = total - max_rows;
    else if (total <= max_rows)
        g_scroll_offset = 0;

    // Reserve the right edge for the scrollbar when we need one.
    const bool need_sb = (total > max_rows);
    const u32 sb_w = need_sb ? duetos::drivers::video::kScrollbarWidth : 0;
    const u32 content_w = (cw > sb_w) ? cw - sb_w : cw;

    u32 y = cy + 2;
    u32 logical_row = 0; // index among matching rows
    for (u32 i = 0; i < kRowCount; ++i)
    {
        if (!ShouldRenderRow(i))
            continue;
        if (logical_row < g_scroll_offset)
        {
            ++logical_row;
            continue;
        }
        if (y + kRowH > cy + ch)
            break;
        if (kRows[i].is_section)
        {
            // Small gap before each section header so the list
            // groups visually. Only apply when the header is
            // not the very first visible row.
            if (logical_row > g_scroll_offset)
            {
                y += kSectionGap;
                if (y + kRowH > cy + ch)
                {
                    ++logical_row;
                    continue;
                }
            }
            FramebufferDrawString(cx + 6, y, kRows[i].text, dim, bg);
        }
        else
        {
            FramebufferDrawString(cx + 8, y, kRows[i].text, fg, bg);
        }
        y += kRowH;
        ++logical_row;
    }

    // Scrollbar registration — visual indicator + kernel drag.
    if (need_sb && cw > sb_w)
    {
        const u32 sb_x = cx + content_w;
        duetos::drivers::video::ScrollbarPaint(sb_x, cy, sb_w, max_rows * kRowH, {total, max_rows, g_scroll_offset});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = cy;
        s.w = sb_w;
        s.h = max_rows * kRowH;
        s.total = total;
        s.visible = max_rows;
        s.first = g_scroll_offset;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    else
    {
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Help)];
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Pass D chrome: refresh the header / filter / footer text
    // from live state, re-anchor the toolbar + labels to the
    // current client rect, and paint the WidgetGroup. The raw
    // reference list (carve-out) sits in the band between the
    // header + filter rows and the AppLabel footer.
    BindHelpOnce();
    RefreshHelpHeader();
    RefreshHelpFilter();
    RefreshHelpFooter();
    RebindHelpBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_help.PaintAll(compose_ctx);

    // Content band — between (toolbar + header + filter row) at
    // the top and the AppLabel footer at the bottom.
    const u32 top_band = kHelpToolbarH + kHelpHeaderH + kHelpFilterH;
    const u32 bot_band = kHelpFooterH + 2U;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintHelpContent(list_x, list_y, list_w, list_h);
    }
}

} // namespace

bool HelpFeedArrow(duetos::u16 keycode)
{
    using namespace duetos::drivers::input;
    const u32 total = CountMatchingRows();
    if (total == 0)
        return true;
    // Compute max_rows from the live window geometry. Use a
    // conservative estimate (window height 280 minus chrome
    // bands) so the clamp doesn't depend on the compositor
    // lock being held. PaintHelpContent re-clamps on each
    // repaint, so a slightly off estimate here is harmless.
    const u32 top_band = kHelpToolbarH + kHelpHeaderH + kHelpFilterH;
    const u32 bot_band = kHelpFooterH + 2U;
    u32 wh = 302U; // default window client height
    if (g_state.handle != kWindowInvalid)
    {
        duetos::u32 wx = 0, wy = 0, ww = 0, wh_raw = 0;
        if (WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh_raw))
        {
            constexpr u32 kTitleH = 22U;
            wh = (wh_raw > kTitleH) ? wh_raw - kTitleH : wh_raw;
        }
    }
    const u32 ch = (wh > top_band + bot_band) ? (wh - top_band - bot_band) : 0;
    const u32 max_rows = (ch > 0) ? ch / kRowH : 1U;

    switch (keycode)
    {
    case kKeyArrowUp:
        if (g_scroll_offset > 0)
            --g_scroll_offset;
        return true;
    case kKeyArrowDown:
        if (total > max_rows && g_scroll_offset + max_rows < total)
            ++g_scroll_offset;
        return true;
    case kKeyPageUp:
        g_scroll_offset = (g_scroll_offset > max_rows) ? g_scroll_offset - max_rows : 0;
        return true;
    case kKeyPageDown:
        if (total > max_rows)
        {
            const u32 max_off = total - max_rows;
            g_scroll_offset = (g_scroll_offset + max_rows < max_off) ? g_scroll_offset + max_rows : max_off;
        }
        return true;
    case kKeyHome:
        g_scroll_offset = 0;
        return true;
    case kKeyEnd:
        g_scroll_offset = (total > max_rows) ? total - max_rows : 0;
        return true;
    default:
        return false;
    }
}

void HelpOnWheel(duetos::i32 dz, duetos::u8 /*modifiers*/)
{
    const u16 key = (dz > 0) ? duetos::drivers::input::kKeyArrowUp : duetos::drivers::input::kKeyArrowDown;
    const i32 steps = (dz > 0) ? dz : -dz;
    for (i32 i = 0; i < steps; ++i)
        HelpFeedArrow(key);
}

void HelpInit(WindowHandle handle)
{
    g_state.handle = handle;
    WindowSetContentDraw(handle, DrawFn, nullptr);
    WindowSetWheelHandler(handle, HelpOnWheel);
    WindowSetScrollHandler(handle, [](u32 first) { g_scroll_offset = first; });
    BindHelpOnce();
}

bool HelpFeedChar(char c)
{
    const u8 uc = static_cast<u8>(c);
    if (uc == 0x08) // Backspace — drop a char, or clear at zero
    {
        if (g_filter_len > 0)
        {
            --g_filter_len;
            g_filter[g_filter_len] = '\0';
            g_scroll_offset = 0; // result set changed — reset to top
        }
        return true;
    }
    // Accept printable ASCII (letters / digits / space /
    // punctuation), reject control codes including Enter /
    // Tab — those collide with global / per-app behaviours.
    if (c >= 0x20 && c <= 0x7E)
    {
        if (g_filter_len < kFilterCap)
        {
            g_filter[g_filter_len++] = c;
            g_filter[g_filter_len] = '\0';
            g_scroll_offset = 0; // result set changed — reset to top
        }
        return true;
    }
    return false;
}

WindowHandle HelpWindow()
{
    return g_state.handle;
}

void HelpSelfTest()
{
    using arch::SerialWrite;
    bool ok = (kRowCount > 0);

    // Every section header must be followed by at least one
    // non-section row. Catches a regression where the list grew
    // a stray "TITLE\n" with no bindings underneath.
    for (u32 i = 0; ok && i < kRowCount; ++i)
    {
        if (!kRows[i].is_section)
            continue;
        if (i + 1 >= kRowCount || kRows[i + 1].is_section)
        {
            ok = false;
            break;
        }
    }

    // ContainsCi case-insensitive match: positive + negative.
    if (!ContainsCi("CTRL+ALT+P", "ctrl"))
        ok = false;
    if (!ContainsCi("CTRL+ALT+P", "alt"))
        ok = false;
    if (!ContainsCi("CTRL+ALT+P", ""))
        ok = false; // empty needle matches all
    if (ContainsCi("CTRL+ALT+P", "zzzz"))
        ok = false;
    if (ContainsCi(nullptr, "ctrl"))
        ok = false;

    // HelpFeedChar: snapshot + restore around the mutations so
    // the test leaves the live filter exactly as it found it.
    char saved_filter[kFilterCap + 1];
    for (u32 i = 0; i < sizeof(saved_filter); ++i)
        saved_filter[i] = g_filter[i];
    const u32 saved_filter_len = g_filter_len;
    g_filter_len = 0;
    g_filter[0] = '\0';

    if (!HelpFeedChar('A'))
        ok = false;
    if (!HelpFeedChar('b'))
        ok = false;
    if (g_filter_len != 2 || g_filter[0] != 'A' || g_filter[1] != 'b')
        ok = false;
    // Backspace pops the most recent char.
    if (!HelpFeedChar(static_cast<char>(0x08)))
        ok = false;
    if (g_filter_len != 1 || g_filter[0] != 'A')
        ok = false;
    // Non-printable control codes are rejected.
    if (HelpFeedChar('\n'))
        ok = false;
    if (HelpFeedChar('\t'))
        ok = false;

    // Pass D: drive a synthetic click on the CLEAR toolbar
    // button via the WidgetGroup dispatch chain. ClickClear
    // wipes the live filter — pre-condition: filter is non-
    // empty (we just pushed 'A' above); post-condition:
    // g_filter_len == 0.
    BindHelpOnce();
    // Anchor the toolbar at (0, 22, 440, 280) — matches the
    // shape boot_bringup.cpp registers the live Help window
    // with (440x302 minus 22 px title bar). CLEAR is action
    // index 0.
    RebindHelpBounds(0U, 22U, 440U, 280U);
    constexpr u32 kClearIdx = 0U;
    const u32 nx = kHelpToolbarPadX + kClearIdx * (kHelpToolbarBtnW + kHelpToolbarBtnGap) + kHelpToolbarBtnW / 2U;
    const u32 ny = 22U + kHelpToolbarPadY + kHelpToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};

    if (g_help.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;
    if (g_help.DispatchEvent(n_down) != EventResult::Consumed)
        ok = false;
    if (g_help.DispatchEvent(n_up) != EventResult::Consumed)
        ok = false;
    if (g_filter_len != 0 || g_filter[0] != '\0')
        ok = false;

    // Header / filter / footer composers must produce non-
    // empty text after a refresh.
    RefreshHelpHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshHelpFilter();
    if (g_filter_text[0] == '\0')
        ok = false;
    RefreshHelpFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    // Restore the pre-test filter so a user with a typed
    // filter doesn't see it wiped at the next boot self-test
    // window paint.
    for (u32 i = 0; i < sizeof(saved_filter); ++i)
        g_filter[i] = saved_filter[i];
    g_filter_len = saved_filter_len;

    g_help_self_test_passed = ok;
    SerialWrite(ok ? "[help-selftest] PASS\n" : "[help-selftest] FAIL\n");
}

bool HelpSelfTestPassed()
{
    return g_help_self_test_passed;
}

void HelpMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the
    // same frame RebindHelpBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindHelpOnce();
    RebindHelpBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_help_prev_left_down;
    const bool release_edge = !left_down && g_help_prev_left_down;
    g_help_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_help.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw reference list sits below the
        // toolbar / header / filter rows the WidgetGroup
        // owns. DispatchEvent's hit-test naturally short-
        // circuits when the click misses the toolbar bounds
        // — the list has no per-row click semantics in v0
        // (filter management is keyboard-driven via
        // HelpFeedChar or the CLEAR toolbar button).
        // MouseDown still fires for the toolbar Pressed-
        // state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_help.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside
        // the toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_help.DispatchEvent(u);
    }
}

} // namespace duetos::apps::help
