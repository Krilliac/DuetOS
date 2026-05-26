#include "apps/charmap.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"

namespace duetos::apps::charmap
{

namespace
{

using duetos::drivers::video::FramebufferDrawRect;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferDrawStringScaled;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 12;
constexpr u32 kPad = 4;
constexpr u32 kCols = 16;
constexpr u32 kCellSize = 24;
constexpr u32 kAsciiStart = 0x20;
constexpr u32 kAsciiEnd = 0x7E;
constexpr u32 kFullStart = 0x20;
constexpr u32 kFullEnd = 0xFF;

struct State
{
    WindowHandle handle;
    bool full_range; // false = ASCII only; true = up to 0xFF
    u32 selection;   // current codepoint
};

constinit State g_state = {kWindowInvalid, false, kAsciiStart};

inline u32 CodepointStart()
{
    return g_state.full_range ? kFullStart : kAsciiStart;
}

inline u32 CodepointEnd()
{
    return g_state.full_range ? kFullEnd : kAsciiEnd;
}

inline u32 CodepointCount()
{
    return CodepointEnd() - CodepointStart() + 1;
}

inline u32 SelectionToIndex()
{
    return g_state.selection - CodepointStart();
}

inline void ClampSelection()
{
    if (g_state.selection < CodepointStart())
        g_state.selection = CodepointStart();
    if (g_state.selection > CodepointEnd())
        g_state.selection = CodepointEnd();
}

void FormatHexU32(char* out, u32 v, u32 digits)
{
    static const char kHex[] = "0123456789ABCDEF";
    for (u32 i = 0; i < digits; ++i)
    {
        out[digits - 1 - i] = kHex[v & 0xF];
        v >>= 4;
    }
    out[digits] = '\0';
}

void FormatDec(char* out, u32 cap, u32 v, u32* len_out)
{
    char tmp[12];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    u32 i = 0;
    while (n > 0 && i + 1 < cap)
        out[i++] = tmp[--n];
    out[i] = '\0';
    if (len_out)
        *len_out = i;
}

// Copy the selected codepoint to the kernel clipboard. ASCII
// stays ASCII; codepoints in [0x80, 0xFF] get a 2-byte UTF-8
// encoding (works for any byte the bitmap font may render
// AND for paste into other native apps that interpret bytes
// as UTF-8 — the legacy Notes / Calculator path treats them
// as opaque bytes so this still composes).
void CopySelectionToClipboard()
{
    char buf[5] = {};
    const u32 cp = g_state.selection;
    if (cp < 0x80)
    {
        buf[0] = static_cast<char>(cp);
        buf[1] = '\0';
    }
    else if (cp < 0x800)
    {
        buf[0] = static_cast<char>(0xC0 | (cp >> 6));
        buf[1] = static_cast<char>(0x80 | (cp & 0x3F));
        buf[2] = '\0';
    }
    else
    {
        // CharMap v0 only exposes codepoints up to 0xFF, so the
        // 3-byte branch is dead — kept here so a future expansion
        // (full BMP) doesn't need to revisit the encoder.
        buf[0] = static_cast<char>(0xE0 | (cp >> 12));
        buf[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = static_cast<char>(0x80 | (cp & 0x3F));
        buf[3] = '\0';
    }
    duetos::drivers::video::WindowClipboardSetText(buf);
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 2 AppButton entries
// (RNGE / COPY) + 3 AppLabel rows (selection summary header,
// range-mode line, and footer controls hint). The 2 toolbar
// buttons duplicate the keyboard shortcuts Tab and Enter/Space
// so the chrome stays discoverable without forcing fresh users
// to memorise the footer hint.
//
// Carve-out that stays raw paint:
//   - 16-column grid of kCellSize × kCellSize cells. The grid's
//     defining property is fixed-width cell alignment + per-cell
//     scale-2 glyph rendering + a 2-pixel accent border around
//     the selected cell. With the full range active we draw up
//     to 224 cells per frame; one AppButton per cell would
//     register 224 widget bounds and dispatch a hit-test per
//     mouse motion packet — heavy. AppPanel / AppLabel have no
//     per-cell hit-test model and would lose the centred glyph
//     + border treatment. The grid paints inside the band DrawFn
//     carves out between the (toolbar + header + mode-line) at
//     the top and the AppLabel footer at the bottom.

constexpr u32 kCmToolbarH = 22U;
constexpr u32 kCmToolbarBtnW = 52U;
constexpr u32 kCmToolbarBtnH = 18U;
constexpr u32 kCmToolbarBtnGap = 4U;
constexpr u32 kCmToolbarPadX = 4U;
constexpr u32 kCmToolbarPadY = 2U;
constexpr u32 kCmActionBtnCount = 2U;
constexpr u32 kCmHeaderH = kRowH;   // selection summary label
constexpr u32 kCmModeH = kRowH;     // range-mode label
constexpr u32 kCmFooterH = kRowH;   // controls hint label

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// AppLabel stores text by pointer so the buffers must outlive
// every Paint. DrawFn re-renders them each frame.
constinit char g_header_text[64] = {};
constinit char g_mode_text[40] = {};
constinit char g_footer_text[80] = {};

// Forward decls for the toolbar click trampolines (defined
// below; they have to live above the constinit g_charmap that
// captures them by function-pointer value).
void ClickRange();
void ClickCopy();

// Toolbar (back), then 2 action AppButtons, then 3 AppLabels
// (header, mode, footer). Reverse declaration order is
// dispatch order — buttons get first refusal on clicks.
constinit auto g_charmap =
    MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppLabel{}, AppLabel{}, AppLabel{});

constinit bool g_charmap_bound = false;
constinit bool g_charmap_prev_left_down = false;
constinit bool g_charmap_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to each action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 2 buttons -> 3
// labels).
AppButton* CmActionButton(u32 i)
{
    auto& a = g_charmap.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;               // btn[0]   -> btn[1]
    AppButton* btns[kCmActionBtnCount] = {&a.head, &b.head};
    return btns[i];
}

// AppLabel accessors — header / mode / footer sit at chain
// positions 3, 4, 5 (zero-indexed) after the 1 toolbar + 2
// buttons.
AppLabel& CmHeaderLabel()
{
    return g_charmap.chain.tail.tail.tail.head;
}
AppLabel& CmModeLabel()
{
    return g_charmap.chain.tail.tail.tail.tail.head;
}
AppLabel& CmFooterLabel()
{
    return g_charmap.chain.tail.tail.tail.tail.tail.head;
}

void BindCharmapOnce()
{
    if (g_charmap_bound)
        return;
    g_charmap_bound = true;

    auto& toolbar = g_charmap.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kCmActionLabels[kCmActionBtnCount] = {"RNGE", "COPY"};
    using ClickFn = void (*)();
    static constexpr ClickFn kCmActionClicks[kCmActionBtnCount] = {ClickRange, ClickCopy};
    for (u32 i = 0; i < kCmActionBtnCount; ++i)
    {
        AppButton* btn = CmActionButton(i);
        btn->label = kCmActionLabels[i];
        btn->on_click = kCmActionClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    auto& header = CmHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Body;
    header.weight = ChromeTextWeight::Regular;
    header.fg_rgb = fg;
    header.bg_rgb = bg;
    header.align_left = true;

    auto& mode = CmModeLabel();
    mode.text = g_mode_text;
    mode.role = ChromeTextRole::Caption;
    mode.weight = ChromeTextWeight::Regular;
    mode.fg_rgb = dim;
    mode.bg_rgb = bg;
    mode.align_left = true;

    auto& footer = CmFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = bg;
    footer.align_left = true;
}

// Re-anchor the toolbar + buttons + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// CharmapMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindCharmapBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_charmap.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kCmToolbarH};

    for (u32 i = 0; i < kCmActionBtnCount; ++i)
    {
        const u32 bx = cx + kCmToolbarPadX + i * (kCmToolbarBtnW + kCmToolbarBtnGap);
        CmActionButton(i)->bounds = Rect{bx, cy + kCmToolbarPadY, kCmToolbarBtnW, kCmToolbarBtnH};
    }

    // Header sits directly below the toolbar; mode-line sits
    // below header. Both span the client width with a small
    // x-pad to match the legacy raw-paint x offset.
    const u32 header_y = cy + kCmToolbarH;
    const u32 mode_y = header_y + kCmHeaderH;
    CmHeaderLabel().bounds = Rect{cx + kPad, header_y, (cw > kPad) ? cw - kPad : cw, kCmHeaderH};
    CmModeLabel().bounds = Rect{cx + kPad, mode_y, (cw > kPad) ? cw - kPad : cw, kCmModeH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kCmFooterH) ? cy + ch - kCmFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    CmFooterLabel().bounds = Rect{cx + kPad, fy, fw, kCmFooterH};
}

// Re-compose g_header_text from live state. Mirrors the legacy
// inline "U+XX (NNN) = 'c'" build in DrawFn.
void RefreshCharmapHeader()
{
    u32 o = 0;
    const char* prefix = "U+";
    while (prefix[o] != '\0' && o + 1 < sizeof(g_header_text))
    {
        g_header_text[o] = prefix[o];
        ++o;
    }
    char hex_buf[8];
    FormatHexU32(hex_buf, g_state.selection, (g_state.selection > 0xFF) ? 4 : 2);
    for (u32 i = 0; hex_buf[i] != '\0' && o + 1 < sizeof(g_header_text); ++i)
        g_header_text[o++] = hex_buf[i];
    if (o + 4 < sizeof(g_header_text))
    {
        g_header_text[o++] = ' ';
        g_header_text[o++] = '(';
    }
    char dec[12];
    u32 dec_len = 0;
    FormatDec(dec, sizeof(dec), g_state.selection, &dec_len);
    for (u32 i = 0; i < dec_len && o + 1 < sizeof(g_header_text); ++i)
        g_header_text[o++] = dec[i];
    if (o + 4 < sizeof(g_header_text))
    {
        g_header_text[o++] = ')';
        g_header_text[o++] = ' ';
        g_header_text[o++] = '=';
        g_header_text[o++] = ' ';
    }
    if (o + 2 < sizeof(g_header_text))
    {
        g_header_text[o++] = '\'';
        g_header_text[o++] = static_cast<char>(g_state.selection);
        if (o + 1 < sizeof(g_header_text))
            g_header_text[o++] = '\'';
    }
    g_header_text[(o < sizeof(g_header_text)) ? o : sizeof(g_header_text) - 1] = '\0';
}

void RefreshCharmapMode()
{
    static const char kAsciiLine[] = "RANGE: ASCII (0x20..0x7E)";
    static const char kFullLine[] = "RANGE: FULL (0x20..0xFF)";
    const char* src = g_state.full_range ? kFullLine : kAsciiLine;
    u32 i = 0;
    for (; src[i] != '\0' && i + 1 < sizeof(g_mode_text); ++i)
        g_mode_text[i] = src[i];
    g_mode_text[i] = '\0';
}

void RefreshCharmapFooter()
{
    static const char kHint[] = "ARROWS=MOVE  ENTER/SPC=COPY  TAB=RANGE  HOME/END  PG";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampolines --------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_charmap above captures each one by function-pointer value.
// Each click mirrors the corresponding keyboard shortcut so a
// fresh user can click straight to RNGE / COPY without
// remembering Tab / Enter.

void ClickRange()
{
    g_state.full_range = !g_state.full_range;
    ClampSelection();
}

void ClickCopy()
{
    CopySelectionToClipboard();
    char buf[64];
    u32 o = 0;
    const char* p = "copied U+";
    while (p[o] != '\0' && o + 1 < sizeof(buf))
    {
        buf[o] = p[o];
        ++o;
    }
    char hex[5];
    FormatHexU32(hex, g_state.selection, (g_state.selection > 0xFF) ? 4 : 2);
    for (u32 i = 0; hex[i] != '\0' && o + 1 < sizeof(buf); ++i)
        buf[o++] = hex[i];
    buf[o] = '\0';
    duetos::drivers::video::NotifyShowKind(buf, duetos::drivers::video::NotifyKind::Success);
}

// Paint the raw codepoint grid carve-out inside the band DrawFn
// carves out between the (toolbar + header + mode-line) at the
// top and the AppLabel footer at the bottom. Fixed-width cell
// alignment + per-cell scale-2 glyph rendering + a 2-pixel
// accent border around the selection is the grid's invariant.
// AppPanel / AppLabel have no per-cell hit-test or centred-
// glyph model so the grid stays raw.
void PaintCellGrid(u32 cx, u32 cy, u32 cw, u32 ch)
{
    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 grid_bg = 0x00181F2A;
    const u32 grid_fg = 0x00C0C8D8;
    const u32 sel_border = th.taskbar_accent;

    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Rows that fit inside the grid pane.
    const u32 rows_visible = ch / kCellSize;
    if (rows_visible == 0)
        return;
    const u32 total_codes = CodepointCount();
    const u32 total_rows = (total_codes + kCols - 1) / kCols;
    const u32 sel_idx = SelectionToIndex();
    const u32 sel_row = sel_idx / kCols;

    // Auto-scroll: keep the selection visible.
    static u32 s_scroll_row = 0;
    if (sel_row < s_scroll_row)
        s_scroll_row = sel_row;
    if (rows_visible > 0 && sel_row >= s_scroll_row + rows_visible)
        s_scroll_row = sel_row - rows_visible + 1;
    if (s_scroll_row + rows_visible > total_rows && total_rows >= rows_visible)
        s_scroll_row = total_rows - rows_visible;

    // Grid background pane.
    const u32 grid_w = kCols * kCellSize;
    if (cw > grid_w + kPad * 2)
        FramebufferFillRect(cx + kPad, cy, grid_w, rows_visible * kCellSize, grid_bg);

    // Paint the visible rows.
    for (u32 r = 0; r < rows_visible && (s_scroll_row + r) < total_rows; ++r)
    {
        for (u32 c = 0; c < kCols; ++c)
        {
            const u32 idx = (s_scroll_row + r) * kCols + c;
            if (idx >= total_codes)
                break;
            const u32 cp = CodepointStart() + idx;
            const u32 cell_x = cx + kPad + c * kCellSize;
            const u32 cell_y = cy + r * kCellSize;
            // Glyph centred: scale=2 → 16×16 inside a 24×24 cell.
            const char ch_buf[2] = {static_cast<char>(cp), '\0'};
            FramebufferDrawStringScaled(cell_x + 4, cell_y + 4, ch_buf, grid_fg, grid_bg, 2);
            if (cp == g_state.selection)
            {
                FramebufferDrawRect(cell_x, cell_y, kCellSize, kCellSize, sel_border, 2);
            }
        }
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const u32 bg = 0x00101828;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Pass D chrome: refresh the header / mode / footer text
    // from live state, re-anchor the toolbar / labels to the
    // current client rect, and paint the WidgetGroup. The raw
    // codepoint grid (carve-out) sits in the band between the
    // mode-line row and the footer label.
    BindCharmapOnce();
    RefreshCharmapHeader();
    RefreshCharmapMode();
    RefreshCharmapFooter();
    RebindCharmapBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_charmap.PaintAll(compose_ctx);

    // Grid band — between (toolbar + header + mode-line) at the
    // top and the AppLabel footer at the bottom.
    const u32 top_band = kCmToolbarH + kCmHeaderH + kCmModeH + kPad;
    const u32 bot_band = kCmFooterH + kPad;
    const u32 grid_x = cx;
    const u32 grid_y = cy + top_band;
    const u32 grid_w = cw;
    const u32 grid_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (grid_h > 0)
    {
        PaintCellGrid(grid_x, grid_y, grid_w, grid_h);
    }
}

} // namespace

void CharMapInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.full_range = false;
    g_state.selection = kAsciiStart;
    WindowSetContentDraw(handle, DrawFn, nullptr);
}

WindowHandle CharMapWindow()
{
    return g_state.handle;
}

bool CharMapFeedChar(char c)
{
    if (c == ' ' || c == '\n' || c == '\r')
    {
        CopySelectionToClipboard();
        char buf[64];
        u32 o = 0;
        const char* p = "copied U+";
        while (p[o] != '\0' && o + 1 < sizeof(buf))
        {
            buf[o] = p[o];
            ++o;
        }
        char hex[5];
        FormatHexU32(hex, g_state.selection, (g_state.selection > 0xFF) ? 4 : 2);
        for (u32 i = 0; hex[i] != '\0' && o + 1 < sizeof(buf); ++i)
            buf[o++] = hex[i];
        buf[o] = '\0';
        duetos::drivers::video::NotifyShowKind(buf, duetos::drivers::video::NotifyKind::Success);
        return true;
    }
    if (c == '\t')
    {
        g_state.full_range = !g_state.full_range;
        ClampSelection();
        return true;
    }
    if (c == 'h' || c == 'H')
        return CharMapFeedArrow(duetos::drivers::input::kKeyArrowLeft);
    if (c == 'l' || c == 'L')
        return CharMapFeedArrow(duetos::drivers::input::kKeyArrowRight);
    if (c == 'j' || c == 'J')
        return CharMapFeedArrow(duetos::drivers::input::kKeyArrowDown);
    if (c == 'k' || c == 'K')
        return CharMapFeedArrow(duetos::drivers::input::kKeyArrowUp);
    return false;
}

bool CharMapFeedArrow(duetos::u16 keycode)
{
    using namespace duetos::drivers::input;
    const u32 lo = CodepointStart();
    const u32 hi = CodepointEnd();
    switch (keycode)
    {
    case kKeyArrowLeft:
        if (g_state.selection > lo)
            --g_state.selection;
        return true;
    case kKeyArrowRight:
        if (g_state.selection < hi)
            ++g_state.selection;
        return true;
    case kKeyArrowUp:
        if (g_state.selection >= lo + kCols)
            g_state.selection -= kCols;
        return true;
    case kKeyArrowDown:
        if (g_state.selection + kCols <= hi)
            g_state.selection += kCols;
        return true;
    case kKeyPageUp:
        g_state.selection = (g_state.selection > lo + kCols * 8) ? (g_state.selection - kCols * 8) : lo;
        return true;
    case kKeyPageDown:
        g_state.selection = (g_state.selection + kCols * 8 <= hi) ? (g_state.selection + kCols * 8) : hi;
        return true;
    case kKeyHome:
        g_state.selection = lo;
        return true;
    case kKeyEnd:
        g_state.selection = hi;
        return true;
    case kKeyDelete:
        // Delete also fires the copy — operators reaching for
        // "do something" find both Enter and Del work.
        CopySelectionToClipboard();
        return true;
    default:
        return false;
    }
}

void CharMapSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;
    char hex[5];
    FormatHexU32(hex, 0x41, 2);
    ok = ok && hex[0] == '4' && hex[1] == '1' && hex[2] == '\0';
    FormatHexU32(hex, 0xFE, 4);
    ok = ok && hex[0] == '0' && hex[1] == '0' && hex[2] == 'F' && hex[3] == 'E';
    char dec[12];
    u32 dlen = 0;
    FormatDec(dec, sizeof(dec), 65, &dlen);
    ok = ok && dlen == 2 && dec[0] == '6' && dec[1] == '5';
    FormatDec(dec, sizeof(dec), 0, &dlen);
    ok = ok && dlen == 1 && dec[0] == '0';

    // Round-trip: ASCII range bounds.
    g_state.full_range = false;
    g_state.selection = kAsciiStart;
    ClampSelection();
    ok = ok && g_state.selection == kAsciiStart;
    g_state.selection = 0xFE;
    ClampSelection();
    ok = ok && g_state.selection == kAsciiEnd;
    g_state.full_range = true;
    g_state.selection = 0xFE;
    ClampSelection();
    ok = ok && g_state.selection == 0xFE;

    // Pass D: drive a synthetic click on the RNGE toolbar button
    // via the WidgetGroup dispatch chain. ClickRange toggles
    // g_state.full_range; the test verifies the dispatch path is
    // wired end-to-end AND that the click mutates the view
    // state. Restore state after.
    const bool saved_full_range = g_state.full_range;
    const u32 saved_selection = g_state.selection;
    BindCharmapOnce();
    // Anchor the toolbar at (0, 22, 400, 298) — same shape
    // boot_bringup.cpp registers the live CharMap window with
    // (400x320 minus 22 px title bar). RNGE is action index 0.
    RebindCharmapBounds(0U, 22U, 400U, 298U);
    g_state.full_range = false;
    constexpr u32 kRangeIdx = 0U;
    const u32 nx = kCmToolbarPadX + kRangeIdx * (kCmToolbarBtnW + kCmToolbarBtnGap) + kCmToolbarBtnW / 2U;
    const u32 ny = 22U + kCmToolbarPadY + kCmToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};
    if (g_charmap.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;
    if (g_charmap.DispatchEvent(n_down) != EventResult::Consumed)
        ok = false;
    if (g_charmap.DispatchEvent(n_up) != EventResult::Consumed)
        ok = false;
    if (g_state.full_range != true)
        ok = false;

    // Header / mode / footer composers must produce non-empty
    // text after a refresh.
    RefreshCharmapHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshCharmapMode();
    if (g_mode_text[0] == '\0')
        ok = false;
    RefreshCharmapFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    // Restore pre-test state so the live UI is unchanged when
    // the umbrella selftest returns.
    g_state.full_range = saved_full_range;
    g_state.selection = saved_selection;
    ClampSelection();

    g_charmap_self_test_passed = ok;
    if (ok)
    {
        SerialWrite("[charmap] self-test OK (format helpers + widget-click)\n");
        SerialWrite("[charmap-selftest] PASS\n");
    }
    else
    {
        SerialWrite("[charmap] self-test FAILED\n");
        SerialWrite("[charmap-selftest] FAIL\n");
    }
}

bool CharMapSelfTestPassed()
{
    return g_charmap_self_test_passed;
}

void CharMapMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the
    // same frame RebindCharmapBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindCharmapOnce();
    RebindCharmapBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_charmap_prev_left_down;
    const bool release_edge = !left_down && g_charmap_prev_left_down;
    g_charmap_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_charmap.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw codepoint grid sits below the
        // toolbar / header / mode-line rows the WidgetGroup
        // owns. The DispatchEvent path's hit-test naturally
        // short-circuits when the click misses the toolbar
        // bounds — the cell grid has no per-pixel click
        // semantics in v0 (selection is driven by the keyboard
        // arrow / Tab paths). MouseDown still fires for the
        // toolbar Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_charmap.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside
        // the toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_charmap.DispatchEvent(u);
    }
}

} // namespace duetos::apps::charmap
