#include "apps/charmap.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
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

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 grid_bg = 0x00181F2A;
    const u32 grid_fg = 0x00C0C8D8;
    const u32 sel_border = th.taskbar_accent;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Header: selection summary.
    char hex_buf[8];
    FormatHexU32(hex_buf, g_state.selection, (g_state.selection > 0xFF) ? 4 : 2);
    char header[64];
    u32 ho = 0;
    const char* prefix = "U+";
    while (prefix[ho] != '\0' && ho + 1 < sizeof(header))
    {
        header[ho] = prefix[ho];
        ++ho;
    }
    for (u32 i = 0; hex_buf[i] != '\0' && ho + 1 < sizeof(header); ++i)
        header[ho++] = hex_buf[i];
    if (ho + 4 < sizeof(header))
    {
        header[ho++] = ' ';
        header[ho++] = '(';
    }
    char dec[12];
    u32 dec_len = 0;
    FormatDec(dec, sizeof(dec), g_state.selection, &dec_len);
    for (u32 i = 0; i < dec_len && ho + 1 < sizeof(header); ++i)
        header[ho++] = dec[i];
    if (ho + 4 < sizeof(header))
    {
        header[ho++] = ')';
        header[ho++] = ' ';
        header[ho++] = '=';
        header[ho++] = ' ';
    }
    if (ho + 2 < sizeof(header))
    {
        header[ho++] = '\'';
        header[ho++] = static_cast<char>(g_state.selection);
        if (ho + 1 < sizeof(header))
            header[ho++] = '\'';
    }
    header[(ho < sizeof(header)) ? ho : sizeof(header) - 1] = '\0';
    FramebufferDrawString(cx + kPad, cy + kPad, header, fg, bg);

    const char* mode_label = g_state.full_range ? "RANGE: FULL (0x20..0xFF)" : "RANGE: ASCII (0x20..0x7E)";
    FramebufferDrawString(cx + kPad, cy + kPad + kRowH, mode_label, dim, bg);

    // Grid area below the header.
    const u32 grid_top = cy + kPad + kRowH * 2 + kPad;
    const u32 footer_h = kRowH + kPad;
    if (ch <= (grid_top - cy) + footer_h)
        return;
    const u32 grid_h = ch - (grid_top - cy) - footer_h;

    // Rows that fit inside the grid pane.
    const u32 rows_visible = grid_h / kCellSize;
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
        FramebufferFillRect(cx + kPad, grid_top, grid_w, rows_visible * kCellSize, grid_bg);

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
            const u32 cell_y = grid_top + r * kCellSize;
            // Glyph centred: scale=2 → 16×16 inside a 24×24 cell.
            const char ch_buf[2] = {static_cast<char>(cp), '\0'};
            FramebufferDrawStringScaled(cell_x + 4, cell_y + 4, ch_buf, grid_fg, grid_bg, 2);
            if (cp == g_state.selection)
            {
                FramebufferDrawRect(cell_x, cell_y, kCellSize, kCellSize, sel_border, 2);
            }
        }
    }

    // Footer hint.
    if (ch > kRowH + 2)
        FramebufferDrawString(cx + kPad, cy + ch - kRowH - 1, "ARROWS=MOVE  ENTER/SPC=COPY  TAB=RANGE  HOME/END  PG",
                              dim, bg);
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

    SerialWrite(ok ? "[charmap] self-test OK\n" : "[charmap] self-test FAILED\n");
}

} // namespace duetos::apps::charmap
