#include "apps/hexview.h"

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
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "mm/kheap.h"

namespace duetos::apps::hexview
{

namespace
{

using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 10;
constexpr u32 kPad = 4;
constexpr u32 kBytesPerRow = 16;
constexpr u32 kMaxFiles = 64;
constexpr u32 kNameCap = 16;
constexpr u32 kStatusCap = 96;

struct State
{
    WindowHandle handle;

    char names[kMaxFiles][kNameCap];
    u32 count;
    u32 index;

    u8* bytes; // owned via KMalloc; nullptr if no file loaded
    u32 bytes_len;
    u32 file_size; // total file size (may exceed bytes_len when capped)
    u32 row_offset;
    char status[kStatusCap];
    bool needs_load; // re-load on next draw
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, nullptr, 0, 0, 0, {}, false};

void StatusSet(const char* msg)
{
    u32 i = 0;
    for (; i + 1 < kStatusCap && msg[i] != '\0'; ++i)
        g_state.status[i] = msg[i];
    g_state.status[i] = '\0';
}

void StatusAppendStr(const char* s)
{
    u32 len = 0;
    while (g_state.status[len] != '\0' && len + 1 < kStatusCap)
        ++len;
    for (u32 i = 0; s[i] != '\0' && len + 1 < kStatusCap; ++i)
        g_state.status[len++] = s[i];
    g_state.status[len] = '\0';
}

void StatusAppendDec(u32 v)
{
    char tmp[16];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    u32 len = 0;
    while (g_state.status[len] != '\0' && len + 1 < kStatusCap)
        ++len;
    while (n > 0 && len + 1 < kStatusCap)
        g_state.status[len++] = tmp[--n];
    g_state.status[len] = '\0';
}

// Format a 32-bit byte offset as 8 uppercase hex digits.
void FormatHex8(char* out, u32 v)
{
    static const char kHex[] = "0123456789ABCDEF";
    for (u32 i = 0; i < 8; ++i)
    {
        out[7 - i] = kHex[v & 0xF];
        v >>= 4;
    }
    out[8] = '\0';
}

// Format a single byte as 2 uppercase hex digits.
void FormatHex2(char* out, u8 v)
{
    static const char kHex[] = "0123456789ABCDEF";
    out[0] = kHex[(v >> 4) & 0xF];
    out[1] = kHex[v & 0xF];
    out[2] = '\0';
}

// Map a byte to its printable form, or '.' for non-printable.
char PrintableByte(u8 b)
{
    if (b >= 0x20 && b <= 0x7E)
        return static_cast<char>(b);
    return '.';
}

// Free the loaded bytes, if any. Idempotent.
void FreeBytes()
{
    if (g_state.bytes != nullptr)
    {
        mm::KFree(g_state.bytes);
        g_state.bytes = nullptr;
    }
    g_state.bytes_len = 0;
    g_state.file_size = 0;
    g_state.row_offset = 0;
}

// Re-scan the FAT32 root. No extension filter — every regular
// file is a candidate. Caps at kMaxFiles to bound memory.
void RescanRoot()
{
    namespace fat = fs::fat32;
    char prev_name[kNameCap];
    bool had_prev = false;
    if (g_state.index < g_state.count)
    {
        for (u32 i = 0; i < kNameCap; ++i)
            prev_name[i] = g_state.names[g_state.index][i];
        had_prev = (prev_name[0] != '\0');
    }
    g_state.count = 0;
    g_state.index = 0;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    fat::DirEntry entries[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, entries, fat::kMaxDirEntries);
    for (u32 i = 0; i < n && g_state.count < kMaxFiles; ++i)
    {
        if ((entries[i].attributes & 0x10) != 0)
            continue;
        const char* src = entries[i].name;
        char* dst = g_state.names[g_state.count];
        u32 j = 0;
        for (; j + 1 < kNameCap && src[j] != '\0'; ++j)
            dst[j] = src[j];
        dst[j] = '\0';
        ++g_state.count;
    }

    if (had_prev)
    {
        for (u32 i = 0; i < g_state.count; ++i)
        {
            const char* a = g_state.names[i];
            bool match = true;
            for (u32 k = 0; k < kNameCap; ++k)
            {
                if (a[k] != prev_name[k])
                {
                    match = false;
                    break;
                }
                if (a[k] == '\0')
                    break;
            }
            if (match)
            {
                g_state.index = i;
                break;
            }
        }
    }
}

// Load the current file's bytes into g_state.bytes (capped at
// kHexViewMaxFileBytes). Returns true on success.
bool LoadCurrent()
{
    namespace fat = fs::fat32;
    FreeBytes();
    StatusSet("");
    if (g_state.count == 0)
    {
        StatusSet("(no files in /)");
        return false;
    }
    if (g_state.index >= g_state.count)
        g_state.index = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        StatusSet("(no FAT32 volume)");
        return false;
    }
    const char* name = g_state.names[g_state.index];
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, name, &e))
    {
        StatusSet("lookup FAILED: ");
        StatusAppendStr(name);
        return false;
    }
    g_state.file_size = e.size_bytes;
    const u32 want = (e.size_bytes < kHexViewMaxFileBytes) ? e.size_bytes : kHexViewMaxFileBytes;
    if (want == 0)
    {
        StatusSet(name);
        StatusAppendStr("  (empty file)");
        return true;
    }
    void* alloc = mm::KMalloc(want);
    if (alloc == nullptr)
    {
        StatusSet("out of kheap memory");
        return false;
    }
    const i64 got = fat::Fat32ReadFile(v, &e, alloc, want);
    if (got <= 0)
    {
        mm::KFree(alloc);
        StatusSet("read FAILED: ");
        StatusAppendStr(name);
        return false;
    }
    g_state.bytes = static_cast<u8*>(alloc);
    g_state.bytes_len = static_cast<u32>(got);
    g_state.row_offset = 0;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(g_state.file_size);
    StatusAppendStr(" B");
    if (e.size_bytes > kHexViewMaxFileBytes)
        StatusAppendStr(" (truncated)");
    return true;
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 3 AppButton entries
// (PREV / NEXT / RSCN) + 2 AppLabel rows (status line and footer
// hint). The 3 toolbar buttons duplicate the keyboard shortcuts
// P / N / R so the chrome stays discoverable without forcing
// fresh users to memorise the footer hint.
//
// Carve-outs that stay raw paint:
//   - Byte grid (offset col + 16 hex bytes + ASCII gutter).
//     The grid's defining property is fixed-width cell alignment
//     — every byte sits at exactly column N * (3 cells of 8 px),
//     the ASCII gutter anchors at a precomputed column so short
//     rows don't slide it left, and the two-group split inserts
//     an extra 8 px gap between bytes 7 and 8. AppLabel /
//     AppPanel have no per-column alignment model and would
//     reflow the grid based on Measure widths. The grid paints
//     inside the band DrawFn carves out below the toolbar /
//     status row and above the footer label.
//   - "[i/N]" page header at the top of the body band. Bound
//     directly into g_idx_text via the first AppLabel — text
//     stays consistent with the rest of the chrome while the
//     grid below keeps its own column origins.
//
// Layout: toolbar (kHvToolbarH = 22) at the top of the client
// area, then a [i/N] header AppLabel, then the status AppLabel
// (bound to g_state.status — StatusSet writes show up without
// an extra refresh hop), then the raw byte grid carve-out, then
// a footer hint AppLabel along the bottom.

constexpr u32 kHvToolbarH = 22U;
constexpr u32 kHvToolbarBtnW = 52U;
constexpr u32 kHvToolbarBtnH = 18U;
constexpr u32 kHvToolbarBtnGap = 4U;
constexpr u32 kHvToolbarPadX = 4U;
constexpr u32 kHvToolbarPadY = 2U;
constexpr u32 kHvNavBtnCount = 3U;
constexpr u32 kHvHeaderH = kRowH;     // [i/N] label height
constexpr u32 kHvStatusH = kRowH + 2; // status row height (matches old paint)
constexpr u32 kHvFooterH = 12U;

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
constinit char g_idx_text[24] = {};
constinit char g_footer_text[80] = {};

// Forward decls for the toolbar click trampolines (defined
// below; they have to live above the constinit g_hexview
// that captures them by function-pointer value).
void ClickPrev();
void ClickNext();
void ClickRescan();

// Toolbar (back), then 3 nav AppButtons, then 2 AppLabels
// (header, status, footer). Reverse declaration order is
// dispatch order — buttons get first refusal on clicks.
constinit auto g_hexview =
    MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppButton{}, AppLabel{}, AppLabel{}, AppLabel{});

constinit bool g_hexview_bound = false;
constinit bool g_hexview_prev_left_down = false;
constinit bool g_hexview_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to each nav button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 3 buttons -> 3
// labels).
AppButton* HvNavButton(u32 i)
{
    auto& a = g_hexview.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;               // btn[0]   -> btn[1]
    auto& c = b.tail;               // btn[1]   -> btn[2]
    AppButton* btns[kHvNavBtnCount] = {&a.head, &b.head, &c.head};
    return btns[i];
}

// AppLabel accessors — header / status / footer sit at chain
// positions 4, 5, 6 (zero-indexed) after the 1 toolbar + 3
// buttons.
AppLabel& HvHeaderLabel()
{
    return g_hexview.chain.tail.tail.tail.tail.head;
}
AppLabel& HvStatusLabel()
{
    return g_hexview.chain.tail.tail.tail.tail.tail.head;
}
AppLabel& HvFooterLabel()
{
    return g_hexview.chain.tail.tail.tail.tail.tail.tail.head;
}

void BindHexviewOnce()
{
    if (g_hexview_bound)
        return;
    g_hexview_bound = true;

    auto& toolbar = g_hexview.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kHvNavLabels[kHvNavBtnCount] = {"PREV", "NEXT", "RSCN"};
    using ClickFn = void (*)();
    static constexpr ClickFn kHvNavClicks[kHvNavBtnCount] = {ClickPrev, ClickNext, ClickRescan};
    for (u32 i = 0; i < kHvNavBtnCount; ++i)
    {
        AppButton* btn = HvNavButton(i);
        btn->label = kHvNavLabels[i];
        btn->on_click = kHvNavClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 ink_addr = 0x00808FA0;

    auto& header = HvHeaderLabel();
    header.text = g_idx_text;
    header.role = ChromeTextRole::Caption;
    header.weight = ChromeTextWeight::Regular;
    header.fg_rgb = ink_addr;
    header.bg_rgb = bg;
    header.align_left = true;

    auto& status = HvStatusLabel();
    status.text = g_state.status;
    status.role = ChromeTextRole::Body;
    status.weight = ChromeTextWeight::Regular;
    status.fg_rgb = fg;
    status.bg_rgb = bg;
    status.align_left = true;

    auto& footer = HvFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = bg;
    footer.align_left = true;
}

// Re-anchor the toolbar + buttons + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// HexviewMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindHexviewBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_hexview.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kHvToolbarH};

    for (u32 i = 0; i < kHvNavBtnCount; ++i)
    {
        const u32 bx = cx + kHvToolbarPadX + i * (kHvToolbarBtnW + kHvToolbarBtnGap);
        HvNavButton(i)->bounds = Rect{bx, cy + kHvToolbarPadY, kHvToolbarBtnW, kHvToolbarBtnH};
    }

    // Header [i/N] sits directly below the toolbar; status sits
    // below header. Both span the client width with a small
    // x-pad to match the legacy raw-paint x offset.
    const u32 header_y = cy + kHvToolbarH;
    const u32 status_y = header_y + kHvHeaderH;
    HvHeaderLabel().bounds = Rect{cx + kPad, header_y, (cw > kPad) ? cw - kPad : cw, kHvHeaderH};
    HvStatusLabel().bounds = Rect{cx + kPad, status_y, (cw > kPad) ? cw - kPad : cw, kHvStatusH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kHvFooterH) ? cy + ch - kHvFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    HvFooterLabel().bounds = Rect{cx + kPad, fy, fw, kHvFooterH};
}

// Re-compose g_idx_text from live state. Mirrors the legacy
// inline "[i/N]" build in DrawFn.
void RefreshHexviewHeader()
{
    u32 o = 0;
    g_idx_text[o++] = '[';
    {
        u32 v = (g_state.count == 0) ? 0 : (g_state.index + 1);
        char tmp[8];
        u32 n = 0;
        if (v == 0)
            tmp[n++] = '0';
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (n > 0 && o + 1 < sizeof(g_idx_text))
            g_idx_text[o++] = tmp[--n];
    }
    if (o + 1 < sizeof(g_idx_text))
        g_idx_text[o++] = '/';
    {
        u32 v = g_state.count;
        char tmp[8];
        u32 n = 0;
        if (v == 0)
            tmp[n++] = '0';
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (n > 0 && o + 1 < sizeof(g_idx_text))
            g_idx_text[o++] = tmp[--n];
    }
    if (o + 1 < sizeof(g_idx_text))
        g_idx_text[o++] = ']';
    g_idx_text[o] = '\0';
}

// Re-compose g_footer_text from live state. Different hint
// when no bytes are loaded (empty-state) vs. when a file is
// active (J/K/PG/Home/End scroll hints).
void RefreshHexviewFooter()
{
    static const char kEmptyHint[] = "N/P=NEXT/PREV  R=RESCAN  WHEEL=SCROLL";
    static const char kActiveHint[] = "N/P=FILE  J/K=ROW  PG=PAGE  HOME/END  R=RELOAD  WHEEL=SCROLL";
    const char* src = (g_state.bytes == nullptr || g_state.bytes_len == 0) ? kEmptyHint : kActiveHint;
    u32 i = 0;
    for (; src[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = src[i];
    g_footer_text[i] = '\0';
}

// -------------------------------------------------------------------
// Draw — paints the current page of bytes.
// -------------------------------------------------------------------
//
// Layout per row: 8-char offset + 2 spaces + 16 hex bytes
// (split 8/8 with a space between groups) + 2 spaces + 16 ASCII
// characters. At 8 px per glyph that's roughly:
//   8 + 2 + (16*3 + 1) + 2 + 16 = 77 char cells = 616 px wide.
// Window content of < 616 px clips the right edge; the operator
// resizes the window as needed.

void StepIndex(bool forward)
{
    if (g_state.count == 0)
        return;
    if (forward)
        g_state.index = (g_state.index + 1) % g_state.count;
    else
        g_state.index = (g_state.index == 0) ? (g_state.count - 1) : (g_state.index - 1);
    g_state.needs_load = true;
}

void ScrollRows(i32 delta)
{
    const u32 total_rows = (g_state.bytes_len + kBytesPerRow - 1) / kBytesPerRow;
    if (total_rows == 0)
        return;
    if (delta < 0)
    {
        const u32 step = static_cast<u32>(-delta);
        g_state.row_offset = (g_state.row_offset > step) ? (g_state.row_offset - step) : 0;
    }
    else
    {
        const u32 step = static_cast<u32>(delta);
        const u32 max_first = (total_rows > 0) ? (total_rows - 1) : 0;
        g_state.row_offset = (g_state.row_offset + step > max_first) ? max_first : (g_state.row_offset + step);
    }
}

// ----- Pass D click trampolines --------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_hexview above captures each one by function-pointer value.
// Each click mirrors the corresponding keyboard shortcut so a
// fresh user can click straight to PREV / NEXT / RSCN without
// remembering N/P/R.

void ClickPrev()
{
    StepIndex(false);
}

void ClickNext()
{
    StepIndex(true);
}

void ClickRescan()
{
    RescanRoot();
    g_state.needs_load = true;
    duetos::drivers::video::NotifyShow("hexview: reloaded");
}

// Paint the raw byte grid carve-out inside the band DrawFn
// carves out between the (toolbar + header + status) row at the
// top and the AppLabel footer at the bottom. Fixed-width cell
// alignment is the grid's invariant — each byte sits at column
// N * (3 cells of 8 px), the ASCII gutter anchors at a
// precomputed column so short rows don't slide it left, and the
// extra 8 px gap between bytes 7 and 8 keeps the two-group
// split visible at any window width. AppLabel / AppPanel have
// no per-column alignment model so the grid stays raw.
void PaintByteGrid(u32 cx, u32 cy, u32 cw, u32 ch)
{
    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 ink_addr = 0x00808FA0;
    const u32 ink_hex = fg;
    const u32 ink_ascii = 0x00B0B8C8;

    if (g_state.needs_load)
    {
        LoadCurrent();
        g_state.needs_load = false;
    }

    if (g_state.bytes == nullptr || g_state.bytes_len == 0)
    {
        // Empty state — paint the legacy empty-state hint at the
        // top of the carve-out band so it's centred between the
        // status row above and the footer below.
        if (ch >= kRowH)
            FramebufferDrawString(cx + kPad, cy + 2, "(no bytes loaded — pick a file via NEXT/PREV)", dim, bg);
        return;
    }

    const u32 rows_visible = ch / kRowH;
    if (rows_visible == 0)
        return;

    const u32 total_rows = (g_state.bytes_len + kBytesPerRow - 1) / kBytesPerRow;
    if (g_state.row_offset >= total_rows)
        g_state.row_offset = (total_rows == 0) ? 0 : (total_rows - 1);
    const u32 first_row = g_state.row_offset;
    const u32 to_draw = (rows_visible < (total_rows - first_row)) ? rows_visible : (total_rows - first_row);

    char hex2[3];
    char addr8[9];
    for (u32 r = 0; r < to_draw; ++r)
    {
        const u32 row_idx = first_row + r;
        const u32 byte_off = row_idx * kBytesPerRow;
        FormatHex8(addr8, byte_off);
        const u32 row_y = cy + r * kRowH;
        FramebufferDrawString(cx + kPad, row_y, addr8, ink_addr, bg);

        // 16 hex bytes split 8 / 8.
        u32 col_x = cx + kPad + 8 * 8 + 8; // after offset + 1 space
        for (u32 b = 0; b < kBytesPerRow; ++b)
        {
            const u32 ofs = byte_off + b;
            if (ofs >= g_state.bytes_len)
                break;
            FormatHex2(hex2, g_state.bytes[ofs]);
            FramebufferDrawString(col_x, row_y, hex2, ink_hex, bg);
            col_x += 3 * 8; // "XX " = 3 cells
            if (b == 7)
                col_x += 8; // extra gap between two groups of 8
        }
        // ASCII gutter.
        char ascii[kBytesPerRow + 1];
        u32 a = 0;
        for (u32 b = 0; b < kBytesPerRow; ++b)
        {
            const u32 ofs = byte_off + b;
            if (ofs >= g_state.bytes_len)
                break;
            ascii[a++] = PrintableByte(g_state.bytes[ofs]);
        }
        ascii[a] = '\0';
        // Anchor ASCII gutter at a fixed column so short rows
        // don't slide it left.
        const u32 ascii_x = cx + kPad + (8 + 1 + (16 * 3 + 1) + 1) * 8;
        FramebufferDrawString(ascii_x, row_y, ascii, ink_ascii, bg);
    }

    // Scrollbar registration so the kernel mouse loop can drag.
    if (total_rows > rows_visible && cw > duetos::drivers::video::kScrollbarWidth)
    {
        const u32 sb_x = cx + cw - duetos::drivers::video::kScrollbarWidth;
        const u32 sb_y = cy;
        const u32 sb_w = duetos::drivers::video::kScrollbarWidth;
        const u32 sb_h = rows_visible * kRowH;
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sb_w, sb_h, {total_rows, rows_visible, first_row});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sb_w;
        s.h = sb_h;
        s.total = total_rows;
        s.visible = rows_visible;
        s.first = first_row;
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
    const u32 bg = 0x00101828;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Pass D chrome: refresh the [i/N] header + footer text from
    // live state, re-anchor the toolbar / labels to the current
    // client rect, and paint the WidgetGroup. The raw byte grid
    // (carve-out) sits in the band between the status row and
    // the footer label.
    BindHexviewOnce();
    RefreshHexviewHeader();
    RefreshHexviewFooter();
    RebindHexviewBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_hexview.PaintAll(compose_ctx);

    // Byte-grid band — between (toolbar + header + status) at the
    // top and the AppLabel footer at the bottom.
    const u32 top_band = kHvToolbarH + kHvHeaderH + kHvStatusH;
    const u32 bot_band = kHvFooterH;
    const u32 grid_x = cx;
    const u32 grid_y = cy + top_band;
    const u32 grid_w = cw;
    const u32 grid_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (grid_h > 0)
    {
        PaintByteGrid(grid_x, grid_y, grid_w, grid_h);
    }
}

} // namespace

void HexViewInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.count = 0;
    g_state.index = 0;
    g_state.bytes = nullptr;
    g_state.bytes_len = 0;
    g_state.file_size = 0;
    g_state.row_offset = 0;
    g_state.status[0] = '\0';
    g_state.needs_load = true;
    RescanRoot();
    WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, HexViewOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle, [](u32 first) { g_state.row_offset = first; });
}

WindowHandle HexViewWindow()
{
    return g_state.handle;
}

bool HexViewFeedChar(char c)
{
    if (c == 'n' || c == 'N')
    {
        StepIndex(true);
        return true;
    }
    if (c == 'p' || c == 'P')
    {
        StepIndex(false);
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        RescanRoot();
        g_state.needs_load = true;
        duetos::drivers::video::NotifyShow("hexview: reloaded");
        return true;
    }
    if (c == 'j' || c == 'J')
    {
        ScrollRows(1);
        return true;
    }
    if (c == 'k' || c == 'K')
    {
        ScrollRows(-1);
        return true;
    }
    return false;
}

bool HexViewFeedArrow(duetos::u16 keycode)
{
    using namespace duetos::drivers::input;
    switch (keycode)
    {
    case kKeyArrowDown:
        ScrollRows(1);
        return true;
    case kKeyArrowUp:
        ScrollRows(-1);
        return true;
    case kKeyArrowRight:
        StepIndex(true);
        return true;
    case kKeyArrowLeft:
        StepIndex(false);
        return true;
    case kKeyPageDown:
        ScrollRows(16);
        return true;
    case kKeyPageUp:
        ScrollRows(-16);
        return true;
    case kKeyHome:
        g_state.row_offset = 0;
        return true;
    case kKeyEnd:
    {
        const u32 total = (g_state.bytes_len + kBytesPerRow - 1) / kBytesPerRow;
        g_state.row_offset = (total > 0) ? (total - 1) : 0;
        return true;
    }
    default:
        return false;
    }
}

void HexViewOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    using duetos::drivers::input::kKeyModCtrl;
    if (dz == 0)
        return;
    const bool ctrl = (modifiers & kKeyModCtrl) != 0;
    const i32 step = ctrl ? 16 : 1;
    // Convention: wheel-up scrolls toward earlier bytes.
    ScrollRows((dz > 0) ? -step * dz : step * (-dz));
}

bool HexViewSelectByName(const char* name)
{
    if (name == nullptr || name[0] == '\0')
        return false;
    RescanRoot();
    auto up = [](char ch) { return (ch >= 'a' && ch <= 'z') ? static_cast<char>(ch - ('a' - 'A')) : ch; };
    for (u32 i = 0; i < g_state.count; ++i)
    {
        const char* a = g_state.names[i];
        u32 k = 0;
        for (; a[k] != '\0' && name[k] != '\0'; ++k)
            if (up(a[k]) != up(name[k]))
                break;
        if (a[k] == '\0' && name[k] == '\0')
        {
            g_state.index = i;
            g_state.needs_load = true;
            return true;
        }
    }
    return false;
}

void HexViewSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;
    char buf[9];
    FormatHex8(buf, 0);
    ok = ok && buf[0] == '0' && buf[7] == '0' && buf[8] == '\0';
    FormatHex8(buf, 0xDEADBEEF);
    ok = ok && buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == 'B' && buf[5] == 'E' &&
         buf[6] == 'E' && buf[7] == 'F';
    char hex2[3];
    FormatHex2(hex2, 0xAB);
    ok = ok && hex2[0] == 'A' && hex2[1] == 'B' && hex2[2] == '\0';
    ok = ok && PrintableByte('A') == 'A';
    ok = ok && PrintableByte(0x00) == '.';
    ok = ok && PrintableByte(0x7F) == '.';
    ok = ok && PrintableByte(0x20) == ' ';
    ok = ok && PrintableByte(0x7E) == '~';

    // Pass D: drive a synthetic click on the NEXT toolbar button
    // via the WidgetGroup dispatch chain. ClickNext calls
    // StepIndex(true) which advances g_state.index when count >
    // 0; we plant a synthetic count of 3 + an index of 0 so the
    // test verifies the dispatch path is wired end-to-end AND
    // that the click mutates the view state. Restore state after.
    const u32 saved_count = g_state.count;
    const u32 saved_index = g_state.index;
    const bool saved_needs_load = g_state.needs_load;
    BindHexviewOnce();
    // Anchor the toolbar at (0, 22, 640, 338) — same shape
    // boot_bringup.cpp registers the live HexView window with
    // (640x360 minus 22 px title bar). NEXT is nav index 1.
    RebindHexviewBounds(0U, 22U, 640U, 338U);
    g_state.count = 3;
    g_state.index = 0;
    g_state.needs_load = false;
    constexpr u32 kNextIdx = 1U;
    const u32 nx = kHvToolbarPadX + kNextIdx * (kHvToolbarBtnW + kHvToolbarBtnGap) + kHvToolbarBtnW / 2U;
    const u32 ny = 22U + kHvToolbarPadY + kHvToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};
    if (g_hexview.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;
    if (g_hexview.DispatchEvent(n_down) != EventResult::Consumed)
        ok = false;
    if (g_hexview.DispatchEvent(n_up) != EventResult::Consumed)
        ok = false;
    if (g_state.index != 1)
        ok = false;
    // ClickNext sets needs_load = true via StepIndex; clear so
    // the live UI doesn't accidentally re-load when the umbrella
    // self-test returns.
    g_state.needs_load = false;

    // Header + footer composers must produce non-empty text
    // after a refresh.
    RefreshHexviewHeader();
    if (g_idx_text[0] == '\0')
        ok = false;
    RefreshHexviewFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    // Restore pre-test state so the live UI is unchanged when
    // the umbrella selftest returns.
    g_state.count = saved_count;
    g_state.index = saved_index;
    g_state.needs_load = saved_needs_load;

    g_hexview_self_test_passed = ok;
    if (ok)
    {
        SerialWrite("[hexview] self-test OK (format helpers + widget-click)\n");
        SerialWrite("[hexview-selftest] PASS\n");
    }
    else
    {
        SerialWrite("[hexview] self-test FAILED\n");
        SerialWrite("[hexview-selftest] FAIL\n");
    }
}

bool HexViewSelfTestPassed()
{
    return g_hexview_self_test_passed;
}

void HexViewMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the
    // same frame RebindHexviewBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindHexviewOnce();
    RebindHexviewBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_hexview_prev_left_down;
    const bool release_edge = !left_down && g_hexview_prev_left_down;
    g_hexview_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_hexview.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw byte grid sits below the toolbar /
        // header / status rows the WidgetGroup owns. The
        // DispatchEvent path's hit-test naturally short-circuits
        // when the click misses the toolbar bounds — the byte
        // grid has no per-pixel click semantics in v0 (drag /
        // selection is reached only via the wheel / keyboard
        // paths). MouseDown still fires for the toolbar
        // Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_hexview.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside
        // the toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_hexview.DispatchEvent(u);
    }
}

} // namespace duetos::apps::hexview
