#include "apps/notify_center.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"

namespace duetos::apps::notify_center
{

namespace
{

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

constexpr u32 kRowH = 12;
constexpr u32 kPad = 4;

constinit duetos::drivers::video::WindowHandle g_handle = kWindowInvalid;
constinit u32 g_selection = 0;
constinit u32 g_scroll = 0;

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 1 AppButton (CLR) + 2
// AppLabels (header "NOTIFICATION HISTORY" + footer hint with
// the keyboard shortcuts). CLR mirrors the X / Del keyboard
// shortcut and routes through the same MessageBox confirm path
// so an empty history reports via toast and a non-empty history
// pops the confirm dialog before clearing.
//
// Carve-outs that stay raw paint:
//   - The notification row list itself. Each row paints a 3 px
//     severity stripe at the left edge in a per-kind RGB, a
//     numeric "[NN] " prefix at a fixed column, then the body
//     text — the at-a-glance severity glyph relies on per-pixel
//     column alignment AppLabel does not model. The selection
//     highlight (full-row fill + inverted ink) is per-row state
//     the WidgetGroup framework does not track yet, so the rows
//     stay raw. Empty-state "(no notifications yet)" hint paints
//     in the same band so it sits where the rows would.
//   - Scrollbar registration. ScrollbarPaint + WindowSetScrollbar
//     stay raw — the kernel mouse loop owns the scrollbar drag
//     path via WindowScrollbarSurface and AppScrollbar's hit-test
//     overlaps that surface.

constexpr u32 kNcToolbarH = 22U;
constexpr u32 kNcToolbarBtnW = 52U;
constexpr u32 kNcToolbarBtnH = 18U;
constexpr u32 kNcToolbarBtnGap = 4U;
constexpr u32 kNcToolbarPadX = 4U;
constexpr u32 kNcToolbarPadY = 2U;
constexpr u32 kNcHeaderH = kRowH + 4U;
constexpr u32 kNcFooterH = kRowH;

// AppLabel stores text by pointer so the buffers must outlive
// every Paint. DrawFn re-renders them each frame.
constinit char g_header_text[32] = {};
constinit char g_footer_text[80] = {};

// Forward decl for the toolbar click trampoline (defined below;
// it has to live above the constinit g_notify_center that
// captures it by function-pointer value).
void ClickClear();

// Toolbar (back), then 1 action AppButton, then 2 AppLabels
// (header, footer). Declaration order is dispatch order — the
// button gets first refusal on clicks.
constinit auto g_notify_center = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppLabel{}, AppLabel{});

constinit bool g_notify_center_bound = false;
constinit bool g_notify_center_prev_left_down = false;
constinit bool g_notify_center_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to the action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 1 button -> 2
// labels).
AppButton* NcActionButton()
{
    return &g_notify_center.chain.tail.head; // toolbar -> btn[0]
}

AppLabel& NcHeaderLabel()
{
    return g_notify_center.chain.tail.tail.head;
}
AppLabel& NcFooterLabel()
{
    return g_notify_center.chain.tail.tail.tail.head;
}

void OnClearConfirm(duetos::drivers::video::DialogResult result, const char* /*text*/, void* /*user*/)
{
    if (result == duetos::drivers::video::DialogResult::Ok)
    {
        duetos::drivers::video::NotifyHistoryClear();
        g_selection = 0;
        g_scroll = 0;
        duetos::drivers::video::NotifyShowKind("notify history cleared", duetos::drivers::video::NotifyKind::Info);
    }
}

void RequestClearConfirm()
{
    if (duetos::drivers::video::NotifyHistoryCount() == 0)
    {
        duetos::drivers::video::NotifyShowKind("notify history is empty", duetos::drivers::video::NotifyKind::Info);
        return;
    }
    // Caller is the kbd-reader thread (or the WidgetGroup
    // dispatch path from the mouse-reader thread), both holding
    // the compositor lock — same context every other DialogOpen
    // call uses.
    duetos::drivers::video::MessageBoxOpen("CLEAR HISTORY", "Discard every notification entry?", OnClearConfirm,
                                           nullptr);
}

void BindNotifyCenterOnce()
{
    if (g_notify_center_bound)
        return;
    g_notify_center_bound = true;

    auto& toolbar = g_notify_center.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    AppButton* btn = NcActionButton();
    btn->label = "CLR";
    btn->on_click = ClickClear;
    btn->weight = ChromeTextWeight::Regular;
    btn->bg_rgb = 0; // theme role default
    btn->fg_rgb = 0x00101020U;

    const auto& th = ThemeCurrent();
    const u32 bg = 0x00181820;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    auto& header = NcHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Caption;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = fg;
    header.bg_rgb = bg;
    header.align_left = true;

    auto& footer = NcFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = bg;
    footer.align_left = true;
}

// Re-anchor the toolbar + button + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// NotifyCenterMouseInput before DispatchEvent so hit-tests +
// visuals stay consistent across window moves / resizes.
void RebindNotifyCenterBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_notify_center.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kNcToolbarH};

    {
        constexpr u32 i = 0U;
        const u32 bx = cx + kNcToolbarPadX + i * (kNcToolbarBtnW + kNcToolbarBtnGap);
        NcActionButton()->bounds = Rect{bx, cy + kNcToolbarPadY, kNcToolbarBtnW, kNcToolbarBtnH};
    }

    // Header sits directly below the toolbar. Spans the client
    // width with a small x-pad to match the legacy raw-paint
    // x-offset.
    const u32 header_y = cy + kNcToolbarH;
    NcHeaderLabel().bounds = Rect{cx + kPad, header_y, (cw > kPad) ? cw - kPad : cw, kNcHeaderH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kNcFooterH) ? cy + ch - kNcFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    NcFooterLabel().bounds = Rect{cx + kPad, fy, fw, kNcFooterH};
}

void RefreshNotifyCenterHeader()
{
    static const char kHeader[] = "NOTIFICATION HISTORY";
    u32 i = 0;
    for (; kHeader[i] != '\0' && i + 1 < sizeof(g_header_text); ++i)
        g_header_text[i] = kHeader[i];
    g_header_text[i] = '\0';
}

void RefreshNotifyCenterFooter()
{
    static const char kHint[] = "J/K UP/DN HOME/END PG  X/DEL=CLEAR  Ctrl+Shift+N=DUMP";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_notify_center above captures it by function-pointer value.
// CLR mirrors the X / Del keyboard shortcut — it routes through
// the same MessageBox confirm path so an empty history reports
// via toast and a non-empty history pops the confirm dialog
// before clearing.

void ClickClear()
{
    RequestClearConfirm();
}

// Paint the raw notification-row list inside the band DrawFn
// carves out between the (toolbar + header) at the top and the
// AppLabel footer at the bottom. Per-row severity stripe + "[NN]"
// prefix + selection highlight all rely on per-pixel column
// alignment AppLabel does not model, so the row list stays raw.
// Empty-state "(no notifications yet)" hint paints in the same
// band so it sits where the rows would.
void PaintNotifyCenterList(u32 cx, u32 cy, u32 cw, u32 ch)
{
    const auto& th = ThemeCurrent();
    const u32 bg = 0x00181820;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 sel_bg = th.taskbar_accent;
    const u32 sel_fg = 0x00101020;

    FramebufferFillRect(cx, cy, cw, ch, bg);

    const u32 max_rows = ch / kRowH;
    if (max_rows == 0)
        return;
    const u32 n = duetos::drivers::video::NotifyHistoryCount();
    if (n == 0)
    {
        FramebufferDrawString(cx + kPad, cy + 2, "(no notifications yet)", dim, bg);
        return;
    }
    if (g_selection >= n)
        g_selection = n - 1;
    if (g_scroll > g_selection)
        g_scroll = g_selection;
    if (g_scroll + max_rows <= g_selection)
        g_scroll = g_selection - max_rows + 1;
    if (n > max_rows)
    {
        const u32 max_scroll = n - max_rows;
        if (g_scroll > max_scroll)
            g_scroll = max_scroll;
    }
    else
    {
        g_scroll = 0;
    }
    const u32 visible = (n - g_scroll < max_rows) ? n - g_scroll : max_rows;
    const u32 row_w = (cw > duetos::drivers::video::kScrollbarWidth + kPad)
                          ? cw - duetos::drivers::video::kScrollbarWidth - kPad
                          : cw;
    // Per-kind tag glyph rendered in a 3-px coloured stripe at
    // the row's left edge. Severity reads at a glance without
    // needing colour-blind operators to parse the panel tint.
    auto kind_stripe_rgb = [](duetos::drivers::video::NotifyKind k) -> u32
    {
        switch (k)
        {
        case duetos::drivers::video::NotifyKind::Success:
            return 0x0050C050u;
        case duetos::drivers::video::NotifyKind::Warning:
            return 0x00E0A040u;
        case duetos::drivers::video::NotifyKind::Error:
            return 0x00E04040u;
        case duetos::drivers::video::NotifyKind::Info:
        default:
            return 0x004060A0u;
        }
    };
    for (u32 i = 0; i < visible; ++i)
    {
        const u32 idx = g_scroll + i;
        const u32 row_y = cy + i * kRowH;
        const bool sel = (idx == g_selection);
        FramebufferFillRect(cx, row_y, row_w, kRowH, sel ? sel_bg : bg);
        // Severity stripe: 3 px wide, full row height.
        const auto kind = duetos::drivers::video::NotifyHistoryGetKind(idx);
        FramebufferFillRect(cx, row_y, 3, kRowH, kind_stripe_rgb(kind));
        char buf[duetos::drivers::video::kNotifyMaxText + 8];
        u32 o = 0;
        buf[o++] = '[';
        if (idx >= 10)
            buf[o++] = static_cast<char>('0' + (idx / 10));
        buf[o++] = static_cast<char>('0' + (idx % 10));
        buf[o++] = ']';
        buf[o++] = ' ';
        const u32 wrote = duetos::drivers::video::NotifyHistoryGet(idx, buf + o, sizeof(buf) - o);
        buf[o + wrote] = '\0';
        FramebufferDrawString(cx + kPad + 4, row_y + 2, buf, sel ? sel_fg : fg, sel ? sel_bg : bg);
    }
    // Scrollbar registration so the kernel mouse loop can
    // hit-test this app's scrollbar with the rest.
    if (n > max_rows && cw > duetos::drivers::video::kScrollbarWidth)
    {
        const u32 sb_x = cx + cw - duetos::drivers::video::kScrollbarWidth;
        const u32 sb_y = cy;
        const u32 sb_w = duetos::drivers::video::kScrollbarWidth;
        const u32 sb_h = max_rows * kRowH;
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sb_w, sb_h, {n, max_rows, g_scroll});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sb_w;
        s.h = sb_h;
        s.total = n;
        s.visible = max_rows;
        s.first = g_scroll;
        duetos::drivers::video::WindowSetScrollbar(g_handle, s);
    }
    else
    {
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_handle, s);
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const u32 bg = 0x00181820;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Pass D chrome: refresh the header / footer text (constant
    // for notify_center — no per-state variation), re-anchor the
    // toolbar / labels to the current client rect, and paint the
    // WidgetGroup. The raw notification list (carve-out) sits in
    // the band between the header row and the AppLabel footer.
    BindNotifyCenterOnce();
    RefreshNotifyCenterHeader();
    RefreshNotifyCenterFooter();
    RebindNotifyCenterBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_notify_center.PaintAll(compose_ctx);

    // List band — between (toolbar + header) at the top and the
    // AppLabel footer at the bottom.
    const u32 top_band = kNcToolbarH + kNcHeaderH;
    const u32 bot_band = kNcFooterH + kPad;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintNotifyCenterList(list_x, list_y, list_w, list_h);
    }
}

} // namespace

void NotifyCenterInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, NotifyCenterOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle, [](u32 first) { g_scroll = first; });
    BindNotifyCenterOnce();
}

duetos::drivers::video::WindowHandle NotifyCenterWindow()
{
    return g_handle;
}

bool NotifyCenterFeedChar(char c)
{
    if (c == 'j' || c == 'J')
        return NotifyCenterFeedArrow(duetos::drivers::input::kKeyArrowDown);
    if (c == 'k' || c == 'K')
        return NotifyCenterFeedArrow(duetos::drivers::input::kKeyArrowUp);
    if (c == 'x' || c == 'X')
    {
        RequestClearConfirm();
        return true;
    }
    return false;
}

bool NotifyCenterFeedArrow(duetos::u16 keycode)
{
    using namespace duetos::drivers::input;
    const u32 n = duetos::drivers::video::NotifyHistoryCount();
    // Delete fires the clear-confirm even on an empty ring; the
    // confirm path itself reports the empty case via toast so
    // the operator gets feedback either way.
    if (keycode == kKeyDelete)
    {
        RequestClearConfirm();
        return true;
    }
    if (n == 0)
        return true;
    switch (keycode)
    {
    case kKeyArrowUp:
        if (g_selection > 0)
            --g_selection;
        return true;
    case kKeyArrowDown:
        if (g_selection + 1 < n)
            ++g_selection;
        return true;
    case kKeyPageUp:
        g_selection = (g_selection > 8) ? g_selection - 8 : 0;
        return true;
    case kKeyPageDown:
        g_selection = (g_selection + 8 < n) ? g_selection + 8 : n - 1;
        return true;
    case kKeyHome:
        g_selection = 0;
        return true;
    case kKeyEnd:
        g_selection = n - 1;
        return true;
    default:
        return false;
    }
}

void NotifyCenterOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    (void)modifiers;
    const u16 key = (dz > 0) ? duetos::drivers::input::kKeyArrowUp : duetos::drivers::input::kKeyArrowDown;
    const i32 steps = (dz > 0) ? dz : -dz;
    for (i32 i = 0; i < steps; ++i)
        NotifyCenterFeedArrow(key);
}

void NotifyCenterSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;

    // Pass D: drive a synthetic hover on the CLR toolbar button
    // via the WidgetGroup dispatch chain. ClickClear routes
    // through MessageBoxOpen which mutates dialog state; the
    // self-test stops at the hover edge so it never actually
    // pops the confirm dialog. The hover Consumed result alone
    // proves the dispatch path + bounds hit-test are wired
    // end-to-end. Header / footer composers are exercised
    // separately.
    BindNotifyCenterOnce();
    // Anchor the toolbar at (0, 22, 380, 218) — same shape
    // boot_bringup.cpp registers the live notify_center window
    // with (380x240 minus 22 px title bar). CLR is action
    // index 0.
    RebindNotifyCenterBounds(0U, 22U, 380U, 218U);
    constexpr u32 kClrIdx = 0U;
    const u32 nx = kNcToolbarPadX + kClrIdx * (kNcToolbarBtnW + kNcToolbarBtnGap) + kNcToolbarBtnW / 2U;
    const u32 ny = 22U + kNcToolbarPadY + kNcToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    if (g_notify_center.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;

    // Header / footer composers must produce non-empty text
    // after a refresh.
    RefreshNotifyCenterHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshNotifyCenterFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    g_notify_center_self_test_passed = ok;
    SerialWrite(ok ? "[notify_center-selftest] PASS\n" : "[notify_center-selftest] FAIL\n");
}

bool NotifyCenterSelfTestPassed()
{
    return g_notify_center_self_test_passed;
}

void NotifyCenterMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_handle == kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the same
    // frame RebindNotifyCenterBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindNotifyCenterOnce();
    RebindNotifyCenterBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_notify_center_prev_left_down;
    const bool release_edge = !left_down && g_notify_center_prev_left_down;
    g_notify_center_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_notify_center.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw notification rows sit below the
        // toolbar / header rows the WidgetGroup owns.
        // DispatchEvent's hit-test naturally short-circuits when
        // the click misses the toolbar bounds — the row list has
        // no per-row click semantics in v0 (selection is reached
        // only via the keyboard / wheel paths). MouseDown still
        // fires for the toolbar Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_notify_center.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_notify_center.DispatchEvent(u);
    }
}

} // namespace duetos::apps::notify_center
