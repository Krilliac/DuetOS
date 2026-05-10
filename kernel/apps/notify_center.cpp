#include "apps/notify_center.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"

namespace duetos::apps::notify_center
{

namespace
{

constexpr u32 kRowH = 12;
constexpr u32 kPad = 4;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;
constinit u32 g_selection = 0;
constinit u32 g_scroll = 0;

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = 0x00181820;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 sel_bg = th.taskbar_accent;
    const u32 sel_fg = 0x00101020;
    FramebufferFillRect(cx, cy, cw, ch, bg);
    FramebufferDrawString(cx + kPad, cy + kPad, "NOTIFICATION HISTORY", fg, bg);
    const u32 list_top = cy + kPad + 12;
    const u32 list_h = (ch > kPad + 12 + 14) ? ch - (kPad + 12 + 14) : 0;
    const u32 max_rows = list_h / kRowH;
    if (max_rows == 0)
        return;
    const u32 n = duetos::drivers::video::NotifyHistoryCount();
    if (n == 0)
    {
        FramebufferDrawString(cx + kPad, list_top + 2, "(no notifications yet)", dim, bg);
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
    // Per-kind tag glyph rendered in a 4-px coloured stripe at
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
        const u32 row_y = list_top + i * kRowH;
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
        const u32 sb_y = list_top;
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
    // Footer hint.
    FramebufferDrawString(cx + kPad, cy + ch - 12, "J/K UP/DN HOME/END PG  X/DEL=CLEAR  Ctrl+Shift+N=DUMP", dim, bg);
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
    // Caller is the kbd-reader thread, holding the compositor
    // lock — same context every other DialogOpen call uses.
    duetos::drivers::video::MessageBoxOpen("CLEAR HISTORY", "Discard every notification entry?", OnClearConfirm,
                                           nullptr);
}

} // namespace

void NotifyCenterInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, NotifyCenterOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle, [](u32 first) { g_scroll = first; });
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

} // namespace duetos::apps::notify_center
