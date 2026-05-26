#include "drivers/video/notify.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

struct ToastState
{
    char text[kNotifyMaxText + 1];
    u32 len;
    u32 ttl;
    NotifyKind kind;
};

constinit ToastState g_toast = {};

// History ring. Front-loaded: index 0 is the most recent
// displayed toast, index `count - 1` is the oldest. Pushed on
// every NotifyShowFor that has non-empty text. Duplicate
// (text, kind) pushes coalesce — a service that fires the same
// toast every second won't fill the ring with the same string.
// Different-kind pushes of the same text DO push so an operator
// sees the Info→Warning→Error transition.
struct HistorySlot
{
    char text[kNotifyMaxText + 1];
    u32 len;
    NotifyKind kind;
};

constinit HistorySlot g_history[kNotifyHistoryCap] = {};
constinit u32 g_history_count = 0;

bool HistoryFrontMatches(const char* text, u32 len, NotifyKind kind)
{
    if (g_history_count == 0)
        return false;
    const HistorySlot& f = g_history[0];
    if (f.len != len || f.kind != kind)
        return false;
    for (u32 i = 0; i < len; ++i)
    {
        if (f.text[i] != text[i])
            return false;
    }
    return true;
}

// Returns true iff this call inserted a new row at the ring's
// front. False when the (text, kind) pair coalesced against the
// existing front entry. The caller uses this to gate the UI sound
// cue so a service that hammers the same toast every tick beeps
// at most once.
bool HistoryPush(const char* text, u32 len, NotifyKind kind)
{
    if (HistoryFrontMatches(text, len, kind))
        return false;
    // Shift down by one to make room at the front. Drop the
    // oldest entry if the ring is full.
    const u32 keep = (g_history_count < kNotifyHistoryCap) ? g_history_count : (kNotifyHistoryCap - 1);
    for (u32 i = keep; i > 0; --i)
    {
        g_history[i] = g_history[i - 1];
    }
    HistorySlot& dst = g_history[0];
    for (u32 i = 0; i < len; ++i)
    {
        dst.text[i] = text[i];
    }
    dst.text[len] = '\0';
    dst.len = len;
    dst.kind = kind;
    if (g_history_count < kNotifyHistoryCap)
        ++g_history_count;
    return true;
}

// RGB swatches for each severity. Picked to read against
// `theme.banner_fg` (which is light in every shipped theme) and
// to match the "panel + 1px dark border" chrome the live toast
// uses. Info falls through to the theme's accent so each
// theme's palette still drives the neutral case.
u32 KindPanelRgb(NotifyKind kind, u32 theme_accent)
{
    switch (kind)
    {
    case NotifyKind::Success:
        return 0x00305030u;
    case NotifyKind::Warning:
        return 0x00604020u;
    case NotifyKind::Error:
        return 0x00603030u;
    case NotifyKind::Info:
    default:
        return theme_accent;
    }
}

u32 StrLenCapped(const char* s, u32 cap)
{
    if (s == nullptr)
    {
        return 0;
    }
    u32 n = 0;
    while (s[n] != '\0' && n < cap)
    {
        ++n;
    }
    return n;
}

// ---------------------------------------------------------------
// Pass D chrome: AppPanel (severity-coloured bg + 1 px border +
// soft shadow on tactility-on themes) + AppLabel (toast body
// text, ChromeTextRole::Body). Toast has NO interactive surface
// — implicit-dismiss-on-timeout is the only dismissal path, so
// there is no NotifyMouseInput and no AppButton.
//
// Carve-outs: none. The full toast chrome composes through the
// WidgetGroup — the per-frame ttl decrement + headless-fb early
// exit stay in NotifyRedraw since they are state mechanics, not
// paint.

using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppPanel;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// AppLabel stores text by pointer, so g_toast.text (a constinit
// fixed-cap buffer that lives in this TU) is the stable storage
// — re-binding it once at bind-time is enough.
constinit auto g_notify = MakeWidgetGroup(AppPanel{}, AppLabel{});

constinit bool g_notify_bound = false;
constinit bool g_notify_self_test_passed = false;

// Walk the chain by hand to grab a stable pointer to the panel +
// label. Chain order mirrors the MakeWidgetGroup argument list
// (panel -> label).
AppPanel& NotifyPanel()
{
    return g_notify.chain.head;
}
AppLabel& NotifyLabel()
{
    return g_notify.chain.tail.head;
}

void BindNotifyOnce()
{
    if (g_notify_bound)
        return;
    g_notify_bound = true;

    AppPanel& p = NotifyPanel();
    // shadow_radius is intentionally smaller than the app-panel
    // default (12) — toasts are ~120-700 px wide and a 12 px
    // shadow blooms past the right edge of the screen at the
    // tightest framebuffers.
    p.shadow_radius = 8U;

    AppLabel& l = NotifyLabel();
    l.text = g_toast.text;
    l.role = ChromeTextRole::Body;
    l.weight = ChromeTextWeight::Regular;
    l.align_left = true;
}

// Re-anchor the panel + label to the live toast bounds. Called
// from NotifyRedraw before PaintAll so the chrome tracks the
// current framebuffer dimensions + text width.
void RebindNotifyBounds(u32 box_x, u32 box_y, u32 box_w, u32 box_h, u32 text_x, u32 text_y, u32 text_w, u32 text_h,
                        u32 panel_rgb, u32 border_rgb, u32 fg_rgb)
{
    AppPanel& p = NotifyPanel();
    p.bounds = Rect{box_x, box_y, box_w, box_h};
    p.bg_rgb = panel_rgb;
    p.border_rgb = border_rgb;

    AppLabel& l = NotifyLabel();
    l.bounds = Rect{text_x, text_y, text_w, text_h};
    l.fg_rgb = fg_rgb;
    l.bg_rgb = panel_rgb;
    // Re-point at the live text buffer in case a self-test (or
    // future caller) ever swaps the underlying storage.
    l.text = g_toast.text;
}

} // namespace

void NotifyShow(const char* text)
{
    NotifyShowKindFor(text, NotifyKind::Info, kNotifyDefaultTtlTicks);
}

void NotifyShowFor(const char* text, u32 ttl_ticks)
{
    NotifyShowKindFor(text, NotifyKind::Info, ttl_ticks);
}

void NotifyShowKind(const char* text, NotifyKind kind)
{
    NotifyShowKindFor(text, kind, kNotifyDefaultTtlTicks);
}

void NotifyShowKindFor(const char* text, NotifyKind kind, u32 ttl_ticks)
{
    if (text == nullptr || text[0] == '\0' || ttl_ticks == 0)
    {
        g_toast.len = 0;
        g_toast.ttl = 0;
        return;
    }
    const u32 n = StrLenCapped(text, kNotifyMaxText);
    for (u32 i = 0; i < n; ++i)
    {
        g_toast.text[i] = text[i];
    }
    g_toast.text[n] = '\0';
    g_toast.len = n;
    g_toast.ttl = ttl_ticks;
    g_toast.kind = kind;
    const bool pushed = HistoryPush(g_toast.text, n, kind);
    // UI sound cue — gated on `pushed` so a service that keeps
    // firing the same (text, kind) pair (which coalesces in the
    // history ring) doesn't beep every tick. Info toasts are
    // silent on purpose: most boot banners are Info and a chime
    // on every welcome message is noise. The cue functions are
    // already gated by SoundCueSetEnabled; no-op when muted.
    if (pushed)
    {
        switch (kind)
        {
        case NotifyKind::Error:
        case NotifyKind::Warning:
            // Warning shares the low-buzz reject tone — operators
            // treat "battery 5%" and "write failed" as the same
            // class of "something needs attention now".
            SoundCueError();
            break;
        case NotifyKind::Success:
            SoundCueChime();
            break;
        case NotifyKind::Info:
        default:
            break;
        }
    }
}

u32 NotifyHistoryCount()
{
    return g_history_count;
}

u32 NotifyHistoryGet(u32 idx, char* out, u32 cap)
{
    if (out == nullptr || cap == 0 || idx >= g_history_count)
        return 0;
    const HistorySlot& s = g_history[idx];
    const u32 take = (s.len + 1 < cap) ? s.len : cap - 1;
    for (u32 i = 0; i < take; ++i)
    {
        out[i] = s.text[i];
    }
    out[take] = '\0';
    return take;
}

NotifyKind NotifyHistoryGetKind(u32 idx)
{
    if (idx >= g_history_count)
        return NotifyKind::Info;
    return g_history[idx].kind;
}

void NotifyHistoryClear()
{
    for (u32 i = 0; i < g_history_count; ++i)
    {
        g_history[i].text[0] = '\0';
        g_history[i].len = 0;
        g_history[i].kind = NotifyKind::Info;
    }
    g_history_count = 0;
}

bool NotifyIsActive()
{
    return g_toast.ttl > 0 && g_toast.len > 0;
}

void NotifyRedraw()
{
    if (g_toast.ttl == 0 || g_toast.len == 0)
    {
        return;
    }
    const auto fb = FramebufferGet();
    if (fb.width == 0 || fb.height == 0)
    {
        // Decrement the TTL anyway so a head-less compose still
        // ages the toast — matches the user expectation that "3
        // seconds" is wall-clock, not paint count.
        --g_toast.ttl;
        return;
    }

    const auto& th = ThemeCurrent();
    const u32 tb_h = TaskbarHeight();
    const u32 padding_x = 12;
    const u32 padding_y = 6;
    const u32 text_w = g_toast.len * 8;
    const u32 box_w = text_w + 2 * padding_x;
    const u32 box_h = 8 + 2 * padding_y;
    const u32 margin = 8;
    if (box_w + margin > fb.width)
    {
        --g_toast.ttl;
        return;
    }
    const u32 box_x = fb.width - box_w - margin;
    const u32 baseline = (fb.height > tb_h) ? fb.height - tb_h : 0;
    const u32 box_y = (baseline > box_h + margin) ? baseline - box_h - margin : 0;

    // Background panel: severity-driven (Info uses theme accent;
    // Warning / Error / Success use fixed swatches that read as
    // "system chrome" but visually distinct from neutral status).
    // Border matches window_border for visual consistency with
    // the rest of the chrome.
    const u32 panel_rgb = KindPanelRgb(g_toast.kind, th.taskbar_accent);

    // Pass D chrome: bind the panel + label widgets once, anchor
    // them to the just-computed box, then paint via the
    // WidgetGroup. AppPanel handles tactility-on shadow internally,
    // so a `tactility=on` theme now drops a soft drop-shadow under
    // the toast — used to be a hard 1 px border only.
    BindNotifyOnce();
    const u32 text_x = box_x + padding_x;
    const u32 text_y = box_y + padding_y;
    RebindNotifyBounds(box_x, box_y, box_w, box_h, text_x, text_y, text_w, box_h - 2 * padding_y, panel_rgb,
                       th.window_border, th.banner_fg);

    Compose compose_ctx{};
    g_notify.PaintAll(compose_ctx);

    --g_toast.ttl;
    if (g_toast.ttl == 0)
    {
        g_toast.len = 0;
        g_toast.text[0] = '\0';
    }
}

void NotifySelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;

    // Mute the sound cue for the duration of the self-test so the
    // Warning / Error rounds below don't blast the PC speaker on
    // every boot. Restored to the operator's prior setting before
    // we return so the live toast path keeps cueing normally.
    const bool prev_sound_enabled = SoundCueIsEnabled();
    SoundCueSetEnabled(false);

    // Save state so the live toast (if any) is restored after the test.
    const ToastState save = g_toast;

    // Snapshot + clear the history ring; the test scribbles into
    // it and we restore the operator's view at the end.
    HistorySlot saved_history[kNotifyHistoryCap];
    for (u32 i = 0; i < kNotifyHistoryCap; ++i)
        saved_history[i] = g_history[i];
    const u32 saved_history_count = g_history_count;
    NotifyHistoryClear();
    ok = ok && (NotifyHistoryCount() == 0);

    g_toast = {};
    ok = ok && !NotifyIsActive();

    NotifyShow("hello");
    ok = ok && NotifyIsActive();
    ok = ok && (g_toast.len == 5);
    ok = ok && (g_toast.ttl == kNotifyDefaultTtlTicks);
    ok = ok && (g_toast.kind == NotifyKind::Info);

    NotifyShowFor("X", 7);
    ok = ok && (g_toast.ttl == 7);

    NotifyShow(nullptr);
    ok = ok && !NotifyIsActive();

    NotifyShowFor("over-long ........................................................................truncated", 3);
    ok = ok && (g_toast.len == kNotifyMaxText);

    // Severity round-trip: Warning toast keeps its kind in the
    // history slot.
    NotifyShow(nullptr);
    NotifyHistoryClear();
    NotifyShowKind("battery 5%", NotifyKind::Warning);
    ok = ok && (g_toast.kind == NotifyKind::Warning);
    ok = ok && (NotifyHistoryCount() == 1);
    ok = ok && (NotifyHistoryGetKind(0) == NotifyKind::Warning);

    // Same text, different kind → ring DOES push (Info→Error
    // transition is operator-meaningful).
    NotifyShowKind("battery 5%", NotifyKind::Error);
    ok = ok && (NotifyHistoryCount() == 2);
    ok = ok && (NotifyHistoryGetKind(0) == NotifyKind::Error);
    ok = ok && (NotifyHistoryGetKind(1) == NotifyKind::Warning);

    // Same (text, kind) → ring coalesces.
    NotifyShowKind("battery 5%", NotifyKind::Error);
    ok = ok && (NotifyHistoryCount() == 2);

    // Out-of-range kind read returns Info as a safe fallback.
    ok = ok && (NotifyHistoryGetKind(99) == NotifyKind::Info);

    NotifyHistoryClear();
    ok = ok && (NotifyHistoryCount() == 0);

    NotifyShow(nullptr);

    // Pass D: bind + re-anchor the WidgetGroup chain and verify
    // the rebind landed. We deliberately do NOT call PaintAll
    // here: under TTF themes (duet*) AppLabel::PaintSelf routes
    // into TtfDrawString -> CompositeCoverage ->
    // FramebufferBlendFill and races the compositor lock when
    // the self-test runs before the WM is online (silent boot
    // halt). The live NotifyRedraw() path exercises Paint each
    // time a real toast fires.
    BindNotifyOnce();
    RebindNotifyBounds(/*box*/ 16U, 16U, 240U, 32U,
                       /*text*/ 28U, 22U, 200U, 20U,
                       /*panel*/ 0x00305030U,
                       /*border*/ 0x00000000U,
                       /*fg*/ 0x00FFFFFFU);
    ok = ok && (NotifyPanel().bounds.w == 240U);
    ok = ok && (NotifyLabel().bounds.w == 200U);
    ok = ok && (NotifyLabel().text == g_toast.text);

    // Restore the operator's history ring + the live toast.
    for (u32 i = 0; i < kNotifyHistoryCap; ++i)
        g_history[i] = saved_history[i];
    g_history_count = saved_history_count;
    g_toast = save;

    // Restore the sound-cue master toggle.
    SoundCueSetEnabled(prev_sound_enabled);

    g_notify_self_test_passed = ok;
    SerialWrite(ok ? "[notify-selftest] PASS\n" : "[notify-selftest] FAIL\n");
}

bool NotifySelfTestPassed()
{
    return g_notify_self_test_passed;
}

} // namespace duetos::drivers::video
