#include "drivers/video/notify.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
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
};

constinit ToastState g_toast = {};

// History ring. Front-loaded: index 0 is the most recent
// displayed toast, index `count - 1` is the oldest. Pushed on
// every NotifyShowFor that has non-empty text. Duplicate-text
// pushes coalesce — a service that fires the same toast every
// second won't fill the ring with the same string.
struct HistorySlot
{
    char text[kNotifyMaxText + 1];
    u32 len;
};

constinit HistorySlot g_history[kNotifyHistoryCap] = {};
constinit u32 g_history_count = 0;

bool HistoryFrontMatches(const char* text, u32 len)
{
    if (g_history_count == 0)
        return false;
    const HistorySlot& f = g_history[0];
    if (f.len != len)
        return false;
    for (u32 i = 0; i < len; ++i)
    {
        if (f.text[i] != text[i])
            return false;
    }
    return true;
}

void HistoryPush(const char* text, u32 len)
{
    if (HistoryFrontMatches(text, len))
        return;
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
    if (g_history_count < kNotifyHistoryCap)
        ++g_history_count;
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

} // namespace

void NotifyShow(const char* text)
{
    NotifyShowFor(text, kNotifyDefaultTtlTicks);
}

void NotifyShowFor(const char* text, u32 ttl_ticks)
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
    HistoryPush(g_toast.text, n);
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

    // Background panel: theme's taskbar accent so the toast reads
    // as "system chrome" rather than app content. Border matches
    // window_border for visual consistency with the rest of the
    // chrome.
    FramebufferFillRect(box_x, box_y, box_w, box_h, th.taskbar_accent);
    FramebufferDrawRect(box_x, box_y, box_w, box_h, th.window_border, 1);

    const u32 text_x = box_x + padding_x;
    const u32 text_y = box_y + padding_y;
    FramebufferDrawString(text_x, text_y, g_toast.text, th.banner_fg, th.taskbar_accent);

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

    // Save state so the live toast (if any) is restored after the test.
    const ToastState save = g_toast;

    g_toast = {};
    ok = ok && !NotifyIsActive();

    NotifyShow("hello");
    ok = ok && NotifyIsActive();
    ok = ok && (g_toast.len == 5);
    ok = ok && (g_toast.ttl == kNotifyDefaultTtlTicks);

    NotifyShowFor("X", 7);
    ok = ok && (g_toast.ttl == 7);

    NotifyShow(nullptr);
    ok = ok && !NotifyIsActive();

    NotifyShowFor("over-long ........................................................................truncated", 3);
    ok = ok && (g_toast.len == kNotifyMaxText);

    NotifyShow(nullptr);

    g_toast = save;

    SerialWrite(ok ? "[notify] self-test OK\n" : "[notify] self-test FAILED\n");
}

} // namespace duetos::drivers::video
