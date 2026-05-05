#include "drivers/video/dnd.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

constexpr u32 kMaxTargets = 16;

struct TargetSlot
{
    bool in_use;
    u8 _pad[3];
    WindowHandle hwnd;
    DndDropFn cb;
    u32 accepted_mask;
};

constinit TargetSlot g_targets[kMaxTargets] = {};

struct DndState
{
    bool active;
    WindowHandle source;
    DndPayload payload;
    u32 cur_x, cur_y;
};

constinit DndState g_state = {};

void StorePayload(DndPayload& dst, const DndPayload& src)
{
    dst.kind = src.kind;
    u32 i = 0;
    while (i < kDndPayloadMax && src.text[i] != '\0')
    {
        dst.text[i] = src.text[i];
        ++i;
    }
    dst.text[i] = '\0';
}

} // namespace

void DndRegisterDropTarget(WindowHandle h, DndDropFn cb, u32 accepted_mask)
{
    // Replace if already registered for the same hwnd.
    for (u32 i = 0; i < kMaxTargets; ++i)
    {
        if (g_targets[i].in_use && g_targets[i].hwnd == h)
        {
            g_targets[i].cb = cb;
            g_targets[i].accepted_mask = accepted_mask;
            return;
        }
    }
    for (u32 i = 0; i < kMaxTargets; ++i)
    {
        if (!g_targets[i].in_use)
        {
            g_targets[i].in_use = true;
            g_targets[i].hwnd = h;
            g_targets[i].cb = cb;
            g_targets[i].accepted_mask = accepted_mask;
            return;
        }
    }
    duetos::arch::SerialWrite("[dnd] register: target table full\n");
}

bool DndBegin(WindowHandle source_hwnd, const DndPayload& payload, u32 grab_x, u32 grab_y)
{
    if (g_state.active)
        return false;
    g_state.active = true;
    g_state.source = source_hwnd;
    StorePayload(g_state.payload, payload);
    g_state.cur_x = grab_x;
    g_state.cur_y = grab_y;
    WindowSetCapture(source_hwnd);
    duetos::arch::SerialWrite("[dnd] begin source=");
    duetos::arch::SerialWriteHex(source_hwnd);
    duetos::arch::SerialWrite(" kind=");
    duetos::arch::SerialWriteHex(static_cast<u64>(payload.kind));
    duetos::arch::SerialWrite("\n");
    return true;
}

bool DndIsActive()
{
    return g_state.active;
}

const DndPayload& DndCurrentPayload()
{
    return g_state.payload;
}

void DndUpdateCursor(u32 cx, u32 cy)
{
    if (!g_state.active)
        return;
    g_state.cur_x = cx;
    g_state.cur_y = cy;
}

bool DndResolveAt(u32 cx, u32 cy)
{
    if (!g_state.active)
        return false;
    bool consumed = false;
    // Walk drop targets — first match wins. Could honour
    // z-order with a scan against WindowTopmostAt; v1's
    // first-match is good enough since drop-target windows
    // typically don't overlap.
    for (u32 i = 0; i < kMaxTargets; ++i)
    {
        const TargetSlot& s = g_targets[i];
        if (!s.in_use || s.cb == nullptr)
            continue;
        if (!WindowIsAlive(s.hwnd) || !WindowIsVisible(s.hwnd))
            continue;
        const u32 mask_bit = 1u << static_cast<u32>(g_state.payload.kind);
        if ((s.accepted_mask & mask_bit) == 0)
            continue;
        u32 wx = 0, wy = 0, ww = 0, wh = 0;
        if (!WindowGetBounds(s.hwnd, &wx, &wy, &ww, &wh))
            continue;
        if (cx < wx || cx >= wx + ww || cy < wy || cy >= wy + wh)
            continue;
        consumed = s.cb(g_state.payload, cx, cy);
        duetos::arch::SerialWrite("[dnd] drop target=");
        duetos::arch::SerialWriteHex(s.hwnd);
        duetos::arch::SerialWrite(consumed ? " accepted\n" : " rejected\n");
        break;
    }
    g_state.active = false;
    g_state.payload.kind = DndKind::None;
    WindowReleaseCapture();
    return consumed;
}

void DndCancel()
{
    if (!g_state.active)
        return;
    g_state.active = false;
    g_state.payload.kind = DndKind::None;
    WindowReleaseCapture();
    duetos::arch::SerialWrite("[dnd] cancel\n");
}

void DndCompose()
{
    if (!g_state.active)
        return;
    // Ghost image: a small panel anchored just below+right of
    // the cursor showing the payload text. Themed for legibility
    // against any wallpaper.
    const auto& th = ThemeCurrent();
    const u32 panel_bg = th.taskbar_accent;
    const u32 ink = 0x00101020;
    const u32 border = th.window_border;
    constexpr u32 kPad = 4;
    constexpr u32 kGlyphW = 8;
    constexpr u32 kGlyphH = 8;
    u32 len = 0;
    while (len < kDndPayloadMax && g_state.payload.text[len] != '\0')
        ++len;
    const u32 text_w = len * kGlyphW;
    const u32 panel_w = text_w + 2 * kPad;
    const u32 panel_h = kGlyphH + 2 * kPad;
    const auto fb = FramebufferGet();
    u32 px = g_state.cur_x + 16;
    u32 py = g_state.cur_y + 16;
    if (px + panel_w > fb.width)
        px = (fb.width > panel_w) ? fb.width - panel_w : 0;
    if (py + panel_h > fb.height)
        py = (fb.height > panel_h) ? fb.height - panel_h : 0;
    FramebufferFillRect(px, py, panel_w, panel_h, panel_bg);
    FramebufferDrawRect(px, py, panel_w, panel_h, border, 1);
    FramebufferDrawString(px + kPad, py + kPad, g_state.payload.text, ink, panel_bg);
}

} // namespace duetos::drivers::video
