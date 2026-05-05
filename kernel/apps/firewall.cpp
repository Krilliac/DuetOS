#include "apps/firewall.h"

#include "drivers/video/framebuffer.h"

namespace duetos::apps::firewall
{

namespace
{

constexpr u32 kRowH = 14;
constexpr u32 kMargin = 16;
constexpr u32 kHeaderFg = 0x00FFD040;
constexpr u32 kFg = 0x00C8D0DA;
constexpr u32 kFgDim = 0x00808890;
constexpr u32 kBg = 0x00181020;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy + kMargin;
    FramebufferDrawString(cx + kMargin, y, "DUETOS FIREWALL", kHeaderFg, kBg);
    y += kRowH + 8;
    FramebufferDrawString(cx + kMargin, y, "STATUS: NOT INSTALLED", kFg, kBg);
    y += kRowH + 4;
    FramebufferDrawString(cx + kMargin, y, "RULES:  0  (no filter subsystem in v0)", kFgDim, kBg);
    y += kRowH * 2;
    FramebufferDrawString(cx + kMargin, y, "DuetOS does not yet ship a packet filter.", kFg, kBg);
    y += kRowH;
    FramebufferDrawString(cx + kMargin, y, "All bound interfaces are unfiltered — every", kFgDim, kBg);
    y += kRowH;
    FramebufferDrawString(cx + kMargin, y, "packet the NIC accepts reaches the stack.", kFgDim, kBg);
    y += kRowH * 2;
    FramebufferDrawString(cx + kMargin, y, "ROADMAP:", kHeaderFg, kBg);
    y += kRowH;
    FramebufferDrawString(cx + kMargin, y, "  wiki/networking/Firewall-Roadmap.md", kFg, kBg);
}

} // namespace

void FirewallInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle FirewallWindow()
{
    return g_handle;
}

} // namespace duetos::apps::firewall
