#include "apps/firewall.h"

#include "drivers/video/framebuffer.h"
#include "net/firewall.h"
#include "net/stack.h"

namespace duetos::apps::firewall
{

namespace
{

constexpr u32 kRowH = 14;
constexpr u32 kMargin = 16;
constexpr u32 kHeaderFg = 0x00FFD040;
constexpr u32 kFg = 0x00C8D0DA;
constexpr u32 kFgDim = 0x00808890;
constexpr u32 kAllowFg = 0x0040E060;
constexpr u32 kDenyFg = 0x00E04040;
constexpr u32 kBg = 0x00181020;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

void Append(char* line, u32& pos, u32 cap, const char* s)
{
    while (*s != '\0' && pos + 1 < cap)
    {
        line[pos++] = *s++;
    }
}

void AppendU(char* line, u32& pos, u32 cap, u64 v)
{
    char buf[24];
    u32 t = 0;
    if (v == 0)
    {
        buf[t++] = '0';
    }
    while (v != 0)
    {
        buf[t++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (t != 0 && pos + 1 < cap)
    {
        line[pos++] = buf[--t];
    }
}

void AppendIp(char* line, u32& pos, u32 cap, duetos::net::Ipv4Address ip, u8 mask)
{
    for (u32 i = 0; i < 4; ++i)
    {
        AppendU(line, pos, cap, ip.octets[i]);
        if (i < 3 && pos + 1 < cap)
        {
            line[pos++] = '.';
        }
    }
    if (pos + 1 < cap)
    {
        line[pos++] = '/';
    }
    AppendU(line, pos, cap, mask);
}

const char* DirName(duetos::net::firewall::Direction d)
{
    return d == duetos::net::firewall::Direction::Ingress ? "IN " : "OUT";
}

const char* ProtoName(duetos::net::firewall::Proto p)
{
    using duetos::net::firewall::Proto;
    switch (p)
    {
    case Proto::Icmp:
        return "ICMP";
    case Proto::Tcp:
        return "TCP ";
    case Proto::Udp:
        return "UDP ";
    case Proto::Any:
    default:
        return "ANY ";
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy + kMargin;
    FramebufferDrawString(cx + kMargin, y, "DUETOS FIREWALL", kHeaderFg, kBg);
    y += kRowH + 4;

    char line[120];
    u32 pos = 0;
    Append(line, pos, sizeof(line), "DEFAULT IN=");
    Append(line, pos, sizeof(line),
           duetos::net::firewall::FwDefaultPolicy(duetos::net::firewall::Direction::Ingress) ==
                   duetos::net::firewall::Action::Allow
               ? "ALLOW"
               : "DENY");
    Append(line, pos, sizeof(line), " OUT=");
    Append(line, pos, sizeof(line),
           duetos::net::firewall::FwDefaultPolicy(duetos::net::firewall::Direction::Egress) ==
                   duetos::net::firewall::Action::Allow
               ? "ALLOW"
               : "DENY");
    line[pos] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
    y += kRowH;

    const duetos::net::firewall::Stats stats = duetos::net::firewall::FwStatsRead();
    pos = 0;
    Append(line, pos, sizeof(line), "STATS    IN: ");
    AppendU(line, pos, sizeof(line), stats.ingress_checked);
    Append(line, pos, sizeof(line), " checked, ");
    AppendU(line, pos, sizeof(line), stats.ingress_denied);
    Append(line, pos, sizeof(line), " denied   OUT: ");
    AppendU(line, pos, sizeof(line), stats.egress_checked);
    Append(line, pos, sizeof(line), " checked, ");
    AppendU(line, pos, sizeof(line), stats.egress_denied);
    Append(line, pos, sizeof(line), " denied");
    line[pos] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kFgDim, kBg);
    y += kRowH + 4;

    FramebufferDrawString(cx + kMargin, y, "RULES (first match wins)", kHeaderFg, kBg);
    y += kRowH;
    FramebufferDrawString(cx + kMargin, y, "IDX  DIR PROTO SRC                DST                ACTION HITS", kFgDim,
                          kBg);
    y += kRowH;

    duetos::net::firewall::Rule snap[duetos::net::firewall::kFwMaxRules];
    const u32 n = duetos::net::firewall::FwSnapshot(snap, duetos::net::firewall::kFwMaxRules);
    bool any = false;
    for (u32 i = 0; i < n && y + kRowH < cy + ch; ++i)
    {
        if (!snap[i].active)
        {
            continue;
        }
        any = true;
        pos = 0;
        if (i < 10)
        {
            line[pos++] = ' ';
        }
        AppendU(line, pos, sizeof(line), i);
        Append(line, pos, sizeof(line), "   ");
        Append(line, pos, sizeof(line), DirName(snap[i].dir));
        line[pos++] = ' ';
        Append(line, pos, sizeof(line), ProtoName(snap[i].proto));
        line[pos++] = ' ';
        const u32 src_start = pos;
        AppendIp(line, pos, sizeof(line), snap[i].src.addr, snap[i].src.mask_bits);
        while (pos - src_start < 18 && pos + 1 < sizeof(line))
        {
            line[pos++] = ' ';
        }
        line[pos++] = ' ';
        const u32 dst_start = pos;
        AppendIp(line, pos, sizeof(line), snap[i].dst.addr, snap[i].dst.mask_bits);
        while (pos - dst_start < 18 && pos + 1 < sizeof(line))
        {
            line[pos++] = ' ';
        }
        line[pos++] = ' ';
        const bool allow = snap[i].action == duetos::net::firewall::Action::Allow;
        Append(line, pos, sizeof(line), allow ? "ALLOW " : "DENY  ");
        line[pos++] = ' ';
        AppendU(line, pos, sizeof(line), snap[i].hits);
        line[pos] = '\0';
        FramebufferDrawString(cx + kMargin, y, line, allow ? kAllowFg : kDenyFg, kBg);
        y += kRowH;
    }
    if (!any)
    {
        FramebufferDrawString(cx + kMargin, y, "  (no active rules — only defaults apply)", kFgDim, kBg);
        y += kRowH;
    }

    y += kRowH;
    FramebufferDrawString(cx + kMargin, y, "EDIT requires NetAdmin capability (kernel shell: fw add/del)", kFgDim, kBg);
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
