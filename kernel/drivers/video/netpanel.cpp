#include "drivers/video/netpanel.h"

#include "drivers/net/net.h"
#include "net/stack.h"
#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video
{

namespace
{

// --- Geometry ---
//
// Two layouts: a small Preview pill, a tall Full panel. Both
// anchor at (g_ax, g_ay) — caller positions them above the
// taskbar tray cell.
constexpr u32 kPreviewW = 220;
constexpr u32 kPreviewH = 56;
constexpr u32 kFullW = 320;
// Height grows with content but is capped to avoid going past the
// top of the framebuffer on small modes. Computed dynamically;
// see ComputeFullHeight().
constexpr u32 kFullHMin = 200;
constexpr u32 kFullHMax = 460;

constexpr u32 kMargin = 10;
constexpr u32 kRowH = 14;
constexpr u32 kSectionGap = 8;

// Same palette family as calendar.cpp + menu.cpp so the popups
// look like siblings.
constexpr u32 kBodyRgb = 0x00303848;
constexpr u32 kBorderRgb = 0x00101828;
constexpr u32 kHeaderRgb = 0x00406090;
constexpr u32 kAccentRgb = 0x0054C06A; // green: connected
constexpr u32 kWarnRgb = 0x00C0A040;   // amber: pending
constexpr u32 kDimRgb = 0x00707884;
constexpr u32 kTextRgb = 0x00FFFFFF;
constexpr u32 kButtonRgb = 0x00406090;

constinit NetPanelMode g_mode = NetPanelMode::Closed;
constinit u32 g_ax = 0;
constinit u32 g_ay = 0;
constinit u32 g_height = 0;
constinit u32 g_renew_x = 0;
constinit u32 g_renew_y = 0;
constinit u32 g_renew_w = 0;
constinit u32 g_renew_h = 0;

// --- Tiny string helpers ---

void WriteAt(u32 x, u32 y, const char* s, u32 fg, u32 bg)
{
    FramebufferDrawString(x, y, s, fg, bg);
}

u32 FormatU64Dec(u64 v, char* buf, u32 cap)
{
    if (cap < 2)
    {
        if (cap == 1)
            buf[0] = '\0';
        return 0;
    }
    char tmp[24];
    u32 n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    if (n > cap - 1)
        n = cap - 1;
    for (u32 i = 0; i < n; ++i)
        buf[i] = tmp[n - 1 - i];
    buf[n] = '\0';
    return n;
}

// "10.0.2.15" — 4 dotted-quad octets into `buf`. Returns chars
// written (excluding NUL).
u32 FormatIpv4(duetos::net::Ipv4Address ip, char* buf, u32 cap)
{
    u32 off = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        if (i != 0)
        {
            if (off + 1 >= cap)
                break;
            buf[off++] = '.';
        }
        char tmp[4];
        const u32 n = FormatU64Dec(ip.octets[i], tmp, sizeof(tmp));
        for (u32 j = 0; j < n && off + 1 < cap; ++j)
            buf[off++] = tmp[j];
    }
    if (off < cap)
        buf[off] = '\0';
    return off;
}

// Place an "IP: a.b.c.d" line.
void DrawLabelValue(u32 x, u32 y, const char* label, const char* value, u32 bg)
{
    WriteAt(x, y, label, kDimRgb, bg);
    const u32 lw = 0;
    (void)lw;
    // Label is fixed-width 4 chars (8 px each = 32 px) + 8 px gap.
    u32 i = 0;
    while (label[i] != '\0')
        ++i;
    WriteAt(x + i * 8 + 8, y, value, kTextRgb, bg);
}

bool Ipv4IsZero(duetos::net::Ipv4Address ip)
{
    for (u32 i = 0; i < 4; ++i)
        if (ip.octets[i] != 0)
            return false;
    return true;
}

u32 ComputeFullHeight()
{
    // Header (24) + connection summary (28) + section gap.
    u32 h = kMargin + 24 + 4 + 28 + kSectionGap;
    // Wireless section header + up to 3 lines (count + shell-status +
    // firmware-pending hint when a driver shell bound).
    h += 12 + kRowH * 3 + kSectionGap;
    // Wired section header + per-NIC: 1 chrome line + 3 detail lines.
    h += 12; // section header
    const u64 nics = duetos::drivers::net::NicCount();
    if (nics == 0)
    {
        h += kRowH;
    }
    else
    {
        for (u64 i = 0; i < nics; ++i)
        {
            if (duetos::drivers::net::NicIsWireless(i))
                continue;
            // Heading + ip + gateway + dns = 4 rows per wired NIC.
            h += kRowH * 4 + 4;
        }
    }
    h += kSectionGap;
    // Renew button row.
    h += 28 + kMargin;
    if (h < kFullHMin)
        h = kFullHMin;
    if (h > kFullHMax)
        h = kFullHMax;
    return h;
}

void DrawHeader(u32 ax, u32 ay, u32 w, const char* title)
{
    FramebufferFillRect(ax + kMargin, ay + kMargin, w - kMargin * 2, 22, kHeaderRgb);
    const u32 tw = 0;
    (void)tw;
    u32 nlen = 0;
    while (title[nlen] != '\0')
        ++nlen;
    const u32 tx = ax + kMargin + 6;
    const u32 ty = ay + kMargin + (22 - 8) / 2;
    WriteAt(tx, ty, title, kTextRgb, kHeaderRgb);
}

void DrawPreview()
{
    FramebufferFillRect(g_ax, g_ay, kPreviewW, kPreviewH, kBodyRgb);
    FramebufferDrawRect(g_ax, g_ay, kPreviewW, kPreviewH, kBorderRgb, 2);

    const auto lease = duetos::net::DhcpLeaseRead();
    const u64 nics = duetos::drivers::net::NicCount();
    const bool any_link = nics > 0;
    const bool online = any_link && lease.valid;

    // Status pip.
    const u32 dot = 8;
    const u32 dot_x = g_ax + 10;
    const u32 dot_y = g_ay + 10;
    FramebufferFillRect(dot_x, dot_y, dot, dot, !any_link ? kDimRgb : online ? kAccentRgb : kWarnRgb);

    const char* status = !any_link ? "OFFLINE (no NIC)" : online ? "CONNECTED" : "PENDING (DHCP)";
    WriteAt(g_ax + 26, g_ay + 10, status, kTextRgb, kBodyRgb);

    // IP line below.
    char buf[24];
    if (online)
    {
        char ipbuf[20];
        FormatIpv4(lease.ip, ipbuf, sizeof(ipbuf));
        u32 off = 0;
        const char* lab = "IP ";
        while (lab[off] != '\0')
        {
            buf[off] = lab[off];
            ++off;
        }
        for (u32 i = 0; ipbuf[i] != '\0' && off + 1 < sizeof(buf); ++i)
            buf[off++] = ipbuf[i];
        buf[off] = '\0';
        WriteAt(g_ax + 10, g_ay + 28, buf, kTextRgb, kBodyRgb);
    }
    else
    {
        WriteAt(g_ax + 10, g_ay + 28, "click for details", kDimRgb, kBodyRgb);
    }

    // Hint at the bottom that clicking expands.
    WriteAt(g_ax + 10, g_ay + 42, "click to expand", kDimRgb, kBodyRgb);
}

void DrawWirelessSection(u32 ax, u32& y, u32 w)
{
    WriteAt(ax + kMargin, y, "WIRELESS", kAccentRgb, kBodyRgb);
    y += 12;
    const auto wifi = duetos::drivers::net::WirelessStatusRead();
    if (wifi.adapters_detected == 0)
    {
        WriteAt(ax + kMargin, y, "  no wireless adapter", kDimRgb, kBodyRgb);
        y += kRowH;
        WriteAt(ax + kMargin, y, "  (use wired below)", kDimRgb, kBodyRgb);
        y += kRowH;
        (void)w;
        return;
    }
    char line[40];
    u32 off = 0;
    const char* p = "  ";
    while (*p != '\0')
        line[off++] = *p++;
    char nbuf[8];
    FormatU64Dec(wifi.adapters_detected, nbuf, sizeof(nbuf));
    for (u32 i = 0; nbuf[i] != '\0' && off + 1 < sizeof(line); ++i)
        line[off++] = nbuf[i];
    p = " adapter(s) detected";
    while (*p != '\0' && off + 1 < sizeof(line))
        line[off++] = *p++;
    line[off] = '\0';
    WriteAt(ax + kMargin, y, line, kTextRgb, kBodyRgb);
    y += kRowH;
    if (wifi.drivers_online > 0)
    {
        WriteAt(ax + kMargin, y, "  driver shell online", kAccentRgb, kBodyRgb);
        y += kRowH;
        WriteAt(ax + kMargin, y, "  (firmware loader pending)", kDimRgb, kBodyRgb);
        y += kRowH;
    }
    else
    {
        WriteAt(ax + kMargin, y, "  no wireless driver online", kWarnRgb, kBodyRgb);
        y += kRowH;
    }
}

void DrawWiredSection(u32 ax, u32& y)
{
    WriteAt(ax + kMargin, y, "WIRED", kAccentRgb, kBodyRgb);
    y += 12;
    const u64 nics = duetos::drivers::net::NicCount();
    bool printed = false;
    char buf[40];
    for (u64 i = 0; i < nics; ++i)
    {
        if (duetos::drivers::net::NicIsWireless(i))
            continue;
        printed = true;
        const auto& nic = duetos::drivers::net::Nic(i);
        // Heading: "  net0  Intel e1000-82540em"
        u32 off = 0;
        const char* p = "  net";
        while (*p != '\0' && off + 1 < sizeof(buf))
            buf[off++] = *p++;
        char nbuf[4];
        FormatU64Dec(i, nbuf, sizeof(nbuf));
        for (u32 j = 0; nbuf[j] != '\0' && off + 1 < sizeof(buf); ++j)
            buf[off++] = nbuf[j];
        if (off + 1 < sizeof(buf))
            buf[off++] = ' ';
        if (nic.vendor != nullptr)
            for (u32 j = 0; nic.vendor[j] != '\0' && off + 1 < sizeof(buf); ++j)
                buf[off++] = nic.vendor[j];
        buf[off] = '\0';
        WriteAt(ax + kMargin, y, buf, kTextRgb, kBodyRgb);
        // Right-aligned link badge.
        const char* link = nic.link_up ? "UP" : "DOWN";
        const u32 link_w = (nic.link_up ? 2 : 4) * 8;
        const u32 link_x = ax + kFullW - kMargin - link_w;
        WriteAt(link_x, y, link, nic.link_up ? kAccentRgb : kDimRgb, kBodyRgb);
        y += kRowH;

        // ip / gateway / dns rows.
        const auto lease = duetos::net::DhcpLeaseRead();
        const auto ip = duetos::net::InterfaceIp(static_cast<u32>(i));
        char ipbuf[20];
        FormatIpv4(ip, ipbuf, sizeof(ipbuf));
        if (Ipv4IsZero(ip))
            DrawLabelValue(ax + kMargin + 16, y, "ip ", "(no lease yet)", kBodyRgb);
        else
            DrawLabelValue(ax + kMargin + 16, y, "ip ", ipbuf, kBodyRgb);
        y += kRowH;

        if (lease.valid)
        {
            FormatIpv4(lease.router, ipbuf, sizeof(ipbuf));
            DrawLabelValue(ax + kMargin + 16, y, "gw ", ipbuf, kBodyRgb);
            y += kRowH;
            FormatIpv4(lease.dns, ipbuf, sizeof(ipbuf));
            DrawLabelValue(ax + kMargin + 16, y, "dns", ipbuf, kBodyRgb);
            y += kRowH;
        }
        else
        {
            WriteAt(ax + kMargin + 16, y, "no DHCP lease — try RENEW", kWarnRgb, kBodyRgb);
            y += kRowH;
            y += kRowH; // keep section heights consistent
        }
        y += 4;
    }
    if (!printed)
    {
        WriteAt(ax + kMargin, y, "  no wired adapter", kDimRgb, kBodyRgb);
        y += kRowH;
    }
}

void DrawFull()
{
    g_height = ComputeFullHeight();
    FramebufferFillRect(g_ax, g_ay, kFullW, g_height, kBodyRgb);
    FramebufferDrawRect(g_ax, g_ay, kFullW, g_height, kBorderRgb, 2);

    DrawHeader(g_ax, g_ay, kFullW, "NETWORK");
    u32 y = g_ay + kMargin + 22 + 6;

    // Connection summary line.
    const auto lease = duetos::net::DhcpLeaseRead();
    const u64 nics = duetos::drivers::net::NicCount();
    const bool any_link = nics > 0;
    const bool online = any_link && lease.valid;
    const u32 dot = 10;
    FramebufferFillRect(g_ax + kMargin, y + 2, dot, dot, !any_link ? kDimRgb : online ? kAccentRgb : kWarnRgb);
    const char* status = !any_link ? "OFFLINE — no NIC discovered"
                         : online  ? "CONNECTED"
                                   : "PENDING — waiting for DHCP";
    WriteAt(g_ax + kMargin + dot + 6, y + 2, status, kTextRgb, kBodyRgb);
    y += kRowH + 4;
    if (online)
    {
        char ipbuf[20];
        FormatIpv4(lease.ip, ipbuf, sizeof(ipbuf));
        DrawLabelValue(g_ax + kMargin + dot + 6, y, "IP ", ipbuf, kBodyRgb);
        y += kRowH;
    }
    else
    {
        y += kRowH;
    }
    y += kSectionGap;

    DrawWirelessSection(g_ax, y, kFullW);
    y += kSectionGap;

    DrawWiredSection(g_ax, y);
    y += kSectionGap;

    // Renew button anchored to the bottom-right.
    const u32 btn_w = 100;
    const u32 btn_h = 22;
    g_renew_x = g_ax + kFullW - kMargin - btn_w;
    g_renew_y = g_ay + g_height - kMargin - btn_h;
    g_renew_w = btn_w;
    g_renew_h = btn_h;
    FramebufferFillRect(g_renew_x, g_renew_y, btn_w, btn_h, kButtonRgb);
    FramebufferDrawRect(g_renew_x, g_renew_y, btn_w, btn_h, kBorderRgb, 1);
    const u32 lbl_w = 5 * 8; // "RENEW"
    WriteAt(g_renew_x + (btn_w - lbl_w) / 2, g_renew_y + (btn_h - 8) / 2, "RENEW", kTextRgb, kButtonRgb);

    // Hint to the left of the button.
    WriteAt(g_ax + kMargin, g_renew_y + (btn_h - 8) / 2, "click outside to close", kDimRgb, kBodyRgb);
}

} // namespace

void NetPanelOpen(u32 ax, u32 ay, NetPanelMode mode)
{
    g_ax = ax;
    g_ay = ay;
    g_mode = mode;
    if (mode == NetPanelMode::Preview)
        g_height = kPreviewH;
    else if (mode == NetPanelMode::Full)
        g_height = ComputeFullHeight();
    else
        g_height = 0;
}

void NetPanelClose()
{
    g_mode = NetPanelMode::Closed;
    g_height = 0;
    g_renew_x = g_renew_y = g_renew_w = g_renew_h = 0;
}

NetPanelMode NetPanelCurrentMode()
{
    return g_mode;
}

bool NetPanelIsOpen()
{
    return g_mode != NetPanelMode::Closed;
}

void NetPanelRedraw()
{
    if (g_mode == NetPanelMode::Closed)
        return;
    if (g_mode == NetPanelMode::Preview)
        DrawPreview();
    else
        DrawFull();
}

bool NetPanelContains(u32 x, u32 y)
{
    if (g_mode == NetPanelMode::Closed)
        return false;
    const u32 w = (g_mode == NetPanelMode::Preview) ? kPreviewW : kFullW;
    const u32 h = (g_mode == NetPanelMode::Preview) ? kPreviewH : g_height;
    return x >= g_ax && x < g_ax + w && y >= g_ay && y < g_ay + h;
}

bool NetPanelRenewButtonContains(u32 x, u32 y)
{
    if (g_mode != NetPanelMode::Full || g_renew_w == 0)
        return false;
    return x >= g_renew_x && x < g_renew_x + g_renew_w && y >= g_renew_y && y < g_renew_y + g_renew_h;
}

bool NetPanelDoRenew()
{
    if (!duetos::net::InterfaceIsBound(0))
        return false;
    return duetos::net::DhcpStart(0);
}

u32 NetPanelWidth()
{
    if (g_mode == NetPanelMode::Preview)
        return kPreviewW;
    return kFullW;
}

u32 NetPanelHeight()
{
    if (g_mode == NetPanelMode::Preview)
        return kPreviewH;
    if (g_mode == NetPanelMode::Full)
        return g_height ? g_height : ComputeFullHeight();
    return 0;
}

} // namespace duetos::drivers::video
