#include "apps/netstatus.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "net/stack.h"
#include "net/wifi.h"

namespace duetos::apps::netstatus
{

namespace
{

constexpr u32 kRowH = 14;
constexpr u32 kMargin = 12;
constexpr u32 kPad = 4;
constexpr u32 kFgDim = 0x00808890;
constexpr u32 kHeaderFg = 0x00FFFFFF;
constexpr u32 kBg = 0x00101820;
constexpr u32 kBound = 0x0040E060;
constexpr u32 kUnbound = 0x00E0A040;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

void Hex2(char* out, u8 v)
{
    static const char kHex[] = "0123456789ABCDEF";
    out[0] = kHex[(v >> 4) & 0xF];
    out[1] = kHex[v & 0xF];
}

void Dec3(char* out, u8 v)
{
    out[0] = static_cast<char>('0' + (v / 100));
    out[1] = static_cast<char>('0' + ((v / 10) % 10));
    out[2] = static_cast<char>('0' + (v % 10));
}

// Right-align a u64 into a fixed-width column. Truncates the
// leading digits if the value exceeds `width` — UI-only, the
// raw counters remain accurate via InterfaceCountersRead.
void U64Col(char* out, u32 width, u64 v)
{
    char tmp[32];
    u32 t = 0;
    if (v == 0)
    {
        tmp[t++] = '0';
    }
    while (v != 0 && t < sizeof(tmp))
    {
        tmp[t++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    if (t > width)
    {
        t = width;
    }
    const u32 pad = width - t;
    for (u32 i = 0; i < pad; ++i)
    {
        out[i] = ' ';
    }
    for (u32 i = 0; i < t; ++i)
    {
        out[pad + i] = tmp[t - 1 - i];
    }
}

void FormatMac(const duetos::net::MacAddress& mac, char* out)
{
    for (u32 i = 0; i < 6; ++i)
    {
        Hex2(out + i * 3, mac.octets[i]);
        if (i < 5)
            out[i * 3 + 2] = ':';
    }
    out[17] = '\0';
}

void FormatIp(const duetos::net::Ipv4Address& ip, char* out)
{
    u32 o = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        Dec3(out + o, ip.octets[i]);
        o += 3;
        if (i < 3)
            out[o++] = '.';
    }
    out[o] = '\0';
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 1 AppButton (RFRSH) + 2
// AppLabels (header "NETWORK STATUS", footer hint). The toolbar
// surfaces a read-only refresh trigger so a fresh user has a
// discoverable affordance without memorising the kernel-shell
// `net` subcommands.
//
// Carve-outs that stay raw paint:
//   - NETWORK INTERFACES table: variable-length multi-column
//     block (IDX / MAC / IPV4 / STATE / RX-PKT / RX-BYTE /
//     TX-PKT / TX-BYTE / FW-DROP) with a section heading and a
//     dim column-header subline. Per-row colour varies
//     (BOUND=green, DOWN=amber). AppListRow has no multi-column /
//     per-row colour model.
//   - ROUTING / DNS block: header + GATEWAY / DNS / DHCP-SVR
//     lines with mixed colours (kBound for resolved values,
//     kFgDim for the DHCP server / lease line).
//   - WI-FI SCAN table: variable-length list with column header
//     (SSID / SEC / RSSI). Per-row colour uniform (kBound) but
//     padding / column alignment is custom.
//   AppPanel / AppListRow / AppLabel have no multi-column /
//   section-header / per-row colour model and would lose the
//   tabular alignment + colour cues. The lists paint inside the
//   band DrawFn carves out between the (toolbar + header) at the
//   top and the AppLabel footer at the bottom.

constexpr u32 kNsToolbarH = 22U;
constexpr u32 kNsToolbarBtnW = 52U;
constexpr u32 kNsToolbarBtnH = 18U;
constexpr u32 kNsToolbarBtnGap = 4U;
constexpr u32 kNsToolbarPadX = 4U;
constexpr u32 kNsToolbarPadY = 2U;
constexpr u32 kNsHeaderH = kRowH + 4U;
constexpr u32 kNsFooterH = kRowH;

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
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

// AppLabel stores text by pointer so the buffers must outlive
// every Paint. DrawFn re-renders them each frame.
constinit char g_header_text[40] = {};
constinit char g_footer_text[80] = {};

// Forward decl for the toolbar click trampoline (defined below;
// it has to live above the constinit g_netstatus that captures
// it by function-pointer value).
void ClickRefresh();

// Toolbar (back), then 1 action AppButton, then 2 AppLabels
// (header, footer). Reverse declaration order is dispatch order
// — buttons get first refusal on clicks.
constinit auto g_netstatus = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppLabel{}, AppLabel{});

constinit bool g_netstatus_bound = false;
constinit bool g_netstatus_prev_left_down = false;
constinit bool g_netstatus_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to the action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 1 button -> 2
// labels).
AppButton* NsActionButton()
{
    return &g_netstatus.chain.tail.head; // toolbar -> btn[0]
}

// AppLabel accessors — header / footer sit at chain positions
// 2, 3 (zero-indexed) after the 1 toolbar + 1 button.
AppLabel& NsHeaderLabel()
{
    return g_netstatus.chain.tail.tail.head;
}
AppLabel& NsFooterLabel()
{
    return g_netstatus.chain.tail.tail.tail.head;
}

void BindNetstatusOnce()
{
    if (g_netstatus_bound)
        return;
    g_netstatus_bound = true;

    auto& toolbar = g_netstatus.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    AppButton* btn = NsActionButton();
    btn->label = "RFRSH";
    btn->on_click = ClickRefresh;
    btn->weight = ChromeTextWeight::Regular;
    btn->bg_rgb = 0; // theme role default
    btn->fg_rgb = 0x00101828U;

    const auto& th = ThemeCurrent();
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    auto& header = NsHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Body;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = fg;
    header.bg_rgb = kBg;
    header.align_left = true;

    auto& footer = NsFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = kBg;
    footer.align_left = true;
}

// Re-anchor the toolbar + button + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// NetstatusMouseInput before DispatchEvent so hit-tests +
// visuals stay consistent across window moves / resizes.
void RebindNetstatusBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_netstatus.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kNsToolbarH};

    {
        constexpr u32 i = 0U;
        const u32 bx = cx + kNsToolbarPadX + i * (kNsToolbarBtnW + kNsToolbarBtnGap);
        NsActionButton()->bounds = Rect{bx, cy + kNsToolbarPadY, kNsToolbarBtnW, kNsToolbarBtnH};
    }

    // Header sits directly below the toolbar. Spans the client
    // width with kMargin x-pad to match the legacy raw-paint
    // x-offset ("cx + kMargin").
    const u32 header_y = cy + kNsToolbarH;
    const u32 header_x_pad = kMargin;
    NsHeaderLabel().bounds =
        Rect{cx + header_x_pad, header_y, (cw > header_x_pad) ? cw - header_x_pad : cw, kNsHeaderH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kNsFooterH) ? cy + ch - kNsFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    NsFooterLabel().bounds = Rect{cx + kPad, fy, fw, kNsFooterH};
}

void RefreshNetstatusHeader()
{
    static const char kHeader[] = "NETWORK INTERFACES";
    u32 i = 0;
    for (; kHeader[i] != '\0' && i + 1 < sizeof(g_header_text); ++i)
        g_header_text[i] = kHeader[i];
    g_header_text[i] = '\0';
}

void RefreshNetstatusFooter()
{
    static const char kHint[] = "EDIT via kernel shell: net up/down/ip/dns  -  wifi scan/connect";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_netstatus above captures it by function-pointer value.
// RFRSH is intentionally read-only: it touches InterfaceCount /
// InterfaceCountersRead / DhcpLeaseRead / WifiScan (all read-
// only snapshot APIs) so any lazy backing store warms up before
// the next paint, then posts a notify so the user gets visual
// confirmation. We deliberately do NOT bind iface editing
// (InterfaceSetIp, NetBindInterface, etc.) to the toolbar —
// editing is gated behind the kernel shell, and the toolbar
// must never grant unprivileged iface mutations.

void ClickRefresh()
{
    // Touch the read-only snapshot APIs so any lazy backing
    // store warms up before the next paint. All calls are
    // side-effect-free at the net stack's contract.
    const u64 n = duetos::net::InterfaceCount();
    for (u32 i = 0; i < static_cast<u32>(n); ++i)
    {
        (void)duetos::net::InterfaceCountersRead(i);
    }
    (void)duetos::net::DhcpLeaseRead();
    duetos::net::WifiScanResult scan_unused[duetos::net::kWifiMaxScanResults];
    u32 scan_count_unused = 0;
    (void)duetos::net::WifiScan(0, scan_unused, duetos::net::kWifiMaxScanResults, &scan_count_unused);
    duetos::drivers::video::NotifyShow("netstatus: refreshed");
}

// Paint the raw netstatus content (interfaces / routing / DHCP /
// Wi-Fi scan) inside the band DrawFn carves out between the
// (toolbar + header) at the top and the AppLabel footer at the
// bottom.
void PaintNetstatusContent(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy;
    FramebufferDrawString(cx + kMargin, y,
                          "IDX  MAC                IPV4             STATE   RX-PKT RX-BYTE  TX-PKT TX-BYTE  FW-DRP",
                          kFgDim, kBg);
    y += kRowH;

    // InterfaceCount() spans every bound iface index. Indices are
    // sparse / driver-assigned (pcnet binds 0, e1000 binds 1, virtio
    // binds 2…), so a slot inside [0, count) can be unbound — we skip
    // those rows and only render live NICs. The "no interfaces" hint
    // fires only when nothing in range is actually bound.
    const u64 n = duetos::net::InterfaceCount();
    u32 bound_rows = 0;
    for (u32 i = 0; i < n; ++i)
    {
        if (duetos::net::InterfaceIsBound(i))
            ++bound_rows;
    }
    if (bound_rows == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO BOUND INTERFACES - STACK NOT INITIALISED)", kFgDim, kBg);
        return;
    }

    for (u32 i = 0; i < n && y + kRowH < cy + ch; ++i)
    {
        if (!duetos::net::InterfaceIsBound(i))
            continue;

        char line[160];
        u32 o = 0;
        line[o++] = ' ';
        line[o++] = static_cast<char>('0' + (i / 10));
        line[o++] = static_cast<char>('0' + (i % 10));
        line[o++] = ' ';
        line[o++] = ' ';

        char mac_text[18];
        FormatMac(duetos::net::InterfaceMac(i), mac_text);
        for (u32 k = 0; k < 17; ++k)
            line[o++] = mac_text[k];
        line[o++] = ' ';
        line[o++] = ' ';

        char ip_text[20];
        FormatIp(duetos::net::InterfaceIp(i), ip_text);
        u32 ip_len = 0;
        while (ip_text[ip_len] != '\0')
            line[o++] = ip_text[ip_len++];
        // Right-pad IP column to 17 chars total so STATE aligns.
        while (ip_len < 17)
        {
            line[o++] = ' ';
            ++ip_len;
        }

        const bool bound = duetos::net::InterfaceIsBound(i);
        const char* state_str = bound ? "BOUND" : "DOWN ";
        u32 s = 0;
        while (state_str[s] != '\0')
            line[o++] = state_str[s++];
        line[o++] = ' ';
        line[o++] = ' ';

        const auto cnt = duetos::net::InterfaceCountersRead(i);
        U64Col(line + o, 7, cnt.rx_packets);
        o += 7;
        line[o++] = ' ';
        U64Col(line + o, 7, cnt.rx_bytes);
        o += 7;
        line[o++] = ' ';
        U64Col(line + o, 7, cnt.tx_packets);
        o += 7;
        line[o++] = ' ';
        U64Col(line + o, 7, cnt.tx_bytes);
        o += 7;
        line[o++] = ' ';
        U64Col(line + o, 7, cnt.tx_dropped_firewall);
        o += 7;
        line[o] = '\0';

        FramebufferDrawString(cx + kMargin, y, line, bound ? kBound : kUnbound, kBg);
        y += kRowH;
    }

    // Routing / DNS — pulled from the most recent DHCP lease. v0
    // is single-lease (the stack tracks one transaction at a time)
    // so a single GATEWAY / DNS line is enough; once multiple
    // leases coexist the app grows a per-iface section.
    y += kRowH;
    if (y + kRowH >= cy + ch)
    {
        return;
    }
    const auto lease = duetos::net::DhcpLeaseRead();
    FramebufferDrawString(cx + kMargin, y, "ROUTING / DNS", kHeaderFg, kBg);
    y += kRowH + 4;

    char line[80];
    u32 o = 0;
    auto append_str = [&line, &o](const char* s)
    {
        while (*s != '\0' && o + 1 < sizeof(line))
        {
            line[o++] = *s++;
        }
    };
    auto append_ip = [&line, &o](duetos::net::Ipv4Address ip)
    {
        char buf[20];
        u32 b = 0;
        for (u32 i = 0; i < 4; ++i)
        {
            const u8 v = ip.octets[i];
            if (v >= 100)
            {
                buf[b++] = static_cast<char>('0' + (v / 100));
            }
            if (v >= 10)
            {
                buf[b++] = static_cast<char>('0' + ((v / 10) % 10));
            }
            buf[b++] = static_cast<char>('0' + (v % 10));
            if (i < 3)
            {
                buf[b++] = '.';
            }
        }
        for (u32 i = 0; i < b && o + 1 < sizeof(line); ++i)
        {
            line[o++] = buf[i];
        }
    };

    if (!lease.valid)
    {
        FramebufferDrawString(cx + kMargin, y, "  (no DHCP lease - gateway / DNS unknown)", kFgDim, kBg);
        return;
    }

    o = 0;
    append_str("GATEWAY  : ");
    append_ip(lease.router);
    line[o] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kBound, kBg);
    y += kRowH;
    if (y + kRowH >= cy + ch)
    {
        return;
    }

    o = 0;
    append_str("DNS      : ");
    append_ip(lease.dns);
    line[o] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kBound, kBg);
    y += kRowH;
    if (y + kRowH >= cy + ch)
    {
        return;
    }

    o = 0;
    append_str("DHCP SVR : ");
    append_ip(lease.server);
    append_str("   LEASE: ");
    {
        u64 v = lease.lease_secs;
        char buf[16];
        u32 b = 0;
        if (v == 0)
        {
            buf[b++] = '0';
        }
        while (v != 0 && b < sizeof(buf))
        {
            buf[b++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (b != 0 && o + 1 < sizeof(line))
        {
            line[o++] = buf[--b];
        }
    }
    append_str("s");
    line[o] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kFgDim, kBg);

    // -- Wi-Fi scan section --
    // Iface 0 is the only iface index we surface here; multi-radio
    // boxes show up later when more than one wireless backend
    // registers. WifiScan returns false (and logs a WARN) when no
    // backend is registered for that iface — that's the common
    // case today and we render a hint line so the operator knows
    // the slot exists.
    y += kRowH + 4;
    if (y + kRowH >= cy + ch)
    {
        return;
    }
    FramebufferDrawString(cx + kMargin, y, "WI-FI SCAN", kHeaderFg, kBg);
    y += kRowH + 4;

    duetos::net::WifiScanResult scan[duetos::net::kWifiMaxScanResults];
    u32 scan_count = 0;
    const bool scanned = duetos::net::WifiScan(0, scan, duetos::net::kWifiMaxScanResults, &scan_count);
    if (!scanned || scan_count == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (no Wi-Fi backend registered yet)", kFgDim, kBg);
        return;
    }

    FramebufferDrawString(cx + kMargin, y, "SSID                              SEC    RSSI", kFgDim, kBg);
    y += kRowH;
    for (u32 i = 0; i < scan_count && y + kRowH < cy + ch; ++i)
    {
        char row[80];
        u32 r = 0;
        // SSID column, padded to 33 chars.
        u32 sl = 0;
        while (scan[i].ssid[sl] != '\0' && sl < duetos::net::kWifiSsidMaxBytes)
        {
            if (r + 1 < sizeof(row))
                row[r++] = scan[i].ssid[sl];
            ++sl;
        }
        while (sl < 33 && r + 1 < sizeof(row))
        {
            row[r++] = ' ';
            ++sl;
        }
        // Security label.
        const char* sec = "OPEN ";
        switch (scan[i].security)
        {
        case duetos::net::WifiSecurity::Open:
            sec = "OPEN ";
            break;
        case duetos::net::WifiSecurity::Wpa2Psk:
            sec = "WPA2 ";
            break;
        }
        for (u32 k = 0; sec[k] != '\0' && r + 1 < sizeof(row); ++k)
            row[r++] = sec[k];
        if (r + 1 < sizeof(row))
            row[r++] = ' ';
        if (r + 1 < sizeof(row))
            row[r++] = ' ';
        // RSSI: signed dBm, typically [-100, 0]. Print as
        // decimal with leading sign.
        const i8 rssi = scan[i].rssi_dbm;
        if (rssi < 0)
        {
            if (r + 1 < sizeof(row))
                row[r++] = '-';
            u32 v = static_cast<u32>(-static_cast<i32>(rssi));
            char tmp[4];
            u32 t = 0;
            if (v == 0)
                tmp[t++] = '0';
            while (v != 0 && t < sizeof(tmp))
            {
                tmp[t++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            }
            while (t != 0 && r + 1 < sizeof(row))
                row[r++] = tmp[--t];
        }
        else
        {
            u32 v = static_cast<u32>(rssi);
            char tmp[4];
            u32 t = 0;
            if (v == 0)
                tmp[t++] = '0';
            while (v != 0 && t < sizeof(tmp))
            {
                tmp[t++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            }
            while (t != 0 && r + 1 < sizeof(row))
                row[r++] = tmp[--t];
        }
        if (r < sizeof(row))
            row[r] = '\0';
        else
            row[sizeof(row) - 1] = '\0';
        FramebufferDrawString(cx + kMargin, y, row, kBound, kBg);
        y += kRowH;
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Pass D chrome: refresh the header / footer text from live
    // state (constant for netstatus — no per-state variation),
    // re-anchor the toolbar / labels to the current client rect,
    // and paint the WidgetGroup. The raw netstatus content
    // (carve-out) sits in the band between the header row and
    // the AppLabel footer.
    BindNetstatusOnce();
    RefreshNetstatusHeader();
    RefreshNetstatusFooter();
    RebindNetstatusBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_netstatus.PaintAll(compose_ctx);

    // Content band — between (toolbar + header) at the top and
    // the AppLabel footer at the bottom.
    const u32 top_band = kNsToolbarH + kNsHeaderH;
    const u32 bot_band = kNsFooterH + kPad;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintNetstatusContent(list_x, list_y, list_w, list_h);
    }
}

} // namespace

void NetStatusInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
    BindNetstatusOnce();
}

duetos::drivers::video::WindowHandle NetStatusWindow()
{
    return g_handle;
}

void NetStatusSelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;

    // Walk InterfaceCount + each accessor to make sure none of
    // them faults on the boot-time iface set.
    const u64 n = duetos::net::InterfaceCount();
    for (u32 i = 0; i < static_cast<u32>(n); ++i)
    {
        (void)duetos::net::InterfaceMac(i);
        (void)duetos::net::InterfaceIp(i);
        (void)duetos::net::InterfaceIsBound(i);
        (void)duetos::net::InterfaceCountersRead(i);
    }

    // Format helpers: Hex2 / Dec3 produce the expected ASCII for
    // a fixed input.
    char hex[3] = {0, 0, 0};
    Hex2(hex, 0xAB);
    if (hex[0] != 'A' || hex[1] != 'B')
        ok = false;
    char dec[4] = {0, 0, 0, 0};
    Dec3(dec, 7);
    if (dec[0] != '0' || dec[1] != '0' || dec[2] != '7')
        ok = false;

    // U64Col right-aligns and zero-pads (with spaces) into the
    // requested width.
    char col[11];
    for (u32 i = 0; i < sizeof(col); ++i)
        col[i] = 0;
    U64Col(col, 10, 123ULL);
    // Expect "       123" (7 spaces then 3 digits).
    if (col[7] != '1' || col[8] != '2' || col[9] != '3')
        ok = false;

    // FormatMac / FormatIp produce ':'/'.'-separated output.
    duetos::net::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = static_cast<u8>(i * 0x11);
    char mac_text[18];
    FormatMac(mac, mac_text);
    if (mac_text[2] != ':' || mac_text[5] != ':' || mac_text[17] != '\0')
        ok = false;

    duetos::net::Ipv4Address ip{};
    ip.octets[0] = 192;
    ip.octets[1] = 168;
    ip.octets[2] = 1;
    ip.octets[3] = 7;
    char ip_text[20];
    FormatIp(ip, ip_text);
    if (ip_text[0] != '1' || ip_text[1] != '9' || ip_text[2] != '2' || ip_text[3] != '.')
        ok = false;

    // Pass D: drive a synthetic click on the RFRSH toolbar button
    // via the WidgetGroup dispatch chain. ClickRefresh only calls
    // read-only net::stack snapshot APIs + NotifyShow — it never
    // mutates the per-iface counters, the DHCP lease, or the
    // Wi-Fi scan cache, so this self-test is safe to run
    // unconditionally at boot.
    BindNetstatusOnce();
    // Anchor the toolbar at (0, 22, 720, 238) — same shape
    // boot_bringup.cpp registers the live netstatus window with
    // (720x260 minus 22 px title bar). RFRSH is action index 0.
    RebindNetstatusBounds(0U, 22U, 720U, 238U);
    constexpr u32 kRfrshIdx = 0U;
    const u32 nx = kNsToolbarPadX + kRfrshIdx * (kNsToolbarBtnW + kNsToolbarBtnGap) + kNsToolbarBtnW / 2U;
    const u32 ny = 22U + kNsToolbarPadY + kNsToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};

    // Capture the pre-click per-iface counters. RFRSH must NOT
    // mutate them — read-only snapshot reads only.
    duetos::net::IfaceCounters before[4];
    const u32 cap = (static_cast<u32>(n) < 4U) ? static_cast<u32>(n) : 4U;
    for (u32 i = 0; i < cap; ++i)
        before[i] = duetos::net::InterfaceCountersRead(i);

    if (g_netstatus.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;
    if (g_netstatus.DispatchEvent(n_down) != EventResult::Consumed)
        ok = false;
    if (g_netstatus.DispatchEvent(n_up) != EventResult::Consumed)
        ok = false;

    for (u32 i = 0; i < cap; ++i)
    {
        const auto after = duetos::net::InterfaceCountersRead(i);
        // Read-only contract: RFRSH must not have touched any
        // mutable counter. We compare the four highest-impact
        // counters; if any drift the test fails. (Net traffic
        // from another task running during the test would also
        // trip this; the test runs before the net stack starts
        // serving so the counters are stable.)
        if (before[i].rx_packets != after.rx_packets)
            ok = false;
        if (before[i].rx_bytes != after.rx_bytes)
            ok = false;
        if (before[i].tx_packets != after.tx_packets)
            ok = false;
        if (before[i].tx_bytes != after.tx_bytes)
            ok = false;
    }

    // Header / footer composers must produce non-empty text
    // after a refresh.
    RefreshNetstatusHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshNetstatusFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    g_netstatus_self_test_passed = ok;
    SerialWrite(ok ? "[netstatus-selftest] PASS\n" : "[netstatus-selftest] FAIL\n");
}

bool NetStatusSelfTestPassed()
{
    return g_netstatus_self_test_passed;
}

void NetStatusMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the same
    // frame RebindNetstatusBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindNetstatusOnce();
    RebindNetstatusBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_netstatus_prev_left_down;
    const bool release_edge = !left_down && g_netstatus_prev_left_down;
    g_netstatus_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_netstatus.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw netstatus content (multi-column
        // iface table, DHCP lease lines, Wi-Fi scan) sits below
        // the toolbar / header rows the WidgetGroup owns.
        // DispatchEvent's hit-test naturally short-circuits when
        // the click misses the toolbar bounds — the content
        // tables have no per-row click semantics in v0
        // (iface editing is gated to the kernel shell). MouseDown
        // still fires for the toolbar Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_netstatus.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_netstatus.DispatchEvent(u);
    }
}

} // namespace duetos::apps::netstatus
