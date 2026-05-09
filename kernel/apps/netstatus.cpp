#include "apps/netstatus.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "net/stack.h"
#include "net/wifi.h"

namespace duetos::apps::netstatus
{

namespace
{

constexpr u32 kRowH = 14;
constexpr u32 kMargin = 12;
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

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy + kMargin;
    FramebufferDrawString(cx + kMargin, y, "NETWORK INTERFACES", kHeaderFg, kBg);
    y += kRowH + 4;
    FramebufferDrawString(
        cx + kMargin, y,
        "IDX  MAC                IPV4             STATE  RX-PKT     RX-BYTE    TX-PKT     TX-BYTE    FW-DROP", kFgDim,
        kBg);
    y += kRowH;

    const u64 n = duetos::net::InterfaceCount();
    if (n == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO BOUND INTERFACES — STACK NOT INITIALISED)", kFgDim, kBg);
        return;
    }

    for (u32 i = 0; i < n && y + kRowH < cy + ch; ++i)
    {
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
        U64Col(line + o, 10, cnt.rx_packets);
        o += 10;
        line[o++] = ' ';
        U64Col(line + o, 10, cnt.rx_bytes);
        o += 10;
        line[o++] = ' ';
        U64Col(line + o, 10, cnt.tx_packets);
        o += 10;
        line[o++] = ' ';
        U64Col(line + o, 10, cnt.tx_bytes);
        o += 10;
        line[o++] = ' ';
        U64Col(line + o, 10, cnt.tx_dropped_firewall);
        o += 10;
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
        FramebufferDrawString(cx + kMargin, y, "  (no DHCP lease — gateway / DNS unknown)", kFgDim, kBg);
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

} // namespace

void NetStatusInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle NetStatusWindow()
{
    return g_handle;
}

void NetStatusSelfTest()
{
    using duetos::arch::SerialWrite;
    const u64 n = duetos::net::InterfaceCount();
    SerialWrite("[apps/netstatus] selftest: ifaces=");
    char buf[8];
    u32 v = static_cast<u32>(n);
    u32 o = 0;
    if (v == 0)
        buf[o++] = '0';
    else
    {
        char tmp[8];
        u32 t = 0;
        while (v != 0)
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (t != 0)
            buf[o++] = tmp[--t];
    }
    buf[o] = '\0';
    SerialWrite(buf);
    SerialWrite(" PASS\n");
}

} // namespace duetos::apps::netstatus
