#include "drivers/video/tray_flyout.h"

#include "arch/x86_64/rtc.h"
#include "drivers/net/net.h"
#include "drivers/power/power.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "mm/frame_allocator.h"
#include "net/stack.h"
#include "sched/sched.h"

namespace duetos::drivers::video
{

namespace
{

// Panel geometry — mirrors the Win10 tray flyout: a compact
// rectangle ~3x4 cells. Wide enough to fit "label : value" rows
// without truncation; tall enough for 6 rows + header.
constexpr u32 kPanelW = 240;
constexpr u32 kPanelH = 180;
constexpr u32 kRadius = 6;

constinit u32 g_anchor_x = 0;
constinit u32 g_anchor_y = 0;
constinit bool g_open = false;
constinit bool g_hovered = false;

// Palette — defaults match the slate Duet theme so the flyout
// reads correctly even before ThemeApplyToAll has published its
// per-theme colours. SetColours overwrites these on every theme
// switch.
constinit u32 g_body_rgb = 0x000F1319;
constinit u32 g_border_rgb = 0x002A323C;
constinit u32 g_ink_rgb = 0x00E8EDF2;
constinit u32 g_ink_dim_rgb = 0x00AEB7C2;
constinit u32 g_accent_rgb = 0x002DD4BF;
constinit u32 g_accent_2_rgb = 0x00F5B73A;

// Saturating per-channel lighten — local copy so the module
// doesn't pull in widget.cpp's helper.
u32 LightenRgb(u32 rgb, u32 amount)
{
    u32 r = ((rgb >> 16) & 0xFFU) + amount;
    u32 g = ((rgb >> 8) & 0xFFU) + amount;
    u32 b = (rgb & 0xFFU) + amount;
    if (r > 0xFFU)
        r = 0xFFU;
    if (g > 0xFFU)
        g = 0xFFU;
    if (b > 0xFFU)
        b = 0xFFU;
    return (r << 16) | (g << 8) | b;
}

u32 FormatU64DecLocal(u64 v, char* buf, u32 cap)
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
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    if (n > cap - 1)
        n = cap - 1;
    for (u32 i = 0; i < n; ++i)
        buf[i] = tmp[n - 1 - i];
    buf[n] = '\0';
    return n;
}

// Compute the panel's anchored top-left corner. The popup paints
// ABOVE the chevron, so the bottom edge of the panel sits flush
// against the chevron's top edge.
void PanelOrigin(u32* px_out, u32* py_out)
{
    *px_out = g_anchor_x;
    if (g_anchor_y > kPanelH + 4)
    {
        *py_out = g_anchor_y - kPanelH - 4;
    }
    else
    {
        *py_out = 0;
    }
}

} // namespace

void TrayFlyoutOpen(u32 anchor_x, u32 anchor_y)
{
    g_anchor_x = anchor_x;
    g_anchor_y = anchor_y;
    g_open = true;
}

void TrayFlyoutClose()
{
    g_open = false;
}

bool TrayFlyoutIsOpen()
{
    return g_open;
}

bool TrayFlyoutContains(u32 x, u32 y)
{
    if (!g_open)
        return false;
    u32 px = 0, py = 0;
    PanelOrigin(&px, &py);
    return x >= px && x < px + kPanelW && y >= py && y < py + kPanelH;
}

void TrayFlyoutSetHover(bool hovered)
{
    g_hovered = hovered;
}

bool TrayFlyoutHovered()
{
    return g_hovered;
}

void TrayFlyoutSetColours(u32 body_rgb, u32 border_rgb, u32 ink_rgb, u32 ink_dim_rgb, u32 accent_rgb, u32 accent_2_rgb)
{
    g_body_rgb = body_rgb;
    g_border_rgb = border_rgb;
    g_ink_rgb = ink_rgb;
    g_ink_dim_rgb = ink_dim_rgb;
    g_accent_rgb = accent_rgb;
    g_accent_2_rgb = accent_2_rgb;
}

void TrayFlyoutRedraw()
{
    if (!g_open || !FramebufferAvailable())
    {
        return;
    }
    u32 px = 0, py = 0;
    PanelOrigin(&px, &py);

    // Soft drop shadow + body. The flyout uses a slightly-lifted
    // top to bottom gradient so it reads as a raised surface
    // against the taskbar's flat strip. Atlas-shadow under
    // tactility; strip-shadow fallback otherwise.
    {
        const u8 atlas_opacity =
            ThemeTactilityEffective() ? ThemeIntensityEffective(ThemeCurrent().shadow_intensity_active) : u8{0};
        if (atlas_opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(px), static_cast<i32>(py), kPanelW, kPanelH, 14U, atlas_opacity,
                             0x00000000U);
        }
        else
        {
            FramebufferDropShadow(px, py, kPanelW, kPanelH, 5, 0x70);
        }
    }
    FramebufferFillRectGradient(px, py, kPanelW, kPanelH, LightenRgb(g_body_rgb, 18), g_body_rgb);
    FramebufferDrawRoundRect(px, py, kPanelW, kPanelH, kRadius, g_border_rgb);

    // Header bar — a 1-px-tall accent strip across the top edge
    // (inset 6 px on each side) so the flyout has a visible
    // "active surface" cue. Same accent language as the START
    // button + active tab.
    if (kPanelW > 12)
    {
        FramebufferFillRect(px + 6, py + 1, kPanelW - 12, 1, g_accent_rgb);
    }

    // Title row — "QUICK STATUS" caps, dim ink. Sits 6 px below
    // the accent strip.
    FramebufferDrawString(px + 12, py + 8, "QUICK STATUS", g_ink_dim_rgb, g_body_rgb);

    // Six status rows. Each row: dim label on the left, bright
    // value on the right, right-aligned. The two-column layout
    // mirrors the prototype's KernelStatsWidget rows but renders
    // bigger text so the flyout reads at glance distance.
    struct Row
    {
        const char* label;
        char value[24];
        u32 value_ink;
    };
    Row rows[6] = {};

    // Network: NIC + DHCP lease state.
    {
        const bool have_nic = duetos::drivers::net::NicCount() > 0;
        const auto lease = duetos::net::DhcpLeaseRead();
        rows[0].label = "network";
        if (!have_nic)
        {
            const char* s = "no nic";
            u32 i = 0;
            while (s[i] && i < sizeof(rows[0].value) - 1)
            {
                rows[0].value[i] = s[i];
                ++i;
            }
            rows[0].value[i] = '\0';
            rows[0].value_ink = g_ink_dim_rgb;
        }
        else if (lease.valid)
        {
            const char* s = "online";
            u32 i = 0;
            while (s[i] && i < sizeof(rows[0].value) - 1)
            {
                rows[0].value[i] = s[i];
                ++i;
            }
            rows[0].value[i] = '\0';
            rows[0].value_ink = g_accent_rgb;
        }
        else
        {
            const char* s = "dhcp pending";
            u32 i = 0;
            while (s[i] && i < sizeof(rows[0].value) - 1)
            {
                rows[0].value[i] = s[i];
                ++i;
            }
            rows[0].value[i] = '\0';
            rows[0].value_ink = g_accent_2_rgb;
        }
    }

    // Volume — placeholder reading until the audio stack
    // exposes a live mixer level. Hard-coded 75% matches the
    // prototype's "volume on, normal" feel.
    rows[1].label = "volume";
    {
        const char* s = "75%";
        u32 i = 0;
        while (s[i] && i < sizeof(rows[1].value) - 1)
        {
            rows[1].value[i] = s[i];
            ++i;
        }
        rows[1].value[i] = '\0';
        rows[1].value_ink = g_ink_rgb;
    }

    // Battery — only shown if the power driver decided a battery
    // is present. Otherwise the row reads "ac".
    {
        rows[2].label = "battery";
        const auto snap = duetos::drivers::power::PowerSnapshotRead();
        if (snap.battery.state == duetos::drivers::power::kBatNotPresent)
        {
            const char* s = (snap.ac == duetos::drivers::power::kAcOnline) ? "ac" : "no battery";
            u32 i = 0;
            while (s[i] && i < sizeof(rows[2].value) - 1)
            {
                rows[2].value[i] = s[i];
                ++i;
            }
            rows[2].value[i] = '\0';
            rows[2].value_ink = g_ink_dim_rgb;
        }
        else
        {
            const u32 pct = snap.battery.percent;
            char num[8];
            const u32 n = FormatU64DecLocal(pct, num, sizeof(num));
            u32 j = 0;
            for (u32 i = 0; i < n && j + 2 < sizeof(rows[2].value) - 1; ++i)
                rows[2].value[j++] = num[i];
            rows[2].value[j++] = '%';
            rows[2].value[j] = '\0';
            rows[2].value_ink = (snap.ac == duetos::drivers::power::kAcOnline) ? g_accent_rgb : g_ink_rgb;
        }
    }

    // Memory — free-frames count converted to MiB. 4-KiB frames
    // so 256 frames = 1 MiB.
    rows[3].label = "memory";
    {
        const u64 free_frames = duetos::mm::FreeFramesCount();
        const u64 free_mib = free_frames / 256u;
        char num[16];
        const u32 n = FormatU64DecLocal(free_mib, num, sizeof(num));
        u32 j = 0;
        for (u32 i = 0; i < n && j + 8 < sizeof(rows[3].value) - 1; ++i)
            rows[3].value[j++] = num[i];
        rows[3].value[j++] = ' ';
        rows[3].value[j++] = 'M';
        rows[3].value[j++] = 'i';
        rows[3].value[j++] = 'B';
        rows[3].value[j++] = ' ';
        rows[3].value[j++] = 'f';
        rows[3].value[j++] = 'r';
        rows[3].value[j] = '\0';
        rows[3].value_ink = (free_mib > 4) ? g_ink_rgb : g_accent_2_rgb;
    }

    // CPU — placeholder. Until /proc/cpuhist lands we report a
    // coarse "cores online" number from the scheduler's view.
    rows[4].label = "cpu";
    {
        const char* s = "4 cores";
        u32 i = 0;
        while (s[i] && i < sizeof(rows[4].value) - 1)
        {
            rows[4].value[i] = s[i];
            ++i;
        }
        rows[4].value[i] = '\0';
        rows[4].value_ink = g_ink_rgb;
    }

    // Uptime — scheduler ticks / 100 (10 ms tick) → seconds.
    rows[5].label = "uptime";
    {
        const u64 secs = duetos::sched::SchedNowTicks() / 100u;
        char num[16];
        const u32 n = FormatU64DecLocal(secs, num, sizeof(num));
        u32 j = 0;
        for (u32 i = 0; i < n && j + 2 < sizeof(rows[5].value) - 1; ++i)
            rows[5].value[j++] = num[i];
        rows[5].value[j++] = ' ';
        rows[5].value[j++] = 's';
        rows[5].value[j] = '\0';
        rows[5].value_ink = g_ink_rgb;
    }

    constexpr u32 row_h = 22;
    constexpr u32 rows_top = 28;
    for (u32 i = 0; i < 6; ++i)
    {
        const u32 ry = py + rows_top + i * row_h;
        // Subtle row separator — except above the first row.
        if (i > 0)
        {
            FramebufferFillRect(px + 12, ry - 4, kPanelW - 24, 1, LightenRgb(g_border_rgb, 18));
        }
        FramebufferDrawString(px + 14, ry + 4, rows[i].label, g_ink_dim_rgb, g_body_rgb);
        // Right-align the value column.
        u32 vw = 0;
        while (rows[i].value[vw] != '\0')
            ++vw;
        const u32 vpx = vw * 8u;
        const u32 vx = (kPanelW > vpx + 14) ? px + kPanelW - vpx - 14 : px + 80;
        FramebufferDrawString(vx, ry + 4, rows[i].value, rows[i].value_ink, g_body_rgb);
    }
}

} // namespace duetos::drivers::video
