#include "drivers/video/volume_flyout.h"

#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "subsystems/audio/audio_backend.h"

namespace duetos::drivers::video
{

namespace
{

namespace audio = duetos::subsystems::audio;

bool g_open = false;
u32 g_x = 0;
u32 g_y = 0;

constexpr u32 kW = 208;
constexpr u32 kH = 76;
constexpr u32 kPad = 12;
constexpr u32 kMuteW = 52;
constexpr u32 kMuteH = 24;
constexpr u32 kTrackH = 6;

constexpr u32 kWhite = 0x00FFFFFFu;
constexpr u32 kTrack = 0x00303A46u;
constexpr u32 kMutedRed = 0x00C04848u;

u32 MuteX()
{
    return g_x + kPad;
}
u32 MuteY()
{
    return g_y + kH - kPad - kMuteH;
}
u32 TrackX()
{
    return MuteX() + kMuteW + 14;
}
u32 TrackY()
{
    return MuteY() + kMuteH / 2 - kTrackH / 2;
}
u32 TrackW()
{
    const u32 right = g_x + kW - kPad;
    const u32 left = TrackX();
    return (right > left) ? right - left : 0;
}

// Append a 0..100 percent value (e.g. "80%") to `out`. Tiny local itoa —
// avoids pulling a formatting dependency for one short string.
void FormatPct(u32 v, char* out)
{
    char tmp[4];
    int n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    while (v > 0)
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    int j = 0;
    while (n > 0)
    {
        out[j++] = tmp[--n];
    }
    out[j++] = '%';
    out[j] = '\0';
}

} // namespace

void VolumeFlyoutOpen(u32 ax, u32 ay)
{
    g_x = ax;
    g_y = ay;
    g_open = true;
}

void VolumeFlyoutClose()
{
    g_open = false;
}

bool VolumeFlyoutIsOpen()
{
    return g_open;
}

u32 VolumeFlyoutWidth()
{
    return kW;
}

u32 VolumeFlyoutHeight()
{
    return kH;
}

void VolumeFlyoutRedraw()
{
    if (!g_open)
    {
        return;
    }
    const Theme& t = ThemeCurrent();
    const u32 stored = audio::AudioGetMasterVolume();
    const bool muted = audio::AudioIsMuted();
    const u32 shown = muted ? 0u : stored;

    FramebufferFillRoundRect(g_x, g_y, kW, kH, 6, t.desktop_bg);
    FramebufferDrawRoundRect(g_x, g_y, kW, kH, 6, t.taskbar_accent);

    // Title + live percent.
    ChromeTextDraw(ChromeTextRole::Caption, g_x + kPad, g_y + 8, "VOLUME", kWhite, t.desktop_bg);
    char pct[8];
    FormatPct(shown, pct);
    const u32 pw = ChromeTextMeasure(ChromeTextRole::Caption, pct);
    ChromeTextDraw(ChromeTextRole::Caption, g_x + kW - kPad - pw, g_y + 8, pct, kWhite, t.desktop_bg);

    // Mute button.
    const u32 mbg = muted ? kMutedRed : t.taskbar_accent;
    FramebufferFillRoundRect(MuteX(), MuteY(), kMuteW, kMuteH, 4, mbg);
    const char* ml = muted ? "MUTED" : "MUTE";
    const u32 mlw = ChromeTextMeasure(ChromeTextRole::Caption, ml);
    const u32 mlh = ChromeTextRoleHeight(ChromeTextRole::Caption);
    ChromeTextDraw(ChromeTextRole::Caption, MuteX() + (kMuteW > mlw ? (kMuteW - mlw) / 2 : 2),
                   MuteY() + (kMuteH > mlh ? (kMuteH - mlh) / 2 : 2), ml, kWhite, mbg, ChromeTextWeight::Bold);

    // Slider: track, filled portion, thumb.
    const u32 tx = TrackX();
    const u32 ty = TrackY();
    const u32 tw = TrackW();
    FramebufferFillRect(tx, ty, tw, kTrackH, kTrack);
    const u32 fillw = (shown >= 100u) ? tw : (tw * shown) / 100u;
    if (fillw > 0)
    {
        FramebufferFillRect(tx, ty, fillw, kTrackH, t.taskbar_accent);
    }
    const u32 thumb_x = tx + (fillw > 4u ? fillw - 4u : 0u);
    FramebufferFillRoundRect(thumb_x, ty - 5u, 8u, kTrackH + 10u, 3u, kWhite);
}

bool VolumeFlyoutContains(u32 x, u32 y)
{
    return g_open && x >= g_x && x < g_x + kW && y >= g_y && y < g_y + kH;
}

bool VolumeFlyoutSliderContains(u32 x, u32 y)
{
    if (!g_open)
    {
        return false;
    }
    const u32 tx = TrackX();
    const u32 ty = TrackY();
    const u32 tw = TrackW();
    return x >= tx && x <= tx + tw && y + 8u >= ty && y <= ty + kTrackH + 8u;
}

void VolumeFlyoutSetFromX(u32 x)
{
    if (!g_open)
    {
        return;
    }
    const u32 tx = TrackX();
    const u32 tw = TrackW();
    u32 v;
    if (tw == 0u || x <= tx)
    {
        v = 0u;
    }
    else if (x >= tx + tw)
    {
        v = 100u;
    }
    else
    {
        v = ((x - tx) * 100u) / tw;
    }
    audio::AudioSetMasterVolume(static_cast<u8>(v));
    audio::AudioSetMuted(false);
}

bool VolumeFlyoutMuteContains(u32 x, u32 y)
{
    return g_open && x >= MuteX() && x < MuteX() + kMuteW && y >= MuteY() && y < MuteY() + kMuteH;
}

} // namespace duetos::drivers::video
