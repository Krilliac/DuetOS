#include "apps/settings.h"

#include "arch/x86_64/serial.h"
#include "drivers/audio/pcspk.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"
#include "subsystems/audio/audio_backend.h"

namespace duetos::apps::settings
{

namespace
{

namespace audio = duetos::subsystems::audio;

// Master-volume slider step for the +/- keys (percent).
constexpr u8 kVolStep = 5;

// Level-bar track fill (dark slate), matching the taskbar volume flyout.
constexpr u32 kBarTrack = 0x00303A46u;

void AppendDec(char* out, u32 cap, u32* o, u64 v)
{
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
    while (n > 0 && *o + 1 < cap)
        out[(*o)++] = tmp[--n];
}

void AppendStr(char* out, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
        out[(*o)++] = *s++;
}

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// ---------------------------------------------------------------
// Pass D chrome: SOUND panel. Header (Title Bold) + footer
// (Caption hint band) AppLabels. The two read-only state rows
// (PC speaker engine, UI cues enabled/muted) and the three
// multi-key hint lines stay raw paint because the cue state
// recomposes every paint via SoundCueIsEnabled and the hint
// rows are heterogeneous cheat-sheet content that composes
// better in-line than as separate AppLabels.

constinit char g_snd_header[16] = "SOUND";
constinit char g_snd_footer[64] = "+/-:volume V:mute  M:cues  B:440Hz beep";

constinit auto g_settings_sound = MakeWidgetGroup(AppLabel{}, AppLabel{});

constinit bool g_settings_sound_bound = false;
constinit bool g_settings_sound_self_test_passed = false;

AppLabel& SndHeader()
{
    return g_settings_sound.chain.head;
}
AppLabel& SndFooter()
{
    return g_settings_sound.chain.tail.head;
}

void BindSettingsSoundOnce()
{
    if (g_settings_sound_bound)
        return;
    g_settings_sound_bound = true;

    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    AppLabel& h = SndHeader();
    h.text = g_snd_header;
    h.role = ChromeTextRole::Title;
    h.weight = ChromeTextWeight::Bold;
    h.fg_rgb = fg;
    h.bg_rgb = bg;
    h.align_left = true;

    AppLabel& f = SndFooter();
    f.text = g_snd_footer;
    f.role = ChromeTextRole::Caption;
    f.weight = ChromeTextWeight::Regular;
    f.fg_rgb = dim;
    f.bg_rgb = bg;
    f.align_left = true;
}

void RebindSettingsSoundBounds(u32 x, u32 y, u32 w, u32 h)
{
    constexpr u32 kHeaderH = 14U;
    constexpr u32 kFooterH = 12U;
    SndHeader().bounds = Rect{x, y, w, kHeaderH};
    const u32 fy = (h > kFooterH) ? y + h - kFooterH : y;
    SndFooter().bounds = Rect{x, fy, w, kFooterH};
}

void Draw(u32 x, u32 y, u32 w, u32 h)
{
    using duetos::drivers::video::ChromeTextDraw;
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    if (w < 8 * 24 || h < 8 * 8)
        return;

    // Pass D chrome: anchor + paint header + footer labels.
    BindSettingsSoundOnce();
    RebindSettingsSoundBounds(x, y, w, h);
    Compose ctx{};
    g_settings_sound.PaintAll(ctx);

    ChromeTextDraw(ChromeTextRole::Body, x, y + 14, "PC SPEAKER ENGINE: PIT channel 2", dim, bg);
    const bool enabled = duetos::drivers::video::SoundCueIsEnabled();
    ChromeTextDraw(ChromeTextRole::Body, x, y + 30, enabled ? "UI CUES: ENABLED" : "UI CUES: MUTED", fg, bg);

    // Master volume — software gain stage in the audio backend. The
    // stored level survives mute (un-mute restores it). Drawn as a
    // labelled level bar with a live percent; +/- keys adjust, V mutes.
    const u8 stored = audio::AudioGetMasterVolume();
    const bool vmuted = audio::AudioIsMuted();
    const u32 shown = vmuted ? 0u : stored;
    char vline[40];
    u32 vo = 0;
    AppendStr(vline, sizeof(vline), &vo, vmuted ? "MASTER VOLUME: MUTED (" : "MASTER VOLUME: ");
    if (vmuted)
    {
        AppendDec(vline, sizeof(vline), &vo, stored);
        AppendStr(vline, sizeof(vline), &vo, "%)");
    }
    else
    {
        AppendDec(vline, sizeof(vline), &vo, stored);
        AppendStr(vline, sizeof(vline), &vo, "%");
    }
    vline[vo] = '\0';
    ChromeTextDraw(ChromeTextRole::Body, x, y + 50, vline, fg, bg);

    // Level bar: track + filled portion proportional to `shown`.
    using duetos::drivers::video::FramebufferDrawRect;
    using duetos::drivers::video::FramebufferFillRect;
    constexpr u32 kBarH = 8U;
    const u32 bar_y = y + 66;
    const u32 bar_w = (w > 16U) ? w - 8U : w;
    FramebufferFillRect(x, bar_y, bar_w, kBarH, kBarTrack);
    const u32 fill_w = (shown >= 100u) ? bar_w : (bar_w * shown) / 100u;
    if (fill_w > 0)
        FramebufferFillRect(x, bar_y, fill_w, kBarH, vmuted ? dim : fg);
    FramebufferDrawRect(x, bar_y, bar_w, kBarH, dim, 1);

    // Hint lines — Caption role for key-shortcut help.
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 82, "+ / - : VOLUME UP/DOWN    V: TOGGLE MUTE", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 94, "M: TOGGLE UI CUES", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 106, "C: CLICK  E: ERROR  A: ALARM  H: CHIME", dim, bg);
    ChromeTextDraw(ChromeTextRole::Caption, x, y + 118, "B: BEEP TEST (440 Hz, 200ms)", dim, bg);
}

bool Key(char c)
{
    using duetos::drivers::video::SoundCueAlarm;
    using duetos::drivers::video::SoundCueChime;
    using duetos::drivers::video::SoundCueClick;
    using duetos::drivers::video::SoundCueError;
    using duetos::drivers::video::SoundCueIsEnabled;
    using duetos::drivers::video::SoundCueSetEnabled;

    // Master-volume controls. '+' (and '=') step up, '-' (and '_')
    // step down by kVolStep; adjusting un-mutes so the change is
    // audible immediately. 'V' toggles mute, retaining the stored
    // level so un-mute restores it.
    if (c == '+' || c == '=')
    {
        u32 v = audio::AudioGetMasterVolume();
        v = (v + kVolStep > 100u) ? 100u : v + kVolStep;
        audio::AudioSetMasterVolume(static_cast<u8>(v));
        audio::AudioSetMuted(false);
        duetos::drivers::video::NotifyShow("volume up");
        return true;
    }
    if (c == '-' || c == '_')
    {
        u32 v = audio::AudioGetMasterVolume();
        v = (v < kVolStep) ? 0u : v - kVolStep;
        audio::AudioSetMasterVolume(static_cast<u8>(v));
        audio::AudioSetMuted(false);
        duetos::drivers::video::NotifyShow("volume down");
        return true;
    }
    if (c == 'v' || c == 'V')
    {
        const bool now = !audio::AudioIsMuted();
        audio::AudioSetMuted(now);
        duetos::drivers::video::NotifyShow(now ? "audio: muted" : "audio: unmuted");
        return true;
    }

    if (c == 'm' || c == 'M')
    {
        const bool now = !SoundCueIsEnabled();
        SoundCueSetEnabled(now);
        duetos::drivers::video::NotifyShow(now ? "sound: enabled" : "sound: muted");
        return true;
    }
    if (c == 'c' || c == 'C')
    {
        SoundCueClick();
        return true;
    }
    if (c == 'e' || c == 'E')
    {
        SoundCueError();
        return true;
    }
    if (c == 'a' || c == 'A')
    {
        SoundCueAlarm();
        return true;
    }
    if (c == 'h' || c == 'H')
    {
        SoundCueChime();
        return true;
    }
    if (c == 'b' || c == 'B')
    {
        // Direct PIT beep — bypasses the cue mute so the user can
        // confirm the speaker is actually wired. 440 Hz / 200 ms.
        duetos::drivers::audio::PcSpeakerBeep(440, 200);
        return true;
    }
    return false;
}

} // namespace

void SettingsSoundInit()
{
    SettingsRegisterPanel(Panel::Sound, Draw, Key);
}

void SettingsSoundSelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;

    // Pass D chrome: bind + rebind only. Skipping PaintAll because
    // under TTF themes (duet*) AppLabel::PaintSelf routes into
    // TtfDrawString -> CompositeCoverage -> FramebufferBlendFill at
    // the synthetic (0,0) origin and races the compositor lock
    // before the WM is online (silent boot halt). The live Draw()
    // path exercises paint when the settings shell composes us.
    BindSettingsSoundOnce();
    RebindSettingsSoundBounds(0U, 0U, 256U, 120U);

    if (g_snd_header[0] == '\0' || g_snd_footer[0] == '\0')
        ok = false;
    if (SndHeader().text == nullptr || SndFooter().text == nullptr)
        ok = false;

    g_settings_sound_self_test_passed = ok;
    SerialWrite(ok ? "[settings-sound-selftest] PASS\n" : "[settings-sound-selftest] FAIL\n");
}

bool SettingsSoundSelfTestPassed()
{
    return g_settings_sound_self_test_passed;
}

} // namespace duetos::apps::settings
