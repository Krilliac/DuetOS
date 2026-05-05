#include "apps/settings.h"

#include "drivers/audio/pcspk.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"

namespace duetos::apps::settings
{

namespace
{

void Draw(u32 x, u32 y, u32 w, u32 h)
{
    using duetos::drivers::video::FramebufferDrawString;
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    if (w < 8 * 24 || h < 8 * 8)
        return;
    FramebufferDrawString(x, y, "SOUND", fg, bg);
    FramebufferDrawString(x, y + 14, "PC SPEAKER ENGINE: PIT channel 2", dim, bg);
    const bool enabled = duetos::drivers::video::SoundCueIsEnabled();
    FramebufferDrawString(x, y + 30, enabled ? "UI CUES: ENABLED" : "UI CUES: MUTED", fg, bg);
    FramebufferDrawString(x, y + 50, "M: TOGGLE MUTE", dim, bg);
    FramebufferDrawString(x, y + 62, "C: PLAY CLICK CUE  E: ERROR  A: ALARM  H: CHIME", dim, bg);
    FramebufferDrawString(x, y + 74, "B: BEEP TEST (440 Hz, 200ms)", dim, bg);
}

bool Key(char c)
{
    using duetos::drivers::video::SoundCueAlarm;
    using duetos::drivers::video::SoundCueChime;
    using duetos::drivers::video::SoundCueClick;
    using duetos::drivers::video::SoundCueError;
    using duetos::drivers::video::SoundCueIsEnabled;
    using duetos::drivers::video::SoundCueSetEnabled;
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

} // namespace duetos::apps::settings
