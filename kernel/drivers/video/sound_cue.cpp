#include "drivers/video/sound_cue.h"

#include "drivers/audio/pcspk.h"

namespace duetos::drivers::video
{

namespace
{
constinit bool g_enabled = true;
} // namespace

void SoundCueClick()
{
    if (!g_enabled)
        return;
    duetos::drivers::audio::PcSpeakerBeep(1000, 80);
}

void SoundCueError()
{
    if (!g_enabled)
        return;
    duetos::drivers::audio::PcSpeakerBeep(220, 150);
}

void SoundCueAlarm()
{
    if (!g_enabled)
        return;
    duetos::drivers::audio::PcSpeakerBeep(880, 200);
}

void SoundCueChime()
{
    if (!g_enabled)
        return;
    duetos::drivers::audio::PcSpeakerBeep(440, 100);
    duetos::drivers::audio::PcSpeakerBeep(660, 100);
}

void SoundCueSetEnabled(bool enabled)
{
    g_enabled = enabled;
}

bool SoundCueIsEnabled()
{
    return g_enabled;
}

} // namespace duetos::drivers::video
