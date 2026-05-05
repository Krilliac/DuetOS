#include "apps/settings.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::apps::settings
{

namespace
{

void Draw(u32 x, u32 y, u32 /*w*/, u32 /*h*/)
{
    const auto& th = duetos::drivers::video::ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(duetos::drivers::video::ThemeRole::Settings)];
    duetos::drivers::video::FramebufferDrawString(x, y, "MOUSE (placeholder)", th.banner_fg, bg);
}

bool Key(char /*c*/)
{
    return false;
}

} // namespace

void SettingsMouseInit()
{
    SettingsRegisterPanel(Panel::Mouse, Draw, Key);
}

} // namespace duetos::apps::settings
