#pragma once

#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppInput : Widget<AppInput>
{
    char* buf = nullptr; // caller-owned buffer
    u32 buf_cap = 0;
    u32 buf_len = 0;
    u32 caret = 0;
    void (*on_change)() = nullptr;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
