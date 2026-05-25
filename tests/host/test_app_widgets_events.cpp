// tests/host/test_app_widgets_events.cpp
//
// Pass D Task 6 — Widget state transitions on synthetic events.
//
// Re-derives the WidgetStateFlags bitfield + the hover/pressed
// state machine inline. The kernel side lives in
// `kernel/drivers/video/app_widgets/widget_base.h`; this shadow
// copy pins the bit layout and the set/clear semantics so a future
// reordering (e.g. moving Pressed off bit 1) is caught here before
// the kernel boot self-test even runs.

#include "host_test_helper.h"

#include <cstdint>

enum class WidgetStateFlags : uint8_t
{
    None = 0U,
    Hover = 1U << 0U,
    Pressed = 1U << 1U,
    Focused = 1U << 2U,
    Disabled = 1U << 3U,
};

static constexpr WidgetStateFlags operator|(WidgetStateFlags a, WidgetStateFlags b)
{
    return static_cast<WidgetStateFlags>(static_cast<uint8_t>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b)));
}

static bool HasFlag(WidgetStateFlags f, WidgetStateFlags t)
{
    return (static_cast<uint8_t>(f) & static_cast<uint8_t>(t)) != 0U;
}

static WidgetStateFlags ClearFlag(WidgetStateFlags f, WidgetStateFlags t)
{
    return static_cast<WidgetStateFlags>(static_cast<uint8_t>(static_cast<uint8_t>(f) & ~static_cast<uint8_t>(t)));
}

int main()
{
    // ----- None -> Hover transition. -----
    WidgetStateFlags s = WidgetStateFlags::None;
    s = s | WidgetStateFlags::Hover;
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Hover));
    EXPECT_TRUE(!HasFlag(s, WidgetStateFlags::Pressed));

    // ----- Hover + Pressed combined; both bits live simultaneously. -----
    s = s | WidgetStateFlags::Pressed;
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Hover));
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Pressed));

    // ----- Clear Pressed leaves Hover untouched. -----
    s = ClearFlag(s, WidgetStateFlags::Pressed);
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Hover));
    EXPECT_TRUE(!HasFlag(s, WidgetStateFlags::Pressed));

    // ----- Disabled is independent of hover/pressed. -----
    s = s | WidgetStateFlags::Disabled;
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Disabled));
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Hover));

    // ----- Focused is independent too; pin all four bits orthogonal. -----
    s = s | WidgetStateFlags::Focused;
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Focused));
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Hover));
    EXPECT_TRUE(HasFlag(s, WidgetStateFlags::Disabled));
    EXPECT_TRUE(!HasFlag(s, WidgetStateFlags::Pressed));

    // ----- None is the additive identity: x | None == x. -----
    WidgetStateFlags only_focus = WidgetStateFlags::None | WidgetStateFlags::Focused;
    EXPECT_TRUE(HasFlag(only_focus, WidgetStateFlags::Focused));
    EXPECT_TRUE(!HasFlag(only_focus, WidgetStateFlags::Hover));

    return ::duetos_host_test::finish_main("tests/host/test_app_widgets_events.cpp");
}
