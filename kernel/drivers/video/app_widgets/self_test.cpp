/*
 * DuetOS app-widget self-test — Pass D umbrella feeder.
 *
 * Constructs each concrete widget without touching the framebuffer
 * (Paint is exercised by the hosted unit tests under
 * tests/host/app_widgets_*; this self-test focuses on the state
 * machine that runs on the kernel side). Drives a few synthetic
 * Event values through OnEvent and asserts the expected state-flag
 * transitions + on_click callbacks.
 *
 * On any failure the test emits `[app-widgets-selftest] FAIL <reason>`
 * on COM1 and fires KBP_PROBE_V(kBootSelftestFail, 0xD0-0xD3). On
 * success it emits `[app-widgets-selftest] PASS` and the Pass D
 * umbrella aggregator (in kernel/core/boot_bringup.cpp) reads the
 * AppWidgetsSelfTestPassed() flag to decide whether to emit
 * `[pass-d-selftest] PASS (widgets=ok, apps=0/0)`.
 *
 * C-style function pointers can't capture, so the on_click probes
 * use static flags the lambda writes through. Acceptable for a
 * self-test; the real apps wire on_click to plain free functions.
 */

#include "drivers/video/app_widgets/self_test.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_list_row.h"
#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

namespace
{

constinit bool s_passed = false;

void mark_fail(duetos::u32 code, const char* msg)
{
    using duetos::arch::SerialWrite;
    SerialWrite(msg);
    SerialWrite("\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, code);
}

} // namespace

void AppWidgetsSelfTest()
{
    using duetos::arch::SerialWrite;

    // (1) Rect::Contains semantics — half-open interval [x, x+w) x
    //     [y, y+h). The button hit-test depends on this being
    //     exactly right or hover/press will fire one pixel off.
    Rect r{10, 20, 100, 50};
    if (!r.Contains(50, 40) || r.Contains(110, 40) || r.Contains(50, 70))
    {
        mark_fail(0xD0, "[app-widgets-selftest] FAIL Rect::Contains semantics wrong");
        return;
    }

    // (2) AppButton state machine: hover on/off, press, release-with-click.
    //     Uses a static flag because C-style fn-pointers can't capture.
    static bool s_click_flag = false;
    s_click_flag = false;
    AppButton btn{};
    btn.bounds = Rect{0, 0, 100, 30};
    btn.label = "Test";
    btn.on_click = +[] { s_click_flag = true; };

    // MouseMove into bounds -> Hover ON.
    if (btn.OnEvent(Event{EventKind::MouseMove, 50, 15, 0, 0}) != EventResult::Consumed ||
        !HasFlag(btn.state.flags, WidgetStateFlags::Hover))
    {
        mark_fail(0xD1, "[app-widgets-selftest] FAIL AppButton hover not set");
        return;
    }
    // MouseMove outside -> Hover OFF.
    if (btn.OnEvent(Event{EventKind::MouseMove, 200, 50, 0, 0}) != EventResult::NotInterested ||
        HasFlag(btn.state.flags, WidgetStateFlags::Hover))
    {
        mark_fail(0xD2, "[app-widgets-selftest] FAIL AppButton hover not cleared");
        return;
    }
    // MouseDown inside -> Pressed.
    (void)btn.OnEvent(Event{EventKind::MouseMove, 50, 15, 0, 0}); // hover ON again
    if (btn.OnEvent(Event{EventKind::MouseDown, 50, 15, 0, 0}) != EventResult::Consumed ||
        !HasFlag(btn.state.flags, WidgetStateFlags::Pressed))
    {
        mark_fail(0xD3, "[app-widgets-selftest] FAIL AppButton press not set");
        return;
    }
    // MouseUp inside -> on_click fired + Pressed cleared.
    (void)btn.OnEvent(Event{EventKind::MouseUp, 50, 15, 0, 0});
    if (!s_click_flag)
    {
        mark_fail(0xD3, "[app-widgets-selftest] FAIL AppButton on_click not fired");
        return;
    }

    // (3) AppListRow click fires immediately on MouseDown (not on
    //     release; rows are select-on-press by design).
    static bool s_row_flag = false;
    s_row_flag = false;
    AppListRow row{};
    row.bounds = Rect{0, 0, 200, 24};
    row.label = "Row";
    row.on_click = +[] { s_row_flag = true; };
    (void)row.OnEvent(Event{EventKind::MouseDown, 100, 12, 0, 0});
    if (!s_row_flag)
    {
        mark_fail(0xD0, "[app-widgets-selftest] FAIL AppListRow click not fired");
        return;
    }

    // (4) AppLabel / AppPanel: paint-only widgets. Sanity that
    //     value-init compiles and default state is None — catches a
    //     future regression where a default ctor accidentally sets
    //     a flag.
    AppLabel lab{};
    AppPanel pan{};
    if (HasFlag(lab.state.flags, WidgetStateFlags::Hover) || HasFlag(pan.state.flags, WidgetStateFlags::Hover))
    {
        mark_fail(0xD0, "[app-widgets-selftest] FAIL default state not None");
        return;
    }

    SerialWrite("[app-widgets-selftest] PASS\n");
    s_passed = true;
}

bool AppWidgetsSelfTestPassed()
{
    return s_passed;
}

} // namespace duetos::drivers::video::app_widgets
