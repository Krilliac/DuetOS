#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Calendar — v0.
 *
 * Windowed month-view calendar with navigation. Pairs with the
 * existing read-only `drivers/video/calendar` popup (which paints
 * only the current month, anchored to the taskbar clock); this
 * app is a full window the user can drag around, and lets them
 * page through past / future months.
 *
 * Bindings (when the calendar window is focused):
 *   '['  / Left  — previous month
 *   ']'  / Right — next month
 *   '{'  / Up    — previous year (12 months back)
 *   '}'  / Down  — next year     (12 months forward)
 *   'T'          — jump back to today
 *
 * Today is highlighted with the theme accent. The active selected
 * (rendered) month is independent of today — a user can browse
 * December 2027 and 'T' returns them to the live RTC month.
 *
 * Context: kernel. Draw is called under the compositor lock; key
 * input arrives via the kernel-app dispatch in main.cpp using the
 * same FeedChar / FeedArrow shape as Notes / Calculator / Browser.
 */

namespace duetos::apps::calendar
{

/// Install Calendar state on `handle`. Until the user touches a
/// key the rendered month tracks the live RTC; after the first
/// navigation the app remembers what month it was on.
void CalendarInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the calendar window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle CalendarWindow();

/// Printable-key feed. '[' / ']' step a month, '{' / '}' step a
/// year, 'T' jumps to today. Returns true iff the key was consumed.
bool CalendarFeedChar(char c);

/// Arrow-key feed. Left/Right step a month, Up/Down step a year.
/// Caller passes the kernel keycode (`kKeyArrowLeft` etc).
bool CalendarFeedArrow(u16 keycode);

/// Mouse press at framebuffer coords (cx, cy). If the click
/// lands on a day cell, the cell's date is recorded in the
/// selection state (visible as an outlined accent fill on the
/// next compose). Cells from the previous / next month also
/// land — clicking a leading / trailing greyed cell selects
/// that day in the adjacent month. Returns true iff the
/// click landed on the calendar grid.
bool CalendarOnClick(duetos::u32 cx, duetos::u32 cy);

/// Boot self-test: Zeller's-congruence weekday round-trip,
/// month-length table including Feb leap years, prev/next
/// navigation across year boundaries. Pure compute.
void CalendarSelfTest();

} // namespace duetos::apps::calendar
