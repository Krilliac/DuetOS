#pragma once

#include "../../core/types.h"

/*
 * Calendar popup — v0.
 *
 * Month-view popup opened by clicking the taskbar clock. Renders a
 * header with the month name + year, a row of weekday initials
 * (S M T W T F S), and a 6x7 grid of day numbers with the RTC's
 * current day highlighted. Same visual style as the start menu so
 * the two popups look like siblings.
 *
 * Scope:
 *   - Displays the month containing RtcRead()->{year,month,day}.
 *   - Highlights the current day via an accent fill.
 *   - Fixed size + placement (popup grows upward from anchor).
 *
 * Not in scope:
 *   - Month navigation (prev/next). This is a read-only glance.
 *   - Event overlay, appointment data, etc.
 *
 * Context: kernel. Redraw from DesktopCompose after the taskbar;
 * toggle from the mouse reader when a click lands inside the
 * clock bounds.
 */

namespace customos::drivers::video
{

/// Open the calendar popup anchored with `ax, ay` as its
/// upper-left corner. Usually called from the clock hit-test;
/// the caller passes a value that puts the popup above the
/// taskbar (anchor_y = clock_y - popup_height).
void CalendarOpen(u32 ax, u32 ay);

void CalendarClose();

bool CalendarIsOpen();

/// Render the popup if open. Safe any time. Re-reads the RTC
/// every call so a minute change flips the month if it's 23:59
/// Dec 31.
void CalendarRedraw();

/// Hit-test for click-outside-to-close.
bool CalendarContains(u32 x, u32 y);

/// Current popup size (post-layout). Callers use the height to
/// anchor the popup above a fixed-height element.
u32 CalendarPanelWidth();
u32 CalendarPanelHeight();

} // namespace customos::drivers::video
