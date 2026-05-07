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

/// Arrow-key feed. Plain Left/Right step a month, Up/Down step
/// a year. Shift+Left/Right step the selected day by one;
/// Shift+Up/Down step the selected day by a week. Delete on
/// the selected date removes its events. `modifiers` is a
/// bitmask of `kKeyMod*` values; 0 (default) preserves the
/// pre-Shift behaviour.
bool CalendarFeedArrow(duetos::u16 keycode, duetos::u8 modifiers = 0);

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

/// Maximum events the in-RAM table holds. v0 has no on-disk
/// persistence — events vanish at reboot. 64 is well above the
/// "personal calendar" usage envelope and keeps the table
/// fully on `.bss`.
inline constexpr duetos::u32 kMaxEvents = 64;

/// Per-event payload size. Long enough for "DENTIST 14:00",
/// "PROJECT REVIEW MEETING", etc., capped so the events table
/// stays within ~6 KiB.
inline constexpr duetos::u32 kEventTextCap = 56;

/// Append an event. Returns true on success; false when the
/// table is full or the date is outside the supported range.
/// Out-of-range writes are silent — callers route through
/// CalendarAddEventForSelected which validates first.
bool CalendarAddEvent(duetos::u32 year, duetos::u8 month, duetos::u8 day, const char* text);

/// Remove all events on the given date. Returns the count of
/// events removed (0 if none matched). The table compacts
/// in-place so subsequent queries stay O(N).
duetos::u32 CalendarRemoveEvents(duetos::u32 year, duetos::u8 month, duetos::u8 day);

/// True iff at least one event exists for the given date. Used
/// by the renderer to paint a small dot on day cells.
bool CalendarHasEvent(duetos::u32 year, duetos::u8 month, duetos::u8 day);

/// Read the text of the first event on the given date into
/// `out` (NUL-terminated). Returns false when no event exists.
/// `cap` MUST be >= kEventTextCap + 1.
bool CalendarFirstEventText(duetos::u32 year, duetos::u8 month, duetos::u8 day, char* out, duetos::u32 cap);

/// Active selection accessor. Returns true when a selection is
/// set; out-params are zero-filled when not. Used by the
/// keyboard router / event-add flow to default to the live
/// selection (or fall through to today).
bool CalendarSelection(duetos::u32* year, duetos::u8* month, duetos::u8* day);

/// Add an event on the active selection (or on today if no
/// selection is set). Convenience wrapper called by the
/// dialog callback that fires after the user types the
/// event text. Returns true on success.
bool CalendarAddEventForSelected(const char* text);

/// Remove every event on the active selection (or today if no
/// selection). Returns the count removed.
duetos::u32 CalendarRemoveEventsForSelected();

/// Live event count. Used by the persist-layer self-test to
/// snapshot before / restore after.
duetos::u32 CalendarEventCount();

/// Read one event by index (0..CalendarEventCount() - 1) into
/// the caller-provided slots. Returns false for out-of-range
/// indices. `text_out` MUST have room for kEventTextCap + 1.
/// Used by the persist layer when serialising the table to
/// disk; not part of the everyday user surface.
bool CalendarEventAt(duetos::u32 index, duetos::u32* year, duetos::u8* month, duetos::u8* day, char* text_out,
                     duetos::u32 text_cap);

/// Persist the in-RAM event table to `CALENDAR.TXT` on the
/// FAT32 root volume. Atomic via CALENDAR.TMP + rename. One
/// line per event in `YYYY-MM-DD\tEVENT TEXT\n` form. Returns
/// true on success; false if no FAT32 volume is mounted or
/// the I/O failed. Caller MUST hold the compositor lock.
bool CalendarSave();

/// Replace the in-RAM event table with the contents of
/// `CALENDAR.TXT` on the FAT32 root volume. Bytes that fail
/// to parse are skipped; the live table is untouched on
/// total I/O failure. Returns true on success. Caller MUST
/// hold the compositor lock.
bool CalendarLoad();

/// Round-trip self-test for CalendarSave / CalendarLoad. Plants
/// a known event marker, saves, drops the in-RAM table, loads,
/// asserts the marker round-tripped. Cleans up afterwards.
/// Skipped silently when no FAT32 volume is mounted or
/// CALENDAR.TXT already exists. Prints one PASS / FAIL / SKIP
/// line to COM1.
void CalendarPersistSelfTest();

} // namespace duetos::apps::calendar
