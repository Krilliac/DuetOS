#pragma once

#include "util/types.h"

/*
 * Volume flyout — the small popup the taskbar speaker cell opens, the
 * way every desktop OS does. A mute toggle plus a horizontal master-
 * volume slider. Reads + writes the audio backend's master volume live
 * (subsystems/audio/audio_backend). Sibling of netpanel: the mouse
 * reader owns the open/close + drag state machine; this module paints
 * the panel, hit-tests its rect / slider / mute button, and applies a
 * slider position to the backend.
 *
 * Context: kernel. Redraw from DesktopCompose after the taskbar; toggle
 * from the mouse reader on a click of the speaker tray cell.
 */

namespace duetos::drivers::video
{

/// Open the flyout with (ax, ay) as the upper-left corner. Idempotent.
void VolumeFlyoutOpen(u32 ax, u32 ay);
void VolumeFlyoutClose();
bool VolumeFlyoutIsOpen();

/// Render if open. Re-reads master volume + mute each call so the slider
/// reflects the live backend state.
void VolumeFlyoutRedraw();

/// Whole-panel hit-test (chrome included).
bool VolumeFlyoutContains(u32 x, u32 y);

/// Slider-track hit-test (with a generous vertical margin so a click
/// near the track grabs it). SetFromX maps an x within the track to a
/// 0..100 master volume, applies it, and un-mutes (adjusting volume
/// always un-mutes — the convention every tray slider follows).
bool VolumeFlyoutSliderContains(u32 x, u32 y);
void VolumeFlyoutSetFromX(u32 x);

/// Mute-button hit-test.
bool VolumeFlyoutMuteContains(u32 x, u32 y);

u32 VolumeFlyoutWidth();
u32 VolumeFlyoutHeight();

} // namespace duetos::drivers::video
