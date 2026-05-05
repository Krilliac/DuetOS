#pragma once

#include "util/types.h"

/*
 * UI sound cues — v0.
 *
 * Thin convenience layer over PcSpeakerBeep that maps named
 * UI events to their canonical tone+duration. Centralises the
 * decision so an alarm or error sound is consistent across
 * every consumer (Notes, Files, Clock alarm, dialog reject).
 *
 * Each cue is a one-shot blocking call — same contract as
 * PcSpeakerBeep itself. Callers must not be holding a long-
 * held lock; v0 cue durations are 80–250 ms.
 *
 * The g_enabled flag (default true) gates every cue so a
 * future Settings toggle can mute system sounds without
 * touching every call site. Toggling it doesn't affect any
 * tone already in flight — it just suppresses future calls.
 *
 * Context: kernel. Callable from task context only.
 */

namespace duetos::drivers::video
{

/// Soft "click" — register a UI commit (button press, menu
/// pick, scrollbar release). 80 ms, 1 kHz.
void SoundCueClick();

/// Reject buzz — fired on rejected operations (dialog cancel
/// on invalid input, "rename failed", "no FAT32 volume").
/// 150 ms, 220 Hz — distinctively low so it reads as "no".
void SoundCueError();

/// Alarm trigger — repeated short tones. Fired by Clock when
/// the alarm matches RTC. 200 ms total, 880 Hz.
void SoundCueAlarm();

/// Notification chime — fired alongside NotifyShow for
/// non-error toasts (boot welcome, screenshot saved). 100 ms
/// + 100 ms two-tone (440 Hz, 660 Hz).
void SoundCueChime();

/// Master mute. Toggled by the Settings Sound panel. Default
/// is true (sounds enabled).
void SoundCueSetEnabled(bool enabled);

/// Read the master mute state.
bool SoundCueIsEnabled();

} // namespace duetos::drivers::video
