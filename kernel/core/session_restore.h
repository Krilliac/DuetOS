#pragma once

#include "util/types.h"

/*
 * Session persistence — theme + per-app window positions across
 * logins / reboots. Backing store is `SESSION.CFG` on the FAT32
 * root volume; format is plain ASCII `key=value\n` lines so it
 * can be read with `dmesg f` style streaming or hand-edited from
 * recovery.
 *
 * Hooks:
 *   - SessionRestoreApply() runs once at boot, after all apps
 *     are init'd and after FAT32 is probed. Applies the saved
 *     theme + each window's last-known x,y.
 *   - SessionRestoreSave() runs from the logout path (shell
 *     CmdLogout, settings logout button) and from the 1 Hz
 *     ui-ticker (autosave so a panic between logout cycles
 *     doesn't lose state).
 *
 * Format (line-oriented, 8.3-friendly):
 *   theme=DARK
 *   win.0.x=200       ; ThemeRole::Calculator
 *   win.0.y=120
 *   win.0.w=400       ; user-resized (e.g. ImageView zoom path)
 *   win.0.h=300
 *   win.1.x=300       ; ThemeRole::Notes
 *   win.1.y=80
 *   mouse.dblclick=50 ; WindowDoubleClickTicks
 *   mouse.sens=128    ; WindowMouseSensitivity (0..255, identity=128)
 *   kbd.rate=11       ; PS/2 typematic rate idx (0..31)
 *   kbd.delay=1       ; PS/2 typematic delay idx (0..3)
 *   kbd.layout=us     ; us / uk / dvorak / de / fr / colemak
 *   sound.cues=1      ; SoundCueIsEnabled (0|1)
 *   tz.minutes=-330   ; signed UTC offset in minutes
 *   calc.mem=42       ; calculator M register (only emitted when set)
 *   calc.memset=1     ; matching memset flag
 *   imageview.last=PHOTO.BMP  ; 8.3 filename of last-loaded image
 *
 * Unknown / malformed lines are skipped silently — the file
 * format is meant to absorb future fields without breaking old
 * boots. Roles / knobs not present in the file keep whatever
 * default state init has assigned them.
 */

namespace duetos::core
{

/// Read SESSION.CFG and apply it: ThemeSet + WindowMoveTo for
/// every recognised line. No-op if FAT32 isn't mounted or the
/// file doesn't exist (first boot path). Call AFTER every app's
/// initial WindowRegister and AFTER ThemeRegisterWindow has run
/// for each role — otherwise WindowMoveTo silently no-ops on
/// invalid handles. Idempotent — calling twice applies the same
/// state twice.
void SessionRestoreApply();

/// Snapshot the current theme + every registered role-window's
/// bounds and write them to SESSION.CFG. Throttles internally:
/// if the resulting payload matches the last successful save
/// byte-for-byte, the FAT32 write is skipped (so the 1 Hz
/// autosave doesn't beat the FAT mirror). Safe to call when no
/// FAT32 volume is mounted (no-op).
void SessionRestoreSave();

/// Boot self-test. Saves a probe state under a temp file, reads
/// it back, asserts the theme + a synthetic window position
/// round-trip exactly, deletes the probe. Skipped if FAT32 is
/// unavailable. Prints PASS / FAIL / SKIP to COM1.
void SessionRestoreSelfTest();

} // namespace duetos::core
