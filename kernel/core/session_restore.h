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
 *   win.1.x=300       ; ThemeRole::Notes
 *   win.1.y=80
 *   ...
 *
 * Unknown / malformed lines are skipped silently — the file
 * format is meant to absorb future fields without breaking old
 * boots. Roles not present in the file keep whatever default
 * position main.cpp assigned them.
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
