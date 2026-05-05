#pragma once

#include "drivers/video/menu.h"
#include "drivers/video/theme.h"
#include "util/types.h"

/*
 * Start-menu /APPS enumeration.
 *
 * Scans the FAT32 root for `/APPS/<NAME>.MNF` "shortcut manifests" and
 * surfaces each one as an extra Start-menu item so a user can
 * add launchers without rebuilding the kernel.
 *
 * Manifest format (line-oriented ASCII, ≤ 256 bytes):
 *   name=My Calculator       ; display label (≤ 30 chars)
 *
 *   ; pick exactly ONE of:
 *   target=calculator        ; case-insensitive ThemeRole name
 *   kind=pe path=APPS/foo.exe  ; FAT32 path, walked from volume root
 *   kind=elf path=APPS/bar
 *
 * Recognised targets: calculator, notes, files, clock, settings,
 * gfxdemo, taskmanager, logview, imageview, about, help, browser,
 * calendar. Unknown targets are skipped (manifest ignored
 * entirely; serial-logged once).
 *
 * `kind=pe` / `kind=elf` invoke `SpawnPeFile` / `SpawnElfFile` on
 * the bytes read from the FAT32 path. Cap set + budget are
 * trusted (the user dropped the manifest into /APPS); a future
 * sandbox slice gates this on a per-manifest cap field.
 *
 * Action-id range: kStartMenuAppsActionBase + slot. Resolution
 * goes through StartMenuAppsResolveLaunch(action, *out_kind, ...).
 */

namespace duetos::drivers::video
{

inline constexpr u32 kStartMenuAppsActionBase = 200;
inline constexpr u32 kStartMenuAppsMax = 16;

/// Discriminates how a slot's action fires.
enum class ShortcutKind : u8
{
    Role = 0, ///< target=<role> — raise the existing app window
    Pe = 1,   ///< kind=pe path=...  — SpawnPeFile from FAT32
    Elf = 2,  ///< kind=elf path=... — SpawnElfFile from FAT32
};

/// Scan FAT32 /APPS, populate the in-memory shortcut table.
/// Creates /APPS as an empty directory and plants
/// /APPS/SAMPLE.MNF as a documentation seed if neither exists.
/// No-op if FAT32 isn't mounted. Idempotent — a second call
/// re-reads the directory.
void StartMenuAppsScan();

/// Append discovered shortcuts to `items[*count..max]`. Each
/// label points into the module's static label pool so caller
/// must not free. `count` is updated; if `max` is reached
/// remaining shortcuts are dropped (logged once on serial).
void StartMenuAppsAppendTo(MenuItem* items, u32* count, u32 max);

/// Translate a fired action id to the target ThemeRole. Returns
/// false if the slot is a PE/ELF launch (use
/// `StartMenuAppsResolveLaunch` for those) or the action is out
/// of band. Kept for callers that only care about the role path.
bool StartMenuAppsResolve(u32 action_id, ThemeRole* out);

/// Full action-id resolver. Sets `*out_kind` and either
/// `*out_role` (Role kind) or `*out_path` (Pe / Elf kinds —
/// pointer into the slot's static path buffer, valid until the
/// next StartMenuAppsScan). Returns false on out-of-band ids
/// or unfilled slots.
bool StartMenuAppsResolveLaunch(u32 action_id, ShortcutKind* out_kind, ThemeRole* out_role, const char** out_path);

/// Boot self-test. Builds a synthetic manifest in memory,
/// parses it, asserts the resulting role matches. Skipped if
/// FAT32 isn't mounted. Prints PASS / FAIL / SKIP to COM1.
void StartMenuAppsSelfTest();

} // namespace duetos::drivers::video
