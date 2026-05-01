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
 *   target=calculator        ; case-insensitive ThemeRole name
 *
 * Recognised targets: calculator, notes, files, clock, settings,
 * gfxdemo, taskmanager, logview. Unknown targets are skipped
 * (manifest ignored entirely; serial-logged once).
 *
 * Real PE / ELF launching is gated on the loader runtime — when
 * that lands, an additional `kind=pe path=APPS/foo.exe` field
 * extends this format. Today only the builtin-role alias path
 * works; that's the v0 contract.
 *
 * Action-id range: kStartMenuAppsActionBase + slot. Resolution
 * goes through StartMenuAppsResolve(action) -> ThemeRole.
 */

namespace duetos::drivers::video
{

inline constexpr u32 kStartMenuAppsActionBase = 200;
inline constexpr u32 kStartMenuAppsMax = 16;

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

/// Translate a fired action id (kStartMenuAppsActionBase..) to
/// the target ThemeRole. Returns false if the id is outside the
/// shortcut range or no manifest fills that slot.
bool StartMenuAppsResolve(u32 action_id, ThemeRole* out);

/// Boot self-test. Builds a synthetic manifest in memory,
/// parses it, asserts the resulting role matches. Skipped if
/// FAT32 isn't mounted. Prints PASS / FAIL / SKIP to COM1.
void StartMenuAppsSelfTest();

} // namespace duetos::drivers::video
