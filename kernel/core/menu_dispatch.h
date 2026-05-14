#pragma once

#include "util/types.h"

/*
 * DuetOS — desktop menu + keyboard-shortcut dispatch.
 *
 * WHAT
 *   `DispatchMenuAction` is the single routing point for every menu
 *   item the desktop shell exposes — Start menu, system menu,
 *   window menu, Files row context menu, and the power / session
 *   band. It maps an `action` id (from the menu definition tables
 *   that live alongside the menu tracker in `kernel_main`) to the
 *   side-effect that backs it. `PrintShortcutHelp` dumps the F1
 *   quick-reference text to the framebuffer console.
 *
 * WHY THIS IS ITS OWN TU
 *   `kernel/core/main.cpp` is the kernel's boot orchestrator. Its
 *   file header says explicitly that the file owns the *call
 *   sequence* — boot order is load-bearing because getting it
 *   wrong is a triple-fault. Steady-state UI handlers are not part
 *   of that sequence: they run from kbd / mouse reader threads
 *   long after `kernel_main` has fallen into its idle loop. Living
 *   in `main.cpp` they bloated the file by ~480 lines and pulled
 *   the desktop UI surface into the boot-order TU; here they are
 *   one focused unit that any future menu / shortcut change can
 *   touch without dragging boot-order in.
 *
 *   The menu-item *tables* (`kAppsItems`, `kSystemItems`, etc.)
 *   stay in `main.cpp` for now because they are constructed inside
 *   `kernel_main`'s ui-closure body alongside the menu tracker. A
 *   later slice can move them too once the ui closure is itself
 *   extracted; today's surface keeps the closures untouched.
 *
 * CONTRACT
 *   - `DispatchMenuAction` does **no** compositing of its own. The
 *     caller (mouse_reader on left-click, kbd_reader on Enter) is
 *     responsible for closing the menu, hiding / showing the
 *     cursor, and recomposing.
 *   - `action == 0` is reserved for "no item" and never reaches
 *     this entry point.
 *   - Power-band actions (40 REBOOT, 41 SHUT DOWN) do not return.
 *   - Action id allocation is shared with the menu definition
 *     tables; see the comment band above each `case` group for the
 *     band that owns it.
 */

namespace duetos::core
{

// Print the F1 / "HELP" menu-item quick-reference text to the
// framebuffer console. ASCII only because the bitmap font maps
// lowercase to uppercase. Called from F1 and from the Start
// menu's HELP item — both paths land here so the text stays in
// one place.
void PrintShortcutHelp();

// Dispatch a menu action_id to the side-effect that backs it.
// `action` is the action_id from the menu's `MenuItem` table; 0
// is reserved for "no item" and never reaches here. `ctx` is the
// ambient `MenuContext()` at fire time — for window menus it's
// the target `WindowHandle`; the system menu and Files row menu
// both pass ctx through too.
void DispatchMenuAction(duetos::u32 action, duetos::u32 ctx);

} // namespace duetos::core
