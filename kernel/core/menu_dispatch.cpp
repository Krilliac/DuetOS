/*
 * DuetOS — desktop menu + keyboard-shortcut dispatch: implementation.
 *
 * Companion to `menu_dispatch.h` — see there for the contract and
 * the rationale for living outside `core/main.cpp`. The dispatch
 * table here is keyed on the menu-item action ids defined by the
 * tables in `kernel_main`'s ui-closure body (kAppsItems,
 * kSystemMenuItems, kWindowMenuItems, etc.).
 *
 * The action-id allocation bands are:
 *   1..6     desktop / start menu — about, cycle, list, ping,
 *            switch-to-tty, help
 *   10..11   raise / close target window (used by hover-menu
 *            entries that already carry a target HWND in ctx)
 *   20..25   window system menu — restore, move, size, minimize,
 *            maximize, close. ctx = target HWND.
 *   30..33   Files-app row context menu — open, rename (GAP),
 *            delete, properties. ctx = row index.
 *   34..39   Files-app row context menu (extended FAT32) —
 *            refresh, new file, new folder, plus the shared
 *            generic non-FAT verbs (37 open / 38 properties /
 *            39 refresh) reused by the DuetFS / ramfs views.
 *   40..43   power / session — reboot, shutdown, lock, logout.
 *            40/41 don't return.
 *   44..47   Files-app row context menu (Trash / ramfs) —
 *            44 open (trash), 45 restore, 46 delete forever,
 *            47 delete (ramfs, disabled). Lives just after the
 *            power band so the Files surface fits inside the
 *            30..49 window reserved in Compositor.md.
 *   50..59   system shortcuts — screenshot, ...
 *   60..69   bespoke viewer windows — net status, device manager,
 *            firewall, ...
 *   100+     app launcher band (action - 100 -> ThemeRole).
 *   200+     /APPS shortcut band — resolved through
 *            StartMenuAppsResolveLaunch.
 */

#include "core/menu_dispatch.h"

#include "apps/devicemgr.h"
#include "apps/files.h"
#include "apps/firewall.h"
#include "apps/netstatus.h"
#include "apps/screenshot.h"
#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "core/session_restore.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/dialog.h"
#include "drivers/video/modal_input.h"
#include "drivers/video/notify.h"
#include "drivers/video/start_menu_apps.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "mm/address_space.h"
#include "mm/kheap.h"
#include "power/reboot.h"
#include "proc/process.h"
#include "proc/spawn.h"
#include "security/login.h"
#include "util/types.h"

namespace duetos::core
{

void PrintShortcutHelp()
{
    using duetos::drivers::video::ConsoleWriteln;
    ConsoleWriteln("");
    ConsoleWriteln("==== DUETOS QUICK REFERENCE ===================");
    ConsoleWriteln("  GETTING STARTED");
    ConsoleWriteln("    CLICK [START] OR PRESS CTRL+ESC TO LAUNCH APPS");
    ConsoleWriteln("    CLICK A TASKBAR TAB TO RAISE THAT WINDOW");
    ConsoleWriteln("    DRAG A TITLE BAR TO MOVE A WINDOW");
    ConsoleWriteln("    CLICK [X] OR PRESS ALT+F4 TO CLOSE");
    ConsoleWriteln("    TYPE 'HELP' AT THE PROMPT FOR SHELL COMMANDS");
    ConsoleWriteln("");
    ConsoleWriteln("  WINDOWS");
    ConsoleWriteln("    ALT+TAB           CYCLE ACTIVE WINDOW");
    ConsoleWriteln("    CTRL+ALT+UP       MAXIMISE / RESTORE");
    ConsoleWriteln("    CTRL+ALT+DOWN     RESTORE / MINIMISE");
    ConsoleWriteln("    CTRL+ALT+LEFT/R   SNAP HALF-SCREEN");
    ConsoleWriteln("    CTRL+ALT+SHIFT+   ARROW: GROW / SHRINK 32 PX");
    ConsoleWriteln("    CTRL+ALT+, / .    OPACITY DOWN / UP");
    ConsoleWriteln("");
    ConsoleWriteln("  DESKTOP / SYSTEM");
    ConsoleWriteln("    F1                THIS HELP");
    ConsoleWriteln("    CTRL+ALT+T        TOGGLE DESKTOP / TTY");
    ConsoleWriteln("    CTRL+ALT+B        TOGGLE TASKBAR TOP / BOT");
    ConsoleWriteln("    CTRL+ALT+L        LOCK / UNLOCK TASKBAR");
    ConsoleWriteln("    CTRL+ALT+Y        CYCLE THEME");
    ConsoleWriteln("    CTRL+ALT+1..9     PICK THEME DIRECTLY");
    ConsoleWriteln("    CTRL+ALT+F1/F2    SHELL / KLOG CONSOLE");
    ConsoleWriteln("    CTRL+ALT+P        SCREENSHOT TO SHOTNNNN.BMP");
    ConsoleWriteln("    CTRL+ALT+M        TOGGLE MAGNIFIER");
    ConsoleWriteln("    CTRL+ALT+K        LOCK SCREEN");
    ConsoleWriteln("    CTRL+C            INTERRUPT SHELL COMMAND");
    ConsoleWriteln("    CTRL+SHIFT+V      ROTATE CLIPBOARD HISTORY");
    ConsoleWriteln("");
    ConsoleWriteln("  NOTES (WHEN ACTIVE)");
    ConsoleWriteln("    CTRL+C / CTRL+V   COPY / PASTE CLIPBOARD");
    ConsoleWriteln("    CTRL+S            SAVE TO NOTES.TXT (FAT32)");
    ConsoleWriteln("    CTRL+O            LOAD FROM NOTES.TXT (FAT32)");
    ConsoleWriteln("    CTRL+F            FIND (case-insensitive)");
    ConsoleWriteln("    F3                FIND NEXT (wraps to start)");
    ConsoleWriteln("    CTRL+H            FIND-AND-REPLACE (two prompts)");
    ConsoleWriteln("    CTRL+A            SELECT ALL");
    ConsoleWriteln("    CTRL+G            GO TO LINE");
    ConsoleWriteln("    STATUS FOOTER     L:line C:col  CHARS  WORDS  *MOD");
    ConsoleWriteln("");
    ConsoleWriteln("  CALCULATOR (WHEN ACTIVE)");
    ConsoleWriteln("    0..9 + - * / =    BASIC ARITHMETIC");
    ConsoleWriteln("    C  %  N/_  BS     CLEAR / PERCENT / SIGN / BACKSPACE");
    ConsoleWriteln("    M / S             MEMORY RECALL / STORE");
    ConsoleWriteln("    A / B             MEMORY ADD / SUBTRACT");
    ConsoleWriteln("    L                 MEMORY CLEAR");
    ConsoleWriteln("    Q / X / Y / R / ! SQRT / SQUARE / ABS / 1OVERN / FACTORIAL");
    ConsoleWriteln("    & | ^ < > ~       BITWISE AND/OR/XOR/SHL/SHR/NOT");
    ConsoleWriteln("    HEX BIN OCT       SHOWN LIVE BELOW DECIMAL DISPLAY");
    ConsoleWriteln("");
    ConsoleWriteln("  TASK MANAGER (WHEN ACTIVE)");
    ConsoleWriteln("    TAB               CYCLE PROCESSES / PERFORMANCE");
    ConsoleWriteln("    UP / DN           MOVE SELECTION (PROCESSES TAB)");
    ConsoleWriteln("    PGUP / PGDN       PAGE-STEP SELECTION");
    ConsoleWriteln("    HOME / END        FIRST / LAST ROW");
    ConsoleWriteln("    S                 CYCLE SORT (CPU / PID / NAME / STATE)");
    ConsoleWriteln("    K / DEL           KILL SELECTED PROCESS (CONFIRM)");
    ConsoleWriteln("    R                 FORCE SNAPSHOT REBUILD");
    ConsoleWriteln("");
    ConsoleWriteln("  FILES (WHEN ACTIVE)");
    ConsoleWriteln("    UP / DN           MOVE SELECTION");
    ConsoleWriteln("    ENTER             OPEN (DESCEND DIR / DISPATCH)");
    ConsoleWriteln("    B / BACKSPACE     UP ONE LEVEL (RAM MODE)");
    ConsoleWriteln("    D / M / T         SWITCH DISK / RAM / TRASH VIEW");
    ConsoleWriteln("    R                 RESCAN (DISK) / RESTORE (TRASH)");
    ConsoleWriteln("    S                 CYCLE SORT (NAME -> SIZE -> TYPE)");
    ConsoleWriteln("    X THEN Y          DISK: TO TRASH; TRASH: PERM-DEL");
    ConsoleWriteln("    E THEN Y          EMPTY TRASH (TRASH VIEW ONLY)");
    ConsoleWriteln("");
    ConsoleWriteln("  IMAGE VIEWER (WHEN ACTIVE)");
    ConsoleWriteln("    N / P / LEFT/RT   NEXT / PREV IMAGE");
    ConsoleWriteln("    R                 RESCAN DISK FOR IMAGES");
    ConsoleWriteln("    + / -             ZOOM IN / OUT (resize)");
    ConsoleWriteln("    CTRL+WHEEL        ZOOM IN / OUT (mouse)");
    ConsoleWriteln("");
    ConsoleWriteln("  BROWSER (WHEN ACTIVE)");
    ConsoleWriteln("    U / TAB           ENTER URL EDIT");
    ConsoleWriteln("    ENTER (URL EDIT)  FETCH; ESC CANCEL");
    ConsoleWriteln("    B / F             BACK / FORWARD HISTORY");
    ConsoleWriteln("    R                 RELOAD CURRENT");
    ConsoleWriteln("    H                 HISTORY LIST");
    ConsoleWriteln("    L / M             BMARK LIST / MARK CURRENT");
    ConsoleWriteln("    S                 SAVE BODY TO DLNNNN.HTM");
    ConsoleWriteln("    J / K / UP / DN   SCROLL");
    ConsoleWriteln("");
    ConsoleWriteln("  CALENDAR (WHEN ACTIVE)");
    ConsoleWriteln("    [ / ]  / LEFT/RT   PREV / NEXT MONTH");
    ConsoleWriteln("    { / }  / UP / DN   PREV / NEXT YEAR");
    ConsoleWriteln("    T                  JUMP TO TODAY");
    ConsoleWriteln("    SHIFT+LEFT/RIGHT   STEP SELECTION 1 DAY");
    ConsoleWriteln("    SHIFT+UP/DOWN      STEP SELECTION 7 DAYS");
    ConsoleWriteln("    ENTER              ADD EVENT (selected date)");
    ConsoleWriteln("    DEL                REMOVE EVENT (selected date)");
    ConsoleWriteln("    CTRL+S / CTRL+O    SAVE / LOAD CALENDAR.TXT");
    ConsoleWriteln("");
    ConsoleWriteln("  SETTINGS BUTTONS");
    ConsoleWriteln("    THEME / OPACITY / TZ / LOG OUT / REBOOT / SHUTDOWN");
    ConsoleWriteln("================================================");
    ConsoleWriteln("");
}

void DispatchMenuAction(duetos::u32 action, duetos::u32 ctx)
{
    using duetos::arch::SerialWrite;
    using duetos::arch::SerialWriteHex;
    switch (action)
    {
    case 1: // ABOUT DUETOS
    {
        const duetos::drivers::video::WindowHandle ah =
            duetos::drivers::video::ThemeRoleWindow(duetos::drivers::video::ThemeRole::About);
        if (ah != duetos::drivers::video::kWindowInvalid)
        {
            duetos::drivers::video::WindowRaise(ah);
            duetos::drivers::video::ConsoleWriteln("-> ABOUT WINDOW RAISED");
        }
        else
        {
            duetos::drivers::video::ConsoleWriteln("-> DUETOS v0 — WINDOWED DESKTOP SHELL");
        }
        break;
    }
    case 2: // CYCLE WINDOWS
        duetos::drivers::video::WindowCycleActive();
        duetos::drivers::video::ConsoleWriteln("-> CYCLED ACTIVE WINDOW");
        break;
    case 3: // LIST WINDOWS
        duetos::drivers::video::ConsoleWriteln("-> REGISTERED WINDOWS:");
        for (duetos::u32 h = 0; h < duetos::drivers::video::WindowRegistryCount(); ++h)
        {
            if (duetos::drivers::video::WindowIsAlive(h))
            {
                const char* title = duetos::drivers::video::WindowTitle(h);
                duetos::drivers::video::ConsoleWrite("   ");
                duetos::drivers::video::ConsoleWriteln((title != nullptr) ? title : "(UNNAMED)");
            }
        }
        break;
    case 4: // PING CONSOLE
        duetos::drivers::video::ConsoleWriteln("-> PONG");
        break;
    case 5: // SWITCH TO TTY
        duetos::drivers::video::SetDisplayMode(duetos::drivers::video::DisplayMode::Tty);
        duetos::drivers::video::ConsoleSetOrigin(16, 16);
        duetos::drivers::video::ConsoleSetColours(duetos::drivers::video::ThemeCurrent().console_fg, 0x00000000);
        break;
    case 7: // NEW TEXT FILE — prompt, then create an empty file on
            // the FAT32 disk root (the user-visible writable volume
            // the Files app's Disk view lists).
    {
        duetos::drivers::video::InputBoxOpen(
            "NEW TEXT FILE", "Enter file name (8.3 form):", "NEW.TXT",
            [](duetos::drivers::video::DialogResult r, const char* text, void*)
            {
                if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr || text[0] == '\0')
                {
                    duetos::drivers::video::NotifyShow("new file cancelled");
                    return;
                }
                const duetos::fs::fat32::Volume* v = duetos::fs::fat32::Fat32Volume(0);
                if (v == nullptr)
                {
                    duetos::drivers::video::NotifyShow("new file: no FAT32 volume");
                    return;
                }
                char path[24];
                path[0] = '/';
                duetos::u32 pi = 1;
                for (duetos::u32 i = 0; text[i] != '\0' && pi + 1 < sizeof(path); ++i)
                    path[pi++] = text[i];
                path[pi] = '\0';
                const bool ok = duetos::fs::fat32::Fat32CreateAtPath(v, path, nullptr, 0) >= 0;
                duetos::drivers::video::NotifyShow(ok ? "file created" : "create failed");
                duetos::arch::SerialWrite("[desktop] new text file ");
                duetos::arch::SerialWrite(ok ? "ok: " : "FAILED: ");
                duetos::arch::SerialWrite(path);
                duetos::arch::SerialWrite("\n");
            },
            nullptr);
        break;
    }
    case 8: // REFRESH DESKTOP — recompose the wallpaper + windows.
        duetos::drivers::video::DesktopCompose(duetos::drivers::video::ThemeCurrent().desktop_bg,
                                               nullptr);
        duetos::drivers::video::ConsoleWriteln("-> DESKTOP REFRESHED");
        break;
    case 9: // SHOW DESKTOP — toggle minimize-all / restore.
        duetos::drivers::video::WindowShowDesktopToggle();
        duetos::drivers::video::ConsoleWriteln("-> SHOW DESKTOP TOGGLED");
        break;
    case 6: // HELP / SHORTCUTS
    {
        const duetos::drivers::video::WindowHandle hh =
            duetos::drivers::video::ThemeRoleWindow(duetos::drivers::video::ThemeRole::Help);
        if (hh != duetos::drivers::video::kWindowInvalid)
        {
            duetos::drivers::video::WindowRaise(hh);
        }
        PrintShortcutHelp();
        break;
    }
    case 10: // RAISE <ctx>
        duetos::drivers::video::WindowRaise(ctx);
        SerialWrite("[ui] ctx raise window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    case 11: // CLOSE <ctx>
        duetos::drivers::video::WindowClose(ctx);
        SerialWrite("[ui] ctx close window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    // Window system menu (action ids 20..25). ctx = target HWND.
    // 21 (MOVE) and 22 (SIZE) are GAPs in v0 — see CLAUDE.md
    // "Subsystem-Isolation" doc; needs a modal-input mode that
    // doesn't yet exist. 22 SIZE is shipped disabled; 21 MOVE
    // does a one-shot recenter under the cursor as a degraded
    // stand-in. Re-enable both when modal-input lands.
    case 20: // RESTORE
        duetos::drivers::video::WindowRestore(ctx);
        SerialWrite("[ui] ctx restore window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    case 21: // MOVE — modal cursor-follow
    {
        // Capture the window's anchor + initial cursor and
        // enter a modal session. Motion frames update the
        // window position so it follows the cursor; press
        // commits (cursor stays where it was, window stays
        // under it); Esc cancels and restores the anchor.
        struct MoveCtx
        {
            duetos::drivers::video::WindowHandle hwnd;
            duetos::u32 anchor_cx, anchor_cy;
            duetos::u32 anchor_x, anchor_y;
        };
        static MoveCtx s_move{};
        s_move.hwnd = ctx;
        duetos::drivers::video::CursorPosition(&s_move.anchor_cx, &s_move.anchor_cy);
        duetos::drivers::video::WindowGetBounds(ctx, &s_move.anchor_x, &s_move.anchor_y, nullptr, nullptr);
        duetos::drivers::video::ModalInputCallbacks cb{};
        cb.cursor = duetos::drivers::video::CursorShape::Hand;
        cb.user = &s_move;
        cb.motion = [](duetos::u32 cx, duetos::u32 cy, void* user)
        {
            const auto* m = static_cast<const MoveCtx*>(user);
            const duetos::i32 dx = static_cast<duetos::i32>(cx) - static_cast<duetos::i32>(m->anchor_cx);
            const duetos::i32 dy = static_cast<duetos::i32>(cy) - static_cast<duetos::i32>(m->anchor_cy);
            const duetos::u32 nx =
                (dx >= 0)
                    ? m->anchor_x + static_cast<duetos::u32>(dx)
                    : (m->anchor_x > static_cast<duetos::u32>(-dx) ? m->anchor_x - static_cast<duetos::u32>(-dx) : 0);
            const duetos::u32 ny =
                (dy >= 0)
                    ? m->anchor_y + static_cast<duetos::u32>(dy)
                    : (m->anchor_y > static_cast<duetos::u32>(-dy) ? m->anchor_y - static_cast<duetos::u32>(-dy) : 0);
            duetos::drivers::video::WindowMoveTo(m->hwnd, nx, ny);
        };
        cb.commit = [](duetos::u32 /*cx*/, duetos::u32 /*cy*/, void* /*user*/) {};
        cb.cancel = [](void* user)
        {
            const auto* m = static_cast<const MoveCtx*>(user);
            duetos::drivers::video::WindowMoveTo(m->hwnd, m->anchor_x, m->anchor_y);
        };
        duetos::drivers::video::ModalInputBegin(cb);
        SerialWrite("[ui] ctx move modal-begin window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    }
    case 22: // SIZE — modal cursor-follow resize from bottom-right
    {
        // Cursor delta from the press point becomes the new
        // (w, h). Anchored on the BR corner — moving the cursor
        // right/down grows the window; left/up shrinks it.
        // Press commits the size; Esc restores anchor.
        struct SizeCtx
        {
            duetos::drivers::video::WindowHandle hwnd;
            duetos::u32 anchor_cx, anchor_cy;
            duetos::u32 anchor_w, anchor_h;
        };
        static SizeCtx s_size{};
        s_size.hwnd = ctx;
        duetos::drivers::video::CursorPosition(&s_size.anchor_cx, &s_size.anchor_cy);
        duetos::drivers::video::WindowGetBounds(ctx, nullptr, nullptr, &s_size.anchor_w, &s_size.anchor_h);
        duetos::drivers::video::ModalInputCallbacks cb{};
        cb.cursor = duetos::drivers::video::CursorShape::ResizeNWSE;
        cb.user = &s_size;
        cb.motion = [](duetos::u32 cx, duetos::u32 cy, void* user)
        {
            const auto* sz = static_cast<const SizeCtx*>(user);
            const duetos::i32 dx = static_cast<duetos::i32>(cx) - static_cast<duetos::i32>(sz->anchor_cx);
            const duetos::i32 dy = static_cast<duetos::i32>(cy) - static_cast<duetos::i32>(sz->anchor_cy);
            duetos::drivers::video::WindowResizeFromEdge(sz->hwnd,
                                                         duetos::drivers::video::WindowResizeEdge::BottomRight,
                                                         /*ax*/ 0, /*ay*/ 0, sz->anchor_w, sz->anchor_h, dx, dy);
        };
        cb.commit = [](duetos::u32 /*cx*/, duetos::u32 /*cy*/, void* /*user*/) {};
        cb.cancel = [](void* user)
        {
            const auto* sz = static_cast<const SizeCtx*>(user);
            duetos::drivers::video::WindowResizeFromEdge(sz->hwnd,
                                                         duetos::drivers::video::WindowResizeEdge::BottomRight, 0, 0,
                                                         sz->anchor_w, sz->anchor_h, 0, 0);
        };
        duetos::drivers::video::ModalInputBegin(cb);
        SerialWrite("[ui] ctx size modal-begin window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    }
    case 23: // MINIMIZE
        duetos::drivers::video::WindowMinimize(ctx);
        SerialWrite("[ui] ctx minimize window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    case 24: // MAXIMIZE
        duetos::drivers::video::WindowMaximize(ctx);
        SerialWrite("[ui] ctx maximize window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    case 25: // CLOSE (system menu) — alias for case 11 with a different label
        duetos::drivers::video::WindowClose(ctx);
        SerialWrite("[ui] ctx sys-close window=");
        SerialWriteHex(ctx);
        SerialWrite("\n");
        break;
    // Files-app row context menu. ctx = the row index in the
    // active listing, captured at MenuOpen time. The Files app's
    // own dispatcher knows what to do with each row id; we route
    // every Files action here.
    // Files context-action band 30..39: 30 OPEN, 31 RENAME, 32
    // DELETE, 33 PROPERTIES, 34 REFRESH, 35 NEW FILE, 36 NEW
    // FOLDER, 37 OPEN (non-FAT views), 38 PROPERTIES (non-FAT),
    // 39 REFRESH (non-FAT). All route to the app's own dispatcher.
    // The 44..47 sub-band carries the Trash / ramfs row verbs
    // that don't fit in 37..39 (OPEN / RESTORE / DELETE FOREVER
    // / ramfs-DELETE), placed just after the power band so the
    // Files surface still fits inside the 30..49 window the
    // wiki action-id table reserves.
    case 30:
    case 31:
    case 32:
    case 33:
    case 34:
    case 35:
    case 36:
    case 37:
    case 38:
    case 39:
    case 44:
    case 45:
    case 46:
    case 47:
        duetos::apps::files::FilesDispatchContextAction(action, ctx);
        break;
    // Power / session band (40..49). 40/41 don't return.
    case 40: // REBOOT
        SerialWrite("[ui] menu fire reboot\n");
        duetos::core::SessionRestoreSave();
        duetos::core::KernelReboot();
        // unreachable
        break;
    case 41: // SHUT DOWN
        SerialWrite("[ui] menu fire shutdown\n");
        duetos::core::SessionRestoreSave();
        duetos::core::KernelHalt();
        // unreachable
        break;
    case 42: // LOCK
        SerialWrite("[ui] menu fire lock\n");
        duetos::core::SessionRestoreSave();
        duetos::core::LoginLock();
        break;
    case 43: // LOG OUT
        SerialWrite("[ui] menu fire logout\n");
        duetos::core::SessionRestoreSave();
        duetos::core::LoginReopen();
        break;
    // System shortcuts (50..59).
    case 50: // SCREENSHOT
        SerialWrite("[ui] menu fire screenshot\n");
        // ScreenshotCapture takes its own CompositorLock per its
        // header contract; the menu close path that runs before
        // we get here has already released the lock.
        duetos::apps::screenshot::ScreenshotCapture();
        break;
    // Bespoke viewer windows (60..69) — no ThemeRole, raised
    // directly via their stored handle.
    case 60: // NETWORK STATUS
    {
        const auto h = duetos::apps::netstatus::NetStatusWindow();
        if (h != duetos::drivers::video::kWindowInvalid)
        {
            duetos::drivers::video::WindowSetVisible(h, true);
            duetos::drivers::video::WindowRaise(h);
        }
        break;
    }
    case 61: // DEVICE MANAGER
    {
        const auto h = duetos::apps::devicemgr::DeviceMgrWindow();
        if (h != duetos::drivers::video::kWindowInvalid)
        {
            duetos::drivers::video::WindowSetVisible(h, true);
            duetos::drivers::video::WindowRaise(h);
        }
        break;
    }
    case 62: // FIREWALL
    {
        const auto h = duetos::apps::firewall::FirewallWindow();
        if (h != duetos::drivers::video::kWindowInvalid)
        {
            duetos::drivers::video::WindowSetVisible(h, true);
            duetos::drivers::video::WindowRaise(h);
        }
        break;
    }
    default:
        // App launcher bands: 100..199 == "raise the window
        // registered for ThemeRole(action - 100)". /APPS shortcut
        // band is 200+slot — resolve through StartMenuAppsResolve
        // to recover the ThemeRole or a path before raising.
        bool have_role = false;
        duetos::drivers::video::ThemeRole role{};
        if (action >= 100 && action < 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::kCount))
        {
            role = static_cast<duetos::drivers::video::ThemeRole>(action - 100);
            have_role = true;
        }
        else
        {
            duetos::drivers::video::ShortcutKind sk{};
            const char* spawn_path = nullptr;
            if (duetos::drivers::video::StartMenuAppsResolveLaunch(action, &sk, &role, &spawn_path))
            {
                if (sk == duetos::drivers::video::ShortcutKind::Role)
                {
                    have_role = true;
                }
                else if ((sk == duetos::drivers::video::ShortcutKind::Pe ||
                          sk == duetos::drivers::video::ShortcutKind::Elf) &&
                         spawn_path != nullptr && spawn_path[0] != '\0')
                {
                    char path_buf[128];
                    duetos::u64 pi = 0;
                    if (spawn_path[0] != '/')
                        path_buf[pi++] = '/';
                    while (spawn_path[pi - (spawn_path[0] != '/' ? 1 : 0)] != '\0' && pi + 1 < sizeof(path_buf))
                    {
                        path_buf[pi] = spawn_path[pi - (spawn_path[0] != '/' ? 1 : 0)];
                        ++pi;
                    }
                    path_buf[pi] = '\0';
                    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
                    duetos::fs::fat32::DirEntry ent;
                    if (vol != nullptr && duetos::fs::fat32::Fat32LookupPath(vol, path_buf, &ent) &&
                        ent.size_bytes > 0 && ent.size_bytes <= 8 * 1024 * 1024)
                    {
                        auto* staging = reinterpret_cast<duetos::u8*>(duetos::mm::KMalloc(ent.size_bytes));
                        if (staging != nullptr)
                        {
                            const auto got = duetos::fs::fat32::Fat32ReadFile(vol, &ent, staging, ent.size_bytes);
                            if (got == static_cast<duetos::i64>(ent.size_bytes))
                            {
                                const duetos::u64 pid =
                                    (sk == duetos::drivers::video::ShortcutKind::Pe)
                                        ? duetos::core::SpawnPeFile(
                                              "/apps/launch", staging, static_cast<duetos::u64>(got),
                                              duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                              duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted)
                                        : duetos::core::SpawnElfFile(
                                              "/apps/launch", staging, static_cast<duetos::u64>(got),
                                              duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                              duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
                                duetos::drivers::video::ConsoleWrite(pid != 0 ? "-> /APPS LAUNCH OK pid="
                                                                              : "-> /APPS LAUNCH FAIL");
                                if (pid != 0)
                                {
                                    char pidbuf[24];
                                    duetos::u32 pi2 = 0;
                                    duetos::u64 v = pid;
                                    char tmp[24];
                                    duetos::u32 ti = 0;
                                    if (v == 0)
                                        tmp[ti++] = '0';
                                    while (v != 0)
                                    {
                                        tmp[ti++] = static_cast<char>('0' + v % 10);
                                        v /= 10;
                                    }
                                    while (ti > 0)
                                        pidbuf[pi2++] = tmp[--ti];
                                    pidbuf[pi2] = '\0';
                                    duetos::drivers::video::ConsoleWriteln(pidbuf);
                                }
                                else
                                {
                                    duetos::drivers::video::ConsoleWriteln(path_buf);
                                }
                            }
                            duetos::mm::KFree(staging);
                        }
                    }
                    else
                    {
                        duetos::drivers::video::ConsoleWrite("-> /APPS NOT FOUND ");
                        duetos::drivers::video::ConsoleWriteln(path_buf);
                    }
                }
            }
        }
        if (have_role)
        {
            const auto h = duetos::drivers::video::ThemeRoleWindow(role);
            if (h != duetos::drivers::video::kWindowInvalid)
            {
                duetos::drivers::video::WindowSetVisible(h, true);
                duetos::drivers::video::WindowRaise(h);
                duetos::drivers::video::ConsoleWrite("-> RAISED ");
                const char* tt = duetos::drivers::video::WindowTitle(h);
                duetos::drivers::video::ConsoleWriteln((tt != nullptr) ? tt : "(UNNAMED)");
            }
            else
            {
                duetos::drivers::video::ConsoleWriteln("-> APP NOT REGISTERED");
            }
        }
        break;
    }
    SerialWrite("[ui] menu fire action=");
    SerialWriteHex(action);
    SerialWrite("\n");
}

} // namespace duetos::core
