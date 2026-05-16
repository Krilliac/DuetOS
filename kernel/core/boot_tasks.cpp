// See boot_tasks.h. Mechanical extraction of the kernel_main
// boot-task lambdas; bodies are byte-identical.

#include "core/boot_tasks.h"

#include "apps/about.h"
#include "apps/browser.h"
#include "apps/calculator.h"
#include "apps/calendar.h"
#include "apps/charmap.h"
#include "apps/clock.h"
#include "apps/dbg.h"
#include "apps/devicemgr.h"
#include "apps/files.h"
#include "apps/firewall.h"
#include "apps/gfxdemo.h"
#include "apps/help.h"
#include "apps/hexview.h"
#include "apps/imageview.h"
#include "apps/netstatus.h"
#include "apps/notes.h"
#include "apps/notify_center.h"
#include "apps/screenshot.h"
#include "apps/settings.h"
#include "apps/sysmon.h"
#include "apps/taskman.h"
#include "apps/terminal.h"
#include "apps/trash.h"
#include "arch/x86_64/serial.h"
#include "core/menu_dispatch.h"
#include "core/session_restore.h"
#include "diag/fix_journal_persist.h"
#include "drivers/input/hid_keyboard.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/calendar.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/dialog.h"
#include "drivers/video/dnd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/magnifier.h"
#include "drivers/video/menu.h"
#include "drivers/video/modal_input.h"
#include "drivers/video/netpanel.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/start_menu_apps.h"
#include "drivers/video/svg.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/theme.h"
#include "drivers/video/tray_flyout.h"
#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"
#include "drivers/video/wallpaper.h"
#include "drivers/video/widget.h"
#include "log/klog.h"
#include "log/klog_persist.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "security/auth.h"
#include "security/broker.h"
#include "security/login.h"
#include "shell/shell.h"
#include "subsystems/win32/window_syscall.h"

namespace duetos::core
{

void UiTickerTask(void*)
{
    auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };
    for (;;)
    {
        duetos::sched::SchedSleepTicks(100);
        // Drain buffered log chunks to KERNEL.LOG once per
        // tick. Outside the compositor lock so a slow FAT32
        // append never stalls the desktop redraw.
        duetos::core::KlogPersistFlush();
        // Mirror the in-RAM fix journal to KERNEL.FIX on the
        // same cadence. Bounded I/O — full ring snapshot is at
        // most 128 KiB + 16 byte header, no-op when no records
        // have been added since the last flush could be cheaply
        // detected via stats but the rewrite itself is small
        // enough that we just always write.
        duetos::diag::FixJournalPersistFlush();
        // Autosave the theme + window-position session state.
        // Internally throttled — bytewise-equal payloads skip
        // the FAT32 write, so a stable session writes once
        // and then idles.
        duetos::core::SessionRestoreSave();
        // Push one sample into Sysmon's rolling ring. Cheap —
        // a heap stats read + a registry walk. No-op when the
        // app hasn't been initialised yet.
        duetos::apps::sysmon::SysmonTick();
        duetos::drivers::video::CompositorLock();
        // While the login gate is up the full-screen login
        // panel owns the framebuffer. Repaint it from its
        // own canonical state so the 1 Hz compose doesn't
        // clobber the field bounds / title bar.
        if (duetos::core::LoginIsActive() && duetos::core::LoginCurrentMode() == duetos::core::LoginMode::Gui)
        {
            duetos::core::LoginRepaint();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }
        if (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty)
        {
            duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
        }
        else
        {
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
        }
        duetos::drivers::video::CompositorUnlock();
    }
}


// Keyboard reader task: consumes Ps2 KeyEvents, runs the
// global shortcut + window/app keyboard dispatch, mirrors
// printable input to the framebuffer console + COM1.
void KbdReaderTask(void*)
{
    using namespace duetos::arch;
    using namespace duetos::drivers::input;
    // Sample at each compose call so Ctrl+Alt+Y (theme cycle)
    // takes effect on the very next repaint — don't cache.
    auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };
    for (;;)
    {
        const KeyEvent ev = Ps2KeyboardReadEvent();
        // Elevation broker — if an off-thread broker request has
        // posted a deferred prompt, the kbd reader takes over the
        // prompt UI here (safe because we ARE the legal
        // Ps2KeyboardReadEvent consumer). On a real handled
        // prompt, skip the normal routing for the synthetic
        // kKeyNone wake event that brought us here.
        if (duetos::security::BrokerKbdReaderPumpDeferred())
            continue;
        // Track async keyboard state BEFORE the early
        // release / kKeyNone filter so release edges are
        // recorded. `ev.code` wraps to the low 8 bits of
        // the VK cache so ext keys collide gracefully with
        // unmapped slots.
        duetos::drivers::video::WindowInputTrackKey(static_cast<duetos::u16>(ev.code), !ev.is_release);
        if (ev.is_release || ev.code == kKeyNone)
        {
            // PE-routed key release. The press / char branch
            // below is skipped for releases (the legacy reader
            // contract is "press only"), but a focused PE that
            // tracks WM_KEYUP / WM_SYSKEYUP — game input,
            // shortcut handlers, anything that distinguishes
            // hold-vs-tap — needs the release edge too. Modifier-
            // only transitions (kKeyNone) carry no VK so they
            // skip; modifier state itself is already tracked via
            // WindowInputTrackKey above.
            if (ev.is_release && ev.code != kKeyNone)
            {
                duetos::drivers::video::CompositorLock();
                const auto active_pe = duetos::drivers::video::WindowActive();
                const duetos::u64 pe_pid = (active_pe != duetos::drivers::video::kWindowInvalid)
                                               ? duetos::drivers::video::WindowOwnerPid(active_pe)
                                               : 0;
                if (pe_pid > 0)
                {
                    // lParam layout for KEYUP: bit 30 (previous
                    // state) = 1, bit 31 (transition state) = 1,
                    // bit 29 = Alt context (mirrors WM_KEYDOWN).
                    // Repeat count (bits 0..15) is always 1 for
                    // releases — auto-repeat collapses on press.
                    constexpr duetos::u32 kWmKeyUp = 0x0101;
                    constexpr duetos::u32 kWmSysKeyUp = 0x0105;
                    const bool alt_held = (ev.modifiers & kKeyModAlt) != 0;
                    const duetos::u64 lp_base = 1ull | (1ull << 30) | (1ull << 31);
                    const duetos::u64 lp = alt_held ? (lp_base | (1ull << 29)) : lp_base;
                    const duetos::u32 keyup_msg = alt_held ? kWmSysKeyUp : kWmKeyUp;
                    duetos::drivers::video::WindowPostMessage(active_pe, keyup_msg, ev.code, lp);
                    duetos::drivers::video::CompositorUnlock();
                    duetos::drivers::video::WindowMsgWakeAll();
                }
                else
                {
                    duetos::drivers::video::CompositorUnlock();
                }
            }
            continue;
        }
        const bool alt = (ev.modifiers & kKeyModAlt) != 0;
        const bool ctrl = (ev.modifiers & kKeyModCtrl) != 0;
        const bool shift = (ev.modifiers & kKeyModShift) != 0;
        // Publish for non-kbd consumers (wheel handlers etc.)
        // so a Ctrl+wheel gesture can be detected without a
        // race against the kbd ring's own state.
        duetos::drivers::video::WindowSetModifierState(ev.modifiers);
        bool dirty = false;

        // Login gate takes absolute priority — while a
        // session isn't open, EVERY keystroke is an auth
        // input. Modifier-held shortcuts (Ctrl+Alt+T, Alt+Tab,
        // ^C) are ignored here so a user can't side-step the
        // prompt by opening a window manager shortcut. The
        // gate draws its own framebuffer output; we bracket
        // with CompositorLock so it races neither the ui-
        // ticker nor the mouse reader.
        if (duetos::core::LoginIsActive())
        {
            // Ctrl+Alt+S on a LOCKED gate is the "switch user"
            // affordance: clears the lock, logs the locker out,
            // re-opens the gate so any account can sign in.
            // Available only while locked — on a fresh boot
            // (LoginIsActive but !LoginIsLocked) the chord
            // routes into LoginFeedKey along with everything
            // else.
            if (ctrl && alt && duetos::core::LoginIsLocked() && (ev.code == 's' || ev.code == 'S'))
            {
                duetos::drivers::video::CompositorLock();
                duetos::core::LoginSwitchUser();
                duetos::drivers::video::CompositorUnlock();
                continue;
            }
            duetos::drivers::video::CompositorLock();
            const bool still_active = duetos::core::LoginFeedKey(ev.code);
            if (!still_active)
            {
                // Login succeeded — wipe the login panel and
                // paint the full desktop (or TTY) underneath.
                // Drop a one-line orientation banner into the
                // console too, so a fresh user sees something
                // pointing at the discovery surface (Start
                // menu + F1) before the bare "duetos>" prompt.
                duetos::drivers::video::ConsoleWriteln("");
                duetos::drivers::video::ConsoleWriteln(
                    "WELCOME TO DUETOS. CLICK [START] OR PRESS F1 FOR A SHORTCUT REFERENCE.");
                const bool is_tty =
                    (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty);
                if (is_tty)
                {
                    duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
                }
                else
                {
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                    duetos::drivers::video::CursorShow();
                }
                // First-run welcome toast. One-shot per boot
                // (the static gate fires only on the first
                // post-login transition); a longer TTL than
                // the default so a new user reads it before
                // it decays. Skipped in TTY mode where there
                // are no toasts.
                static bool s_welcome_shown = false;
                if (!is_tty && !s_welcome_shown)
                {
                    s_welcome_shown = true;
                    duetos::drivers::video::NotifyShowFor("Welcome to DuetOS - press F1 for shortcuts", 8);
                }
            }
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // DnD active: Esc cancels the drag, every other
        // key is consumed silently so a stray keypress
        // doesn't bleed through.
        if (duetos::drivers::video::DndIsActive())
        {
            duetos::drivers::video::CompositorLock();
            if (ev.code == kKeyEsc)
            {
                duetos::drivers::video::DndCancel();
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Modal-input session (window Move / Size). Esc
        // cancels and restores the anchor; everything else
        // is consumed silently so a stray key doesn't bleed
        // through to apps.
        if (duetos::drivers::video::ModalInputIsActive())
        {
            duetos::drivers::video::CompositorLock();
            if (ev.code == kKeyEsc)
            {
                duetos::drivers::video::ModalInputOnCancel();
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Modal-dialog gate: when a MessageBox / InputBox is
        // up, route every keystroke into the dialog and skip
        // every downstream branch (menus, shortcuts, app
        // routing). The dialog consumes Enter / Esc, edits an
        // InputBox buffer on printable chars, and resolves
        // its callback when the user picks a button. Keeps
        // the modal contract simple: while a dialog is open,
        // nothing else hears keys.
        if (duetos::drivers::video::DialogIsActive())
        {
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::DialogFeedKey(static_cast<duetos::u16>(ev.code), ev.is_release, ev.modifiers);
            if (ev.code == kKeyEnter)
            {
                duetos::drivers::video::DialogFeedChar('\n');
            }
            else if (ev.code == kKeyBackspace)
            {
                duetos::drivers::video::DialogFeedChar(0x08);
            }
            else if (ev.code >= 0x20 && ev.code <= 0x7E)
            {
                duetos::drivers::video::DialogFeedChar(static_cast<char>(ev.code));
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Menu navigation: when a context / start menu is
        // open, arrow keys move the highlight, Enter activates
        // the hovered item, Esc closes, Right opens a submenu,
        // Left closes a submenu (or the whole menu at root).
        // Done before app shortcuts so the menu's modal UX
        // wins over per-app focus. Skipped on modifier-held
        // chords so Ctrl+C / Alt+Tab still reach the global
        // shortcuts below.
        if (!ctrl && !alt && duetos::drivers::video::MenuIsOpen())
        {
            duetos::drivers::video::CompositorLock();
            // Capture context BEFORE feeding the key — Esc /
            // Left at the root close the menu and reset
            // MenuContext to 0, but we need the original ctx
            // to know whether to wake a TrackPopupMenu syscall.
            const duetos::u32 ctx_before = duetos::drivers::video::MenuContext();
            const duetos::u32 fired = duetos::drivers::video::MenuFeedKey(static_cast<duetos::u16>(ev.code));
            const bool still_open = duetos::drivers::video::MenuIsOpen();
            if (fired != 0)
            {
                if (ctx_before == duetos::subsystems::win32::kTrackPopupSentinelCtx)
                {
                    duetos::subsystems::win32::TrackPopupCompleteFromKernel(fired);
                }
                else
                {
                    duetos::core::DispatchMenuAction(fired, ctx_before);
                }
                duetos::drivers::video::MenuClose();
            }
            else if (!still_open && ctx_before == duetos::subsystems::win32::kTrackPopupSentinelCtx)
            {
                // Esc / Left-at-root closed the popup without
                // firing — wake the syscall with cancel.
                duetos::subsystems::win32::TrackPopupCompleteFromKernel(0);
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Ctrl+C latches the shell interrupt flag. No
        // DesktopCompose here — the long-running command
        // holding the shell will notice next time it polls.
        // Skipped entirely if Alt is also held (that's a
        // different shortcut like Ctrl+Alt+T).
        if (ctrl && !alt && (ev.code == 'c' || ev.code == 'C'))
        {
            // If the active window is Notes, treat Ctrl+C as
            // "copy entire buffer to the kernel clipboard" so
            // a fresh user can hand text off to a Win32 PE
            // that calls GetClipboardData. Falls through to
            // the shell interrupt only when Notes isn't the
            // active window — preserves the established
            // ^C-aborts-shell-command behaviour.
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            const bool notes_focused =
                (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow());
            duetos::drivers::video::CompositorUnlock();
            if (notes_focused)
            {
                duetos::apps::notes::NotesCopyToClipboard();
                duetos::drivers::video::NotifyShow("copied to clipboard");
                SerialWrite("[ui] ^C copy notes -> clipboard\n");
                continue;
            }
            duetos::core::ShellInterrupt();
            SerialWrite("[ui] ^C\n");
            continue;
        }
        // Ctrl+Shift+V — rotate the clipboard history one step.
        // Bring the most recently displaced clip back to the
        // active slot; the previous active gets pushed onto
        // the history ring so a second rotate cycles back.
        // Bound globally so a user can roll the clipboard from
        // any focus context, then Ctrl+V into Notes.
        if (ctrl && shift && !alt && (ev.code == 'v' || ev.code == 'V'))
        {
            duetos::drivers::video::CompositorLock();
            const bool ok = duetos::drivers::video::WindowClipboardHistoryRotate();
            duetos::drivers::video::CompositorUnlock();
            if (ok)
            {
                char preview[48];
                const duetos::u32 n = duetos::drivers::video::WindowClipboardGetText(preview, sizeof(preview));
                char toast[80];
                duetos::u32 o = 0;
                const char* prefix = "clip: ";
                for (duetos::u32 k = 0; prefix[k] != '\0' && o + 1 < sizeof(toast); ++k)
                    toast[o++] = prefix[k];
                duetos::u32 take = n;
                if (take > sizeof(toast) - o - 4)
                    take = sizeof(toast) - o - 4;
                for (duetos::u32 k = 0; k < take; ++k)
                    toast[o++] = preview[k];
                if (n > take)
                {
                    toast[o++] = '.';
                    toast[o++] = '.';
                    toast[o++] = '.';
                }
                toast[o] = '\0';
                duetos::drivers::video::NotifyShow(toast);
            }
            else
            {
                duetos::drivers::video::NotifyShow("clip history empty");
            }
            SerialWrite("[ui] ^+V clipboard rotate\n");
            continue;
        }
        // Ctrl+V — paste the kernel clipboard into Notes when
        // Notes is the active window. No-op anywhere else
        // (the shell doesn't support paste yet, calculator /
        // files / settings don't accept arbitrary text).
        if (ctrl && !alt && (ev.code == 'v' || ev.code == 'V'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                const duetos::u32 n = duetos::apps::notes::NotesPasteFromClipboard();
                duetos::drivers::video::CompositorUnlock();
                if (n > 0)
                {
                    duetos::drivers::video::NotifyShow("pasted from clipboard");
                }
                SerialWrite("[ui] ^V paste -> notes\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+S — persist Notes / Calendar to the FAT32 root.
        // Active-window-gated: Notes -> NOTES.TXT, Calendar ->
        // CALENDAR.TXT. Anywhere else this chord is unbound.
        if (ctrl && !alt && (ev.code == 's' || ev.code == 'S'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                const bool ok = duetos::apps::notes::NotesSave();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShowKind(ok ? "saved to NOTES.TXT" : "save failed",
                                                       ok ? duetos::drivers::video::NotifyKind::Success
                                                          : duetos::drivers::video::NotifyKind::Error);
                SerialWrite(ok ? "[ui] ^S notes saved\n" : "[ui] ^S notes save FAILED\n");
                continue;
            }
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::calendar::CalendarWindow())
            {
                const bool ok = duetos::apps::calendar::CalendarSave();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShowKind(ok ? "saved to CALENDAR.TXT" : "calendar save failed",
                                                       ok ? duetos::drivers::video::NotifyKind::Success
                                                          : duetos::drivers::video::NotifyKind::Error);
                SerialWrite(ok ? "[ui] ^S calendar saved\n" : "[ui] ^S calendar save FAILED\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+A — Notes select-all. Active-window-gated.
        if (ctrl && !alt && (ev.code == 'a' || ev.code == 'A'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                duetos::apps::notes::NotesSelectAll();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShow("notes: selected all");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+G — Notes goto-line. Opens an InputBox that
        // takes a 1-based line number; the callback parses
        // and calls NotesGotoLine. Active-window-gated.
        if (ctrl && !alt && (ev.code == 'g' || ev.code == 'G'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            const bool is_notes =
                active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow();
            duetos::drivers::video::CompositorUnlock();
            if (is_notes)
            {
                duetos::drivers::video::InputBoxOpen(
                    "GO TO LINE", "Line:", "1",
                    [](duetos::drivers::video::DialogResult r, const char* text, void*)
                    {
                        if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr)
                            return;
                        duetos::u32 v = 0;
                        for (duetos::u32 i = 0; text[i] != '\0'; ++i)
                        {
                            if (text[i] < '0' || text[i] > '9')
                                return;
                            v = v * 10 + static_cast<duetos::u32>(text[i] - '0');
                        }
                        duetos::drivers::video::CompositorLock();
                        duetos::apps::notes::NotesGotoLine(v);
                        duetos::drivers::video::CompositorUnlock();
                    },
                    nullptr);
                continue;
            }
        }

        // Ctrl+F — open the Notes find dialog. Active-window
        // gated; opens an InputBox pre-populated with the last
        // query (if any). InputBox callback runs NotesFindSet
        // which jumps to the first match at/after the cursor
        // and stores the query for F3 follow-ups.
        if (ctrl && !alt && (ev.code == 'f' || ev.code == 'F'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            const bool is_notes =
                active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow();
            duetos::drivers::video::CompositorUnlock();
            if (is_notes)
            {
                duetos::drivers::video::InputBoxOpen(
                    "FIND", "Search:", duetos::apps::notes::NotesFindQuery(),
                    [](duetos::drivers::video::DialogResult r, const char* text, void*)
                    {
                        if (r != duetos::drivers::video::DialogResult::Ok)
                            return;
                        duetos::drivers::video::CompositorLock();
                        const bool ok = duetos::apps::notes::NotesFindSet(text);
                        duetos::drivers::video::CompositorUnlock();
                        duetos::drivers::video::NotifyShow(ok ? "find: match" : "find: no match");
                    },
                    nullptr);
                continue;
            }
        }

        // Ctrl+H — open the Notes Find-and-Replace flow. Two
        // chained InputBoxes: first asks for the search query,
        // second for the replacement. The intermediate query
        // is stashed in a static buffer because the dialog
        // callback fires after the keyboard event loop has
        // moved on. Active-window gated, like Ctrl+F.
        if (ctrl && !alt && (ev.code == 'h' || ev.code == 'H'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            const bool is_notes =
                active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow();
            duetos::drivers::video::CompositorUnlock();
            if (is_notes)
            {
                static char pending_query[64];
                pending_query[0] = '\0';
                duetos::drivers::video::InputBoxOpen(
                    "REPLACE: FIND", "Find:", duetos::apps::notes::NotesFindQuery(),
                    [](duetos::drivers::video::DialogResult r, const char* text, void*)
                    {
                        if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr || text[0] == '\0')
                            return;
                        duetos::u32 i = 0;
                        for (; i + 1 < sizeof(pending_query) && text[i] != '\0'; ++i)
                            pending_query[i] = text[i];
                        pending_query[i] = '\0';
                        duetos::drivers::video::InputBoxOpen(
                            "REPLACE: WITH", "Replace with:", "",
                            [](duetos::drivers::video::DialogResult r2, const char* repl, void*)
                            {
                                if (r2 != duetos::drivers::video::DialogResult::Ok)
                                    return;
                                duetos::drivers::video::CompositorLock();
                                const duetos::u32 n = duetos::apps::notes::NotesReplaceAll(pending_query, repl);
                                duetos::drivers::video::CompositorUnlock();
                                if (n == 0)
                                {
                                    duetos::drivers::video::NotifyShow("replace: no matches");
                                }
                                else
                                {
                                    char msg[40];
                                    duetos::u32 o = 0;
                                    const char* lead = "replace: ";
                                    for (duetos::u32 k = 0; lead[k] != '\0' && o + 1 < sizeof(msg); ++k)
                                        msg[o++] = lead[k];
                                    // Render n in decimal.
                                    char tmp[12];
                                    duetos::u32 nn = 0;
                                    duetos::u32 v = n;
                                    if (v == 0)
                                        tmp[nn++] = '0';
                                    else
                                        while (v > 0 && nn < sizeof(tmp))
                                        {
                                            tmp[nn++] = static_cast<char>('0' + (v % 10));
                                            v /= 10;
                                        }
                                    while (nn > 0 && o + 1 < sizeof(msg))
                                        msg[o++] = tmp[--nn];
                                    const char* tail = " match(es)";
                                    for (duetos::u32 k = 0; tail[k] != '\0' && o + 1 < sizeof(msg); ++k)
                                        msg[o++] = tail[k];
                                    msg[o] = '\0';
                                    duetos::drivers::video::NotifyShow(msg);
                                }
                            },
                            nullptr);
                    },
                    nullptr);
                continue;
            }
        }

        // F3 — step to the next Notes find match. Same
        // active-window gate as Ctrl+F so the chord is
        // unbound elsewhere.
        if (!ctrl && !alt && ev.code == kKeyF3)
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                const bool ok = duetos::apps::notes::NotesFindNext();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShow(ok ? "find: next match" : "find: no match");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Alt+Left / Alt+Right — Browser back / forward. Web
        // convention. Active-window-gated so it doesn't shadow
        // any future window-manager bindings.
        if (alt && !ctrl && !shift && (ev.code == kKeyArrowLeft || ev.code == kKeyArrowRight))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::browser::BrowserWindow())
            {
                if (ev.code == kKeyArrowLeft)
                {
                    duetos::apps::browser::BrowserNavBack();
                    SerialWrite("[ui] alt+left browser back\n");
                }
                else
                {
                    duetos::apps::browser::BrowserNavForward();
                    SerialWrite("[ui] alt+right browser forward\n");
                }
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
                duetos::drivers::video::CompositorUnlock();
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+Shift+N — dump the notification history ring
        // to the framebuffer console. The toast retention
        // ring (notify.cpp) keeps the last 16 distinct
        // toasts; without a viewer they stay invisible to a
        // user who blinked while one popped. Console dump
        // is the low-friction v1 surface; a dedicated
        // Notification Center app is a future slice.
        if (ctrl && shift && !alt && (ev.code == 'n' || ev.code == 'N'))
        {
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::ConsoleWriteln("");
            duetos::drivers::video::ConsoleWriteln("--- NOTIFICATION HISTORY (newest first) ---");
            const duetos::u32 n = duetos::drivers::video::NotifyHistoryCount();
            if (n == 0)
            {
                duetos::drivers::video::ConsoleWriteln("(empty)");
            }
            else
            {
                char line[duetos::drivers::video::kNotifyMaxText + 8];
                for (duetos::u32 i = 0; i < n; ++i)
                {
                    duetos::u32 o = 0;
                    line[o++] = '[';
                    if (i >= 10)
                        line[o++] = static_cast<char>('0' + (i / 10));
                    line[o++] = static_cast<char>('0' + (i % 10));
                    line[o++] = ']';
                    line[o++] = ' ';
                    const duetos::u32 cap_left = sizeof(line) - o;
                    const duetos::u32 wrote = duetos::drivers::video::NotifyHistoryGet(i, line + o, cap_left);
                    line[o + wrote] = '\0';
                    duetos::drivers::video::ConsoleWriteln(line);
                }
            }
            duetos::drivers::video::ConsoleWriteln("--- end of history ---");
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            SerialWrite("[ui] ^+N notify history dump\n");
            continue;
        }

        // Ctrl+D — begin a DnD drag of the Files-app's
        // currently-selected row. Active-window-gated. Esc
        // cancels the drag via the modal-input / dialog
        // Esc paths.
        if (ctrl && !alt && !shift && (ev.code == 'd' || ev.code == 'D'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::files::FilesWindow())
            {
                duetos::apps::files::FilesBeginDragSelection();
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
                duetos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] ^D begin files drag\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+L — focus the Browser URL bar, web-browser
        // convention. Only fires when Browser is active so
        // it doesn't shadow other apps' single-letter keys.
        if (ctrl && !alt && !shift && (ev.code == 'l' || ev.code == 'L'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::browser::BrowserWindow())
            {
                duetos::apps::browser::BrowserFocusUrl();
                duetos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] ^L browser focus url\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+Z — undo the last Notes edit. Pops one frame
        // off the 16-entry undo ring (with 250 ms coalesce so
        // typing a word counts as one undoable step). Active-
        // window-gated.
        if (ctrl && !alt && !shift && (ev.code == 'z' || ev.code == 'Z'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                const bool ok = duetos::apps::notes::NotesUndo();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShow(ok ? "undo" : "nothing to undo");
                SerialWrite(ok ? "[ui] ^Z undo notes\n" : "[ui] ^Z notes undo (empty)\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+O — replace the Notes buffer with the contents
        // of NOTES.TXT from the FAT32 root. Active-window-gated.
        // The pre-load buffer is overwritten without
        // confirmation; matches the unsaved-by-default
        // discipline of Notes — there is no "are you sure"
        // dialog primitive in the WM yet.
        if (ctrl && !alt && (ev.code == 'o' || ev.code == 'O'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                const bool ok = duetos::apps::notes::NotesLoad();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShowKind(ok ? "loaded NOTES.TXT" : "load failed (no NOTES.TXT?)",
                                                       ok ? duetos::drivers::video::NotifyKind::Success
                                                          : duetos::drivers::video::NotifyKind::Error);
                SerialWrite(ok ? "[ui] ^O notes loaded\n" : "[ui] ^O notes load FAILED\n");
                continue;
            }
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::calendar::CalendarWindow())
            {
                const bool ok = duetos::apps::calendar::CalendarLoad();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShowKind(ok ? "loaded CALENDAR.TXT" : "calendar load failed",
                                                       ok ? duetos::drivers::video::NotifyKind::Success
                                                          : duetos::drivers::video::NotifyKind::Error);
                SerialWrite(ok ? "[ui] ^O calendar loaded\n" : "[ui] ^O calendar load FAILED\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // Ctrl+N — start a fresh blank Notes document (the
        // everyday "new file"). !shift so it doesn't collide
        // with Ctrl+Shift+N (notification-ring dump). Undoable
        // inside Notes, so no confirmation dialog is needed.
        if (ctrl && !alt && !shift && (ev.code == 'n' || ev.code == 'N'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::notes::NotesWindow())
            {
                duetos::apps::notes::NotesNew();
                duetos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] ^N notes new document\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // F1 (no modifiers) dumps the user-facing keyboard +
        // shortcut reference into the desktop console. Tested
        // BEFORE the Ctrl+Alt+F1 console-flip handler — bare
        // F1 must not also flip consoles, and the modifier
        // gate makes the two paths mutually exclusive.
        if (!ctrl && !alt && ev.code == kKeyF1)
        {
            duetos::drivers::video::CompositorLock();
            // Raise the windowed Help reference; new users see
            // a persistent panel they can leave open. Falls
            // through to PrintShortcutHelp so the framebuffer
            // console scrollback also carries the same text.
            const duetos::drivers::video::WindowHandle hh =
                duetos::drivers::video::ThemeRoleWindow(duetos::drivers::video::ThemeRole::Help);
            if (hh != duetos::drivers::video::kWindowInvalid)
            {
                duetos::drivers::video::WindowRaise(hh);
            }
            duetos::core::PrintShortcutHelp();
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            SerialWrite("[ui] F1 help\n");
            continue;
        }

        // Ctrl+Alt+F1 / F2 flip the render target between
        // the shell and klog consoles. Same screen origin,
        // so the switch is in-place; each has its own
        // scrollback. Works in both desktop and TTY modes.
        if (ctrl && alt && (ev.code == kKeyF1 || ev.code == kKeyF2))
        {
            duetos::drivers::video::CompositorLock();
            if (ev.code == kKeyF1)
            {
                duetos::drivers::video::ConsoleSelectShell();
                SerialWrite("[ui] tty -> shell\n");
            }
            else
            {
                duetos::drivers::video::ConsoleSelectKlog();
                SerialWrite("[ui] tty -> klog\n");
            }
            const bool is_tty = (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty);
            if (is_tty)
            {
                duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
            }
            else
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
            }
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Ctrl+Alt+C — toggle the framebuffer console region's
        // visibility. The console region is hidden by default
        // once the windowed Terminal app is up (the Terminal
        // shows the same shell content through the console
        // mirror), so this shortcut is the on-demand "show me
        // the on-screen console" escape hatch — useful when
        // the compositor is wedged or the Terminal window
        // has been closed. Slice 3a of the ToaruOS port.
        if (ctrl && alt && (ev.code == 'c' || ev.code == 'C'))
        {
            duetos::drivers::video::CompositorLock();
            const bool now_visible = !duetos::drivers::video::ConsoleIsPaintEnabled();
            duetos::drivers::video::ConsoleSetPaintEnabled(now_visible);
            SerialWrite(now_visible ? "[ui] console -> visible\n" : "[ui] console -> hidden\n");
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Ctrl+Alt+T flips between desktop and TTY mode. In
        // TTY mode the console fills the framebuffer with a
        // Linux-VT feel (black bg, console top-left); in
        // desktop mode the console docks back into the
        // windowed layout. The underlying char buffer is
        // shared, so scrollback survives the flip.
        if (ctrl && alt && (ev.code == 't' || ev.code == 'T'))
        {
            duetos::drivers::video::CompositorLock();
            const bool to_tty =
                (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Desktop);
            if (to_tty)
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::SetDisplayMode(duetos::drivers::video::DisplayMode::Tty);
                duetos::drivers::video::ConsoleSetOrigin(16, 16);
                duetos::drivers::video::ConsoleSetColours(duetos::drivers::video::ThemeCurrent().console_fg,
                                                          0x00000000);
                duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
            }
            else
            {
                duetos::drivers::video::SetDisplayMode(duetos::drivers::video::DisplayMode::Desktop);
                duetos::drivers::video::ConsoleSetOrigin(16, 400);
                duetos::drivers::video::ConsoleSetColours(duetos::drivers::video::ThemeCurrent().console_fg,
                                                          duetos::drivers::video::ThemeCurrent().console_bg);
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
            }
            duetos::drivers::video::CompositorUnlock();
            SerialWrite(to_tty ? "[ui] enter TTY mode\n" : "[ui] enter DESKTOP mode\n");
            continue;
        }

        // Ctrl+Alt+Arrow snaps the focused window to a half of
        // the work area. The Win key isn't exposed by the PS/2
        // path so Ctrl+Alt is the surrogate modifier (matches
        // the rest of this handler's chords).
        //   Left  → left half       (Win+Left analogue)
        //   Right → right half      (Win+Right analogue)
        //   Up    → top half        (Win+Up analogue)
        //   Down  → bottom half     (Win+Down analogue)
        // The active window is the snap target; if there is no
        // active window the chord is a silent no-op. Recompose
        // after the snap so the new geometry paints.
        if (ctrl && alt &&
            (ev.code == duetos::drivers::input::kKeyArrowLeft || ev.code == duetos::drivers::input::kKeyArrowRight ||
             ev.code == duetos::drivers::input::kKeyArrowUp || ev.code == duetos::drivers::input::kKeyArrowDown))
        {
            const duetos::drivers::video::WindowHandle active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid)
            {
                duetos::drivers::video::CompositorLock();
                switch (ev.code)
                {
                case duetos::drivers::input::kKeyArrowLeft:
                    duetos::drivers::video::WindowSnapLeft(active);
                    break;
                case duetos::drivers::input::kKeyArrowRight:
                    duetos::drivers::video::WindowSnapRight(active);
                    break;
                case duetos::drivers::input::kKeyArrowUp:
                    duetos::drivers::video::WindowSnapTop(active);
                    break;
                case duetos::drivers::input::kKeyArrowDown:
                    duetos::drivers::video::WindowSnapBottom(active);
                    break;
                default:
                    break;
                }
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
                duetos::drivers::video::CompositorUnlock();
            }
            continue;
        }

        // Ctrl+Alt+B toggles the taskbar dock edge between
        // Bottom (default) and Top. Re-anchor + recompose
        // so the new placement appears immediately. Useful
        // for users who want the strip out of the way of
        // an app pinned to the bottom of the desktop.
        if (ctrl && alt && (ev.code == 'b' || ev.code == 'B'))
        {
            duetos::drivers::video::CompositorLock();
            const auto cur = duetos::drivers::video::TaskbarGetDock();
            duetos::drivers::video::TaskbarSetDock(cur == duetos::drivers::video::TaskbarDock::Bottom
                                                       ? duetos::drivers::video::TaskbarDock::Top
                                                       : duetos::drivers::video::TaskbarDock::Bottom);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            SerialWrite("[ui] taskbar dock -> ");
            SerialWrite(duetos::drivers::video::TaskbarGetDock() == duetos::drivers::video::TaskbarDock::Top
                            ? "top\n"
                            : "bottom\n");
            continue;
        }
        // Ctrl+Alt+L locks / unlocks the taskbar. While unlocked
        // the user can drag the strip to either horizontal edge
        // — drop snaps to whichever half of the screen the
        // cursor was released in. Default: locked.
        if (ctrl && alt && (ev.code == 'l' || ev.code == 'L'))
        {
            duetos::drivers::video::TaskbarSetLocked(!duetos::drivers::video::TaskbarIsLocked());
            SerialWrite("[ui] taskbar -> ");
            SerialWrite(duetos::drivers::video::TaskbarIsLocked() ? "locked\n" : "unlocked\n");
            continue;
        }
        // Ctrl+Alt+K — lock the screen. Re-opens the GUI login
        // gate; the next successful login restores the desktop.
        // Bound separately from Ctrl+Alt+L (taskbar drag-lock)
        // so muscle-memory for the existing chord stays intact.
        if (ctrl && alt && (ev.code == 'k' || ev.code == 'K'))
        {
            // Capture session state BEFORE the compositor
            // lock — SessionRestoreSave issues a FAT32 write
            // and we don't want to hold the lock across that
            // I/O. State is read via WindowGetBounds, which
            // takes its own short-lived lock.
            duetos::core::SessionRestoreSave();
            duetos::drivers::video::CompositorLock();
            duetos::core::AuthLogout();
            duetos::core::LoginStart(duetos::core::LoginMode::Gui);
            duetos::drivers::video::CompositorUnlock();
            SerialWrite("[ui] screen locked\n");
            continue;
        }
        // Ctrl+Alt+M — toggle the magnifier accessibility inset.
        // 200x150 px viewport at the top-right showing 2x zoom
        // around the cursor. Drops to bottom-right when the
        // cursor is in the top-right quadrant so the inset
        // never occludes its own source region.
        if (ctrl && alt && (ev.code == 'm' || ev.code == 'M'))
        {
            duetos::drivers::video::CompositorLock();
            const bool on = duetos::drivers::video::MagnifierToggle();
            duetos::drivers::video::NotifyShow(on ? "magnifier on" : "magnifier off");
            duetos::drivers::video::CompositorUnlock();
            SerialWrite(on ? "[ui] magnifier on\n" : "[ui] magnifier off\n");
            continue;
        }
        // Ctrl+Alt+P captures the framebuffer to the next
        // SHOTNNNN.BMP slot on the FAT32 root volume. Holds
        // the compositor lock across the capture so a draw
        // doesn't race the row copy. Toast surfaces the
        // outcome; failure modes (no FAT32, no FB, disk
        // full) all log a one-line reason to COM1.
        if (ctrl && alt && (ev.code == 'p' || ev.code == 'P'))
        {
            duetos::drivers::video::CompositorLock();
            const bool ok = duetos::apps::screenshot::ScreenshotCapture();
            duetos::drivers::video::CompositorUnlock();
            duetos::drivers::video::NotifyShowKind(ok ? "screenshot saved" : "screenshot failed",
                                                   ok ? duetos::drivers::video::NotifyKind::Success
                                                      : duetos::drivers::video::NotifyKind::Error);
            SerialWrite(ok ? "[ui] ^Alt+P screenshot saved\n" : "[ui] ^Alt+P screenshot FAILED\n");
            continue;
        }
        // Ctrl+Alt+T captures the framebuffer to the next
        // SHOTNNNN.TGA slot. Same pixel layout as the BMP path
        // (BGRA8888, top-down) — only the 18-byte header
        // differs. The shared filename counter means BMP and
        // TGA captures interleave with strictly-increasing
        // numbers.
        if (ctrl && alt && (ev.code == 't' || ev.code == 'T'))
        {
            duetos::drivers::video::CompositorLock();
            const bool ok_tga = duetos::apps::screenshot::ScreenshotCaptureTga();
            duetos::drivers::video::CompositorUnlock();
            duetos::drivers::video::NotifyShowKind(ok_tga ? "screenshot (TGA) saved" : "screenshot (TGA) failed",
                                                   ok_tga ? duetos::drivers::video::NotifyKind::Success
                                                          : duetos::drivers::video::NotifyKind::Error);
            SerialWrite(ok_tga ? "[ui] ^Alt+T screenshot (TGA) saved\n" : "[ui] ^Alt+T screenshot (TGA) FAILED\n");
            continue;
        }
        // Ctrl+Alt+Y cycles the desktop theme. Classic (teal)
        // -> Slate10 (Win10 x Unreal Slate hybrid) -> Amber
        // (mono CRT tribute) -> Duet (redesigned palette,
        // teal+amber dual accent) -> wrap. Re-chromes every
        // themed window + the taskbar + console + cursor
        // backing, then recomposes so the new palette appears
        // on screen in one flip.
        if (ctrl && alt && (ev.code == 'y' || ev.code == 'Y'))
        {
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::ThemeCycle();
            duetos::drivers::video::ThemeApplyToAll();
            duetos::drivers::video::NotifyShow(
                duetos::drivers::video::ThemeIdName(duetos::drivers::video::ThemeCurrentId()));
            const bool is_tty = (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty);
            if (is_tty)
            {
                duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
            }
            else
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
            }
            duetos::drivers::video::CompositorUnlock();
            SerialWrite("[ui] theme -> ");
            SerialWrite(duetos::drivers::video::ThemeIdName(duetos::drivers::video::ThemeCurrentId()));
            SerialWrite("\n");
            continue;
        }
        // Ctrl+Alt+, / Ctrl+Alt+. — adjust active window
        // opacity in 32-step increments. Lower bound 64
        // (anything below would render the chrome
        // unreadable); upper bound 255 (fully opaque).
        if (ctrl && alt && (ev.code == ',' || ev.code == '.'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid)
            {
                const duetos::u8 cur = duetos::drivers::video::WindowGetOpacity(active);
                duetos::u8 next = cur;
                constexpr duetos::u8 kStep = 32;
                constexpr duetos::u8 kMin = 64;
                if (ev.code == ',')
                {
                    next = (cur > kMin + kStep) ? static_cast<duetos::u8>(cur - kStep) : kMin;
                }
                else
                {
                    next = (cur > 0xFFu - kStep) ? 0xFFu : static_cast<duetos::u8>(cur + kStep);
                }
                duetos::drivers::video::WindowSetOpacity(active, next);
                SerialWrite("[ui] opacity=");
                SerialWriteHex(next);
                SerialWrite("\n");
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }
        // Ctrl+Alt+digit picks a specific theme directly —
        // saves repeat presses of Ctrl+Alt+Y when there are
        // 9 themes registered. Index 1..9 maps onto
        // ThemeId 0..8 so the digit row reads as "press 4
        // for the 4th theme" matching `theme list`'s
        // column ordering.
        if (ctrl && alt && ev.code >= '1' && ev.code <= '9')
        {
            const auto idx = static_cast<duetos::u32>(ev.code - '1');
            if (idx < static_cast<duetos::u32>(duetos::drivers::video::ThemeId::kCount))
            {
                duetos::drivers::video::CompositorLock();
                duetos::drivers::video::ThemeSet(static_cast<duetos::drivers::video::ThemeId>(idx));
                duetos::drivers::video::ThemeApplyToAll();
                duetos::drivers::video::NotifyShow(
                    duetos::drivers::video::ThemeIdName(duetos::drivers::video::ThemeCurrentId()));
                const bool is_tty =
                    (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty);
                if (is_tty)
                {
                    duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
                }
                else
                {
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                    duetos::drivers::video::CursorShow();
                }
                duetos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] theme set -> ");
                SerialWrite(duetos::drivers::video::ThemeIdName(duetos::drivers::video::ThemeCurrentId()));
                SerialWrite("\n");
                continue;
            }
        }

        // Window-manager shortcuts take priority over any
        // text-input path. Alt+Tab cycles active window;
        // Alt+F4 closes it.
        if (alt && ev.code == kKeyTab)
        {
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::WindowCycleActive();
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            SerialWrite("[ui] alt-tab\n");
            continue;
        }
        // Ctrl+Alt+Shift+Arrow grows / shrinks the active
        // window from its bottom-right corner in 32-px steps.
        // Tested BEFORE the bare Ctrl+Alt+Arrow snap handler
        // because the modifier mask is more specific.
        if (ctrl && alt && shift &&
            (ev.code == duetos::drivers::input::kKeyArrowLeft || ev.code == duetos::drivers::input::kKeyArrowRight ||
             ev.code == duetos::drivers::input::kKeyArrowUp || ev.code == duetos::drivers::input::kKeyArrowDown))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid)
            {
                duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
                if (duetos::drivers::video::WindowGetBounds(active, &wx, &wy, &ww, &wh))
                {
                    constexpr duetos::u32 kStep = 32;
                    constexpr duetos::u32 kMin = 96; // floor — anything smaller is unusable
                    duetos::u32 new_w = ww;
                    duetos::u32 new_h = wh;
                    if (ev.code == duetos::drivers::input::kKeyArrowRight)
                    {
                        new_w = ww + kStep;
                    }
                    else if (ev.code == duetos::drivers::input::kKeyArrowLeft)
                    {
                        new_w = (ww > kMin + kStep) ? ww - kStep : kMin;
                    }
                    else if (ev.code == duetos::drivers::input::kKeyArrowDown)
                    {
                        new_h = wh + kStep;
                    }
                    else
                    {
                        new_h = (wh > kMin + kStep) ? wh - kStep : kMin;
                    }
                    duetos::drivers::video::WindowResizeTo(active, new_w, new_h);
                    SerialWrite("[ui] resize w=");
                    SerialWriteHex(new_w);
                    SerialWrite(" h=");
                    SerialWriteHex(new_h);
                    SerialWrite("\n");
                }
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }
        // Ctrl+Alt+Arrow window snap shortcuts. Mirror Win10's
        // Win+Arrow tiling: Left/Right snap to halves, Up
        // maximizes, Down restores (or minimizes if not max).
        // Ctrl+Alt is the standard "system" modifier in this
        // session — Win key isn't tracked separately.
        if (ctrl && alt &&
            (ev.code == duetos::drivers::input::kKeyArrowLeft || ev.code == duetos::drivers::input::kKeyArrowRight ||
             ev.code == duetos::drivers::input::kKeyArrowUp || ev.code == duetos::drivers::input::kKeyArrowDown))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid)
            {
                if (ev.code == duetos::drivers::input::kKeyArrowLeft)
                {
                    duetos::drivers::video::WindowSnapLeft(active);
                    SerialWrite("[ui] snap-left\n");
                }
                else if (ev.code == duetos::drivers::input::kKeyArrowRight)
                {
                    duetos::drivers::video::WindowSnapRight(active);
                    SerialWrite("[ui] snap-right\n");
                }
                else if (ev.code == duetos::drivers::input::kKeyArrowUp)
                {
                    duetos::drivers::video::WindowMaximize(active);
                    SerialWrite("[ui] maximize\n");
                }
                else
                {
                    if (duetos::drivers::video::WindowIsMaximized(active))
                    {
                        duetos::drivers::video::WindowRestore(active);
                        SerialWrite("[ui] restore\n");
                    }
                    else
                    {
                        duetos::drivers::video::WindowMinimize(active);
                        SerialWrite("[ui] minimize\n");
                    }
                }
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }
        if (alt && ev.code == kKeyF4)
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid)
            {
                // Notes dirty-close — open MessageBox for
                // "Discard unsaved changes?". Callback closes
                // the window on OK; Cancel keeps it open.
                const bool is_notes = (active == duetos::apps::notes::NotesWindow());
                const bool notes_dirty = is_notes && duetos::apps::notes::NotesIsDirty();
                if (notes_dirty)
                {
                    static duetos::drivers::video::WindowHandle s_close_target = duetos::drivers::video::kWindowInvalid;
                    s_close_target = active;
                    duetos::drivers::video::MessageBoxOpen(
                        "UNSAVED CHANGES",
                        "The Notes buffer has unsaved edits.\n"
                        "OK = discard and close. Cancel = keep editing.",
                        [](duetos::drivers::video::DialogResult r, const char* /*text*/, void* /*user*/)
                        {
                            if (r == duetos::drivers::video::DialogResult::Ok &&
                                s_close_target != duetos::drivers::video::kWindowInvalid)
                            {
                                duetos::drivers::video::WindowClose(s_close_target);
                                SerialWrite("[ui] dirty-close confirmed window=");
                                SerialWriteHex(s_close_target);
                                SerialWrite("\n");
                            }
                            else
                            {
                                SerialWrite("[ui] dirty-close cancelled\n");
                            }
                            s_close_target = duetos::drivers::video::kWindowInvalid;
                        },
                        nullptr);
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                    duetos::drivers::video::CursorShow();
                    duetos::drivers::video::CompositorUnlock();
                    continue;
                }
                duetos::drivers::video::WindowClose(active);
                SerialWrite("[ui] alt-f4 close window=");
                SerialWriteHex(active);
                SerialWrite("\n");
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // PE-routed keystrokes. When the active window belongs
        // to a ring-3 process (owner_pid > 0), post WM_KEYDOWN
        // + WM_CHAR to its message queue and skip both the
        // kernel-app routing and shell paths. PE pumps blocked
        // on GetMessage wake on the next scheduler tick and
        // dequeue the message. Modifiers already handled above
        // (Alt+Tab / Alt+F4 / Ctrl+Alt+*) take precedence and
        // never reach this block because they `continue` out.
        {
            duetos::drivers::video::CompositorLock();
            const auto active_pe = duetos::drivers::video::WindowActive();
            const duetos::u64 pe_pid = (active_pe != duetos::drivers::video::kWindowInvalid)
                                           ? duetos::drivers::video::WindowOwnerPid(active_pe)
                                           : 0;
            if (pe_pid > 0)
            {
                // Alt held = WM_SYSKEYDOWN (0x0104) /
                // WM_SYSCHAR (0x0106); otherwise
                // WM_KEYDOWN (0x0100) / WM_CHAR (0x0102).
                // lParam layout: bit 29 set iff Alt (context
                // code) — mirrors Win32.
                constexpr duetos::u32 kWmKeyDown = 0x0100;
                constexpr duetos::u32 kWmChar = 0x0102;
                constexpr duetos::u32 kWmSysKeyDown = 0x0104;
                constexpr duetos::u32 kWmSysChar = 0x0106;
                const bool alt_held = (ev.modifiers & kKeyModAlt) != 0;
                const duetos::u64 lp_base = 1; // repeat count = 1
                const duetos::u64 lp = alt_held ? (lp_base | (1ull << 29)) : lp_base;
                const duetos::u32 keydown_msg = alt_held ? kWmSysKeyDown : kWmKeyDown;
                const duetos::u32 char_msg = alt_held ? kWmSysChar : kWmChar;
                duetos::drivers::video::WindowPostMessage(active_pe, keydown_msg, ev.code, lp);
                if (ev.code >= 0x20 && ev.code <= 0x7E)
                {
                    duetos::drivers::video::WindowPostMessage(active_pe, char_msg, ev.code, lp);
                }
                else if (ev.code == kKeyEnter)
                {
                    duetos::drivers::video::WindowPostMessage(active_pe, char_msg, '\r', lp);
                }
                else if (ev.code == kKeyBackspace)
                {
                    duetos::drivers::video::WindowPostMessage(active_pe, char_msg, 0x08, lp);
                }
                duetos::drivers::video::CompositorUnlock();
                // Wake any GetMessage blocker — broadcasts
                // to every process; each re-checks its own
                // per-window ring.
                duetos::drivers::video::WindowMsgWakeAll();
                // No screen repaint required — PEs own their
                // display list and update on next compose when
                // their pump calls InvalidateRect / GDI calls
                // directly. A future slice ties WM_PAINT to
                // compose.
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
        }

        // App-routed keystrokes. When the active window is an
        // app that registered a typed-input surface (Notes,
        // Calculator), feed it here and skip the shell path
        // entirely. Compositor lock brackets the feed so it
        // serialises with the ui-ticker's draw.
        {
            bool app_consumed = false;
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid)
            {
                // Non-ASCII navigation keys — routed per app.
                // Files takes Up/Down for selection; Notes takes
                // the full arrow cluster plus Home/End/Delete
                // for its cursor.
                if (active == duetos::apps::files::FilesWindow() &&
                    (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown))
                {
                    app_consumed = duetos::apps::files::FilesFeedArrow(ev.code == kKeyArrowUp);
                }
                else if (active == duetos::apps::files::FilesWindow() &&
                         (ev.code == kKeyHome || ev.code == kKeyEnd || ev.code == kKeyPageUp ||
                          ev.code == kKeyPageDown))
                {
                    app_consumed = duetos::apps::files::FilesFeedListKey(static_cast<duetos::u16>(ev.code));
                }
                else if (active == duetos::apps::imageview::ImageViewWindow() &&
                         (ev.code == kKeyArrowLeft || ev.code == kKeyArrowRight))
                {
                    app_consumed = duetos::apps::imageview::ImageViewFeedArrow(ev.code == kKeyArrowLeft);
                }
                else if (active == duetos::apps::browser::BrowserWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown))
                {
                    app_consumed = duetos::apps::browser::BrowserFeedArrow(ev.code);
                }
                else if (active == duetos::apps::calendar::CalendarWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyArrowLeft ||
                          ev.code == kKeyArrowRight || ev.code == kKeyPageUp || ev.code == kKeyPageDown ||
                          ev.code == kKeyDelete))
                {
                    app_consumed =
                        duetos::apps::calendar::CalendarFeedArrow(static_cast<duetos::u16>(ev.code), ev.modifiers);
                }
                else if (active == duetos::apps::notify_center::NotifyCenterWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyPageUp ||
                          ev.code == kKeyPageDown || ev.code == kKeyHome || ev.code == kKeyEnd ||
                          ev.code == kKeyDelete))
                {
                    app_consumed =
                        duetos::apps::notify_center::NotifyCenterFeedArrow(static_cast<duetos::u16>(ev.code));
                }
                else if (active == duetos::apps::hexview::HexViewWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyArrowLeft ||
                          ev.code == kKeyArrowRight || ev.code == kKeyPageUp || ev.code == kKeyPageDown ||
                          ev.code == kKeyHome || ev.code == kKeyEnd))
                {
                    app_consumed = duetos::apps::hexview::HexViewFeedArrow(static_cast<duetos::u16>(ev.code));
                }
                else if (active == duetos::apps::charmap::CharMapWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyArrowLeft ||
                          ev.code == kKeyArrowRight || ev.code == kKeyPageUp || ev.code == kKeyPageDown ||
                          ev.code == kKeyHome || ev.code == kKeyEnd || ev.code == kKeyDelete))
                {
                    app_consumed = duetos::apps::charmap::CharMapFeedArrow(static_cast<duetos::u16>(ev.code));
                }
                else if (active == duetos::apps::terminal::TerminalWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyArrowLeft ||
                          ev.code == kKeyArrowRight))
                {
                    app_consumed = duetos::apps::terminal::TerminalFeedArrow(static_cast<duetos::u16>(ev.code));
                }
                else if (active == duetos::apps::notes::NotesWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyArrowLeft ||
                          ev.code == kKeyArrowRight || ev.code == kKeyHome || ev.code == kKeyEnd ||
                          ev.code == kKeyDelete || ev.code == kKeyPageUp || ev.code == kKeyPageDown))
                {
                    app_consumed = duetos::apps::notes::NotesFeedKey(ev.code, ev.modifiers);
                }
                else if (active == duetos::apps::taskman::TaskmanWindow() &&
                         (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyHome ||
                          ev.code == kKeyEnd || ev.code == kKeyPageUp || ev.code == kKeyPageDown ||
                          ev.code == kKeyDelete))
                {
                    app_consumed = duetos::apps::taskman::TaskmanFeedKey(static_cast<duetos::u16>(ev.code));
                }
                else
                {
                    char c = 0;
                    if (ev.code == kKeyEnter)
                        c = '\n';
                    else if (ev.code == kKeyBackspace)
                        c = 0x08;
                    else if (ev.code == kKeyTab && !alt)
                        c = '\t';
                    else if (ev.code >= 0x20 && ev.code <= 0x7E)
                        c = static_cast<char>(ev.code);
                    if (c != 0)
                    {
                        if (active == duetos::apps::notes::NotesWindow())
                        {
                            duetos::apps::notes::NotesFeedChar(c);
                            app_consumed = true;
                        }
                        else if (active == duetos::apps::calculator::CalculatorWindow())
                        {
                            app_consumed = duetos::apps::calculator::CalculatorFeedChar(c);
                        }
                        else if (active == duetos::apps::files::FilesWindow())
                        {
                            app_consumed = duetos::apps::files::FilesFeedChar(c);
                        }
                        else if (active == duetos::apps::gfxdemo::GfxDemoWindow())
                        {
                            app_consumed = duetos::apps::gfxdemo::GfxDemoFeedChar(c);
                        }
                        else if (active == duetos::apps::settings::SettingsWindow())
                        {
                            app_consumed = duetos::apps::settings::SettingsFeedChar(c);
                        }
                        else if (active == duetos::apps::imageview::ImageViewWindow())
                        {
                            app_consumed = duetos::apps::imageview::ImageViewFeedChar(c);
                        }
                        else if (active == duetos::apps::browser::BrowserWindow())
                        {
                            app_consumed = duetos::apps::browser::BrowserFeedChar(c);
                        }
                        else if (active == duetos::apps::calendar::CalendarWindow())
                        {
                            app_consumed = duetos::apps::calendar::CalendarFeedChar(c);
                        }
                        else if (active == duetos::apps::clock::ClockWindow())
                        {
                            app_consumed = duetos::apps::clock::ClockFeedChar(c);
                        }
                        else if (active == duetos::apps::notify_center::NotifyCenterWindow())
                        {
                            app_consumed = duetos::apps::notify_center::NotifyCenterFeedChar(c);
                        }
                        else if (active == duetos::apps::hexview::HexViewWindow())
                        {
                            app_consumed = duetos::apps::hexview::HexViewFeedChar(c);
                        }
                        else if (active == duetos::apps::charmap::CharMapWindow())
                        {
                            app_consumed = duetos::apps::charmap::CharMapFeedChar(c);
                        }
                        else if (active == duetos::apps::terminal::TerminalWindow())
                        {
                            app_consumed = duetos::apps::terminal::TerminalFeedChar(c);
                        }
                        else if (active == duetos::apps::sysmon::SysmonWindow())
                        {
                            app_consumed = duetos::apps::sysmon::SysmonFeedChar(c);
                        }
                        else if (active == duetos::apps::dbg::DbgWindow())
                        {
                            app_consumed = duetos::apps::dbg::DbgFeedChar(c);
                        }
                        else if (active == duetos::apps::taskman::TaskmanWindow())
                        {
                            app_consumed = duetos::apps::taskman::TaskmanFeedChar(c);
                        }
                        else if (active == duetos::apps::help::HelpWindow())
                        {
                            app_consumed = duetos::apps::help::HelpFeedChar(c);
                        }
                    }
                }
            }
            duetos::drivers::video::CompositorUnlock();
            if (app_consumed)
            {
                dirty = true;
                // Fall through to the `if (dirty)` recompose
                // below by skipping the shell-routing branches.
                goto app_key_recompose;
            }
        }

        // Feed the shell instead of writing to the console
        // directly. ShellFeedChar echoes the char; Backspace
        // rubs out the last input; Enter submits + dispatches.
        // Mirror input chars to COM1 so a headless session is
        // still diagnosable end-to-end.
        //
        // In parallel, push the cooked byte into the
        // registered ring-3 stdin focus (if any) so userland
        // binaries calling SYS_STDIN_READ see real keystrokes.
        // The kernel-shell + ring-3-stdin paths are
        // independent; a userland program that reads stdin
        // doesn't suppress the kernel-shell line editor (and
        // vice versa). v0 policy is intentionally permissive
        // — the userland shell is a peer of the kernel shell,
        // not a replacement. ProcessFeedStdinFocusChar reads
        // the focus pointer + does the push under a single
        // IRQ-off section so the reaper can't free the
        // process between the two operations.
        if (ev.code == kKeyBackspace)
        {
            duetos::core::ShellBackspace();
            duetos::core::ProcessFeedStdinFocusChar('\x7F');
            dirty = true;
        }
        else if (ev.code == kKeyEnter)
        {
            duetos::core::ShellSubmit();
            duetos::core::ProcessFeedStdinFocusChar('\n');
            dirty = true;
        }
        else if (ev.code == kKeyArrowUp)
        {
            duetos::core::ShellHistoryPrev();
            dirty = true;
        }
        else if (ev.code == kKeyArrowDown)
        {
            duetos::core::ShellHistoryNext();
            dirty = true;
        }
        else if (ev.code == kKeyTab)
        {
            duetos::core::ShellTabComplete();
            dirty = true;
        }
        else if (ev.code >= 0x20 && ev.code <= 0x7E)
        {
            const char ch = static_cast<char>(ev.code);
            duetos::core::ShellFeedChar(ch);
            duetos::core::ProcessFeedStdinFocusChar(ch);
            const char buf[2] = {ch, '\0'};
            SerialWrite(buf);
            dirty = true;
        }
    app_key_recompose:
        if (dirty)
        {
            duetos::drivers::video::CompositorLock();
            const bool is_tty = (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty);
            if (is_tty)
            {
                duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
            }
            else
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
            }
            duetos::drivers::video::CompositorUnlock();
        }
    }
}
} // namespace duetos::core
