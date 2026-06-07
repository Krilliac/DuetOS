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
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "core/menu_dispatch.h"
#include "core/session_restore.h"
#include "diag/fix_journal_persist.h"
#include "drivers/input/hid_keyboard.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/calendar.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/desktop_icons.h"
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
#include "drivers/video/volume_flyout.h"
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
#include "subsystems/audio/audio_backend.h"
#include "time/tick.h"
#include "time/timekeeper.h"
#include "subsystems/win32/window_syscall.h"

namespace duetos::core
{

namespace
{

// Scheduler self-test shared state, worker-only. Moved with
// SchedDemoWorkerTask out of kernel_main; must outlive each
// spawn so it keeps static storage duration.
duetos::sched::Mutex s_demo_mutex{};
duetos::u64 s_shared_counter = 0;

// Forward decl — defined further down in a sibling anonymous
// namespace. KbdReaderTask above MouseReaderTask uses it to
// implement the Ctrl+Esc shortcut.
void StartMenuToggle();

} // namespace

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
        duetos::diag::FixJournalPersistPeriodicTick();
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
    // Opt out of the hung-task detector — this task legitimately
    // sits in `TaskState::Blocked` inside `Ps2KeyboardReadEvent` for
    // arbitrarily long when no keys are pressed (the QEMU smoke runs
    // through a 60s boot with no input at all). The detector would
    // otherwise correctly report it as "blocked > 30s" every minute.
    duetos::sched::SchedExemptCurrentFromHungTask();
    // Sample at each compose call so Ctrl+Alt+Y (theme cycle)
    // takes effect on the very next repaint — don't cache.
    auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };

    // Software auto-repeat suppression — VirtualBox ONLY. A held key
    // auto-repeats; the ps2kbd typematic-rate set (0xF3) disables this
    // on real hardware, QEMU, KVM, and VMware, but VirtualBox ACKs that
    // command and ignores it, driving repeat from the HOST as make/BREAK
    // PAIRS — so a guard that keys off "a press with no intervening
    // release" can't catch it, and the press-to-press interval
    // (~180-330 ms observed) overlaps deliberate double-letter typing,
    // so a fixed time window can't either. The reliable discriminator is
    // the release->re-press GAP: VBox's auto-repeat re-presses the same
    // key only ~50-80 ms after its own release, which a human physically
    // cannot do (a deliberate same-key re-type — "ll", "ee" — is >120 ms
    // apart). So under VBox: when a key is re-pressed within kRepeatGapNs
    // of its OWN release, treat it as the start of an auto-repeat RUN and
    // suppress every further press of that key until a different key
    // arrives or the key goes idle for kRunBreakNs. Result: tap = one
    // char, held key = one char, genuine double-letters preserved.
    //
    // Why this is gated to VBox (F-002): the 50-80 ms release->re-press
    // window the heuristic keys off ALSO catches fast LEGITIMATE input —
    // an automation/test sendkey burst, or a real fast typist (and QEMU
    // sendkey delivers make+break instantaneously, so two back-to-back
    // commands look like a sub-ms re-press). Applying the suppressor
    // universally dropped genuine keys on every non-VBox host: typing
    // "peek" fast came out "PEK", and a 6-press start-menu nav landed 3
    // rows short, opening the wrong app. Since the 0xF3 typematic command
    // genuinely disables host auto-repeat everywhere EXCEPT VBox, the
    // suppressor is only ever needed under VBox — everywhere else it can
    // only do harm. Gate it on the cached hypervisor kind.
    //
    // The clock is time::MonotonicNs() (HPET / clocksource-backed real
    // time), NOT time::TickCount() (scheduler ticks): the scheduler
    // tick lags real time under load / TCG, so a 158 ms human gap can
    // register as <10 ticks and be wrongly eaten. MonotonicNs tracks
    // wall time on QEMU and VBox alike (falls back to TSC/PIT when HPET
    // is absent, as it is under VirtualBox).
    const bool vbox_auto_repeat = duetos::arch::HypervisorInfoGet().kind == duetos::arch::HypervisorKind::VirtualBox;
    constexpr duetos::u64 kRepeatGapNs = 100'000'000ull; // 100 ms release->re-press
    constexpr duetos::u64 kRunBreakNs = 450'000'000ull;  // 450 ms idle ends a run
    duetos::u16 last_press_code = kKeyNone;              // last accepted (delivered) press
    duetos::u16 last_release_code = kKeyNone;            // most recent release's key
    duetos::u64 last_release_ns = 0;                     // MonotonicNs of that release
    duetos::u16 repeat_run_code = kKeyNone;              // key whose auto-repeat run we're eating
    duetos::u64 repeat_run_ns = 0;                       // MonotonicNs of the last suppressed repeat
    for (;;)
    {
        const KeyEvent ev = Ps2KeyboardReadEvent();
        // Per-event diagnostic (DEBUG-gated): each line is one event
        // returned by the keyboard layer. A single physical keypress
        // that emits several "key press" lines points at hardware/
        // firmware typematic auto-repeat (see the keyboard init's
        // typematic-rate set). Greppable as `kbd-ev`.
        KLOG_DEBUG_V("input/kbd", ev.is_release ? "kbd-ev release code" : "kbd-ev press code",
                     static_cast<u64>(ev.code));
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
        // Record a real key's release for the auto-repeat run detector
        // below (it keys off the release->re-press gap). Modifier-only
        // transitions (kKeyNone) carry no VK and are skipped.
        if (ev.is_release && ev.code != kKeyNone)
        {
            last_release_code = ev.code;
            last_release_ns = duetos::time::MonotonicNs();
        }
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

        // Software auto-repeat suppression — VirtualBox ONLY (see the
        // declaration block above for the full rationale / why hardware +
        // time-window approaches don't work under VirtualBox, and why
        // running this anywhere else drops genuine fast keystrokes, F-002).
        // On QEMU / KVM / VMware / real HW the 0xF3 typematic command
        // already disables host auto-repeat, so every press here is real.
        if (vbox_auto_repeat)
        {
            const duetos::u64 now_ns = duetos::time::MonotonicNs();
            // Already eating an auto-repeat run for this key: keep
            // eating until it changes key or goes idle.
            if (repeat_run_code != kKeyNone && ev.code == repeat_run_code && (now_ns - repeat_run_ns) < kRunBreakNs)
            {
                repeat_run_ns = now_ns;
                continue;
            }
            repeat_run_code = kKeyNone;
            // Detect the start of a run: this key was just released
            // (kRepeatGapNs ago or less) and re-pressed — a gap no
            // human achieves, so it is the emulator's host-driven
            // auto-repeat. Eat this press and enter run mode.
            if (ev.code == last_press_code && ev.code == last_release_code && (now_ns - last_release_ns) < kRepeatGapNs)
            {
                repeat_run_code = ev.code;
                repeat_run_ns = now_ns;
                // One line per run start (not per suppressed repeat) so a
                // VBox log shows the fix engaging without flooding.
                KLOG_DEBUG_V("input/kbd", "auto-repeat run suppressed; code", static_cast<duetos::u64>(ev.code));
                continue;
            }
            last_press_code = ev.code;
        }

        const bool alt = (ev.modifiers & kKeyModAlt) != 0;
        const bool ctrl = (ev.modifiers & kKeyModCtrl) != 0;
        const bool shift = (ev.modifiers & kKeyModShift) != 0;
        // Publish for non-kbd consumers (wheel handlers etc.)
        // so a Ctrl+wheel gesture can be detected without a
        // race against the kbd ring's own state.
        duetos::drivers::video::WindowSetModifierState(ev.modifiers);
        bool dirty = false;

        // Ctrl+Shift+Esc — the Privileged-Origin kill switch (spec §13.5).
        // Highest-priority chord, handled here in the kernel input path (NOT
        // by the page), so a malicious armed page can never swallow it. It
        // atomically revokes ALL armed privilege (today: the browser's tab)
        // and is a no-op when nothing is armed. The `continue` is load-
        // bearing: the Start-menu toggle below matches `ctrl && !alt && Esc`
        // WITHOUT excluding shift, so without this earlier handler the chord
        // would fall through and open the Start menu instead.
        if (ctrl && shift && !alt && ev.code == kKeyEsc && !ev.is_release)
        {
            duetos::apps::browser::BrowserPrivKillSwitch();
            SerialWrite("[ui] ctrl+shift+esc privileged kill switch\n");
            continue;
        }

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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Esc during a snap-zone hover preview clears the
        // preview without affecting the in-flight drag-move —
        // the user keeps holding LMB, the translucent target
        // overlay vanishes, and a subsequent release commits
        // the window at the cursor position (no snap). The
        // mouse loop owns the drag state machine so we just
        // drop the preview state here and force a recompose;
        // the keystroke is NOT consumed (no `continue;`) so
        // other Esc-listeners downstream still get a chance.
        if (ev.code == kKeyEsc && !ev.is_release &&
            duetos::drivers::video::SnapPreviewArmed() != duetos::drivers::video::SnapZone::None)
        {
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::SnapPreviewArm(duetos::drivers::video::SnapZone::None);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            // Fire any resolved dialog callback OUTSIDE the
            // compositor lock — it may do FAT32 I/O, and nesting
            // fat32 under compositor is the compositor<->fat32
            // lockdep cycle this defers to break.
            duetos::drivers::video::DialogDrainResolved();
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Ctrl+C latches the shell interrupt flag. No
        // DesktopCompose here — the long-running command
        // holding the shell will notice next time it polls.
        // Skipped entirely if Alt is also held (that's a
        // different shortcut like Ctrl+Alt+T) or if Shift is
        // held (Ctrl+Shift+C is the terminal viewport-copy
        // shortcut handled separately below).
        if (ctrl && !alt && !shift && (ev.code == 'c' || ev.code == 'C'))
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
        // Ctrl+Shift+C — when the terminal window is active, copy
        // its currently visible viewport to the clipboard. This is
        // the substitute for drag-selection while the widget layer
        // lacks an in-content mouse-press hook: scroll back via
        // PgUp / wheel to whatever output you want, then Ctrl+Shift+C
        // grabs it. No-op anywhere else (the shell's ^C path is
        // !shift above; ^Shift+C here is unambiguous).
        if (ctrl && shift && !alt && (ev.code == 'c' || ev.code == 'C'))
        {
            duetos::drivers::video::CompositorLock();
            const auto active = duetos::drivers::video::WindowActive();
            if (active != duetos::drivers::video::kWindowInvalid && active == duetos::apps::terminal::TerminalWindow())
            {
                duetos::apps::terminal::TerminalCopyVisibleViewport();
                duetos::drivers::video::CompositorUnlock();
                duetos::drivers::video::NotifyShow("copied viewport to clipboard");
                SerialWrite("[ui] ^+C terminal copy viewport\n");
                continue;
            }
            duetos::drivers::video::CompositorUnlock();
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
        // Ctrl+Esc opens (toggles) the Start menu. Universal
        // keyboard discoverability of the Start menu —
        // matches what every desktop user reaches for after
        // failing to find a Super-key handler. Wraps the same
        // mouse-click path so behaviour, animations, item set,
        // and dispatch are identical.
        if (ctrl && !alt && ev.code == duetos::drivers::input::kKeyEsc)
        {
            StartMenuToggle();
            SerialWrite("[ui] ^Esc Start menu toggle\n");
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                    duetos::drivers::video::CursorShow();
                    duetos::drivers::video::CompositorUnlock();
                    continue;
                }
                // For built-in role-registered apps (Calculator,
                // Notepad, Help, etc.), Alt+F4 hides instead of
                // destroying. Destroying would mark the slot
                // alive=false permanently and the Start menu's
                // "open <role>" handler — which looks up the role
                // -> window mapping — would never raise it again.
                // PE / user-spawned windows have no ThemeRole;
                // they get the destroy semantics that match the
                // Win32 expectation (a closed PE window stays
                // closed until the process re-creates it).
                duetos::drivers::video::ThemeRole role{};
                const bool is_role_app = duetos::drivers::video::ThemeRoleForWindow(active, &role);
                // Also treat the bespoke non-role panels (Network
                // Status, Device Manager, Firewall, Debugger,
                // Notification Center via its own role) as hide-
                // on-close. The check is the conservative one:
                // does the window belong to the kernel-owned app
                // catalogue rather than a runtime spawn? `parent
                // == kWindowInvalid` distinguishes the two —
                // user-spawned PE windows record their owner_pid
                // and never get added to the role registry, so
                // the role check above is sufficient for them;
                // the non-role internal panels likewise have
                // owner_pid == 0.
                const bool is_kernel_app = is_role_app || duetos::drivers::video::WindowOwnerPid(active) == 0;
                if (is_kernel_app)
                {
                    duetos::drivers::video::WindowSetVisible(active, false);
                    SerialWrite("[ui] alt-f4 hide window=");
                }
                else
                {
                    duetos::drivers::video::WindowClose(active);
                    SerialWrite("[ui] alt-f4 close window=");
                }
                SerialWriteHex(active);
                SerialWrite("\n");
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
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
                         (ev.code == kKeyArrowLeft || ev.code == kKeyArrowRight || ev.code == kKeyArrowUp ||
                          ev.code == kKeyArrowDown))
                {
                    app_consumed = duetos::apps::imageview::ImageViewFeedArrow(static_cast<duetos::u16>(ev.code));
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
                          ev.code == kKeyArrowRight || ev.code == kKeyPageUp || ev.code == kKeyPageDown ||
                          ev.code == kKeyHome || ev.code == kKeyEnd))
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
            }
            duetos::drivers::video::CompositorUnlock();
        }
    }
}

// A packet a previous AcquireCoalescedPacket() stopped on because
// it changed the button mask. Parked here so it's replayed as its
// own discrete event before any further motion coalescing.
struct PendingMousePacket
{
    bool valid;
    duetos::drivers::input::MousePacket pkt;
};

// Fold a burst of queued same-button motion packets into one packet
// so a single (expensive, full-screen) DesktopCompose covers the
// whole burst instead of running once per PS/2 packet. That
// one-compose-per-packet pattern is the root cause of the start-menu
// mouse lag: a full recompose cannot keep up with the ~100 Hz PS/2
// packet rate, so the driver's 32-slot ring overflows, motion deltas
// are dropped (drop-oldest), and the cursor crawls / skips.
//
// CONTRACT — why this is NOT just "sum every delta":
//   Button transitions are DISCRETE events. The reader body below
//   resolves press / release / right-press edges one packet at a
//   time (drag begin/end, menu item dispatch, click-to-raise). If a
//   press and its release both land inside one drain and we coalesce
//   across them, the click is silently lost. So the drain MUST stop
//   the instant a queued packet's button mask differs from what has
//   been accumulated, and hand that packet back (via `pending`) to
//   be processed on its own next iteration.
duetos::drivers::input::MousePacket AcquireCoalescedPacket(PendingMousePacket& pending)
{
    using duetos::drivers::input::MousePacket;

    // A button-change packet parked last iteration takes priority
    // and is returned untouched so its edge is handled discretely.
    if (pending.valid)
    {
        pending.valid = false;
        return pending.pkt;
    }

    MousePacket acc = duetos::drivers::input::Ps2MouseReadPacket(); // blocks until 1 packet

    // Drain queued packets, folding motion while the button mask is
    // unchanged. The stop condition is the whole correctness story:
    // we coalesce as long as `buttons` matches what we've
    // accumulated — which deliberately INCLUDES a held-button drag
    // (buttons stay equal for the whole drag, so a fast drag's
    // motion still coalesces into one compose; that was the
    // explicit ask, and it's safe because no press/release EDGE
    // occurs while the mask is constant). The instant the mask
    // differs, that packet is a press/release/right-press edge: the
    // reader body resolves those one at a time, so we park it and
    // stop, replaying it discretely next iteration.
    MousePacket next;
    while (duetos::drivers::input::Ps2MouseTryReadPacket(&next))
    {
        if (next.buttons == acc.buttons)
        {
            acc.dx += next.dx;
            acc.dy += next.dy;
            acc.dz += next.dz;
            continue;
        }
        pending = {true, next};
        break;
    }

    return acc;
}

// ============================================================
// Start menu — shared between the mouse-reader (click on START
// button) and the kbd-reader (Ctrl+Esc / Super). Item arrays
// live at file scope so both tasks can rebuild + open the same
// menu without a copy-paste of the layout.
// ============================================================
namespace
{
using StartMenuRole = duetos::drivers::video::ThemeRole;
using duetos::drivers::video::kMenuItemFlagDisabled;
using duetos::drivers::video::kMenuItemFlagSeparator;
using duetos::drivers::video::kMenuItemFlagSubmenu;

const duetos::drivers::video::MenuItem kStartMenuAppsItems[] = {
    {"CALCULATOR", 100 + static_cast<duetos::u32>(StartMenuRole::Calculator), 0, nullptr, 0},
    {"NOTEPAD", 100 + static_cast<duetos::u32>(StartMenuRole::Notes), 0, nullptr, 0},
    {"FILES", 100 + static_cast<duetos::u32>(StartMenuRole::Files), 0, nullptr, 0},
    {"CLOCK", 100 + static_cast<duetos::u32>(StartMenuRole::Clock), 0, nullptr, 0},
    {"CALENDAR", 100 + static_cast<duetos::u32>(StartMenuRole::Calendar), 0, nullptr, 0},
    {"BROWSER", 100 + static_cast<duetos::u32>(StartMenuRole::Browser), 0, nullptr, 0},
    {"IMAGE VIEWER", 100 + static_cast<duetos::u32>(StartMenuRole::ImageView), 0, nullptr, 0},
    {"GFX DEMO", 100 + static_cast<duetos::u32>(StartMenuRole::GfxDemo), 0, nullptr, 0},
    {"ABOUT", 100 + static_cast<duetos::u32>(StartMenuRole::About), 0, nullptr, 0},
    {"HELP", 100 + static_cast<duetos::u32>(StartMenuRole::Help), 0, nullptr, 0},
};
const duetos::drivers::video::MenuItem kStartMenuSystemItems[] = {
    {"SETTINGS", 100 + static_cast<duetos::u32>(StartMenuRole::Settings), 0, nullptr, 0},
    {"TASK MANAGER", 100 + static_cast<duetos::u32>(StartMenuRole::TaskManager), 0, nullptr, 0},
    {"SYSTEM MONITOR", 100 + static_cast<duetos::u32>(StartMenuRole::Sysmon), 0, nullptr, 0},
    {"KERNEL LOG", 100 + static_cast<duetos::u32>(StartMenuRole::LogView), 0, nullptr, 0},
    {"NOTIFICATIONS", 100 + static_cast<duetos::u32>(StartMenuRole::NotifyCenter), 0, nullptr, 0},
    {"NETWORK STATUS", 60, 0, nullptr, 0},
    {"DEVICE MANAGER", 61, 0, nullptr, 0},
    {"FIREWALL", 62, 0, nullptr, 0},
    {"DEBUGGER", 63, 0, nullptr, 0},
    {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0},
    {"CYCLE WINDOWS", 2, 0, nullptr, 0},
    {"SWITCH TO TTY", 5, 0, nullptr, 0},
};
const duetos::drivers::video::MenuItem kStartMenuUtilitiesItems[] = {
    {"HEX VIEWER", 100 + static_cast<duetos::u32>(StartMenuRole::HexView), 0, nullptr, 0},
    {"CHARACTER MAP", 100 + static_cast<duetos::u32>(StartMenuRole::CharMap), 0, nullptr, 0},
    {"TERMINAL", 100 + static_cast<duetos::u32>(StartMenuRole::Terminal), 0, nullptr, 0},
};
const duetos::drivers::video::MenuItem kStartMenuPowerItems[] = {
    {"LOCK", 42, 0, nullptr, 0},   {"LOG OUT", 43, 0, nullptr, 0},   {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0},
    {"REBOOT", 40, 0, nullptr, 0}, {"SHUT DOWN", 41, 0, nullptr, 0},
};

constexpr duetos::u32 kStartMenuUserAppsCap = 12;
duetos::drivers::video::MenuItem g_start_menu_user_apps[kStartMenuUserAppsCap] = {};
duetos::drivers::video::MenuItem g_start_menu_root[7] = {};

// Rebuild the root from the current /APPS scan + open the menu
// anchored above the START button. Closing-on-toggle is the
// caller's responsibility (the mouse path wraps with MenuIsOpen,
// the kbd path does too).
void StartMenuRebuildAndOpen()
{
    duetos::u32 user_apps_count = 0;
    duetos::drivers::video::StartMenuAppsAppendTo(g_start_menu_user_apps, &user_apps_count, kStartMenuUserAppsCap);

    g_start_menu_root[0] = {"APPS", 0, kMenuItemFlagSubmenu, kStartMenuAppsItems,
                            sizeof(kStartMenuAppsItems) / sizeof(kStartMenuAppsItems[0])};
    g_start_menu_root[1] = {"UTILITIES", 0, kMenuItemFlagSubmenu, kStartMenuUtilitiesItems,
                            sizeof(kStartMenuUtilitiesItems) / sizeof(kStartMenuUtilitiesItems[0])};
    g_start_menu_root[2] = {"SYSTEM", 0, kMenuItemFlagSubmenu, kStartMenuSystemItems,
                            sizeof(kStartMenuSystemItems) / sizeof(kStartMenuSystemItems[0])};
    g_start_menu_root[3] = {(user_apps_count == 0) ? "USER APPS (EMPTY)" : "USER APPS", 0,
                            kMenuItemFlagSubmenu | (user_apps_count == 0 ? kMenuItemFlagDisabled : 0u),
                            g_start_menu_user_apps, user_apps_count};
    g_start_menu_root[4] = {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0};
    g_start_menu_root[5] = {"SCREENSHOT", 50, 0, nullptr, 0};
    g_start_menu_root[6] = {"POWER", 0, kMenuItemFlagSubmenu, kStartMenuPowerItems,
                            sizeof(kStartMenuPowerItems) / sizeof(kStartMenuPowerItems[0])};

    duetos::u32 sx = 0, sy = 0, sw = 0, sh = 0;
    duetos::drivers::video::TaskbarStartBounds(&sx, &sy, &sw, &sh);
    constexpr duetos::u32 kStartMenuItemsCount = sizeof(g_start_menu_root) / sizeof(g_start_menu_root[0]);
    duetos::drivers::video::MenuOpen(g_start_menu_root, kStartMenuItemsCount, sx, sy, 0);
    const duetos::u32 mh = duetos::drivers::video::MenuPanelHeight();
    const duetos::u32 my = (sy > mh) ? sy - mh : 0;
    duetos::drivers::video::MenuOpen(g_start_menu_root, kStartMenuItemsCount, sx, my, 0);
}

void StartMenuToggle()
{
    duetos::drivers::video::CompositorLock();
    if (duetos::drivers::video::MenuIsOpen())
    {
        duetos::drivers::video::MenuClose();
    }
    else
    {
        StartMenuRebuildAndOpen();
    }
    // Force a full desktop recompose so the menu open/close is
    // visible immediately. Without this the mouse-click path
    // schedules a recompose on the next ui-ticker beat (~33 ms);
    // the keyboard toggle should feel equally instant.
    duetos::drivers::video::CursorHide();
    duetos::drivers::video::DesktopCompose(duetos::drivers::video::ThemeCurrent().desktop_bg, nullptr);
    duetos::drivers::video::CursorShow();
    duetos::drivers::video::CompositorUnlock();
}

} // namespace

// Mouse reader task: Ps2 packet consumer driving window
// focus/drag/resize/snap, menu + taskbar + tray interaction,
// scrollbar drag and the desktop context menu.
void MouseReaderTask(void*)
{
    using namespace duetos::arch;
    // Opt out of the hung-task detector — same rationale as
    // KbdReaderTask: a quiescent QEMU smoke leaves this task
    // Blocked inside `Ps2MouseReadEvent` for the entire run.
    duetos::sched::SchedExemptCurrentFromHungTask();
    // Drag state is local to this thread. No other task
    // observes windows moving, so keeping the state on the
    // stack (via static-lambda-local) avoids a fragile global.
    struct DragState
    {
        bool active;
        duetos::drivers::video::WindowHandle window;
        duetos::u32 grab_offset_x;
        duetos::u32 grab_offset_y;
    };
    static DragState drag{false, duetos::drivers::video::kWindowInvalid, 0, 0};
    // Edge-resize state. Activated when the user presses on
    // a window's resize border. Tracks the window + edge +
    // anchor bounds so the resize is computed off the
    // press-time geometry, not the prior frame's.
    struct ResizeState
    {
        bool active;
        duetos::drivers::video::WindowHandle window;
        duetos::drivers::video::WindowResizeEdge edge;
        duetos::u32 anchor_cx, anchor_cy;
        duetos::u32 anchor_x, anchor_y, anchor_w, anchor_h;
    };
    static ResizeState resize{
        false, duetos::drivers::video::kWindowInvalid, duetos::drivers::video::WindowResizeEdge::None, 0, 0, 0, 0, 0,
        0};
    // Scrollbar drag-the-thumb state.
    struct ScrollbarDrag
    {
        bool active;
        duetos::drivers::video::WindowHandle hwnd;
        duetos::u32 grab_offset_in_thumb;
    };
    static ScrollbarDrag sb_drag{false, duetos::drivers::video::kWindowInvalid, 0};
    static bool prev_left = false;
    static bool prev_right = false;
    auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };

    // Menu item sets — static so their label pointers outlive
    // the menu's open state. action_id scheme is documented in
    // kernel_main's comment above; keep these tables in sync.
    //
    // Action-id allocation:
    //   1..39   — misc commands (1=ABOUT, 2=CYCLE, 5=TTY, 6=HELP,
    //             10/11=RAISE/CLOSE, 20-25=system menu,
    //             30-33=Files context).
    //   40..49  — power / session
    //               40=REBOOT, 41=SHUT DOWN, 42=LOCK, 43=LOG OUT.
    //   50..59  — system shortcuts
    //               50=SCREENSHOT.
    //   60..69  — bespoke viewer windows that don't have a
    //             ThemeRole today
    //               60=NETWORK STATUS, 61=DEVICE MANAGER,
    //               62=FIREWALL.
    //   100..199 — open app by ThemeRole (id = 100 + role).
    //   200..255 — /APPS shortcut slots (StartMenuAppsResolveLaunch).
    //
    // Layout: a six-row root that fans out to four submenus
    // (APPS, SYSTEM, USER APPS, POWER) plus a leaf SCREENSHOT
    // and a separator. Each leaf panel stays under the menu
    // renderer's 12-item-per-panel cap (kMaxItems in menu.cpp).
    using duetos::drivers::video::kMenuItemFlagDisabled;
    using duetos::drivers::video::kMenuItemFlagSeparator;
    using duetos::drivers::video::kMenuItemFlagSubmenu;
    static const duetos::drivers::video::MenuItem kDesktopMenuItems[] = {
        {"FILE MANAGER", 104, 0, nullptr, 0}, // 100 + ThemeRole::Files(4)
        {"TERMINAL", 117, 0, nullptr, 0},     // 100 + ThemeRole::Terminal(17)
        {"NEW TEXT FILE", 7, 0, nullptr, 0},    {"REFRESH DESKTOP", 8, 0, nullptr, 0},
        {"SETTINGS", 107, 0, nullptr, 0}, // 100 + ThemeRole::Settings(7)
        {"HELP / SHORTCUTS", 6, 0, nullptr, 0}, {"ABOUT DUETOS", 1, 0, nullptr, 0},
        {"CYCLE WINDOWS", 2, 0, nullptr, 0},    {"LIST WINDOWS", 3, 0, nullptr, 0},
        {"SWITCH TO TTY", 5, 0, nullptr, 0},
    };
    // Taskbar right-click menu — the everyday "manage windows
    // from the bar" gesture. TASK MANAGER uses the 100+role
    // raise band (ThemeRole::TaskManager == 2 -> 102); the rest
    // reuse the existing global window actions.
    static const duetos::drivers::video::MenuItem kTaskbarMenuItems[] = {
        {"TASK MANAGER", 102, 0, nullptr, 0},
        {"CYCLE WINDOWS", 2, 0, nullptr, 0},
        {"LIST WINDOWS", 3, 0, nullptr, 0},
        {"SHOW DESKTOP", 9, 0, nullptr, 0},
    };
    // Window body menu (right-click on a native window's
    // client area). Enriches the original Raise/Close pair
    // with the same Min/Max/Restore the system menu offers,
    // so a user who right-clicks the body gets full controls
    // without aiming at the title bar.
    static const duetos::drivers::video::MenuItem kWindowMenuItems[] = {
        {"RAISE", 10, 0, nullptr, 0},   {"MINIMIZE", 23, 0, nullptr, 0}, {"MAXIMIZE", 24, 0, nullptr, 0},
        {"RESTORE", 20, 0, nullptr, 0}, {"CLOSE", 11, 0, nullptr, 0},
    };
    // Terminal client-area right-click — text actions (COPY /
    // PASTE / CLEAR via the 70..72 dispatch band) on top of the
    // standard window controls, so a right-click in the terminal
    // body is the everyday "copy what I see" gesture. This is the
    // popup that stands in for true drag-selection until the
    // widget layer grows an in-content mouse-press hook.
    static const duetos::drivers::video::MenuItem kTerminalMenuItems[] = {
        {"COPY", 70, 0, nullptr, 0},  {"PASTE", 71, 0, nullptr, 0}, {"CLEAR", 72, 0, nullptr, 0},
        {"RAISE", 10, 0, nullptr, 0}, {"CLOSE", 11, 0, nullptr, 0},
    };
    // Title-bar (NC) right-click — the classic Win32 system
    // menu. RESTORE/MINIMIZE/MAXIMIZE/CLOSE are wired; MOVE
    // does a one-shot recenter (GAP) and SIZE is shown
    // disabled — both wait on a modal-input mode.
    static const duetos::drivers::video::MenuItem kSystemMenuItems[] = {
        {"RESTORE", 20, 0, nullptr, 0},  {"MOVE", 21, 0, nullptr, 0},     {"SIZE", 22, 0, nullptr, 0},
        {"MINIMIZE", 23, 0, nullptr, 0}, {"MAXIMIZE", 24, 0, nullptr, 0}, {"CLOSE", 25, 0, nullptr, 0},
    };

    // Carries a button-change packet across iterations when the
    // coalescing drain stops on an edge (see AcquireCoalescedPacket).
    static PendingMousePacket pending{false, {}};

    for (;;)
    {
        const auto p = AcquireCoalescedPacket(pending);

        // In TTY mode the cursor is hidden and windows aren't
        // painted — ignore UI-side mouse handling entirely.
        // Serial logging still happens so packet delivery is
        // visible end-to-end.
        if (duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty)
        {
            SerialWrite("[mouse-tty] dx=");
            SerialWriteHex(static_cast<duetos::u64>(p.dx));
            SerialWrite(" dy=");
            SerialWriteHex(static_cast<duetos::u64>(p.dy));
            SerialWrite(" btn=");
            SerialWriteHex(p.buttons);
            SerialWrite("\n");
            continue;
        }

        // Feed the kernel-side raw-motion accumulator before
        // any compositor warp logic touches the cursor. This is
        // what DirectInput's GetDeviceState mouse path reads —
        // the warp-corrected cursor diff would lie about user
        // motion when programmatic SetCursor moves the cursor
        // (e.g. confined-to-window capture).
        // PS/2 packets carry dz=0 in the MousePacket (the IBM
        // 3-byte wire format has no wheel slot); USB-HID mice
        // populate it from a 4+ byte report.
        duetos::subsystems::win32::MouseInputAccumulate(p.dx, p.dy, p.dz, p.buttons);

        // Every UI mutation inside this packet lives under
        // the compositor mutex — the kbd reader can be mid-
        // ConsoleWrite / DesktopCompose at the same time.
        duetos::drivers::video::CompositorLock();
        // Apply per-user mouse sensitivity scale (Settings
        // Mouse panel). 128 = identity. Bypass while a
        // modal-input or DnD session is live so the user
        // gets 1:1 cursor tracking during gestures.
        const duetos::u8 sens = duetos::drivers::video::WindowMouseSensitivity();
        const bool gesture_active =
            duetos::drivers::video::ModalInputIsActive() || duetos::drivers::video::DndIsActive();
        duetos::i32 mdx = p.dx;
        duetos::i32 mdy = p.dy;
        if (sens != 128 && !gesture_active)
        {
            mdx = static_cast<duetos::i32>((static_cast<duetos::i64>(mdx) * sens) / 128);
            mdy = static_cast<duetos::i32>((static_cast<duetos::i64>(mdy) * sens) / 128);
        }
        duetos::drivers::video::CursorMove(mdx, mdy);

        duetos::u32 cx = 0, cy = 0;
        duetos::drivers::video::CursorPosition(&cx, &cy);

        // Topmost window under the cursor. Used twice below — once
        // by the cursor-shape hit-test (assigned to `over_resize`)
        // and once by the right-click target lookup (assigned to
        // `hit`). The window list cannot mutate during this
        // iteration (we hold the compositor lock acquired above),
        // so one walk is correct for both. On a debug build with
        // KASAN this halves the dominant per-packet cost — the
        // walk is shadow-checked on every pointer chase, and the
        // ring-3 smoke battery puts 13+ windows on the list.
        const auto cached_topmost_under_cursor = duetos::drivers::video::WindowTopmostAt(cx, cy);

        // Desktop-icon hover highlight. Only when the cursor is on the bare
        // desktop (no window or taskbar under it). DesktopIconSetHover
        // returns true only when the hovered icon actually changes, so the
        // recompose below fires at most once per icon crossing, never per
        // packet (the discipline that keeps the PS/2 ring from overflowing).
        const int desk_icon_hover = (cached_topmost_under_cursor == duetos::drivers::video::kWindowInvalid &&
                                     !duetos::drivers::video::TaskbarContains(cx, cy))
                                        ? duetos::drivers::video::DesktopIconHitTest(cx, cy)
                                        : -1;
        const bool icon_hover_changed = duetos::drivers::video::DesktopIconSetHover(desk_icon_hover);

        // Track menu hover. Cheap when no menu is open. When
        // open, this updates the highlighted row so the next
        // compose paints it. `menu_hover_changed` drives the
        // forced recompose below: only repaint when the
        // highlighted row actually moved, not on every cursor
        // jiggle within a row (the cursor sprite itself is
        // already repainted by CursorMove above).
        const bool menu_hover_changed = duetos::drivers::video::MenuTrackHoverAt(cx, cy);

        // Tooltip hover tracker. Records widget-under-cursor
        // + first-hover tick so a 1-second linger can promote
        // to a tooltip on the next compose.
        duetos::drivers::video::WidgetTooltipTrack(cx, cy, duetos::arch::TimerTicks());

        // Modal-input session (Move / Size from system menu)
        // — feed every motion frame to the registered handler
        // so the window follows the cursor live.
        if (duetos::drivers::video::ModalInputIsActive())
        {
            duetos::drivers::video::ModalInputOnMotion(cx, cy);
        }
        // DnD ghost follows the cursor every motion frame
        // while a drag is live.
        if (duetos::drivers::video::DndIsActive())
        {
            duetos::drivers::video::DndUpdateCursor(cx, cy);
        }

        // Cursor-shape hit-test. Skipped while Wait is active
        // (the long-op holder owns the shape). Otherwise:
        // hovering a button widget → Hand; hovering Notes /
        // Browser editable client area → IBeam; PE-owned window
        // with a Win32 SetCursor-requested shape → that shape;
        // everywhere else → Arrow. The CursorSetShape change-gate
        // keeps per-packet calls cheap when the shape doesn't
        // move.
        //
        // Priority order: kernel-owned chrome rules (resize bands,
        // Hand-on-button, native IBeam) win over the PE-requested
        // shape. The PE request replaces the unconditional Arrow
        // fallback for windows whose owning process has called
        // user32!SetCursor (see SYS_GDI_SET_CURSOR handler) — so
        // a PE drawing its own text-edit area can set IBeam and
        // have it honored on every motion packet, but the kernel
        // still wins when the cursor is over a resize band or a
        // button-widget on top of the PE window.
        if (duetos::drivers::video::CursorGetShape() != duetos::drivers::video::CursorShape::Wait)
        {
            using duetos::drivers::video::CursorShape;
            using duetos::drivers::video::WindowResizeEdge;
            CursorShape want = CursorShape::Arrow;
            bool want_chosen = false; // gates the PE-request fallback
            const auto over_resize = cached_topmost_under_cursor;
            WindowResizeEdge edge = WindowResizeEdge::None;
            if (over_resize != duetos::drivers::video::kWindowInvalid)
            {
                edge = duetos::drivers::video::WindowPointInResizeEdge(over_resize, cx, cy);
            }
            if (edge == WindowResizeEdge::Left || edge == WindowResizeEdge::Right)
            {
                want = CursorShape::ResizeEW;
                want_chosen = true;
            }
            else if (edge == WindowResizeEdge::Top || edge == WindowResizeEdge::Bottom)
            {
                want = CursorShape::ResizeNS;
                want_chosen = true;
            }
            else if (edge == WindowResizeEdge::TopLeft || edge == WindowResizeEdge::BottomRight)
            {
                want = CursorShape::ResizeNWSE;
                want_chosen = true;
            }
            else if (edge == WindowResizeEdge::TopRight || edge == WindowResizeEdge::BottomLeft)
            {
                want = CursorShape::ResizeNESW;
                want_chosen = true;
            }
            else if (duetos::drivers::video::WidgetCursorOverButton(cx, cy))
            {
                want = CursorShape::Hand;
                want_chosen = true;
            }
            else if (over_resize != duetos::drivers::video::kWindowInvalid &&
                     !duetos::drivers::video::WindowPointInTitle(over_resize, cx, cy) &&
                     (over_resize == duetos::apps::notes::NotesWindow() ||
                      over_resize == duetos::apps::browser::BrowserWindow()))
            {
                want = CursorShape::IBeam;
                want_chosen = true;
            }
            // No kernel-owned rule matched — consult the
            // per-window PE-requested cursor shape (set via
            // SYS_GDI_SET_CURSOR). Only honored when the cursor is
            // over a window that called SetCursor; otherwise the
            // Arrow default falls through. Title-bar hits keep the
            // Arrow fallback so window chrome stays predictable
            // even when the PE requests something for the client
            // area.
            if (!want_chosen && over_resize != duetos::drivers::video::kWindowInvalid &&
                !duetos::drivers::video::WindowPointInTitle(over_resize, cx, cy))
            {
                duetos::u8 pe_shape = 0;
                if (duetos::drivers::video::WindowGetRequestedCursorShape(over_resize, &pe_shape))
                {
                    // Clamp to the known enum range. Out-of-range
                    // values (a future enum extension a stale
                    // kernel doesn't recognise) collapse to Arrow
                    // so the cursor never paints uninitialised
                    // sprite memory.
                    if (pe_shape <= static_cast<duetos::u8>(CursorShape::ResizeNWSE))
                    {
                        want = static_cast<CursorShape>(pe_shape);
                    }
                }
            }
            duetos::drivers::video::CursorSetShape(want);
        }

        const bool left_down = (p.buttons & duetos::drivers::input::kMouseButtonLeft) != 0;
        const bool press_edge = left_down && !prev_left;
        const bool release_edge = !left_down && prev_left;
        prev_left = left_down;

        const bool right_down = (p.buttons & duetos::drivers::input::kMouseButtonRight) != 0;
        const bool right_press = right_down && !prev_right;
        const bool right_release = !right_down && prev_right;
        prev_right = right_down;

        // Login gate — Pass B fix. While LoginIsActive() in Gui mode the
        // desktop chrome (windows, taskbar, widget table) must NOT receive
        // mouse events: clicking through to apps would bypass auth entirely.
        // We still let CursorMove (above) update the sprite position so the
        // cursor tracks visually, and we route a press-edge click on the
        // sign-in button to LoginFeedKey(kKeyEnter) — same submit path as
        // pressing Enter. Everything else (drag, widget routing, window
        // hit-test, DesktopCompose) is skipped. The compositor lock taken
        // above is released and the loop continues.
        if (duetos::core::LoginIsActive() && duetos::core::LoginCurrentMode() == duetos::core::LoginMode::Gui)
        {
            if (press_edge)
            {
                // Route by hit-test, sign-in button first (it overlaps no
                // other field), then password input, then the username
                // row (avatar/name/role). Anything else is inert.
                if (duetos::core::LoginHitTestSignInButton(cx, cy))
                {
                    duetos::core::LoginFeedKey(duetos::drivers::input::kKeyEnter);
                }
                else if (duetos::core::LoginHitTestPasswordField(cx, cy))
                {
                    duetos::core::LoginFocusPassword();
                }
                else if (duetos::core::LoginHitTestUsernameField(cx, cy))
                {
                    duetos::core::LoginFocusUsername();
                }
            }
            duetos::drivers::video::CompositorUnlock();
            continue;
        }

        // Right-click opens a context menu. Different item set
        // depending on what's under the cursor:
        //   - Taskbar: skip (no right-click menu there yet).
        //   - Title bar (any window): system menu (Restore /
        //     Move / Size / Min / Max / Close), ctx = HWND.
        //   - Native (kernel-app) window body: enriched
        //     window menu (Raise + Min/Max/Restore/Close),
        //     ctx = HWND. Also lets the Files app intercept
        //     to show its per-row menu.
        //   - PE (user-process) window body: NO kernel menu
        //     opens. Instead a WM_CONTEXTMENU is posted (see
        //     the PE mouse-routing block below) so the app
        //     can call TrackPopupMenu itself.
        //   - Desktop: desktop menu (ABOUT / CYCLE / LIST /
        //     TTY), ctx = 0.
        // If a menu is already open, a right-click simply
        // closes it — matches Windows behaviour.
        bool pe_right_skip = false;
        if (right_press)
        {
            if (duetos::drivers::video::MenuIsOpen())
            {
                // If the open menu belongs to a PE
                // TrackPopupMenu syscall, signal cancel so the
                // syscall returns 0. Then close.
                if (duetos::drivers::video::MenuContext() == duetos::subsystems::win32::kTrackPopupSentinelCtx)
                {
                    duetos::subsystems::win32::TrackPopupCompleteFromKernel(0);
                }
                duetos::drivers::video::MenuClose();
            }
            else if (duetos::drivers::video::TaskbarContains(cx, cy))
            {
                duetos::drivers::video::MenuOpen(kTaskbarMenuItems,
                                                 sizeof(kTaskbarMenuItems) / sizeof(kTaskbarMenuItems[0]), cx, cy, 0);
                SerialWrite("[ui] right-click target=taskbar\n");
            }
            else
            {
                const auto hit = cached_topmost_under_cursor;
                if (hit != duetos::drivers::video::kWindowInvalid)
                {
                    const bool in_title = duetos::drivers::video::WindowPointInTitle(hit, cx, cy);
                    if (in_title)
                    {
                        duetos::drivers::video::MenuOpen(
                            kSystemMenuItems, sizeof(kSystemMenuItems) / sizeof(kSystemMenuItems[0]), cx, cy, hit);
                        SerialWrite("[ui] right-click target=title window=");
                        SerialWriteHex(hit);
                        SerialWrite("\n");
                    }
                    else
                    {
                        const duetos::u64 owner_pid = duetos::drivers::video::WindowOwnerPid(hit);
                        if (owner_pid > 0)
                        {
                            // PE window body: defer to the
                            // app via WM_CONTEXTMENU.
                            pe_right_skip = true;
                            SerialWrite("[ui] right-click target=client (pe) window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                        else if (hit == duetos::apps::files::FilesWindow() &&
                                 duetos::apps::files::FilesOnRightClick(cx, cy))
                        {
                            // Files app claimed it (per-row
                            // context menu opened). No-op
                            // here; the menu is up.
                            SerialWrite("[ui] right-click target=client (files) window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                        else if (hit == duetos::apps::terminal::TerminalWindow())
                        {
                            // Terminal body: COPY/PASTE/CLEAR popup.
                            duetos::drivers::video::MenuOpen(kTerminalMenuItems,
                                                             sizeof(kTerminalMenuItems) / sizeof(kTerminalMenuItems[0]),
                                                             cx, cy, hit);
                            SerialWrite("[ui] right-click target=client (terminal) window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                        else
                        {
                            duetos::drivers::video::MenuOpen(
                                kWindowMenuItems, sizeof(kWindowMenuItems) / sizeof(kWindowMenuItems[0]), cx, cy, hit);
                            SerialWrite("[ui] right-click target=client (native) window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                    }
                }
                else
                {
                    duetos::drivers::video::MenuOpen(
                        kDesktopMenuItems, sizeof(kDesktopMenuItems) / sizeof(kDesktopMenuItems[0]), cx, cy, 0);
                    SerialWrite("[ui] right-click target=desktop\n");
                }
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            if (!pe_right_skip)
            {
                duetos::drivers::video::CompositorUnlock();
                continue;
            }
            // PE-bound right-click: fall through so the PE
            // mouse-routing block below can post WM_RBUTTONDOWN
            // / WM_RBUTTONUP / WM_CONTEXTMENU. drag.active stays
            // false, so the ordinary press_edge cases that
            // follow are bypassed naturally (right_press is
            // handled here, left state unchanged).
        }

        // Priority for press edges (highest first):
        //   0a. Menu open + click on item → fire action, close.
        //   0b. Menu open + click outside → close.
        //   1.  Click on START → open/close menu.
        //   2.  Taskbar tab → raise tab's window.
        //   3.  Close-box on topmost window → close it.
        //   4.  Title bar → raise + begin drag.
        //   5.  Any other part of a window → raise only.
        bool menu_handled = false;
        // DnD gate: a press edge during a drag resolves the
        // drop at the cursor position. Consume the click so
        // it doesn't fall through.
        if (press_edge && duetos::drivers::video::DndIsActive())
        {
            duetos::drivers::video::DndResolveAt(cx, cy);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            menu_handled = true;
        }
        // Modal-input gate: a press edge during a Move /
        // Size session commits and exits. Consume the click
        // so it doesn't fall through to chrome handling.
        if (press_edge && duetos::drivers::video::ModalInputIsActive())
        {
            duetos::drivers::video::ModalInputOnPress(cx, cy);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            menu_handled = true;
        }
        // Modal-dialog gate: if a MessageBox / InputBox is up,
        // route press edges into it and consume the click.
        // The dialog runs OK / Cancel hit-tests + dismiss
        // logic itself.
        if (press_edge && duetos::drivers::video::DialogIsActive())
        {
            duetos::drivers::video::DialogOnPress(cx, cy);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            // Same contract as the keyboard path: fire the
            // resolved callback with no compositor lock held.
            duetos::drivers::video::DialogDrainResolved();
            menu_handled = true; // suppress every downstream press path
        }
        if (press_edge && duetos::drivers::video::MenuIsOpen())
        {
            // Track stack depth around MenuItemAt so we can
            // detect "click on a submenu row opened a child
            // panel" — in that case the menu stays up and no
            // dispatch happens.
            const duetos::u32 ctx = duetos::drivers::video::MenuContext();
            const duetos::u32 prev_depth = duetos::drivers::video::MenuStackDepth();
            const duetos::u32 action = duetos::drivers::video::MenuItemAt(cx, cy);
            const duetos::u32 new_depth = duetos::drivers::video::MenuStackDepth();
            bool keep_open = false;
            if (new_depth > prev_depth)
            {
                // Submenu opened — keep menu up, dispatch nothing.
                keep_open = true;
            }
            else if (action != 0)
            {
                if (ctx == duetos::subsystems::win32::kTrackPopupSentinelCtx)
                {
                    duetos::subsystems::win32::TrackPopupCompleteFromKernel(action);
                }
                else
                {
                    duetos::core::DispatchMenuAction(action, ctx);
                }
            }
            else
            {
                // Click missed item / outside menu — cancel.
                if (ctx == duetos::subsystems::win32::kTrackPopupSentinelCtx)
                {
                    duetos::subsystems::win32::TrackPopupCompleteFromKernel(0);
                }
            }
            if (!keep_open)
            {
                duetos::drivers::video::MenuClose();
            }
            // Force an immediate recompose so any console
            // output the action wrote (HELP / ABOUT / -> RAISED
            // ...) appears now rather than waiting up to a
            // second for the ui-ticker. Also clears (or refreshes)
            // the menu panel from the framebuffer.
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            menu_handled = true;
        }

        // Click on the clock/date widget toggles the calendar
        // popup. Tested BEFORE the start-menu branch because
        // the clock lives on the opposite side of the
        // taskbar; a hit here can never overlap the START
        // rect.
        if (press_edge && !menu_handled && !drag.active)
        {
            duetos::u32 kx = 0, ky = 0, kw = 0, kh = 0;
            duetos::drivers::video::TaskbarClockBounds(&kx, &ky, &kw, &kh);
            if (kw > 0 && cx >= kx && cx < kx + kw && cy >= ky && cy < ky + kh)
            {
                if (duetos::drivers::video::CalendarIsOpen())
                {
                    duetos::drivers::video::CalendarClose();
                }
                else
                {
                    // Anchor upper-left so the popup sits
                    // flush above the taskbar's top edge.
                    const duetos::u32 ph = duetos::drivers::video::CalendarPanelHeight();
                    const duetos::u32 pw = duetos::drivers::video::CalendarPanelWidth();
                    const duetos::u32 ax = (kx + kw > pw) ? (kx + kw - pw) : 0;
                    const duetos::u32 ay = (ky > ph) ? ky - ph : 0;
                    duetos::drivers::video::CalendarOpen(ax, ay);
                    SerialWrite("[ui] calendar open\n");
                }
                menu_handled = true;
            }
        }

        // Clicking outside an open calendar dismisses it.
        if (press_edge && !menu_handled && duetos::drivers::video::CalendarIsOpen() &&
            !duetos::drivers::video::CalendarContains(cx, cy))
        {
            duetos::drivers::video::CalendarClose();
        }

        // Desktop icons — double-click on a bare-desktop icon raises its
        // app. Gated on "no window under the cursor" so an icon covered
        // by a window is never clickable (icons paint beneath windows).
        // Double-click uses the same tick window as title-bar dbl-click.
        if (press_edge && !menu_handled && !drag.active &&
            cached_topmost_under_cursor == duetos::drivers::video::kWindowInvalid &&
            !duetos::drivers::video::TaskbarContains(cx, cy))
        {
            const int icon = duetos::drivers::video::DesktopIconHitTest(cx, cy);
            if (icon >= 0)
            {
                static duetos::u64 s_icon_dc_tick = 0;
                static int s_icon_dc_idx = -1;
                const duetos::u64 dc_ticks = duetos::drivers::video::WindowDoubleClickTicks();
                const duetos::u64 now_tick = duetos::arch::TimerTicks();
                const bool is_dbl = (s_icon_dc_idx == icon) && (now_tick - s_icon_dc_tick <= dc_ticks);
                if (is_dbl)
                {
                    duetos::drivers::video::DesktopIconActivate(icon);
                    // Auto-focus the URL bar when the browser icon is activated
                    // so keyboard-first URL entry works immediately (F-032).
                    if (duetos::drivers::video::DesktopIconWindow(icon) == duetos::apps::browser::BrowserWindow())
                        duetos::apps::browser::BrowserFocusUrl();
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                    duetos::drivers::video::CursorShow();
                    s_icon_dc_idx = -1; // consume so a triple-click doesn't re-fire
                    SerialWrite("[ui] desktop icon launch idx=");
                    SerialWriteHex(static_cast<duetos::u64>(icon));
                    SerialWrite("\n");
                }
                else
                {
                    s_icon_dc_tick = now_tick;
                    s_icon_dc_idx = icon;
                }
                menu_handled = true; // claim the click; don't fall through to window/start chain
            }
        }

        // --- Network flyout handlers ---------------------------
        //
        // Hover-preview + click-toggle on the NET tray cell,
        // mirroring the Windows / GNOME bottom-right Wi-Fi flyout.
        // State machine:
        //   - Cursor over cell + no mode → open Preview.
        //   - Click on cell + Preview open → upgrade to Full.
        //   - Click on cell + Full open → close.
        //   - Cursor leaves cell + panel + mode is Preview →
        //     close (Full sticks through hover-out by design).
        //   - Click outside Full panel → close.
        //   - Click on RENEW button inside Full → kick DHCP.
        {
            duetos::u32 nx = 0, ny = 0, nw = 0, nh = 0;
            duetos::drivers::video::TaskbarNetCellBounds(&nx, &ny, &nw, &nh);
            const bool over_cell = (nw > 0) && cx >= nx && cx < nx + nw && cy >= ny && cy < ny + nh;
            const auto net_mode = duetos::drivers::video::NetPanelCurrentMode();

            // RENEW button — handled BEFORE the click-outside
            // dismissal so the press doesn't simultaneously
            // close the panel.
            if (press_edge && !menu_handled && net_mode == duetos::drivers::video::NetPanelMode::Full &&
                duetos::drivers::video::NetPanelRenewButtonContains(cx, cy))
            {
                (void)duetos::drivers::video::NetPanelDoRenew();
                SerialWrite("[ui] netpanel renew\n");
                menu_handled = true;
            }

            // Click on the NET tray cell — toggle modes.
            if (press_edge && !menu_handled && over_cell)
            {
                if (net_mode == duetos::drivers::video::NetPanelMode::Full)
                {
                    duetos::drivers::video::NetPanelClose();
                }
                else
                {
                    // Always (re-)open in Full mode on click,
                    // even if Preview was already up — clicking
                    // is the explicit "show me everything" gesture.
                    const duetos::u32 fw = 320; // matches netpanel kFullW
                    duetos::drivers::video::NetPanelOpen(0, 0, duetos::drivers::video::NetPanelMode::Full);
                    const duetos::u32 fh = duetos::drivers::video::NetPanelHeight();
                    const duetos::u32 ax = (nx + nw > fw) ? (nx + nw - fw) : 0;
                    const duetos::u32 ay = (ny > fh) ? ny - fh : 0;
                    duetos::drivers::video::NetPanelOpen(ax, ay, duetos::drivers::video::NetPanelMode::Full);
                    SerialWrite("[ui] netpanel open (full)\n");
                }
                menu_handled = true;
            }
            // Click outside an open Full panel → close.
            else if (press_edge && !menu_handled && net_mode == duetos::drivers::video::NetPanelMode::Full &&
                     !duetos::drivers::video::NetPanelContains(cx, cy))
            {
                duetos::drivers::video::NetPanelClose();
                SerialWrite("[ui] netpanel close (click outside)\n");
                // Don't set menu_handled — the click might still
                // legitimately fall through to a window or other
                // taskbar widget.
            }
            // Hover open / close — runs every packet, no
            // press_edge gate. Only mutates state if the panel
            // isn't already in Full mode (Full ignores hover-out).
            else if (over_cell && net_mode == duetos::drivers::video::NetPanelMode::Closed)
            {
                const duetos::u32 pw = 220; // matches netpanel kPreviewW
                const duetos::u32 ph = 56;  // matches kPreviewH
                const duetos::u32 ax = (nx + nw > pw) ? (nx + nw - pw) : 0;
                const duetos::u32 ay = (ny > ph) ? ny - ph : 0;
                duetos::drivers::video::NetPanelOpen(ax, ay, duetos::drivers::video::NetPanelMode::Preview);
                SerialWrite("[ui] netpanel hover preview\n");
            }
            else if (!over_cell && net_mode == duetos::drivers::video::NetPanelMode::Preview &&
                     !duetos::drivers::video::NetPanelContains(cx, cy))
            {
                duetos::drivers::video::NetPanelClose();
            }
        }

        // --- Volume flyout (taskbar speaker cell) ---------------
        //
        // Click the speaker cell to toggle a mute + master-volume
        // slider popup; scroll the wheel over the cell to nudge the
        // level +/-5%. Mirrors the network flyout's click-toggle and
        // click-outside-to-close pattern.
        {
            namespace audio = duetos::subsystems::audio;
            duetos::u32 vx = 0, vy = 0, vw = 0, vh = 0;
            duetos::drivers::video::TaskbarVolumeBounds(&vx, &vy, &vw, &vh);
            const bool over_vol = (vw > 0) && cx >= vx && cx < vx + vw && cy >= vy && cy < vy + vh;

            if (over_vol && p.dz != 0 && !menu_handled)
            {
                duetos::i32 next = static_cast<duetos::i32>(audio::AudioGetMasterVolume()) + (p.dz > 0 ? 5 : -5);
                next = (next < 0) ? 0 : (next > 100 ? 100 : next);
                audio::AudioSetMasterVolume(static_cast<duetos::u8>(next));
                audio::AudioSetMuted(false);
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
                menu_handled = true;
            }

            if (press_edge && !menu_handled && over_vol)
            {
                if (duetos::drivers::video::VolumeFlyoutIsOpen())
                {
                    duetos::drivers::video::VolumeFlyoutClose();
                }
                else
                {
                    const duetos::u32 fw = duetos::drivers::video::VolumeFlyoutWidth();
                    const duetos::u32 fh = duetos::drivers::video::VolumeFlyoutHeight();
                    const duetos::u32 ax = (vx + vw > fw) ? (vx + vw - fw) : 0;
                    const duetos::u32 ay = (vy > fh) ? vy - fh : 0;
                    duetos::drivers::video::VolumeFlyoutOpen(ax, ay);
                }
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
                menu_handled = true;
            }
            else if (press_edge && !menu_handled && duetos::drivers::video::VolumeFlyoutIsOpen() &&
                     duetos::drivers::video::VolumeFlyoutContains(cx, cy))
            {
                if (duetos::drivers::video::VolumeFlyoutMuteContains(cx, cy))
                {
                    audio::AudioSetMuted(!audio::AudioIsMuted());
                }
                else if (duetos::drivers::video::VolumeFlyoutSliderContains(cx, cy))
                {
                    duetos::drivers::video::VolumeFlyoutSetFromX(cx);
                }
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
                menu_handled = true;
            }
            else if (press_edge && !menu_handled && duetos::drivers::video::VolumeFlyoutIsOpen() &&
                     !duetos::drivers::video::VolumeFlyoutContains(cx, cy))
            {
                duetos::drivers::video::VolumeFlyoutClose();
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
            }
        }

        // --- Tray flyout (chevron-up overflow button) -----------
        //
        // Hover-expand + click-toggle on the chevron at the
        // left of the system tray. Mirrors Win10/Win11's "show
        // hidden icons" pattern: hover lifts the chevron's
        // glyph slightly, click opens a popup with detailed
        // status rows (network, volume, battery, memory,
        // CPU, uptime).
        {
            duetos::u32 chx = 0, chy = 0, chw = 0, chh = 0;
            duetos::drivers::video::TaskbarChevronBounds(&chx, &chy, &chw, &chh);
            const bool over_chev = (chw > 0) && cx >= chx && cx < chx + chw && cy >= chy && cy < chy + chh;

            // Hover state — runs every packet (no press_edge
            // gate). The taskbar redraw consults this on the
            // next compose to decide whether to enlarge the
            // chevron glyph.
            duetos::drivers::video::TaskbarChevronSetHover(over_chev);
            duetos::drivers::video::TrayFlyoutSetHover(over_chev);

            // Click on the chevron toggles the flyout.
            if (press_edge && !menu_handled && over_chev)
            {
                if (duetos::drivers::video::TrayFlyoutIsOpen())
                {
                    duetos::drivers::video::TrayFlyoutClose();
                    SerialWrite("[ui] tray flyout close (chevron)\n");
                }
                else
                {
                    // Anchor the flyout's bottom edge against
                    // the chevron's top — the popup paints
                    // ABOVE the anchor.
                    duetos::drivers::video::TrayFlyoutOpen(chx, chy);
                    SerialWrite("[ui] tray flyout open\n");
                }
                menu_handled = true;
            }
            // Click outside an open flyout dismisses it.
            else if (press_edge && !menu_handled && duetos::drivers::video::TrayFlyoutIsOpen() &&
                     !duetos::drivers::video::TrayFlyoutContains(cx, cy))
            {
                duetos::drivers::video::TrayFlyoutClose();
                SerialWrite("[ui] tray flyout close (click outside)\n");
            }
        }

        // START button press opens (or closes) the menu.
        if (press_edge && !menu_handled && !drag.active)
        {
            duetos::u32 sx = 0, sy = 0, sw = 0, sh = 0;
            duetos::drivers::video::TaskbarStartBounds(&sx, &sy, &sw, &sh);
            if (cx >= sx && cx < sx + sw && cy >= sy && cy < sy + sh)
            {
                if (duetos::drivers::video::MenuIsOpen())
                {
                    duetos::drivers::video::MenuClose();
                }
                else
                {
                    StartMenuRebuildAndOpen();
                    SerialWrite("[ui] menu open\n");
                }
                menu_handled = true;
            }
        }

        // "Show Desktop" sliver at the right edge of the
        // taskbar. First press snapshots the visibility of
        // every alive window and hides them; second press
        // restores the snapshotted state. Tab-click + START
        // clicks already consumed earlier presses, so this
        // hit-test runs on the residual press_edge stream.
        if (press_edge && !menu_handled && !drag.active)
        {
            duetos::u32 dx = 0, dy = 0, dw = 0, dh = 0;
            duetos::drivers::video::TaskbarShowDesktopBounds(&dx, &dy, &dw, &dh);
            if (dw > 0 && cx >= dx && cx < dx + dw && cy >= dy && cy < dy + dh)
            {
                const bool now_active = duetos::drivers::video::WindowShowDesktopToggle();
                SerialWrite(now_active ? "[ui] show-desktop ON\n" : "[ui] show-desktop OFF\n");
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
                menu_handled = true; // sliver ate the click
            }
        }

        // Scrollbar press hit-test. Runs before edge-resize
        // and chrome handling because a scrollbar bar lives
        // inside the client area + is a higher-priority
        // gesture than "raise window". Track click sets a
        // new `first` (page-back / page-forward / on-thumb).
        // On-thumb captures into sb_drag for follow-up motion.
        if (press_edge && !menu_handled && !drag.active && !resize.active)
        {
            const auto sh = duetos::drivers::video::WindowTopmostAt(cx, cy);
            duetos::drivers::video::WindowScrollbarSurface s{};
            if (sh != duetos::drivers::video::kWindowInvalid && duetos::drivers::video::WindowGetScrollbar(sh, &s))
            {
                const duetos::drivers::video::ScrollbarState state{s.total, s.visible, s.first};
                const duetos::u32 hit = duetos::drivers::video::ScrollbarHitTest(cx, cy, s.x, s.y, s.w, s.h, state);
                if (hit != duetos::drivers::video::kScrollbarNoHit)
                {
                    const duetos::u32 thumb_y = duetos::drivers::video::ScrollbarThumbY(s.h, state);
                    const duetos::u32 thumb_h = duetos::drivers::video::ScrollbarThumbH(s.h, state);
                    const duetos::u32 click_y = cy - s.y;
                    if (click_y >= thumb_y && click_y < thumb_y + thumb_h)
                    {
                        sb_drag.active = true;
                        sb_drag.hwnd = sh;
                        sb_drag.grab_offset_in_thumb = click_y - thumb_y;
                    }
                    else
                    {
                        duetos::drivers::video::WindowDispatchScroll(sh, hit);
                    }
                    menu_handled = true;
                }
            }
        }

        // Edge-resize detection. Runs before the chrome-press
        // block so a click on the 4-px border doesn't fall
        // through to title-bar drag-start. Handles the press
        // edge only — the motion + release branches further
        // down do the actual resize.
        if (press_edge && !menu_handled && !drag.active && !resize.active)
        {
            const auto rh = duetos::drivers::video::WindowTopmostAt(cx, cy);
            if (rh != duetos::drivers::video::kWindowInvalid)
            {
                const auto rede = duetos::drivers::video::WindowPointInResizeEdge(rh, cx, cy);
                if (rede != duetos::drivers::video::WindowResizeEdge::None)
                {
                    duetos::u32 ax = 0, ay = 0, aw = 0, ah = 0;
                    duetos::drivers::video::WindowGetBounds(rh, &ax, &ay, &aw, &ah);
                    resize.active = true;
                    resize.window = rh;
                    resize.edge = rede;
                    resize.anchor_cx = cx;
                    resize.anchor_cy = cy;
                    resize.anchor_x = ax;
                    resize.anchor_y = ay;
                    resize.anchor_w = aw;
                    resize.anchor_h = ah;
                    duetos::drivers::video::WindowRaise(rh);
                    menu_handled = true; // chrome path skips
                    SerialWrite("[ui] resize begin window=");
                    SerialWriteHex(rh);
                    SerialWrite(" edge=");
                    SerialWriteHex(static_cast<duetos::u64>(rede));
                    SerialWrite("\n");
                }
            }
        }

        if (press_edge && !menu_handled && !drag.active && duetos::drivers::video::TaskbarContains(cx, cy))
        {
            const duetos::u32 tab_hit = duetos::drivers::video::TaskbarTabAt(cx, cy);
            if (tab_hit != duetos::drivers::video::kWindowInvalid)
            {
                duetos::drivers::video::WindowRaise(tab_hit);
                SerialWrite("[ui] taskbar raise window=");
                SerialWriteHex(tab_hit);
                SerialWrite("\n");
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
                menu_handled = true; // taskbar ate the click
            }
            else
            {
                // Clock / date widget click -> open the Calendar
                // (everyday "click the clock to see the calendar"
                // gesture). 112 == 100 + ThemeRole::Calendar(12),
                // routed through the shared role-raise path.
                duetos::u32 clx = 0, cly = 0, clw = 0, clh = 0;
                duetos::drivers::video::TaskbarClockBounds(&clx, &cly, &clw, &clh);
                if (clw > 0 && clh > 0 && cx >= clx && cx < clx + clw && cy >= cly && cy < cly + clh)
                {
                    duetos::core::DispatchMenuAction(112, 0);
                    SerialWrite("[ui] taskbar clock click -> calendar\n");
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                    duetos::drivers::video::CursorShow();
                    menu_handled = true;
                }
                else if (!duetos::drivers::video::TaskbarIsLocked())
                {
                    // Empty-strip click on an unlocked taskbar ->
                    // begin drag. Snap target decided on release.
                    duetos::drivers::video::TaskbarBeginDrag();
                    menu_handled = true;
                }
            }
        }

        if (press_edge && menu_handled)
        {
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
        }
        else if (press_edge && !drag.active)
        {
            const auto hit = duetos::drivers::video::WindowTopmostAt(cx, cy);
            if (hit != duetos::drivers::video::kWindowInvalid)
            {
                if (duetos::drivers::video::WindowPointInCloseBox(hit, cx, cy))
                {
                    // PE-owned windows receive WM_CLOSE and
                    // decide whether to DestroyWindow (or
                    // ignore). Kernel-owned boot windows hide
                    // instead of destroying so the Start menu's
                    // role-raise handler can bring them back —
                    // same reason as the Alt+F4 close path: a
                    // destroyed role slot is permanent in v0,
                    // and "closed Calculator" should mean "the
                    // window is gone for now," not "Calculator
                    // is unrecoverable for this session."
                    if (duetos::drivers::video::WindowOwnerPid(hit) > 0)
                    {
                        constexpr duetos::u32 kWmClose = 0x0010;
                        duetos::drivers::video::WindowPostMessage(hit, kWmClose, 0, 0);
                        duetos::drivers::video::WindowMsgWakeAll();
                        SerialWrite("[ui] post WM_CLOSE window=");
                        SerialWriteHex(hit);
                        SerialWrite("\n");
                    }
                    else
                    {
                        duetos::drivers::video::WindowSetVisible(hit, false);
                        SerialWrite("[ui] hide window=");
                        SerialWriteHex(hit);
                        SerialWrite("\n");
                    }
                }
                else if (duetos::drivers::video::WindowPointInMaxBox(hit, cx, cy))
                {
                    // Toggle: max → restore, restore → max.
                    if (duetos::drivers::video::WindowIsMaximized(hit))
                    {
                        duetos::drivers::video::WindowRestore(hit);
                        SerialWrite("[ui] restore window=");
                    }
                    else
                    {
                        duetos::drivers::video::WindowMaximize(hit);
                        SerialWrite("[ui] maximize window=");
                    }
                    SerialWriteHex(hit);
                    SerialWrite("\n");
                    duetos::drivers::video::WindowRaise(hit);
                }
                else if (duetos::drivers::video::WindowPointInMinBox(hit, cx, cy))
                {
                    duetos::drivers::video::WindowMinimize(hit);
                    SerialWrite("[ui] minimize window=");
                    SerialWriteHex(hit);
                    SerialWrite("\n");
                }
                else
                {
                    duetos::u32 wx = 0, wy = 0;
                    duetos::drivers::video::WindowGetBounds(hit, &wx, &wy, nullptr, nullptr);
                    duetos::drivers::video::WindowRaise(hit);
                    const bool in_title = duetos::drivers::video::WindowPointInTitle(hit, cx, cy);
                    if (in_title)
                    {
                        // Title-bar double-click toggles
                        // maximize/restore — the gesture every
                        // desktop OS converges on. Detected here
                        // (not in the routing block below)
                        // because the title-bar branch swallows
                        // press edges before the routing block
                        // sees them; without this the second
                        // click would just re-arm the drag.
                        const duetos::u64 kTitleDblClickTicks = duetos::drivers::video::WindowDoubleClickTicks();
                        static duetos::u64 s_title_dc_tick = 0;
                        static duetos::drivers::video::WindowHandle s_title_dc_hwnd =
                            duetos::drivers::video::kWindowInvalid;
                        const duetos::u64 now_tick = duetos::arch::TimerTicks();
                        const bool is_title_dbl =
                            (s_title_dc_hwnd == hit) && (now_tick - s_title_dc_tick <= kTitleDblClickTicks);
                        if (is_title_dbl)
                        {
                            if (duetos::drivers::video::WindowIsMaximized(hit))
                            {
                                duetos::drivers::video::WindowRestore(hit);
                                SerialWrite("[ui] title-bar dblclk -> restore window=");
                            }
                            else
                            {
                                duetos::drivers::video::WindowMaximize(hit);
                                SerialWrite("[ui] title-bar dblclk -> maximize window=");
                            }
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                            // Consume the second click so a fast
                            // triple-click doesn't fire a third
                            // toggle in the same gesture.
                            s_title_dc_hwnd = duetos::drivers::video::kWindowInvalid;
                        }
                        else
                        {
                            s_title_dc_tick = now_tick;
                            s_title_dc_hwnd = hit;
                            drag.active = true;
                            drag.window = hit;
                            drag.grab_offset_x = cx - wx;
                            drag.grab_offset_y = cy - wy;
                            SerialWrite("[ui] drag begin window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                    }
                    else
                    {
                        SerialWrite("[ui] raise window=");
                        SerialWriteHex(hit);
                        SerialWrite("\n");
                        // Native-app press dispatch on
                        // client-area clicks. Calendar's
                        // click-to-select-date is the only
                        // current consumer; other apps fan
                        // their press events through the
                        // routing block further down (PE
                        // path) or get them via WidgetRouteMouse.
                        if (hit == duetos::apps::calendar::CalendarWindow())
                        {
                            duetos::apps::calendar::CalendarOnClick(cx, cy);
                        }
                    }
                }
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
            }
        }
        if (release_edge && drag.active)
        {
            // Aero-style snap commit: if the drag-motion path
            // armed a snap-zone preview (translucent overlay
            // visible), commit the matching snap operation
            // instead of leaving the window at the cursor-
            // released position. No armed zone → the drag ends
            // wherever the cursor landed, exactly as before.
            // The compositor lock is held here (loop acquires
            // it at the top of the body), so call the snap ops
            // directly. Always clear the preview on release so a
            // re-drag starts from a clean slate.
            const duetos::drivers::video::SnapZone zone = duetos::drivers::video::SnapPreviewArmed();
            bool snapped = true;
            switch (zone)
            {
            case duetos::drivers::video::SnapZone::Maximize:
                duetos::drivers::video::WindowMaximize(drag.window);
                break;
            case duetos::drivers::video::SnapZone::Left:
                duetos::drivers::video::WindowSnapLeft(drag.window);
                break;
            case duetos::drivers::video::SnapZone::Right:
                duetos::drivers::video::WindowSnapRight(drag.window);
                break;
            case duetos::drivers::video::SnapZone::TopLeft:
                duetos::drivers::video::WindowSnapTopLeft(drag.window);
                break;
            case duetos::drivers::video::SnapZone::TopRight:
                duetos::drivers::video::WindowSnapTopRight(drag.window);
                break;
            case duetos::drivers::video::SnapZone::BottomLeft:
                duetos::drivers::video::WindowSnapBottomLeft(drag.window);
                break;
            case duetos::drivers::video::SnapZone::BottomRight:
                duetos::drivers::video::WindowSnapBottomRight(drag.window);
                break;
            case duetos::drivers::video::SnapZone::None:
            default:
                snapped = false;
                break;
            }
            SerialWrite(snapped ? "[ui] drag end (snap-zone) window=" : "[ui] drag end window=");
            SerialWriteHex(drag.window);
            SerialWrite("\n");
            drag.active = false;
            duetos::drivers::video::SnapPreviewArm(duetos::drivers::video::SnapZone::None);
            if (snapped)
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
            }
        }
        if (release_edge && sb_drag.active)
        {
            sb_drag.active = false;
            sb_drag.hwnd = duetos::drivers::video::kWindowInvalid;
            SerialWrite("[ui] scrollbar drag end\n");
        }
        if (release_edge && resize.active)
        {
            SerialWrite("[ui] resize end window=");
            SerialWriteHex(resize.window);
            SerialWrite("\n");
            resize.active = false;
            resize.edge = duetos::drivers::video::WindowResizeEdge::None;
        }
        if (release_edge && duetos::drivers::video::TaskbarIsDragging())
        {
            // Snap to whichever horizontal edge the cursor was
            // released over.
            duetos::drivers::video::TaskbarEndDrag(cy);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
            SerialWrite("[ui] taskbar dock -> ");
            SerialWrite(duetos::drivers::video::TaskbarGetDock() == duetos::drivers::video::TaskbarDock::Top
                            ? "top (drag-snap)\n"
                            : "bottom (drag-snap)\n");
        }

        // Mouse-message routing to PE windows. Posts
        // WM_MOUSEMOVE / WM_LBUTTONDOWN / WM_LBUTTONUP to the
        // topmost PE window under the cursor — unless a
        // window has SetCapture'd the mouse, in which case
        // events always go to the captured window regardless
        // of cursor location. Skipped in the obvious
        // compositor-owned states (menu open, mid-drag, over
        // the taskbar / calendar). Close-box presses on a PE
        // re-route to WM_CLOSE (already handled below).
        if (!drag.active && !menu_handled && !duetos::drivers::video::TaskbarContains(cx, cy) &&
            !duetos::drivers::video::MenuIsOpen() && !duetos::drivers::video::CalendarContains(cx, cy))
        {
            const auto captured = duetos::drivers::video::WindowGetCapture();
            const auto pe_hit = (captured != duetos::drivers::video::kWindowInvalid)
                                    ? captured
                                    : duetos::drivers::video::WindowTopmostAt(cx, cy);
            const duetos::u64 pe_pid =
                (pe_hit != duetos::drivers::video::kWindowInvalid) ? duetos::drivers::video::WindowOwnerPid(pe_hit) : 0;
            if (pe_pid > 0)
            {
                constexpr duetos::u32 kWmMouseMove = 0x0200;
                constexpr duetos::u32 kWmLButtonDown = 0x0201;
                constexpr duetos::u32 kWmLButtonUp = 0x0202;
                constexpr duetos::u32 kWmRButtonDown = 0x0204;
                constexpr duetos::u32 kWmRButtonUp = 0x0205;
                constexpr duetos::u32 kWmContextMenu = 0x007B;
                constexpr duetos::u64 kMkLButton = 0x0001;
                constexpr duetos::u64 kMkRButton = 0x0002;
                duetos::u32 wx = 0, wy = 0;
                duetos::drivers::video::WindowGetBounds(pe_hit, &wx, &wy, nullptr, nullptr);
                // Client-local coords. title bar is 22 px by
                // default + 2 px top border; widget chrome
                // uses these constants internally.
                const duetos::i32 client_x = static_cast<duetos::i32>(cx) - static_cast<duetos::i32>(wx) - 2;
                const duetos::i32 client_y = static_cast<duetos::i32>(cy) - static_cast<duetos::i32>(wy) - 22 - 2;
                const duetos::u64 lparam = (static_cast<duetos::u64>(client_x) & 0xFFFF) |
                                           ((static_cast<duetos::u64>(client_y) & 0xFFFF) << 16);
                duetos::u64 wparam = 0;
                if (left_down)
                    wparam |= kMkLButton;
                if (right_down)
                    wparam |= kMkRButton;
                // WM_MOUSEMOVE on every packet that actually
                // moved — dx/dy are signed byte deltas in
                // the PS/2 packet.
                if (p.dx != 0 || p.dy != 0)
                {
                    duetos::drivers::video::WindowPostMessage(pe_hit, kWmMouseMove, wparam, lparam);
                }
                if (press_edge)
                {
                    // Double-click detection: two press edges
                    // within ~500ms (50 ticks @ 100Hz) at the
                    // same pixel on the same HWND fire
                    // WM_LBUTTONDBLCLK (0x0203) instead of a
                    // second WM_LBUTTONDOWN.
                    constexpr duetos::u32 kWmLButtonDblClk = 0x0203;
                    const duetos::u64 kDblClickTicks = duetos::drivers::video::WindowDoubleClickTicks();
                    static duetos::u64 s_last_click_tick = 0;
                    static duetos::drivers::video::WindowHandle s_last_click_hwnd =
                        duetos::drivers::video::kWindowInvalid;
                    static duetos::u32 s_last_click_x = 0;
                    static duetos::u32 s_last_click_y = 0;
                    const duetos::u64 now_tick = duetos::arch::TimerTicks();
                    const bool is_dbl = (s_last_click_hwnd == pe_hit) &&
                                        (now_tick - s_last_click_tick <= kDblClickTicks) && (s_last_click_x == cx) &&
                                        (s_last_click_y == cy);
                    if (is_dbl)
                    {
                        duetos::drivers::video::WindowPostMessage(pe_hit, kWmLButtonDblClk, wparam, lparam);
                        s_last_click_hwnd = duetos::drivers::video::kWindowInvalid;
                    }
                    else
                    {
                        duetos::drivers::video::WindowPostMessage(pe_hit, kWmLButtonDown, wparam, lparam);
                        s_last_click_tick = now_tick;
                        s_last_click_hwnd = pe_hit;
                        s_last_click_x = cx;
                        s_last_click_y = cy;
                    }
                }
                if (release_edge)
                {
                    duetos::drivers::video::WindowPostMessage(pe_hit, kWmLButtonUp, wparam, lparam);
                }
                if (right_press)
                {
                    duetos::drivers::video::WindowPostMessage(pe_hit, kWmRButtonDown, wparam, lparam);
                }
                if (right_release)
                {
                    duetos::drivers::video::WindowPostMessage(pe_hit, kWmRButtonUp, wparam, lparam);
                    // Win32 WM_CONTEXTMENU contract: posted on
                    // RBUTTONUP, wparam = HWND, lparam = SCREEN
                    // coords (not client-local). PE apps decode
                    // with GET_X/Y_LPARAM.
                    const duetos::u64 ctx_lparam =
                        (static_cast<duetos::u64>(cx) & 0xFFFF) | ((static_cast<duetos::u64>(cy) & 0xFFFF) << 16);
                    duetos::drivers::video::WindowPostMessage(pe_hit, kWmContextMenu,
                                                              static_cast<duetos::u64>(pe_hit) + 1, ctx_lparam);
                    SerialWrite("[win32/wm] wm_contextmenu posted hwnd=");
                    SerialWriteHex(pe_hit);
                    SerialWrite(" pid=");
                    SerialWriteHex(pe_pid);
                    SerialWrite("\n");
                }
                duetos::drivers::video::WindowMsgWakeAll();
            }
            else if (pe_hit != duetos::drivers::video::kWindowInvalid && press_edge)
            {
                // Native-window double-click dispatch. Only
                // fires on press_edge for owner_pid == 0
                // windows (kernel apps). Same 500ms / same-
                // pixel / same-hwnd discipline as the PE DC
                // path above. Title-bar DC is handled in the
                // chrome branch (maximize/restore toggle), so
                // a hit here is always client-area.
                const duetos::u64 kNativeDblClickTicks = duetos::drivers::video::WindowDoubleClickTicks();
                static duetos::u64 s_native_dc_tick = 0;
                static duetos::drivers::video::WindowHandle s_native_dc_hwnd = duetos::drivers::video::kWindowInvalid;
                static duetos::u32 s_native_dc_x = 0;
                static duetos::u32 s_native_dc_y = 0;
                const duetos::u64 now_tick = duetos::arch::TimerTicks();
                const bool is_dbl = (s_native_dc_hwnd == pe_hit) &&
                                    (now_tick - s_native_dc_tick <= kNativeDblClickTicks) && (s_native_dc_x == cx) &&
                                    (s_native_dc_y == cy);
                if (is_dbl)
                {
                    if (pe_hit == duetos::apps::files::FilesWindow())
                    {
                        duetos::apps::files::FilesOnDoubleClick(cx, cy);
                    }
                    else if (pe_hit == duetos::apps::browser::BrowserWindow())
                    {
                        duetos::apps::browser::BrowserOnDoubleClick(cx, cy);
                    }
                    else if (pe_hit == duetos::apps::notes::NotesWindow())
                    {
                        duetos::apps::notes::NotesOnDoubleClick(cx, cy);
                    }
                    // Calculator / Calendar / Clock / ImageView
                    // don't have a DC entry point — those
                    // gestures aren't part of their UX.
                    s_native_dc_hwnd = duetos::drivers::video::kWindowInvalid;
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                    duetos::drivers::video::CursorShow();
                }
                else
                {
                    s_native_dc_tick = now_tick;
                    s_native_dc_hwnd = pe_hit;
                    s_native_dc_x = cx;
                    s_native_dc_y = cy;
                }
            }

            // Wheel dispatch — works for native AND PE owners.
            // The dispatcher fans out: PE windows get
            // WM_MOUSEWHEEL posted; native windows invoke their
            // registered WindowWheelFn handler.
            if (p.dz != 0 && pe_hit != duetos::drivers::video::kWindowInvalid)
            {
                duetos::i32 dz = p.dz;
                if (dz > 8)
                    dz = 8;
                if (dz < -8)
                    dz = -8;
                duetos::u32 wx = 0, wy = 0;
                duetos::drivers::video::WindowGetBounds(pe_hit, &wx, &wy, nullptr, nullptr);
                const duetos::i32 client_x = static_cast<duetos::i32>(cx) - static_cast<duetos::i32>(wx) - 2;
                const duetos::i32 client_y = static_cast<duetos::i32>(cy) - static_cast<duetos::i32>(wy) - 22 - 2;
                duetos::u64 mk = 0;
                if (left_down)
                    mk |= 0x0001U;
                if (right_down)
                    mk |= 0x0002U;
                // Modifiers come from the kbd-reader's last
                // published state. Wheel handlers branch on
                // Ctrl (zoom in ImageView) etc.
                const duetos::u8 mods = duetos::drivers::video::WindowModifierState();
                duetos::drivers::video::WindowDispatchWheel(pe_hit, client_x, client_y, dz, cx, cy, mk, mods);
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
                duetos::drivers::video::CursorShow();
            }
        }

        if (drag.active)
        {
            // Position the window so the grabbed pixel stays
            // under the cursor. Any sub-pixel clamp lives
            // inside WindowMoveTo.
            const duetos::u32 nx = (cx > drag.grab_offset_x) ? cx - drag.grab_offset_x : 0;
            const duetos::u32 ny = (cy > drag.grab_offset_y) ? cy - drag.grab_offset_y : 0;
            duetos::drivers::video::WindowMoveTo(drag.window, nx, ny);
            // Aero-style snap-zone hover preview. Hit-test the
            // cursor against the screen-edge / corner bands and
            // arm the preview rect. Re-arming the same zone is a
            // no-op (cheap scalar write); leaving every band
            // clears the armed state so the overlay disappears
            // when the user steers back to the interior.
            duetos::drivers::video::SnapZone zone = duetos::drivers::video::SnapPreviewHitTest(cx, cy);
            if (zone != duetos::drivers::video::SnapZone::None)
            {
                // Suppress the arm when the dragged window
                // already occupies exactly the target rect —
                // the preview would just sit on top of the
                // window's own chrome with nothing to suggest.
                duetos::u32 zx = 0, zy = 0, zw = 0, zh = 0;
                duetos::drivers::video::SnapZoneGetRect(zone, &zx, &zy, &zw, &zh);
                duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
                if (duetos::drivers::video::WindowGetBounds(drag.window, &wx, &wy, &ww, &wh) && wx == zx && wy == zy &&
                    ww == zw && wh == zh)
                {
                    zone = duetos::drivers::video::SnapZone::None;
                }
            }
            duetos::drivers::video::SnapPreviewArm(zone);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
        }
        else if (sb_drag.active)
        {
            // Scrollbar drag — follow the cursor's vertical
            // position, translate via ScrollbarDragTo, dispatch.
            duetos::drivers::video::WindowScrollbarSurface s{};
            if (duetos::drivers::video::WindowGetScrollbar(sb_drag.hwnd, &s))
            {
                const duetos::drivers::video::ScrollbarState state{s.total, s.visible, s.first};
                const duetos::u32 nf =
                    duetos::drivers::video::ScrollbarDragTo(cy, s.y, s.h, sb_drag.grab_offset_in_thumb, state);
                duetos::drivers::video::WindowDispatchScroll(sb_drag.hwnd, nf);
            }
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
        }
        else if (resize.active)
        {
            // Resize-drag: feed the cumulative cursor delta
            // since the press into the resize calc, anchored
            // on the press-time bounds.
            const duetos::i32 dx = static_cast<duetos::i32>(cx) - static_cast<duetos::i32>(resize.anchor_cx);
            const duetos::i32 dy = static_cast<duetos::i32>(cy) - static_cast<duetos::i32>(resize.anchor_cy);
            duetos::drivers::video::WindowResizeFromEdge(resize.window, resize.edge, resize.anchor_x, resize.anchor_y,
                                                         resize.anchor_w, resize.anchor_h, dx, dy);
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
        }
        else
        {
            // Non-drag path: route clicks + motion through the
            // widget table as before. Only reachable when the
            // cursor is NOT pinning a window move; this keeps
            // the button widget inert during drag, matching
            // Windows' "modal drag" semantics.
            const duetos::u32 hit = duetos::drivers::video::WidgetRouteMouse(cx, cy, p.buttons);
            if (hit != duetos::drivers::video::kWidgetInvalid)
            {
                SerialWrite("[ui] widget event id=");
                SerialWriteHex(hit);
                SerialWrite("\n");
                // Dispatch to app-level handlers. Each app
                // claims a private ID range (see Calculator's
                // kIdBase); non-claiming handlers return false
                // and the event is just logged above.
                duetos::apps::calculator::CalculatorOnWidgetEvent(hit);
                duetos::apps::settings::SettingsOnWidgetEvent(hit);
            }
            // Pass D: migrated apps own their own hit-testing and
            // need to see every motion packet so AppButton hover
            // state can track the cursor across tactility themes.
            // Each call is internal-edge-detecting so press / release
            // events still fire exactly once per click.
            duetos::apps::calculator::CalculatorMouseInput(cx, cy, p.buttons);
            duetos::apps::notes::NotesMouseInput(cx, cy, p.buttons);
            duetos::apps::files::FilesMouseInput(cx, cy, p.buttons);
            duetos::apps::taskman::TaskmanMouseInput(cx, cy, p.buttons);
            duetos::apps::settings::SettingsMouseInput(cx, cy, p.buttons);
            duetos::apps::browser::BrowserMouseInput(cx, cy, p.buttons);
            duetos::apps::calendar::CalendarMouseInput(cx, cy, p.buttons);
            duetos::apps::imageview::ImageViewMouseInput(cx, cy, p.buttons);
            duetos::apps::clock::ClockMouseInput(cx, cy, p.buttons);
            duetos::apps::hexview::HexViewMouseInput(cx, cy, p.buttons);
            duetos::apps::notify_center::NotifyCenterMouseInput(cx, cy, p.buttons);
            duetos::apps::charmap::CharMapMouseInput(cx, cy, p.buttons);
            duetos::apps::devicemgr::DeviceMgrMouseInput(cx, cy, p.buttons);
            duetos::apps::firewall::FirewallMouseInput(cx, cy, p.buttons);
            duetos::apps::help::HelpMouseInput(cx, cy, p.buttons);
            duetos::apps::netstatus::NetStatusMouseInput(cx, cy, p.buttons);
            duetos::apps::sysmon::SysmonMouseInput(cx, cy, p.buttons);
            duetos::apps::about::AboutMouseInput(cx, cy, p.buttons);
        }

        // Hover responsiveness: when a menu is open and the
        // highlighted row changed this frame, force an immediate
        // recompose so the highlight tracks the mouse without
        // waiting for the 1 Hz ui-ticker. Gated on an actual
        // hover-row change (not raw motion): a packet that only
        // jiggles the cursor inside one row produces an identical
        // menu and the cursor sprite is already repainted by
        // CursorMove — a full-screen recompose there is the
        // wasted work that overran the PS/2 ring. Skipped during
        // drag (drag has its own compose) and when the menu was
        // already handled (the dispatch path composes too).
        if (!drag.active && !menu_handled && duetos::drivers::video::MenuIsOpen() && menu_hover_changed)
        {
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
        }

        // Same change-gated recompose for the desktop-icon hover highlight:
        // repaint only when the hovered icon changed, never per packet.
        if (!drag.active && !menu_handled && icon_hover_changed)
        {
            duetos::drivers::video::CursorHide();
            duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            duetos::drivers::video::CursorShow();
        }

        duetos::drivers::video::CompositorUnlock();

        // No per-packet trace here. It was a one-shot bring-up aid;
        // logging every PS/2 packet (raw serial, or KLOG_DEBUG which
        // still emits in the debug build operators actually run) is a
        // blocking 115200-baud write per packet. Under continuous
        // motion that monopolised this task across enough consecutive
        // scheduler ticks to trip the soft-lockup detector (val=<tid>
        // of this reader; see kernel/diag/soft_lockup.cpp) and buried
        // every other diagnostic. Continuous motion deltas have no
        // standing diagnostic value; the actionable mouse faults
        // (ring overflow, sync loss) are already KLOG_ONCE_WARN'd in
        // kernel/drivers/input/ps2mouse.cpp, and button/click effects
        // surface as `[ui] ...` events. Re-add a *throttled* trace
        // locally only while actively debugging input.
    }
}

// Win32 timer ticker: walks the per-window timer table every
// scheduler tick and posts WM_TIMER under the compositor lock.
// Doubles as the 100 Hz driver for `WindowAnimateStepAll` — the
// min / max / restore / snap tweens advance one step per call
// here (the only path in the kernel that runs at 100 Hz under
// the compositor lock). When a tween is actively stepping, the
// task forces a `DesktopCompose` so the user sees the motion;
// the 1 Hz `UiTickerTask`'s cadence is too coarse to render
// a ~100 ms transition smoothly.
void WinTimerTickerTask(void*)
{
    auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };
    // Wallpaper motion runs at ~25 FPS nominal. This task fires every
    // 10 ms (SchedSleepTicks(1) = 1 scheduler tick = 10 ms); every 4th
    // call is 40 ms ≈ 25 FPS nominal. Effective FPS depends on how long
    // each DesktopCompose takes (~25-30 ms on VBox, so effective ~8 Hz);
    // on QEMU/real-HW DesktopCompose is faster and you get closer to the
    // 25 Hz nominal. Previously kWallpaperSubDiv was 7 which targeted
    // 14 Hz but VBox delivered 4 Hz — slideshow territory. Drop to 4.
    static u32 s_wallpaper_sub = 0;
    static constexpr u32 kWallpaperSubDiv = 4; // 10 ms × 4 = 40 ms ≈ 25 FPS nominal
    for (;;)
    {
        duetos::sched::SchedSleepTicks(1);
        duetos::drivers::video::CompositorLock();
        duetos::drivers::video::WindowTimerTick();
        const bool anim_stepped = duetos::drivers::video::WindowAnimateStepAll();

        // Advance ambient wallpaper motion at ~15 FPS. WallpaperTick()
        // updates arc rotation, pulse, and topo drift phases then marks
        // dirty rects. Skip during the login gate (LoginRepaint owns the
        // framebuffer) and in TTY mode (no wallpaper is painted there).
        const bool gate_active =
            duetos::core::LoginIsActive() && duetos::core::LoginCurrentMode() == duetos::core::LoginMode::Gui;
        const bool is_tty = duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty;
        bool wallpaper_ticked = false;
        if (!gate_active && !is_tty)
        {
            if (++s_wallpaper_sub >= kWallpaperSubDiv)
            {
                s_wallpaper_sub = 0;
                duetos::drivers::video::WallpaperTick();
                wallpaper_ticked = true;
            }
        }

        if (anim_stepped || wallpaper_ticked)
        {
            // Skip recompose while the login gate owns the framebuffer or
            // in TTY mode — desktop-only affordance.
            //
            // CursorHide/Show is no longer needed: DesktopCompose now
            // paints the cursor sprite into the offscreen buffer via
            // CursorOverlayInCompose, and cursor.cpp's DrawAt/RestoreAt
            // call FramebufferInvalidateSnapshot to force-blit cursor's
            // prior live-FB positions. Together these eliminate cursor
            // flash entirely without ghosts, lag, or trails.
            if (!gate_active && !is_tty)
            {
                duetos::drivers::video::DesktopCompose(desktop_bg(), nullptr);
            }
        }
        duetos::drivers::video::CompositorUnlock();
    }
}

// Scheduler self-test worker: bumps a mutex-guarded shared
// counter five times, exercising the wait-queue slow path.
void SchedDemoWorkerTask(void* arg)
{
    using namespace duetos::arch;
    const char* name = static_cast<const char*>(arg);
    for (duetos::u64 i = 0; i < 5; ++i)
    {
        duetos::sched::MutexLock(&s_demo_mutex);

        const duetos::u64 before = s_shared_counter;
        // Burn a couple of ms of CPU inside the critical section so
        // that other workers are almost guaranteed to hit the slow
        // path on MutexLock and park on the wait queue. Without this
        // the race is too tight for the self-test to be meaningful.
        for (duetos::u64 j = 0; j < 2'000'000; ++j)
        {
            asm volatile("" ::: "memory");
        }
        s_shared_counter = before + 1;

        {
            // Bracket the 7 Write*s so a peer worker / loadtest can't
            // split the line. Mirrors the AP-bringup + stress-driver
            // line-guard pattern from the 2026-05-22 SMP-saturation
            // slice — `[sched] A i=... counter=...` was a top
            // offender under SMP=8 stress (`LOADTEST: requesting 8
            // CPU worker(s) for [sched] 8C i=0x...`).
            arch::SerialLineGuard guard;
            SerialWrite("[sched] ");
            SerialWrite(name);
            SerialWrite(" i=");
            SerialWriteHex(i);
            SerialWrite(" counter=");
            SerialWriteHex(s_shared_counter);
            SerialWrite("\n");
        }

        duetos::sched::MutexUnlock(&s_demo_mutex);
        duetos::sched::SchedSleepTicks(1); // yield + 10 ms pause
    }
}
} // namespace duetos::core
