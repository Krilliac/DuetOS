// See boot_tasks.h. Mechanical extraction of the kernel_main
// boot-task lambdas; bodies are byte-identical.

#include "core/boot_tasks.h"

#include "apps/sysmon.h"
#include "core/session_restore.h"
#include "diag/fix_journal_persist.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "log/klog_persist.h"
#include "sched/sched.h"
#include "security/login.h"

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

} // namespace duetos::core
