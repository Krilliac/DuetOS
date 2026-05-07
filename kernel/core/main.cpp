/*
 * DuetOS — kernel entry + boot orchestrator.
 *
 * WHAT
 *   The single file that wires every kernel subsystem together.
 *   `kernel_main` is what `boot.S` jumps to once long mode +
 *   higher-half mapping are live. From here every other subsystem
 *   (mm, sched, drivers, FS, Win32) is brought up in dependency
 *   order, then the scheduler is started and control transfers
 *   to the idle loop / first user task.
 *
 * HOW
 *   The body of `kernel_main` is intentionally one long top-down
 *   sequence rather than a tree of init routines. Boot order is
 *   load-bearing — if frame_allocator runs before the Multiboot2
 *   memory map is parsed, you get a triple fault — and the linear
 *   form makes the order legible at a glance. Read the file from
 *   `kernel_main` downward; each block has a `// === Phase: <name>`
 *   header.
 *
 *   Subsystems split into their own TUs; this file only owns the
 *   *call sequence*. The order is approximately:
 *     early console -> physmem map -> paging -> heap -> IDT/GDT ->
 *     APIC + timer -> SMP AP bringup -> scheduler online -> drivers
 *     (PCIe, NVMe, GPU, input) -> VFS -> Win32 / Linux subsystems
 *     -> first user task.
 *
 *   Build-flag knobs: DUETOS_PANIC_DEMO / DUETOS_TRAP_DEMO /
 *   DUETOS_CANARY_DEMO / DUETOS_ATTACK_SIM toggle deliberate
 *   late-boot stress paths for testing the recovery / dump
 *   plumbing. None of them ship in a release preset.
 *
 * WHY THIS FILE IS LARGE
 *   The kernel has a lot of subsystems and they all need to be
 *   wired in *somewhere*. We could decompose `kernel_main` into
 *   per-phase helpers, but the trade is "shorter file" against
 *   "boot order is now spread over a dozen TUs" — and getting boot
 *   order wrong is a triple-fault, not a unit-test failure. One
 *   long readable function wins.
 */

#include "util/adler32.h"
#include "util/base64.h"
#include "util/build_config.h"
#include "util/crc32.h"
#include "util/bmp.h"
#include "util/datetime.h"
#include "util/deflate.h"
#include "util/gzip.h"
#include "util/png.h"
#include "util/tga.h"
#include "util/types.h"
#include "util/unicode.h"
#include "acpi/acpi.h"
#include "acpi/aml.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cet.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_mitigations.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/thermal.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/lbr.h"
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "cpu/percpu.h"
#include "cpu/topology.h"
#include "debug/breakpoints.h"
#include "debug/extable.h"
#include "debug/probes.h"
#include "debug/tripwire.h"
#include "debug/watch.h"
#include "drivers/audio/audio.h"
#include "drivers/audio/hda.h"
#include "drivers/audio/hda_jack.h"
#include "drivers/audio/hda_jack_inventory.h"
#include "drivers/gpu/cea861.h"
#include "drivers/gpu/cvt.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/edid.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/gpu_resources.h"
#include "drivers/gpu/intel_gsc_fw.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/net/bcm43xx_fw.h"
#include "drivers/net/bcm43xx_upload.h"
#include "drivers/net/iwlwifi_fw.h"
#include "drivers/net/iwlwifi_rings.h"
#include "drivers/net/iwlwifi_upload.h"
#include "drivers/net/net.h"
#include "drivers/net/rtl88xx_fw.h"
#include "drivers/net/rtl88xx_upload.h"
#include "net/bluetooth/diag.h"
#include "net/bluetooth/hci.h"
#include "net/wireless/beacon.h"
#include "crypto/aes.h"
#include "crypto/aes_keywrap.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "crypto/prf.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "net/wireless/eapol.h"
#include "net/wireless/fourway.h"
#include "net/wireless/mlme.h"
#include "net/wireless/test/wireless_e2e_test.h"
#include "net/wireless/wdev.h"
#include "net/wireless/wifi_diag.h"
#include "drivers/mei/mei.h"
#include "drivers/pci/pci.h"
#include "drivers/power/power.h"
#include "drivers/usb/cdc_ecm.h"
#include "drivers/usb/hid_descriptor.h"
#include "drivers/usb/msc_scsi.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "net/net_smoke.h"
#include "net/firewall.h"
#include "net/stack.h"
#include "subsystems/graphics/graphics.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/block.h"
#include "drivers/storage/nvme.h"
#include "fs/duetfs.h"
#include "fs/exfat.h"
#include "fs/ext4.h"
#include "fs/fat32.h"
#include "fs/file_route.h"
#include "fs/gpt.h"
#include "fs/ntfs.h"
#include "apps/calculator.h"
#include "apps/about.h"
#include "apps/browser.h"
#include "apps/calendar.h"
#include "apps/clock.h"
#include "apps/notify_center.h"
#include "apps/devicemgr.h"
#include "apps/files.h"
#include "apps/firewall.h"
#include "apps/dbg.h"
#include "apps/gfxdemo.h"
#include "apps/help.h"
#include "apps/imageview.h"
#include "apps/netstatus.h"
#include "apps/notes.h"
#include "apps/screenshot.h"
#include "apps/settings.h"
#include "apps/taskman.h"
#include "apps/trash.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/svg.h"
#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"
#include "drivers/video/wallpaper.h"
#include "generated_chrome_font.h"
#include "drivers/video/calendar.h"
#include "drivers/video/magnifier.h"
#include "drivers/video/dialog.h"
#include "drivers/video/dnd.h"
#include "drivers/video/menu.h"
#include "drivers/video/modal_input.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/start_menu_apps.h"
#include "drivers/video/netpanel.h"
#include "drivers/video/notify.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/theme.h"
#include "drivers/video/tray_flyout.h"
#include "drivers/video/widget.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/mount.h"
#include "fs/vfs.h"
#include "mm/address_space.h"
#include "mm/dma.h"
#include "mm/frame_allocator.h"
#include "mm/zone.h"
#include "ipc/handle_table.h"
#include "diag/event_trace.h"
#include "diag/fault_react.h"
#include "diag/fix_journal.h"
#include "diag/fix_journal_persist.h"
#include "diag/gdb_server.h"
#include "diag/minidump.h"
#include "diag/perf_profile.h"
#include "diag/soft_lockup.h"
#include "ipc/kevent.h"
#include "ipc/kfile.h"
#include "ipc/kmailbox.h"
#include "ipc/kmutex.h"
#include "ipc/kobject.h"
#include "ipc/ksemaphore.h"
#include "ipc/kwaitable.h"
#include "sync/lockdep.h"
#include "sync/rcu.h"
#include "sync/rwlock.h"
#include "sync/seqlock.h"
#include "sync/spinlock.h"
#include "time/clocksource.h"
#include "time/tick.h"
#include "time/timekeeper.h"
#include "time/timezone.h"
#include "diag/cleanroom_trace.h"
#include "security/auth.h"
#include "security/auth_pentest.h"
#include "security/cap_audit.h"
#include "loader/firmware_loader.h"
#include "diag/heartbeat.h"
#include "log/klog.h"
#include "log/klog_persist.h"
#include "power/reboot.h"
#include "security/login.h"
#include "core/init.h"
#include "core/panic.h"
#include "core/serial_input.h"
#include "core/session_restore.h"
#include "syscall/cap_gate.h"
#include "proc/process.h"
#include "util/random.h"
#include "security/domain_dump.h"
#include "security/driver_domain.h"
#include "security/fault_domain.h"
#include "security/module.h"
#include "diag/diag_decode.h"
#include "diag/hexdump.h"
#include "util/result.h"
#include "util/string.h"
#include "proc/ring3_smoke.h"
#include "diag/runtime_checker.h"
#include "diag/ubsan.h"
#include "subsystems/linux/ring3_smoke.h"
#include "subsystems/linux/syscall.h"
#include "subsystems/win32/custom_selftest.h"
#include "subsystems/win32/gdi_objects.h"
#include "subsystems/win32/nt_coverage.h"
#include "subsystems/win32/registry.h"
#include "subsystems/win32/window_syscall.h"
#include "loader/dll_loader.h"
#include "loader/elf_loader.h"
#include "shell/shell.h"
#include "syscall/syscall.h"
#include "mm/kheap.h"
#include "mm/kstack.h"
#include "mm/multiboot2.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "security/attack_sim.h"
#include "security/canary.h"
#include "security/event_ring.h"
#include "security/guard.h"
#include "security/ir_runbook.h"
#include "security/password_hash.h"
#include "security/pentest_gui.h"
#include "security/policy.h"
#include "security/purple_team.h"
#include "test/smoke_profile.h"

/*
 * Kernel entry in C++. Called by kernel/arch/x86_64/boot.S once the CPU is
 * in 64-bit long mode with a valid stack and the first 1 GiB of physical
 * memory identity-mapped.
 *
 * Current scope: bring up descriptors, parse the Multiboot2 memory map,
 * hand the frame allocator a working bitmap, run its self-test, carve a
 * fixed-size pool out for the kernel heap and self-test it, adopt the
 * boot PML4 + run the paging self-test, mask the legacy 8259, bring up
 * the LAPIC, calibrate + arm the LAPIC timer at 100 Hz, start the
 * scheduler with three workers contending on a shared mutex (exercising
 * the new wait-queue blocking path), then drop into the idle loop with
 * interrupts enabled. SMP and userland are separate follow-up commits.
 */

#ifdef DUETOS_CANARY_DEMO
// Deliberately overrun a stack buffer so the function's epilogue
// stack-canary check fails on return. Volatile + asm sink prevent
// the optimiser from eliding the out-of-bounds stores. MUST return
// normally — the stack-protector epilogue runs on `ret`, and we
// want the __stack_chk_fail tail-call to happen.
//
// No __attribute__((no_stack_protector)) here — the WHOLE POINT is
// that this function DOES have a canary the compiler can check.
[[gnu::noinline]] static void CanarySmashDemo()
{
    volatile duetos::u8 buf[8] = {};
    for (int i = 0; i < 64; ++i)
    {
        buf[i] = static_cast<duetos::u8>(i);
    }
    asm volatile("" : : "r"(&buf[0]) : "memory");
}
#endif

namespace
{

// Storage for the chrome font handle. Populated by the
// chrome-font-load initcall once at boot; outlives the registration
// because TtfChromeFontSet stores a borrowed pointer.
constinit duetos::drivers::video::TtfFont g_chrome_font_storage{};

// Cached copy of the boot cmdline. Populated on the first
// FindBootCmdline call that resolves a non-null string while the
// Multiboot2 info struct is still reachable through the low
// identity map (early boot, before MmFinalizePaging tears that
// map down). Later callers — KbdReader / ui-ticker setup at
// kernel_main+~4300, the `idlelock=<seconds>` parser, anything
// running after the heavy boot phases — read from this cache
// instead of re-walking the original info buffer at the now-
// unmapped low VA.
//
// 4 KiB is well over Multiboot2's per-tag size for cmdline (the
// loader caps it at 1 KiB on every implementation we've
// surveyed); a longer string truncates with a trailing NUL
// rather than corrupting adjacent data.
constinit char g_boot_cmdline_cache[4096] = {};
constinit bool g_boot_cmdline_cached = false;

// Walk the Multiboot2 tag list for type-1 (boot cmdline) and
// return its NUL-terminated string, or nullptr if absent.
//
// Caches the result on first success: subsequent calls hand back
// the cached copy without dereferencing `info_phys`. This is
// required because `info_phys` is the LOW identity-mapped address
// the boot loader handed us, and that mapping disappears once
// MmFinalizePaging tears the early page tables down. A late-boot
// caller passing the same `info_phys` would page-fault inside
// this function (observed in CI as `arch/traps msg="#PF Page
// fault" cr2=0x92000` at FindBootCmdline+0x40, with the bringup
// smoke crashing right after `[bringup-tail] kbd-reader spawned`).
const char* FindBootCmdline(duetos::uptr info_phys)
{
    if (g_boot_cmdline_cached)
    {
        return g_boot_cmdline_cache[0] != '\0' ? g_boot_cmdline_cache : nullptr;
    }
    if (info_phys == 0)
    {
        return nullptr;
    }
    const auto* info = reinterpret_cast<const duetos::mm::MultibootInfoHeader*>(info_phys);
    duetos::uptr cursor = info_phys + sizeof(duetos::mm::MultibootInfoHeader);
    const duetos::uptr end = info_phys + info->total_size;
    while (cursor < end)
    {
        const auto* tag = reinterpret_cast<const duetos::mm::MultibootTagHeader*>(cursor);
        if (tag->type == duetos::mm::kMultibootTagEnd)
        {
            break;
        }
        if (tag->type == duetos::mm::kMultibootTagCmdline)
        {
            // String starts right after the 8-byte {type, size} header.
            const char* src = reinterpret_cast<const char*>(cursor + sizeof(duetos::mm::MultibootTagHeader));
            // Copy into the cache so callers after MmFinalizePaging
            // still have a valid pointer. Truncate at the buffer
            // size minus 1 to keep the trailing NUL.
            duetos::usize i = 0;
            while (i + 1 < sizeof(g_boot_cmdline_cache) && src[i] != '\0')
            {
                g_boot_cmdline_cache[i] = src[i];
                ++i;
            }
            g_boot_cmdline_cache[i] = '\0';
            g_boot_cmdline_cached = true;
            return g_boot_cmdline_cache;
        }
        cursor += (tag->size + 7u) & ~duetos::uptr{7};
    }
    // No cmdline tag — record the absence so a re-call short-
    // circuits without re-walking the (potentially-unmapped) info.
    g_boot_cmdline_cache[0] = '\0';
    g_boot_cmdline_cached = true;
    return nullptr;
}

// Return true iff `cmdline` contains the whitespace-delimited
// token "key=value" where `value` matches `want`. Case-sensitive.
// A nullptr cmdline returns false. This is the smallest thing
// that'll work for "boot=tty" / "boot=desktop"; a full parser
// lands with the first cmdline-heavy consumer.
bool CmdlineMatches(const char* cmdline, const char* key, const char* want)
{
    if (cmdline == nullptr)
    {
        return false;
    }
    // Walk tokens. A token is a run of non-whitespace, separated
    // by spaces. Compare key prefix + '=' then the value tail.
    const char* p = cmdline;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t')
        {
            ++p;
        }
        if (*p == '\0')
        {
            break;
        }
        const char* token = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
        {
            ++p;
        }
        // [token, p) is the current token.
        // Match key+'=' prefix.
        const char* k = key;
        const char* t = token;
        while (*k != '\0' && t < p && *t == *k)
        {
            ++k;
            ++t;
        }
        if (*k == '\0' && t < p && *t == '=')
        {
            ++t;
            // Compare [t, p) against want.
            const char* w = want;
            while (*w != '\0' && t < p && *t == *w)
            {
                ++t;
                ++w;
            }
            if (*w == '\0' && t == p)
            {
                return true;
            }
        }
    }
    return false;
}

// Print a concise, user-facing keyboard-shortcut + getting-started
// reference into the framebuffer console. Called from F1 and from
// the Start menu's HELP item — both paths land here so the text
// stays in one place. Lines are kept short enough to fit the
// 80-column console without wrapping. ASCII only because the font
// driver maps lowercase to uppercase anyway.
void PrintShortcutHelp()
{
    using duetos::drivers::video::ConsoleWriteln;
    ConsoleWriteln("");
    ConsoleWriteln("==== DUETOS QUICK REFERENCE ===================");
    ConsoleWriteln("  GETTING STARTED");
    ConsoleWriteln("    CLICK [START] (BOTTOM-LEFT) TO LAUNCH APPS");
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

// Dispatch a menu action_id to the side-effect that backs it.
// Shared between mouse_reader (left-click on item) and kbd_reader
// (Enter on hovered item). The caller is responsible for the
// surrounding flow — closing the menu, hiding/showing the cursor,
// and recomposing. This function does no compositing of its own.
//
// `action` is the action_id from the menu's MenuItem table; 0 is
// reserved for "no item" and never reaches here. `ctx` is the
// ambient MenuContext() at fire time — for window menus it's the
// target WindowHandle (the system menu uses ctx for the same).
//
// New action-id bands grow this switch; the master allocation
// table lives in the comment above `kernel_main`'s ui closures.
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
    // Files-app row context menu (action ids 30..33). ctx = the
    // row index in the FAT32 listing, captured at MenuOpen time.
    // The Files app's own dispatcher knows what to do with each
    // row id; we route there. RENAME (31) is a known v0 GAP —
    // there's no text-input modal yet; it just notifies the user.
    case 30: // FILES — OPEN
    case 31: // FILES — RENAME (GAP)
    case 32: // FILES — DELETE
    case 33: // FILES — PROPERTIES
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

} // namespace

extern "C" void kernel_main(duetos::u32 multiboot_magic, duetos::uptr multiboot_info)
{
    using namespace duetos::arch;
    using namespace duetos::mm;

    SerialInit();
    SerialWrite("[boot] DuetOS kernel reached long mode.\n");

    // klog online as early as Serial. Self-test prints one line at
    // each severity so visual inspection of the early boot log
    // confirms the tag format + u64-value form are working. Trace
    // calls are gated by the runtime threshold — boot-time default
    // is keyed off `core::kKlogDefaultLevel` (Debug for debug
    // builds, Info for release). Use `loglevel <t|d|i|w|e>` at the
    // shell to flip live.
    duetos::core::KLogSelfTest();

    // Build-flavor banner. Single line so the boot log reader can
    // see at a glance which preset produced this image — useful
    // when crash reports come in from different builds. The
    // sub-knobs match the ones declared in CMakeLists.txt and
    // surfaced by build_config.h.
    SerialWrite("[boot] DuetOS build flavor: ");
    SerialWrite(duetos::core::BuildFlavorName());
    if constexpr (duetos::core::kAssertsEnabled)
    {
        SerialWrite(" +asserts");
    }
    if constexpr (duetos::core::kBootSelfTests)
    {
        SerialWrite(" +selftests");
    }
    if constexpr (duetos::core::kLockOrderAudit)
    {
        SerialWrite(" +lockaudit");
    }
    if constexpr (duetos::core::kCapAuditMode == duetos::core::CapAuditMode::Full)
    {
        SerialWrite(" +capaudit=full");
    }
    else if constexpr (duetos::core::kCapAuditMode == duetos::core::CapAuditMode::Sample)
    {
        SerialWrite(" +capaudit=sample");
    }
    if constexpr (duetos::core::kUbsanRuntime)
    {
        SerialWrite(" +ubsan");
    }
    if constexpr (duetos::core::kKaslrEnabled)
    {
        SerialWrite(" +kaslr");
    }
    if constexpr (duetos::core::kKlogCompileFloor == 0)
    {
        // Trace-level call sites compiled in. Worth surfacing —
        // operators looking at a forensic-release banner expect to
        // see this so they know `loglevel t` will produce output.
        SerialWrite(" +trace");
    }
    SerialWrite("\n");

    constexpr duetos::u32 kMultiboot2BootMagic = 0x36D76289;
    if (multiboot_magic == kMultiboot2BootMagic)
    {
        SerialWrite("[boot] Multiboot2 handoff verified.\n");
    }
    else
    {
        SerialWrite("[boot] WARNING: unexpected boot magic.\n");
    }

    SerialWrite("[boot] Probing CPU features.\n");
    duetos::arch::CpuInfoProbe();
    duetos::arch::CpuMitigationsProbe();
    duetos::arch::CetProbe();

    SerialWrite("[boot] Detecting hypervisor.\n");
    duetos::arch::HypervisorProbe();

    SerialWrite("[boot] Probing SMBIOS.\n");
    duetos::arch::SmbiosInit();

    SerialWrite("[boot] Reading MSR thermals.\n");
    duetos::arch::ThermalProbe();

    // Phase::Earlycon — utility-primitive self-tests (Result /
    // String / Hexdump / VaRegion). All four panic on failure, so
    // each adapter just calls + returns Ok. Registered here rather
    // than in their own TUs because there is no `_init_array`
    // invocation yet (see init.h's trailing NOTE) — when a future
    // slice wires `_init_array`, these registrations migrate into
    // the source TUs alongside the test definitions and
    // `kernel_main` keeps only the `RunPhase(...)` line.
    // (A1-followup, 2026-04-27.)
    //
    // The four Earlycon adapters are pure self-tests — they don't
    // double as init code, so a release build with
    // `kBootSelfTests == false` skips them entirely. The
    // `if constexpr` makes the registration AND the self-test
    // body dead code that the optimizer drops; the boot log loses
    // four lines but gains ~one millisecond on a slow VM.
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Earlycon, "result-selftest",
                                       []()
                                       {
                                           SerialWrite("[boot] Exercising Result<T,E> + TRY primitives.\n");
                                           duetos::core::ResultSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Earlycon, "string-selftest",
                                       []()
                                       {
                                           SerialWrite("[boot] Exercising freestanding memset/memcpy/memmove.\n");
                                           duetos::core::StringSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Earlycon, "hexdump-selftest",
                                       []()
                                       {
                                           SerialWrite("[boot] Exercising kernel-VA range + hexdump formatters.\n");
                                           duetos::core::HexdumpSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(
            duetos::core::Phase::Earlycon, "varegion-selftest",
            []()
            {
                SerialWrite("[boot] Exercising VA-region classifier (panic / trap dump annotation).\n");
                duetos::core::VaRegionSelfTest();
                return duetos::core::Result<void>{};
            });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Earlycon);

    // One-shot mm-map anchor for every later panic dump. The region
    // tags on cr2/rsp/rbp/rip in a crash record map back to the
    // ranges printed here without forcing the operator to consult
    // paging.h / kstack.h / linker.ld separately.
    duetos::core::WriteMmMapSummary();

    SerialWrite("[boot] Exercising process / capability helpers.\n");
    DUETOS_BOOT_SELFTEST(duetos::core::ProcessSelfTest());

    SerialWrite("[boot] Exercising kernel registry helpers.\n");
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::registry::RegistrySelfTest());

    SerialWrite("[boot] Seeding kernel entropy pool.\n");
    duetos::core::RandomInit();
    DUETOS_BOOT_SELFTEST(duetos::core::RandomSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::Crc32SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::Base64SelfTest());
    // NOTE: The stack canary has already been randomized from RDTSC
    // in boot.S before kernel_main was called. The C++ helper
    // `RandomizeStackCanary` in stack_canary.cpp is kept as an API
    // that future slices can use to re-randomize (e.g. per-task
    // canary rotation) but it's NOT called from kernel_main —
    // kernel_main is huge and its stashed prologue value would
    // drift from any mid-function re-randomization attempt.

    SerialWrite("[boot] Installing kernel GDT.\n");
    GdtInit();

    SerialWrite("[boot] Installing IDT (all 256 vectors).\n");
    IdtInit();

    SerialWrite("[boot] Installing TSS + IST stacks (#DF / #MC / #NMI).\n");
    TssInit();
    IdtSetIst(2, kIstNmi);           // #NMI
    IdtSetIst(8, kIstDoubleFault);   // #DF
    IdtSetIst(18, kIstMachineCheck); // #MC

    SerialWrite("[boot] Installing syscall gate (int 0x80, DPL=3).\n");
    duetos::core::SyscallInit();

    // Phase::Idt — Slice-80 trap surface check. Issues an int3
    // (kernel-mode #BP, must recover via
    // TrapResponse::LogAndContinue) and an int 0x42 (spurious
    // vector, must recover via TrapDispatch's spurious branch).
    // If either regresses the kernel halts here and the boot log
    // shows the cause. (A1-followup, 2026-04-28.)
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Idt, "traps-selftest",
                                       []()
                                       {
                                           TrapsSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Idt);

#ifdef DUETOS_GDB_SERVER
    // Wire COM2 to the in-kernel GDB stub as early as possible —
    // immediately after the IDT comes online so the trap-dispatch
    // path (which routes int3 / #DB into the stop loop) is itself
    // armed. Gated behind DUETOS_GDB_SERVER because a wired stub
    // with no attached debugger would hang the kernel on the
    // first int3 (the stop loop blocks waiting for packets that
    // will never arrive).
    duetos::diag::gdb::GdbServerInitCom2();
    SerialWrite("[gdb-stub] COM2 wired (115200 8N1) — connect via QEMU's tcp::1234 server\n");
#endif

    // The DUETOS_GDB_DEMO int3 fires LATER in kernel_main, after
    // BpInit() (so debug::BpInstallSoftware works — GDB's Z0
    // patches int3 into .text via that subsystem, which itself
    // needs paging.SetPteFlags4K to flip the page writable, which
    // needs paging.SplitPsPage to split the boot 2 MiB
    // superpage). Wiring the demo too early panics with
    // `mm/paging: SplitPsPage: PML4 entry not present` because
    // PagingInit hasn't installed g_pml4 yet.

    // Kernel extable — scoped fault recovery. Register before any
    // subsystem tries to install its own rows; the user-copy
    // helpers are always entry 0 / 1.
    SerialWrite("[boot] Bringing up kernel extable.\n");
    duetos::arch::TrapsRegisterExtable();
    DUETOS_BOOT_SELFTEST(duetos::debug::ExtableSelfTest());

    // Fault-domain registry self-test. Registers a toy domain,
    // restarts it twice, checks counters. Real driver domains are
    // registered later in boot once their subsystems are up.
    DUETOS_BOOT_SELFTEST(duetos::core::FaultDomainSelfTest());

    // Self-defensive fault-reaction dispatcher. Verifies the
    // policy + floor + decay paths against a toy domain so a
    // regression in the dispatcher is loud at boot rather than
    // discovered the next time a real driver hits a fault.
    DUETOS_BOOT_SELFTEST(duetos::diag::FaultReactSelfTest());

    // Per-driver fault-domain extension self-test (plan E3).
    // Wraps the core fault-domain registry with a driver-tag
    // convention; demo register/restart cycle.
    DUETOS_BOOT_SELFTEST(duetos::security::DriverDomainSelfTest());

    // Module lifecycle layer over FaultDomain. Verifies the
    // ModuleState transitions (Stopped/Running/Crashed), the
    // refusal paths (start-when-Running, stop-when-Stopped),
    // and the init-failure recovery edge.
    DUETOS_BOOT_SELFTEST(duetos::security::ModuleSelfTest());

    // Per-domain non-fatal crash dump emitter. Verifies the
    // Begin/End pair, the recent-dumps ring, and the replay
    // path. Output to COM1 is a witness of the dump format.
    DUETOS_BOOT_SELFTEST(duetos::security::DomainDumpSelfTest());

    // Register one real driver as a driver fault domain
    // (plan E3-followup, 2026-04-28). The soft-lockup detector
    // has a clean Enable/Disable pair so it's the natural first
    // candidate; other drivers register as their teardown
    // story matures. `RestartDriverDomain("soft-lockup")` from
    // the shell now drives the detector through a clean
    // disable+enable cycle.
    duetos::security::RegisterDriverDomain(
        "soft-lockup",
        []() -> ::duetos::core::Result<void>
        {
            duetos::diag::SoftLockupEnable();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::diag::SoftLockupDisable();
            return {};
        });
    // Lockdep as a driver domain (E3-followup, 2026-04-28).
    // Restart re-baselines the edge graph + clears the held
    // stack — useful after triaging a noisy boot to start
    // fresh without rebooting.
    duetos::security::RegisterDriverDomain(
        "lockdep",
        []() -> ::duetos::core::Result<void>
        {
            duetos::sync::LockdepRegisterCanonicalClasses();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::sync::LockdepReset();
            return {};
        });
    // Event-trace + perf-profile as driver domains. Restart
    // wipes the relevant ring so an operator can re-baseline
    // before kicking off a measurement run.
    duetos::security::RegisterDriverDomain(
        "event-trace", []() -> ::duetos::core::Result<void> { return {}; },
        []() -> ::duetos::core::Result<void>
        {
            duetos::diag::EventTraceReset();
            return {};
        });
    duetos::security::RegisterDriverDomain(
        "perf", []() -> ::duetos::core::Result<void> { return {}; },
        []() -> ::duetos::core::Result<void>
        {
            duetos::diag::PerfReset();
            return {};
        });
    // NMI watchdog as a driver domain. Restart cycles
    // Disable + Init — useful if a long-running diagnostic
    // session needs the watchdog quiet for a window then
    // re-armed.
    duetos::security::RegisterDriverDomain(
        "nmi-watchdog",
        []() -> ::duetos::core::Result<void>
        {
            duetos::arch::NmiWatchdogInit();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::arch::NmiWatchdogDisable();
            return {};
        });
    // Cleanroom-trace ring (separate from event_trace; older
    // syscall flight-recorder). Has a clean-clear API; restart
    // wipes the buffer.
    duetos::security::RegisterDriverDomain(
        "cleanroom-trace", []() -> ::duetos::core::Result<void> { return {}; },
        []() -> ::duetos::core::Result<void>
        {
            duetos::core::CleanroomTraceClear();
            return {};
        });
    // Runtime checker — boot-baseline + per-scan integrity checks.
    // Restart re-captures the baseline (control regs, IDT/GDT
    // hashes, .text spot hashes, etc.) — useful after an operator
    // legitimately mutated something the checker would otherwise
    // flag, e.g. swapping a stale IDT entry during a triage
    // session. Teardown clears the baseline-captured gate so the
    // next init's KASSERT passes.
    duetos::security::RegisterDriverDomain(
        "runtime-checker",
        []() -> ::duetos::core::Result<void>
        {
            duetos::core::RuntimeCheckerInit();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::core::RuntimeCheckerTeardown();
            return {};
        });
    // Breakpoint subsystem — software int3 + hardware DR-slot
    // tables backing the kernel debugger and GDB stub. Restart
    // disarms every DR slot, drops every table row, and clears
    // the inited flag so a fresh BpInit runs cleanly. Useful
    // after a flaky GDB session left orphaned int3 traps the
    // operator wants to clear without rebooting.
    duetos::security::RegisterDriverDomain(
        "breakpoints",
        []() -> ::duetos::core::Result<void>
        {
            duetos::debug::BpInit();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::debug::BpTeardown();
            return {};
        });
    // Linear framebuffer — the firmware-handoff direct-pixel
    // surface every console / splash / compositor path lowers
    // onto. Restart is useful after a virtio-gpu mode-set
    // attempt left the surface in a half-configured state, or
    // when an operator wants to re-snapshot the boot-time
    // baseline without a reboot.
    duetos::security::RegisterDriverDomain(
        "framebuffer",
        []() -> ::duetos::core::Result<void>
        {
            duetos::drivers::video::FramebufferReinit();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::drivers::video::FramebufferTeardown();
            return {};
        });
    // PCI bus enumeration — the parent of every PCIe device
    // driver in the tree. Restart is useful after the operator
    // hot-plugs a device through QEMU's monitor (or a real
    // PCIe slot) and wants the device table re-walked without
    // rebooting; downstream drivers (nvme / ahci / xhci /
    // e1000 / gpu) need their own restarts to pick up the new
    // BAR / MSI-X assignments.
    duetos::security::RegisterDriverDomain(
        "pci",
        []() -> ::duetos::core::Result<void>
        {
            duetos::drivers::pci::PciEnumerate();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::drivers::pci::PciTeardown();
            return {};
        });
    // AHCI / SATA — the storage controller for every
    // pre-NVMe drive in the supported HW matrix. Restart
    // frees per-port DMA scratch buffers + re-walks PCI for
    // newly-attached SATA drives. Block-device handles leak
    // until the block layer grows an Unregister (documented
    // in AhciTeardown).
    duetos::security::RegisterDriverDomain(
        "ahci",
        []() -> ::duetos::core::Result<void>
        {
            duetos::drivers::storage::AhciInit();
            return {};
        },
        []() -> ::duetos::core::Result<void>
        {
            duetos::drivers::storage::AhciTeardown();
            return {};
        });
    // Wave-1 fault-domain registrations are now self-registered
    // via KERNEL_INITCALL(Drivers, "<name>.module", ...) at each
    // driver's TU — picked up by the `RunPhase(Phase::Drivers)`
    // call later in this function. Migrated subsystems:
    // ramfs, nvme, drivers/gpu, drivers/net, drivers/audio,
    // fs/fat32. Pattern documented in
    // `wiki/security/Kernel-Modularization.md`.

    // Init-call registry self-test (plan A1). Exercises register +
    // RunPhase + bad-argument + failing-callback paths against the
    // fixed-size table in `core/init.cpp`. The infrastructure is
    // landed; migration of `kernel_main`'s imperative call list to
    // the registry is deferred (see plan A1 follow-up).
    DUETOS_BOOT_SELFTEST(duetos::core::InitSelfTest());

    // UBSAN klog runtime (plan D5). The kernel is not currently
    // compiled with `-fsanitize=undefined`, so none of the
    // `__ubsan_handle_*` symbols are reachable from real code at
    // boot — the self-test invokes the report path directly to
    // confirm the runtime is linked in. Day a future debug preset
    // turns the compile flag on, the symbols are already here.
    DUETOS_BOOT_SELFTEST(duetos::diag::UbsanSelfTest());

    // SyscallGateSelfTest moved to AFTER PerCpuInitBsp — its
    // denial path calls RecordSandboxDenial → CurrentTask() →
    // CurrentCpu(), which reads GSBASE. Running it before the
    // BSP per-CPU struct is installed reads whatever GSBASE the
    // firmware left behind: zero / harmless under OVMF, real-
    // mode IVT under SeaBIOS (the BSP shadow page contains
    // 0xf000:ffff IVT entries that look like non-null pointers,
    // pass the null-check in RecordSandboxDenial, and #GP-fault
    // when the synthetic Task* is dereferenced for ->process).
    // The self-test now runs once GSBASE has been programmed and
    // current_task is the well-defined nullptr from the constinit
    // PerCpu literal.

    SerialWrite("[boot] Parsing Multiboot2 memory map.\n");
    FrameAllocatorInit(multiboot_info);

    SerialWrite("  total frames : ");
    SerialWriteHex(TotalFrames());
    SerialWrite("\n");
    SerialWrite("  free frames  : ");
    SerialWriteHex(FreeFramesCount());
    SerialWrite("\n");

    // Phase::PhysMem (plan A1-followup, continued migration). The
    // FrameAllocator's init has inter-dependencies with the
    // multiboot parse above, so it stays imperative — the
    // VERIFICATION step (`FrameAllocatorSelfTest`) is the part
    // that fits cleanly into the registry. Same pattern follows
    // for Heap below: init imperative, self-test through
    // RunPhase. As more subsystems gain init() functions whose
    // ordering is verifiable through phase membership alone, the
    // imperative tail shrinks.
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::PhysMem, "frame-allocator-selftest",
                                       []()
                                       {
                                           FrameAllocatorSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // Robustness — frame allocator OOM injection hook used by
        // the loader unwind self-tests below.
        duetos::core::InitcallRegister(duetos::core::Phase::PhysMem, "frame-oom-injection-selftest",
                                       []()
                                       {
                                           duetos::mm::FrameAllocatorOomInjectionSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // mm/zone scaffold (plan C1) — additive layer over the
        // global frame allocator; v0 forwards every zone request
        // to the same pool.
        duetos::core::InitcallRegister(duetos::core::Phase::PhysMem, "zone-selftest",
                                       []()
                                       {
                                           ZoneSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // mm/dma — DMA-coherent buffer allocation. Sits on top of
        // the per-zone contiguous-frame allocator; the first real
        // consumers are the iwlwifi TFD/RBD rings + (when they
        // land) AHCI + Intel HDA CORB. See `dma-coherent-v0.md`.
        duetos::core::InitcallRegister(duetos::core::Phase::PhysMem, "dma-selftest",
                                       []()
                                       {
                                           DmaSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::PhysMem);

    SerialWrite("[boot] Bringing up kernel heap.\n");
    KernelHeapInit();
    // Walk _init_array AFTER the heap is online (any constructor
    // that needs to allocate is now safe). v0 entry count is
    // typically 0 — kernel TUs use `constinit` — but invoking
    // the table closes the "silent partial-init" gap A1-followup
    // identified.
    duetos::core::RunInitArray();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Heap, "kernel-heap-selftest",
                                       []()
                                       {
                                           KernelHeapSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Heap);

    KLOG_METRICS("boot", "after-kernel-heap");

    SerialWrite("[boot] Bringing up paging.\n");
    PagingInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Paging, "paging-selftest",
                                       []()
                                       {
                                           PagingSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Paging);

    // Kernel-stack guard-paged arena — runs here because it needs
    // the managed paging API (PagingInit) for MapPage / UnmapPage
    // but must be online before any SchedCreate call uses it.
    DUETOS_BOOT_SELFTEST(duetos::mm::KernelStackSelfTest());
    // Kernel-image W^X / DEP — split the 2 MiB PS direct map covering
    // the kernel image into 4 KiB pages, then apply per-section flags:
    //   .text  → R + X   (writes to .text now #PF)
    //   .rodata → R      (writes or execution from .rodata now #PF)
    //   .data/.bss → R + W (execution from .data/.bss now #PF)
    //
    // MUST run AFTER PagingInit adopted the boot PML4 + enabled
    // EFER.NXE, and BEFORE anything else needs .rodata strings. No
    // subsystem below this point should be writing to .text; if any
    // of them does, the fault will fire here at boot rather than
    // corrupt code silently later.
    ProtectKernelImage();

    // Breakpoint subsystem (int3 + DR0..DR3). Must run AFTER
    // ProtectKernelImage so we know .text is at its final 4 KiB-
    // granular protection and SetPteFlags4K can flip the W bit
    // for a BP install. Runs BEFORE SMP bring-up so the single-
    // CPU invariant the BP installer asserts is still true.
    duetos::debug::BpInit();
    if (!duetos::debug::BpSelfTest())
    {
        SerialWrite("[boot] WARN: breakpoint self-test failed — see serial log\n");
    }
    // Named hardware-watchpoint wrapper — exercises the on-hit
    // dispatch + counter + remove path on a stack-local. Uses one
    // DR slot transiently and releases it before returning. See
    // kernel/debug/watch.h for the public API and `bp watch …`
    // for the operator-facing surface.
    if constexpr (duetos::core::kBootSelfTests)
    {
        if (!duetos::debug::WatchSelfTest())
        {
            SerialWrite("[boot] WARN: watchpoint self-test failed — see serial log\n");
        }
        // Software-tripwire counterpart to Watch — exercises CRC32
        // baseline / scribble-detect / refresh / remove on a stack-
        // local buffer. No hardware DR slots involved; the table is
        // pure .bss. See kernel/debug/tripwire.h.
        if (!duetos::debug::TripwireSelfTest())
        {
            SerialWrite("[boot] WARN: tripwire self-test failed — see serial log\n");
        }
    }

#ifdef DUETOS_GDB_DEMO
    // Deliberate int3 so the AI / dev can exercise the full
    // attach + inspect + continue cycle without staging a real
    // crash. Fires HERE (after BpInit) so GDB's Z0 packets can
    // round-trip through debug::BpInstallSoftware → PokeByte →
    // SetPteFlags4K — every layer is now online. The stop loop
    // blocks until GDB attaches AND issues `c` / `D` / `k`.
    // Build with -DDUETOS_GDB_DEMO=ON to enable.
    SerialWrite("[gdb-demo] firing int3 — kernel pauses until GDB attaches + continues\n");
    asm volatile("int3");
    SerialWrite("[gdb-demo] resumed from GDB int3 — kernel_main continues\n");
#endif
    // Static probes — KBP_PROBE(...) call sites sprinkled across
    // the kernel. Rare+useful events (panic, sandbox denial,
    // Win32 stub miss, kernel #PF) are armed-log by default so
    // the first boot shows activity without any arming.
    duetos::debug::ProbeInit();

    // Fix journal — observe-and-record gap detector. Recorders
    // must be live BEFORE the syscall surface starts taking real
    // calls so an unknown syscall on the first ring3 spawn lands
    // a record. Init zeroes the .bss ring and resets stats; the
    // selftest synthesizes one record per detector kind and
    // verifies dedup + mark-done. Per Design-Decision #016 this
    // is observe-only; nothing in the journal mutates kernel
    // state.
    duetos::diag::FixJournalInit();
    DUETOS_BOOT_SELFTEST(duetos::diag::FixJournalSelfTest());

    // Phase::Drivers — framebuffer is the only "driver" with a
    // self-test that fits the registry shape today; PCI/NVMe/USB
    // self-tests are inline checks rather than separately-named
    // SelfTest functions. (A1-followup, 2026-04-28.)
    SerialWrite("[boot] Bringing up framebuffer (if present).\n");
    duetos::drivers::video::FramebufferInit(multiboot_info);
    // Initialise the DPMS bookkeeper (record state = On, no driver
    // hook). Settings shutdown/reboot transition to Off before the
    // firmware-level shutdown, so any on-screen state matches the
    // power request.
    duetos::drivers::gpu::DpmsInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Drivers, "framebuffer-selftest",
                                       []()
                                       {
                                           duetos::drivers::video::FramebufferSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Drivers, "ttf-selftest",
                                       []()
                                       {
                                           duetos::drivers::video::TtfSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Drivers, "ttf-raster-selftest",
                                       []()
                                       {
                                           duetos::drivers::video::TtfRasterSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Drivers, "svg-selftest",
                                       []()
                                       {
                                           duetos::drivers::video::SvgSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    // Load the embedded chrome font (Liberation Sans Regular, SIL OFL
    // 1.1) and register it for the TTF dispatch path. Once registered,
    // the 5 Duet-family themes' window-title paint stops falling back
    // to the bitmap font and renders via the slice-4 rasterizer.
    duetos::core::InitcallRegister(
        duetos::core::Phase::Drivers, "chrome-font-load",
        []()
        {
            const auto* bytes = duetos::drivers::video::generated::kBinChromeFontBytes;
            const auto size = static_cast<duetos::u32>(sizeof(duetos::drivers::video::generated::kBinChromeFontBytes));
            auto r = duetos::drivers::video::TtfLoad(bytes, size);
            if (r.has_value())
            {
                g_chrome_font_storage = r.value();
                duetos::drivers::video::TtfChromeFontSet(&g_chrome_font_storage);
                duetos::arch::SerialWrite("[boot] chrome font (Liberation Sans) loaded + registered\n");
            }
            else
            {
                duetos::arch::SerialWrite("[boot] chrome font load FAILED — staying on bitmap fallback\n");
            }
            return duetos::core::Result<void>{};
        });
    // Parse the embedded wallpaper SVGs once into static SvgImage
    // instances. WallpaperPaint then layers them on the matching
    // theme paints (DuetMark + topo for Duet family; syscalls grid
    // for Slate10).
    duetos::core::InitcallRegister(duetos::core::Phase::Drivers, "wallpaper-svg-init",
                                   []()
                                   {
                                       duetos::drivers::video::WallpaperSvgInit();
                                       return duetos::core::Result<void>{};
                                   });
    (void)duetos::core::RunPhase(duetos::core::Phase::Drivers);

    // GUI composition. Order for every paint pass:
    //   1. Desktop fill
    //   2. Desktop banner text
    //   3. Windows in z-order (back-to-front)
    //   4. Widgets (buttons on top of windows for v0)
    //   5. Cursor on top (CursorShow re-samples backing)
    //
    // Wrapped in a file-scope helper so both the initial boot
    // paint AND the window-drag path (mouse reader thread) can
    // repaint the whole surface with one call.
    //
    // Initial theme selection honours the kernel cmdline
    // (theme=classic / theme=slate10 / theme=amber / theme=duet);
    // default is the classic teal palette the first GUI slice
    // shipped. Ctrl+Alt+Y cycles at runtime.
    {
        const char* early_cmdline = FindBootCmdline(multiboot_info);
        for (int i = 0; i < static_cast<int>(duetos::drivers::video::ThemeId::kCount); ++i)
        {
            const auto id = static_cast<duetos::drivers::video::ThemeId>(i);
            if (CmdlineMatches(early_cmdline, "theme", duetos::drivers::video::ThemeIdName(id)))
            {
                duetos::drivers::video::ThemeSet(id);
                break;
            }
        }
    }
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::ThemeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::NotifySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::MagnifierSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::time::TimezoneSelfTest());
    const auto& theme0 = duetos::drivers::video::ThemeCurrent();

    // CALCULATOR — native DuetOS app. Window chrome first,
    // then CalculatorInit registers its 16 buttons + content
    // drawer against the returned handle. Width / height are
    // sized to fit the 4x4 keypad (4 * 68 + 3 * 4 = 284 px
    // wide + 2 * 8 inset = 300; 4 * 36 + 3 * 4 + 60 top
    // inset + 4 bottom = 220). Colours come from the active
    // theme so Ctrl+Alt+Y re-hues without touching layout.
    using Role = duetos::drivers::video::ThemeRole;
    auto theme_chrome = [&](Role role)
    {
        duetos::drivers::video::WindowChrome c{};
        c.colour_border = theme0.window_border;
        c.colour_title = theme0.role_title[static_cast<duetos::u32>(role)];
        c.colour_client = theme0.role_client[static_cast<duetos::u32>(role)];
        c.colour_close_btn = theme0.window_close;
        c.title_height = 22;
        return c;
    };

    duetos::drivers::video::WindowChrome win_a_chrome = theme_chrome(Role::Calculator);
    win_a_chrome.x = 60;
    win_a_chrome.y = 60;
    win_a_chrome.w = 300;
    // Bumped from 220 to fit the multi-radix preview band that
    // sits between the main display strip and the 4x4 button grid.
    win_a_chrome.h = 260;
    const duetos::drivers::video::WindowHandle calc_handle =
        duetos::drivers::video::WindowRegister(win_a_chrome, "CALCULATOR");
    duetos::drivers::video::ThemeRegisterWindow(Role::Calculator, calc_handle);
    duetos::apps::calculator::CalculatorInit(calc_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::calculator::CalculatorSelfTest());

    duetos::drivers::video::WindowChrome win_b_chrome = theme_chrome(Role::Notes);
    win_b_chrome.x = 500;
    win_b_chrome.y = 100;
    win_b_chrome.w = 380;
    win_b_chrome.h = 200;
    // NOTEPAD — native DuetOS notes app. The content-draw
    // callback is installed inside NotesInit; the kbd-reader
    // thread below routes keystrokes here when this window
    // is active (focus == keyboard owner).
    const duetos::drivers::video::WindowHandle notes_handle =
        duetos::drivers::video::WindowRegister(win_b_chrome, "NOTEPAD");
    duetos::drivers::video::ThemeRegisterWindow(Role::Notes, notes_handle);
    duetos::apps::notes::NotesInit(notes_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::notes::NotesSelfTest());

    // Task Manager window — a window whose content drawer
    // prints live scheduler + memory stats. The ui-ticker's
    // 1 Hz recompose refreshes it for free.
    duetos::drivers::video::WindowChrome taskman_chrome = theme_chrome(Role::TaskManager);
    taskman_chrome.x = 180;
    taskman_chrome.y = 310;
    // Bigger default size for the 5-column per-task list — the
    // original 340x170 aggregate-stats panel is too narrow to
    // host PID + NAME + STATE + CPU% + TICKS without truncation.
    taskman_chrome.w = 520;
    taskman_chrome.h = 260;
    const duetos::drivers::video::WindowHandle taskman_handle =
        duetos::drivers::video::WindowRegister(taskman_chrome, "TASK MANAGER");
    duetos::drivers::video::ThemeRegisterWindow(Role::TaskManager, taskman_handle);

    // Live log viewer window — renders a compact view of the
    // klog ring (the same ring `dmesg` prints). Refreshes every
    // ui-ticker beat, so kernel activity appears without the
    // user having to flip consoles.
    duetos::drivers::video::WindowChrome logview_chrome = theme_chrome(Role::LogView);
    logview_chrome.x = 560;
    logview_chrome.y = 310;
    logview_chrome.w = 420;
    logview_chrome.h = 180;
    const duetos::drivers::video::WindowHandle logview_handle =
        duetos::drivers::video::WindowRegister(logview_chrome, "KERNEL LOG");
    duetos::drivers::video::ThemeRegisterWindow(Role::LogView, logview_handle);
    // Subtitle for Duet-era chrome to render next to the title.
    // Themes that don't read it (Classic / Slate10 / Amber)
    // ignore the field; the storage is unconditional.
    duetos::drivers::video::WindowSetSubtitle(logview_handle, "/sys/klog | live");

    duetos::drivers::video::WindowSetContentDraw(
        logview_handle,
        [](duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, void*)
        {
            // Shared state so the klog chunk callback knows
            // where to render. Compositor mutex is held
            // around the whole compose so these statics are
            // race-free.
            //
            // Severity colouring: the first chunk per log line
            // is always the 4-byte tag ("[I] " / "[W] " / "[E] "
            // / "[D] ") from LevelTag(). We inspect it and set
            // the line's fg; subsequent chunks on the same line
            // inherit that colour until the newline resets.
            constexpr duetos::u32 kFgInfo = 0x00A0C8FF;  // muted blue-white
            constexpr duetos::u32 kFgWarn = 0x00FFD860;  // amber
            constexpr duetos::u32 kFgError = 0x00FF6050; // soft red
            constexpr duetos::u32 kFgDebug = 0x00808080; // grey
            struct Render
            {
                duetos::u32 cx, cy, col, row, max_col, max_row, fg, bg;
                bool done;
            };
            static Render r;
            r.cx = cx;
            r.cy = cy;
            r.col = 0;
            r.row = 0;
            r.max_col = cw / 8;
            r.max_row = ch / 10;
            r.fg = kFgInfo;
            // Match the window's current client fill so text cells
            // blend cleanly into the chrome after a theme switch.
            r.bg = duetos::drivers::video::ThemeCurrent()
                       .role_client[static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::LogView)];
            r.done = false;
            duetos::core::DumpLogRingTo(
                [](const char* s)
                {
                    if (r.done || s == nullptr)
                        return;
                    // Severity detection: first char per chunk
                    // is '[' for the tag chunks klog emits.
                    // Other chunks (subsystem, message) don't
                    // start with '[' so won't match.
                    if (s[0] == '[' && s[2] == ']')
                    {
                        switch (s[1])
                        {
                        case 'I':
                            r.fg = kFgInfo;
                            break;
                        case 'W':
                            r.fg = kFgWarn;
                            break;
                        case 'E':
                            r.fg = kFgError;
                            break;
                        case 'D':
                            r.fg = kFgDebug;
                            break;
                        default:
                            break;
                        }
                    }
                    while (*s != '\0')
                    {
                        const char c = *s++;
                        if (c == '\n')
                        {
                            ++r.row;
                            r.col = 0;
                            if (r.row >= r.max_row)
                            {
                                r.done = true;
                                return;
                            }
                            continue;
                        }
                        if (r.col >= r.max_col)
                        {
                            ++r.row;
                            r.col = 0;
                            if (r.row >= r.max_row)
                            {
                                r.done = true;
                                return;
                            }
                        }
                        duetos::drivers::video::FramebufferDrawChar(r.cx + r.col * 8, r.cy + r.row * 10, c, r.fg, r.bg);
                        ++r.col;
                    }
                });
        },
        nullptr);

    // Per-task list with sort + kill — see kernel/apps/taskman.cpp.
    // Replaces the original 7-row aggregate-stats panel; the
    // header still shows CPU% / IDLE% / MEM totals, then a row
    // per task with PID, name, state, since-boot CPU%, and ticks.
    duetos::apps::taskman::TaskmanInit(taskman_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::taskman::TaskmanSelfTest());

    // FILES — native DuetOS file browser. Lists the ramfs
    // trusted root; Up/Down to move, Enter to descend, Backspace
    // or 'B' to go back.
    duetos::drivers::video::WindowChrome files_chrome = theme_chrome(Role::Files);
    files_chrome.x = 220;
    files_chrome.y = 160;
    files_chrome.w = 400;
    files_chrome.h = 200;
    const duetos::drivers::video::WindowHandle files_handle =
        duetos::drivers::video::WindowRegister(files_chrome, "FILES");
    duetos::drivers::video::ThemeRegisterWindow(Role::Files, files_handle);
    duetos::apps::files::FilesInit(files_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::files::FilesSelfTest());

    // CLOCK — 7-segment-style wall clock. No input, refreshes
    // via the 1 Hz ui-ticker. Sized tight around the digit row
    // (6 digits + 2 colons + gaps) with room for a date line.
    duetos::drivers::video::WindowChrome clock_chrome = theme_chrome(Role::Clock);
    clock_chrome.x = 640;
    clock_chrome.y = 520;
    clock_chrome.w = 240;
    clock_chrome.h = 110;
    const duetos::drivers::video::WindowHandle clock_handle =
        duetos::drivers::video::WindowRegister(clock_chrome, "CLOCK");
    duetos::drivers::video::ThemeRegisterWindow(Role::Clock, clock_handle);
    duetos::apps::clock::ClockInit(clock_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::clock::ClockSelfTest());

    // GFX DEMO — native graphics demonstration. Renders a per-
    // pixel computed image (RGB gradient + sine-wave overlay +
    // concentric rings) into its window's client area, exercising
    // the same FramebufferPutPixel / FramebufferFillRect /
    // FramebufferDrawString primitives that the DirectX v0 path
    // uses internally. Visible proof that the kernel's pixel
    // pipeline produces real graphical output, not just glyphs.
    duetos::drivers::video::WindowChrome gfx_chrome = theme_chrome(Role::GfxDemo);
    gfx_chrome.x = 900;
    gfx_chrome.y = 40;
    gfx_chrome.w = 340;
    gfx_chrome.h = 280;
    const duetos::drivers::video::WindowHandle gfx_handle =
        duetos::drivers::video::WindowRegister(gfx_chrome, "GFX DEMO");
    duetos::drivers::video::ThemeRegisterWindow(Role::GfxDemo, gfx_handle);
    duetos::apps::gfxdemo::GfxDemoInit(gfx_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::gfxdemo::GfxDemoSelfTest());

    // DEBUGGER — native interactive debugger app (memory view +
    // edit, regs, breakpoints, watchlist, byte-pattern scan,
    // disassembly). DbgInit registers its own window via
    // WindowRegister using a Slate-10-friendly chrome, so we
    // don't pre-register one here.
    duetos::apps::dbg::DbgInit();
    DUETOS_BOOT_SELFTEST(duetos::apps::dbg::DbgSelfTest());

    // SETTINGS — unified panel that wraps the Ctrl+Alt chord
    // surfaces (theme cycle / direct picker, opacity step, high-
    // contrast preset, default reset) plus a wall-clock and
    // about readout. Hidden by default; raised from the Start
    // menu's SETTINGS entry.
    duetos::drivers::video::WindowChrome settings_chrome = theme_chrome(Role::Settings);
    settings_chrome.x = 320;
    settings_chrome.y = 100;
    settings_chrome.w = 380;
    settings_chrome.h = 340;
    const duetos::drivers::video::WindowHandle settings_handle =
        duetos::drivers::video::WindowRegister(settings_chrome, "SETTINGS");
    duetos::drivers::video::ThemeRegisterWindow(Role::Settings, settings_handle);
    duetos::apps::settings::SettingsInit(settings_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsSelfTest());

    // IMAGE VIEWER — opens BMP files from the FAT32 root volume.
    // Pairs with the Screenshot app (Ctrl+Alt+P): every capture
    // lands as a 32-bpp top-down BMP this viewer accepts byte-
    // for-byte. Hidden by default; raised from the Start menu's
    // IMAGE VIEWER entry. N/P cycle images, R re-scans the root.
    duetos::drivers::video::WindowChrome image_chrome = theme_chrome(Role::ImageView);
    image_chrome.x = 280;
    image_chrome.y = 90;
    image_chrome.w = 460;
    image_chrome.h = 360;
    const duetos::drivers::video::WindowHandle image_handle =
        duetos::drivers::video::WindowRegister(image_chrome, "IMAGE VIEWER");
    duetos::drivers::video::ThemeRegisterWindow(Role::ImageView, image_handle);
    duetos::apps::imageview::ImageViewInit(image_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::imageview::ImageViewSelfTest());

    // ABOUT — windowed system-info readout. Replaces the legacy
    // two-line "ABOUT DUETOS" console message; raised from the
    // Start menu's ABOUT entry. Refreshes on every compositor
    // tick so uptime + heap counters update visibly.
    duetos::drivers::video::WindowChrome about_chrome = theme_chrome(Role::About);
    about_chrome.x = 360;
    about_chrome.y = 140;
    about_chrome.w = 360;
    about_chrome.h = 220;
    const duetos::drivers::video::WindowHandle about_handle =
        duetos::drivers::video::WindowRegister(about_chrome, "ABOUT DUETOS");
    duetos::drivers::video::ThemeRegisterWindow(Role::About, about_handle);
    duetos::apps::about::AboutInit(about_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::about::AboutSelfTest());

    // HELP — windowed shortcut reference. F1 + Start-menu HELP /
    // SHORTCUTS still print to the framebuffer console (so the
    // text survives a console scrollback); this window is the
    // discovery surface for someone seeing DuetOS for the first
    // time. Static content list — see kernel/apps/help.cpp.
    duetos::drivers::video::WindowChrome help_chrome = theme_chrome(Role::Help);
    help_chrome.x = 200;
    help_chrome.y = 50;
    help_chrome.w = 380;
    help_chrome.h = 480;
    const duetos::drivers::video::WindowHandle help_handle =
        duetos::drivers::video::WindowRegister(help_chrome, "HELP");
    duetos::drivers::video::ThemeRegisterWindow(Role::Help, help_handle);
    duetos::apps::help::HelpInit(help_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::help::HelpSelfTest());

    // BROWSER — minimal HTTP-only browser. Hidden by default;
    // raised from the Start menu's BROWSER entry. Each fetch
    // spawns a one-shot kernel task so the input thread stays
    // responsive.
    duetos::drivers::video::WindowChrome browser_chrome = theme_chrome(Role::Browser);
    browser_chrome.x = 100;
    browser_chrome.y = 60;
    browser_chrome.w = 640;
    browser_chrome.h = 460;
    const duetos::drivers::video::WindowHandle browser_handle =
        duetos::drivers::video::WindowRegister(browser_chrome, "BROWSER");
    duetos::drivers::video::ThemeRegisterWindow(Role::Browser, browser_handle);
    duetos::apps::browser::BrowserInit(browser_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::BrowserSelfTest());

    // CALENDAR — windowed month-view sibling of the read-only
    // taskbar-clock popup. Lets the user page through past / future
    // months. Hidden by default; raised from the Start menu's
    // CALENDAR entry. T jumps back to today.
    duetos::drivers::video::WindowChrome calendar_chrome = theme_chrome(Role::Calendar);
    calendar_chrome.x = 240;
    calendar_chrome.y = 80;
    calendar_chrome.w = 360;
    calendar_chrome.h = 280;
    const duetos::drivers::video::WindowHandle calendar_handle =
        duetos::drivers::video::WindowRegister(calendar_chrome, "CALENDAR");
    duetos::drivers::video::ThemeRegisterWindow(Role::Calendar, calendar_handle);
    duetos::apps::calendar::CalendarInit(calendar_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::calendar::CalendarSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::calendar::CalendarPersistSelfTest());

    // NOTIFICATION CENTER — windowed reader over the toast
    // history ring kept in drivers/video/notify.cpp. Same
    // info-panel chrome family as Calendar / Browser / About.
    duetos::drivers::video::WindowChrome notify_chrome = theme_chrome(Role::NotifyCenter);
    notify_chrome.x = 280;
    notify_chrome.y = 120;
    notify_chrome.w = 380;
    notify_chrome.h = 240;
    const duetos::drivers::video::WindowHandle notify_handle =
        duetos::drivers::video::WindowRegister(notify_chrome, "NOTIFICATIONS");
    duetos::drivers::video::ThemeRegisterWindow(Role::NotifyCenter, notify_handle);
    duetos::apps::notify_center::NotifyCenterInit(notify_handle);

    // NETWORK STATUS — read-only viewer over net::stack accessors.
    // No ThemeRole today; the chrome is seeded from Settings'
    // palette so it sits in the same slate-grey "tools" family.
    {
        duetos::drivers::video::WindowChrome chrome = theme_chrome(Role::Settings);
        chrome.x = 220;
        chrome.y = 110;
        chrome.w = 480;
        chrome.h = 260;
        const duetos::drivers::video::WindowHandle h = duetos::drivers::video::WindowRegister(chrome, "NETWORK STATUS");
        duetos::drivers::video::WindowSetVisible(h, false);
        duetos::apps::netstatus::NetStatusInit(h);
        DUETOS_BOOT_SELFTEST(duetos::apps::netstatus::NetStatusSelfTest());
    }

    // DEVICE MANAGER — read-only PCI device list.
    {
        duetos::drivers::video::WindowChrome chrome = theme_chrome(Role::TaskManager);
        chrome.x = 260;
        chrome.y = 130;
        chrome.w = 460;
        chrome.h = 320;
        const duetos::drivers::video::WindowHandle h = duetos::drivers::video::WindowRegister(chrome, "DEVICE MANAGER");
        duetos::drivers::video::WindowSetVisible(h, false);
        duetos::apps::devicemgr::DeviceMgrInit(h);
        DUETOS_BOOT_SELFTEST(duetos::apps::devicemgr::DeviceMgrSelfTest());
    }

    // FIREWALL — empty-state placeholder; honest about the absent
    // filter subsystem. See apps/firewall.h for the GAP marker.
    {
        duetos::drivers::video::WindowChrome chrome = theme_chrome(Role::Settings);
        chrome.x = 300;
        chrome.y = 150;
        chrome.w = 440;
        chrome.h = 240;
        const duetos::drivers::video::WindowHandle h = duetos::drivers::video::WindowRegister(chrome, "FIREWALL");
        duetos::drivers::video::WindowSetVisible(h, false);
        duetos::apps::firewall::FirewallInit(h);
    }

    // Framebuffer text console. 80x40 chars of boot log at the
    // bottom of the desktop, under the windows in z-order. Dragging
    // a window over it occludes; moving away restores.
    // Taskbar across the bottom of the framebuffer. Placed at
    // runtime so a different resolution still anchors correctly.
    {
        const auto fb_info = duetos::drivers::video::FramebufferGet();
        // Per-theme taskbar height — Duet family ships 36 px,
        // others ship 28. The fallback (theme.taskbar_height
        // == 0 from a stale palette in a future ABI bump) keeps
        // the historical 28-px strip so the chrome stays
        // recognizable.
        const duetos::u32 tb_h = (theme0.taskbar_height != 0) ? theme0.taskbar_height : 28u;
        const duetos::u32 tb_y = (fb_info.height > tb_h) ? fb_info.height - tb_h : 0;
        duetos::drivers::video::TaskbarInit(tb_y, tb_h, theme0.taskbar_bg, theme0.taskbar_fg, theme0.taskbar_accent,
                                            theme0.taskbar_tab_inactive, theme0.taskbar_border);
    }

    // Menu action ids. Ambient MenuContext() carries a target
    // (window handle) for context-menu items that need one.
    //   1..9   — desktop / global actions (ignore context)
    //   10     — raise window (context = WindowHandle)
    //   11     — close window (context = WindowHandle)
    // Range scheme keeps the dispatcher's switch table readable
    // and leaves room for future desktop / window actions without
    // reshuffling ids.

    duetos::drivers::video::ConsoleInit(16, 400, theme0.console_fg, theme0.console_bg);

    // Publish theme0's palette into every chrome owner that
    // didn't already get its colours via Init (the taskbar +
    // console did, the start menu didn't). After this point any
    // theme-cycle hotkey simply re-runs the same publish path.
    duetos::drivers::video::ThemeApplyToAll();

    // Tee kernel log lines to the on-screen console so the desktop
    // shows subsystem activity live — not just the boot seed block.
    // Forwards chunks through ConsoleWrite; no DesktopCompose is
    // triggered here (ui-ticker recomposes at 1 Hz, and user input
    // forces a recompose on demand). IRQ-time klogs race the kbd
    // reader on the char buffer but the damage is bounded to one
    // garbled line at worst; the authoritative log ring is serial.
    // Klog lines route to the dedicated klog console buffer.
    // Ctrl+Alt+F2 switches the render target to that buffer so
    // the user sees live kernel log output; Ctrl+Alt+F1 goes
    // back to the interactive shell buffer. Both consoles share
    // the same screen origin so the flip is in-place.
    duetos::core::SetLogTee([](const char* s) { duetos::drivers::video::ConsoleWriteKlog(s); });

    // File sink: tee every Info+ log line into /tmp/boot.log on tmpfs.
    // Accumulates chunks until a newline arrives, then appends the
    // whole line. tmpfs caps files at 512 bytes — once that fills,
    // further appends silently truncate, so the file captures the
    // earliest boot-critical Info+ lines. Once a real FS lands, swap
    // the sink for an on-disk writer and remove the cap.
    duetos::core::SetLogFileSink(
        [](const char* s)
        {
            static char line[256];
            static duetos::u32 len = 0;
            if (s == nullptr)
                return;
            while (*s != 0)
            {
                if (len < sizeof(line) - 1)
                {
                    line[len++] = *s;
                }
                if (*s == '\n')
                {
                    duetos::fs::TmpFsAppend("boot.log", line, len);
                    len = 0;
                }
                ++s;
            }
        });
    duetos::drivers::video::ConsoleWriteln("DUETOS BOOT LOG");
    duetos::drivers::video::ConsoleWriteln("=================");
    duetos::drivers::video::ConsoleWriteln("");
    duetos::drivers::video::ConsoleWriteln("LONG-MODE KERNEL        OK");
    duetos::drivers::video::ConsoleWriteln("GDT IDT TSS IST         OK");
    duetos::drivers::video::ConsoleWriteln("PAGING W^X SMEP SMAP    OK");
    duetos::drivers::video::ConsoleWriteln("FRAME ALLOCATOR / HEAP  OK");
    duetos::drivers::video::ConsoleWriteln("ACPI MADT FADT MCFG     OK");
    duetos::drivers::video::ConsoleWriteln("LAPIC IOAPIC HPET       OK");
    duetos::drivers::video::ConsoleWriteln("SCHEDULER + BLOCKING    OK");
    duetos::drivers::video::ConsoleWriteln("PS/2 KEYBOARD           OK");
    duetos::drivers::video::ConsoleWriteln("PS/2 MOUSE              OK");
    duetos::drivers::video::ConsoleWriteln("PCI ENUMERATION         OK");
    duetos::drivers::video::ConsoleWriteln("FRAMEBUFFER + FONT      OK");
    duetos::drivers::video::ConsoleWriteln("WINDOW MANAGER v0       OK");
    duetos::drivers::video::ConsoleWriteln("");
    duetos::drivers::video::ConsoleWriteln("READY.  TRY DRAGGING A WINDOW BY ITS TITLE BAR.");

    // Account subsystem — seed the built-in admin/guest
    // accounts, run the verify/reject self-test, then arm the
    // login gate below. Order matters: the gate consults the
    // account table, so AuthInit must precede LoginStart.
    duetos::core::AuthInit();
    DUETOS_BOOT_SELFTEST(duetos::core::AuthSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::AuthBruteForceProbe());

    // Shell welcome + initial prompt. Landing here after every
    // subsystem init line keeps the boot log visible above the
    // prompt — the user sees the tail end of the kernel's own
    // output, then their own typing cursor.
    duetos::core::ShellInit();

    // Demo clickable button, owned by window A. x/y are offsets
    // (The CLICK ME demo button previously registered here has
    // been removed — the window it lived in is now the Calculator,
    // which registers its own 4x4 keypad via CalculatorInit above.)

    // Initial display mode. Priority:
    //   1. Runtime kernel cmdline "boot=tty" / "boot=desktop"
    //      (Multiboot2 tag 1 — set via GRUB menu entry).
    //   2. Compile-time DUETOS_BOOT_TTY fallback.
    //   3. Desktop (default).
    // Runtime Ctrl+Alt+T still flips regardless after boot.
    const char* cmdline = FindBootCmdline(multiboot_info);
    if (cmdline != nullptr)
    {
        SerialWrite("[boot] cmdline: \"");
        SerialWrite(cmdline);
        SerialWrite("\"\n");
    }
    // Pin the qemu-smoke profile early. Read once, cached. If the
    // cmdline carries `smoke=<profile>`, every subsequent SmokeProfile*
    // query in the boot tail (ring3 spawn gate, Linux ABI gate, sleep-
    // and-exit sentinel) sees a stable answer.
    duetos::test::SmokeProfileInit(cmdline);
    bool want_tty = false;
    if (CmdlineMatches(cmdline, "boot", "tty"))
    {
        want_tty = true;
    }
    else if (CmdlineMatches(cmdline, "boot", "desktop"))
    {
        want_tty = false;
    }
    else
    {
#ifdef DUETOS_BOOT_TTY
        want_tty = true;
#endif
    }

    // demo-calendar=1 opens the calendar popup at boot so a headless
    // screenshot can capture the widget without needing to inject a
    // mouse click. No effect on normal boots.
    const bool demo_calendar = CmdlineMatches(cmdline, "demo-calendar", "1");

    if (want_tty)
    {
        duetos::drivers::video::SetDisplayMode(duetos::drivers::video::DisplayMode::Tty);
        duetos::drivers::video::ConsoleSetOrigin(16, 16);
        duetos::drivers::video::ConsoleSetColours(theme0.console_fg, 0x00000000);
        duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
    }
    else
    {
        duetos::drivers::video::DesktopCompose(theme0.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
        duetos::drivers::video::CursorInit(theme0.desktop_bg);
        if (demo_calendar)
        {
            duetos::u32 kx = 0, ky = 0, kw = 0, kh = 0;
            duetos::drivers::video::TaskbarClockBounds(&kx, &ky, &kw, &kh);
            const duetos::u32 ph = duetos::drivers::video::CalendarPanelHeight();
            const duetos::u32 pw = duetos::drivers::video::CalendarPanelWidth();
            const duetos::u32 ax = (kx + kw > pw) ? (kx + kw - pw) : 0;
            const duetos::u32 ay = (ky > ph) ? ky - ph : 0;
            duetos::drivers::video::CalendarOpen(ax, ay);
            duetos::drivers::video::DesktopCompose(theme0.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
        }
    }

    // procfs / sysfs snapshots: materialize the static-text
    // dumps NOW so they capture state at the "system ready"
    // mark (just before the login gate, before user input).
    // After this, all five files behave like any other
    // static-bytes ramfs entry.
    duetos::fs::RamfsBoottraceSnapshot();
    duetos::fs::RamfsSyscallsSnapshot();
    duetos::fs::RamfsAbiSnapshot();
    duetos::fs::RamfsCpuhistSnapshot();
    duetos::fs::RamfsInspectSnapshot();

    // Spawn the userland shell stub. Hand-built ELF ships in
    // /bin/usershell.elf; calls SYS_WRITE("Hello from
    // userland shell stub\n") + SYS_EXIT(0) and returns to
    // the reaper. Proves end-to-end ring-3: ELF parse,
    // PT_LOAD map, ring transition, syscall round-trip,
    // exit cleanup. A future slice grows this into a real
    // prompt-driven shell with TOML reader.
    {
        const auto pid = duetos::core::SpawnElfFile("/bin/usershell.elf", duetos::fs::RamfsUsershellElfBytes(),
                                                    duetos::fs::RamfsUsershellElfSize(), duetos::core::CapSetTrusted(),
                                                    duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                                    duetos::core::kTickBudgetTrusted);
        SerialWrite("[boot] usershell pid=");
        SerialWriteHex(pid);
        SerialWrite("\n");
    }

    // Login gate — blocks keyboard input from reaching the shell
    // until a valid session is open. TTY mode prints a classic
    // `username:` / `password:` banner; desktop mode paints a
    // winlogon-style welcome panel over the framebuffer. The
    // kbd-reader thread routes keys to LoginFeedKey while the
    // gate is up.
    //
    // `autologin=1` on the kernel cmdline skips the gate entirely
    // — useful for headless screenshot captures + CI boot smoke
    // tests where the runner can't drive a keyboard. The default
    // remains "login required."
    const bool autologin = CmdlineMatches(cmdline, "autologin", "1");
    if (!autologin)
    {
        const auto mode = want_tty ? duetos::core::LoginMode::Tty : duetos::core::LoginMode::Gui;
        duetos::core::LoginStart(mode);
    }
    else
    {
        SerialWrite("[boot] autologin=1 — skipping login gate\n");
    }

    // `pentest=gui` arms the self-driving red-team runner that
    // scripts keystrokes into the login gate + shell. See
    // security/pentest_gui.cpp for the probe list. Deliberately
    // requires an explicit opt-in — the final probe invokes
    // `halt`, which is one-way.
    if (CmdlineMatches(cmdline, "pentest", "gui"))
    {
        SerialWrite("[boot] pentest=gui — arming GUI pentest runner\n");
        duetos::security::PentestGuiStart();
    }

    // Phase::Vfs — ramfs init imperative (it lays down the v0 root
    // hierarchy + seed files); VFS self-test routes through the
    // registry. (A1-followup, 2026-04-28.)
    SerialWrite("[boot] Seeding ramfs + VFS self-test.\n");
    duetos::fs::RamfsInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Vfs, "vfs-selftest",
                                       []()
                                       {
                                           duetos::fs::VfsSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Vfs, "vfs-mount-selftest",
                                       []()
                                       {
                                           duetos::fs::VfsMountSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Vfs);

    SerialWrite("[boot] Parsing ACPI tables.\n");
    duetos::acpi::AcpiInit(multiboot_info);
    DUETOS_BOOT_SELFTEST(duetos::acpi::AcpiUnderflowSelfTest());

    // SRAT memory-affinity records are now parsed (AcpiInit ->
    // SratInit). Hand them to the frame allocator so subsequent
    // AllocateFrame calls bias toward the calling CPU's local
    // node. UMA boots (no SRAT) leave the per-node table empty
    // and the global linear-scan path stays the only path.
    duetos::mm::FrameAllocatorBuildNumaRanges();
    DUETOS_BOOT_SELFTEST(duetos::mm::FrameAllocatorNumaSelfTest());
    SerialWrite("[boot] Building AML namespace from DSDT/SSDT.\n");
    duetos::acpi::AmlNamespaceBuild();
    {
        auto aml_init = []() -> duetos::core::Result<void>
        {
            duetos::acpi::AmlNamespaceBuild();
            return {};
        };
        auto aml_teardown = []() -> duetos::core::Result<void> { return duetos::acpi::AmlNamespaceShutdown(); };
        duetos::security::RegisterDriverDomain("acpi/aml", aml_init, aml_teardown);
    }

    SerialWrite("[boot] Disabling 8259 PIC.\n");
    PicDisable();

    // Phase::Apic — LAPIC + IOAPIC + HPET init are imperative (each
    // depends on the previous), but HPET's self-test fits the
    // registry shape cleanly. (A1-followup, 2026-04-28.)
    SerialWrite("[boot] Bringing up LAPIC.\n");
    LapicInit();

    SerialWrite("[boot] Bringing up IOAPIC.\n");
    IoApicInit();

    SerialWrite("[boot] Bringing up HPET (if present).\n");
    HpetInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Apic, "hpet-selftest",
                                       []()
                                       {
                                           HpetSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Apic);

    // Phase::Time — clocksource registry, timekeeper init + self-tests.
    // The init body still runs imperatively (it samples HPET at
    // calibration time + registers TSC if available); self-tests
    // route through the registry. (A1-followup, 2026-04-28.)
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Time, "clocksource-selftest",
                                       []()
                                       {
                                           duetos::time::ClocksourceSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    duetos::time::TimekeeperInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Time, "timekeeper-selftest",
                                       []()
                                       {
                                           duetos::time::TimekeeperSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // Portable scheduler-tick wrapper (plan A2-followup) —
        // additive façade over arch::TimerTicks; consumers migrate
        // off the arch-specific call as the time/ directory grows.
        duetos::core::InitcallRegister(duetos::core::Phase::Time, "tick-selftest",
                                       []()
                                       {
                                           duetos::time::TickSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Time);

    // Sample the CMOS RTC once at boot so the wall-clock time
    // is visible in the boot log. A future slice wires this
    // into the VFS stat path + Win32 GetSystemTimeAsFileTime.
    {
        duetos::arch::RtcTime t = {};
        duetos::arch::RtcRead(&t);
        SerialWrite("[rtc] wall clock ");
        SerialWriteHex(t.year);
        SerialWrite("-");
        SerialWriteHex(t.month);
        SerialWrite("-");
        SerialWriteHex(t.day);
        SerialWrite(" ");
        SerialWriteHex(t.hour);
        SerialWrite(":");
        SerialWriteHex(t.minute);
        SerialWrite(":");
        SerialWriteHex(t.second);
        SerialWrite(" (UTC)\n");
    }

    // Anchor klog's wall-clock prefix to the RTC reading we just
    // took. After this call, `klog::SetLogWallClock(true)` will
    // surface a `[YYYY-MM-DDTHH:MM:SSZ]` prefix on every log line.
    // Defaults to OFF so existing log scanners are not surprised;
    // shell `klog wallclock on` and the boot-config knob can flip
    // it.
    duetos::core::WallClockInit();

    // CMOS is a 128-byte nvram that survives power-off; firmware
    // stashes BIOS setup + POST diagnostic codes + (on some
    // laptops) battery / thermal hints here. Dump it once at boot
    // for observability — the hex grid is enough for a reader to
    // cross-reference against vendor docs.
    duetos::arch::CmosDump();

    SerialWrite("[boot] Installing BSP per-CPU struct.\n");
    duetos::cpu::PerCpuInitBsp();

    // Decode BSP CPUID 0x1F/0x0B + SRAT row into the per-CPU
    // topology table. AP rows are filled later by each AP from
    // inside ApEntryFromTrampoline before signaling online_flag,
    // so the BSP's WaitForApOnline poll inside SmpStartAps is the
    // rendezvous; cluster assignment runs after SmpStartAps returns.
    duetos::cpu::TopologyInitBsp();

    // Architectural LBR — start the per-CPU branch trace ring as
    // early as practical so a panic during late init still has
    // useful records to dump. No-op + serial line on CPUs that
    // don't advertise the feature (TCG QEMU, pre-Goldmont-Plus
    // Intel, AMD).
    duetos::arch::LbrInitBsp();

    // Centralised syscall capability gate (plan A4). Walks every
    // row of `kSyscallCapTable` against synthetic empty / trusted
    // processes; asserts empty fails, trusted passes, and that
    // the unknown-syscall path is a no-op. The dispatcher itself
    // already calls SyscallGate before each handler — this just
    // verifies the table + lookup + denial path before any user
    // code reaches the int 0x80 boundary. Runs AFTER PerCpuInitBsp
    // so the denial path's CurrentTask() reads a programmed GSBASE.
    duetos::core::SyscallGateSelfTest();

    // Cap-gate audit: validates the trace-hook counters + sample
    // path. Cheap (three synthetic events) and the audit is what
    // a release operator looks at to confirm the cap-gate is
    // actually firing in production. Runs only when boot
    // self-tests are on (debug + audit-flavored release).
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::security::CapAuditSelfTest();
    }

    SerialWrite("[boot] Programming Linux-ABI syscall MSRs.\n");
    duetos::subsystems::linux::SyscallInit();

    DUETOS_BOOT_SELFTEST(duetos::sync::SpinLockSelfTest());

    // Seqlock (plan B1.3). Sequence-counter primitive for
    // read-mostly hot data (timekeeper, per-CPU stat counters).
    // Only the writer side touches the inner SpinLock, so the
    // self-test runs immediately after `SpinLockSelfTest` — every
    // dependency is in place. Contention paths (multi-CPU
    // writer/reader race) only fire under SMP and are deferred
    // to a follow-up self-test once AP bringup lands.
    DUETOS_BOOT_SELFTEST(duetos::sync::SeqLockSelfTest());

    // Lockdep-lite (plan D1 infra). Validates that the
    // edge-graph + held-stack + cycle detection works in
    // isolation. SpinLock acquire/release paths now call into
    // the lockdep hooks (D1-followup); untagged locks pay one
    // compare-and-skip per call. Mutex / RwLock instrumentation
    // is still deferred. Runs early because it has no
    // dependencies past arch::Cli/Sti.
    DUETOS_BOOT_SELFTEST(duetos::sync::LockdepSelfTest());
    // Name the canonical hot global locks (sched / kobject /
    // kstack / pci-config / breakpoints) so any inversion
    // detected post-self-test prints readable names instead of
    // raw class IDs. Idempotent; called after the self-test so
    // self-test scratch names don't get clobbered by names that
    // need to be live for the rest of boot.
    duetos::sync::LockdepRegisterCanonicalClasses();

    SerialWrite("[boot] Bringing up periodic timer.\n");
    duetos::time::TimerInit();

    SerialWrite("[boot] Bringing up scheduler.\n");
    duetos::sched::SchedInit();
    // Per-task syscall-trail self-test — exercises the ring
    // logic on the current (kboot) task before any user task
    // can populate it. Restores the pre-test state on exit so
    // a panic that fires later doesn't surface synthetic
    // entries. Cheap and gives us boot-time evidence the dump
    // section's mechanism works (the section itself only
    // appears on a panic from a task that issued syscalls,
    // which kboot itself never does).
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::sched::SyscallTrailSelfTest();
        // Minidump self-test — validates the .dmp builder's
        // header / version / stream-count shape against a
        // synthetic context. Builds into the static buffer but
        // does NOT egress to debugcon, so a clean boot leaves
        // the host's `duetos.dmp` file empty.
        duetos::diag::minidump::MinidumpSelfTest();
    }
    // Idle task FIRST so the runqueue is never empty — even if the
    // reaper or any subsequent worker blocks before the boot task
    // spawns anything else, Schedule() always has a fallback to
    // pick. Supersedes the "ensure SmpStartAps has a runnable peer"
    // workaround that used to depend on worker creation order.
    duetos::sched::SchedStartIdle("idle-bsp");
    duetos::sched::SchedStartReaper();

    // Address-space isolation self-test — direct assertion that a
    // user page mapped in one AS is invisible in a sibling AS, and
    // that AddressSpaceActivate flips CR3 correctly. Routed through
    // Phase::Sched: AddressSpaceMapUserPage takes an `RwLock` whose
    // `MutexLock` slow path needs `Current()` and the wait-queue
    // machinery, so the test must run after `SchedInit`.
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "address-space-selftest",
                                       []()
                                       {
                                           duetos::mm::AddressSpaceSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // Phase::Sched (plan A1-followup, 2026-04-28). RwLock state-
        // machine self-test + the two contention self-tests (RwLock +
        // SeqLock) all need the scheduler online to spawn the helper
        // tasks they use. Routing them through the registry keeps
        // their ordering visible without changing observable behavior.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "rwlock-selftest",
                                       []()
                                       {
                                           duetos::sync::RwLockSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "seqlock-contention-selftest",
                                       []()
                                       {
                                           duetos::sync::SeqLockContentionSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "rwlock-contention-selftest",
                                       []()
                                       {
                                           duetos::sync::RwLockContentionSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // KMailbox stress test (plan B1-followup, 2026-04-28). 4
        // producer × 4 consumer tasks racing on capacity-8 mailbox.
        // Verifies the not_full / not_empty condvar wiring under
        // real producer/consumer contention.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "kmailbox-stress",
                                       []()
                                       {
                                           duetos::ipc::KMailboxContentionSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // Dynamic event tracer self-test (plan D2). Verifies the
        // lockless append + snapshot + ordering invariants with
        // synthesised events. The tracer itself is a passive
        // surface; the boot path doesn't write any events through
        // it today (instrumentation points are added at the call
        // sites that want them, not centrally).
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "event-trace-selftest",
                                       []()
                                       {
                                           duetos::diag::EventTraceSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // PMU sample profiler (plan D3) — same shape as event_trace
        // but for sampled RIPs. Sampling source (PMU NMI overflow)
        // is NOT wired in this slice; the ring + dump are landed so
        // a future D3-followup can hook PerfRecord into the NMI
        // handler with a one-line call.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "perf-profile-selftest",
                                       []()
                                       {
                                           duetos::diag::PerfProfileSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // RCU (plan B1.4) — quiescent-state read-copy-update keyed
        // off the scheduler tick. Self-test queues a callback,
        // drives a tick, asserts the callback fires once. RcuTick
        // is already wired into OnTimerTick by this point.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "rcu-selftest",
                                       []()
                                       {
                                           duetos::sync::RcuSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // GDB serial stub (plan D7) — protocol parser + canned
        // responses for the commands a GDB session sends on
        // connect. v0 isn't wired into the COM2 RX path yet; the
        // self-test drives synthesised conversations through the
        // parser directly.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "gdb-stub-selftest",
                                       []()
                                       {
                                           duetos::diag::gdb::GdbServerSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Sched);

    // KObject + HandleTable infrastructure self-tests (plan A3).
    // Verifies refcount + destroy-on-zero, plus the table's
    // insert/lookup/duplicate/remove/drain matrix. The
    // infrastructure is purely additive — existing per-type
    // handle arrays on Process keep working unchanged. Migration
    // of any current handle surface is tracked as a follow-up.
    DUETOS_BOOT_SELFTEST(duetos::ipc::KObjectSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::HandleTableSelfTest());
    // Concrete KMutex subclass self-test (plan A3-followup) —
    // demonstrates the full HandleTable round-trip on a real
    // type with refcounted storage. Existing per-type Win32
    // mutex array on Process keeps its own syscall surface; the
    // SYS_MUTEX_* migration is a separate, larger slice (the
    // Win32 ABI semantics — kWaitObject0 / kWaitTimeout, infinite
    // waits, deadlock-detect callbacks — are non-trivial to
    // unwind from the existing per-type array).
    DUETOS_BOOT_SELFTEST(duetos::ipc::KMutexSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::KEventSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::KSemaphoreSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::KMailboxSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::KWaitableSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::KFileSelfTest());
    // Linux fd-table helper self-test (Linux fd → KFile
    // migration). Exercises LinuxFdAllocLowest / AttachKFile /
    // Dup / SetCloexec / CloseOnExec / Close on a stand-in
    // Process so the helper plumbing — including the per-pool
    // release-callback dispatch through KFileDestroy — is
    // verified before any real Linux ABI workload reaches the
    // syscall surface.
    DUETOS_BOOT_SELFTEST(duetos::core::LinuxFdSelfTest());
    // Soft-lockup detector (plan D4). The detector itself is
    // already wired into the timer-IRQ tail (`OnTimerTick`), so
    // a real lockup would already be surfaced; the self-test
    // drives the state machine with synthesised inputs (idle
    // skip, threshold trigger, rate limit, per-TID reset) to
    // confirm the gating logic is correct before any real
    // workload exercises it.
    DUETOS_BOOT_SELFTEST(duetos::diag::SoftLockupSelfTest());

    SerialWrite("[boot] Bringing up PS/2 keyboard.\n");
    duetos::drivers::input::Ps2KeyboardInit();

    SerialWrite("[boot] Bringing up PS/2 mouse.\n");
    duetos::drivers::input::Ps2MouseInit();

    SerialWrite("[boot] Enumerating PCI bus.\n");
    duetos::drivers::pci::PciEnumerate();

    SerialWrite("[boot] Detecting Intel MEI/HECI devices.\n");
    duetos::drivers::mei::MeiInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::mei::MeiSelfTest());

    SerialWrite("[boot] Detecting GPUs.\n");
    duetos::drivers::gpu::GpuInit();
    // drivers/gpu fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "drivers/gpu.module", ...) in
    // `kernel/drivers/gpu/gpu.cpp`.

    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::EdidSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::CvtSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::DpmsSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::Cea861SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::intel::IntelGscFwSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::GpuResourcesSelfTest());

    SerialWrite("[boot] Bringing up firmware loader (scaffold).\n");
    duetos::core::FwLoaderInit();
    duetos::net::wireless::diag::Init();
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::IwlFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::RtlFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::BcmFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::BeaconSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::bluetooth::HciSelfTest());
    duetos::net::bluetooth::BluetoothDiagInit();
    DUETOS_BOOT_SELFTEST(duetos::net::bluetooth::BluetoothDiagSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::UnicodeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::BmpSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::TgaSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::DateTimeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::DeflateSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::GzipZlibSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::PngSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::Adler32SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::Sha1SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::Sha256SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::HmacSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::Pbkdf2SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::PrfSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::AesSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::AesKeyWrapSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::PasswordHashSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::EapolSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::FourWaySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::WdevSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::MlmeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::IwlUploadSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::IwlRingsSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::RtlUploadSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::BcmUploadSelfTest());
    // End-to-end loopback self-test exercises the entire control
    // tier (scan + auth + assoc + 4-way handshake) against a
    // software FakeAp peer + LoopbackDriver. Equivalent to
    // Linux's `mac80211_hwsim` for our stack.
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::test::WirelessE2ESelfTest());

    SerialWrite("[boot] Detecting NICs.\n");
    duetos::drivers::net::NetInit();
    // drivers/net fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "drivers/net.module", ...) in
    // `kernel/drivers/net/net.cpp`.

    SerialWrite("[boot] Detecting USB host controllers.\n");
    duetos::drivers::usb::UsbInit();
    duetos::drivers::usb::xhci::XhciInit();
    // Register xHCI as a restartable fault domain. Init() is
    // already idempotent (early-return on g_init_done), so the
    // domain's init hook just wraps it in a Result<void>.
    {
        auto xhci_init = []() -> duetos::core::Result<void>
        {
            duetos::drivers::usb::xhci::XhciInit();
            return {};
        };
        auto xhci_teardown = []() -> duetos::core::Result<void> { return duetos::drivers::usb::xhci::XhciShutdown(); };
        duetos::security::RegisterDriverDomain("drivers/usb/xhci", xhci_init, xhci_teardown);
    }
    // Probe USB-Ethernet adapters now that xHCI enumeration is
    // complete. CDC-ECM is the USB standard — works with QEMU's
    // `-device usb-net` emulation, premium USB-Ethernet dongles,
    // and iPhone tethering. RNDIS (Android default), CDC-NCM
    // (Apple devices, Wi-Fi 6 routers), AX88xxx and RTL81xx
    // vendor-specific protocols are follow-up class drivers.
    // CdcEcmProbe is deliberately NOT called here. Invoking it
    // during USB init auto-probes every enumerated device; when
    // the device isn't CDC-ECM (QEMU's usb-net is RNDIS, most
    // Android phones are RNDIS too) the probe's control transfers
    // still happen, and a timing interaction with the pre-poll
    // event-ring state regresses the e1000 DHCP path (the RX
    // polling task stops delivering frames to the network stack
    // until a reboot). Callable manually from a shell command or
    // a kernel thread once a real CDC-ECM device is known to be
    // attached; the auto-probe will land in a follow-up slice
    // that dispatches events by TRB so class drivers don't race
    // with each other or the HID polling path.
    DUETOS_BOOT_SELFTEST(duetos::drivers::usb::hid::HidSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::usb::msc::MscSelfTest());

    SerialWrite("[boot] Detecting audio controllers.\n");
    duetos::drivers::audio::AudioInit();
    // drivers/audio fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "drivers/audio.module", ...) in
    // `kernel/drivers/audio/audio.cpp`.
    DUETOS_BOOT_SELFTEST(duetos::drivers::audio::hda::VerbEncodingSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::audio::hda::HdaJackSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::audio::hda::HdaJackInventorySelfTest());

    SerialWrite("[boot] Bringing up power / thermal shell.\n");
    duetos::drivers::power::PowerInit();

    SerialWrite("[boot] Bringing up network stack skeleton.\n");
    duetos::net::NetStackInit();
    DUETOS_BOOT_SELFTEST(duetos::net::firewall::FwSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::core::IdleLockSelfTest());
    // Smoke test runs in its own task. It owns the (single) TCP
    // slot during its run and installs the boot HTTP listener
    // afterwards via NetSmokeInstallBootListener — so an active
    // connect to www.google.com (step 4) doesn't collide with
    // the listener's TcpListen call. `netsmoke=force` opts in to
    // running on emulator (QEMU SLIRP supports DNS+TCP egress).
    const bool force_net_smoke = CmdlineMatches(cmdline, "netsmoke", "force");
    duetos::net::NetSmokeTestStart(force_net_smoke);

    SerialWrite("[boot] Bringing up graphics ICD.\n");
    duetos::subsystems::graphics::GraphicsIcdInit();
    DUETOS_BOOT_SELFTEST(duetos::subsystems::graphics::GraphicsIcdSelfTest());
    duetos::subsystems::win32::GdiInit();

    SerialWrite("[boot] Bringing up block device layer.\n");
    duetos::drivers::storage::BlockLayerInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::storage::BlockLayerSelfTest());

    SerialWrite("[boot] Bringing up NVMe controller.\n");
    duetos::drivers::storage::NvmeInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::storage::NvmeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::diag::minidump::DiskPersistSelfTest());

    SerialWrite("[boot] Bringing up AHCI controller(s).\n");
    duetos::drivers::storage::AhciInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::storage::AhciSelfTest());

    // Security event ring + IR runbook: stand up the structured
    // event surface BEFORE any wall TU starts publishing. Storage
    // is constinit so a stray pre-init publish is safe; this call
    // just zeroes counters + logs the init.
    SerialWrite("[boot] Starting security event ring.\n");
    duetos::security::EventRingInit();
    DUETOS_BOOT_SELFTEST(duetos::security::EventRingSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::IrRunbookSelfTest());

    // Security guard must be live BEFORE any loader runs. Advisory
    // mode at boot: scans + logs, never blocks. Flip to Enforce via
    // the shell `guard enforce` once the boot-log is clean.
    SerialWrite("[boot] Starting security guard.\n");
    duetos::security::GuardInit();
    DUETOS_BOOT_SELFTEST(duetos::security::GuardSelfTest());

    // Canary file-self-defense init: seed per-boot dynamic
    // canary names from kernel entropy. MUST follow RandomInit
    // (already on the boot path above). Without this the
    // dynamic-canary slots stay empty and only the static
    // registry matches.
    SerialWrite("[boot] Seeding per-boot canary names.\n");
    duetos::security::CanaryInit();

    // Policy engine: snapshot the per-subsystem modes Guard /
    // Canary / Blockguard chose for themselves. Profile starts at
    // Default; operators flip to Lab/Production/Forensic via the
    // `policy` shell command.
    SerialWrite("[boot] Initializing security policy engine.\n");
    duetos::security::PolicyInit();
    DUETOS_BOOT_SELFTEST(duetos::security::PolicySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::PurpleTeamSelfTest());

    DUETOS_BOOT_SELFTEST(duetos::fs::TmpFsSelfTest());

    SerialWrite("[boot] Probing GPT on block devices.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::gpt::GptSelfTest());

    SerialWrite("[boot] Probing FAT32 on block devices.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::fat32::Fat32SelfTest());
    // fs/fat32 fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "fs/fat32.module", ...) in
    // `kernel/fs/fat32.cpp`.

    // Auto-register every probed FAT32 volume in the mount registry
    // so `VfsMountResolve` (and therefore the file-routing layer)
    // sees them. The mount point matches the existing hardcoded
    // "/disk/<idx>" routing prefix — the longest-prefix resolver
    // produces the same routing decision the legacy parser made,
    // but now gated on actual mount-table entries.
    {
        char mp[16] = "/disk/0";
        for (duetos::u32 i = 0; i < duetos::fs::fat32::Fat32VolumeCount() && i < 10; ++i)
        {
            mp[6] = static_cast<char>('0' + i);
            mp[7] = '\0';
            (void)duetos::fs::VfsMount(mp, duetos::fs::FsType::Fat32, i);
        }
    }

    SerialWrite("[boot] Cross-mount VfsResolve self-test.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::VfsResolveCrossMountSelfTest());

    // First Rust subsystem in the kernel — DuetFS v1 brings up the
    // project's native filesystem. DuetFsBoot creates a 256 KiB RAM-
    // backed volume, mkfs's it, seeds /etc/version, and registers it
    // in the VFS mount table at /duetfs. DuetFsSelfTest exercises the
    // full v1 surface (mkfs, create, write, read, mkdir, unlink,
    // truncate) on a SCRATCH image so the boot mount stays clean.
    SerialWrite("[boot] DuetFS bring-up.\n");
    duetos::fs::duetfs::DuetFsBoot();
    DUETOS_BOOT_SELFTEST(duetos::fs::duetfs::DuetFsSelfTest());

    SerialWrite("[boot] Routing Win32 file syscalls through FAT32.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::routing::SelfTest());

    // Notes save/load round-trip — runs here (post-FAT32-probe) so
    // the SKIP path stays only "no FAT32 volume" rather than "Notes
    // ran before storage was up". Skipped silently if NOTES.TXT
    // pre-exists on the boot image.
    DUETOS_BOOT_SELFTEST(duetos::apps::notes::NotesPersistSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::screenshot::ScreenshotSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::trash::TrashSelfTest());

    // FAT32 is online. Promote the Files app's default view from
    // RAM to DISK so the first time a user clicks Start -> FILES
    // they see what's actually on the volume (notes / screenshots
    // / logs) rather than the read-only ramfs tree. The user can
    // still toggle back with M (memory).
    duetos::apps::files::FilesPromoteToDisk();

    // Restore the saved Calendar event table from CALENDAR.TXT if
    // one exists. Silent no-op if the file isn't there — first-
    // boot Calendar simply starts with an empty event store.
    duetos::apps::calendar::CalendarLoad();

    // Install the FAT32 file sink — replaces the early tmpfs
    // sink (single-slot API). The tmpfs `/tmp/boot.log`
    // captured the early-boot lines; from here on, every
    // Info+ log entry goes to `KERNEL.LOG` on the FAT32 root.
    // Non-fatal if FAT32 is unavailable — Install logs and
    // returns.
    duetos::core::KlogPersistInstall();
    DUETOS_BOOT_SELFTEST(duetos::core::KlogPersistSelfTest());

    // Install the FAT32 sink for the fix journal — KERNEL.FIX on
    // the root volume. Same install-after-FAT32 contract as klog;
    // the rotation policy ages the prior session's KERNEL.FIX into
    // KERNEL.F0..F<N-1> so a reviewer can pull gaps from previous
    // boots too.
    duetos::diag::FixJournalPersistInstall();
    DUETOS_BOOT_SELFTEST(duetos::diag::FixJournalPersistSelfTest());

    // Session restore: read SESSION.CFG and apply the saved
    // theme + per-app window positions. No-op on first boot
    // (file doesn't exist) or if FAT32 isn't mounted.
    // SessionRestoreSelfTest exercises the parse path in
    // memory without touching the on-disk config.
    DUETOS_BOOT_SELFTEST(duetos::core::SessionRestoreSelfTest());
    duetos::core::SessionRestoreApply();

    // Win32 registry hive: replay any sidecar values the previous
    // boot wrote (NtSetValueKey / NtDeleteValueKey targets land in
    // REGISTRY.HIV and are restored here). Self-test runs first so
    // a regression surfaces before the live load mutates the pool.
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::registry::RegistryHiveSelfTest());
    duetos::subsystems::win32::registry::RegistryHiveLoad();

    // /APPS shortcut enumeration. Creates the directory + a
    // SAMPLE.MNF seed on first boot so the user has a working
    // template to copy. Each *.MNF file becomes an extra entry
    // in the Start menu, dispatched through ThemeRole.
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::StartMenuAppsSelfTest());
    duetos::drivers::video::StartMenuAppsScan();

    SerialWrite("[boot] Probing read-only FS shells (ext4 / NTFS / exFAT).\n");
    duetos::fs::ext4::Ext4ScanAll();
    duetos::fs::ntfs::NtfsScanAll();
    duetos::fs::exfat::ExfatScanAll();

    // Metrics checkpoint: everything above is bringup overhead; what
    // the system consumes from here on is steady-state.
    KLOG_METRICS("boot", "bringup-complete");
    SerialWrite("[bringup-tail] post-metrics\n");

    // Sanity-check the tmpfs log sink — by now enough Info+ lines
    // have fired that /tmp/boot.log should be at its 512-byte cap.
    {
        const char* bytes = nullptr;
        duetos::u32 len = 0;
        if (duetos::fs::TmpFsRead("boot.log", &bytes, &len))
        {
            duetos::core::LogWithValue(duetos::core::LogLevel::Info, "core/klog", "/tmp/boot.log size (bytes)", len);
        }
        else
        {
            duetos::core::Log(duetos::core::LogLevel::Warn, "core/klog", "/tmp/boot.log not present");
        }
    }

    // Keyboard reader thread: consumes KeyEvents and writes the
    // printable ones into the framebuffer console. Backspace and
    // Enter get line-editing semantics; modifier-only edges
    // update internal state silently. The console is also
    // mirrored to COM1 so a headless run still produces the
    // classic serial boot log.
    //
    // v0 race note: this thread and the mouse reader both call
    // DesktopCompose without a lock. FB writes are per-pixel
    // atomic on x86_64 and the worst-case collision is a
    // transient visual artifact, not corrupt state. A proper
    // compositor mutex lands with the first crash, or on SMP
    // scheduler join — whichever comes first.
    auto kbd_reader = [](void*)
    {
        using namespace duetos::drivers::input;
        // Sample at each compose call so Ctrl+Alt+Y (theme cycle)
        // takes effect on the very next repaint — don't cache.
        auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };
        for (;;)
        {
            const KeyEvent ev = Ps2KeyboardReadEvent();
            // Track async keyboard state BEFORE the early
            // release / kKeyNone filter so release edges are
            // recorded. `ev.code` wraps to the low 8 bits of
            // the VK cache so ext keys collide gracefully with
            // unmapped slots.
            duetos::drivers::video::WindowInputTrackKey(static_cast<duetos::u16>(ev.code), !ev.is_release);
            if (ev.is_release || ev.code == kKeyNone)
            {
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
                        DispatchMenuAction(fired, ctx_before);
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
                    duetos::drivers::video::NotifyShow(ok ? "saved to NOTES.TXT" : "save failed");
                    SerialWrite(ok ? "[ui] ^S notes saved\n" : "[ui] ^S notes save FAILED\n");
                    continue;
                }
                if (active != duetos::drivers::video::kWindowInvalid &&
                    active == duetos::apps::calendar::CalendarWindow())
                {
                    const bool ok = duetos::apps::calendar::CalendarSave();
                    duetos::drivers::video::CompositorUnlock();
                    duetos::drivers::video::NotifyShow(ok ? "saved to CALENDAR.TXT" : "calendar save failed");
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
                if (active != duetos::drivers::video::kWindowInvalid &&
                    active == duetos::apps::browser::BrowserWindow())
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
                if (active != duetos::drivers::video::kWindowInvalid &&
                    active == duetos::apps::browser::BrowserWindow())
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
                    duetos::drivers::video::NotifyShow(ok ? "loaded NOTES.TXT" : "load failed (no NOTES.TXT?)");
                    SerialWrite(ok ? "[ui] ^O notes loaded\n" : "[ui] ^O notes load FAILED\n");
                    continue;
                }
                if (active != duetos::drivers::video::kWindowInvalid &&
                    active == duetos::apps::calendar::CalendarWindow())
                {
                    const bool ok = duetos::apps::calendar::CalendarLoad();
                    duetos::drivers::video::CompositorUnlock();
                    duetos::drivers::video::NotifyShow(ok ? "loaded CALENDAR.TXT" : "calendar load failed");
                    SerialWrite(ok ? "[ui] ^O calendar loaded\n" : "[ui] ^O calendar load FAILED\n");
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
                PrintShortcutHelp();
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
                duetos::drivers::video::NotifyShow(ok ? "screenshot saved" : "screenshot failed");
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
                duetos::drivers::video::NotifyShow(ok_tga ? "screenshot (TGA) saved" : "screenshot (TGA) failed");
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
                (ev.code == duetos::drivers::input::kKeyArrowLeft ||
                 ev.code == duetos::drivers::input::kKeyArrowRight || ev.code == duetos::drivers::input::kKeyArrowUp ||
                 ev.code == duetos::drivers::input::kKeyArrowDown))
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
                (ev.code == duetos::drivers::input::kKeyArrowLeft ||
                 ev.code == duetos::drivers::input::kKeyArrowRight || ev.code == duetos::drivers::input::kKeyArrowUp ||
                 ev.code == duetos::drivers::input::kKeyArrowDown))
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
                        static duetos::drivers::video::WindowHandle s_close_target =
                            duetos::drivers::video::kWindowInvalid;
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
                              ev.code == kKeyPageDown))
                    {
                        app_consumed =
                            duetos::apps::notify_center::NotifyCenterFeedArrow(static_cast<duetos::u16>(ev.code));
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
            }
        }
    };
    duetos::sched::SchedCreate(kbd_reader, nullptr, "kbd-reader");
    SerialWrite("[bringup-tail] kbd-reader spawned\n");

    // Idle-timeout auto-lock watcher. Wakes once a second and
    // calls LoginLock when the active session has been idle past
    // the configured threshold (default 600s; override via
    // `idlelock=<seconds>` on the boot cmdline; 0 disables).
    {
        const char* boot_cmdline = FindBootCmdline(multiboot_info);
        if (boot_cmdline != nullptr)
        {
            const char* p = boot_cmdline;
            while (*p != '\0')
            {
                while (*p == ' ' || *p == '\t')
                {
                    ++p;
                }
                if (*p == '\0')
                {
                    break;
                }
                const char* token = p;
                while (*p != '\0' && *p != ' ' && *p != '\t')
                {
                    ++p;
                }
                const char* prefix = "idlelock=";
                const char* k = prefix;
                const char* t = token;
                while (*k != '\0' && t < p && *t == *k)
                {
                    ++k;
                    ++t;
                }
                if (*k == '\0')
                {
                    duetos::u32 n = 0;
                    bool any_digit = false;
                    while (t < p && *t >= '0' && *t <= '9')
                    {
                        n = n * 10 + duetos::u32(*t - '0');
                        ++t;
                        any_digit = true;
                    }
                    if (any_digit && t == p)
                    {
                        duetos::core::IdleLockSetThresholdSeconds(n);
                    }
                }
            }
        }
    }
    duetos::core::IdleLockTaskStart();

    // Serial-input pump: lets a host terminal connected via
    // QEMU's `-serial stdio` drive the shell — typed bytes
    // arrive on COM1 and feed the same ShellFeedChar /
    // ShellSubmit / ShellHistoryPrev API as PS/2 keystrokes.
    // The pump is read-only (it only translates inbound RBR
    // bytes into shell calls), so it composes cleanly with
    // every output-side serial caller.
    duetos::core::SerialInputStart();

    // Register the shell's post-emit hook so a klog line that
    // interrupts the operator's typing redraws the prompt +
    // current input buffer on a fresh line. Without this, fast
    // log chatter scrolls partially-typed commands off-screen.
    duetos::core::SetPostEmitHook(&duetos::core::ShellRedrawAfterLogLine);

    // UI ticker: once per second, re-composite so the taskbar's
    // uptime / wall-clock counter advances even when the user
    // hasn't touched keyboard or mouse. Uses the compositor
    // mutex so it serialises cleanly with input threads. Full
    // recompose at 1 Hz costs ~one frame's worth of MMIO writes.
    // Branches on display mode so TTY-mode ticks don't re-draw
    // a hidden desktop.
    auto ui_ticker = [](void*)
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
    };
    duetos::sched::SchedCreate(ui_ticker, nullptr, "ui-ticker");
    SerialWrite("[bringup-tail] ui-ticker spawned\n");

    // Mouse reader thread: blocks on Ps2MouseReadPacket, prints one
    // line per decoded packet. Same end-to-end closure the keyboard
    // reader gives, for IRQ 12. On machines without a PS/2 aux line
    // (most laptops), Ps2MouseInit returned without routing the
    // IRQ — the reader just parks forever on an unfed queue.
    auto mouse_reader = [](void*)
    {
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
        static ResizeState resize{false,
                                  duetos::drivers::video::kWindowInvalid,
                                  duetos::drivers::video::WindowResizeEdge::None,
                                  0,
                                  0,
                                  0,
                                  0,
                                  0,
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
        using StartMenuRole = duetos::drivers::video::ThemeRole;

        static const duetos::drivers::video::MenuItem kAppsItems[] = {
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
        static const duetos::drivers::video::MenuItem kSystemItems[] = {
            {"SETTINGS", 100 + static_cast<duetos::u32>(StartMenuRole::Settings), 0, nullptr, 0},
            {"TASK MANAGER", 100 + static_cast<duetos::u32>(StartMenuRole::TaskManager), 0, nullptr, 0},
            {"KERNEL LOG", 100 + static_cast<duetos::u32>(StartMenuRole::LogView), 0, nullptr, 0},
            {"NETWORK STATUS", 60, 0, nullptr, 0},
            {"DEVICE MANAGER", 61, 0, nullptr, 0},
            {"FIREWALL", 62, 0, nullptr, 0},
            {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0},
            {"CYCLE WINDOWS", 2, 0, nullptr, 0},
            {"SWITCH TO TTY", 5, 0, nullptr, 0},
        };
        static const duetos::drivers::video::MenuItem kPowerItems[] = {
            {"LOCK", 42, 0, nullptr, 0},
            {"LOG OUT", 43, 0, nullptr, 0},
            {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0},
            {"REBOOT", 40, 0, nullptr, 0},
            {"SHUT DOWN", 41, 0, nullptr, 0},
        };

        // /APPS shortcuts — populated each open from the FAT32
        // scan so a freshly-dropped /APPS/*.MNF picks up without
        // a reboot. Capped at 12 to fit the menu renderer's per-
        // panel limit (StartMenuAppsAppendTo logs an overflow line
        // if more were discovered).
        constexpr duetos::u32 kUserAppsCap = 12;
        static duetos::drivers::video::MenuItem kUserAppsItems[kUserAppsCap] = {};
        duetos::u32 user_apps_count = 0;
        duetos::drivers::video::StartMenuAppsAppendTo(kUserAppsItems, &user_apps_count, kUserAppsCap);

        // Six-row root. USER APPS is disabled when empty so the
        // user sees the bucket (and learns about the /APPS slot)
        // without firing a launcher path that resolves to nothing.
        static duetos::drivers::video::MenuItem kStartItems[6] = {};
        kStartItems[0] = {"APPS", 0, kMenuItemFlagSubmenu, kAppsItems, sizeof(kAppsItems) / sizeof(kAppsItems[0])};
        kStartItems[1] = {"SYSTEM", 0, kMenuItemFlagSubmenu, kSystemItems,
                          sizeof(kSystemItems) / sizeof(kSystemItems[0])};
        kStartItems[2] = {(user_apps_count == 0) ? "USER APPS (EMPTY)" : "USER APPS", 0,
                          kMenuItemFlagSubmenu | (user_apps_count == 0 ? kMenuItemFlagDisabled : 0u), kUserAppsItems,
                          user_apps_count};
        kStartItems[3] = {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0};
        kStartItems[4] = {"SCREENSHOT", 50, 0, nullptr, 0};
        kStartItems[5] = {"POWER", 0, kMenuItemFlagSubmenu, kPowerItems, sizeof(kPowerItems) / sizeof(kPowerItems[0])};
        constexpr duetos::u32 start_items_count = sizeof(kStartItems) / sizeof(kStartItems[0]);
        static const duetos::drivers::video::MenuItem kDesktopMenuItems[] = {
            {"HELP / SHORTCUTS", 6, 0, nullptr, 0}, {"ABOUT DUETOS", 1, 0, nullptr, 0},
            {"CYCLE WINDOWS", 2, 0, nullptr, 0},    {"LIST WINDOWS", 3, 0, nullptr, 0},
            {"SWITCH TO TTY", 5, 0, nullptr, 0},
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
        // Title-bar (NC) right-click — the classic Win32 system
        // menu. RESTORE/MINIMIZE/MAXIMIZE/CLOSE are wired; MOVE
        // does a one-shot recenter (GAP) and SIZE is shown
        // disabled — both wait on a modal-input mode.
        static const duetos::drivers::video::MenuItem kSystemMenuItems[] = {
            {"RESTORE", 20, 0, nullptr, 0},  {"MOVE", 21, 0, nullptr, 0},     {"SIZE", 22, 0, nullptr, 0},
            {"MINIMIZE", 23, 0, nullptr, 0}, {"MAXIMIZE", 24, 0, nullptr, 0}, {"CLOSE", 25, 0, nullptr, 0},
        };

        for (;;)
        {
            const auto p = duetos::drivers::input::Ps2MouseReadPacket();

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

            // Track menu hover. Cheap when no menu is open. When
            // open, this updates the highlighted row so the next
            // compose paints it. The recompose itself is forced
            // below if the cursor moved while a menu was open.
            duetos::drivers::video::MenuTrackHoverAt(cx, cy);

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
            // Browser editable client area → IBeam; everywhere
            // else → Arrow. The CursorSetShape change-gate keeps
            // per-packet calls cheap when the shape doesn't move.
            if (duetos::drivers::video::CursorGetShape() != duetos::drivers::video::CursorShape::Wait)
            {
                using duetos::drivers::video::CursorShape;
                using duetos::drivers::video::WindowResizeEdge;
                CursorShape want = CursorShape::Arrow;
                const auto over_resize = duetos::drivers::video::WindowTopmostAt(cx, cy);
                WindowResizeEdge edge = WindowResizeEdge::None;
                if (over_resize != duetos::drivers::video::kWindowInvalid)
                {
                    edge = duetos::drivers::video::WindowPointInResizeEdge(over_resize, cx, cy);
                }
                if (edge == WindowResizeEdge::Left || edge == WindowResizeEdge::Right)
                {
                    want = CursorShape::ResizeEW;
                }
                else if (edge == WindowResizeEdge::Top || edge == WindowResizeEdge::Bottom)
                {
                    want = CursorShape::ResizeNS;
                }
                else if (edge == WindowResizeEdge::TopLeft || edge == WindowResizeEdge::BottomRight)
                {
                    want = CursorShape::ResizeNWSE;
                }
                else if (edge == WindowResizeEdge::TopRight || edge == WindowResizeEdge::BottomLeft)
                {
                    want = CursorShape::ResizeNESW;
                }
                else if (duetos::drivers::video::WidgetCursorOverButton(cx, cy))
                {
                    want = CursorShape::Hand;
                }
                else if (over_resize != duetos::drivers::video::kWindowInvalid &&
                         !duetos::drivers::video::WindowPointInTitle(over_resize, cx, cy) &&
                         (over_resize == duetos::apps::notes::NotesWindow() ||
                          over_resize == duetos::apps::browser::BrowserWindow()))
                {
                    want = CursorShape::IBeam;
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
                else if (!duetos::drivers::video::TaskbarContains(cx, cy))
                {
                    const auto hit = duetos::drivers::video::WindowTopmostAt(cx, cy);
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
                            else
                            {
                                duetos::drivers::video::MenuOpen(kWindowMenuItems,
                                                                 sizeof(kWindowMenuItems) / sizeof(kWindowMenuItems[0]),
                                                                 cx, cy, hit);
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
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
                        DispatchMenuAction(action, ctx);
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                        // Open with the start item set; measure
                        // panel height AFTER MenuOpen populates
                        // its item count so the anchor sits
                        // flush against the top of the START
                        // button regardless of how many items
                        // are in the set.
                        duetos::drivers::video::MenuOpen(kStartItems, start_items_count, sx, sy, 0);
                        const duetos::u32 mh = duetos::drivers::video::MenuPanelHeight();
                        const duetos::u32 my = (sy > mh) ? sy - mh : 0;
                        duetos::drivers::video::MenuOpen(kStartItems, start_items_count, sx, my, 0);
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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                    duetos::drivers::video::CursorShow();
                    menu_handled = true; // taskbar ate the click
                }
                else if (!duetos::drivers::video::TaskbarIsLocked())
                {
                    // Empty-strip click on an unlocked taskbar -> begin
                    // drag. Snap target is decided on release below.
                    duetos::drivers::video::TaskbarBeginDrag();
                    menu_handled = true;
                }
            }

            if (press_edge && menu_handled)
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                        // ignore). Kernel-owned boot windows
                        // still close immediately — no PE to
                        // delegate to.
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
                            duetos::drivers::video::WindowClose(hit);
                            SerialWrite("[ui] close window=");
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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                    duetos::drivers::video::CursorShow();
                }
            }
            if (release_edge && drag.active)
            {
                SerialWrite("[ui] drag end window=");
                SerialWriteHex(drag.window);
                SerialWrite("\n");
                drag.active = false;
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                const duetos::u64 pe_pid = (pe_hit != duetos::drivers::video::kWindowInvalid)
                                               ? duetos::drivers::video::WindowOwnerPid(pe_hit)
                                               : 0;
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
                                            (now_tick - s_last_click_tick <= kDblClickTicks) &&
                                            (s_last_click_x == cx) && (s_last_click_y == cy);
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
                    static duetos::drivers::video::WindowHandle s_native_dc_hwnd =
                        duetos::drivers::video::kWindowInvalid;
                    static duetos::u32 s_native_dc_x = 0;
                    static duetos::u32 s_native_dc_y = 0;
                    const duetos::u64 now_tick = duetos::arch::TimerTicks();
                    const bool is_dbl = (s_native_dc_hwnd == pe_hit) &&
                                        (now_tick - s_native_dc_tick <= kNativeDblClickTicks) &&
                                        (s_native_dc_x == cx) && (s_native_dc_y == cy);
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
                        duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
            }
            else if (resize.active)
            {
                // Resize-drag: feed the cumulative cursor delta
                // since the press into the resize calc, anchored
                // on the press-time bounds.
                const duetos::i32 dx = static_cast<duetos::i32>(cx) - static_cast<duetos::i32>(resize.anchor_cx);
                const duetos::i32 dy = static_cast<duetos::i32>(cy) - static_cast<duetos::i32>(resize.anchor_cy);
                duetos::drivers::video::WindowResizeFromEdge(resize.window, resize.edge, resize.anchor_x,
                                                             resize.anchor_y, resize.anchor_w, resize.anchor_h, dx, dy);
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
            }

            // Hover responsiveness: when a menu is open and the
            // cursor moved this frame, force an immediate recompose
            // so the highlighted row tracks the mouse without
            // waiting for the 1 Hz ui-ticker. Skipped during drag
            // (drag has its own compose) and when the menu was
            // already handled (the dispatch path composes too).
            if (!drag.active && !menu_handled && duetos::drivers::video::MenuIsOpen() && (p.dx != 0 || p.dy != 0))
            {
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
            }

            duetos::drivers::video::CompositorUnlock();

            SerialWrite("[mouse] dx=");
            SerialWriteHex(static_cast<duetos::u64>(p.dx));
            SerialWrite(" dy=");
            SerialWriteHex(static_cast<duetos::u64>(p.dy));
            SerialWrite(" btn=");
            SerialWriteHex(p.buttons);
            SerialWrite("\n");
        }
    };
    duetos::sched::SchedCreate(mouse_reader, nullptr, "mouse-reader");
    SerialWrite("[bringup-tail] mouse-reader spawned\n");

    // Win32 timer ticker: walks the per-window timer table every
    // scheduler tick (10 ms) and posts WM_TIMER when a timer
    // elapses. SYS_WIN_TIMER_SET / KILL mutate the table
    // directly. Runs under the compositor lock so it serialises
    // with the input readers + GetMessage blockers.
    auto win_timer_ticker = [](void*)
    {
        for (;;)
        {
            duetos::sched::SchedSleepTicks(1);
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::WindowTimerTick();
            duetos::drivers::video::CompositorUnlock();
        }
    };
    duetos::sched::SchedCreate(win_timer_ticker, nullptr, "win-timer");

    // Scheduler self-test: three kernel threads that each bump a shared
    // counter five times under a mutex. If the mutex serialises them
    // correctly, the counter reaches exactly 15 and the prints interleave
    // without any skipped values. A race would skip values (two workers
    // reading the same `before` and writing `before + 1`). This also
    // exercises WaitQueueBlock / WaitQueueWakeOne whenever two workers
    // collide on MutexLock, so the wait-queue machinery is on the boot
    // path by default.
    static duetos::sched::Mutex s_demo_mutex{};
    static duetos::u64 s_shared_counter = 0;

    auto worker = [](void* arg)
    {
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

            SerialWrite("[sched] ");
            SerialWrite(name);
            SerialWrite(" i=");
            SerialWriteHex(i);
            SerialWrite(" counter=");
            SerialWriteHex(s_shared_counter);
            SerialWrite("\n");

            duetos::sched::MutexUnlock(&s_demo_mutex);
            duetos::sched::SchedSleepTicks(1); // yield + 10 ms pause
        }
    };

    // Scheduler self-test workers exit after 5 iterations and so
    // they bump g_tasks_exited — which would falsely satisfy
    // SmokeProfileSleepAndExit's delta wait if they happened to
    // finish during the smoke profile's polling window. Under any
    // smoke profile (i.e. not None) the workers add no signature
    // coverage the smoke wrapper checks, so gate them to bare-
    // metal full-boot only. Local-dev `tools/qemu/run.sh` (no
    // smoke arg → profile=None) keeps running them.
    if (duetos::test::SmokeProfileGet() == duetos::test::SmokeProfile::None)
    {
        duetos::sched::SchedCreate(worker, const_cast<char*>("A"), "worker-A");
        duetos::sched::SchedCreate(worker, const_cast<char*>("B"), "worker-B");
        duetos::sched::SchedCreate(worker, const_cast<char*>("C"), "worker-C");
    }

    // First ring-3 slice: spawn a dedicated scheduler thread that maps a
    // user code + stack page, drops to ring 3, and runs an interruptible
    // pause/jmp loop forever. Kernel workers above keep running and
    // periodically preempt it; the proof-of-life is that this whole
    // boot sequence continues to make forward progress after the
    // iretq into user mode.
    SerialWrite("[boot] >>> StartRing3SmokeTask\n");
    duetos::core::StartRing3SmokeTask();
    SerialWrite("[boot] <<< StartRing3SmokeTask\n");
    // Linux-ABI proof-of-life suite. Each Spawn below adds a
    // ring-3 task whose stdout lines are not asserted by the
    // pe-* / ring3 smoke profiles. Profile-gated so:
    //   - profile=None on bare metal: spawn every Linux smoke
    //   - profile=None on emulator (local dev): skip (slow under
    //     TCG; the ShouldSpawn(Linux) helper handles this)
    //   - profile=linux: spawn (specific profile asked for them)
    //   - any other profile: skip
    if (duetos::test::SmokeProfileShouldSpawn(duetos::test::SmokeTarget::Linux))
    {
        // Linux-ABI proof-of-life. Reaches MSR_LSTAR entry stub →
        // LinuxSyscallDispatch → sys_exit_group. A clean exit here
        // proves the whole plumbing — EFER.SCE, MSR setup, swapgs
        // dance, iretq return — works end-to-end.
        duetos::subsystems::linux::SpawnRing3LinuxSmoke();

        // synxtest is the "compile-and-run an executable to see what
        // works" probe — a single static-C ELF that exercises ~120
        // Linux syscalls and prints a pass/fail / rc tag per call. We
        // also run it under profile=Linux because it's bounded
        // (one process, one exit) and the failure-inventory it prints
        // is the single most useful Linux-ABI signal in the boot log.
        // The other five Linux smokes (ElfSmoke / FileSmoke /
        // MmapSmoke / TranslateSmoke / ExtendSmoke) cumulatively burn
        // ~50s of guest time at the runner's ~12:1 wall:guest ratio,
        // so they stay gated on profile=None bare metal.
        duetos::subsystems::linux::SpawnSynxTestElf();
        // synfs is synxtest's sister with kCapFsRead + kCapFsWrite —
        // every FS-mutation syscall (mkdir/rmdir/rename/chmod/
        // truncate/unlink/copy_file_range/...) actually reaches the
        // kernel handler. Same `bounded, prints rc per call` shape so
        // it's safe under TCG.
        duetos::subsystems::linux::SpawnSynfsElf();
        // synet is the socket-family sibling. kCapNet so the BSD
        // socket calls reach the v0 net stack. Same atomic-line
        // [net] output convention as synfs.
        duetos::subsystems::linux::SpawnSynetElf();
        // synfull is the exhaustive variant — issues every spec
        // syscall (0..462 modulo skip-list) with zero args and
        // prints `[full] <nr>=<rc>`. Coverage matrix for the
        // entire Linux ABI surface.
        duetos::subsystems::linux::SpawnSynfullElf();

        if (duetos::test::SmokeProfileGet() == duetos::test::SmokeProfile::None)
        {
            // Same payload wrapped in an ELF64 image loaded via
            // SpawnElfLinux — proves the loader + abi-flavor plumbing
            // works in an in-memory path.
            duetos::subsystems::linux::SpawnRing3LinuxElfSmoke();
            // sys_open/read/close exercise: open HELLO.TXT from FAT32
            // via the Linux ABI and echo its contents back through
            // sys_write. Validates the whole file-I/O chain end-to-end.
            duetos::subsystems::linux::SpawnRing3LinuxFileSmoke();
            // File-backed mmap exerciser: open HELLO.TXT, mmap 17 bytes
            // PROT_READ + MAP_PRIVATE, write the mapped region to
            // stdout. Proves the new file-backed branch in DoMmap works
            // end-to-end — anonymous mmap was the only shape supported
            // before this slice.
            duetos::subsystems::linux::SpawnRing3LinuxMmapSmoke();
            // Translation-unit exercise: fire one syscall that the TU
            // converts to a no-op (madvise) and one it declines with a
            // deliberate -ENOSYS (rseq). Boot log shows [translate]
            // lines for each.
            duetos::subsystems::linux::SpawnRing3LinuxTranslateSmoke();
            // File-extend exerciser: opens HELLO.TXT, seeks to EOF,
            // writes a few bytes (routes through Fat32AppendAtPath),
            // closes, prints "extended\n" to stdout. Slot 12's
            // untested-at-the-time extend path gets a boot-time check.
            duetos::subsystems::linux::SpawnRing3LinuxExtendSmoke();
            // Real-binary path: read /fat/LINUX.ELF off the mounted
            // FAT32 volume and spawn it via SpawnElfLinux. Exercises
            // the AHCI -> GPT -> partition-block -> FAT32 -> ElfLoad
            // -> Linux-ABI chain end-to-end. Silent no-op when no FAT32
            // volume is probed (e.g. when the self-test harness forgets
            // to ship an image).
            const auto* fat_vol = duetos::fs::fat32::Fat32Volume(0);
            if (fat_vol != nullptr)
            {
                duetos::fs::fat32::DirEntry elf_entry;
                if (duetos::fs::fat32::Fat32LookupPath(fat_vol, "LINUX.ELF", &elf_entry))
                {
                    static duetos::u8 elf_buf[4096];
                    const duetos::i64 n =
                        duetos::fs::fat32::Fat32ReadFile(fat_vol, &elf_entry, elf_buf, sizeof(elf_buf));
                    if (n > 0)
                    {
                        SerialWrite("[boot] Spawning /fat/LINUX.ELF via SpawnElfLinux.\n");
                        duetos::core::SpawnElfLinux("fat-linux-elf", elf_buf, static_cast<duetos::u64>(n),
                                                    duetos::core::CapSetEmpty(), duetos::fs::RamfsSandboxRoot(),
                                                    /*frame_budget=*/16, duetos::core::kTickBudgetSandbox);
                    }
                    else
                    {
                        SerialWrite("[boot] /fat/LINUX.ELF read failed — skipping autospawn.\n");
                    }
                }
            }
        }
    }

    // qemu-smoke profile dispatch. If the cmdline carried
    // `smoke=<profile>`, we've spawned exactly the profile's
    // target task(s) above (every other ShouldSpawn call returned
    // false). Sleep long enough for those tasks to print their
    // expected sentinels, write the [smoke] complete line, and
    // exit QEMU via isa-debug-exit. The boot tail below
    // (SmpStartAps, Phase::Userland, idle loop) is reserved for
    // profile=None / bare-metal full boot — under a smoke profile
    // we never reach it, sparing the wall budget.
    SerialWrite("[boot] >>> SmokeProfileSleepAndExit\n");
    duetos::test::SmokeProfileSleepAndExit();
    SerialWrite("[boot] <<< SmokeProfileSleepAndExit (returned, profile=None path)\n");

    // Reschedule-IPI handler must be installed BEFORE any AP can
    // wake, since the moment an AP joins the scheduler a peer-CPU
    // wake (e.g. WaitQueueWakeOne firing on the BSP and routing to
    // the AP's runqueue) will pull the IPI trigger.
    duetos::arch::SmpInstallReschedIpiHandler();

    // Bring up APs. SmpStartAps calls SchedSleepTicks(1) between
    // INIT and SIPI; the dedicated idle task installed at the top
    // of SchedInit guarantees the runqueue is non-empty, so the
    // BSP always has something to switch to while it sleeps —
    // independent of worker-creation order.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

    // Every AP populated its own k_topo[i] before flipping the
    // trampoline's online_flag, so by the time SmpStartAps returns
    // the per-CPU topology table is complete. Pick a cluster-id
    // rule (NUMA-node, package, or single) and propagate to PerCpu.
    duetos::cpu::TopologyAssignClusters();
    duetos::cpu::TopologyDump();

    // Runtime invariant checker baseline. Capture NOW, after
    // every init that touches IDT / GDT / TSS / CR4 / EFER has
    // run — so the hashes reflect the final steady-state view
    // of those structures. Earlier capture would flag every
    // subsequent IdtSetUserGate / TssSetRsp0 as "drift".
    duetos::core::RuntimeCheckerInit();

    // NMI watchdog. Arms a PMU counter to fire NMI every few
    // seconds of real execution; if the timer IRQ stops
    // incrementing its pet counter across consecutive NMIs the
    // kernel is declared wedged. Silently no-ops if the CPU
    // doesn't advertise architectural perfmon (typical on
    // QEMU TCG). Called AFTER TimerInit so the pet-from-IRQ
    // path is already live — otherwise the very first overflow
    // would find a zero pet counter and immediately strike.
    duetos::arch::NmiWatchdogInit();

    // ntdll bedrock-coverage scoreboard. Cheap one-shot log line
    // that records how many of the 292 universal NT calls
    // (j00ru's table) we currently route to internal SYS_*. Lets
    // the boot log act as a regression detector — if a future
    // refactor breaks a SYS_* used in the mapping, the count
    // drops and the change is visible.
    duetos::win32::Win32LogNtCoverage();
    duetos::subsystems::linux::LinuxLogAbiCoverage();

    // Stage-2 EAT parser + DLL loader smoke test. Loads an
    // embedded ~2 KiB test DLL into a scratch AS, walks its
    // Phase::Userland (plan A1-followup, 2026-04-28). The two
    // very-late self-tests — DllLoader (PE32+ load + import-table
    // walk + export-directory resolution against a synthetic
    // image) and Win32 custom-diagnostics (every recorded hook
    // fires through a synthetic process) — both need ring-3
    // smokes to have spawned + the ABI plumbing to be live, so
    // they fit Phase::Userland cleanly. With this slice
    // Earlycon + PhysMem + Heap + Paging + Idt + Apic + Time +
    // Sched + Drivers + Vfs + Userland are ALL on the registry.
    // The only remaining imperative tail is one-shot subsystem
    // bring-up that doesn't have a SelfTest function (idle loop,
    // heartbeat thread, etc.).
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegister(duetos::core::Phase::Userland, "elf-loader-unwind-selftest",
                                       []()
                                       {
                                           duetos::core::ElfLoaderUnwindSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Userland, "dll-loader-selftest",
                                       []()
                                       {
                                           duetos::core::DllLoaderSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        duetos::core::InitcallRegister(duetos::core::Phase::Userland, "win32-custom-selftest",
                                       []()
                                       {
                                           duetos::subsystems::win32::custom::Win32CustomSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Userland);

    duetos::core::StartHeartbeatThread();

    SerialWrite("[boot] All subsystems online. Entering idle loop.\n");

#ifdef DUETOS_CRTRACE_SURVEY
    // Survey-mode dump. The shell-side `crtrace show` command also
    // mirrors to serial; this boot-time variant fires once all
    // subsystems are online so headless CI runs capture the full
    // ring without needing to drive the shell. Gated because the
    // dump is hundreds of lines and noisy on normal interactive
    // boots. Enable with `cmake -DDUETOS_CRTRACE_SURVEY=ON`.
    {
        const duetos::u32 cr_count = duetos::core::CleanroomTraceCount();
        SerialWrite("=== CRTRACE BOOT DUMP BEGIN count=");
        SerialWriteHex(cr_count);
        SerialWrite(" ===\n");
        for (duetos::u32 i = 0; i < cr_count; ++i)
        {
            duetos::core::CleanroomTraceEntry e{};
            if (!duetos::core::CleanroomTraceRead(i, &e))
                continue;
            SerialWrite("CRTRACE [");
            SerialWriteHex(i);
            SerialWrite("] ");
            SerialWrite(e.subsystem);
            SerialWrite("::");
            SerialWrite(e.event);
            duetos::core::CleanroomTraceWriteDecoded(e);
            SerialWrite("\n");
        }
        SerialWrite("=== CRTRACE BOOT DUMP END ===\n");
    }
#endif

#ifdef DUETOS_CANARY_DEMO
    // Compile-time-gated deliberate stack smash. Calls a helper that
    // overruns a local array past its stack canary; on function
    // return, the compiler-inserted epilogue reads the stashed
    // canary, finds it clobbered, and tail-calls __stack_chk_fail,
    // which panics with "stack canary corrupted — overflow detected".
    //
    // MUST be a function that actually returns — kernel_main itself
    // doesn't (it ends in IdleLoop), so the epilogue-check would
    // never run if we inlined the smash here.
    CanarySmashDemo();
#endif

#ifdef DUETOS_ATTACK_SIM
    // Compile-time-gated red-team attack suite. Runs five
    // in-kernel attack scenarios (IDT hijack, GDT swap, LSTAR
    // syscall-hook, canary defang, LBA 0 bootkit write) and
    // verifies the runtime invariant checker catches each one.
    // OFF in normal builds because the simulations escalate the
    // guard to Enforce + blockguard to Deny — stateful
    // side-effects that would poison subsequent image loads /
    // sensitive-LBA writes for the rest of the boot.
    // Run the suite under the purple-team scorecard wrapper. The
    // wrapper calls AttackSimRun internally and brackets it with
    // event-ring snapshots + a per-suite coverage percentage.
    duetos::security::PurpleTeamRunAll();
#endif

#ifdef DUETOS_PANIC_DEMO
    // Compile-time-gated deliberate panic used by tools/debug/test-panic.sh
    // to verify the panic path stays healthy end-to-end. Never
    // enabled in a normal build — the default preset does not pass
    // -DDUETOS_PANIC_DEMO.
    duetos::core::Panic("test/panic-demo", "DUETOS_PANIC_DEMO enabled; halting on purpose");
#endif

#ifdef DUETOS_TRAP_DEMO
    // Compile-time-gated deliberate CPU exception used by
    // tools/debug/test-trap.sh to verify the trap dispatcher's crash-dump
    // path produces an extractable record (BEGIN/END markers,
    // symbolized RIP, backtrace). `ud2` is the canonical "never
    // resume" undefined-opcode encoding and raises #UD with no
    // error code.
    asm volatile("ud2");
#endif

    // Terminate the boot task instead of idle-looping on the boot
    // stack. Rationale: kboot runs on the low-VA boot stack
    // (.bss.boot). Any Schedule() triggered from kboot's context
    // (e.g. a timer IRQ that raises need_resched) flips CR3 to
    // whatever task we're switching INTO. Per-process ASes zero
    // PML4[0..255], so the boot stack's low VA isn't reachable
    // after the flip — the next stack access would #PF on IST
    // stacks (also low-VA) and cascade into a #DF cluster.
    //
    // SchedExit marks kboot Dead, drops it from the runqueue,
    // and loops in Schedule() picking other tasks. The dedicated
    // idle task (SchedStartIdle) ensures the runqueue is never
    // empty. From this point on, kboot is never re-scheduled and
    // the boot stack is never touched again — it just sits at
    // low VA unreferenced until reboot.
    //
    // Note: kboot has stack_base=nullptr (it never had a
    // scheduler-allocated stack), so the reaper's KFree(stack_base)
    // is a no-op for it. The boot stack's .bss.boot storage isn't
    // heap-managed; the linker placed it and it persists.
    duetos::sched::SchedExit();
}
