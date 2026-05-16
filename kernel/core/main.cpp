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
#include "util/saturating.h"
#include "util/datetime.h"
#include "util/deflate.h"
#include "util/gzip.h"
#include "util/zip.h"
#include "util/jpeg.h"
#include "util/png.h"
#include "util/tga.h"
#include "util/types.h"
#include "util/unicode.h"
#include "util/vt_parser.h"
#include "acpi/acpi.h"
#include "acpi/aml.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cet.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/fpu.h"
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
#include "debug/hot_patch.h"
#include "debug/extable.h"
#include "debug/probes.h"
#include "debug/tripwire.h"
#include "debug/watch.h"
#include "drivers/audio/audio.h"
#include "drivers/audio/hda.h"
#include "drivers/audio/hda_jack.h"
#include "drivers/audio/hda_jack_inventory.h"
#include "subsystems/audio/audio_backend.h"
#include "drivers/gpu/cea861.h"
#include "drivers/gpu/cvt.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/edid.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/amd_gpu.h"
#include "drivers/gpu/gpu_resources.h"
#include "drivers/gpu/intel_gpu.h"
#include "drivers/gpu/intel_gsc_fw.h"
#include "drivers/gpu/nvidia_gpu.h"
#include "drivers/input/hid_keyboard.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/net/ath9k_htc.h"
#include "drivers/net/ath9k_htc_fw.h"
#include "drivers/net/ath9k_htc_upload.h"
#include "drivers/net/bcm43xx_fw.h"
#include "drivers/net/bcm43xx_upload.h"
#include "drivers/net/firmware_policy.h"
#include "drivers/net/iwlwifi_fw.h"
#include "drivers/net/iwlwifi_rings.h"
#include "drivers/net/iwlwifi_ucode_builder.h"
#include "drivers/net/iwlwifi_upload.h"
#include "drivers/net/mt76_fw.h"
#include "drivers/net/net.h"
#include "drivers/net/rtl88xx_fw.h"
#include "drivers/net/rtl88xx_upload.h"
#include "net/bluetooth/diag.h"
#include "net/drsh/drsh.h"
#include "net/bluetooth/hci.h"
#include "net/bluetooth/hid.h"
#include "net/wireless/beacon.h"
#include "net/wireless/inventory.h"
#include "crypto/aes.h"
#include "crypto/aes_gcm.h"
#include "crypto/aes_keywrap.h"
#include "crypto/asn1.h"
#include "crypto/bigint.h"
#include "crypto/hkdf.h"
#include "crypto/rsa.h"
#include "crypto/x509.h"
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
#include "drivers/virtio/virtio.h"
#include "drivers/power/power.h"
#include "drivers/usb/btusb.h"
#include "drivers/usb/cdc_ecm.h"
#include "drivers/usb/hid_descriptor.h"
#include "drivers/usb/usb_class_desc.h"
#include "drivers/usb/msc_scsi.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "net/net_smoke.h"
#include "net/firewall.h"
#include "net/stack.h"
#include "net/tcp.h"
#include "net/tls.h"
#include "subsystems/graphics/graphics.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/block.h"
#include "drivers/storage/nvme.h"
#include "fs/boot_slot.h"
#include "fs/duetfs.h"
#include "fs/exfat.h"
#include "fs/ext4.h"
#include "fs/fat32.h"
#include "fs/file_route.h"
#include "fs/gpt.h"
#include "fs/installer.h"
#include "fs/ntfs.h"
#include "apps/calculator.h"
#include "apps/about.h"
#include "apps/browser.h"
#include "apps/calendar.h"
#include "apps/charmap.h"
#include "apps/clock.h"
#include "apps/notify_center.h"
#include "apps/devicemgr.h"
#include "apps/hexview.h"
#include "apps/sysmon.h"
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
#include "apps/terminal.h"
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
#include "ipc/iocp.h"
#include "diag/event_trace.h"
#include "diag/fault_inject.h"
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
#include "ipc/named_kobjects.h"
#include "ipc/named_pipes.h"
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
#include "security/argon2id.h"
#include "security/auth.h"
#include "security/auth_pentest.h"
#include "security/blake2b.h"
#include "security/chacha20_poly1305.h"
#include "security/persistence.h"
#include "security/broker.h"
#include "security/cap_audit.h"
#include "security/grace.h"
#include "security/rbac.h"
#include "security/kaslr.h"
#include "loader/firmware_loader.h"
#include "loader/firmware_package.h"
#include "diag/heartbeat.h"
#include "diag/stress_driver.h"
#include "log/klog.h"
#include "log/klog_persist.h"
#include "power/reboot.h"
#include "security/login.h"
#include "core/boot_bringup.h"
#include "core/boot_cmdline.h"
#include "core/boot_tasks.h"
#include "core/init.h"
#include "core/menu_dispatch.h"
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
#include "proc/spawn.h"
#include "diag/runtime_checker.h"
#include "diag/ubsan.h"
#include "subsystems/linux/ring3_smoke.h"
#include "subsystems/linux/syscall.h"
#include "subsystems/win32/apc_selftest.h"
#include "subsystems/win32/custom_selftest.h"
#include "subsystems/win32/heap_selftest.h"
#include "subsystems/win32/vmap_selftest.h"
#include "subsystems/win32/gdi_objects.h"
#include "subsystems/win32/nt_coverage.h"
#include "subsystems/win32/registry.h"
#include "subsystems/win32/window_syscall.h"
#include "loader/compat_shim.h"
#include "loader/dll_loader.h"
#include "loader/elf_loader.h"
#include "shell/shell.h"
#include "syscall/syscall.h"
#include "mm/kheap.h"
#include "mm/slab.h"
#include "mm/kstack.h"
#include "mm/multiboot2.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "sched/workpool.h"
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

// FindBootCmdline / CmdlineMatches were hoisted into the
// shared core/boot_cmdline TU so the boot-bringup TUs can use
// them too. Pull them into this anonymous namespace so the
// existing unqualified call sites in kernel_main resolve
// unchanged.
using duetos::core::CmdlineMatches;
using duetos::core::FindBootCmdline;

} // namespace

extern "C" void kernel_main(duetos::u32 multiboot_magic, duetos::uptr multiboot_info)
{
    using namespace duetos::arch;
    using namespace duetos::mm;

    duetos::core::BootBringupEarly(multiboot_magic, multiboot_info);
    duetos::core::BootBringupMemPaging();
    duetos::core::BootBringupDesktop(multiboot_info);

    // cmdline was resolved inside BootBringupDesktop; re-derive
    // the cached pointer for the remaining boot phases. This is
    // a cache hit — FindBootCmdline does not re-walk the (by now
    // possibly-unmapped) multiboot_info buffer.
    const char* cmdline = duetos::core::FindBootCmdline(multiboot_info);

    duetos::core::BootBringupKernelServices(cmdline, multiboot_info);

    duetos::core::BootBringupDevices(CmdlineMatches(cmdline, "netsmoke", "force"));

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
    duetos::sched::Task* kbd_reader_task =
        duetos::sched::SchedCreate(duetos::core::KbdReaderTask, nullptr, "kbd-reader");
    SerialWrite("[bringup-tail] kbd-reader spawned\n");

    // Register the kbd-reader task id with the elevation broker so
    // off-thread broker requests (Win32 NtAdjustPrivilegesToken, any
    // future user-mode elevation API) route through the deferred-
    // prompt path instead of racing the shell for keystrokes.
    if (kbd_reader_task != nullptr)
    {
        duetos::security::BrokerSetKbdReaderTid(duetos::sched::TaskId(kbd_reader_task));
    }

    // `pentest=gui` scripts keystrokes into the login gate + shell.
    // Arm it only after the kbd-reader is live; starting it when the
    // login gate opens overflows the keyboard injection ring because
    // no reader exists yet to drain synthetic key events.
    if (CmdlineMatches(cmdline, "pentest", "gui"))
    {
        SerialWrite("[boot] pentest=gui — arming GUI pentest runner\n");
        duetos::security::PentestGuiStart();
    }

    // `stress=cpu|mem|mix|spin` arms the boot-time stress driver in
    // kernel/diag/stress_driver.cpp. No-op when the token is absent,
    // so a normal boot pays nothing. Optional tunables come from the
    // same cmdline: stress-secs=N, stress-workers=N, stress-mib=N.
    duetos::core::diag::StressDriverArm(cmdline);

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
    duetos::sched::SchedCreate(duetos::core::UiTickerTask, nullptr, "ui-ticker");
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
            {"SYSTEM MONITOR", 100 + static_cast<duetos::u32>(StartMenuRole::Sysmon), 0, nullptr, 0},
            {"KERNEL LOG", 100 + static_cast<duetos::u32>(StartMenuRole::LogView), 0, nullptr, 0},
            {"NETWORK STATUS", 60, 0, nullptr, 0},
            {"DEVICE MANAGER", 61, 0, nullptr, 0},
            {"FIREWALL", 62, 0, nullptr, 0},
            {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0},
            {"CYCLE WINDOWS", 2, 0, nullptr, 0},
            {"SWITCH TO TTY", 5, 0, nullptr, 0},
        };
        static const duetos::drivers::video::MenuItem kUtilitiesItems[] = {
            {"HEX VIEWER", 100 + static_cast<duetos::u32>(StartMenuRole::HexView), 0, nullptr, 0},
            {"CHARACTER MAP", 100 + static_cast<duetos::u32>(StartMenuRole::CharMap), 0, nullptr, 0},
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
        static duetos::drivers::video::MenuItem kStartItems[7] = {};
        kStartItems[0] = {"APPS", 0, kMenuItemFlagSubmenu, kAppsItems, sizeof(kAppsItems) / sizeof(kAppsItems[0])};
        kStartItems[1] = {"UTILITIES", 0, kMenuItemFlagSubmenu, kUtilitiesItems,
                          sizeof(kUtilitiesItems) / sizeof(kUtilitiesItems[0])};
        kStartItems[2] = {"SYSTEM", 0, kMenuItemFlagSubmenu, kSystemItems,
                          sizeof(kSystemItems) / sizeof(kSystemItems[0])};
        kStartItems[3] = {(user_apps_count == 0) ? "USER APPS (EMPTY)" : "USER APPS", 0,
                          kMenuItemFlagSubmenu | (user_apps_count == 0 ? kMenuItemFlagDisabled : 0u), kUserAppsItems,
                          user_apps_count};
        kStartItems[4] = {nullptr, 0, kMenuItemFlagSeparator, nullptr, 0};
        kStartItems[5] = {"SCREENSHOT", 50, 0, nullptr, 0};
        kStartItems[6] = {"POWER", 0, kMenuItemFlagSubmenu, kPowerItems, sizeof(kPowerItems) / sizeof(kPowerItems[0])};
        constexpr duetos::u32 start_items_count = sizeof(kStartItems) / sizeof(kStartItems[0]);
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
                else if (duetos::drivers::video::TaskbarContains(cx, cy))
                {
                    duetos::drivers::video::MenuOpen(
                        kTaskbarMenuItems, sizeof(kTaskbarMenuItems) / sizeof(kTaskbarMenuItems[0]), cx, cy, 0);
                    SerialWrite("[ui] right-click target=taskbar\n");
                }
                else
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
                        duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
                // Aero-style edge snap: dropping a dragged window
                // against a screen edge snaps it (top = maximize,
                // left/right = half). The snap APIs were already
                // keyboard-wired; the mouse drag-to-edge gesture —
                // what most users actually reach for — was the dead
                // zone. Compositor lock is held here (loop acquires
                // it at the top), so call the snap ops directly.
                const auto fb_snap = duetos::drivers::video::FramebufferGet();
                constexpr duetos::u32 kSnapEdge = 12;
                bool snapped = true;
                if (cy <= kSnapEdge)
                    duetos::drivers::video::WindowMaximize(drag.window);
                else if (cx <= kSnapEdge)
                    duetos::drivers::video::WindowSnapLeft(drag.window);
                else if (fb_snap.width > kSnapEdge && cx >= fb_snap.width - kSnapEdge)
                    duetos::drivers::video::WindowSnapRight(drag.window);
                else
                    snapped = false;
                SerialWrite(snapped ? "[ui] drag end (edge snap) window=" : "[ui] drag end window=");
                SerialWriteHex(drag.window);
                SerialWrite("\n");
                drag.active = false;
                if (snapped)
                {
                    duetos::drivers::video::CursorHide();
                    duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
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
    // TLB-shootdown IPI must be installed BEFORE APs come online —
    // the moment a peer CPU runs in any AS the BSP could be unmapping
    // a page from, the shootdown IPI is the only thing keeping that
    // peer's TLB from carrying a stale entry into a recycled frame.
    // wiki/security/Linux-CVE-Audit.md class FF.
    duetos::arch::SmpInstallTlbShootdownIpiHandler();

    // Bring up APs. SmpStartAps calls SchedSleepTicks(1) between
    // INIT and SIPI; the dedicated idle task installed at the top
    // of SchedInit guarantees the runqueue is non-empty, so the
    // BSP always has something to switch to while it sleeps —
    // independent of worker-creation order.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

    // Drive any future Phase::Smp registrants now that APs are
    // online and the per-CPU runqueues exist.
    (void)duetos::core::RunPhase(duetos::core::Phase::Smp);

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
        // Periodic load-balancer decision test. Lives in Phase::Userland
        // because it needs SmpStartAps + TopologyAssignClusters to have
        // run — earlier phases only see the BSP, which exercises the
        // single-CPU short-circuit but never the cluster + margin paths.
        duetos::core::InitcallRegister(duetos::core::Phase::Userland, "sched-loadbalance-selftest",
                                       []()
                                       {
                                           duetos::sched::LoadBalanceSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Userland);

    duetos::core::StartHeartbeatThread();

    // Inform the init-wedge watchdog (in arch/timer.cpp) that
    // bring-up has fully finished. Steady-state quiet windows after
    // this point — the idle loop, compositor naps with no input
    // pending — are legitimate and shouldn't fire the wedge probe.
    duetos::arch::MarkInitComplete();

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
