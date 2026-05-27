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
#include "cpu/ipi_call.h"
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
#include "diag/selfthink.h"
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
#include "util/result_check.h"
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
#include "security/gui_fuzz.h"
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
    SerialWrite("[bringup-tail] kernel-services done\n");

    // The LAPIC timer is armed and interrupts are live (the scheduler
    // has been running since BootBringupKernelServices). Verify the
    // tick is actually being delivered before any long-running ring-3
    // task is spawned; on hypervisors where the LAPIC timer counts
    // but never raises its IRQ (VirtualBox), this transparently
    // switches the scheduler tick to an IOAPIC-routed PIT source so
    // preemption works. No-op on QEMU / real hardware.
    duetos::arch::TimerVerifyDeliveryOrFallback();

    duetos::core::BootBringupDevices(CmdlineMatches(cmdline, "netsmoke", "force"));
    SerialWrite("[bringup-tail] devices done\n");

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

    // `gui-fuzz[=secs]` arms the self-driving GUI stress harness in
    // kernel/security/gui_fuzz.cpp. Like pentest=gui it must come
    // up after the kbd-reader/mouse-reader are live so the
    // injection rings have a drainer. No-op when the token is
    // absent. Pair with autologin=1 so events land on the desktop.
    duetos::security::GuiFuzzArm(cmdline);

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
    duetos::sched::SchedCreate(duetos::core::MouseReaderTask, nullptr, "mouse-reader");
    SerialWrite("[bringup-tail] mouse-reader spawned\n");

    // Win32 timer ticker: walks the per-window timer table every
    // scheduler tick (10 ms) and posts WM_TIMER when a timer
    // elapses. SYS_WIN_TIMER_SET / KILL mutate the table
    // directly. Runs under the compositor lock so it serialises
    // with the input readers + GetMessage blockers.
    duetos::sched::SchedCreate(duetos::core::WinTimerTickerTask, nullptr, "win-timer");

    // Scheduler self-test: three kernel threads that each bump a shared
    // counter five times under a mutex. If the mutex serialises them
    // correctly, the counter reaches exactly 15 and the prints interleave
    // without any skipped values. A race would skip values (two workers
    // reading the same `before` and writing `before + 1`). This also
    // exercises WaitQueueBlock / WaitQueueWakeOne whenever two workers
    // collide on MutexLock, so the wait-queue machinery is on the boot
    // path by default.

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
        duetos::sched::SchedCreate(duetos::core::SchedDemoWorkerTask, const_cast<char*>("A"), "worker-A");
        duetos::sched::SchedCreate(duetos::core::SchedDemoWorkerTask, const_cast<char*>("B"), "worker-B");
        duetos::sched::SchedCreate(duetos::core::SchedDemoWorkerTask, const_cast<char*>("C"), "worker-C");
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
    // Cross-CPU function-call IPI (kernel/cpu/ipi_call.h). Must
    // install BEFORE SmpStartAps so the AP IDT clone (built during
    // bring-up) inherits the wired vector — otherwise the first
    // IpiCallEach to a fresh AP would fault on an empty IDT slot.
    duetos::cpu::IpiCallInstall();

    // Bring up APs. SmpStartAps calls SchedSleepTicks(1) between
    // INIT and SIPI; the dedicated idle task installed at the top
    // of SchedInit guarantees the runqueue is non-empty, so the
    // BSP always has something to switch to while it sleeps —
    // independent of worker-creation order.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

    // Drive any future Phase::Smp registrants now that APs are
    // online and the per-CPU runqueues exist.
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Smp), "boot", "RunPhase Smp");

    // Every AP populated its own k_topo[i] before flipping the
    // trampoline's online_flag, so by the time SmpStartAps returns
    // the per-CPU topology table is complete. Pick a cluster-id
    // rule (NUMA-node, package, or single) and propagate to PerCpu.
    duetos::cpu::TopologyAssignClusters();
    duetos::cpu::TopologyDump();

    // Cross-CPU function-call primitive self-test. Drives:
    //   - IpiCallOne to self (wait=true / wait=false).
    //   - IpiCallOne to a peer CPU when SMP > 1.
    //   - IpiCallEach across every online CPU.
    // Unconditional (not gated by `kBootSelfTests`) so the
    // structural `[ipi-call] self-test OK` sentinel appears in
    // release smoke logs too — the primitive is foundational
    // enough that a silent regression would mask real breakage in
    // future TLB-shootdown / runtime-checker callers.
    duetos::cpu::IpiCallSelfTest();

    // Runtime invariant checker baseline is owned by
    // `BootBringupKernelServices`: it runs `RuntimeCheckerTeardown`
    // + `RuntimeCheckerInit` immediately after `linux::SyscallInit`
    // programs LSTAR/STAR/CSTAR/SYSENTER (see boot_bringup.cpp's
    // post-SyscallInit re-baseline). Nothing between that point and
    // the idle loop mutates the baselined GLOBAL state:
    //   - GDT contents are stable (per-CPU TSS rsp0 lives in the
    //     per-CPU TSS body, not g_gdt; LTR's BUSY bit is masked
    //     by GdtHash; AP GDT bundles are separate from g_gdt).
    //   - IDT contents are stable (IdtSetUserGate fires only from
    //     core::SyscallInit, which is much earlier).
    //   - CR0/CR4/EFER are stable on the BSP (NmiWatchdogInit
    //     below programs PMU MSRs, which the baseline doesn't
    //     touch; CET enable would mutate CR4 but is not wired in).
    // A redundant re-init here also runs in scheduler context AFTER
    // `SmpStartAps`, so it can land on an AP whose LSTAR/STAR/CR0
    // differ from the BSP — capturing those AP-local values as the
    // baseline then trips a false `SyscallMsrHijacked` alarm on
    // every subsequent BSP-side scan. Leave the canonical
    // post-SyscallInit baseline as the source of truth.

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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "elf-loader-unwind-selftest",
                                              []()
                                              {
                                                  duetos::core::ElfLoaderUnwindSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "dll-loader-selftest",
                                              []()
                                              {
                                                  duetos::core::DllLoaderSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "win32-custom-selftest",
                                              []()
                                              {
                                                  duetos::subsystems::win32::custom::Win32CustomSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Periodic load-balancer decision test. Lives in Phase::Userland
        // because it needs SmpStartAps + TopologyAssignClusters to have
        // run — earlier phases only see the BSP, which exercises the
        // single-CPU short-circuit but never the cluster + margin paths.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "sched-loadbalance-selftest",
                                              []()
                                              {
                                                  duetos::sched::LoadBalanceSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // SMT-aware placement decision test. Same Phase::Userland
        // rationale: needs SmpStartAps + TopologyAssignClusters
        // (which now also runs AssignCoreGroups) to have finalized
        // the per-CPU core_group / sibling fields it asserts on.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "smt-placement-selftest",
                                              []()
                                              {
                                                  duetos::sched::SmtPlacementSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Hard CPU affinity decision test. Same Phase::Userland
        // rationale: needs SmpStartAps so >=2 CPUs exist for the
        // forbidden-CPU placement checks (SKIPs otherwise).
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "affinity-mask-selftest",
                                              []()
                                              {
                                                  duetos::sched::AffinityMaskSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Hybrid P/E-core placement bias decision test. SKIPs on
        // every QEMU guest (no Intel-hybrid model); locks the
        // decision-function contract for real hardware.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "hybrid-placement-selftest",
                                              []()
                                              {
                                                  duetos::sched::HybridPlacementSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // MWAIT-idle feature-gate test. PASSes on every guest
        // (reports mwait vs hlt-fallback) — a real green signal.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "idle-power-selftest",
                                              []()
                                              {
                                                  duetos::sched::IdlePowerSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // APIC-mode consistency test (x2APIC vs xAPIC). PASSes on
        // every guest, reporting the active mode — a real signal.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Userland, "apic-mode-selftest",
                                              []()
                                              {
                                                  duetos::arch::ApicModeSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Userland), "boot", "RunPhase Userland");

    duetos::core::StartHeartbeatThread();

    // Cross-subsystem self-portrait + causal-chain ring. Mirrors
    // kheartbeat's shape: a kthread on a steady tick cadence
    // keeps the latest portrait fresh so shell queries don't
    // rebuild on every read. The causal ring is appended to
    // independently by the probe / autonomic / runtime-checker
    // paths; the kthread just refreshes the snapshot.
    duetos::diag::selfthink::StartSelfthinkThread();

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
