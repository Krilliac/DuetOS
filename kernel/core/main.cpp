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

#include "util/build_config.h"
#include "util/types.h"
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
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "cpu/percpu.h"
#include "debug/breakpoints.h"
#include "debug/extable.h"
#include "debug/probes.h"
#include "drivers/audio/audio.h"
#include "drivers/gpu/gpu.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/net/bcm43xx_fw.h"
#include "drivers/net/iwlwifi_fw.h"
#include "drivers/net/net.h"
#include "drivers/net/rtl88xx_fw.h"
#include "net/wireless/beacon.h"
#include "drivers/pci/pci.h"
#include "drivers/power/power.h"
#include "drivers/usb/cdc_ecm.h"
#include "drivers/usb/hid_descriptor.h"
#include "drivers/usb/msc_scsi.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "net/net_smoke.h"
#include "net/stack.h"
#include "subsystems/graphics/graphics.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/block.h"
#include "drivers/storage/nvme.h"
#include "fs/exfat.h"
#include "fs/ext4.h"
#include "fs/fat32.h"
#include "fs/file_route.h"
#include "fs/gpt.h"
#include "fs/ntfs.h"
#include "apps/calculator.h"
#include "apps/clock.h"
#include "apps/files.h"
#include "apps/gfxdemo.h"
#include "apps/notes.h"
#include "apps/screenshot.h"
#include "apps/settings.h"
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
#include "drivers/video/menu.h"
#include "drivers/video/start_menu_apps.h"
#include "drivers/video/netpanel.h"
#include "drivers/video/notify.h"
#include "drivers/video/taskbar.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/zone.h"
#include "ipc/handle_table.h"
#include "diag/event_trace.h"
#include "diag/gdb_stub.h"
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
#include "security/cap_audit.h"
#include "loader/firmware_loader.h"
#include "diag/heartbeat.h"
#include "log/klog.h"
#include "log/klog_persist.h"
#include "security/login.h"
#include "core/init.h"
#include "core/panic.h"
#include "core/session_restore.h"
#include "syscall/cap_gate.h"
#include "proc/process.h"
#include "util/random.h"
#include "security/driver_domain.h"
#include "security/fault_domain.h"
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
#include "shell/shell.h"
#include "syscall/syscall.h"
#include "mm/kheap.h"
#include "mm/kstack.h"
#include "mm/multiboot2.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "security/attack_sim.h"
#include "security/guard.h"
#include "security/pentest_gui.h"
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

// Walk the Multiboot2 tag list for type-1 (boot cmdline) and
// return its NUL-terminated string, or nullptr if absent. The
// pointer is into the live info struct; do not free.
const char* FindBootCmdline(duetos::uptr info_phys)
{
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
            return reinterpret_cast<const char*>(cursor + sizeof(duetos::mm::MultibootTagHeader));
        }
        cursor += (tag->size + 7u) & ~duetos::uptr{7};
    }
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
    ConsoleWriteln("    CTRL+C            INTERRUPT SHELL COMMAND");
    ConsoleWriteln("");
    ConsoleWriteln("  NOTES (WHEN ACTIVE)");
    ConsoleWriteln("    CTRL+C / CTRL+V   COPY / PASTE CLIPBOARD");
    ConsoleWriteln("    CTRL+S            SAVE TO NOTES.TXT (FAT32)");
    ConsoleWriteln("    CTRL+O            LOAD FROM NOTES.TXT (FAT32)");
    ConsoleWriteln("================================================");
    ConsoleWriteln("");
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

    // Per-driver fault-domain extension self-test (plan E3).
    // Wraps the core fault-domain registry with a driver-tag
    // convention; demo register/restart cycle.
    DUETOS_BOOT_SELFTEST(duetos::security::DriverDomainSelfTest());

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
        // mm/zone scaffold (plan C1) — additive layer over the
        // global frame allocator; v0 forwards every zone request
        // to the same pool.
        duetos::core::InitcallRegister(duetos::core::Phase::PhysMem, "zone-selftest",
                                       []()
                                       {
                                           ZoneSelfTest();
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
    // Static probes — KBP_PROBE(...) call sites sprinkled across
    // the kernel. Rare+useful events (panic, sandbox denial,
    // Win32 stub miss, kernel #PF) are armed-log by default so
    // the first boot shows activity without any arming.
    duetos::debug::ProbeInit();

    // Phase::Drivers — framebuffer is the only "driver" with a
    // self-test that fits the registry shape today; PCI/NVMe/USB
    // self-tests are inline checks rather than separately-named
    // SelfTest functions. (A1-followup, 2026-04-28.)
    SerialWrite("[boot] Bringing up framebuffer (if present).\n");
    duetos::drivers::video::FramebufferInit(multiboot_info);
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
    win_a_chrome.h = 220;
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
    taskman_chrome.w = 340;
    taskman_chrome.h = 170;
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

    duetos::drivers::video::WindowSetContentDraw(
        taskman_handle,
        [](duetos::u32 cx, duetos::u32 cy, duetos::u32 /*cw*/, duetos::u32 /*ch*/, void*)
        {
            using duetos::drivers::video::FramebufferDrawString;
            constexpr duetos::u32 kFg = 0x0080F088;
            // Match the window's current client fill so the text
            // rows sit on the same colour as the chrome client.
            const duetos::u32 kBg =
                duetos::drivers::video::ThemeCurrent()
                    .role_client[static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::TaskManager)];
            // Manual decimal formatter for u64 — kernel has no
            // printf. Fixed-width (10 digits) so the numeric
            // column doesn't jitter when values roll over.
            auto fmt_u64 = [](duetos::u64 v, char* out)
            {
                char tmp[24];
                duetos::u32 n = 0;
                if (v == 0)
                {
                    tmp[n++] = '0';
                }
                else
                {
                    while (v > 0 && n < sizeof(tmp))
                    {
                        tmp[n++] = static_cast<char>('0' + (v % 10));
                        v /= 10;
                    }
                }
                duetos::u32 pad = (n < 10) ? 10 - n : 0;
                duetos::u32 o = 0;
                for (duetos::u32 i = 0; i < pad; ++i)
                    out[o++] = ' ';
                for (duetos::u32 i = 0; i < n; ++i)
                    out[o++] = tmp[n - 1 - i];
                out[o] = '\0';
            };

            const auto s = duetos::sched::SchedStatsRead();
            const duetos::u64 total = duetos::mm::TotalFrames();
            const duetos::u64 free_frames = duetos::mm::FreeFramesCount();
            const duetos::u64 uptime_s = duetos::sched::SchedNowTicks() / 100;

            char num[24];
            char line[64];
            struct Row
            {
                const char* label;
                duetos::u64 value;
            };
            const Row rows[] = {
                {"UPTIME (S)     ", uptime_s},        {"CTX SWITCHES   ", s.context_switches},
                {"TASKS LIVE     ", s.tasks_live},    {"TASKS SLEEPING ", s.tasks_sleeping},
                {"TASKS BLOCKED  ", s.tasks_blocked}, {"MEM FREE (4K)  ", free_frames},
                {"MEM TOTAL (4K) ", total},
            };
            duetos::u32 y_off = cy + 4;
            for (duetos::u32 i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i)
            {
                fmt_u64(rows[i].value, num);
                duetos::u32 o = 0;
                for (duetos::u32 j = 0; rows[i].label[j] != '\0' && o + 1 < sizeof(line); ++j)
                    line[o++] = rows[i].label[j];
                for (duetos::u32 j = 0; num[j] != '\0' && o + 1 < sizeof(line); ++j)
                    line[o++] = num[j];
                line[o] = '\0';
                FramebufferDrawString(cx + 6, y_off, line, kFg, kBg);
                y_off += 10;
            }
        },
        nullptr);

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

    // SETTINGS — unified panel that wraps the Ctrl+Alt chord
    // surfaces (theme cycle / direct picker, opacity step, high-
    // contrast preset, default reset) plus a wall-clock and
    // about readout. Hidden by default; raised from the Start
    // menu's SETTINGS entry.
    duetos::drivers::video::WindowChrome settings_chrome = theme_chrome(Role::Settings);
    settings_chrome.x = 320;
    settings_chrome.y = 120;
    settings_chrome.w = 380;
    settings_chrome.h = 280;
    const duetos::drivers::video::WindowHandle settings_handle =
        duetos::drivers::video::WindowRegister(settings_chrome, "SETTINGS");
    duetos::drivers::video::ThemeRegisterWindow(Role::Settings, settings_handle);
    duetos::apps::settings::SettingsInit(settings_handle);
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsSelfTest());

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
    }
    (void)duetos::core::RunPhase(duetos::core::Phase::Vfs);

    SerialWrite("[boot] Parsing ACPI tables.\n");
    duetos::acpi::AcpiInit(multiboot_info);
    SerialWrite("[boot] Building AML namespace from DSDT/SSDT.\n");
    duetos::acpi::AmlNamespaceBuild();
    {
        auto aml_init = []() -> duetos::core::Result<void>
        {
            duetos::acpi::AmlNamespaceBuild();
            return {};
        };
        auto aml_teardown = []() -> duetos::core::Result<void> { return duetos::acpi::AmlNamespaceShutdown(); };
        duetos::core::FaultDomainRegister("acpi/aml", aml_init, aml_teardown);
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

    // CMOS is a 128-byte nvram that survives power-off; firmware
    // stashes BIOS setup + POST diagnostic codes + (on some
    // laptops) battery / thermal hints here. Dump it once at boot
    // for observability — the hex grid is enough for a reader to
    // cross-reference against vendor docs.
    duetos::arch::CmosDump();

    SerialWrite("[boot] Installing BSP per-CPU struct.\n");
    duetos::cpu::PerCpuInitBsp();

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
                                           duetos::diag::gdb::GdbStubSelfTest();
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

    SerialWrite("[boot] Detecting GPUs.\n");
    duetos::drivers::gpu::GpuInit();
    {
        auto gpu_init = []() -> duetos::core::Result<void>
        {
            duetos::drivers::gpu::GpuInit();
            return {};
        };
        auto gpu_teardown = []() -> duetos::core::Result<void> { return duetos::drivers::gpu::GpuShutdown(); };
        duetos::core::FaultDomainRegister("drivers/gpu", gpu_init, gpu_teardown);
    }

    SerialWrite("[boot] Bringing up firmware loader (scaffold).\n");
    duetos::core::FwLoaderInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::IwlFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::RtlFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::BcmFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::BeaconSelfTest());

    SerialWrite("[boot] Detecting NICs.\n");
    duetos::drivers::net::NetInit();
    {
        auto net_init = []() -> duetos::core::Result<void>
        {
            duetos::drivers::net::NetInit();
            return {};
        };
        auto net_teardown = []() -> duetos::core::Result<void> { return duetos::drivers::net::NetShutdown(); };
        duetos::core::FaultDomainRegister("drivers/net", net_init, net_teardown);
    }

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
        duetos::core::FaultDomainRegister("drivers/usb/xhci", xhci_init, xhci_teardown);
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
    {
        auto audio_init = []() -> duetos::core::Result<void>
        {
            duetos::drivers::audio::AudioInit();
            return {};
        };
        auto audio_teardown = []() -> duetos::core::Result<void> { return duetos::drivers::audio::AudioShutdown(); };
        duetos::core::FaultDomainRegister("drivers/audio", audio_init, audio_teardown);
    }

    SerialWrite("[boot] Bringing up power / thermal shell.\n");
    duetos::drivers::power::PowerInit();

    SerialWrite("[boot] Bringing up network stack skeleton.\n");
    duetos::net::NetStackInit();
    // Smoke test runs in its own task. It owns the (single) TCP
    // slot during its run and installs the boot HTTP listener
    // afterwards via NetSmokeInstallBootListener — so an active
    // connect to www.google.com (step 4) doesn't collide with
    // the listener's TcpListen call. `netsmoke=force` opts in to
    // running on emulator (QEMU SLIRP supports DNS+TCP egress).
    const bool force_net_smoke = CmdlineMatches(cmdline, "netsmoke", "force");
    duetos::net::NetSmokeTestStart(force_net_smoke);

    SerialWrite("[boot] Bringing up graphics ICD skeleton.\n");
    duetos::subsystems::graphics::GraphicsIcdInit();
    duetos::subsystems::win32::GdiInit();

    SerialWrite("[boot] Bringing up block device layer.\n");
    duetos::drivers::storage::BlockLayerInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::storage::BlockLayerSelfTest());

    SerialWrite("[boot] Bringing up NVMe controller.\n");
    duetos::drivers::storage::NvmeInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::storage::NvmeSelfTest());

    SerialWrite("[boot] Bringing up AHCI controller(s).\n");
    duetos::drivers::storage::AhciInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::storage::AhciSelfTest());

    // Security guard must be live BEFORE any loader runs. Advisory
    // mode at boot: scans + logs, never blocks. Flip to Enforce via
    // the shell `guard enforce` once the boot-log is clean.
    SerialWrite("[boot] Starting security guard.\n");
    duetos::security::GuardInit();
    DUETOS_BOOT_SELFTEST(duetos::security::GuardSelfTest());

    DUETOS_BOOT_SELFTEST(duetos::fs::TmpFsSelfTest());

    SerialWrite("[boot] Probing GPT on block devices.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::gpt::GptSelfTest());

    SerialWrite("[boot] Probing FAT32 on block devices.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::fat32::Fat32SelfTest());

    SerialWrite("[boot] Routing Win32 file syscalls through FAT32.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::routing::SelfTest());

    // Notes save/load round-trip — runs here (post-FAT32-probe) so
    // the SKIP path stays only "no FAT32 volume" rather than "Notes
    // ran before storage was up". Skipped silently if NOTES.TXT
    // pre-exists on the boot image.
    DUETOS_BOOT_SELFTEST(duetos::apps::notes::NotesPersistSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::screenshot::ScreenshotSelfTest());

    // Install the FAT32 file sink — replaces the early tmpfs
    // sink (single-slot API). The tmpfs `/tmp/boot.log`
    // captured the early-boot lines; from here on, every
    // Info+ log entry goes to `KERNEL.LOG` on the FAT32 root.
    // Non-fatal if FAT32 is unavailable — Install logs and
    // returns.
    duetos::core::KlogPersistInstall();
    DUETOS_BOOT_SELFTEST(duetos::core::KlogPersistSelfTest());

    // Session restore: read SESSION.CFG and apply the saved
    // theme + per-app window positions. No-op on first boot
    // (file doesn't exist) or if FAT32 isn't mounted.
    // SessionRestoreSelfTest exercises the parse path in
    // memory without touching the on-disk config.
    DUETOS_BOOT_SELFTEST(duetos::core::SessionRestoreSelfTest());
    duetos::core::SessionRestoreApply();

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
                }
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

            // Ctrl+S — persist the Notes buffer to the FAT32 root
            // as NOTES.TXT. Active-window-gated: anywhere else this
            // chord is unbound. NotesSave logs success/failure to
            // COM1; the toast surfaces the same outcome to the user.
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
                    else if (active == duetos::apps::notes::NotesWindow() &&
                             (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown || ev.code == kKeyArrowLeft ||
                              ev.code == kKeyArrowRight || ev.code == kKeyHome || ev.code == kKeyEnd ||
                              ev.code == kKeyDelete))
                    {
                        app_consumed = duetos::apps::notes::NotesFeedKey(ev.code);
                    }
                    else
                    {
                        char c = 0;
                        if (ev.code == kKeyEnter)
                            c = '\n';
                        else if (ev.code == kKeyBackspace)
                            c = 0x08;
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
            if (ev.code == kKeyBackspace)
            {
                duetos::core::ShellBackspace();
                dirty = true;
            }
            else if (ev.code == kKeyEnter)
            {
                duetos::core::ShellSubmit();
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
        static bool prev_left = false;
        static bool prev_right = false;
        auto desktop_bg = []() { return duetos::drivers::video::ThemeCurrent().desktop_bg; };

        // Menu item sets — static so their label pointers outlive
        // the menu's open state. action_id scheme is documented in
        // kernel_main's comment above; keep these tables in sync.
        // action_id 100..199 are reserved for "open app by ThemeRole"
        // — id = 100 + role index — so the dispatch handler can fan
        // back out to a single ThemeRoleWindow lookup. New roles
        // pick the next 100 + idx and need a label here only.
        static const duetos::drivers::video::MenuItem kStartItemsBuiltins[] = {
            {"CALCULATOR", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::Calculator)},
            {"NOTEPAD", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::Notes)},
            {"FILES", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::Files)},
            {"CLOCK", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::Clock)},
            {"TASK MANAGER", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::TaskManager)},
            {"KERNEL LOG", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::LogView)},
            {"GFX DEMO", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::GfxDemo)},
            {"SETTINGS", 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::Settings)},
        };
        static const duetos::drivers::video::MenuItem kStartItemsTrailing[] = {
            {"HELP / SHORTCUTS", 6},
            {"CYCLE WINDOWS", 2},
            {"ABOUT DUETOS", 1},
        };
        // Combined array: builtins, then /APPS shortcuts, then
        // help/cycle/about. The ui-thread is the only writer
        // (so a function-static is fine), but it's recomputed
        // each open so a freshly-dropped /APPS/*.MNF picks up
        // without a reboot — StartMenuAppsScan runs at boot,
        // but a per-open re-scan would be cheap to add later.
        constexpr duetos::u32 kBuiltinsN = sizeof(kStartItemsBuiltins) / sizeof(kStartItemsBuiltins[0]);
        constexpr duetos::u32 kTrailingN = sizeof(kStartItemsTrailing) / sizeof(kStartItemsTrailing[0]);
        constexpr duetos::u32 kStartItemsCap = kBuiltinsN + duetos::drivers::video::kStartMenuAppsMax + kTrailingN;
        static duetos::drivers::video::MenuItem kStartItems[kStartItemsCap] = {};
        duetos::u32 start_items_count = 0;
        for (duetos::u32 i = 0; i < kBuiltinsN; ++i)
        {
            kStartItems[start_items_count++] = kStartItemsBuiltins[i];
        }
        duetos::drivers::video::StartMenuAppsAppendTo(kStartItems, &start_items_count, kStartItemsCap - kTrailingN);
        for (duetos::u32 i = 0; i < kTrailingN; ++i)
        {
            kStartItems[start_items_count++] = kStartItemsTrailing[i];
        }
        static const duetos::drivers::video::MenuItem kDesktopMenuItems[] = {
            {"HELP / SHORTCUTS", 6}, {"ABOUT DUETOS", 1},  {"CYCLE WINDOWS", 2},
            {"LIST WINDOWS", 3},     {"SWITCH TO TTY", 5},
        };
        static const duetos::drivers::video::MenuItem kWindowMenuItems[] = {
            {"RAISE", 10},
            {"CLOSE", 11},
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
            // PS/2 has no wheel byte; xHCI HID will inject wheel
            // ticks once that path is wired.
            duetos::subsystems::win32::MouseInputAccumulate(p.dx, p.dy, /*dz=*/0, p.buttons);

            // Every UI mutation inside this packet lives under
            // the compositor mutex — the kbd reader can be mid-
            // ConsoleWrite / DesktopCompose at the same time.
            duetos::drivers::video::CompositorLock();
            duetos::drivers::video::CursorMove(p.dx, p.dy);

            duetos::u32 cx = 0, cy = 0;
            duetos::drivers::video::CursorPosition(&cx, &cy);

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
            //   - Window body or title: window menu with Raise/
            //     Close, context = that window's handle.
            //   - Desktop: desktop menu (ABOUT / CYCLE / LIST /
            //     TTY), context = 0.
            // If a menu is already open, a right-click simply
            // closes it — matches Windows behaviour (right-click
            // on whitespace dismisses the popup).
            if (right_press)
            {
                if (duetos::drivers::video::MenuIsOpen())
                {
                    duetos::drivers::video::MenuClose();
                }
                else if (!duetos::drivers::video::TaskbarContains(cx, cy))
                {
                    const auto hit = duetos::drivers::video::WindowTopmostAt(cx, cy);
                    if (hit != duetos::drivers::video::kWindowInvalid)
                    {
                        duetos::drivers::video::MenuOpen(
                            kWindowMenuItems, sizeof(kWindowMenuItems) / sizeof(kWindowMenuItems[0]), cx, cy, hit);
                    }
                    else
                    {
                        duetos::drivers::video::MenuOpen(
                            kDesktopMenuItems, sizeof(kDesktopMenuItems) / sizeof(kDesktopMenuItems[0]), cx, cy, 0);
                    }
                }
                duetos::drivers::video::CursorHide();
                duetos::drivers::video::DesktopCompose(desktop_bg(), "WELCOME TO DUETOS   BOOT OK");
                duetos::drivers::video::CursorShow();
                duetos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] right-click\n");
                continue;
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
            if (press_edge && duetos::drivers::video::MenuIsOpen())
            {
                const duetos::u32 action = duetos::drivers::video::MenuItemAt(cx, cy);
                if (action != 0)
                {
                    const duetos::u32 ctx = duetos::drivers::video::MenuContext();
                    // Dispatch action. Context (ctx) is a caller-
                    // supplied u32 — for window menus it's the
                    // target WindowHandle.
                    switch (action)
                    {
                    case 1: // ABOUT DUETOS
                        duetos::drivers::video::ConsoleWriteln("");
                        duetos::drivers::video::ConsoleWriteln("-> DUETOS v0 — WINDOWED DESKTOP SHELL");
                        duetos::drivers::video::ConsoleWriteln("   KEYBOARD + MOUSE + FRAMEBUFFER ALL LIVE");
                        break;
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
                    case 5: // SWITCH TO TTY (from desktop context menu)
                        duetos::drivers::video::SetDisplayMode(duetos::drivers::video::DisplayMode::Tty);
                        duetos::drivers::video::ConsoleSetOrigin(16, 16);
                        duetos::drivers::video::ConsoleSetColours(duetos::drivers::video::ThemeCurrent().console_fg,
                                                                  0x00000000);
                        break;
                    case 6: // HELP / SHORTCUTS
                        PrintShortcutHelp();
                        break;
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
                    default:
                        // App launcher bands: 100..199 == "raise the
                        // window registered for ThemeRole(action - 100),
                        // un-hiding it if Show Desktop or a min/hide
                        // dropped its visible bit." Out-of-band ids
                        // fall through to the unrecognised log.
                        // Builtin start-menu items use action 100+role.
                        // /APPS shortcuts use action 200+slot — resolve
                        // through StartMenuAppsResolve to recover the
                        // ThemeRole before raising. Both paths share
                        // the visibility / raise / log block below.
                        bool have_role = false;
                        duetos::drivers::video::ThemeRole role{};
                        if (action >= 100 &&
                            action < 100 + static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::kCount))
                        {
                            role = static_cast<duetos::drivers::video::ThemeRole>(action - 100);
                            have_role = true;
                        }
                        else if (duetos::drivers::video::StartMenuAppsResolve(action, &role))
                        {
                            have_role = true;
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
                duetos::drivers::video::MenuClose();
                // Force an immediate recompose so any console
                // output the action wrote (HELP / ABOUT / -> RAISED
                // ...) appears now rather than waiting up to a
                // second for the ui-ticker. Also clears the menu
                // panel from the framebuffer.
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
                            drag.active = true;
                            drag.window = hit;
                            drag.grab_offset_x = cx - wx;
                            drag.grab_offset_y = cy - wy;
                            SerialWrite("[ui] drag begin window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
                        }
                        else
                        {
                            SerialWrite("[ui] raise window=");
                            SerialWriteHex(hit);
                            SerialWrite("\n");
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
                        constexpr duetos::u64 kDblClickTicks = 50; // 500ms
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
                    }
                    duetos::drivers::video::WindowMsgWakeAll();
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
        // dance, iretq return — works end-to-end. Under
        // profile=Linux this is the ONLY smoke we spawn — the
        // smoke wrapper script asserts only on the substring
        // "linux" in the log, and one successful sys_exit_group
        // covers it. The other six Linux smokes (ElfSmoke,
        // FileSmoke, MmapSmoke, SynxTestElf, TranslateSmoke,
        // ExtendSmoke) cumulatively burn ~50s of guest time at
        // the runner's ~12:1 wall:guest ratio = ~600s of wall,
        // beyond the per-profile 480s budget; they only run on
        // bare-metal profile=None (full coverage).
        duetos::subsystems::linux::SpawnRing3LinuxSmoke();
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
            // Real host-compiled static C ELF (userland/apps/synxtest) —
            // exercises ~12 Linux syscalls and prints a pass/fail tag
            // per call. This is the "compile and run an executable to
            // see what works" probe; boot log shows which parts of the
            // Linux ABI actually hold up when a non-hand-rolled binary
            // does the asking.
            duetos::subsystems::linux::SpawnSynxTestElf();
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

    // Bring up APs. SmpStartAps calls SchedSleepTicks(1) between
    // INIT and SIPI; the dedicated idle task installed at the top
    // of SchedInit guarantees the runqueue is non-empty, so the
    // BSP always has something to switch to while it sleeps —
    // independent of worker-creation order.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

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
    duetos::security::AttackSimRun();
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
