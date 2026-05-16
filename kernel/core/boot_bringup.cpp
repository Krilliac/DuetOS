// See boot_bringup.h. Mechanical extraction from main.cpp;
// behaviour and ordering are unchanged.

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
#include "core/boot_bringup.h"

namespace duetos::core
{

void BootBringupEarly(duetos::u32 multiboot_magic, duetos::uptr multiboot_info)
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
    if constexpr (duetos::core::kKasanDiagnostics)
    {
        SerialWrite(" +kasan");
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
    // Hard-stop gate on the baseline x86_64 features the kernel
    // unconditionally uses (FPU/SSE/SSE2, TSC, MSR, APIC, PAE, NX,
    // LongMode). On a CPU missing any of these the kernel would
    // otherwise triple-fault on the first dependent code path —
    // most commonly the EFER.NXE write inside PagingInit on a
    // pre-K8/Yonah part with no XD support. Failing loudly here
    // with a named-missing-feature banner is the difference
    // between "boots on this machine" and "silent reboot loop."
    duetos::arch::CpuMinimumFeatureGate();
    duetos::arch::CpuMitigationsProbe();
    duetos::arch::CetProbe();
    duetos::arch::FpuInit();
    duetos::arch::AsmEntryAnchorReport();

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

    SerialWrite("[boot] Exercising PE app-compat sidecar parser.\n");
    DUETOS_BOOT_SELFTEST(duetos::core::compat::SelfTest());

    SerialWrite("[boot] Exercising A/B boot-slot state machine.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::boot_slot::SelfTest());

    // IocpSelfTest used to run here, but its KObject-promotion
    // half calls IocpCreate → KMalloc, which needs the kernel
    // heap to be live. KernelHeapInit doesn't run until later
    // (see "Bringing up kernel heap" below) so the early call
    // panicked with "kheap OOM?" on every boot. The self-test
    // is now registered as a Heap-phase initcall down at the
    // KernelHeapInit site, where the heap is guaranteed online.

    SerialWrite("[boot] Exercising kernel registry helpers.\n");
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::registry::RegistrySelfTest());

    SerialWrite("[boot] Seeding kernel entropy pool.\n");
    duetos::core::RandomInit();
    DUETOS_BOOT_SELFTEST(duetos::core::RandomSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::Crc32SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::Base64SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::SaturatingSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::vt::VtParserSelfTest());

    // KASLR — compute the candidate slide from the now-seeded entropy
    // pool. The slide isn't applied to the kernel image yet (that
    // depends on a PIE-build + relocation slice landing), but every
    // consumer of `KaslrGetKernelSlide` reads from one source of truth
    // so the day the slide-application stub lands, no audit pass is
    // needed. See wiki/security/Linux-CVE-Audit.md class II.
    duetos::security::KaslrInit();
    DUETOS_BOOT_SELFTEST(duetos::security::KaslrSelfTest());
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
}


void BootBringupMemPaging()
{
    using namespace duetos::arch;
    using namespace duetos::mm;

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
        // IocpSelfTest moved to Phase::Sched — alongside the
        // other IPC primitives that use `sched::Mutex` /
        // `sched::Condvar`. IocpTryPost / IocpTryPop / IocpWait
        // serialise through the embedded mutex (blocking-wait
        // support, plan IOCP-followup); the scheduler must be
        // online for those calls to deadlock-detect correctly.
        // The IocpCreate -> KMalloc half is still valid here
        // (heap is up at Phase::Sched too), so the test runs end
        // to end at the later phase.
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
        // Kernel hot-patch — exercises the 5-byte JMP-rel32 overlay
        // over the `patchable_function_entry` NOP, end-to-end on
        // an in-TU target + replacement. Runs here (after
        // ProtectKernelImage, before SMP bring-up) so the .text
        // is 4 KiB-mapped and the single-CPU patch-window contract
        // holds trivially. See kernel/debug/hot_patch.h.
        if (!duetos::debug::HotPatchSelfTest())
        {
            SerialWrite("[boot] WARN: hot-patch self-test failed — see serial log\n");
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
}


// Kernel-services bring-up: VFS/ramfs, ACPI + AML namespace,
// APIC/IOAPIC/HPET, clocksource/timekeeper/tick, RTC + wall
// clock, per-CPU BSP + topology, LBR, syscall-cap gate,
// Linux-ABI syscall MSRs, sync-primitive + lockdep self-tests,
// periodic timer + NMI watchdog, scheduler init + idle/reaper,
// and the IPC/KObject/Win32/Linux-fd/soft-lockup self-tests.
// Pure code motion out of kernel_main: the block crosses no
// kernel_main locals beyond the boot cmdline string and the
// Multiboot2 info pointer (init-wedge-panic parse + AcpiInit);
// every other effect lands on global/subsystem state.
void BootBringupKernelServices(const char* cmdline, duetos::uptr multiboot_info)
{
    using namespace duetos::arch;
    using namespace duetos::mm;

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

    // Drive any future Phase::PerCpuBsp registrants. No callers
    // yet, but the phase slot exists so the registry stays the
    // single contract for "per-CPU BSP init."
    (void)duetos::core::RunPhase(duetos::core::Phase::PerCpuBsp);

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

    // Arm the NMI watchdog as soon as the timer IRQ is firing so
    // any subsequent driver-bring-up wedge (xHCI reset wait, audio
    // controller hang, stuck MMIO poll, IRQ-disabled spinlock
    // deadlock) panics with a useful trap frame instead of leaving
    // the box silently halted. The watchdog uses a perfmon
    // overflow that delivers as NMI, so even an IRQ-masked spinlock
    // wedge wakes the panic path. Silently no-ops if the CPU
    // doesn't advertise architectural perfmon (typical on QEMU
    // TCG without `-cpu max`) — the init-wedge watchdog in
    // arch/timer.cpp then takes over as the timer-IRQ-based
    // fallback. Previously this was deferred to the very end of
    // boot, which meant a hang in any earlier driver had no
    // hardware-level detector at all.
    duetos::arch::NmiWatchdogInit();

    // init-wedge-panic=<N>: turn the init-wedge watchdog from
    // warn-only into a hard panic after N silent-heartbeats. The
    // cmdline value is a small decimal; conservative parse —
    // multi-digit accepted, single-digit common. 0 / missing keeps
    // the default warn-only behaviour. Useful for CI and stress
    // runs where a wedge must surface as a fault rather than as a
    // silent timeout.
    {
        const char* cur = cmdline;
        const char* kkey = "init-wedge-panic=";
        while (cur != nullptr && *cur != '\0')
        {
            const char* hit = nullptr;
            // Find "init-wedge-panic=" anywhere in cmdline.
            for (const char* p = cur; *p != '\0'; ++p)
            {
                duetos::u32 i = 0;
                while (kkey[i] != '\0' && p[i] == kkey[i])
                {
                    ++i;
                }
                if (kkey[i] == '\0')
                {
                    hit = p + i;
                    break;
                }
            }
            if (hit == nullptr)
            {
                break;
            }
            duetos::u32 val = 0;
            while (*hit >= '0' && *hit <= '9')
            {
                val = val * 10u + duetos::u32(*hit - '0');
                ++hit;
            }
            duetos::arch::SetInitWedgePanicThreshold(val);
            break;
        }
    }

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
        // Kernel work pool — N worker threads pulling work items
        // from a shared bounded FIFO. Self-test fans 256 increment
        // ops out across 4 workers with a queue intentionally
        // smaller than the item count, so Submit's blocking path
        // gets exercised alongside Drain quiescence and Shutdown
        // teardown.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "workpool-selftest",
                                       []()
                                       {
                                           duetos::sched::WorkPoolSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // Slab allocator — fixed-size object cache layered over
        // KMalloc. Self-test exercises alloc / free / multi-slab
        // grow / LIFO reuse / Destroy lifecycle. Runs in
        // Phase::Sched because the per-cache mutex requires the
        // scheduler to be online; uncontended fast path doesn't
        // block but the mutex still inspects the scheduler's
        // current-task slot.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "slab-selftest",
                                       []()
                                       {
                                           duetos::mm::SlabSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // IOCP completion-port primitive (`kernel/ipc/iocp.{h,cpp}`).
        // Moved to Phase::Sched because the post / pop / wait paths
        // serialise through an embedded `sched::Mutex` and the
        // blocking-wait variant parks on a `sched::Condvar` —
        // both require the scheduler to be online. KMalloc is up
        // by this phase too, so the KObject-promotion half still
        // runs end to end.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "iocp-selftest",
                                       []()
                                       {
                                           SerialWrite("[boot] Exercising IOCP completion-port primitive.\n");
                                           duetos::ipc::IocpSelfTest();
                                           return duetos::core::Result<void>{};
                                       });
        // Deliberate fault-injection harness (kernel/diag/fault_inject).
        // Only the recoverable OomSlab class runs at boot — the panic
        // and NullDeref classes are non-returning and would halt the
        // box. The self-test exists so the recoverable-OOM path is
        // exercised every boot, not just when an operator types the
        // shell command. Same Phase::Sched bucket as the slab self-
        // test because the harness creates its own SlabCache and so
        // shares the slab subsystem's "scheduler must be online"
        // prerequisite.
        duetos::core::InitcallRegister(duetos::core::Phase::Sched, "fault-inject-selftest",
                                       []()
                                       {
                                           duetos::diag::fault_inject::FaultInjectSelfTest();
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
    DUETOS_BOOT_SELFTEST(duetos::ipc::NamedKObjectSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::NamedPipeSelfTest());
    // Kernel-resident APC queue (T8-02). Exercises queue / drain
    // / cross-tid isolation / capacity overflow on a stand-in
    // Process so any regression in apc_syscall.cpp is caught
    // before a real PE drives QueueUserAPC / NtQueueApcThread.
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::ApcSelfTest());
    // Win32 multi-heap allocator (T5-02). First-fit + split +
    // LIFO-reuse + OOM round-trip on a flat-buffer mini-walker
    // that mirrors the binding-based production code path.
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::Win32HeapSelfTest());
    // VirtualAlloc reserve/commit region tracker (T5-01 partial).
    // Verifies the bitmap state-machine: reserve, partial commit,
    // partial decommit, release, capacity overflow.
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::Win32VmapSelfTest());
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
}
} // namespace duetos::core
