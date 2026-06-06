// See boot_bringup.h. Mechanical extraction from main.cpp;
// behaviour and ordering are unchanged.

#include "util/adler32.h"
#include "util/base64.h"
#include "util/build_config.h"
#include "util/crc32.h"
#include "util/bmp.h"
#include "util/saturating.h"
#include "util/soft_float.h"
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
#include "acpi/acpi_power.h"
#include "acpi/acpi_sci.h"
#include "acpi/aml.h"
#include "acpi/aml_eval.h"
#include "acpi/ec.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cet.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/fpu.h"
#include "arch/x86_64/cpu_mitigations.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/thermal.h"
#include "arch/x86_64/rapl.h"
#include "arch/x86_64/cpufreq.h"
#include "arch/x86_64/spi_flash.h"
#include "drivers/gpu/gpu_telemetry.h"
#include "drivers/net/nic_telemetry.h"
#include "net/wireless/reg_telemetry.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/lbr.h"
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/percpu_ops.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/msr_safe.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "cpu/cpuhp.h"
#include "cpu/critical.h"
#include "cpu/percpu.h"
#include "cpu/percpu_counter.h"
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
#include "drivers/gpu/display_power.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/edid.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/amd_cp_ucode.h"
#include "drivers/gpu/amd_gfx_fw.h"
#include "drivers/gpu/amd_gpu.h"
#include "drivers/gpu/amd_gpu_cmds.h"
#include "drivers/gpu/gpu_resources.h"
#include "drivers/gpu/intel_display.h"
#include "drivers/gpu/intel_forcewake.h"
#include "drivers/gpu/intel_ggtt.h"
#include "drivers/gpu/intel_gpu.h"
#include "drivers/gpu/intel_gpu_cmds.h"
#include "drivers/gpu/intel_gsc_fw.h"
#include "drivers/gpu/nvidia_gpu.h"
#include "drivers/gpu/nvidia_gsp_fw.h"
#include "drivers/input/hid_keyboard.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/iommu/dmar.h"
#include "drivers/iommu/iommu.h"
#include "drivers/iommu/ivrs.h"
#include "drivers/iommu/vtd.h"
#include "drivers/iommu/vtd_paging.h"
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
#include "net/cookies.h"
#include "net/http.h"
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
#include "net/x509_verify.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "crypto/prf.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "net/wireless/eapol.h"
#include "net/wireless/fourway.h"
#include "net/wireless/gcmp.h"
#include "net/wireless/mock_isp.h"
#include "net/wireless/mlme.h"
#include "net/wireless/regdb.h"
#include "net/wireless/test/wireless_dataplane_test.h"
#include "net/wireless/test/wireless_e2e_test.h"
#include "net/wireless/wdev.h"
#include "net/wireless/wifi_diag.h"
#include "drivers/mei/mei.h"
#include "drivers/npu/npu.h"
#include "drivers/pci/pci.h"
#include "drivers/psp/psp.h"
#include "drivers/virtio/virtio.h"
#include "drivers/power/power.h"
#include "env/autonomic.h"
#include "env/environment.h"
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
#include "net/tls_socket.h"
#include "subsystems/graphics/graphics.h"
#include "subsystems/graphics/graphics_vk_spirv.h"
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
#include "apps/browser/assistant_backend.h"
#include "apps/browser/dock_surface.h"
#include "apps/browser/omnibox.h"
#include "security/privilege/arm_state.h"
#include "security/privilege/audit.h"
#include "security/privilege/broker.h"
#include "security/privilege/config.h"
#include "apps/browser/privileged/origin_predicate.h"
#include "security/privilege/scope.h"
#include "apps/browser/start_page.h"
#include "apps/browser/tab_strip.h"
#include "web/css.h"
#include "web/html.h"
#include "web/jpeg.h"
#include "web/js_dom.h"
#include "web/layout.h"
#include "web/paint.h"
#include "web/png.h"
#include "web/priv_binding.h"
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
#include "apps/dbg_internal.h"
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
#include "web/js/engine.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/svg.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/app_widgets/self_test.h"
#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"
#include "drivers/video/splash.h"
#include "drivers/video/wallpaper.h"
#include "generated_chrome_font.h"
#include "generated_chrome_font_bold.h"
#include "drivers/video/calendar.h"
#include "drivers/video/desktop_icons.h"
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
#include "mm/poison.h"
#include "mm/poison_alloc.h"
#include "mm/zone.h"
#include "ipc/handle_table.h"
#include "ipc/iocp.h"
#include "diag/event_trace.h"
#include "diag/fault_inject.h"
#include "diag/fault_react.h"
#include "diag/panic_wait.h"
#include "diag/fix_journal.h"
#include "diag/kpath.h"
#include "diag/kpath_persist.h"
#include "diag/fix_journal_persist.h"
#include "diag/introspect.h"
#include "diag/selfthink.h"
#include "diag/selfthink_baselines.h"
#include "diag/selfthink_narrative.h"
#include "diag/selfthink_persist.h"
#include "env/autonomic_feedback.h"
#include "diag/gdb_server.h"
#include "diag/minidump.h"
#include "diag/perf_profile.h"
#include "diag/fma/diagnose.h"
#include "diag/hung_task.h"
#include "diag/kstat.h"
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
#include "sync/adaptive_mutex.h"
#include "sync/lockdep.h"
#include "sync/rcu.h"
#include "sync/rwlock.h"
#include "sync/seqlock.h"
#include "sync/spinlock.h"
#include "time/clocksource.h"
#include "time/cyclic.h"
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
#include "security/me_psp_guard.h"
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
#include "core/boot_cmdline.h"
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
#include "loader/apiset_static.h"
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

namespace
{

// Storage for the chrome font handle. Populated by the
// chrome-font-load initcall once at boot inside BootBringupDesktop;
// outlives the registration because TtfChromeFontSet stores a
// borrowed pointer, so it must have static storage duration.
constinit duetos::drivers::video::TtfFont g_chrome_font_storage{};

// Storage for the chrome bold font handle. Same lifetime contract as
// g_chrome_font_storage — populated by the chrome-font-bold-load
// initcall, borrowed by TtfChromeBoldSet, must live for the kernel's
// lifetime. When ChromeTextDraw is called with ChromeTextWeight::Bold,
// the TTF dispatch path picks this face up.
constinit duetos::drivers::video::TtfFont g_chrome_bold_font_storage{};

// Expensive boot self-tests (heavy asymmetric crypto: RSA, RSA-4096 +
// ECDSA P-256/P-384 X.509 chain verify, Argon2id password hashing, TLS
// handshakes) cost ~200 s under QEMU TCG. That blows the budget in BOTH
// directions: it makes an interactive boot crawl AND it eats the CI
// smoke job's entire timeout, so it must NOT be tied to the smoke
// profile. They are therefore OFF by default everywhere — normal boot
// AND the CI smoke gate — and run ONLY behind an explicit opt-in:
//   - the kernel cmdline token `selftests=full`.
// A dedicated/nightly full-verification job (or a developer chasing a
// crypto regression) passes `selftests=full` and budgets the longer
// timeout; the fast smoke gate stays fast. The smoke harness asserts no
// crypto sentinels, so skipping them under smoke breaks no CI check.
// Set once at the top of BootBringupKernelServices (which has the
// cmdline) before the crypto cluster in BootBringupDevices runs. Gated
// by DUETOS_BOOT_SELFTEST_CI (see below).
constinit bool g_expensive_selftests = false;

// Minimal substring search — the kernel has no strstr in scope here and
// the cmdline is a short, NUL-terminated string.
bool CmdlineContains(const char* haystack, const char* needle)
{
    if (haystack == nullptr || needle == nullptr)
        return false;
    for (const char* h = haystack; *h != '\0'; ++h)
    {
        const char* a = h;
        const char* b = needle;
        while (*a != '\0' && *b != '\0' && *a == *b)
        {
            ++a;
            ++b;
        }
        if (*b == '\0')
            return true;
    }
    return false;
}

bool CmdlineEnablesExpensiveSelfTests(const char* cmdline)
{
    // Explicit opt-in ONLY. Deliberately not triggered by `smoke=` —
    // the CI smoke gate must stay fast (these tests eat its whole
    // timeout). A full-verification run passes `selftests=full`.
    return CmdlineContains(cmdline, "selftests=full");
}

} // namespace

// Wrap a heavy self-test so it runs only under an explicit
// `selftests=full` opt-in (OFF in normal boots and the CI smoke gate).
// Expands inside namespace duetos::core, so the unqualified
// g_expensive_selftests resolves to the anonymous-namespace flag above.
// Nests DUETOS_BOOT_SELFTEST, so release builds still drop the call
// entirely via the kBootSelfTests compile gate.
#define DUETOS_BOOT_SELFTEST_CI(call)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (g_expensive_selftests)                                                                                     \
        {                                                                                                              \
            DUETOS_BOOT_SELFTEST(call);                                                                                \
        }                                                                                                              \
    } while (0)

void BootBringupEarly(duetos::u32 multiboot_magic, duetos::uptr multiboot_info)
{
    using namespace duetos::arch;
    using namespace duetos::mm;

    SerialInit();
    SerialWrite("[boot] DuetOS kernel reached long mode.\n");

    // Detect an external debugger host (duetos-vmm --gdb adds
    // "debugstub=1" to the cmdline). Parsed here — early, while the low
    // Multiboot2 info page is still identity-mapped, which also primes the
    // FindBootCmdline cache for later callers. When set, the kernel stands
    // down its boot-time int3 / hardware-breakpoint / watchpoint self-tests
    // below: those execute int3 / arm DR slots, which the host debugger
    // intercepts as #BP/#DB and would wedge or corrupt the boot.
    duetos::core::DebugStubInit(duetos::core::FindBootCmdline(multiboot_info));
    if (duetos::core::DebugStubAttached())
    {
        SerialWrite("[boot] debug stub attached — standing down int3/DR boot "
                    "self-tests (host owns #BP/#DB)\n");
    }

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

    // KARL — Kernel Address Randomized Link. When ON, the kernel's
    // per-TU link order was randomized with the printed seed; a
    // panic dump needs the matching `kernel.symbols` map (emitted
    // next to the kernel ELF / under /boot on the ISO) to decode
    // RIPs back to function names. When OFF, every build of this
    // commit lays symbols at the same offsets and a stock nm of
    // the kernel ELF suffices.
    if constexpr (duetos::core::kKarlEnabled)
    {
        SerialWrite("[boot] karl=seed=");
        SerialWriteHex(duetos::core::kKarlBuildSeed);
        SerialWrite("\n");
    }
    else
    {
        SerialWrite("[boot] karl=disabled\n");
    }

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

    SerialWrite("[boot] Reading RAPL power telemetry.\n");
    duetos::arch::RaplProbe();

    SerialWrite("[boot] Reading CPU frequency telemetry.\n");
    duetos::arch::CpuFreqProbe();

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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Earlycon, "result-selftest",
                                              []()
                                              {
                                                  SerialWrite("[boot] Exercising Result<T,E> + TRY primitives.\n");
                                                  duetos::core::ResultSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Earlycon, "string-selftest",
                                              []()
                                              {
                                                  SerialWrite(
                                                      "[boot] Exercising freestanding memset/memcpy/memmove.\n");
                                                  duetos::core::StringSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Earlycon, "hexdump-selftest",
                                              []()
                                              {
                                                  SerialWrite(
                                                      "[boot] Exercising kernel-VA range + hexdump formatters.\n");
                                                  duetos::core::HexdumpSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(
            duetos::core::Phase::Earlycon, "varegion-selftest",
            []()
            {
                SerialWrite("[boot] Exercising VA-region classifier (panic / trap dump annotation).\n");
                duetos::core::VaRegionSelfTest();
                return duetos::core::Result<void>{};
            });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Earlycon), "boot", "RunPhase Earlycon");

    // One-shot mm-map anchor for every later panic dump. The region
    // tags on cr2/rsp/rbp/rip in a crash record map back to the
    // ranges printed here without forcing the operator to consult
    // paging.h / kstack.h / linker.ld separately.
    duetos::core::WriteMmMapSummary();

    SerialWrite("[boot] Exercising process / capability helpers.\n");
    DUETOS_BOOT_SELFTEST(duetos::core::ProcessSelfTest());

    SerialWrite("[boot] Exercising PE app-compat sidecar parser.\n");
    DUETOS_BOOT_SELFTEST(duetos::core::compat::SelfTest());

    SerialWrite("[boot] Exercising API-set contract table.\n");
    DUETOS_BOOT_SELFTEST(duetos::loader::ApiSetSelfTest());

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
    DUETOS_BOOT_SELFTEST(duetos::core::Sf32SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::arch::RaplSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::arch::CpuFreqSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::arch::SpiFlashSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::GpuTelemetrySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::NicTelemetrySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::RegTelemetrySelfTest());

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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Idt, "traps-selftest",
                                              []()
                                              {
                                                  TrapsSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Idt), "boot", "RunPhase Idt");

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
    // Fault-recoverable wrmsr — covers the wrmsr inside
    // `arch::WriteMsrSafe`, used by the LAPIC IPI path so an
    // intermittent KVM/QEMU #GP on the x2APIC ICR doesn't
    // recursive-halt the BSP. See arch/x86_64/msr_safe.{h,cpp,S}.
    duetos::arch::RegisterMsrSafeExtable();

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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::PhysMem, "frame-allocator-selftest",
                                              []()
                                              {
                                                  FrameAllocatorSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Robustness — frame allocator OOM injection hook used by
        // the loader unwind self-tests below.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::PhysMem, "frame-oom-injection-selftest",
                                              []()
                                              {
                                                  duetos::mm::FrameAllocatorOomInjectionSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // mm/zone scaffold (plan C1) — additive layer over the
        // global frame allocator; v0 forwards every zone request
        // to the same pool.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::PhysMem, "zone-selftest",
                                              []()
                                              {
                                                  ZoneSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // mm/dma — DMA-coherent buffer allocation. Sits on top of
        // the per-zone contiguous-frame allocator; the first real
        // consumers are the iwlwifi TFD/RBD rings + (when they
        // land) AHCI + Intel HDA CORB. See `dma-coherent-v0.md`.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::PhysMem, "dma-selftest",
                                              []()
                                              {
                                                  DmaSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::PhysMem), "boot", "RunPhase PhysMem");

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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Heap, "kernel-heap-selftest",
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
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Heap), "boot", "RunPhase Heap");

    KLOG_METRICS("boot", "after-kernel-heap");

    SerialWrite("[boot] Bringing up paging.\n");
    PagingInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Paging, "paging-selftest",
                                              []()
                                              {
                                                  PagingSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Paging), "boot", "RunPhase Paging");

    // Kernel-stack guard-paged arena — runs here because it needs
    // the managed paging API (PagingInit) for MapPage / UnmapPage
    // but must be online before any SchedCreate call uses it.
    DUETOS_BOOT_SELFTEST(duetos::mm::KernelStackSelfTest());
    // Hardware-poison frame blacklist round-trip. No machine-check
    // is fired during the test — it exercises the list mutation
    // and lookup paths with synthetic PFNs and restores live state.
    DUETOS_BOOT_SELFTEST(duetos::mm::PoisonFrameSelfTest());
    // Guard-page poison allocator — sibling of KMalloc that
    // dedicates 3 pages of VA per allocation ([guard][data][guard])
    // so overruns and use-after-free trap at the write site
    // instead of corrupting random neighbours. MUST run before
    // any AddressSpaceCreate — the PML4[384] entry the region
    // lives under is propagated into every per-process AS at
    // AS-create time, so a late init would leave existing
    // address spaces blind to the region.
    //
    // The self-test is "init-with-validation" rather than a pure
    // test: it exercises the alloc/free round-trip AND it's the
    // first call that walks the new PML4 entry into existence,
    // so it doubles as the trigger that pulls in the PDPT/PD/PT
    // for the region's first slot. Runs unconditionally (same
    // policy as RegistrySelfTest, the canonical
    // init-with-validation example).
    duetos::mm::PoisonAllocInit();
    duetos::mm::PoisonAllocSelfTest();
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

    // Arm the boot-stack guard page now that the kernel image is at its
    // final 4 KiB-granular protection. From here on, any overflow below
    // stack_bottom (e.g. the deep TLS->x509->ASN.1->RSA/EC self-test tower
    // that runs later on this same boot stack) faults at the guard with a
    // named "boot stack overflow" panic instead of silently scribbling low
    // RAM and producing a wild ret. Mirrors the per-slot guard the heap
    // kstack arena already carries.
    InstallBootStackGuard();

    // Breakpoint subsystem (int3 + DR0..DR3). Must run AFTER
    // ProtectKernelImage so we know .text is at its final 4 KiB-
    // granular protection and SetPteFlags4K can flip the W bit
    // for a BP install. Runs BEFORE SMP bring-up so the single-
    // CPU invariant the BP installer asserts is still true.
    duetos::debug::BpInit();
    // Skip under an external debugger host: BpSelfTest plants a real int3
    // and arms a DR slot, which the host owns — it would intercept the
    // #BP/#DB and corrupt the test (or wedge the boot).
    if (!duetos::core::DebugStubAttached() && !duetos::debug::BpSelfTest())
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
        // WatchSelfTest arms a hardware watchpoint (DR slot) -> #DB, which
        // the host debugger owns; skip it under the stub.
        if (!duetos::core::DebugStubAttached() && !duetos::debug::WatchSelfTest())
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

    // KPath — code path execution ledger. Sits next to the fix
    // journal because both observe-record runtime behaviour and
    // share the FAT32 sink pattern. Init runs after FixJournalInit
    // so KPath's selftest (which fires probes through ProbeFire)
    // doesn't trip a fix-journal call before its ring is live.
    duetos::diag::KPathInit();
    DUETOS_BOOT_SELFTEST(duetos::diag::KPathSelfTest());
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

    // Decide once whether the expensive crypto/TLS self-tests run this
    // boot (see g_expensive_selftests). Done here — before the crypto
    // cluster in BootBringupDevices, which has no cmdline of its own.
    g_expensive_selftests = CmdlineEnablesExpensiveSelfTests(cmdline);
    SerialWrite(g_expensive_selftests
                    ? "[boot] expensive self-tests ENABLED (selftests=full)\n"
                    : "[boot] expensive self-tests skipped (default; pass selftests=full to run heavy crypto/TLS)\n");

    // Phase::Vfs — ramfs init imperative (it lays down the v0 root
    // hierarchy + seed files); VFS self-test routes through the
    // registry. (A1-followup, 2026-04-28.)
    SerialWrite("[boot] Seeding ramfs + VFS self-test.\n");
    duetos::fs::RamfsInit();
    // Frame-backed writable RAM volume. Heap + frame allocator are
    // online by here; parses ramfs-mib= from the cmdline and builds
    // the /run, /run/lock, /tmp directory skeleton.
    duetos::fs::RamVolInit(multiboot_info);
    // Make the volume reachable from the path namespace at /run so
    // the shell + file_route can read service files. Mount-failure
    // is non-fatal: the direct fs::RamVol* API still works, only
    // path-based access is unavailable.
    (void)duetos::fs::VfsMount("/run", duetos::fs::FsType::RamVol, 0);
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Vfs, "vfs-selftest",
                                              []()
                                              {
                                                  duetos::fs::VfsSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Vfs, "vfs-mount-selftest",
                                              []()
                                              {
                                                  duetos::fs::VfsMountSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Vfs), "boot", "RunPhase Vfs");

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
    DUETOS_BOOT_SELFTEST(duetos::acpi::AmlEvalSelfTest());
    duetos::acpi::AcpiEcInit();
    DUETOS_BOOT_SELFTEST(duetos::acpi::AcpiEcSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::acpi::AcpiPowerSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::acpi::AcpiSleepPrepSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::acpi::AcpiMadtX2ApicSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::acpi::AcpiSciSelfTest());

    // VT-d DMAR discovery + parse. Reads the ACPI DMAR table (when
    // firmware advertises one) and surfaces the IOMMU register
    // bases + reserved-memory regions for the next IOMMU slice to
    // consume. No behavioural effect today — just data surfacing.
    // Absent on QEMU-default + VirtualBox; firmware-present on
    // most real Intel laptops/desktops + QEMU with
    // `-device intel-iommu`.
    duetos::drivers::iommu::DmarInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::iommu::DmarSelfTest());

    // VT-d register MMIO map + capability decode (read-only). No
    // control bits written; no translation enabled. Surfaces what
    // each IOMMU supports so slice 27c can program page tables +
    // enable translation without re-decoding. No-op when
    // DmarPresent()=false (QEMU-default / VirtualBox).
    duetos::drivers::iommu::VtdInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::iommu::VtdSelfTest());

    // AMD-Vi IVRS discovery + parse. Mirror of DmarInit for AMD
    // platforms. No-op (table absent) on Intel boxes; surfaces
    // IVHD/IVMD blocks on AMD boxes for the (future) AMD-Vi
    // register / page-table slices to consume. No write of any
    // IOMMU register here either.
    duetos::drivers::iommu::IvrsInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::iommu::IvrsSelfTest());

    // VT-d identity-passthrough page tables. Builds root + shared
    // context + identity-mapping PDPT (3 frames = 12 KiB). The
    // self-test exercises the in-memory walk independently of
    // whether any real IOMMU is present.
    DUETOS_BOOT_SELFTEST(duetos::drivers::iommu::vtd_paging::VtdPagingSelfTest());

    // Vendor-neutral IOMMU enable. Routes through
    // drivers/iommu/iommu.cpp which picks Intel vs AMD based on
    // what IommuInit discovered. Gated by DUETOS_IOMMU_ENABLE
    // (build flag). When DUETOS_IOMMU_REQUIRE is also set, a
    // failed enable panics — the deployment-safety gate that lets
    // release builds refuse to run without IOMMU protection.
    if (duetos::drivers::iommu::IommuEnableEffective())
    {
        auto r = duetos::drivers::iommu::IommuEnableAtBoot();
        if (!r.has_value())
        {
            if (duetos::drivers::iommu::IommuRequireEffective())
            {
                duetos::core::Panic("boot/iommu", "DUETOS_IOMMU_REQUIRE set but IommuEnableAtBoot failed");
            }
            SerialWrite("[boot] IOMMU enable returned error — translation remains off\n");
        }
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Apic, "hpet-selftest",
                                              []()
                                              {
                                                  HpetSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Apic), "boot", "RunPhase Apic");

    // Phase::Time — clocksource registry, timekeeper init + self-tests.
    // The init body still runs imperatively (it samples HPET at
    // calibration time + registers TSC if available); self-tests
    // route through the registry. (A1-followup, 2026-04-28.)
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Time, "clocksource-selftest",
                                              []()
                                              {
                                                  duetos::time::ClocksourceSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    duetos::time::TimekeeperInit();
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Time, "timekeeper-selftest",
                                              []()
                                              {
                                                  duetos::time::TimekeeperSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Portable scheduler-tick wrapper (plan A2-followup) —
        // additive façade over arch::TimerTicks; consumers migrate
        // off the arch-specific call as the time/ directory grows.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Time, "tick-selftest",
                                              []()
                                              {
                                                  duetos::time::TickSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Time), "boot", "RunPhase Time");

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

    // CPU hotplug state machine — Linux-style ordered bring-up
    // chain. The BSP is already initialised by this point (we are
    // currently EXECUTING on it), so the framework's
    // `CpuhpMarkOnline(0)` short-circuits BSP to Online without
    // walking the chain. AP bring-up in SmpStartAps below routes
    // through `CpuhpBringUp(cpu_id)` via the registered STARTING
    // band states. The self-test exercises the rollback path
    // against toy states in the unreserved 700+ band.
    duetos::cpu::CpuhpMarkOnline(0);
    duetos::cpu::CpuhpSelfTest();
    SerialWrite("[cpuhp] state-machine ready\n");

    // Drive any future Phase::PerCpuBsp registrants. No callers
    // yet, but the phase slot exists so the registry stays the
    // single contract for "per-CPU BSP init."
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::PerCpuBsp), "boot", "RunPhase PerCpuBsp");

    // Decode BSP CPUID 0x1F/0x0B + SRAT row into the per-CPU
    // topology table. AP rows are filled later by each AP from
    // inside ApEntryFromTrampoline before signaling online_flag,
    // so the BSP's WaitForApOnline poll inside SmpStartAps is the
    // rendezvous; cluster assignment runs after SmpStartAps returns.
    duetos::cpu::TopologyInitBsp();

    // Single-instruction per-CPU access self-test. Validates the
    // `arch::ThisCpu*` macro suite (movq / incq / addq via the GS
    // segment override) against `cpu::CurrentCpu()->field`. Cheap
    // (~thousand single-instruction increments) and IRQ-off, so
    // safe to run inline here right after the BSP slot is live.
    duetos::arch::ThisCpuOpsSelfTest();

    // Preempt-off (IRQs-on) critical-section self-test. Validates
    // the `cpu::CriticalEnter` / `CriticalExit` round-trip,
    // nesting, RAII guard, and the deferred-preempt drain — all
    // before any in-kernel client of the primitive has a chance to
    // exercise it. Runs unconditionally (same policy as
    // PoisonAllocSelfTest / ThisCpuOpsSelfTest above): the
    // primitive will be used in release builds, so it must be
    // validated in release boot too. Cheap (~10 atomic ops + 1
    // Schedule()), and runs after PerCpuInitBsp so critnest /
    // deferred_preempt slots are live.
    duetos::cpu::CriticalSelfTest();

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

    // Re-capture the runtime-checker baseline now that all of the
    // syscall MSRs (LSTAR/STAR/CSTAR/SYSENTER) are programmed.
    // The first RuntimeCheckerInit (early in driver-domain bring-up)
    // ran BEFORE the Linux SyscallInit above, so its baseline saw
    // LSTAR=0. Every later RuntimeCheckerScan would then compare a
    // live non-zero LSTAR against the stale-zero baseline and
    // report `HealthIssue::SyscallMsrHijacked` — a false rootkit
    // signal that escalated `blockguard -> Deny` and failed the
    // boot-smoke FORBIDDEN guard. Teardown clears the captured
    // gate; Init re-reads every g_baseline_* MSR/register against
    // the now-final values.
    duetos::core::RuntimeCheckerTeardown();
    duetos::core::RuntimeCheckerInit();

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
    // Kind taxonomy + LOCKDEP_ASSERT_HELD coverage. Runs in the
    // same window as the base self-test because the cross-kind
    // rule lives in the same `LockdepBeforeAcquire` path and has
    // the same dependencies (arch::Cli/Sti only).
    DUETOS_BOOT_SELFTEST(duetos::sync::LockdepKindClassSelfTest());
    // Name the canonical hot global locks (sched / kobject /
    // kstack / pci-config / breakpoints) so any inversion
    // detected post-self-test prints readable names instead of
    // raw class IDs. Idempotent; called after the self-test so
    // self-test scratch names don't get clobbered by names that
    // need to be live for the rest of boot. This pass also lays
    // down each class's kind tag (Spin / Sleep) so the cross-kind
    // rule has live data going into the rest of the kernel boot.
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

    // Cyclic subsystem (Solaris/illumos-style level-rule timer
    // callbacks). Install AFTER SchedInit + idle + reaper are
    // running — Install spawns the Low-level dispatcher kthread.
    // The self-test runs unconditionally (PoisonAllocSelfTest /
    // RegistrySelfTest convention) so a release boot still gets
    // the "init-with-validation" coverage; the cyclic ABI is too
    // load-bearing on the first slice to gate behind kBootSelfTests.
    duetos::time::CyclicInstall();
    duetos::time::CyclicSelfTest();

    // Pre-stage the boot-time stress driver mode (no task spawn yet
    // — that happens later from kernel_main once the shell + ring3
    // smokes are queued). Sets the `StressDriverArmed()` flag so the
    // autonomic engine's first SecurityEscalate evaluation (the
    // engine inits later in BootBringupDevices, then ticks from the
    // env-monitor task) already sees stress mode active and
    // suppresses the escalation. Without this pre-stage, on
    // x86_64-debug the engine fires SecurityEscalate at ~t=30s
    // (UBSAN / red-zone audit raises a kernel-integrity finding
    // before the bringup-tail StressDriverArm call runs at ~t=50s),
    // flips guard mode to Enforce, and the ring3-hello-pe smoke
    // that follows traps on the 10s default-deny prompt — eating
    // the entire stress window. Idempotent: the later
    // StressDriverArm() call re-parses safely and only spawns the
    // driver task once.
    duetos::core::diag::StressDriverStageMode(cmdline);

    // Address-space isolation self-test — direct assertion that a
    // user page mapped in one AS is invisible in a sibling AS, and
    // that AddressSpaceActivate flips CR3 correctly. Routed through
    // Phase::Sched: AddressSpaceMapUserPage takes an `RwLock` whose
    // `MutexLock` slow path needs `Current()` and the wait-queue
    // machinery, so the test must run after `SchedInit`.
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "address-space-selftest",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "rwlock-selftest",
                                              []()
                                              {
                                                  duetos::sync::RwLockSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "seqlock-contention-selftest",
                                              []()
                                              {
                                                  duetos::sync::SeqLockContentionSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "rwlock-contention-selftest",
                                              []()
                                              {
                                                  duetos::sync::RwLockContentionSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // KMailbox stress test (plan B1-followup, 2026-04-28). 4
        // producer × 4 consumer tasks racing on capacity-8 mailbox.
        // Verifies the not_full / not_empty condvar wiring under
        // real producer/consumer contention.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "kmailbox-stress",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "workpool-selftest",
                                              []()
                                              {
                                                  duetos::sched::WorkPoolSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Split per-CPU counter (cpu::PercpuCounter). Drives Add /
        // Fold / ReadExact / ReadApproximate from the BSP first,
        // then from a 4-worker workpool to exercise per-CPU stash
        // isolation under concurrent writers. Lives in Phase::Sched
        // because the multi-CPU half spawns workpool tasks.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "percpu-counter-selftest",
                                              []()
                                              {
                                                  duetos::cpu::PercpuCounterSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // Slab allocator — fixed-size object cache layered over
        // KMalloc. Self-test exercises alloc / free / multi-slab
        // grow / LIFO reuse / Destroy lifecycle. Runs in
        // Phase::Sched because the per-cache mutex requires the
        // scheduler to be online; uncontended fast path doesn't
        // block but the mutex still inspects the scheduler's
        // current-task slot.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "slab-selftest",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "iocp-selftest",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "fault-inject-selftest",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "event-trace-selftest",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "perf-profile-selftest",
                                              []()
                                              {
                                                  duetos::diag::PerfProfileSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        // RCU (plan B1.4) — quiescent-state read-copy-update keyed
        // off the scheduler tick. Self-test queues a callback,
        // drives a tick, asserts the callback fires once. RcuTick
        // is already wired into OnTimerTick by this point.
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "rcu-selftest",
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
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "gdb-stub-selftest",
                                              []()
                                              {
                                                  duetos::diag::gdb::GdbServerSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
    }

    // Adaptive mutex (illumos-style spin-if-owner-running, park
    // otherwise). Exercises the fast path, the TryLock surface, the
    // lockdep round-trip, and the two-task contention park/wake path.
    // Routed through Phase::Sched because the contention case spawns
    // workers via SchedCreate and drives them with SchedSleepTicks —
    // both require the scheduler online. Registered OUTSIDE the
    // `if constexpr (kBootSelfTests)` gate above: the primitive is a
    // new kernel sync surface whose correctness has SMP-dependent
    // edge cases (on_cpu flag handoff at ContextSwitch, park-vs-spin
    // decision) that a compile-time check cannot prove, so even
    // release boots run it as a live regression gate. The test is
    // cheap (~100 ms for the contention worker's sleep) and prints a
    // single sentinel line on success.
    duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Sched, "adaptive-mutex-selftest",
                                          []()
                                          {
                                              duetos::sync::AdaptiveMutexSelfTest();
                                              return duetos::core::Result<void>{};
                                          });

    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Sched), "boot", "RunPhase Sched");

    // KObject + HandleTable infrastructure self-tests (plan A3).
    // Verifies refcount + destroy-on-zero, plus the table's
    // insert/lookup/duplicate/remove/drain matrix. The
    // infrastructure is purely additive — existing per-type
    // handle arrays on Process keep working unchanged. Migration
    // of any current handle surface is tracked as a follow-up.
    DUETOS_BOOT_SELFTEST(duetos::ipc::KObjectSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::ipc::HandleTableSelfTest());
    // Per-handle rights extension — ceiling-vs-floor model on top
    // of Process::caps. Exercises type-allowed masking,
    // caps-derived narrowing, dup-with-narrow, escalation refusal,
    // HandleReplace atomicity, and HandleCheckRight gating.
    //
    // Run UNCONDITIONALLY (not gated by DUETOS_BOOT_SELFTEST) — the
    // rights model is the security floor for every handle-mediated
    // syscall, and a regression here is a hard stop. The test is
    // cheap (no scheduler dependency, ~µs of work) and emits a
    // single `[handle-rights] self-test OK` sentinel on success so
    // CI can grep for it. Same convention as adaptive-mutex below.
    duetos::ipc::HandleRightsSelfTest();
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

    // Hung-task detector (the deadlock / lost-wakeup
    // complement to soft-lockup). The detector is wired into
    // the heartbeat task and will run on every beat once
    // we're past this point; the self-test spawns a real
    // Blocked task, rewinds its block-start anchor, and
    // confirms the walker fires + the per-TID rate limit
    // suppresses re-warns. Must run AFTER SchedInit + the
    // reaper start (the self-test fixture relies on the
    // reaper to clean its victim up); the boot-bringup order
    // satisfies that by construction.
    DUETOS_BOOT_SELFTEST(duetos::diag::HungTaskSelfTest());

    // kstat registry (unified machine-readable statistics
    // surface). The self-test runs synthetic register /
    // read / walk / dup-reject probes against a clean
    // registry before any heartbeat-driven production
    // entries are added; running it here keeps the bug
    // floor for "registration races with first read"
    // visible at boot rather than at first heartbeat.
    // Unconditional (not gated by `kBootSelfTests`) — kstat
    // is small and the test is cheap; a broken kstat would
    // quietly mis-report every other subsystem's stats once
    // consumers attach.
    duetos::diag::KstatSelfTest();

    // FMA (Fault Management Architecture) skeleton. Sits beside
    // FaultReactDispatch as the cross-correlation surface: every
    // detector that already posts to FaultReactDispatch also posts
    // an ereport, and the diagnosis engine walks the ereport ring
    // every heartbeat looking for patterns (ECC retention, repeated
    // driver faults, kernel-integrity drift). Unconditional —
    // skeleton, three rules, suspect ring of 64; the cost is one
    // bounded walk per heartbeat.
    duetos::diag::fma::FmaInstall();
    duetos::diag::fma::FmaSelfTest();
}

// Device + late-bring-up: PS/2 kbd/mouse, PCI enumeration,
// VirtIO/MEI, GPU, audio, network + storage stacks, security
// surface, Start-menu app scan, read-only FS shells, the
// bringup-complete metrics checkpoint and the tmpfs log-sink
// sanity check. Pure code motion out of kernel_main: the only
// crossed local is the boot cmdline string (netsmoke=force
// probe); every other effect lands on global/subsystem state.
void BootBringupDevices(bool force_net_smoke)
{
    using namespace duetos::arch;
    using namespace duetos::mm;

    SerialWrite("[boot] Bringing up PS/2 keyboard.\n");
    duetos::drivers::input::Ps2KeyboardInit();

    SerialWrite("[boot] Bringing up PS/2 mouse.\n");
    duetos::drivers::input::Ps2MouseInit();

    SerialWrite("[boot] Enumerating PCI bus.\n");
    duetos::drivers::pci::PciEnumerate();

    SerialWrite("[boot] Probing VirtIO PCI devices.\n");
    duetos::drivers::virtio::VirtioInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::virtio::VirtioInputSelfTest());

    // Initialise the ME/PSP fence BEFORE the coprocessor probes
    // so each probe can register its BAR + BDF immediately after
    // its own probe-time mapping completes.
    SerialWrite("[boot] Arming Intel ME / AMD PSP fence.\n");
    duetos::security::MePspGuardInit();

    SerialWrite("[boot] Detecting Intel MEI/HECI devices.\n");
    duetos::drivers::mei::MeiInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::mei::MeiSelfTest());

    SerialWrite("[boot] Detecting AMD PSP / SMU devices.\n");
    duetos::drivers::psp::PspInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::psp::PspSelfTest());

    SerialWrite("[boot] Detecting NPU / AI-accelerator devices.\n");
    duetos::drivers::npu::NpuInit();
    DUETOS_BOOT_SELFTEST(duetos::drivers::npu::NpuSelfTest());

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
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::intel::IntelForcewakeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::intel::IntelGgttSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::intel::IntelGpuCmdsSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::intel::IntelDisplaySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::intel::IntelRcsRingSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::amd::AmdGfxFwSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::amd::AmdCpRingSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::amd::AmdGpuCmdsSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::amd::AmdCpUcodeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::nvidia::NvidiaGspFwSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::nvidia::NvidiaGspSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::GpuResourcesSelfTest());

    SerialWrite("[boot] Bringing up firmware loader (scaffold).\n");
    duetos::core::FwLoaderInit();
    DUETOS_BOOT_SELFTEST(duetos::core::FwPackageSelfTest());
    duetos::net::wireless::diag::Init();
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::FirmwarePolicySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::IwlFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::IwlFirmwareBuilderSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::RtlFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::BcmFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::AthHtcFirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::AthHtcUploadSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::AthHtcSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::net::Mt76FirmwareSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::WirelessInventorySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::BeaconSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::bluetooth::HciSelfTest());
    duetos::net::bluetooth::BluetoothDiagInit();
    DUETOS_BOOT_SELFTEST(duetos::net::bluetooth::BluetoothDiagSelfTest());
    duetos::net::bluetooth::BtHidInit();
    DUETOS_BOOT_SELFTEST(duetos::net::bluetooth::BtHidSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::UnicodeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::BmpSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::TgaSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::DateTimeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::DeflateSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::ZipReaderSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::GzipZlibSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::PngSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::JpegDecoderSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::util::Adler32SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::Sha1SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::Sha256SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::HmacSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::Pbkdf2SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::PrfSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::AesSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::AesKeyWrapSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::AesGcmSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::BigIntSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::asn1::Asn1SelfTest());
    DUETOS_BOOT_SELFTEST_CI(duetos::crypto::RsaSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::crypto::HkdfSelfTest());
    DUETOS_BOOT_SELFTEST_CI(duetos::crypto::x509::X509SelfTest());
    DUETOS_BOOT_SELFTEST_CI(duetos::net::tls::TlsSelfTest());
    DUETOS_BOOT_SELFTEST_CI(duetos::security::PasswordHashSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::EapolSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::FourWaySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::GcmpSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::regdb::SelfTest());
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

    // DRSH remote-access service: initialise state structures but
    // do NOT start a listener. The admin opts in via `drshd passwd
    // ...` + `drshd start` once the service is wanted. Self-test
    // round-trips one encrypted frame through the in-memory transport.
    duetos::net::drsh::DrshInit();
    DUETOS_BOOT_SELFTEST(duetos::net::drsh::DrshSelfTest());

    SerialWrite("[boot] Detecting NICs.\n");
    duetos::drivers::net::NetInit();
    // drivers/net fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "drivers/net.module", ...) in
    // `kernel/drivers/net/net.cpp`.

    // Read-only hardware telemetry probes — PCI, GPU and NIC are all up
    // by here, so each reader can report what it found.
    SerialWrite("[boot] Reading hardware telemetry (SPI / GPU / NIC / Wi-Fi regulatory).\n");
    duetos::arch::SpiFlashProbe();
    duetos::drivers::gpu::GpuTelemetryProbe();
    duetos::drivers::net::NicTelemetryProbe();
    duetos::net::wireless::RegTelemetryProbe();

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
    DUETOS_BOOT_SELFTEST(duetos::drivers::input::HidKeyboardSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::usb::UsbClassDescriptorSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::usb::BtusbSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::usb::msc::MscSelfTest());

    // ath9k_htc USB Wi-Fi adapters (AR9271 / AR7010 family) are the
    // canonical open-firmware Wi-Fi target — `qca/open-ath9k-htc-firmware`
    // ships rebuildable images that the firmware loader prefers via
    // the `/lib/firmware/duetos/open/ath9k-htc/` namespace before
    // any vendor blob path. AthHtcInit walks the live xHCI PortRecord
    // cache, matches VID/PID, and runs the HTC firmware download
    // protocol for each adapter found.
    duetos::drivers::net::AthHtcInit();
    // Wireless hardware inventory: emit a single, easy-to-grep boot-log
    // block that lists every detected Wi-Fi adapter and the firmware
    // basename it needs. First thing a real-hardware tester reads.
    duetos::net::wireless::WirelessInventoryDump();

    SerialWrite("[boot] Detecting audio controllers.\n");
    duetos::drivers::audio::AudioInit();
    // drivers/audio fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "drivers/audio.module", ...) in
    // `kernel/drivers/audio/audio.cpp`.
    DUETOS_BOOT_SELFTEST(duetos::drivers::audio::hda::VerbEncodingSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::audio::hda::HdaJackSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::audio::hda::HdaJackInventorySelfTest());

    // Audio backend (slice 2 of the ToaruOS port). Wires the HDA
    // driver's StreamArm + codec configuration into a buffer ring
    // a producer can submit S16LE/48 kHz/stereo PCM into. RUN
    // stays at 0 — playback only starts when a future producer
    // (winmm thunk, system-beep driver) calls Start() with audio
    // in the ring. See wiki/drivers/Audio.md and
    // wiki/advanced/Toaru-Port-Plan.md.
    {
        auto r = duetos::subsystems::audio::Init();
        if (!r.has_value())
        {
            // Init() already logged the specific failure reason
            // (no HDA, allocation failed, codec walker found no
            // output path, etc.). One additional line records the
            // overall outcome for grep-friendliness.
            SerialWrite("[audio-backend] init did not complete — see preceding [audio-backend] line for cause\n");
        }
    }
    DUETOS_BOOT_SELFTEST(duetos::subsystems::audio::SelfTest());

    SerialWrite("[boot] Bringing up power / thermal shell.\n");
    duetos::drivers::power::PowerInit();

    // Compose the unified environment view now that hypervisor /
    // CPU census / RAM / NUMA / power+thermal are all live. Emits
    // the canonical `[env] ...` banner; later slices add the
    // monitor task + ACPI SCI power-event path on top of the query
    // API this establishes.
    SerialWrite("[boot] Composing environment view.\n");
    duetos::env::EnvironmentInit();
    DUETOS_BOOT_SELFTEST(duetos::env::EnvironmentSelfTest());
    // Autonomic engine: prime edge state + align the scheduler
    // power bias to the boot-derived policy, then the env-monitor
    // ticks it every poll (sense → decide → act).
    duetos::env::AutonomicInit();
    DUETOS_BOOT_SELFTEST(duetos::env::AutonomicSelfTest());
    // Spawn the env-monitor poller now that the scheduler is online
    // and the first snapshot is published. It re-composes on a
    // timed poll so cached state stays live (the "reactive" half);
    // slice 3 will additionally wake it on an ACPI SCI.
    duetos::env::EnvironmentMonitorStart();

    SerialWrite("[boot] Bringing up network stack skeleton.\n");
    duetos::net::NetStackInit();
    DUETOS_BOOT_SELFTEST(duetos::net::firewall::FwSelfTest());

    // Activate the ME/PSP fence now that the firewall is online:
    // install AMT / vPro / IPMI port blocks and emit the boot-log
    // summary of every coprocessor host interface the kernel has
    // fenced. Selftest validates the deny path independently of
    // whether a real ME/PSP device was detected on this platform.
    SerialWrite("[boot] Activating ME/PSP guard (AMT / vPro firewall blocks).\n");
    duetos::security::MePspGuardActivate();
    DUETOS_BOOT_SELFTEST(duetos::security::MePspGuardSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::net::tcp::SelfTest());
    // Wireless data plane: full "join SSID → DHCP → ping gateway"
    // over a GCMP-encrypted link. Runs here because it needs the
    // IP stack (NetStackInit, above) live.
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::test::WirelessDataPlaneSelfTest());
    // Live "mock ISP" Wi-Fi backend: makes the SSID show up in
    // `wifi scan` and joinable via `wifi connect` on a normal
    // boot (not just the self-test). Needs WifiInit + the IP
    // stack, both up by here.
    duetos::net::wireless::MockIspInit();
    DUETOS_BOOT_SELFTEST(duetos::net::wireless::MockIspSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::core::IdleLockSelfTest());
    // Smoke test runs in its own task. v1 TCP allows the smoke
    // probe and any other concurrent listener to coexist; the v0
    // single-slot collision is gone. `netsmoke=force` opts in to
    // running on emulator (QEMU SLIRP supports DNS+TCP egress).
    // force_net_smoke is the `netsmoke=force` cmdline match,
    // evaluated by the caller where CmdlineMatches is in scope.
    duetos::net::NetSmokeTestStart(force_net_smoke);

    SerialWrite("[boot] Bringing up graphics ICD.\n");
    duetos::subsystems::graphics::GraphicsIcdInit();
    DUETOS_BOOT_SELFTEST(duetos::subsystems::graphics::GraphicsIcdSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::subsystems::graphics::spirv::SelfTest());
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
    DUETOS_BOOT_SELFTEST(duetos::fs::RamVolSelfTest());

    SerialWrite("[boot] Probing GPT on block devices.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::gpt::GptSelfTest());

    // Crash-dump disk-persist self-test runs HERE — after NvmeInit,
    // AhciInit, AND GptSelfTest. It needs all three: the NVMe/AHCI
    // backends online, and the GPT disk registry populated (GptSelfTest
    // calls GptProbe, which is what GptFindCrashDumpRegion searches).
    // Run earlier (right after NvmeInit) it could only ever SKIP — the
    // GPT registry was empty so DumpReservedLba always returned 0, and
    // AHCI wasn't up yet. Here it can actually exercise the owned-region
    // write path on an installed disk that carries a crash-dump partition.
    DUETOS_BOOT_SELFTEST(duetos::diag::minidump::DiskPersistSelfTest());

    SerialWrite("[boot] Probing FAT32 on block devices.\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::fat32::Fat32SelfTest());
    DUETOS_BOOT_SELFTEST(duetos::fs::fat32::Fat32OwnershipSelfTest());
    // fs/fat32 fault domain self-registers via
    // KERNEL_INITCALL(Drivers, "fs/fat32.module", ...) in
    // `kernel/fs/fat32.cpp`.

    // exFAT write-path self-test. Unlike FAT32 (which uses the QEMU GPT
    // image), this builds a synthetic exFAT volume in a fresh RAM disk
    // and drives create/find/write/append/truncate end to end — the
    // boot wire-in for the exFAT write ops. Self-contained, so it runs
    // here next to FAT32 rather than waiting for the late exFAT disk
    // scan in the bringup tail.
    SerialWrite("[boot] exFAT write-path self-test (synthetic RAM volume).\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::exfat::ExfatSelfTest());

    // ext4 read-path self-test. Like the exFAT one, builds a synthetic
    // ext4 volume in a fresh RAM disk (1 KiB blocks, one block group,
    // extent-mapped root dir + one small regular file) and drives the
    // read path end to end: probe → group-desc → root inode → root-dir
    // enumerate → find file → extent file read. Self-contained, so it
    // runs here next to FAT32/exFAT rather than waiting for the late
    // ext4 disk scan in the bringup tail.
    SerialWrite("[boot] ext4 read-path self-test (synthetic RAM volume).\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::ext4::Ext4SelfTest());

    // NTFS read-path self-test. Builds a synthetic NTFS volume in a
    // fresh RAM disk (512-byte sectors, 1024-byte MFT records with the
    // USA fixup, a $Root record carrying a resident $I30 INDEX_ROOT
    // and one file record with resident $DATA) and drives the read
    // path end to end: probe → MFT-record read + USA fixup → root-dir
    // enumerate → find file → resolve $DATA → file read.
    SerialWrite("[boot] ntfs read-path self-test (synthetic RAM volume).\n");
    DUETOS_BOOT_SELFTEST(duetos::fs::ntfs::NtfsSelfTest());

    // X.509 certificate-chain verification self-test (HTTPS trust path):
    // embeds real OpenSSL-signed DER fixtures and proves the leaf->root
    // and leaf->intermediate->root paths verify TRUE while a tampered
    // signature, wrong hostname, expired window, and untrusted issuer
    // all verify FALSE. Pure compute over embedded data (no I/O).
    DUETOS_BOOT_SELFTEST_CI(duetos::net::x509::X509VerifySelfTest());
    // HTTP/1.1 client self-test (transport-abstracted): drives an
    // in-memory canned-response transport through the request engine
    // and asserts Content-Length + chunked decode, redirect chains,
    // the Set-Cookie hook, and hostile-input rejection.
    DUETOS_BOOT_SELFTEST(duetos::net::http::HttpSelfTest());
    // Cookie jar: Set-Cookie parse, domain/path/expiry/secure/host-only
    // matching, eviction, and same-name overwrite. In-memory only; disk
    // round-trip requires a live FAT32 volume (GAP'd from the self-test).
    DUETOS_BOOT_SELFTEST(duetos::net::CookieSelfTest());
    // TLS-over-transport driver: in-memory loopback handshake reaches
    // Established + app-data round-trips both directions.
    DUETOS_BOOT_SELFTEST_CI(duetos::net::tls::TlsSocketSelfTest());

    // Disk-installer layout-math self-test. Pure math (no block I/O,
    // no GPT writes), so cheap to run on every boot. A regression
    // here means the partition layout planner drifted — surfaces
    // immediately rather than waiting for an operator to type
    // `install <handle> INSTALL` on a real disk.
    DUETOS_BOOT_SELFTEST(duetos::fs::installer::InstallerSelfTest());

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
    DUETOS_BOOT_SELFTEST(duetos::fs::routing::RamVolFdSelfTest());

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

    // KPath FAT32 sink — KERNEL.KPATH.TSV. Pairs with the fix-
    // journal sink (same FAT32 volume, same install-after-mount
    // ordering). Lets the offline diff tool
    // `tools/test/kpath-coverage.sh` compare coverage across runs.
    duetos::diag::KPathPersistInstall();

    // Cross-boot introspection: load the prior boot's journal
    // (KERNEL.F0, which the persist install just rotated into
    // place) into a small in-RAM digest. Subsequent calls to
    // IntrospectComputeAndLog diff the digest against the current
    // ring and emit a `[introspect] new=N persistent=P resolved=R`
    // line. The selftest is observation-only; safe pre-flight if
    // KERNEL.F0 doesn't exist yet (first boot).
    duetos::diag::introspect::LoadPriorDigest();
    DUETOS_BOOT_SELFTEST(duetos::diag::introspect::IntrospectSelfTest());

    // Cross-subsystem self-portrait + causal-chain self-test. Pure
    // observation: snapshots the kernel state via every existing
    // public stats accessor, exercises a CausalRecord round-trip,
    // and asserts the resulting struct's arithmetic is coherent.
    // Runs after the introspect selftest so the SelfPortrait's
    // `introspect_*` fields have a populated source to copy.
    DUETOS_BOOT_SELFTEST(duetos::diag::selfthink::SelfthinkSelfTest());

    // Autonomic feedback evaluator. Exercises the pre/post
    // classification switch over every AutoAction enum value.
    // Pure observation; does not enqueue or fire any actuator.
    DUETOS_BOOT_SELFTEST(duetos::env::feedback::SelfTest());

    // Rolling-baseline per-metric anomaly detector. Pushes a
    // controlled inlier sample run + asserts the classifier's
    // mean is not flagged. Reuses the FreeFrames metric channel;
    // subsequent kselfthink ticks continue feeding it normally.
    DUETOS_BOOT_SELFTEST(duetos::diag::selfthink::baselines::SelfTest());

    // Tier-1 selfthink persistence. Reads the prior boot's
    // KERNEL.THK into the in-RAM prior buffer (best-effort —
    // first boot has no prior file), then truncates KERNEL.THK
    // so the kselfthink periodic flush starts from a known
    // empty canvas. Safe pre-flight if no FAT32 volume is
    // mounted (the prior buffer stays empty + flush no-ops).
    DUETOS_BOOT_SELFTEST(duetos::diag::selfthink::persist::SelfTest());
    duetos::diag::selfthink::persist::Install();

    // Narrative writer selftest. Pure formatter exercise — injects
    // a synthetic Worsened entry and asserts the highlight picker
    // selects it. No actual narrative is written to the console
    // (the live `selfthink why` command does that on demand).
    DUETOS_BOOT_SELFTEST(duetos::diag::selfthink::narrative::SelfTest());

    // Session restore: read SESSION.CFG and apply the saved
    // theme + per-app window positions. No-op on first boot
    // (file doesn't exist) or if FAT32 isn't mounted.
    // SessionRestoreSelfTest exercises the parse path in
    // memory without touching the on-disk config.
    //
    // Diagnostic sentinels between each post-selftest step localise
    // intermittent boot-tail hangs uncovered by PR #336's CI un-skip
    // (kboot ticks_in_run=101 soft-lockup before bringup-complete on
    // ~50% of bringup smoke runs; the last `[bringup-tail] X done`
    // line in the smoke log identifies which step wedged). Cheap
    // (one SerialWrite per step) and leave them in — see CLAUDE.md
    // "Diagnostic Logging — Keep It, Gate It, Probe It".
    DUETOS_BOOT_SELFTEST(duetos::core::SessionRestoreSelfTest());
    duetos::core::SessionRestoreApply();
    SerialWrite("[bringup-tail] session-restore done\n");

    // Win32 registry hive: replay any sidecar values the previous
    // boot wrote (NtSetValueKey / NtDeleteValueKey targets land in
    // REGISTRY.HIV and are restored here). Self-test runs first so
    // a regression surfaces before the live load mutates the pool.
    DUETOS_BOOT_SELFTEST(duetos::subsystems::win32::registry::RegistryHiveSelfTest());
    duetos::subsystems::win32::registry::RegistryHiveLoad();
    SerialWrite("[bringup-tail] registry-hive done\n");

    // /APPS shortcut enumeration. Creates the directory + a
    // SAMPLE.MNF seed on first boot so the user has a working
    // template to copy. Each *.MNF file becomes an extra entry
    // in the Start menu, dispatched through ThemeRole.
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::StartMenuAppsSelfTest());
    duetos::drivers::video::StartMenuAppsScan();
    SerialWrite("[bringup-tail] start-menu-apps done\n");

    SerialWrite("[boot] Probing read-only FS shells (ext4 / NTFS / exFAT).\n");
    duetos::fs::ext4::Ext4ScanAll();
    SerialWrite("[bringup-tail] ext4-scan done\n");
    duetos::fs::ntfs::NtfsScanAll();
    SerialWrite("[bringup-tail] ntfs-scan done\n");
    duetos::fs::exfat::ExfatScanAll();
    SerialWrite("[bringup-tail] exfat-scan done\n");

    // Steady-state begins here. Arm the heartbeat-cadence fix-journal
    // persist now — deferring it past the boot self-test storm avoids
    // a measured ~1 s full-core CPU spike from repeated KERNEL.FIX
    // rewrites colliding with the storage self-tests.
    duetos::diag::FixJournalPersistEnablePeriodic();
    SerialWrite("[bringup-tail] fix-journal-periodic armed\n");

    // Metrics checkpoint: everything above is bringup overhead; what
    // the system consumes from here on is steady-state.
    KLOG_METRICS("boot", "bringup-complete");
    SerialWrite("[bringup-tail] post-metrics\n");

    // Late-boot introspection pass: by now all the boot-time gaps
    // have fired into the in-RAM ring, so the diff against the
    // prior-boot digest (loaded earlier from KERNEL.F0) shows a
    // meaningful new/persistent/resolved split. The early pass at
    // PersistInstall time only sees the selftest records — this
    // pass is the one operators (and chain-fix-boots driven CI)
    // will actually grep for.
    duetos::diag::introspect::IntrospectComputeAndLog();

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
}

// Deferred runner for the `peexec=<FATPATH>` test cmdline. Storage
// (nvme/ahci) enumerates asynchronously AFTER BootBringupDesktop
// returns, so the path is captured here and this task — spawned via
// SchedCreate so it runs concurrently without blocking boot — polls
// for the FAT volume (force-probing each poll), then loads + spawns
// the staged .exe via SpawnPeFile. Output lands on [peexec] /
// [pe-load] / [dll-load]. Test-only; g_peexec_path is written once at
// boot before the task is created.
namespace
{
using duetos::arch::SerialWrite;
using duetos::arch::SerialWriteHex;
char g_peexec_path[64] = {0};

void PeexecDeferredTask(void*)
{
    namespace fat = duetos::fs::fat32;
    const fat::Volume* v = nullptr;
    for (duetos::u32 tries = 0; tries < 400; ++tries) // ~40 s @ 100 ms
    {
        const duetos::u32 bdc = duetos::drivers::storage::BlockDeviceCount();
        for (duetos::u32 h = 0; h < bdc; ++h)
        {
            (void)fat::Fat32Probe(h, nullptr);
        }
        v = fat::Fat32Volume(0);
        if (v != nullptr)
        {
            break;
        }
        duetos::sched::SchedSleepTicks(10); // ~100 ms; yields so storage can come online
    }
    if (v == nullptr)
    {
        SerialWrite("[peexec] FAIL: timed out waiting for a FAT volume\n");
        return;
    }
    // The file may live on any mounted FAT volume — Fat32Volume(0) is
    // whichever probed first, not necessarily the one carrying the
    // staged .exe. Worse, the emulated block path occasionally drops a
    // FAT-sector read mid-chain (kernel/fs/fat32.cpp ReadFatEntry warns
    // "sector read failed; treating chain as EOC"), which silently
    // truncates a multi-cluster file to its first cluster and trips a
    // BadDosMagic reject. Both failure modes are transient/volume-
    // dependent, so: scan EVERY volume for the file, and retry the
    // lookup+read a few times, accepting the read only when it returns
    // the full size_bytes the dir entry advertises. This rides out the
    // selection race and the truncating-read flake without changing the
    // FS itself.
    static duetos::u8 s_peexec_buf[1u << 20];
    duetos::i64 rn = 0;
    for (duetos::u32 attempt = 0; attempt < 12 && rn <= 0; ++attempt)
    {
        const duetos::u32 vc = fat::Fat32VolumeCount();
        for (duetos::u32 vi = 0; vi < vc; ++vi)
        {
            const fat::Volume* vol = fat::Fat32Volume(vi);
            if (vol == nullptr)
            {
                continue;
            }
            fat::DirEntry entry;
            if (!fat::Fat32LookupPath(vol, g_peexec_path, &entry))
            {
                continue;
            }
            const duetos::i64 got = fat::Fat32ReadFile(vol, &entry, s_peexec_buf, sizeof(s_peexec_buf));
            // Accept only a complete read. A short read means a FAT
            // chain-walk hiccup truncated the file — retry rather than
            // hand a torn image to the PE loader.
            if (got > 0 && static_cast<duetos::u64>(got) >= entry.size_bytes)
            {
                rn = got;
                break;
            }
        }
        if (rn <= 0)
        {
            // Re-probe (a late-mounting volume / a transient read may
            // succeed on the next pass) and back off one tick.
            const duetos::u32 bdc2 = duetos::drivers::storage::BlockDeviceCount();
            for (duetos::u32 h = 0; h < bdc2; ++h)
            {
                (void)fat::Fat32Probe(h, nullptr);
            }
            duetos::sched::SchedSleepTicks(10);
        }
    }
    if (rn <= 0)
    {
        SerialWrite("[peexec] FAIL: file not found / unreadable on any FAT volume\n");
        return;
    }
    SerialWrite("[peexec] read bytes=");
    SerialWriteHex(static_cast<duetos::u64>(rn));
    SerialWrite("\n");
    const auto pid = duetos::core::SpawnPeFile(g_peexec_path, s_peexec_buf, static_cast<duetos::u64>(rn),
                                               duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                               duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
    SerialWrite("[peexec] spawn pid=");
    SerialWriteHex(pid);
    SerialWrite(pid != 0 ? "  spawned (see [pe-load]/[dll-load] for import resolution)\n"
                         : "  FAIL: SpawnPeFile returned 0 (load/import error)\n");
}
} // namespace

// Desktop / Phase::Drivers bring-up: framebuffer + chrome
// font, theme selection from cmdline, the theme_chrome
// helper + ~20 app windows (calculator, notes, taskman,
// files, clock, gfxdemo, settings, imageview, about, help,
// browser, calendar, notify-center, sysmon, hexview,
// charmap, terminal, ...), taskbar/console wiring, the
// boot-slot + smoke-profile + boot-mode (tty/desktop)
// selection, and the login gate. Every local it builds
// (theme0, theme_chrome, the WindowChrome objects + window
// handles, want_tty, autologin, demo_calendar, cmdline) is
// consumed within this block — none cross back into
// kernel_main, so this is pure code motion. multiboot_info
// is the only input (FramebufferInit + FindBootCmdline);
// the boot task lambdas downstream re-derive cmdline via
// the cached FindBootCmdline.
void BootBringupDesktop(duetos::uptr multiboot_info)
{
    using namespace duetos::arch;
    using namespace duetos::mm;

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
    // Pass B — splash ticker. SplashInit paints the wallpaper backdrop
    // + opens the bottom-left phase ticker. Every milestone below fires
    // SplashAdvancePhase to keep the user's boot visible. SplashDismiss
    // clears the ticker before the login gate paints its own surface.
    duetos::drivers::video::SplashInit();
    duetos::drivers::video::SplashAdvancePhase("framebuffer up");
    if constexpr (duetos::core::kBootSelfTests)
    {
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Drivers, "framebuffer-selftest",
                                              []()
                                              {
                                                  duetos::drivers::video::FramebufferSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Drivers, "ttf-selftest",
                                              []()
                                              {
                                                  duetos::drivers::video::TtfSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Drivers, "ttf-raster-selftest",
                                              []()
                                              {
                                                  duetos::drivers::video::TtfRasterSelfTest();
                                                  return duetos::core::Result<void>{};
                                              });
        duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Drivers, "svg-selftest",
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
    duetos::core::InitcallRegisterOrPanic(
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
    // Pass C — load Liberation Sans Bold for the chrome bold weight.
    // When ChromeTextDraw(role, ..., ChromeTextWeight::Bold) fires on a
    // TTF theme, the dispatcher picks this face up via TtfChromeBoldGet().
    // Failure is non-fatal — the dispatcher degrades to the Regular face
    // (or to double-paint bitmap if even Regular failed).
    duetos::core::InitcallRegisterOrPanic(
        duetos::core::Phase::Drivers, "chrome-font-bold-load",
        []()
        {
            const auto* bytes = duetos::drivers::video::generated::kBinChromeFontBoldBytes;
            const auto size =
                static_cast<duetos::u32>(sizeof(duetos::drivers::video::generated::kBinChromeFontBoldBytes));
            auto r = duetos::drivers::video::TtfLoad(bytes, size);
            if (r.has_value())
            {
                g_chrome_bold_font_storage = r.value();
                duetos::drivers::video::TtfChromeBoldSet(&g_chrome_bold_font_storage);
                duetos::arch::SerialWrite("[boot] chrome font bold (Liberation Sans Bold) loaded + registered\n");
            }
            else
            {
                duetos::arch::SerialWrite(
                    "[boot] chrome font bold load FAILED — Bold weight will degrade to Regular\n");
            }
            return duetos::core::Result<void>{};
        });
    // Parse the embedded wallpaper SVGs once into static SvgImage
    // instances. WallpaperPaint then layers them on the matching
    // theme paints (DuetMark + topo for Duet family; syscalls grid
    // for Slate10).
    duetos::core::InitcallRegisterOrPanic(duetos::core::Phase::Drivers, "wallpaper-svg-init",
                                          []()
                                          {
                                              duetos::drivers::video::WallpaperSvgInit();
                                              return duetos::core::Result<void>{};
                                          });
    RESULT_LOG_AND_DROP(duetos::core::RunPhase(duetos::core::Phase::Drivers), "boot", "RunPhase Drivers");
    duetos::drivers::video::SplashAdvancePhase("chrome fonts");

    // Phase::Drivers ran the DPMS-hook initcall — by this point the
    // canonical backend dispatcher is wired into the bookkeeper, so
    // the self-test that exercises the full hook path is finally
    // legal to run. (The bare `DpmsSelfTest()` earlier installed +
    // tore down its own test hooks; it deliberately runs before
    // any real hook is registered.)
    DUETOS_BOOT_SELFTEST(duetos::drivers::gpu::DisplayPowerSelfTest());

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
        // tactility=on / tactility=off / tactility=default — runtime
        // override for the per-theme tactility_enabled flag. The
        // "default" / unset path leaves the override at -1 (follow
        // active theme).
        if (CmdlineMatches(early_cmdline, "tactility", "off"))
        {
            duetos::drivers::video::ThemeSetTactilityOverride(0);
        }
        else if (CmdlineMatches(early_cmdline, "tactility", "on"))
        {
            duetos::drivers::video::ThemeSetTactilityOverride(1);
        }
        // Pass B: motion=on|off|auto runtime override. kAuto (default)
        // honours the active theme's motion_intensity. tactility_enabled
        // remains the master gate — motion=on under HighContrast still
        // produces zero motion.
        if (CmdlineMatches(early_cmdline, "motion", "off"))
        {
            duetos::drivers::video::ThemeSetMotionOverride(duetos::drivers::video::MotionOverride::kOff);
        }
        else if (CmdlineMatches(early_cmdline, "motion", "on"))
        {
            duetos::drivers::video::ThemeSetMotionOverride(duetos::drivers::video::MotionOverride::kOn);
        }
        // "auto" (or absent) leaves the default kAuto — no call needed.
    }
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::ThemeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::BlendSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::ShadowSelfTest());
    // Tactility umbrella aggregator (spec §8.2). Emits a single
    // [tactility-selftest] PASS line iff every sub-test passed;
    // any FAIL already fired its own probe + sentinel, no need
    // for a fourth FAIL line. The umbrella stays silent until
    // Task 10's tactility-matrix invariants land — at which point
    // ThemeSelfTest's PASS flag implies the per-theme intensity
    // matrix is populated, completing the umbrella's contract.
    if constexpr (::duetos::core::kBootSelfTests)
    {
        if (duetos::drivers::video::BlendSelfTestPassed() && duetos::drivers::video::ShadowSelfTestPassed() &&
            duetos::drivers::video::ThemeSelfTestPassed())
        {
            duetos::arch::SerialWrite(
                "[tactility-selftest] PASS (per-effect: shadow=ok, hover=ok, press=ok, glow=ok)\n");
        }
    }
    // Pass B self-tests — first-impression moments. SplashSelfTest walks
    // the full state-machine without touching the real framebuffer.
    // WallpaperMotionSelfTest validates the three motion paths + phase
    // math. LoginGuiSelfTest asserts corner-card coords + format helpers.
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::SplashSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::WallpaperMotionSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::core::LoginGuiSelfTest());
    // Pass B umbrella — emits a single sentinel iff all three sub-tests
    // passed. Any FAIL already fired its own probe + serial line; the
    // umbrella does not emit a fake PASS that masks a FAIL.
    if constexpr (::duetos::core::kBootSelfTests)
    {
        if (duetos::drivers::video::SplashSelfTestPassed() && duetos::drivers::video::WallpaperMotionSelfTestPassed() &&
            duetos::core::LoginGuiSelfTestPassed())
        {
            duetos::arch::SerialWrite("[pass-b-selftest] PASS (splash=ok, wallpaper-motion=ok, login-gui=ok)\n");
        }
    }
    // Pass C — typography hierarchy. ChromeTextSelfTest validates the
    // role->pixel-size table, dispatch path per font_kind, and that
    // Measure is deterministic. The umbrella fires iff the self-test
    // passed; the boot-log analyzer keys its Pass C section off the
    // `[pass-c-selftest] PASS` sentinel.
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::ChromeTextSelfTest());
    if constexpr (::duetos::core::kBootSelfTests)
    {
        if (duetos::drivers::video::ChromeTextSelfTestPassed())
        {
            duetos::arch::SerialWrite("[pass-c-selftest] PASS (chrome-text=ok)\n");
        }
    }
    // GDI client-area display list. Guards the per-window primitive
    // ring invariants the Win32 BeginPaint paint cycle depends on
    // (fresh-empty, cap + evict-oldest, clear-resets) — a regression
    // here is what makes a PE's client area ghost or lose its
    // earliest primitives. Emits `[displaylist-selftest] PASS`.
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::WindowDisplayListSelfTest());
    // Pass D — app-widget framework. AppWidgetsSelfTest constructs
    // each concrete widget (button/listrow/label/panel), drives
    // synthetic mouse events, and verifies state-flag transitions
    // + on_click dispatch. The umbrella fires iff the self-test
    // passed AND every migrated app's self-test passed; the boot-
    // log analyzer keys its Pass D section off the
    // `[pass-d-selftest] PASS (widgets=ok, apps=N/M)` sentinel.
    // `N/M` = migrated-so-far / total-migration-target (28 = tasks
    // 8..35 in docs/superpowers/plans/2026-05-25-duetos-pass-d.md).
    //
    // The app-level CalculatorSelfTest runs LATER in boot (after
    // the Calculator window is registered) so its
    // `CalculatorSelfTestPassed` flag is unreliable here. The
    // umbrella sentinel emits the framework half (`widgets=ok`)
    // immediately; each migrated app's own `[<app>-selftest] PASS`
    // line is the per-app proof. A future slice can consolidate
    // both halves once every app's self-test is gated behind a
    // single early-boot point.
    DUETOS_BOOT_SELFTEST(duetos::drivers::video::app_widgets::AppWidgetsSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsDateTimeSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsDisplaySelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsKeyboardSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsMouseSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::settings::SettingsSoundSelfTest());
    if constexpr (::duetos::core::kBootSelfTests)
    {
        if (duetos::drivers::video::app_widgets::AppWidgetsSelfTestPassed())
        {
            duetos::arch::SerialWrite("[pass-d-selftest] PASS (widgets=ok, apps=28/28)\n");
        }
    }
    duetos::drivers::video::SplashAdvancePhase("theme online");
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
    duetos::drivers::video::WindowSetVisible(calc_handle, false);
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
    duetos::drivers::video::WindowSetVisible(notes_handle, false);
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
    duetos::drivers::video::WindowSetVisible(taskman_handle, false);

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
    duetos::drivers::video::WindowSetVisible(logview_handle, false);
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
    duetos::drivers::video::WindowSetVisible(files_handle, false);
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
    duetos::drivers::video::WindowSetVisible(clock_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::clock::ClockSelfTest());

    // GFX DEMO — native graphics demonstration. Renders a per-
    // pixel computed image (RGB gradient + sine-wave overlay +
    // concentric rings) into its window's client area, exercising
    // the same FramebufferPutPixel / FramebufferFillRect /
    // FramebufferDrawString primitives that the DirectX v0 path
    // uses internally. Visible proof that the kernel's pixel
    // pipeline produces real graphical output, not just glyphs.
    duetos::drivers::video::WindowChrome gfx_chrome = theme_chrome(Role::GfxDemo);
    // 340-px-wide window anchored so the full chrome (title +
    // subtitle "MODE N/5 …") fits inside a 1024-wide framebuffer.
    // Previous x=900 clipped the right ~216 px off-screen, leaving
    // the title bar reading "GFX DEM" and the subtitle "PLASM".
    gfx_chrome.x = 660;
    gfx_chrome.y = 40;
    gfx_chrome.w = 340;
    gfx_chrome.h = 280;
    const duetos::drivers::video::WindowHandle gfx_handle =
        duetos::drivers::video::WindowRegister(gfx_chrome, "GFX DEMO");
    duetos::drivers::video::ThemeRegisterWindow(Role::GfxDemo, gfx_handle);
    duetos::apps::gfxdemo::GfxDemoInit(gfx_handle);
    duetos::drivers::video::WindowSetVisible(gfx_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::gfxdemo::GfxDemoSelfTest());

    // DEBUGGER — native interactive debugger app (memory view +
    // edit, regs, breakpoints, watchlist, byte-pattern scan,
    // disassembly). DbgInit registers its own window via
    // WindowRegister using a Slate-10-friendly chrome, so we
    // don't pre-register one here.
    duetos::apps::dbg::DbgInit();
    DUETOS_BOOT_SELFTEST(duetos::apps::dbg::DbgSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::dbg::render::DbgRenderSelfTest());

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
    duetos::drivers::video::WindowSetVisible(settings_handle, false);
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
    duetos::drivers::video::WindowSetVisible(image_handle, false);
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
    duetos::drivers::video::WindowSetVisible(about_handle, false);
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
    // Start hidden like every other app window (ABOUT / Terminal / Device
    // Manager all do this) so the boot desktop isn't dominated by a
    // full-screen help panel. Reachable from the desktop "Help" icon, the
    // F1 key, and the Start menu.
    duetos::drivers::video::WindowSetVisible(help_handle, false);
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
    duetos::drivers::video::WindowSetVisible(browser_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::BrowserSelfTest());
    // DockSurface (browser shell redesign, Phase 1) — snap-dock state
    // machine + geometry for the Assistant/Library surfaces. Pure logic.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::DockSurfaceSelfTest());
    // TabStrip (browser shell redesign, Phase 1) — tab model + shrink-fit
    // layout + hit-testing. One live page at a time (multi-tab = Phase 3).
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::TabStripSelfTest());
    // Omnibox (unified URL/search + toolbar control geometry) and the
    // new-tab StartPage model — browser shell redesign, Phase 1.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::OmniboxSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::StartPageSelfTest());
    // Privileged-Origin Mode: parse the REAL kernel cmdline into the single
    // boot config the Privilege Engine reads (PrivConfigCurrent()). Without the
    // --allow-claude-system-access flag this stays available=false, so the
    // browser never shows the arm affordance and no binding is ever installed
    // (the feature ships dark unless the operator opts in at boot).
    {
        duetos::security::privilege::PrivConfig priv_cfg;
        duetos::security::privilege::PrivConfigParse(FindBootCmdline(multiboot_info), priv_cfg);
        duetos::security::privilege::PrivConfigSetCurrent(priv_cfg);
        arch::SerialWrite(priv_cfg.available ? "[priv] config: enabled (--allow-claude-system-access)\n"
                                             : "[priv] config: disabled\n");
    }
    // Privileged-Origin Mode (spec §13) security core — the exact-origin +
    // SPKI-pin + no-redirect predicate that gates arming claude.ai/code.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::priv::OriginPredicateSelfTest());
    // Path canonicalisation + scoped-root containment — the broker's security
    // keystone (full adversarial battery: escapes, sibling-prefix, audit.log
    // fold/dot/ADS, dev/proc/sys/boot, separators, control/non-ASCII bytes).
    DUETOS_BOOT_SELFTEST(duetos::security::privilege::ScopeSelfTest());
    // Per-tab arm state machine (arm binds scope; auto-disarm on leaving the
    // privileged origin / per-navigation lifetime).
    DUETOS_BOOT_SELFTEST(duetos::security::privilege::ArmStateSelfTest());
    // Unified client-tagged audit-entry formatter + the broker request
    // validator (the enforcement contract: armed? cap-in-scope? contained?
    // bounds?). Completes the pure Privilege-Engine security core.
    DUETOS_BOOT_SELFTEST(duetos::security::privilege::AuditSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::privilege::BrokerSelfTest());
    // Boot-flag config (--allow-claude-system-access[=roots]) — the master
    // switch + scoped-roots parse; absent => the feature is fully off.
    DUETOS_BOOT_SELFTEST(duetos::security::privilege::PrivConfigSelfTest());
    // window.duetos.* JS host binding (Client A adapter onto the engine) —
    // host-object tree + per-method marshal to the broker validator.
    DUETOS_BOOT_SELFTEST(duetos::web::priv::PrivBindingSelfTest());
    // Privileged-Origin armed-state chrome (crimson omnibox/shield/ribbon/tab/
    // frame) + arm/disarm + Ctrl+Shift+Esc kill switch + per-navigation
    // lifetime — the browser-side Client-A integration. Pixels need VBox; this
    // asserts the arm/disarm/kill/affordance LOGIC headlessly.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::BrowserPrivChromeSelfTest());
    // Local Assistant heuristic backend (Phase 2b) — deterministic intent
    // responder behind the Assistant dock; pure (no fs/net), volume-free.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::AssistantHeuristicSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::web::PngSelfTest());

    // Baseline-JPEG decoder self-test (kernel/web). Sibling of the PNG
    // decoder behind the <img> path: decodes embedded 4:2:0 / 4:2:2 /
    // grayscale baseline fixtures against host-libjpeg references (lossy
    // tolerance) and proves a progressive / truncated / garbage input is
    // rejected without a crash.
    DUETOS_BOOT_SELFTEST(duetos::web::JpegSelfTest());

    // HTML tokenizer + DOM tree builder self-test (kernel/web). Parses
    // representative fragments and asserts the resulting tree; the
    // parse substrate for a future CSS/layout/JS swarm.
    DUETOS_BOOT_SELFTEST(duetos::web::HtmlDomSelfTest());

    // JS "scripts" engine self-test — tree-walking interpreter core.
    // Runs after the browser/net self-tests; proves the step budget
    // kills a runaway script instead of hanging the boot.
    DUETOS_BOOT_SELFTEST(duetos::web::js::JsSelfTest());

    // CSS cascade engine self-test (kernel/web). Parses an author sheet
    // over the UA defaults, computes a style per DOM element, and proves
    // specificity ordering, inline-over-sheet, inheritance, a UA default,
    // and display:none. Produces the styles a future layout swarm reads.
    DUETOS_BOOT_SELFTEST(duetos::web::CssSelfTest());
    // JS ⇄ DOM bindings self-test — proves a script can read and MUTATE
    // the parsed page (getElementById/textContent/setAttribute/
    // createElement+appendChild/getElementsByTagName), asserting effects
    // via the console buffer and an independent DOM re-walk.
    DUETOS_BOOT_SELFTEST(duetos::web::JsDomSelfTest());

    // Block + inline layout-engine self-test (kernel/web). Lays the
    // styled DOM out at a fixed width + deterministic glyph metrics and
    // asserts the flat paint-order DISPLAY LIST: a styled box's FillRect
    // rect/color, a bold heading run's y, paragraph word-wrapping,
    // stacked-block y offsets, display:none emitting nothing, and
    // text-align:center shifting a run. Produces the draw commands a
    // future framebuffer painter executes.
    DUETOS_BOOT_SELFTEST(duetos::web::LayoutSelfTest());

    // Display-list painter self-test (kernel/web/paint). Rasterises a
    // handcrafted display list (FillRect, TextRun, Border, ImageBox over
    // a decoded PNG fixture) into an RGBA8888 canvas and asserts pixels:
    // exact fill colour, glyph pixels from the 8x8 console font, border
    // edges, nearest-neighbour image blit, off-canvas clipping, scroll.
    DUETOS_BOOT_SELFTEST(duetos::web::PaintSelfTest());

    // Browser end-to-end render self-test. Drives RenderPage on a canned
    // page (author CSS + heading + box + a DOM-mutating script) through
    // parse->style->script->layout->paint and asserts the painted
    // pixels + that the script mutation reached the display list.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::BrowserRenderSelfTest());

    // Browser LINK navigation self-test. Renders a canned page with a
    // root-relative + absolute <a href>, asserts the layout-tagged link
    // rects resolve to the right absolute URLs, that a hit-test inside a
    // rect maps to the link, and that the follow/focus paths target the
    // resolved URL — all network-free.
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::BrowserLinksSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::apps::browser::BrowserClickSelfTest());

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
    duetos::drivers::video::WindowSetVisible(calendar_handle, false);
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
    duetos::drivers::video::WindowSetVisible(notify_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::notify_center::NotifyCenterSelfTest());

    // SYSMON — rolling system monitor: heap-used % + free-list
    // fragmentation, sampled once per ui-ticker tick. About
    // shows a snapshot; Sysmon shows the trend.
    duetos::drivers::video::WindowChrome sysmon_chrome = theme_chrome(Role::Sysmon);
    sysmon_chrome.x = 320;
    sysmon_chrome.y = 100;
    sysmon_chrome.w = 380;
    sysmon_chrome.h = 280;
    const duetos::drivers::video::WindowHandle sysmon_handle =
        duetos::drivers::video::WindowRegister(sysmon_chrome, "SYSTEM MONITOR");
    duetos::drivers::video::ThemeRegisterWindow(Role::Sysmon, sysmon_handle);
    duetos::apps::sysmon::SysmonInit(sysmon_handle);
    duetos::drivers::video::WindowSetVisible(sysmon_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::sysmon::SysmonSelfTest());

    // HEXVIEW — read-only hex / ASCII inspector for FAT32 root
    // files. Loads up to 1 MiB per file; J/K scrolls one row,
    // PageUp/Down by one screen, N/P cycles files. Wider than
    // most app windows because the canonical hex layout is
    // ~616 px (8 + 16*3 + 16 char cells).
    duetos::drivers::video::WindowChrome hex_chrome = theme_chrome(Role::HexView);
    hex_chrome.x = 80;
    hex_chrome.y = 80;
    hex_chrome.w = 640;
    hex_chrome.h = 360;
    const duetos::drivers::video::WindowHandle hex_handle =
        duetos::drivers::video::WindowRegister(hex_chrome, "HEX VIEWER");
    duetos::drivers::video::ThemeRegisterWindow(Role::HexView, hex_handle);
    duetos::apps::hexview::HexViewInit(hex_handle);
    duetos::drivers::video::WindowSetVisible(hex_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::hexview::HexViewSelfTest());

    // CHARMAP — codepoint grid; Enter copies selected glyph as
    // UTF-8 to the clipboard so it pastes into Notes / Calculator
    // / Browser via the standard Ctrl+V path.
    duetos::drivers::video::WindowChrome charmap_chrome = theme_chrome(Role::CharMap);
    charmap_chrome.x = 240;
    charmap_chrome.y = 90;
    charmap_chrome.w = 400;
    charmap_chrome.h = 320;
    const duetos::drivers::video::WindowHandle charmap_handle =
        duetos::drivers::video::WindowRegister(charmap_chrome, "CHARACTER MAP");
    duetos::drivers::video::ThemeRegisterWindow(Role::CharMap, charmap_handle);
    duetos::apps::charmap::CharMapInit(charmap_handle);
    duetos::drivers::video::WindowSetVisible(charmap_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::charmap::CharMapSelfTest());

    // TERMINAL — windowed VT/ANSI host (slice 1 of the ToaruOS
    // clean-room port). Wide window to fit ~80 cells of an 8 px
    // bitmap glyph plus padding; tall enough for ~24 rows of the
    // 10 px terminal cell. See wiki/advanced/Toaru-Port-Plan.md.
    duetos::drivers::video::WindowChrome term_chrome = theme_chrome(Role::Terminal);
    term_chrome.x = 120;
    term_chrome.y = 70;
    term_chrome.w = 680;
    term_chrome.h = 280;
    const duetos::drivers::video::WindowHandle term_handle =
        duetos::drivers::video::WindowRegister(term_chrome, "TERMINAL");
    duetos::drivers::video::ThemeRegisterWindow(Role::Terminal, term_handle);
    duetos::apps::terminal::TerminalInit(term_handle);
    duetos::drivers::video::WindowSetVisible(term_handle, false);
    DUETOS_BOOT_SELFTEST(duetos::apps::terminal::TerminalSelfTest());

    // Slice 3a: hide the framebuffer console region now that the
    // windowed Terminal is mirroring the same shell content. The
    // console keeps buffering writes (the Terminal's mirror still
    // fires); only the 80x40 paint region is reclaimed for the
    // desktop. Ctrl+Alt+C toggles it visible again on demand.
    duetos::drivers::video::ConsoleSetPaintEnabled(false);

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

    // DEVICE MANAGER — read-only PCI device list. Handle captured for the
    // desktop-icon registration below (Device Manager has no ThemeRole, so
    // its icon binds to the window handle directly).
    duetos::drivers::video::WindowHandle devicemgr_win = duetos::drivers::video::kWindowInvalid;
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
        devicemgr_win = h;
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
        DUETOS_BOOT_SELFTEST(duetos::apps::firewall::FirewallSelfTest());
    }

    // DESKTOP ICONS — surface the canonical destinations on the bare
    // desktop (double-click to launch), the way every other OS does.
    // Targets are window handles: themed apps resolve via ThemeRoleWindow,
    // Device Manager uses the handle captured above. "Computer" and "Trash"
    // both open the Files manager — it shows drives in its disk view, which
    // is also where deleted items live (/TRASH); a standalone trash window
    // is a follow-up.
    {
        using duetos::drivers::video::DesktopIconRegister;
        using duetos::drivers::video::IconGlyph;
        using duetos::drivers::video::ThemeRoleWindow;
        DesktopIconRegister("Computer", IconGlyph::Computer, ThemeRoleWindow(Role::Files));
        DesktopIconRegister("Browser", IconGlyph::Browser, ThemeRoleWindow(Role::Browser));
        DesktopIconRegister("Terminal", IconGlyph::Terminal, ThemeRoleWindow(Role::Terminal));
        DesktopIconRegister("Calculator", IconGlyph::Calculator, ThemeRoleWindow(Role::Calculator));
        DesktopIconRegister("Notepad", IconGlyph::Notepad, ThemeRoleWindow(Role::Notes));
        DesktopIconRegister("Settings", IconGlyph::Settings, ThemeRoleWindow(Role::Settings));
        DesktopIconRegister("Device Mgr", IconGlyph::DeviceMgr, devicemgr_win);
        DesktopIconRegister("Trash", IconGlyph::Trash, ThemeRoleWindow(Role::Files));
        DesktopIconRegister("Help", IconGlyph::Help, ThemeRoleWindow(Role::Help));
        DUETOS_BOOT_SELFTEST(duetos::drivers::video::DesktopIconsSelfTest());
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
    duetos::drivers::video::SplashAdvancePhase("compositor up");

    // Early-boot file sink: tee every Info+ log line into
    // /tmp/boot.log on tmpfs. Receives one fully-formed line per
    // call — the per-area FAT32 router will replace this sink later
    // (KlogPersistInstall) once a real FS is mounted; until then,
    // every line lands in the single boot.log so post-boot inspection
    // has the early bring-up record. tmpfs caps files at 512 bytes —
    // once that fills, further appends silently truncate, so the
    // file captures the earliest boot-critical Info+ lines.
    duetos::core::SetLogLineSink([](duetos::core::LogLevel, duetos::core::LogArea, const char* line, duetos::u32 len)
                                 { duetos::fs::TmpFsAppend("boot.log", line, len); });
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
    DUETOS_BOOT_SELFTEST(duetos::core::AuthSnapshotSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::core::AuthLazyMigrationSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::AuthBruteForceProbe());

    // Role-based access control: seed the built-in role table and
    // bind the default memberships. Must precede the broker self-
    // test below (which uses the seeded role policy to authorise
    // the synthetic FsWrite elevation). The grace cache likewise
    // needs an explicit Init before broker calls. Order:
    //   RbacInit -> GraceCacheInit -> BrokerSelfTest -> RbacSelfTest -> GraceCacheSelfTest
    // (See wiki/security/RBAC-and-Elevation.md for the design.)
    DUETOS_BOOT_SELFTEST(duetos::security::Blake2bSelfTest());

    DUETOS_BOOT_SELFTEST(duetos::security::Argon2idSelfTest());

    DUETOS_BOOT_SELFTEST(duetos::security::ChaCha20Poly1305SelfTest());

    DUETOS_BOOT_SELFTEST(duetos::security::PersistenceSelfTest());

    DUETOS_BOOT_SELFTEST(duetos::security::PasswordHashV2SelfTest());

    duetos::security::RbacInit();
    duetos::security::GraceCacheInit();
    DUETOS_BOOT_SELFTEST(duetos::security::RbacSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::RbacSnapshotSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::GraceCacheSelfTest());
    DUETOS_BOOT_SELFTEST(duetos::security::BrokerSelfTest());
    duetos::drivers::video::SplashAdvancePhase("auth ready");

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
    // panic_wait=gdb cmdline arms the panic-wait gate so a
    // panic later in boot stops for GDB attach instead of
    // halting. Cheap latch — bool write. Done here (right
    // after the cmdline is logged) so anything in BootBringup*
    // that can panic benefits from it.
    duetos::diag::PanicWaitInitFromCmdline(cmdline);
    // Pick up the A/B boot-slot hand-off from the bootloader. `slot=a`
    // or `slot=b` overrides the default; absence is treated as
    // slot=a (the boot_slot::Default fallback). Once SetCurrentState
    // runs, the running kernel's `CurrentState()` reflects which slot
    // it's executing from, which lets the future watchdog +
    // installer + shell `slotinfo` all answer "which slot am I?"
    // without re-deriving it.
    if (CmdlineMatches(cmdline, "slot", "b"))
    {
        auto st = duetos::fs::boot_slot::CurrentState();
        st.active = duetos::fs::boot_slot::Slot::kB;
        duetos::fs::boot_slot::SetCurrentState(st);
        SerialWrite("[boot] boot-slot active=b (from cmdline)\n");
    }
    else if (CmdlineMatches(cmdline, "slot", "a"))
    {
        auto st = duetos::fs::boot_slot::CurrentState();
        st.active = duetos::fs::boot_slot::Slot::kA;
        duetos::fs::boot_slot::SetCurrentState(st);
        SerialWrite("[boot] boot-slot active=a (from cmdline)\n");
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

    // demo-browser=1 renders the built-in welcome page and shows the
    // Browser window at boot so a headless screenshot can capture the
    // rendered web engine without injecting a Start-menu click. No
    // effect on normal boots.
    const bool demo_browser = CmdlineMatches(cmdline, "demo-browser", "1");

    if (want_tty)
    {
        duetos::drivers::video::SetDisplayMode(duetos::drivers::video::DisplayMode::Tty);
        duetos::drivers::video::ConsoleSetOrigin(16, 16);
        duetos::drivers::video::ConsoleSetColours(theme0.console_fg, 0x00000000);
        duetos::drivers::video::DesktopCompose(0x00000000, nullptr);
    }
    else
    {
        duetos::drivers::video::DesktopCompose(theme0.desktop_bg, nullptr);
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
            duetos::drivers::video::DesktopCompose(theme0.desktop_bg, nullptr);
        }
        if (demo_browser)
        {
            duetos::apps::browser::BrowserOpenDemo();
            duetos::drivers::video::DesktopCompose(theme0.desktop_bg, nullptr);
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

    // Portable native ELF demo apps. Both compiled by the new
    // `duetos_native_app()` CMake helper (see kernel/CMakeLists.txt)
    // and embedded into ramfs the same way usershell.elf is.
    // hello_native is a "did the pipeline survive?" smoke; nat_calc
    // exercises the userland libc's printf-family + a recursive-
    // descent expression evaluator. Same trusted-cap set + frame
    // budget as the shell.
    {
        const auto pid = duetos::core::SpawnElfFile("/bin/hello_native", duetos::fs::RamfsHelloNativeBytes(),
                                                    duetos::fs::RamfsHelloNativeSize(), duetos::core::CapSetTrusted(),
                                                    duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                                    duetos::core::kTickBudgetTrusted);
        SerialWrite("[boot] hello_native pid=");
        SerialWriteHex(pid);
        SerialWrite("\n");
    }
    {
        const auto pid =
            duetos::core::SpawnElfFile("/bin/nat_calc", duetos::fs::RamfsNatCalcBytes(), duetos::fs::RamfsNatCalcSize(),
                                       duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                       duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
        SerialWrite("[boot] nat_calc pid=");
        SerialWriteHex(pid);
        SerialWrite("\n");
    }
    {
        const auto pid = duetos::core::SpawnElfFile("/bin/nat_sysinfo", duetos::fs::RamfsNatSysinfoBytes(),
                                                    duetos::fs::RamfsNatSysinfoSize(), duetos::core::CapSetTrusted(),
                                                    duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                                    duetos::core::kTickBudgetTrusted);
        SerialWrite("[boot] nat_sysinfo pid=");
        SerialWriteHex(pid);
        SerialWrite("\n");
    }
    // peexec=<FATPATH> kernel cmdline: load a Windows PE/.exe off
    // FAT32 vol 0 and spawn it as a Win32 process at boot. This is the
    // automated entry point for running EXTERNAL .exe files staged onto
    // the disk image (tools/test/run-exe.sh stages the exe + sets this
    // cmdline) — it avoids having to drive the interactive shell, so a
    // test harness can boot-run an arbitrary exe and grep the serial.
    // Twin of the PEEXEC shell command. SpawnPeFile validates the image
    // and resolves imports against the preloaded Win32 DLL set; failures
    // surface on the [pe-load] / [dll-load] lines.
    if (cmdline != nullptr)
    {
        namespace fat = duetos::fs::fat32;
        const char* kkey = "peexec=";
        const char* hit = nullptr;
        for (const char* p = cmdline; *p != '\0'; ++p)
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
        if (hit != nullptr)
        {
            duetos::u32 n = 0;
            while (hit[n] != '\0' && hit[n] != ' ' && n < sizeof(g_peexec_path) - 1)
            {
                g_peexec_path[n] = hit[n];
                ++n;
            }
            g_peexec_path[n] = '\0';
            SerialWrite("[peexec] boot-run path=");
            SerialWrite(g_peexec_path);
            SerialWrite(" (deferred — waiting for async storage)\n");
            // MUST NOT block here: storage (nvme/ahci) only enumerates
            // AFTER this bringup returns, so polling for FAT on this
            // thread would stall the boot (and never see a disk). Hand
            // off to a dedicated thread that polls + spawns concurrently.
            (void)duetos::sched::SchedCreate(PeexecDeferredTask, nullptr, "peexec-deferred");
        }
    }

    // /bin/duet-pkg — on-target package manager scaffold. Spawning
    // it at boot with no argv runs its built-in selftest, so the
    // boot log carries the `[duet-pkg-selftest] PASS` sentinel on
    // every healthy boot. Once full subcommand support lands, the
    // boot spawn can drop the selftest and gate the binary behind
    // an explicit shell invocation.
    {
        const auto pid =
            duetos::core::SpawnElfFile("/bin/duet-pkg", duetos::fs::RamfsDuetPkgBytes(), duetos::fs::RamfsDuetPkgSize(),
                                       duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                       duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
        SerialWrite("[boot] duet-pkg pid=");
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
        if (mode == duetos::core::LoginMode::Gui)
        {
            // Splash ticker has done its job; clear it before the login
            // gate paints its own surface. TTY path skips this — splash
            // never started in TTY mode (SplashInit no-ops when FB is
            // unavailable) so Dismiss is a no-op there too, but we
            // avoid the call for clarity.
            duetos::drivers::video::SplashAdvancePhase("login starting");
            duetos::drivers::video::SplashDismiss();
        }
        duetos::core::LoginStart(mode);
    }
    else
    {
        SerialWrite("[boot] autologin=1 — skipping login gate\n");
    }
}
} // namespace duetos::core
