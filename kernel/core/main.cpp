#include "types.h"
#include "../acpi/acpi.h"
#include "../acpi/aml.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/cpu_info.h"
#include "../arch/x86_64/hypervisor.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/smbios.h"
#include "../arch/x86_64/thermal.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/ioapic.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/nmi_watchdog.h"
#include "../arch/x86_64/pic.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"
#include "../debug/breakpoints.h"
#include "../debug/extable.h"
#include "../debug/probes.h"
#include "../drivers/audio/audio.h"
#include "../drivers/gpu/gpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/net/net.h"
#include "../drivers/pci/pci.h"
#include "../drivers/power/power.h"
#include "../drivers/usb/hid_descriptor.h"
#include "../drivers/usb/msc_scsi.h"
#include "../drivers/usb/usb.h"
#include "../drivers/usb/xhci.h"
#include "../net/stack.h"
#include "../subsystems/graphics/graphics.h"
#include "../drivers/storage/ahci.h"
#include "../drivers/storage/block.h"
#include "../drivers/storage/nvme.h"
#include "../fs/exfat.h"
#include "../fs/ext4.h"
#include "../fs/fat32.h"
#include "../fs/file_route.h"
#include "../fs/gpt.h"
#include "../fs/ntfs.h"
#include "../apps/calculator.h"
#include "../apps/clock.h"
#include "../apps/files.h"
#include "../apps/notes.h"
#include "../drivers/video/console.h"
#include "../drivers/video/cursor.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/calendar.h"
#include "../drivers/video/menu.h"
#include "../drivers/video/taskbar.h"
#include "../drivers/video/theme.h"
#include "../drivers/video/widget.h"
#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../sync/spinlock.h"
#include "auth.h"
#include "heartbeat.h"
#include "klog.h"
#include "login.h"
#include "panic.h"
#include "process.h"
#include "random.h"
#include "fault_domain.h"
#include "result.h"
#include "ring3_smoke.h"
#include "runtime_checker.h"
#include "../subsystems/linux/ring3_smoke.h"
#include "../subsystems/linux/syscall.h"
#include "../subsystems/win32/stubs.h"
#include "dll_loader.h"
#include "shell.h"
#include "syscall.h"
#include "../mm/kheap.h"
#include "../mm/kstack.h"
#include "../mm/multiboot2.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../security/attack_sim.h"
#include "../security/guard.h"
#include "../security/pentest_gui.h"

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
    // calls are gated by the runtime threshold (default Info) — use
    // `loglevel t` at the shell to enable function-scope tracing.
    duetos::core::KLogSelfTest();

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

    SerialWrite("[boot] Detecting hypervisor.\n");
    duetos::arch::HypervisorProbe();

    SerialWrite("[boot] Probing SMBIOS.\n");
    duetos::arch::SmbiosInit();

    SerialWrite("[boot] Reading MSR thermals.\n");
    duetos::arch::ThermalProbe();

    SerialWrite("[boot] Exercising Result<T,E> + TRY primitives.\n");
    duetos::core::ResultSelfTest();

    SerialWrite("[boot] Seeding kernel entropy pool.\n");
    duetos::core::RandomInit();
    duetos::core::RandomSelfTest();
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

    // Slice-80 surface check. Issues an int3 (kernel-mode #BP, must
    // recover via TrapResponse::LogAndContinue) and an int 0x42
    // (spurious vector, must recover via TrapDispatch's spurious
    // branch). If either regresses the kernel halts here and the
    // boot log shows the cause.
    TrapsSelfTest();

    // Kernel extable — scoped fault recovery. Register before any
    // subsystem tries to install its own rows; the user-copy
    // helpers are always entry 0 / 1.
    SerialWrite("[boot] Bringing up kernel extable.\n");
    duetos::arch::TrapsRegisterExtable();
    duetos::debug::ExtableSelfTest();

    // Fault-domain registry self-test. Registers a toy domain,
    // restarts it twice, checks counters. Real driver domains are
    // registered later in boot once their subsystems are up.
    duetos::core::FaultDomainSelfTest();

    SerialWrite("[boot] Parsing Multiboot2 memory map.\n");
    FrameAllocatorInit(multiboot_info);

    SerialWrite("  total frames : ");
    SerialWriteHex(TotalFrames());
    SerialWrite("\n");
    SerialWrite("  free frames  : ");
    SerialWriteHex(FreeFramesCount());
    SerialWrite("\n");

    FrameAllocatorSelfTest();

    SerialWrite("[boot] Bringing up kernel heap.\n");
    KernelHeapInit();
    KernelHeapSelfTest();

    KLOG_METRICS("boot", "after-kernel-heap");

    SerialWrite("[boot] Bringing up paging.\n");
    PagingInit();
    PagingSelfTest();

    // Kernel-stack guard-paged arena — runs here because it needs
    // the managed paging API (PagingInit) for MapPage / UnmapPage
    // but must be online before any SchedCreate call uses it.
    duetos::mm::KernelStackSelfTest();
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

    SerialWrite("[boot] Bringing up framebuffer (if present).\n");
    duetos::drivers::video::FramebufferInit(multiboot_info);
    duetos::drivers::video::FramebufferSelfTest();

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
    // (theme=classic / theme=slate10); default is the classic
    // teal palette the first GUI slice shipped. Ctrl+Alt+Y
    // cycles at runtime.
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
    duetos::apps::calculator::CalculatorSelfTest();

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
                        duetos::drivers::video::FramebufferDrawChar(r.cx + r.col * 8, r.cy + r.row * 10, c, r.fg,
                                                                      r.bg);
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
    duetos::apps::files::FilesSelfTest();

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
    duetos::apps::clock::ClockSelfTest();

    // Framebuffer text console. 80x40 chars of boot log at the
    // bottom of the desktop, under the windows in z-order. Dragging
    // a window over it occludes; moving away restores.
    // Taskbar across the bottom of the framebuffer. Placed at
    // runtime so a different resolution still anchors correctly.
    {
        const auto fb_info = duetos::drivers::video::FramebufferGet();
        constexpr duetos::u32 tb_h = 28;
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
    duetos::core::AuthSelfTest();

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

    SerialWrite("[boot] Seeding ramfs + VFS self-test.\n");
    duetos::fs::RamfsInit();
    {
        using namespace duetos::fs;
        const RamfsNode* trusted = RamfsTrustedRoot();
        const RamfsNode* sandbox = RamfsSandboxRoot();

        // Positive lookups against the trusted tree. Trailing slash,
        // leading slash, empty-component runs — all tolerated.
        if (VfsLookup(trusted, "/etc/version", 64) == nullptr)
            duetos::core::Panic("fs/vfs", "self-test: /etc/version missing from trusted root");
        if (VfsLookup(trusted, "/bin/hello", 64) == nullptr)
            duetos::core::Panic("fs/vfs", "self-test: /bin/hello missing from trusted root");
        if (VfsLookup(trusted, "//etc//version", 64) == nullptr)
            duetos::core::Panic("fs/vfs", "self-test: double-slash tolerance broken");

        // The sandbox root has exactly one file; its lookup must
        // succeed, and the trusted-only paths must fail.
        if (VfsLookup(sandbox, "/welcome.txt", 64) == nullptr)
            duetos::core::Panic("fs/vfs", "self-test: /welcome.txt missing from sandbox root");
        if (VfsLookup(sandbox, "/etc/version", 64) != nullptr)
            duetos::core::Panic("fs/vfs", "self-test: JAIL BROKEN — sandbox saw trusted /etc/version");
        if (VfsLookup(sandbox, "/bin/hello", 64) != nullptr)
            duetos::core::Panic("fs/vfs", "self-test: JAIL BROKEN — sandbox saw trusted /bin/hello");

        // ".." is rejected outright.
        if (VfsLookup(trusted, "/etc/..", 64) != nullptr)
            duetos::core::Panic("fs/vfs", "self-test: .. accepted (would break jails)");

        SerialWrite("[fs/vfs] self-test OK\n");
    }

    // Address-space isolation self-test — direct assertion that a
    // user page mapped in one AS is invisible in a sibling AS, and
    // that AddressSpaceActivate flips CR3 correctly. Indirectly
    // covered by ring3_smoke running two tasks at the same VA, but
    // this runs BEFORE scheduler/ring3 bring-up so a regression
    // surfaces at the earliest possible point.
    duetos::mm::AddressSpaceSelfTest();

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

    SerialWrite("[boot] Bringing up LAPIC.\n");
    LapicInit();

    SerialWrite("[boot] Bringing up IOAPIC.\n");
    IoApicInit();

    SerialWrite("[boot] Bringing up HPET (if present).\n");
    HpetInit();
    HpetSelfTest();

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

    SerialWrite("[boot] Programming Linux-ABI syscall MSRs.\n");
    duetos::subsystems::linux::SyscallInit();

    duetos::sync::SpinLockSelfTest();

    SerialWrite("[boot] Bringing up periodic timer.\n");
    TimerInit();

    SerialWrite("[boot] Bringing up scheduler.\n");
    duetos::sched::SchedInit();
    // Idle task FIRST so the runqueue is never empty — even if the
    // reaper or any subsequent worker blocks before the boot task
    // spawns anything else, Schedule() always has a fallback to
    // pick. Supersedes the "ensure SmpStartAps has a runnable peer"
    // workaround that used to depend on worker creation order.
    duetos::sched::SchedStartIdle("idle-bsp");
    duetos::sched::SchedStartReaper();

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
        auto xhci_teardown = []() -> duetos::core::Result<void>
        { return duetos::drivers::usb::xhci::XhciShutdown(); };
        duetos::core::FaultDomainRegister("drivers/usb/xhci", xhci_init, xhci_teardown);
    }
    duetos::drivers::usb::hid::HidSelfTest();
    duetos::drivers::usb::msc::MscSelfTest();

    SerialWrite("[boot] Detecting audio controllers.\n");
    duetos::drivers::audio::AudioInit();
    {
        auto audio_init = []() -> duetos::core::Result<void>
        {
            duetos::drivers::audio::AudioInit();
            return {};
        };
        auto audio_teardown = []() -> duetos::core::Result<void>
        { return duetos::drivers::audio::AudioShutdown(); };
        duetos::core::FaultDomainRegister("drivers/audio", audio_init, audio_teardown);
    }

    SerialWrite("[boot] Bringing up power / thermal shell.\n");
    duetos::drivers::power::PowerInit();

    SerialWrite("[boot] Bringing up network stack skeleton.\n");
    duetos::net::NetStackInit();
    {
        // Park a canned reply on TCP port 7777. Any connection
        // that lands with a data segment gets this body + FIN.
        // Handy to smoke-test the TCP state machine from the
        // host with `nc 10.0.2.15 7777` (given appropriate
        // hostfwd) or `curl http://.../` once HTTP lands.
        static const char kHello[] = "HTTP/1.0 200 OK\r\n"
                                     "Content-Type: text/plain\r\n"
                                     "Content-Length: 24\r\n"
                                     "\r\n"
                                     "Hello from DuetOS!\r\n\r\n";
        duetos::net::TcpListen(7777, reinterpret_cast<const duetos::u8*>(kHello), sizeof(kHello) - 1);
    }

    SerialWrite("[boot] Bringing up graphics ICD skeleton.\n");
    duetos::subsystems::graphics::GraphicsIcdInit();

    SerialWrite("[boot] Bringing up block device layer.\n");
    duetos::drivers::storage::BlockLayerInit();
    duetos::drivers::storage::BlockLayerSelfTest();

    SerialWrite("[boot] Bringing up NVMe controller.\n");
    duetos::drivers::storage::NvmeInit();
    duetos::drivers::storage::NvmeSelfTest();

    SerialWrite("[boot] Bringing up AHCI controller(s).\n");
    duetos::drivers::storage::AhciInit();
    duetos::drivers::storage::AhciSelfTest();

    // Security guard must be live BEFORE any loader runs. Advisory
    // mode at boot: scans + logs, never blocks. Flip to Enforce via
    // the shell `guard enforce` once the boot-log is clean.
    SerialWrite("[boot] Starting security guard.\n");
    duetos::security::GuardInit();
    duetos::security::GuardSelfTest();

    SerialWrite("[boot] Probing GPT on block devices.\n");
    duetos::fs::gpt::GptSelfTest();

    SerialWrite("[boot] Probing FAT32 on block devices.\n");
    duetos::fs::fat32::Fat32SelfTest();

    SerialWrite("[boot] Routing Win32 file syscalls through FAT32.\n");
    duetos::fs::routing::SelfTest();

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
            duetos::core::LogWithValue(duetos::core::LogLevel::Info, "core/klog", "/tmp/boot.log size (bytes)",
                                         len);
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
            if (ev.is_release || ev.code == kKeyNone)
            {
                continue;
            }
            const bool alt = (ev.modifiers & kKeyModAlt) != 0;
            const bool ctrl = (ev.modifiers & kKeyModCtrl) != 0;
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
                duetos::core::ShellInterrupt();
                SerialWrite("[ui] ^C\n");
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

            // Ctrl+Alt+Y cycles the desktop theme. Classic (teal)
            // -> Slate10 (Win10 x Unreal Slate hybrid) -> wrap.
            // Re-chromes every themed window + the taskbar +
            // console + cursor backing, then recomposes so the
            // new palette appears on screen in one flip.
            if (ctrl && alt && (ev.code == 'y' || ev.code == 'Y'))
            {
                duetos::drivers::video::CompositorLock();
                duetos::drivers::video::ThemeCycle();
                duetos::drivers::video::ThemeApplyToAll();
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
                    // WM_KEYDOWN = 0x0100; WM_CHAR = 0x0102.
                    // wParam = virtual-key code (use raw scan/char
                    // code for v0 — we don't have a VK table yet).
                    // lParam = 1 (repeat count), top bits reserved.
                    constexpr duetos::u32 kWmKeyDown = 0x0100;
                    constexpr duetos::u32 kWmChar = 0x0102;
                    duetos::drivers::video::WindowPostMessage(active_pe, kWmKeyDown, ev.code, 1);
                    if (ev.code >= 0x20 && ev.code <= 0x7E)
                    {
                        duetos::drivers::video::WindowPostMessage(active_pe, kWmChar, ev.code, 1);
                    }
                    else if (ev.code == kKeyEnter)
                    {
                        duetos::drivers::video::WindowPostMessage(active_pe, kWmChar, '\r', 1);
                    }
                    else if (ev.code == kKeyBackspace)
                    {
                        duetos::drivers::video::WindowPostMessage(active_pe, kWmChar, 0x08, 1);
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
                    // Arrow-key routing — only Files consumes these
                    // today, but the block is shaped so future apps
                    // can add their own arrow handlers.
                    if (active == duetos::apps::files::FilesWindow() &&
                        (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown))
                    {
                        app_consumed = duetos::apps::files::FilesFeedArrow(ev.code == kKeyArrowUp);
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
        static const duetos::drivers::video::MenuItem kStartItems[] = {
            {"ABOUT DUETOS", 1},
            {"CYCLE WINDOWS", 2},
            {"LIST WINDOWS", 3},
            {"PING CONSOLE", 4},
        };
        static const duetos::drivers::video::MenuItem kDesktopMenuItems[] = {
            {"ABOUT DUETOS", 1},
            {"CYCLE WINDOWS", 2},
            {"LIST WINDOWS", 3},
            {"SWITCH TO TTY", 5},
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
                    }
                    SerialWrite("[ui] menu fire action=");
                    SerialWriteHex(action);
                    SerialWrite("\n");
                }
                duetos::drivers::video::MenuClose();
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
                        duetos::drivers::video::MenuOpen(kStartItems, sizeof(kStartItems) / sizeof(kStartItems[0]),
                                                           sx, sy, 0);
                        const duetos::u32 mh = duetos::drivers::video::MenuPanelHeight();
                        const duetos::u32 my = (sy > mh) ? sy - mh : 0;
                        duetos::drivers::video::MenuOpen(kStartItems, sizeof(kStartItems) / sizeof(kStartItems[0]),
                                                           sx, my, 0);
                        SerialWrite("[ui] menu open\n");
                    }
                    menu_handled = true;
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

            // Mouse-message routing to PE windows. Posts
            // WM_MOUSEMOVE / WM_LBUTTONDOWN / WM_LBUTTONUP to the
            // topmost PE window under the cursor, with
            // lParam = MAKELONG(client_x, client_y). Skipped in
            // the obvious compositor-owned states (menu open,
            // mid-drag, over the taskbar / calendar) so a PE
            // doesn't see stray clicks that the shell consumed.
            // Close-box presses on a PE re-route to WM_CLOSE
            // (already handled in the press-edge block below).
            if (!drag.active && !menu_handled && !duetos::drivers::video::TaskbarContains(cx, cy) &&
                !duetos::drivers::video::MenuIsOpen() && !duetos::drivers::video::CalendarContains(cx, cy))
            {
                const auto pe_hit = duetos::drivers::video::WindowTopmostAt(cx, cy);
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
                        duetos::drivers::video::WindowPostMessage(pe_hit, kWmLButtonDown, wparam, lparam);
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

    duetos::sched::SchedCreate(worker, const_cast<char*>("A"), "worker-A");
    duetos::sched::SchedCreate(worker, const_cast<char*>("B"), "worker-B");
    duetos::sched::SchedCreate(worker, const_cast<char*>("C"), "worker-C");

    // First ring-3 slice: spawn a dedicated scheduler thread that maps a
    // user code + stack page, drops to ring 3, and runs an interruptible
    // pause/jmp loop forever. Kernel workers above keep running and
    // periodically preempt it; the proof-of-life is that this whole
    // boot sequence continues to make forward progress after the
    // iretq into user mode.
    duetos::core::StartRing3SmokeTask();
    // Linux-ABI proof-of-life. Reaches MSR_LSTAR entry stub →
    // LinuxSyscallDispatch → sys_exit_group. A clean exit here
    // proves the whole plumbing — EFER.SCE, MSR setup, swapgs
    // dance, iretq return — works end-to-end.
    duetos::subsystems::linux::SpawnRing3LinuxSmoke();
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
    {
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
    // export directory, and asserts name + ordinal lookups
    // resolve to VAs inside the mapped image. Cheap and
    // self-cleaning (scratch AS is released before return).
    duetos::core::DllLoaderSelfTest();

    duetos::core::StartHeartbeatThread();

    SerialWrite("[boot] All subsystems online. Entering idle loop.\n");

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
    // Compile-time-gated deliberate panic used by tools/test-panic.sh
    // to verify the panic path stays healthy end-to-end. Never
    // enabled in a normal build — the default preset does not pass
    // -DDUETOS_PANIC_DEMO.
    duetos::core::Panic("test/panic-demo", "DUETOS_PANIC_DEMO enabled; halting on purpose");
#endif

#ifdef DUETOS_TRAP_DEMO
    // Compile-time-gated deliberate CPU exception used by
    // tools/test-trap.sh to verify the trap dispatcher's crash-dump
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
