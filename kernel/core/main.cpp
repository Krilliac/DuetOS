#include "types.h"
#include "../acpi/acpi.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/ioapic.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/pic.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/timer.h"
#include "../cpu/percpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/pci/pci.h"
#include "../drivers/storage/ahci.h"
#include "../drivers/storage/block.h"
#include "../drivers/storage/nvme.h"
#include "../fs/fat32.h"
#include "../fs/gpt.h"
#include "../apps/calculator.h"
#include "../apps/clock.h"
#include "../apps/files.h"
#include "../apps/notes.h"
#include "../drivers/video/console.h"
#include "../drivers/video/cursor.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/menu.h"
#include "../drivers/video/taskbar.h"
#include "../drivers/video/widget.h"
#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../sync/spinlock.h"
#include "heartbeat.h"
#include "klog.h"
#include "panic.h"
#include "ring3_smoke.h"
#include "../subsystems/linux/ring3_smoke.h"
#include "../subsystems/linux/syscall.h"
#include "shell.h"
#include "syscall.h"
#include "../mm/kheap.h"
#include "../mm/multiboot2.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../security/guard.h"

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

#ifdef CUSTOMOS_CANARY_DEMO
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
    volatile customos::u8 buf[8] = {};
    for (int i = 0; i < 64; ++i)
    {
        buf[i] = static_cast<customos::u8>(i);
    }
    asm volatile("" : : "r"(&buf[0]) : "memory");
}
#endif

namespace
{

// Walk the Multiboot2 tag list for type-1 (boot cmdline) and
// return its NUL-terminated string, or nullptr if absent. The
// pointer is into the live info struct; do not free.
const char* FindBootCmdline(customos::uptr info_phys)
{
    if (info_phys == 0)
    {
        return nullptr;
    }
    const auto* info = reinterpret_cast<const customos::mm::MultibootInfoHeader*>(info_phys);
    customos::uptr cursor = info_phys + sizeof(customos::mm::MultibootInfoHeader);
    const customos::uptr end = info_phys + info->total_size;
    while (cursor < end)
    {
        const auto* tag = reinterpret_cast<const customos::mm::MultibootTagHeader*>(cursor);
        if (tag->type == customos::mm::kMultibootTagEnd)
        {
            break;
        }
        if (tag->type == customos::mm::kMultibootTagCmdline)
        {
            // String starts right after the 8-byte {type, size} header.
            return reinterpret_cast<const char*>(cursor + sizeof(customos::mm::MultibootTagHeader));
        }
        cursor += (tag->size + 7u) & ~customos::uptr{7};
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

extern "C" void kernel_main(customos::u32 multiboot_magic, customos::uptr multiboot_info)
{
    using namespace customos::arch;
    using namespace customos::mm;

    SerialInit();
    SerialWrite("[boot] CustomOS kernel reached long mode.\n");

    // klog online as early as Serial. Self-test prints one line at
    // each severity so visual inspection of the early boot log
    // confirms the tag format + u64-value form are working. Trace
    // calls are gated by the runtime threshold (default Info) — use
    // `loglevel t` at the shell to enable function-scope tracing.
    customos::core::KLogSelfTest();

    constexpr customos::u32 kMultiboot2BootMagic = 0x36D76289;
    if (multiboot_magic == kMultiboot2BootMagic)
    {
        SerialWrite("[boot] Multiboot2 handoff verified.\n");
    }
    else
    {
        SerialWrite("[boot] WARNING: unexpected boot magic.\n");
    }

    SerialWrite("[boot] Installing kernel GDT.\n");
    GdtInit();

    SerialWrite("[boot] Installing IDT (vectors 0..31).\n");
    IdtInit();

    SerialWrite("[boot] Installing TSS + IST stacks (#DF / #MC / #NMI).\n");
    TssInit();
    IdtSetIst(2, kIstNmi);           // #NMI
    IdtSetIst(8, kIstDoubleFault);   // #DF
    IdtSetIst(18, kIstMachineCheck); // #MC

    SerialWrite("[boot] Installing syscall gate (int 0x80, DPL=3).\n");
    customos::core::SyscallInit();

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

    SerialWrite("[boot] Bringing up framebuffer (if present).\n");
    customos::drivers::video::FramebufferInit(multiboot_info);
    customos::drivers::video::FramebufferSelfTest();

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
    constexpr customos::u32 kDesktopTeal = 0x00204868;

    // CALCULATOR — native CustomOS app. Window chrome first,
    // then CalculatorInit registers its 16 buttons + content
    // drawer against the returned handle. Width / height are
    // sized to fit the 4x4 keypad (4 * 68 + 3 * 4 = 284 px
    // wide + 2 * 8 inset = 300; 4 * 36 + 3 * 4 + 60 top
    // inset + 4 bottom = 220).
    customos::drivers::video::WindowChrome win_a_chrome{};
    win_a_chrome.x = 60;
    win_a_chrome.y = 60;
    win_a_chrome.w = 300;
    win_a_chrome.h = 220;
    win_a_chrome.colour_border = 0x00101828;
    win_a_chrome.colour_title = 0x00205080;
    win_a_chrome.colour_client = 0x00101828;
    win_a_chrome.colour_close_btn = 0x00E04020;
    win_a_chrome.title_height = 22;
    const customos::drivers::video::WindowHandle calc_handle =
        customos::drivers::video::WindowRegister(win_a_chrome, "CALCULATOR");
    customos::apps::calculator::CalculatorInit(calc_handle);
    customos::apps::calculator::CalculatorSelfTest();

    customos::drivers::video::WindowChrome win_b_chrome{};
    win_b_chrome.x = 500;
    win_b_chrome.y = 100;
    win_b_chrome.w = 380;
    win_b_chrome.h = 200;
    win_b_chrome.colour_border = 0x00101828;
    win_b_chrome.colour_title = 0x00306838;
    win_b_chrome.colour_client = 0x00E0E0D8;
    win_b_chrome.colour_close_btn = 0x00E04020;
    win_b_chrome.title_height = 22;
    // NOTEPAD — native CustomOS notes app. The content-draw
    // callback is installed inside NotesInit; the kbd-reader
    // thread below routes keystrokes here when this window
    // is active (focus == keyboard owner).
    const customos::drivers::video::WindowHandle notes_handle =
        customos::drivers::video::WindowRegister(win_b_chrome, "NOTEPAD");
    customos::apps::notes::NotesInit(notes_handle);

    // Task Manager window — a window whose content drawer
    // prints live scheduler + memory stats. The ui-ticker's
    // 1 Hz recompose refreshes it for free.
    customos::drivers::video::WindowChrome taskman_chrome{};
    taskman_chrome.x = 180;
    taskman_chrome.y = 310;
    taskman_chrome.w = 340;
    taskman_chrome.h = 170;
    taskman_chrome.colour_border = 0x00101828;
    taskman_chrome.colour_title = 0x00803020;
    taskman_chrome.colour_client = 0x00101828;
    taskman_chrome.colour_close_btn = 0x00E04020;
    taskman_chrome.title_height = 22;
    const customos::drivers::video::WindowHandle taskman_handle =
        customos::drivers::video::WindowRegister(taskman_chrome, "TASK MANAGER");

    // Live log viewer window — renders a compact view of the
    // klog ring (the same ring `dmesg` prints). Refreshes every
    // ui-ticker beat, so kernel activity appears without the
    // user having to flip consoles.
    customos::drivers::video::WindowChrome logview_chrome{};
    logview_chrome.x = 560;
    logview_chrome.y = 310;
    logview_chrome.w = 420;
    logview_chrome.h = 180;
    logview_chrome.colour_border = 0x00101828;
    logview_chrome.colour_title = 0x00407080;
    logview_chrome.colour_client = 0x00101020;
    logview_chrome.colour_close_btn = 0x00E04020;
    logview_chrome.title_height = 22;
    const customos::drivers::video::WindowHandle logview_handle =
        customos::drivers::video::WindowRegister(logview_chrome, "KERNEL LOG");

    customos::drivers::video::WindowSetContentDraw(
        logview_handle,
        [](customos::u32 cx, customos::u32 cy, customos::u32 cw, customos::u32 ch, void*)
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
            constexpr customos::u32 kFgInfo = 0x00A0C8FF;  // muted blue-white
            constexpr customos::u32 kFgWarn = 0x00FFD860;  // amber
            constexpr customos::u32 kFgError = 0x00FF6050; // soft red
            constexpr customos::u32 kFgDebug = 0x00808080; // grey
            constexpr customos::u32 kBg = 0x00101020;
            struct Render
            {
                customos::u32 cx, cy, col, row, max_col, max_row, fg;
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
            r.done = false;
            customos::core::DumpLogRingTo(
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
                        customos::drivers::video::FramebufferDrawChar(r.cx + r.col * 8, r.cy + r.row * 10, c, r.fg,
                                                                      kBg);
                        ++r.col;
                    }
                });
        },
        nullptr);

    customos::drivers::video::WindowSetContentDraw(
        taskman_handle,
        [](customos::u32 cx, customos::u32 cy, customos::u32 /*cw*/, customos::u32 /*ch*/, void*)
        {
            using customos::drivers::video::FramebufferDrawString;
            constexpr customos::u32 kFg = 0x0080F088;
            constexpr customos::u32 kBg = 0x00101828;
            // Manual decimal formatter for u64 — kernel has no
            // printf. Fixed-width (10 digits) so the numeric
            // column doesn't jitter when values roll over.
            auto fmt_u64 = [](customos::u64 v, char* out)
            {
                char tmp[24];
                customos::u32 n = 0;
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
                customos::u32 pad = (n < 10) ? 10 - n : 0;
                customos::u32 o = 0;
                for (customos::u32 i = 0; i < pad; ++i)
                    out[o++] = ' ';
                for (customos::u32 i = 0; i < n; ++i)
                    out[o++] = tmp[n - 1 - i];
                out[o] = '\0';
            };

            const auto s = customos::sched::SchedStatsRead();
            const customos::u64 total = customos::mm::TotalFrames();
            const customos::u64 free_frames = customos::mm::FreeFramesCount();
            const customos::u64 uptime_s = customos::sched::SchedNowTicks() / 100;

            char num[24];
            char line[64];
            struct Row
            {
                const char* label;
                customos::u64 value;
            };
            const Row rows[] = {
                {"UPTIME (S)     ", uptime_s},        {"CTX SWITCHES   ", s.context_switches},
                {"TASKS LIVE     ", s.tasks_live},    {"TASKS SLEEPING ", s.tasks_sleeping},
                {"TASKS BLOCKED  ", s.tasks_blocked}, {"MEM FREE (4K)  ", free_frames},
                {"MEM TOTAL (4K) ", total},
            };
            customos::u32 y_off = cy + 4;
            for (customos::u32 i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i)
            {
                fmt_u64(rows[i].value, num);
                customos::u32 o = 0;
                for (customos::u32 j = 0; rows[i].label[j] != '\0' && o + 1 < sizeof(line); ++j)
                    line[o++] = rows[i].label[j];
                for (customos::u32 j = 0; num[j] != '\0' && o + 1 < sizeof(line); ++j)
                    line[o++] = num[j];
                line[o] = '\0';
                FramebufferDrawString(cx + 6, y_off, line, kFg, kBg);
                y_off += 10;
            }
        },
        nullptr);

    // FILES — native CustomOS file browser. Lists the ramfs
    // trusted root; Up/Down to move, Enter to descend, Backspace
    // or 'B' to go back.
    customos::drivers::video::WindowChrome files_chrome{};
    files_chrome.x = 220;
    files_chrome.y = 160;
    files_chrome.w = 400;
    files_chrome.h = 200;
    files_chrome.colour_border = 0x00101828;
    files_chrome.colour_title = 0x00606020;
    files_chrome.colour_client = 0x00101828;
    files_chrome.colour_close_btn = 0x00E04020;
    files_chrome.title_height = 22;
    const customos::drivers::video::WindowHandle files_handle =
        customos::drivers::video::WindowRegister(files_chrome, "FILES");
    customos::apps::files::FilesInit(files_handle);
    customos::apps::files::FilesSelfTest();

    // CLOCK — 7-segment-style wall clock. No input, refreshes
    // via the 1 Hz ui-ticker. Sized tight around the digit row
    // (6 digits + 2 colons + gaps) with room for a date line.
    customos::drivers::video::WindowChrome clock_chrome{};
    clock_chrome.x = 640;
    clock_chrome.y = 520;
    clock_chrome.w = 240;
    clock_chrome.h = 110;
    clock_chrome.colour_border = 0x00101828;
    clock_chrome.colour_title = 0x00203040;
    clock_chrome.colour_client = 0x00081008;
    clock_chrome.colour_close_btn = 0x00E04020;
    clock_chrome.title_height = 22;
    const customos::drivers::video::WindowHandle clock_handle =
        customos::drivers::video::WindowRegister(clock_chrome, "CLOCK");
    customos::apps::clock::ClockInit(clock_handle);
    customos::apps::clock::ClockSelfTest();

    // Framebuffer text console. 80x40 chars of boot log at the
    // bottom of the desktop, under the windows in z-order. Dragging
    // a window over it occludes; moving away restores.
    // Taskbar across the bottom of the framebuffer. Placed at
    // runtime so a different resolution still anchors correctly.
    {
        const auto fb_info = customos::drivers::video::FramebufferGet();
        constexpr customos::u32 tb_h = 28;
        const customos::u32 tb_y = (fb_info.height > tb_h) ? fb_info.height - tb_h : 0;
        customos::drivers::video::TaskbarInit(tb_y, tb_h, 0x00202838, 0x00FFFFFF, 0x00406090);
    }

    // Menu action ids. Ambient MenuContext() carries a target
    // (window handle) for context-menu items that need one.
    //   1..9   — desktop / global actions (ignore context)
    //   10     — raise window (context = WindowHandle)
    //   11     — close window (context = WindowHandle)
    // Range scheme keeps the dispatcher's switch table readable
    // and leaves room for future desktop / window actions without
    // reshuffling ids.

    customos::drivers::video::ConsoleInit(16, 400, 0x0080F088, 0x00181028);

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
    customos::core::SetLogTee([](const char* s) { customos::drivers::video::ConsoleWriteKlog(s); });

    // File sink: tee every Info+ log line into /tmp/boot.log on tmpfs.
    // Accumulates chunks until a newline arrives, then appends the
    // whole line. tmpfs caps files at 512 bytes — once that fills,
    // further appends silently truncate, so the file captures the
    // earliest boot-critical Info+ lines. Once a real FS lands, swap
    // the sink for an on-disk writer and remove the cap.
    customos::core::SetLogFileSink(
        [](const char* s)
        {
            static char line[256];
            static customos::u32 len = 0;
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
                    customos::fs::TmpFsAppend("boot.log", line, len);
                    len = 0;
                }
                ++s;
            }
        });
    customos::drivers::video::ConsoleWriteln("CUSTOMOS BOOT LOG");
    customos::drivers::video::ConsoleWriteln("=================");
    customos::drivers::video::ConsoleWriteln("");
    customos::drivers::video::ConsoleWriteln("LONG-MODE KERNEL        OK");
    customos::drivers::video::ConsoleWriteln("GDT IDT TSS IST         OK");
    customos::drivers::video::ConsoleWriteln("PAGING W^X SMEP SMAP    OK");
    customos::drivers::video::ConsoleWriteln("FRAME ALLOCATOR / HEAP  OK");
    customos::drivers::video::ConsoleWriteln("ACPI MADT FADT MCFG     OK");
    customos::drivers::video::ConsoleWriteln("LAPIC IOAPIC HPET       OK");
    customos::drivers::video::ConsoleWriteln("SCHEDULER + BLOCKING    OK");
    customos::drivers::video::ConsoleWriteln("PS/2 KEYBOARD           OK");
    customos::drivers::video::ConsoleWriteln("PS/2 MOUSE              OK");
    customos::drivers::video::ConsoleWriteln("PCI ENUMERATION         OK");
    customos::drivers::video::ConsoleWriteln("FRAMEBUFFER + FONT      OK");
    customos::drivers::video::ConsoleWriteln("WINDOW MANAGER v0       OK");
    customos::drivers::video::ConsoleWriteln("");
    customos::drivers::video::ConsoleWriteln("READY.  TRY DRAGGING A WINDOW BY ITS TITLE BAR.");

    // Shell welcome + initial prompt. Landing here after every
    // subsystem init line keeps the boot log visible above the
    // prompt — the user sees the tail end of the kernel's own
    // output, then their own typing cursor.
    customos::core::ShellInit();

    // Demo clickable button, owned by window A. x/y are offsets
    // (The CLICK ME demo button previously registered here has
    // been removed — the window it lived in is now the Calculator,
    // which registers its own 4x4 keypad via CalculatorInit above.)

    // Initial display mode. Priority:
    //   1. Runtime kernel cmdline "boot=tty" / "boot=desktop"
    //      (Multiboot2 tag 1 — set via GRUB menu entry).
    //   2. Compile-time CUSTOMOS_BOOT_TTY fallback.
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
#ifdef CUSTOMOS_BOOT_TTY
        want_tty = true;
#endif
    }

    if (want_tty)
    {
        customos::drivers::video::SetDisplayMode(customos::drivers::video::DisplayMode::Tty);
        customos::drivers::video::ConsoleSetOrigin(16, 16);
        customos::drivers::video::ConsoleSetColours(0x0080F088, 0x00000000);
        customos::drivers::video::DesktopCompose(0x00000000, nullptr);
    }
    else
    {
        customos::drivers::video::DesktopCompose(kDesktopTeal, "WELCOME TO CUSTOMOS   BOOT OK");
        customos::drivers::video::CursorInit(kDesktopTeal);
    }

    SerialWrite("[boot] Seeding ramfs + VFS self-test.\n");
    customos::fs::RamfsInit();
    {
        using namespace customos::fs;
        const RamfsNode* trusted = RamfsTrustedRoot();
        const RamfsNode* sandbox = RamfsSandboxRoot();

        // Positive lookups against the trusted tree. Trailing slash,
        // leading slash, empty-component runs — all tolerated.
        if (VfsLookup(trusted, "/etc/version", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: /etc/version missing from trusted root");
        if (VfsLookup(trusted, "/bin/hello", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: /bin/hello missing from trusted root");
        if (VfsLookup(trusted, "//etc//version", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: double-slash tolerance broken");

        // The sandbox root has exactly one file; its lookup must
        // succeed, and the trusted-only paths must fail.
        if (VfsLookup(sandbox, "/welcome.txt", 64) == nullptr)
            customos::core::Panic("fs/vfs", "self-test: /welcome.txt missing from sandbox root");
        if (VfsLookup(sandbox, "/etc/version", 64) != nullptr)
            customos::core::Panic("fs/vfs", "self-test: JAIL BROKEN — sandbox saw trusted /etc/version");
        if (VfsLookup(sandbox, "/bin/hello", 64) != nullptr)
            customos::core::Panic("fs/vfs", "self-test: JAIL BROKEN — sandbox saw trusted /bin/hello");

        // ".." is rejected outright.
        if (VfsLookup(trusted, "/etc/..", 64) != nullptr)
            customos::core::Panic("fs/vfs", "self-test: .. accepted (would break jails)");

        SerialWrite("[fs/vfs] self-test OK\n");
    }

    // Address-space isolation self-test — direct assertion that a
    // user page mapped in one AS is invisible in a sibling AS, and
    // that AddressSpaceActivate flips CR3 correctly. Indirectly
    // covered by ring3_smoke running two tasks at the same VA, but
    // this runs BEFORE scheduler/ring3 bring-up so a regression
    // surfaces at the earliest possible point.
    customos::mm::AddressSpaceSelfTest();

    SerialWrite("[boot] Parsing ACPI tables.\n");
    customos::acpi::AcpiInit(multiboot_info);

    SerialWrite("[boot] Disabling 8259 PIC.\n");
    PicDisable();

    SerialWrite("[boot] Bringing up LAPIC.\n");
    LapicInit();

    SerialWrite("[boot] Bringing up IOAPIC.\n");
    IoApicInit();

    SerialWrite("[boot] Bringing up HPET (if present).\n");
    HpetInit();
    HpetSelfTest();

    SerialWrite("[boot] Installing BSP per-CPU struct.\n");
    customos::cpu::PerCpuInitBsp();

    SerialWrite("[boot] Programming Linux-ABI syscall MSRs.\n");
    customos::subsystems::linux::SyscallInit();

    customos::sync::SpinLockSelfTest();

    SerialWrite("[boot] Bringing up periodic timer.\n");
    TimerInit();

    SerialWrite("[boot] Bringing up scheduler.\n");
    customos::sched::SchedInit();
    // Idle task FIRST so the runqueue is never empty — even if the
    // reaper or any subsequent worker blocks before the boot task
    // spawns anything else, Schedule() always has a fallback to
    // pick. Supersedes the "ensure SmpStartAps has a runnable peer"
    // workaround that used to depend on worker creation order.
    customos::sched::SchedStartIdle("idle-bsp");
    customos::sched::SchedStartReaper();

    SerialWrite("[boot] Bringing up PS/2 keyboard.\n");
    customos::drivers::input::Ps2KeyboardInit();

    SerialWrite("[boot] Bringing up PS/2 mouse.\n");
    customos::drivers::input::Ps2MouseInit();

    SerialWrite("[boot] Enumerating PCI bus.\n");
    customos::drivers::pci::PciEnumerate();

    SerialWrite("[boot] Bringing up block device layer.\n");
    customos::drivers::storage::BlockLayerInit();
    customos::drivers::storage::BlockLayerSelfTest();

    SerialWrite("[boot] Bringing up NVMe controller.\n");
    customos::drivers::storage::NvmeInit();
    customos::drivers::storage::NvmeSelfTest();

    SerialWrite("[boot] Bringing up AHCI controller(s).\n");
    customos::drivers::storage::AhciInit();
    customos::drivers::storage::AhciSelfTest();

    // Security guard must be live BEFORE any loader runs. Advisory
    // mode at boot: scans + logs, never blocks. Flip to Enforce via
    // the shell `guard enforce` once the boot-log is clean.
    SerialWrite("[boot] Starting security guard.\n");
    customos::security::GuardInit();
    customos::security::GuardSelfTest();

    SerialWrite("[boot] Probing GPT on block devices.\n");
    customos::fs::gpt::GptSelfTest();

    SerialWrite("[boot] Probing FAT32 on block devices.\n");
    customos::fs::fat32::Fat32SelfTest();

    // Metrics checkpoint: everything above is bringup overhead; what
    // the system consumes from here on is steady-state.
    KLOG_METRICS("boot", "bringup-complete");

    // Sanity-check the tmpfs log sink — by now enough Info+ lines
    // have fired that /tmp/boot.log should be at its 512-byte cap.
    {
        const char* bytes = nullptr;
        customos::u32 len = 0;
        if (customos::fs::TmpFsRead("boot.log", &bytes, &len))
        {
            customos::core::LogWithValue(customos::core::LogLevel::Info, "core/klog", "/tmp/boot.log size (bytes)",
                                         len);
        }
        else
        {
            customos::core::Log(customos::core::LogLevel::Warn, "core/klog", "/tmp/boot.log not present");
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
        using namespace customos::drivers::input;
        constexpr customos::u32 kDesktopTealLocal = 0x00204868;
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

            // Ctrl+C latches the shell interrupt flag. No
            // DesktopCompose here — the long-running command
            // holding the shell will notice next time it polls.
            // Skipped entirely if Alt is also held (that's a
            // different shortcut like Ctrl+Alt+T).
            if (ctrl && !alt && (ev.code == 'c' || ev.code == 'C'))
            {
                customos::core::ShellInterrupt();
                SerialWrite("[ui] ^C\n");
                continue;
            }

            // Ctrl+Alt+F1 / F2 flip the render target between
            // the shell and klog consoles. Same screen origin,
            // so the switch is in-place; each has its own
            // scrollback. Works in both desktop and TTY modes.
            if (ctrl && alt && (ev.code == kKeyF1 || ev.code == kKeyF2))
            {
                customos::drivers::video::CompositorLock();
                if (ev.code == kKeyF1)
                {
                    customos::drivers::video::ConsoleSelectShell();
                    SerialWrite("[ui] tty -> shell\n");
                }
                else
                {
                    customos::drivers::video::ConsoleSelectKlog();
                    SerialWrite("[ui] tty -> klog\n");
                }
                const bool is_tty =
                    (customos::drivers::video::GetDisplayMode() == customos::drivers::video::DisplayMode::Tty);
                if (is_tty)
                {
                    customos::drivers::video::DesktopCompose(0x00000000, nullptr);
                }
                else
                {
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                }
                customos::drivers::video::CompositorUnlock();
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
                customos::drivers::video::CompositorLock();
                const bool to_tty =
                    (customos::drivers::video::GetDisplayMode() == customos::drivers::video::DisplayMode::Desktop);
                if (to_tty)
                {
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::SetDisplayMode(customos::drivers::video::DisplayMode::Tty);
                    customos::drivers::video::ConsoleSetOrigin(16, 16);
                    customos::drivers::video::ConsoleSetColours(0x0080F088, 0x00000000);
                    customos::drivers::video::DesktopCompose(0x00000000, nullptr);
                }
                else
                {
                    customos::drivers::video::SetDisplayMode(customos::drivers::video::DisplayMode::Desktop);
                    customos::drivers::video::ConsoleSetOrigin(16, 400);
                    customos::drivers::video::ConsoleSetColours(0x0080F088, 0x00181028);
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                }
                customos::drivers::video::CompositorUnlock();
                SerialWrite(to_tty ? "[ui] enter TTY mode\n" : "[ui] enter DESKTOP mode\n");
                continue;
            }

            // Window-manager shortcuts take priority over any
            // text-input path. Alt+Tab cycles active window;
            // Alt+F4 closes it.
            if (alt && ev.code == kKeyTab)
            {
                customos::drivers::video::CompositorLock();
                customos::drivers::video::WindowCycleActive();
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
                customos::drivers::video::CompositorUnlock();
                SerialWrite("[ui] alt-tab\n");
                continue;
            }
            if (alt && ev.code == kKeyF4)
            {
                customos::drivers::video::CompositorLock();
                const auto active = customos::drivers::video::WindowActive();
                if (active != customos::drivers::video::kWindowInvalid)
                {
                    customos::drivers::video::WindowClose(active);
                    SerialWrite("[ui] alt-f4 close window=");
                    SerialWriteHex(active);
                    SerialWrite("\n");
                }
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
                customos::drivers::video::CompositorUnlock();
                continue;
            }

            // App-routed keystrokes. When the active window is an
            // app that registered a typed-input surface (Notes,
            // Calculator), feed it here and skip the shell path
            // entirely. Compositor lock brackets the feed so it
            // serialises with the ui-ticker's draw.
            {
                bool app_consumed = false;
                customos::drivers::video::CompositorLock();
                const auto active = customos::drivers::video::WindowActive();
                if (active != customos::drivers::video::kWindowInvalid)
                {
                    // Arrow-key routing — only Files consumes these
                    // today, but the block is shaped so future apps
                    // can add their own arrow handlers.
                    if (active == customos::apps::files::FilesWindow() &&
                        (ev.code == kKeyArrowUp || ev.code == kKeyArrowDown))
                    {
                        app_consumed = customos::apps::files::FilesFeedArrow(ev.code == kKeyArrowUp);
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
                            if (active == customos::apps::notes::NotesWindow())
                            {
                                customos::apps::notes::NotesFeedChar(c);
                                app_consumed = true;
                            }
                            else if (active == customos::apps::calculator::CalculatorWindow())
                            {
                                app_consumed = customos::apps::calculator::CalculatorFeedChar(c);
                            }
                            else if (active == customos::apps::files::FilesWindow())
                            {
                                app_consumed = customos::apps::files::FilesFeedChar(c);
                            }
                        }
                    }
                }
                customos::drivers::video::CompositorUnlock();
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
                customos::core::ShellBackspace();
                dirty = true;
            }
            else if (ev.code == kKeyEnter)
            {
                customos::core::ShellSubmit();
                dirty = true;
            }
            else if (ev.code == kKeyArrowUp)
            {
                customos::core::ShellHistoryPrev();
                dirty = true;
            }
            else if (ev.code == kKeyArrowDown)
            {
                customos::core::ShellHistoryNext();
                dirty = true;
            }
            else if (ev.code == kKeyTab)
            {
                customos::core::ShellTabComplete();
                dirty = true;
            }
            else if (ev.code >= 0x20 && ev.code <= 0x7E)
            {
                const char ch = static_cast<char>(ev.code);
                customos::core::ShellFeedChar(ch);
                const char buf[2] = {ch, '\0'};
                SerialWrite(buf);
                dirty = true;
            }
        app_key_recompose:
            if (dirty)
            {
                customos::drivers::video::CompositorLock();
                const bool is_tty =
                    (customos::drivers::video::GetDisplayMode() == customos::drivers::video::DisplayMode::Tty);
                if (is_tty)
                {
                    customos::drivers::video::DesktopCompose(0x00000000, nullptr);
                }
                else
                {
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                }
                customos::drivers::video::CompositorUnlock();
            }
        }
    };
    customos::sched::SchedCreate(kbd_reader, nullptr, "kbd-reader");

    // UI ticker: once per second, re-composite so the taskbar's
    // uptime / wall-clock counter advances even when the user
    // hasn't touched keyboard or mouse. Uses the compositor
    // mutex so it serialises cleanly with input threads. Full
    // recompose at 1 Hz costs ~one frame's worth of MMIO writes.
    // Branches on display mode so TTY-mode ticks don't re-draw
    // a hidden desktop.
    auto ui_ticker = [](void*)
    {
        constexpr customos::u32 kDesktopTealLocal = 0x00204868;
        for (;;)
        {
            customos::sched::SchedSleepTicks(100);
            customos::drivers::video::CompositorLock();
            if (customos::drivers::video::GetDisplayMode() == customos::drivers::video::DisplayMode::Tty)
            {
                customos::drivers::video::DesktopCompose(0x00000000, nullptr);
            }
            else
            {
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
            }
            customos::drivers::video::CompositorUnlock();
        }
    };
    customos::sched::SchedCreate(ui_ticker, nullptr, "ui-ticker");

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
            customos::drivers::video::WindowHandle window;
            customos::u32 grab_offset_x;
            customos::u32 grab_offset_y;
        };
        static DragState drag{false, customos::drivers::video::kWindowInvalid, 0, 0};
        static bool prev_left = false;
        static bool prev_right = false;
        constexpr customos::u32 kDesktopTealLocal = 0x00204868;

        // Menu item sets — static so their label pointers outlive
        // the menu's open state. action_id scheme is documented in
        // kernel_main's comment above; keep these tables in sync.
        static const customos::drivers::video::MenuItem kStartItems[] = {
            {"ABOUT CUSTOMOS", 1},
            {"CYCLE WINDOWS", 2},
            {"LIST WINDOWS", 3},
            {"PING CONSOLE", 4},
        };
        static const customos::drivers::video::MenuItem kDesktopMenuItems[] = {
            {"ABOUT CUSTOMOS", 1},
            {"CYCLE WINDOWS", 2},
            {"LIST WINDOWS", 3},
            {"SWITCH TO TTY", 5},
        };
        static const customos::drivers::video::MenuItem kWindowMenuItems[] = {
            {"RAISE", 10},
            {"CLOSE", 11},
        };

        for (;;)
        {
            const auto p = customos::drivers::input::Ps2MouseReadPacket();

            // In TTY mode the cursor is hidden and windows aren't
            // painted — ignore UI-side mouse handling entirely.
            // Serial logging still happens so packet delivery is
            // visible end-to-end.
            if (customos::drivers::video::GetDisplayMode() == customos::drivers::video::DisplayMode::Tty)
            {
                SerialWrite("[mouse-tty] dx=");
                SerialWriteHex(static_cast<customos::u64>(p.dx));
                SerialWrite(" dy=");
                SerialWriteHex(static_cast<customos::u64>(p.dy));
                SerialWrite(" btn=");
                SerialWriteHex(p.buttons);
                SerialWrite("\n");
                continue;
            }

            // Every UI mutation inside this packet lives under
            // the compositor mutex — the kbd reader can be mid-
            // ConsoleWrite / DesktopCompose at the same time.
            customos::drivers::video::CompositorLock();
            customos::drivers::video::CursorMove(p.dx, p.dy);

            customos::u32 cx = 0, cy = 0;
            customos::drivers::video::CursorPosition(&cx, &cy);

            const bool left_down = (p.buttons & customos::drivers::input::kMouseButtonLeft) != 0;
            const bool press_edge = left_down && !prev_left;
            const bool release_edge = !left_down && prev_left;
            prev_left = left_down;

            const bool right_down = (p.buttons & customos::drivers::input::kMouseButtonRight) != 0;
            const bool right_press = right_down && !prev_right;
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
                if (customos::drivers::video::MenuIsOpen())
                {
                    customos::drivers::video::MenuClose();
                }
                else if (!customos::drivers::video::TaskbarContains(cx, cy))
                {
                    const auto hit = customos::drivers::video::WindowTopmostAt(cx, cy);
                    if (hit != customos::drivers::video::kWindowInvalid)
                    {
                        customos::drivers::video::MenuOpen(
                            kWindowMenuItems, sizeof(kWindowMenuItems) / sizeof(kWindowMenuItems[0]), cx, cy, hit);
                    }
                    else
                    {
                        customos::drivers::video::MenuOpen(
                            kDesktopMenuItems, sizeof(kDesktopMenuItems) / sizeof(kDesktopMenuItems[0]), cx, cy, 0);
                    }
                }
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
                customos::drivers::video::CompositorUnlock();
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
            if (press_edge && customos::drivers::video::MenuIsOpen())
            {
                const customos::u32 action = customos::drivers::video::MenuItemAt(cx, cy);
                if (action != 0)
                {
                    const customos::u32 ctx = customos::drivers::video::MenuContext();
                    // Dispatch action. Context (ctx) is a caller-
                    // supplied u32 — for window menus it's the
                    // target WindowHandle.
                    switch (action)
                    {
                    case 1: // ABOUT CUSTOMOS
                        customos::drivers::video::ConsoleWriteln("");
                        customos::drivers::video::ConsoleWriteln("-> CUSTOMOS v0 — WINDOWED DESKTOP SHELL");
                        customos::drivers::video::ConsoleWriteln("   KEYBOARD + MOUSE + FRAMEBUFFER ALL LIVE");
                        break;
                    case 2: // CYCLE WINDOWS
                        customos::drivers::video::WindowCycleActive();
                        customos::drivers::video::ConsoleWriteln("-> CYCLED ACTIVE WINDOW");
                        break;
                    case 3: // LIST WINDOWS
                        customos::drivers::video::ConsoleWriteln("-> REGISTERED WINDOWS:");
                        for (customos::u32 h = 0; h < customos::drivers::video::WindowRegistryCount(); ++h)
                        {
                            if (customos::drivers::video::WindowIsAlive(h))
                            {
                                const char* title = customos::drivers::video::WindowTitle(h);
                                customos::drivers::video::ConsoleWrite("   ");
                                customos::drivers::video::ConsoleWriteln((title != nullptr) ? title : "(UNNAMED)");
                            }
                        }
                        break;
                    case 4: // PING CONSOLE
                        customos::drivers::video::ConsoleWriteln("-> PONG");
                        break;
                    case 5: // SWITCH TO TTY (from desktop context menu)
                        customos::drivers::video::SetDisplayMode(customos::drivers::video::DisplayMode::Tty);
                        customos::drivers::video::ConsoleSetOrigin(16, 16);
                        customos::drivers::video::ConsoleSetColours(0x0080F088, 0x00000000);
                        break;
                    case 10: // RAISE <ctx>
                        customos::drivers::video::WindowRaise(ctx);
                        SerialWrite("[ui] ctx raise window=");
                        SerialWriteHex(ctx);
                        SerialWrite("\n");
                        break;
                    case 11: // CLOSE <ctx>
                        customos::drivers::video::WindowClose(ctx);
                        SerialWrite("[ui] ctx close window=");
                        SerialWriteHex(ctx);
                        SerialWrite("\n");
                        break;
                    }
                    SerialWrite("[ui] menu fire action=");
                    SerialWriteHex(action);
                    SerialWrite("\n");
                }
                customos::drivers::video::MenuClose();
                menu_handled = true;
            }

            // START button press opens (or closes) the menu.
            if (press_edge && !menu_handled && !drag.active)
            {
                customos::u32 sx = 0, sy = 0, sw = 0, sh = 0;
                customos::drivers::video::TaskbarStartBounds(&sx, &sy, &sw, &sh);
                if (cx >= sx && cx < sx + sw && cy >= sy && cy < sy + sh)
                {
                    if (customos::drivers::video::MenuIsOpen())
                    {
                        customos::drivers::video::MenuClose();
                    }
                    else
                    {
                        // Open with the start item set; measure
                        // panel height AFTER MenuOpen populates
                        // its item count so the anchor sits
                        // flush against the top of the START
                        // button regardless of how many items
                        // are in the set.
                        customos::drivers::video::MenuOpen(kStartItems, sizeof(kStartItems) / sizeof(kStartItems[0]),
                                                           sx, sy, 0);
                        const customos::u32 mh = customos::drivers::video::MenuPanelHeight();
                        const customos::u32 my = (sy > mh) ? sy - mh : 0;
                        customos::drivers::video::MenuOpen(kStartItems, sizeof(kStartItems) / sizeof(kStartItems[0]),
                                                           sx, my, 0);
                        SerialWrite("[ui] menu open\n");
                    }
                    menu_handled = true;
                }
            }

            if (press_edge && !menu_handled && !drag.active && customos::drivers::video::TaskbarContains(cx, cy))
            {
                const customos::u32 tab_hit = customos::drivers::video::TaskbarTabAt(cx, cy);
                if (tab_hit != customos::drivers::video::kWindowInvalid)
                {
                    customos::drivers::video::WindowRaise(tab_hit);
                    SerialWrite("[ui] taskbar raise window=");
                    SerialWriteHex(tab_hit);
                    SerialWrite("\n");
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                    menu_handled = true; // taskbar ate the click
                }
            }

            if (press_edge && menu_handled)
            {
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
            }
            else if (press_edge && !drag.active)
            {
                const auto hit = customos::drivers::video::WindowTopmostAt(cx, cy);
                if (hit != customos::drivers::video::kWindowInvalid)
                {
                    if (customos::drivers::video::WindowPointInCloseBox(hit, cx, cy))
                    {
                        customos::drivers::video::WindowClose(hit);
                        SerialWrite("[ui] close window=");
                        SerialWriteHex(hit);
                        SerialWrite("\n");
                    }
                    else
                    {
                        customos::u32 wx = 0, wy = 0;
                        customos::drivers::video::WindowGetBounds(hit, &wx, &wy, nullptr, nullptr);
                        customos::drivers::video::WindowRaise(hit);
                        const bool in_title = customos::drivers::video::WindowPointInTitle(hit, cx, cy);
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
                    customos::drivers::video::CursorHide();
                    customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                    customos::drivers::video::CursorShow();
                }
            }
            if (release_edge && drag.active)
            {
                SerialWrite("[ui] drag end window=");
                SerialWriteHex(drag.window);
                SerialWrite("\n");
                drag.active = false;
            }

            if (drag.active)
            {
                // Position the window so the grabbed pixel stays
                // under the cursor. Any sub-pixel clamp lives
                // inside WindowMoveTo.
                const customos::u32 nx = (cx > drag.grab_offset_x) ? cx - drag.grab_offset_x : 0;
                const customos::u32 ny = (cy > drag.grab_offset_y) ? cy - drag.grab_offset_y : 0;
                customos::drivers::video::WindowMoveTo(drag.window, nx, ny);
                customos::drivers::video::CursorHide();
                customos::drivers::video::DesktopCompose(kDesktopTealLocal, "WELCOME TO CUSTOMOS   BOOT OK");
                customos::drivers::video::CursorShow();
            }
            else
            {
                // Non-drag path: route clicks + motion through the
                // widget table as before. Only reachable when the
                // cursor is NOT pinning a window move; this keeps
                // the button widget inert during drag, matching
                // Windows' "modal drag" semantics.
                const customos::u32 hit = customos::drivers::video::WidgetRouteMouse(cx, cy, p.buttons);
                if (hit != customos::drivers::video::kWidgetInvalid)
                {
                    SerialWrite("[ui] widget event id=");
                    SerialWriteHex(hit);
                    SerialWrite("\n");
                    // Dispatch to app-level handlers. Each app
                    // claims a private ID range (see Calculator's
                    // kIdBase); non-claiming handlers return false
                    // and the event is just logged above.
                    customos::apps::calculator::CalculatorOnWidgetEvent(hit);
                }
            }

            customos::drivers::video::CompositorUnlock();

            SerialWrite("[mouse] dx=");
            SerialWriteHex(static_cast<customos::u64>(p.dx));
            SerialWrite(" dy=");
            SerialWriteHex(static_cast<customos::u64>(p.dy));
            SerialWrite(" btn=");
            SerialWriteHex(p.buttons);
            SerialWrite("\n");
        }
    };
    customos::sched::SchedCreate(mouse_reader, nullptr, "mouse-reader");

    // Scheduler self-test: three kernel threads that each bump a shared
    // counter five times under a mutex. If the mutex serialises them
    // correctly, the counter reaches exactly 15 and the prints interleave
    // without any skipped values. A race would skip values (two workers
    // reading the same `before` and writing `before + 1`). This also
    // exercises WaitQueueBlock / WaitQueueWakeOne whenever two workers
    // collide on MutexLock, so the wait-queue machinery is on the boot
    // path by default.
    static customos::sched::Mutex s_demo_mutex{};
    static customos::u64 s_shared_counter = 0;

    auto worker = [](void* arg)
    {
        const char* name = static_cast<const char*>(arg);
        for (customos::u64 i = 0; i < 5; ++i)
        {
            customos::sched::MutexLock(&s_demo_mutex);

            const customos::u64 before = s_shared_counter;
            // Burn a couple of ms of CPU inside the critical section so
            // that other workers are almost guaranteed to hit the slow
            // path on MutexLock and park on the wait queue. Without this
            // the race is too tight for the self-test to be meaningful.
            for (customos::u64 j = 0; j < 2'000'000; ++j)
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

            customos::sched::MutexUnlock(&s_demo_mutex);
            customos::sched::SchedSleepTicks(1); // yield + 10 ms pause
        }
    };

    customos::sched::SchedCreate(worker, const_cast<char*>("A"), "worker-A");
    customos::sched::SchedCreate(worker, const_cast<char*>("B"), "worker-B");
    customos::sched::SchedCreate(worker, const_cast<char*>("C"), "worker-C");

    // First ring-3 slice: spawn a dedicated scheduler thread that maps a
    // user code + stack page, drops to ring 3, and runs an interruptible
    // pause/jmp loop forever. Kernel workers above keep running and
    // periodically preempt it; the proof-of-life is that this whole
    // boot sequence continues to make forward progress after the
    // iretq into user mode.
    customos::core::StartRing3SmokeTask();
    // Linux-ABI proof-of-life. Reaches MSR_LSTAR entry stub →
    // LinuxSyscallDispatch → sys_exit_group. A clean exit here
    // proves the whole plumbing — EFER.SCE, MSR setup, swapgs
    // dance, iretq return — works end-to-end.
    customos::subsystems::linux::SpawnRing3LinuxSmoke();
    // Same payload wrapped in an ELF64 image loaded via
    // SpawnElfLinux — proves the loader + abi-flavor plumbing
    // works, which is the path a real Linux ELF off disk will
    // use once FAT32 exec wiring lands.
    customos::subsystems::linux::SpawnRing3LinuxElfSmoke();

    // Bring up APs. SmpStartAps calls SchedSleepTicks(1) between
    // INIT and SIPI; the dedicated idle task installed at the top
    // of SchedInit guarantees the runqueue is non-empty, so the
    // BSP always has something to switch to while it sleeps —
    // independent of worker-creation order.
    SerialWrite("[boot] Bringing up APs.\n");
    SmpStartAps();

    customos::core::StartHeartbeatThread();

    SerialWrite("[boot] All subsystems online. Entering idle loop.\n");

#ifdef CUSTOMOS_CANARY_DEMO
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

#ifdef CUSTOMOS_PANIC_DEMO
    // Compile-time-gated deliberate panic used by tools/test-panic.sh
    // to verify the panic path stays healthy end-to-end. Never
    // enabled in a normal build — the default preset does not pass
    // -DCUSTOMOS_PANIC_DEMO.
    customos::core::Panic("test/panic-demo", "CUSTOMOS_PANIC_DEMO enabled; halting on purpose");
#endif

#ifdef CUSTOMOS_TRAP_DEMO
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
    customos::sched::SchedExit();
}
