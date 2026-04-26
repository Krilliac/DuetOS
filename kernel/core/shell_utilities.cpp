/*
 * DuetOS — kernel shell: trivial utility commands.
 *
 * Sibling TU of shell.cpp. Houses the lightweight commands that
 * touch one or two subsystems and don't need any of the larger
 * TU-private helpers still living in shell.cpp:
 *
 *   basename / dirname  — pure string manipulation
 *   flushtlb            — CR3 reload
 *   mem                 — frame allocator totals
 *   mode                — display-mode query
 *   history             — read the hoisted history ring
 *   sleep               — block on the scheduler tick
 *   shutdown            — ACPI S5 path + halt fallback
 *
 * Larger utility commands (Cal / Rand / Uuid / Color / Beep /
 * Checksum / Repeat / Expr / Rev / Tac / Nl / Reset) stay in
 * shell.cpp until either their helper dependencies are hoisted
 * or their callers move with them.
 */

#include "shell_internal.h"

#include "../acpi/acpi.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/cpu_info.h"
#include "../arch/x86_64/serial.h"
#include "../drivers/video/console.h"
#include "../drivers/video/widget.h"
#include "../mm/frame_allocator.h"
#include "../sched/sched.h"

#include "shell.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

} // namespace

void CmdBasename(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("BASENAME: USAGE: BASENAME PATH");
        return;
    }
    const char* p = argv[1];
    u32 last_slash = 0;
    bool have = false;
    for (u32 i = 0; p[i] != '\0'; ++i)
    {
        if (p[i] == '/')
        {
            last_slash = i;
            have = true;
        }
    }
    if (!have)
    {
        ConsoleWriteln(p);
        return;
    }
    // Everything after the last '/'. Empty (trailing slash) →
    // print the original path minus slashes, matching coreutils.
    const char* tail = p + last_slash + 1;
    if (*tail == '\0')
    {
        ConsoleWriteln(p);
    }
    else
    {
        ConsoleWriteln(tail);
    }
}

void CmdDirname(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("DIRNAME: USAGE: DIRNAME PATH");
        return;
    }
    const char* p = argv[1];
    u32 last_slash = 0;
    bool have = false;
    for (u32 i = 0; p[i] != '\0'; ++i)
    {
        if (p[i] == '/')
        {
            last_slash = i;
            have = true;
        }
    }
    if (!have)
    {
        ConsoleWriteln(".");
        return;
    }
    if (last_slash == 0)
    {
        ConsoleWriteln("/");
        return;
    }
    for (u32 i = 0; i < last_slash; ++i)
    {
        ConsoleWriteChar(p[i]);
    }
    ConsoleWriteChar('\n');
}

void CmdFlushTlb()
{
    // Reload CR3 with its current value — the classic x86_64
    // "flush every non-global TLB entry" primitive. Global
    // pages survive (they're typically kernel direct-map);
    // anything else is cold on next access.
    const u64 cr3 = duetos::arch::ReadCr3();
    asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    ConsoleWriteln("TLB FLUSHED (CR3 RELOAD).");
}

void CmdMem()
{
    const u64 total = duetos::mm::TotalFrames();
    const u64 free_frames = duetos::mm::FreeFramesCount();
    const u64 used = total - free_frames;
    constexpr u64 kPageKiB = 4;
    ConsoleWrite("TOTAL  ");
    WriteU64Dec(total);
    ConsoleWrite(" FRAMES (");
    WriteU64Dec(total * kPageKiB);
    ConsoleWriteln(" KIB)");
    ConsoleWrite("USED   ");
    WriteU64Dec(used);
    ConsoleWrite(" FRAMES (");
    WriteU64Dec(used * kPageKiB);
    ConsoleWriteln(" KIB)");
    ConsoleWrite("FREE   ");
    WriteU64Dec(free_frames);
    ConsoleWrite(" FRAMES (");
    WriteU64Dec(free_frames * kPageKiB);
    ConsoleWriteln(" KIB)");
}

void CmdMode()
{
    const auto mode = duetos::drivers::video::GetDisplayMode();
    ConsoleWrite("CURRENT MODE: ");
    ConsoleWriteln(mode == duetos::drivers::video::DisplayMode::Tty ? "TTY (FULLSCREEN CONSOLE)"
                                                                    : "DESKTOP (WINDOWED SHELL)");
    ConsoleWriteln("PRESS CTRL+ALT+T TO TOGGLE.");
}

void CmdHistory()
{
    if (g_history_count == 0)
    {
        ConsoleWriteln("(NO HISTORY)");
        return;
    }
    // Display oldest-first so the numbers count in typing order —
    // readers intuit "1 is the first thing I ran" even though
    // internally `HistoryAt(1)` is the newest entry. Swap the
    // mapping here; callers of `!N` use the same convention.
    for (u32 i = g_history_count; i > 0; --i)
    {
        const u32 display_num = g_history_count - i + 1;
        ConsoleWrite("  ");
        WriteU64Dec(display_num);
        ConsoleWrite("  ");
        ConsoleWriteln(HistoryAt(i));
    }
}

void CmdSleep(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SLEEP: USAGE: SLEEP SECONDS");
        return;
    }
    u32 secs = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ConsoleWriteln("SLEEP: BAD NUMBER");
            return;
        }
        secs = secs * 10 + static_cast<u32>(argv[1][i] - '0');
    }
    // 100 Hz scheduler tick → 100 ticks per second. Sleep via
    // the scheduler's block-on-tick primitive so the CPU
    // genuinely yields to other tasks, rather than spin-waiting.
    // Poll the interrupt flag in 1-second increments so Ctrl+C
    // can abort a long sleep.
    for (u32 s = 0; s < secs; ++s)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        duetos::sched::SchedSleepTicks(100);
    }
}

[[noreturn]] void CmdShutdownNow()
{
    ConsoleWriteln("SHUTDOWN: evaluating AML \\_S5 + writing PM1a...");
    duetos::arch::SerialWrite("[shell] user invoked shutdown\n");
    // Flush any last bytes by driving a dummy serial write
    // before the PM1 write that may cut power mid-instruction.
    if (duetos::acpi::AcpiShutdown())
    {
        // AcpiShutdown returns true only on never-reached paths;
        // v0 implementation always returns after the write. Fall
        // through.
    }
    // Firmware didn't honour S5 (most common on QEMU TCG unless
    // -machine pc / q35 + the _PTS method runs, which we skip).
    // Fall back to reboot, then halt if that also fails.
    ConsoleWriteln("SHUTDOWN: S5 not honoured; falling back to halt.");
    duetos::arch::Halt();
}

} // namespace duetos::core::shell::internal
