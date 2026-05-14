/*
 * DuetOS — kernel shell: implementation.
 *
 * Companion to shell.h — see there for the v0 scope (line-edit
 * model, command list, intentional limits like single global
 * line buffer, no piping).
 *
 * WHAT
 *   Reads keystrokes from the keyboard input thread, edits a
 *   line buffer, and on Enter dispatches to a fixed command
 *   table. Output goes to the framebuffer console (and to
 *   serial when the framebuffer is unavailable, e.g. early
 *   boot or headless).
 *
 * HOW
 *   Two-tier dispatch:
 *     1. Built-in commands matched by `CommandIs(line, "name")`
 *        in a long if/else chain near `ShellExecute`. Each
 *        command body inlines its own argument parsing — no
 *        argv tokeniser.
 *     2. External commands aren't supported in v0. An unknown
 *        first token prints "command not found" and returns.
 *
 *   Output helpers (WriteU64Dec, WriteU64Hex, etc.) live near
 *   the top — they're used by every command body. Section
 *   banners (`// === network commands`, `// === inspect`,
 *   `// === graphics`) group commands by domain so reading
 *   the file top-to-bottom finds related commands together.
 *
 * WHY THIS FILE IS HUGE (~9.5K LINES)
 *   The shell is the user's primary debug surface. Every
 *   subsystem grows a few `command` entries to expose state
 *   (`pci`, `acpi`, `mem`, `windows`, `ifconfig`, `ext4`,
 *   `nvme`, `inspect`, ...). At ~75-100 commands, each 30-150
 *   lines of body, the file naturally grows past the 500-line
 *   anti-bloat threshold. Splitting commands into per-domain
 *   TUs is on the table once a real text editor / pipe layer
 *   exists; until then, `Ctrl+F help` plus the section banners
 *   keep navigation tractable.
 */

#include "shell/shell.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/thermal.h"
#include "arch/x86_64/timer.h"
#include "acpi/acpi.h"
#include "drivers/audio/pcspk.h"
#include "drivers/gpu/bochs_vbe.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/virtio_gpu.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/net/net.h"
#include "drivers/pci/pci.h"
#include "drivers/usb/cdc_ecm.h"
#include "drivers/usb/rndis.h"
#include "drivers/power/power.h"
#include "net/stack.h"
#include "net/wifi.h"
#include "drivers/storage/block.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/fat32.h"
#include "subsystems/graphics/graphics.h"
#include "subsystems/translation/translate.h"
#include "fs/gpt.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "debug/breakpoints.h"
#include "debug/probes.h"
#include "debug/inspect.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "security/attack_sim.h"
#include "security/guard.h"
#include "loader/elf_loader.h"
#include "diag/hexdump.h"
#include "diag/cleanroom_trace.h"
#include "diag/crprobe.h"
#include "loader/firmware_loader.h"
#include "security/auth.h"
#include "diag/kdbg.h"
#include "log/klog.h"
#include "security/login.h"
#include "util/symbols.h"
#include "proc/process.h"
#include "util/random.h"
#include "power/reboot.h"
#include "diag/runtime_checker.h"
#include "shell/shell_internal.h"

namespace duetos::core
{

// Hoist the per-domain Cmd* handlers from the shell sibling TUs
// (shell_security.cpp, ...) back into this TU's outer namespace
// so the dispatch chain in Dispatch() keeps reading like the
// in-TU layout the file used to have.
using namespace shell::internal;

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// kInputMax / kHistoryCap + StrEq / StrStartsWith moved to
// shell_internal.h. The history ring (g_history* + HistoryPush /
// HistoryAt / HistoryExpand) and the live input buffer (g_input /
// g_len / g_interrupt + ReplaceLine) live in shell_state.cpp.

// WriteU64Dec / WriteU8TwoDigits / WriteU64Hex / WriteI64Dec
// moved to shell_format.cpp; declared in shell_internal.h.

// CmdHelp / CmdWindows / CmdTheme + ApplyThemeAndRepaint /
// CmdWhich / CmdTime / CmdSource / CmdSysinfo / CmdRepeat /
// CmdRebootNow / CmdHaltNow + the kCommandSet[] table + the
// Prompt + Tokenize / kMaxArgs helpers + the Dispatch entry
// point all moved to shell_dispatch.cpp. Dispatch and Prompt
// are declared cross-TU in shell_internal.h so this TU's public
// ShellInit / ShellSubmit wrappers can still reach them.

} // namespace

void ShellInit()
{
    ConsoleWriteln("");

    // Print /etc/motd if present — human-facing welcome text,
    // replaces the tiny "DUETOS SHELL" banner the earlier
    // version used. If the file is missing (e.g. a stripped
    // sandbox tree), fall back to the minimum one-liner.
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 motd_len = ReadFileToBuf("/etc/motd", scratch, sizeof(scratch));
    if (motd_len != static_cast<u32>(-1))
    {
        for (u32 i = 0; i < motd_len; ++i)
        {
            ConsoleWriteChar(scratch[i]);
        }
        if (motd_len == 0 || scratch[motd_len - 1] != '\n')
        {
            ConsoleWriteChar('\n');
        }
    }
    else
    {
        ConsoleWriteln("DUETOS SHELL v0   TYPE HELP FOR COMMANDS.");
    }

    // Auto-source /etc/profile. Effect is identical to the user
    // running `source /etc/profile` manually — sets any boot-time
    // aliases / prompt / env vars the distribution wants. Silent
    // no-op if the file doesn't exist. Goes through the dispatcher
    // (rather than calling CmdSource directly) so the latter can
    // stay TU-private to shell_dispatch.cpp.
    //
    // Under DUETOS_SHELL_SELFTEST the profile chain-sources
    // /etc/selftest.sh; the serial mirror isn't normally on yet
    // (SerialInputStart runs much later), so headless callers
    // would lose the markers. Pre-arm + restore the mirror around
    // the dispatch so the SELFTEST PASS/FAIL lines reach COM1.
    const auto* prof = duetos::fs::VfsLookup(duetos::fs::RamfsTrustedRoot(), "/etc/profile", 64);
    if (prof != nullptr && prof->type == duetos::fs::RamfsNodeType::kFile)
    {
#ifdef DUETOS_SHELL_SELFTEST
        duetos::drivers::video::ConsoleEnableSerialMirror(true);
#endif
        char source_line[] = "source /etc/profile";
        Dispatch(source_line);
#ifdef DUETOS_SHELL_SELFTEST
        duetos::drivers::video::ConsoleEnableSerialMirror(false);
#endif
    }

    Prompt();
}

void ShellFeedChar(char c)
{
    if (c < 0x20 || c > 0x7E)
    {
        return; // non-printable ignored — Enter/Backspace have dedicated entries
    }
    if (g_len + 1 >= kInputMax)
    {
        return; // buffer full — silently drop trailing input
    }
    g_input[g_len++] = c;
    ConsoleWriteChar(c);
}

void ShellBackspace()
{
    if (g_len == 0)
    {
        return;
    }
    --g_len;
    g_input[g_len] = '\0';
    ConsoleWriteChar('\b');
}

// Returns true if the typed line starts with a verb whose
// command line carries a plaintext password — `su`, `login`,
// `passwd` all take the password as a positional argv. Pushing
// those lines into the history ring would let `history` / `!N`
// recall them verbatim. Skip the history-push for those lines
// only; everything else is recorded normally.
static bool ShellLineHasSecret(const char* line)
{
    if (line == nullptr)
        return false;
    // Skip leading whitespace then match the first token (lowercase
    // ASCII verbs). We compare a small fixed set; the dispatcher
    // lower-cases internally before its own match, so anchoring to
    // a single case here is consistent.
    u32 i = 0;
    while (line[i] == ' ' || line[i] == '\t')
        ++i;
    auto starts_with = [&](const char* tok) -> bool
    {
        u32 j = 0;
        while (tok[j] != '\0')
        {
            const char a = line[i + j];
            // Accept either case so an upper-case "SU" is also
            // detected — the shell verb table matches case-
            // insensitively at dispatch time.
            const char a_lo = (a >= 'A' && a <= 'Z') ? static_cast<char>(a - 'A' + 'a') : a;
            if (a_lo != tok[j])
                return false;
            ++j;
        }
        // Token boundary: next char must be whitespace or end.
        const char after = line[i + j];
        return after == '\0' || after == ' ' || after == '\t';
    };
    return starts_with("su") || starts_with("login") || starts_with("passwd");
}

void ShellSubmit()
{
    g_input[g_len] = '\0';
    ConsoleWriteChar('\n');
    if (!ShellLineHasSecret(g_input))
    {
        HistoryPush(g_input);
    }
    g_history_cursor = 0;
    Dispatch(g_input);
    g_len = 0;
    g_input[0] = '\0';
    Prompt();
}

void ShellRedrawAfterLogLine()
{
    // klog has just finished writing a line and a newline. If the
    // operator is mid-input (g_len > 0), redraw the prompt + their
    // current buffer on the fresh line so they can see what they
    // typed instead of having it scrolled off-screen by the log
    // chatter. The recursion guard in klog ensures we never call
    // back into Log* from here (Prompt + ConsoleWrite go straight
    // to console + serial, not through klog).
    if (g_len == 0)
        return;
    Prompt();
    for (u32 i = 0; i < g_len; ++i)
    {
        ConsoleWriteChar(g_input[i]);
    }
}

u32 ShellHistoryCount()
{
    return g_history_count;
}

const char* ShellHistoryGet(u32 n)
{
    return HistoryAt(n);
}

void ShellHistoryPrev()
{
    if (g_history_count == 0)
    {
        return;
    }
    if (g_history_cursor >= g_history_count)
    {
        return; // already at the oldest entry
    }
    ++g_history_cursor;
    ReplaceLine(HistoryAt(g_history_cursor));
}

void ShellHistoryNext()
{
    if (g_history_cursor == 0)
    {
        return; // already at the live prompt
    }
    --g_history_cursor;
    if (g_history_cursor == 0)
    {
        ReplaceLine(nullptr); // back to empty live line
        return;
    }
    ReplaceLine(HistoryAt(g_history_cursor));
}

// ExtendLine / NamePrefixMatch / CompleteCommandName /
// CompletePath + the CompleteCandidate / CompleteCollector
// helpers + kCompleteMax all moved to shell_complete.cpp,
// alongside the public ShellTabComplete entry point.
void ShellInterrupt()
{
    g_interrupt = true;
}

bool ShellInterruptRequested()
{
    if (g_interrupt)
    {
        g_interrupt = false;
        return true;
    }
    return false;
}

// ShellTabComplete moved to shell_complete.cpp.

} // namespace duetos::core
