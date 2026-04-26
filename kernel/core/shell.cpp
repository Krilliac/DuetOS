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

#include "shell.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/cpu_info.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smbios.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/thermal.h"
#include "../arch/x86_64/timer.h"
#include "../acpi/acpi.h"
#include "../drivers/audio/pcspk.h"
#include "../drivers/gpu/bochs_vbe.h"
#include "../drivers/gpu/gpu.h"
#include "../drivers/gpu/virtio_gpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/net/net.h"
#include "../drivers/pci/pci.h"
#include "../drivers/usb/cdc_ecm.h"
#include "../drivers/usb/rndis.h"
#include "../drivers/power/power.h"
#include "../net/stack.h"
#include "../net/wifi.h"
#include "../drivers/storage/block.h"
#include "../drivers/video/console.h"
#include "../drivers/video/cursor.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/theme.h"
#include "../drivers/video/widget.h"
#include "../fs/fat32.h"
#include "../subsystems/graphics/graphics.h"
#include "../subsystems/translation/translate.h"
#include "../fs/gpt.h"
#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"
#include "../debug/breakpoints.h"
#include "../debug/probes.h"
#include "../debug/inspect.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../security/attack_sim.h"
#include "../security/guard.h"
#include "elf_loader.h"
#include "hexdump.h"
#include "cleanroom_trace.h"
#include "crprobe.h"
#include "firmware_loader.h"
#include "auth.h"
#include "kdbg.h"
#include "klog.h"
#include "login.h"
#include "symbols.h"
#include "process.h"
#include "random.h"
#include "reboot.h"
#include "ring3_smoke.h"
#include "runtime_checker.h"
#include "shell_internal.h"

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
    const auto* prof = duetos::fs::VfsLookup(duetos::fs::RamfsTrustedRoot(), "/etc/profile", 64);
    if (prof != nullptr && prof->type == duetos::fs::RamfsNodeType::kFile)
    {
        char source_line[] = "source /etc/profile";
        Dispatch(source_line);
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

void ShellSubmit()
{
    g_input[g_len] = '\0';
    ConsoleWriteChar('\n');
    HistoryPush(g_input);
    g_history_cursor = 0;
    Dispatch(g_input);
    g_len = 0;
    g_input[0] = '\0';
    Prompt();
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

// Extend the edit buffer with the tail of `text` starting at
// offset `from`, optionally followed by a single `trailer`
// character. Echoes each byte to the console. Caps at kInputMax
// silently. Used by both command-name and path completion.
void ExtendLine(const char* text, u32 from, char trailer)
{
    u32 i = g_len;
    while (text[from] != '\0' && i + 1 < kInputMax)
    {
        g_input[i] = text[from];
        ConsoleWriteChar(text[from]);
        ++i;
        ++from;
    }
    if (trailer != '\0' && i + 1 < kInputMax)
    {
        g_input[i] = trailer;
        ConsoleWriteChar(trailer);
        ++i;
    }
    g_len = i;
    g_input[g_len] = '\0';
}

// True iff `name` starts with the first `plen` bytes of `prefix`
// (or `plen == 0`, in which case everything matches).
bool NamePrefixMatch(const char* name, const char* prefix, u32 plen)
{
    for (u32 i = 0; i < plen; ++i)
    {
        if (name[i] == '\0' || name[i] != prefix[i])
        {
            return false;
        }
    }
    return true;
}

void CompleteCommandName()
{
    const u32 kCmdCount = kCommandCount;

    const char* match = nullptr;
    u32 match_count = 0;
    for (u32 i = 0; i < kCmdCount; ++i)
    {
        if (StrStartsWith(kCommandSet[i], g_input))
        {
            match = kCommandSet[i];
            ++match_count;
        }
    }
    if (match_count == 0)
    {
        return;
    }
    if (match_count == 1)
    {
        ExtendLine(match, g_len, ' ');
        return;
    }
    ConsoleWriteChar('\n');
    for (u32 i = 0; i < kCmdCount; ++i)
    {
        if (StrStartsWith(kCommandSet[i], g_input))
        {
            ConsoleWrite("  ");
            ConsoleWriteln(kCommandSet[i]);
        }
    }
    Prompt();
    ConsoleWrite(g_input);
}

// Walk-time candidate record used by the path completer. A
// candidate is either a ramfs node (borrowed pointer) or a
// tmpfs slot (name + isdir=false). We decouple from the
// backing storage so /tmp entries and static entries can
// both be matched in the same sweep.
struct CompleteCandidate
{
    const char* name;
    bool is_dir;
};

// Cap matches what a human can usefully scan and matches
// kTmpFsSlotCount + a handful of static entries.
constexpr u32 kCompleteMax = 24;

struct CompleteCollector
{
    CompleteCandidate items[kCompleteMax];
    u32 count;
    const char* leaf;
    u32 leaf_len;
};

// Complete an absolute path in the tail of the edit buffer. The
// `partial_start` argument is the index into g_input where the
// path begins (first char AFTER the separating whitespace).
// Leading character MUST be '/' for v0 — relative-path support
// lands with a CWD concept.
void CompletePath(u32 partial_start)
{
    const u32 partial_len = g_len - partial_start;
    if (partial_len == 0 || g_input[partial_start] != '/')
    {
        return;
    }
    u32 last_slash = 0;
    for (u32 i = 0; i < partial_len; ++i)
    {
        if (g_input[partial_start + i] == '/')
        {
            last_slash = i;
        }
    }
    char parent_buf[96];
    if (last_slash == 0)
    {
        parent_buf[0] = '/';
        parent_buf[1] = '\0';
    }
    else
    {
        u32 j = 0;
        for (; j < last_slash && j + 1 < sizeof(parent_buf); ++j)
        {
            parent_buf[j] = g_input[partial_start + j];
        }
        parent_buf[j] = '\0';
    }

    const char* leaf = &g_input[partial_start + last_slash + 1];
    const u32 leaf_len = partial_len - last_slash - 1;

    // Don't value-init the whole struct — `col{}` on a 400-
    // byte local emits a memset call, which doesn't exist in
    // this freestanding environment. Only `count` needs to
    // start at 0; `items[]` entries are written before read.
    CompleteCollector col;
    col.count = 0;
    col.leaf = leaf;
    col.leaf_len = leaf_len;

    // Populate candidates from the appropriate backing. /tmp is
    // the writable tier; everything else is the static ramfs;
    // root additionally surfaces a synthetic "tmp/" entry so
    // Tab at / yields both worlds.
    if (StrEq(parent_buf, "/tmp"))
    {
        auto cb = [](const char* name, u32 /*len*/, void* cookie)
        {
            auto* c = static_cast<CompleteCollector*>(cookie);
            if (c->count >= kCompleteMax)
                return;
            if (!NamePrefixMatch(name, c->leaf, c->leaf_len))
                return;
            c->items[c->count].name = name;
            c->items[c->count].is_dir = false;
            ++c->count;
        };
        duetos::fs::TmpFsEnumerate(cb, &col);
    }
    else
    {
        const auto* root = duetos::fs::RamfsTrustedRoot();
        const auto* parent = duetos::fs::VfsLookup(root, parent_buf, sizeof(parent_buf));
        if (parent == nullptr || parent->type != duetos::fs::RamfsNodeType::kDir || parent->children == nullptr)
        {
            return;
        }
        for (u32 i = 0; parent->children[i] != nullptr && col.count < kCompleteMax; ++i)
        {
            const auto* c = parent->children[i];
            if (!NamePrefixMatch(c->name, leaf, leaf_len))
                continue;
            col.items[col.count].name = c->name;
            col.items[col.count].is_dir = (c->type == duetos::fs::RamfsNodeType::kDir);
            ++col.count;
        }
        // Root also offers "tmp/" as a completion target — the
        // tmpfs mount point isn't a static ramfs child.
        if (StrEq(parent_buf, "/"))
        {
            const char* synth = "tmp";
            if (NamePrefixMatch(synth, leaf, leaf_len) && col.count < kCompleteMax)
            {
                col.items[col.count].name = synth;
                col.items[col.count].is_dir = true;
                ++col.count;
            }
        }
    }

    if (col.count == 0)
    {
        return;
    }
    if (col.count == 1)
    {
        const char trailer = col.items[0].is_dir ? '/' : ' ';
        ExtendLine(col.items[0].name, leaf_len, trailer);
        return;
    }
    ConsoleWriteChar('\n');
    for (u32 i = 0; i < col.count; ++i)
    {
        ConsoleWrite("  ");
        ConsoleWrite(col.items[i].name);
        if (col.items[i].is_dir)
        {
            ConsoleWriteln("/");
        }
        else
        {
            ConsoleWriteChar('\n');
        }
    }
    Prompt();
    ConsoleWrite(g_input);
}

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

void ShellTabComplete()
{
    if (g_len == 0)
    {
        return;
    }
    g_input[g_len] = '\0';

    // Split the buffer at the FIRST whitespace. If there isn't
    // one, this is command-name completion. Otherwise the first
    // token is a command name and we complete the last token as
    // a path — but only for commands that take a path.
    u32 first_ws = 0;
    bool has_ws = false;
    for (u32 i = 0; i < g_len; ++i)
    {
        if (g_input[i] == ' ' || g_input[i] == '\t')
        {
            first_ws = i;
            has_ws = true;
            break;
        }
    }
    if (!has_ws)
    {
        CompleteCommandName();
        return;
    }

    // Find the LAST whitespace so we know where the last token
    // begins. That's the token we're completing.
    u32 last_ws = first_ws;
    for (u32 i = first_ws + 1; i < g_len; ++i)
    {
        if (g_input[i] == ' ' || g_input[i] == '\t')
        {
            last_ws = i;
        }
    }

    // Temporarily terminate the first token so StrEq can read it.
    const char saved = g_input[first_ws];
    g_input[first_ws] = '\0';
    const bool path_cmd =
        StrEq(g_input, "ls") || StrEq(g_input, "cat") || StrEq(g_input, "touch") || StrEq(g_input, "rm") ||
        StrEq(g_input, "cp") || StrEq(g_input, "mv") || StrEq(g_input, "wc") || StrEq(g_input, "head") ||
        StrEq(g_input, "tail") || StrEq(g_input, "source") || StrEq(g_input, "grep") || StrEq(g_input, "sort") ||
        StrEq(g_input, "uniq") || StrEq(g_input, "readelf") || StrEq(g_input, "hexdump") || StrEq(g_input, "stat") ||
        StrEq(g_input, "tac") || StrEq(g_input, "nl") || StrEq(g_input, "rev") || StrEq(g_input, "checksum");
    g_input[first_ws] = saved;

    if (path_cmd)
    {
        CompletePath(last_ws + 1);
    }
}

} // namespace duetos::core
