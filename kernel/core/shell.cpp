#include "shell.h"

#include "../arch/x86_64/rtc.h"
#include "../drivers/video/console.h"
#include "../drivers/video/widget.h"
#include "../sched/sched.h"

namespace customos::core
{

namespace
{

using customos::drivers::video::ConsoleWrite;
using customos::drivers::video::ConsoleWriteChar;
using customos::drivers::video::ConsoleWriteln;

constexpr u32 kInputMax = 64;
constinit char g_input[kInputMax] = {};
constinit u32 g_len = 0;

// Command history. Ring buffer of the last `kHistoryCap`
// submitted lines. g_history_count saturates at the cap; newest
// entry lives at ((head - 1) mod cap). g_history_cursor is the
// recall index — 0 == "at the live prompt" (no recall), 1 == the
// most recent entry, etc. Walking Up goes back in history;
// Down walks forward until we reach the live prompt.
constexpr u32 kHistoryCap = 8;
constinit char g_history[kHistoryCap][kInputMax] = {};
constinit u32 g_history_head = 0;
constinit u32 g_history_count = 0;
constinit u32 g_history_cursor = 0;

bool StrEq(const char* a, const char* b)
{
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
}

// Compare the first `n` characters of a and b. Used for the
// "echo <rest>" dispatch where we only know the command prefix.
bool StrStartsWith(const char* s, const char* prefix)
{
    for (u32 i = 0;; ++i)
    {
        if (prefix[i] == '\0')
            return true;
        if (s[i] != prefix[i])
            return false;
    }
}

void HistoryPush(const char* line)
{
    // Skip empty submissions and duplicates of the newest entry —
    // matches every shell users are used to.
    if (line[0] == '\0')
    {
        return;
    }
    if (g_history_count > 0)
    {
        const u32 newest = (g_history_head + kHistoryCap - 1) % kHistoryCap;
        if (StrEq(g_history[newest], line))
        {
            return;
        }
    }
    u32 i = 0;
    for (; i < kInputMax - 1 && line[i] != '\0'; ++i)
    {
        g_history[g_history_head][i] = line[i];
    }
    g_history[g_history_head][i] = '\0';
    g_history_head = (g_history_head + 1) % kHistoryCap;
    if (g_history_count < kHistoryCap)
    {
        ++g_history_count;
    }
}

// Look up the `n`th most-recent entry (n=1 newest, n=history_count
// oldest). Returns nullptr if n is out of range.
const char* HistoryAt(u32 n)
{
    if (n == 0 || n > g_history_count)
    {
        return nullptr;
    }
    const u32 idx = (g_history_head + kHistoryCap - n) % kHistoryCap;
    return g_history[idx];
}

// Wipe the current visible line (print '\b' len times) and load
// `text` into the edit buffer + echo it. `nullptr` just clears
// the line.
void ReplaceLine(const char* text)
{
    while (g_len > 0)
    {
        ConsoleWriteChar('\b');
        --g_len;
    }
    g_input[0] = '\0';
    if (text == nullptr)
    {
        return;
    }
    for (u32 i = 0; text[i] != '\0' && g_len + 1 < kInputMax; ++i)
    {
        g_input[g_len] = text[i];
        ConsoleWriteChar(text[i]);
        ++g_len;
    }
    g_input[g_len] = '\0';
}

void WriteU64Dec(u64 v)
{
    if (v == 0)
    {
        ConsoleWriteChar('0');
        return;
    }
    char tmp[24];
    u32 n = 0;
    while (v > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    for (u32 i = 0; i < n; ++i)
    {
        ConsoleWriteChar(tmp[n - 1 - i]);
    }
}

void WriteU8TwoDigits(u8 v)
{
    ConsoleWriteChar(static_cast<char>('0' + (v / 10)));
    ConsoleWriteChar(static_cast<char>('0' + (v % 10)));
}

void Prompt()
{
    ConsoleWrite("$ ");
}

// ---------------------------------------------------------------
// Commands
// ---------------------------------------------------------------

void CmdHelp()
{
    ConsoleWriteln("AVAILABLE COMMANDS:");
    ConsoleWriteln("  HELP        LIST THIS HELP");
    ConsoleWriteln("  ABOUT       ABOUT CUSTOMOS");
    ConsoleWriteln("  VERSION     CUSTOMOS VERSION");
    ConsoleWriteln("  CLEAR       CLEAR THE CONSOLE");
    ConsoleWriteln("  UPTIME      SECONDS SINCE BOOT");
    ConsoleWriteln("  DATE        WALL TIME + DATE");
    ConsoleWriteln("  WINDOWS     LIST REGISTERED WINDOWS");
    ConsoleWriteln("  MODE        SHOW CURRENT DISPLAY MODE");
    ConsoleWriteln("  ECHO TEXT   PRINT TEXT");
    ConsoleWriteln("");
    ConsoleWriteln("KEYS:  UP/DOWN = HISTORY   CTRL+ALT+T = TOGGLE MODE");
    ConsoleWriteln("       ALT+TAB = CYCLE WINDOW  ALT+F4 = CLOSE WINDOW");
}

void CmdAbout()
{
    ConsoleWriteln("CUSTOMOS — A FROM-SCRATCH x86_64 KERNEL WITH A");
    ConsoleWriteln("NATIVE WINDOWED DESKTOP AND A FIRST-CLASS WIN32");
    ConsoleWriteln("SUBSYSTEM PLANNED. BOOT: MULTIBOOT2.  SHELL: YOU.");
}

void CmdVersion()
{
    ConsoleWriteln("CUSTOMOS v0 (WINDOWED DESKTOP SHELL)");
}

void CmdClear()
{
    customos::drivers::video::ConsoleClear();
}

void CmdUptime()
{
    const u64 secs = customos::sched::SchedNowTicks() / 100;
    ConsoleWrite("UPTIME ");
    WriteU64Dec(secs);
    ConsoleWriteln(" SECONDS");
}

void CmdDate()
{
    customos::arch::RtcTime t{};
    customos::arch::RtcRead(&t);
    WriteU8TwoDigits(t.hour);
    ConsoleWriteChar(':');
    WriteU8TwoDigits(t.minute);
    ConsoleWriteChar(':');
    WriteU8TwoDigits(t.second);
    ConsoleWriteChar(' ');
    WriteU64Dec(t.year);
    ConsoleWriteChar('-');
    WriteU8TwoDigits(t.month);
    ConsoleWriteChar('-');
    WriteU8TwoDigits(t.day);
    ConsoleWriteChar('\n');
}

void CmdWindows()
{
    using namespace customos::drivers::video;
    ConsoleWriteln("REGISTERED WINDOWS:");
    for (u32 h = 0; h < WindowRegistryCount(); ++h)
    {
        ConsoleWrite("  [");
        WriteU64Dec(h);
        ConsoleWrite("] ");
        ConsoleWrite(WindowIsAlive(h) ? "ALIVE  " : "DEAD   ");
        const char* t = WindowTitle(h);
        ConsoleWriteln((t != nullptr) ? t : "(UNTITLED)");
    }
}

void CmdMode()
{
    const auto mode = customos::drivers::video::GetDisplayMode();
    ConsoleWrite("CURRENT MODE: ");
    ConsoleWriteln(mode == customos::drivers::video::DisplayMode::Tty ? "TTY (FULLSCREEN CONSOLE)"
                                                                       : "DESKTOP (WINDOWED SHELL)");
    ConsoleWriteln("PRESS CTRL+ALT+T TO TOGGLE.");
}

void CmdEcho(const char* args)
{
    // `args` points at the remainder of the line after the
    // "echo " prefix. Skip any leading whitespace so "echo  x"
    // and "echo x" produce the same output.
    while (*args == ' ')
    {
        ++args;
    }
    ConsoleWriteln(args);
}

void Dispatch(const char* line)
{
    if (line[0] == '\0')
    {
        return; // empty submission — no diagnostic, just re-prompt
    }
    if (StrEq(line, "help"))
    {
        CmdHelp();
        return;
    }
    if (StrEq(line, "about"))
    {
        CmdAbout();
        return;
    }
    if (StrEq(line, "version"))
    {
        CmdVersion();
        return;
    }
    if (StrEq(line, "clear"))
    {
        CmdClear();
        return;
    }
    if (StrEq(line, "uptime"))
    {
        CmdUptime();
        return;
    }
    if (StrEq(line, "date"))
    {
        CmdDate();
        return;
    }
    if (StrEq(line, "windows"))
    {
        CmdWindows();
        return;
    }
    if (StrEq(line, "mode"))
    {
        CmdMode();
        return;
    }
    if (StrStartsWith(line, "echo ") || StrEq(line, "echo"))
    {
        const char* args = line + 4;
        if (*args == ' ')
        {
            ++args;
        }
        CmdEcho(args);
        return;
    }
    ConsoleWrite("COMMAND NOT FOUND: ");
    ConsoleWriteln(line);
    ConsoleWriteln("TYPE HELP FOR A LIST OF COMMANDS.");
}

} // namespace

void ShellInit()
{
    ConsoleWriteln("");
    ConsoleWriteln("CUSTOMOS SHELL v0   TYPE HELP FOR COMMANDS.");
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

} // namespace customos::core
