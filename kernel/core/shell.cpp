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
    ConsoleWriteln("  ECHO TEXT   PRINT TEXT");
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
    Dispatch(g_input);
    g_len = 0;
    Prompt();
}

} // namespace customos::core
