/*
 * DuetOS — kernel shell: trivial banner / status commands.
 *
 * Sibling TU of shell.cpp. Houses the five smallest commands —
 * about / version / clear / uptime / date. Each fits in <30 lines
 * and depends only on the console driver, the RTC, and the
 * scheduler's tick counter.
 *
 * Larger "core"-flavoured commands (help, theme, dmesg, stats,
 * env, alias, source, man, history, sysinfo, time, set, unset,
 * getenv, seq, which) stay in shell.cpp until a follow-up slice
 * promotes their shared helpers (env table, alias table, history
 * ring) into shell_internal.h.
 */

#include "shell_internal.h"

#include "../arch/x86_64/rtc.h"
#include "../drivers/video/console.h"
#include "../sched/sched.h"

#include "auth.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

} // namespace

void CmdAbout()
{
    ConsoleWriteln("DUETOS — A FROM-SCRATCH x86_64 KERNEL WITH A");
    ConsoleWriteln("NATIVE WINDOWED DESKTOP AND A FIRST-CLASS WIN32");
    ConsoleWriteln("SUBSYSTEM PLANNED. BOOT: MULTIBOOT2.  SHELL: YOU.");
}

void CmdVersion()
{
    ConsoleWriteln("DUETOS v0 (WINDOWED DESKTOP SHELL)");
}

void CmdClear()
{
    duetos::drivers::video::ConsoleClear();
}

void CmdUptime()
{
    const u64 secs = duetos::sched::SchedNowTicks() / 100;
    ConsoleWrite("UPTIME ");
    WriteU64Dec(secs);
    ConsoleWriteln(" SECONDS");
}

void CmdDate()
{
    duetos::arch::RtcTime t{};
    duetos::arch::RtcRead(&t);
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

void CmdYield()
{
    // Voluntary yield from the shell thread — useful for testing
    // cooperative scheduling behaviour by hand. No output.
    duetos::sched::SchedYield();
}

void CmdUname(u32 argc, char** argv)
{
    // uname default: kernel name. -a prints everything.
    const bool all = (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'a');
    if (all)
    {
        ConsoleWrite("DuetOS duetos v0 x86_64  (tick ");
        WriteU64Dec(duetos::sched::SchedNowTicks());
        ConsoleWriteln(")");
    }
    else
    {
        ConsoleWriteln("DuetOS");
    }
}

void CmdWhoami()
{
    const char* name = AuthCurrentUserName();
    if (name[0] == '\0')
    {
        ConsoleWriteln("(no session)");
    }
    else
    {
        ConsoleWriteln(name);
    }
}

void CmdPwd()
{
    // No per-process CWD yet; every path in the shell is
    // absolute against the trusted ramfs root. `pwd` prints
    // "/" so scripts that consult it don't break.
    ConsoleWriteln("/");
}

void CmdTrue()
{
    // No-op success — useful in scripts: `cmd && true`.
}

void CmdFalse()
{
    // No-op failure placeholder. No exit codes yet; the
    // visual-only marker prints nothing (matches /bin/false).
}

void CmdHostname()
{
    const EnvSlot* s = EnvFind("HOSTNAME");
    ConsoleWriteln((s != nullptr) ? s->value : "duetos");
}

} // namespace duetos::core::shell::internal
