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

// ---------------------------------------------------------------
// Env / alias commands. Thin wrappers over the hoisted env-table
// and alias-table machinery in shell_state.cpp.
// ---------------------------------------------------------------

void CmdSet(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("SET: USAGE: SET NAME VALUE");
        return;
    }
    if (!EnvSet(argv[1], argv[2]))
    {
        ConsoleWriteln("SET: ENV TABLE FULL");
    }
}

void CmdUnset(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("UNSET: MISSING NAME");
        return;
    }
    if (!EnvUnset(argv[1]))
    {
        ConsoleWrite("UNSET: NO SUCH VAR: ");
        ConsoleWriteln(argv[1]);
    }
}

void CmdGetenv(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("GETENV: USAGE: GETENV NAME");
        return;
    }
    const EnvSlot* s = EnvFind(argv[1]);
    if (s == nullptr)
    {
        ConsoleWriteln("(UNSET)");
        return;
    }
    ConsoleWriteln(s->value);
}

void CmdEnv()
{
    bool any = false;
    for (u32 i = 0; i < kEnvSlotCount; ++i)
    {
        if (!g_env[i].in_use)
            continue;
        any = true;
        ConsoleWrite("  ");
        ConsoleWrite(g_env[i].name);
        ConsoleWriteChar('=');
        ConsoleWriteln(g_env[i].value);
    }
    if (!any)
    {
        ConsoleWriteln("(NO VARIABLES SET)");
    }
}

void CmdAlias(u32 argc, char** argv)
{
    if (argc == 1)
    {
        // List all.
        bool any = false;
        for (u32 i = 0; i < kAliasSlotCount; ++i)
        {
            if (!g_aliases[i].in_use)
                continue;
            any = true;
            ConsoleWrite("  ");
            ConsoleWrite(g_aliases[i].name);
            ConsoleWrite("  = ");
            ConsoleWriteln(g_aliases[i].expansion);
        }
        if (!any)
        {
            ConsoleWriteln("(NO ALIASES)");
        }
        return;
    }
    if (argc == 2)
    {
        const AliasSlot* s = AliasFind(argv[1]);
        if (s == nullptr)
        {
            ConsoleWrite("ALIAS: NO SUCH ALIAS: ");
            ConsoleWriteln(argv[1]);
            return;
        }
        ConsoleWrite(argv[1]);
        ConsoleWrite(" = ");
        ConsoleWriteln(s->expansion);
        return;
    }
    // 3+ args — join args[2..argc] with single spaces into the
    // expansion, matching how the user typed it.
    char buf[kAliasExpansionMax];
    u32 out = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && out + 1 < sizeof(buf))
            buf[out++] = ' ';
        for (u32 j = 0; argv[i][j] != '\0' && out + 1 < sizeof(buf); ++j)
            buf[out++] = argv[i][j];
    }
    buf[out] = '\0';
    if (!AliasSet(argv[1], buf))
    {
        ConsoleWriteln("ALIAS: TABLE FULL");
    }
}

void CmdUnalias(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("UNALIAS: MISSING NAME");
        return;
    }
    if (!AliasUnset(argv[1]))
    {
        ConsoleWrite("UNALIAS: NO SUCH ALIAS: ");
        ConsoleWriteln(argv[1]);
    }
}

} // namespace duetos::core::shell::internal
