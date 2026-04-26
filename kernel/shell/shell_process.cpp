/*
 * DuetOS — kernel shell: process / scheduler / memory commands.
 *
 * Sibling TU of shell.cpp. Houses the read-only observability
 * triple — ps / top / free — plus the spawn + kill mutators that
 * round out the process bucket. Linuxexec / Exec / Translate /
 * Readelf live in shell_exec.cpp; AttackSim / Guard live in
 * shell_security.cpp.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "proc/ring3_smoke.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// SchedStateName: TU-private, used by CmdPs / CmdTop only.
const char* SchedStateName(u8 s)
{
    switch (s)
    {
    case 0:
        return "READY";
    case 1:
        return "RUN  ";
    case 2:
        return "SLEEP";
    case 3:
        return "BLOCK";
    case 4:
        return "DEAD ";
    default:
        return "?    ";
    }
}

} // namespace

void CmdPs()
{
    // Header row: PID + STATE + PRI + TICKS-run + NAME.
    //   TICKS is the cumulative per-task tick count since creation.
    //   Divide by `SchedStatsRead().total_ticks` for a since-boot
    //   CPU-%; `top` renders that column directly.
    ConsoleWriteln(" PID  STATE  PRI  TICKS     NAME");
    struct Cookie
    {
        u32 count;
    };
    Cookie cookie{0};
    duetos::sched::SchedEnumerate(
        [](const duetos::sched::SchedTaskInfo& info, void* ck)
        {
            auto* c = static_cast<Cookie*>(ck);
            ConsoleWriteChar(info.is_running ? '*' : ' ');
            if (info.id < 10)
                ConsoleWriteChar(' ');
            if (info.id < 100)
                ConsoleWriteChar(' ');
            WriteU64Dec(info.id);
            ConsoleWriteChar(' ');
            ConsoleWriteChar(' ');
            ConsoleWrite(SchedStateName(info.state));
            ConsoleWriteChar(' ');
            ConsoleWriteChar(' ');
            ConsoleWriteChar(info.priority == 0 ? 'N' : 'I'); // Normal / Idle
            ConsoleWriteChar(' ');
            ConsoleWriteChar(' ');
            char tbuf[24];
            u32 tw = 0;
            u64 tr = info.ticks_run;
            if (tr == 0)
                tbuf[tw++] = '0';
            else
            {
                char rev[24];
                u32 rn = 0;
                while (tr > 0)
                {
                    rev[rn++] = static_cast<char>('0' + tr % 10);
                    tr /= 10;
                }
                while (rn > 0)
                    tbuf[tw++] = rev[--rn];
            }
            tbuf[tw] = 0;
            for (u32 k = tw; k < 8; ++k)
                ConsoleWriteChar(' ');
            ConsoleWrite(tbuf);
            ConsoleWriteChar(' ');
            ConsoleWriteln(info.name != nullptr ? info.name : "(unnamed)");
            ++c->count;
        },
        &cookie);
    ConsoleWrite("TOTAL: ");
    WriteU64Dec(cookie.count);
    ConsoleWriteln(" tasks");
}

void CmdTop()
{
    // `top`: one-shot snapshot of CPU% per task + system idle.
    // Not a live refresh (the shell blocks on keyboard input with
    // no input-loop integration yet) — run it repeatedly for a
    // trend. CPU% is since-boot — `ticks_run / total_ticks * 100`.
    const auto s = duetos::sched::SchedStatsRead();
    const u64 total = s.total_ticks;
    ConsoleWrite("SYSTEM: total_ticks=");
    WriteU64Dec(total);
    ConsoleWrite(" idle_ticks=");
    WriteU64Dec(s.idle_ticks);
    ConsoleWrite(" cpu_busy=");
    const u64 busy_pct = (total > 0) ? ((total - s.idle_ticks) * 100u / total) : 0;
    WriteU64Dec(busy_pct);
    ConsoleWriteln("%");
    ConsoleWriteln(" PID  CPU%  STATE  PRI  NAME");
    struct Cookie
    {
        u64 total;
    };
    Cookie cookie{total};
    duetos::sched::SchedEnumerate(
        [](const duetos::sched::SchedTaskInfo& info, void* ck)
        {
            auto* c = static_cast<Cookie*>(ck);
            ConsoleWriteChar(info.is_running ? '*' : ' ');
            if (info.id < 10)
                ConsoleWriteChar(' ');
            if (info.id < 100)
                ConsoleWriteChar(' ');
            WriteU64Dec(info.id);
            ConsoleWrite("  ");
            const u64 pct = (c->total > 0) ? (info.ticks_run * 100u / c->total) : 0;
            if (pct < 10)
                ConsoleWriteChar(' ');
            if (pct < 100)
                ConsoleWriteChar(' ');
            WriteU64Dec(pct);
            ConsoleWrite("%   ");
            ConsoleWrite(SchedStateName(info.state));
            ConsoleWrite("  ");
            ConsoleWriteChar(info.priority == 0 ? 'N' : 'I');
            ConsoleWrite("   ");
            ConsoleWriteln(info.name != nullptr ? info.name : "(unnamed)");
        },
        &cookie);
}

void CmdFree()
{
    // Compact "free -k"-ish output: one line each for memory
    // totals and the kernel heap.
    const u64 total = duetos::mm::TotalFrames();
    const u64 free_f = duetos::mm::FreeFramesCount();
    const u64 used = total - free_f;
    constexpr u64 kKiB = 4;
    ConsoleWriteln("           total         used         free");
    ConsoleWrite("PHYS  ");
    WriteU64Dec(total * kKiB);
    ConsoleWrite("K  ");
    WriteU64Dec(used * kKiB);
    ConsoleWrite("K  ");
    WriteU64Dec(free_f * kKiB);
    ConsoleWriteln("K");
    const auto h = duetos::mm::KernelHeapStatsRead();
    ConsoleWrite("HEAP  ");
    WriteU64Dec(h.pool_bytes);
    ConsoleWrite("   ");
    WriteU64Dec(h.used_bytes);
    ConsoleWrite("   ");
    WriteU64Dec(h.free_bytes);
    ConsoleWriteChar('\n');
}

void CmdKill(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("KILL: USAGE: KILL PID");
        return;
    }
    u64 pid = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ConsoleWriteln("KILL: BAD PID");
            return;
        }
        pid = pid * 10 + static_cast<u64>(argv[1][i] - '0');
    }
    const auto r = duetos::sched::SchedKillByPid(pid);
    switch (r)
    {
    case duetos::sched::KillResult::Signaled:
        ConsoleWrite("KILL: SIGNALED PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" (WILL DIE ON NEXT SCHEDULE)");
        break;
    case duetos::sched::KillResult::NotFound:
        ConsoleWrite("KILL: NO SUCH PID: ");
        WriteU64Dec(pid);
        ConsoleWriteChar('\n');
        break;
    case duetos::sched::KillResult::Protected:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS PROTECTED (idle/reaper/boot)");
        break;
    case duetos::sched::KillResult::AlreadyDead:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS ALREADY DEAD");
        break;
    case duetos::sched::KillResult::Blocked:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS BLOCKED — FLAGGED, WILL DIE WHEN WOKEN");
        break;
    }
}

void CmdSpawn(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SPAWN: USAGE: SPAWN <KIND>");
        ConsoleWriteln("  KINDS:  hello  sandbox  jail  nx  hog  hostile  dropcaps  priv  badint");
        ConsoleWriteln("          kread  ptrfuzz  writefuzz  hellope  winkill  winhello");
        ConsoleWriteln("  SEE `MAN SPAWN` FOR DETAILS.");
        return;
    }
    if (!duetos::core::SpawnOnDemand(argv[1]))
    {
        ConsoleWrite("SPAWN: UNKNOWN KIND: ");
        ConsoleWriteln(argv[1]);
        ConsoleWriteln("  KINDS:  hello  sandbox  jail  nx  hog  hostile  dropcaps  priv  badint");
        ConsoleWriteln("          kread  ptrfuzz  writefuzz  hellope  winkill  winhello");
        return;
    }
    ConsoleWrite("SPAWN: QUEUED ");
    ConsoleWriteln(argv[1]);
    ConsoleWriteln("  (RUN `PS` TO SEE IT, OR WATCH THE KERNEL LOG)");
}

} // namespace duetos::core::shell::internal
