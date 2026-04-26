/*
 * DuetOS — kernel shell: process / scheduler / memory commands.
 *
 * Sibling TU of shell.cpp. Houses the read-only observability
 * triple: ps (per-task scheduler enumeration), top (one-shot
 * CPU% snapshot), free (frame + kernel-heap totals).
 *
 * Spawn / Kill / Exec / Linuxexec / Translate / Readelf are
 * queued for a follow-up slice — those handlers share path-strip
 * and FAT32-load helpers with several other shell commands, so
 * extracting them coordinates with that follow-up work.
 */

#include "shell_internal.h"

#include "../drivers/video/console.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"

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

} // namespace duetos::core::shell::internal
