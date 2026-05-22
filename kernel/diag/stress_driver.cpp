#include "diag/stress_driver.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "shell/shell_internal.h"
#include "util/string.h"
#include "util/types.h"

namespace duetos::core::diag
{

namespace
{

using duetos::arch::SerialWrite;
using duetos::core::shell::internal::StressDriverCpu;
using duetos::core::shell::internal::StressDriverMem;
using duetos::core::shell::internal::StressDriverMix;
using duetos::core::shell::internal::StressDriverSpin;

// Mode encoded as a tiny int so the spawned task carries it in the
// arg pointer slot without a heap allocation.
enum class Mode : u32
{
    None = 0,
    Cpu = 1,
    Mem = 2,
    Mix = 3,
    Spin = 4,
};

struct Config
{
    Mode mode = Mode::None;
    u32 secs = 10;
    u32 workers = 8;
    u32 mib = 32;
};

// Module-local config snapshot. Arm() stages it before SchedCreate
// hands the worker a pointer to this struct — the worker reads its
// own values out and never touches the struct again, so a second
// stress= arming wouldn't race (we only arm once per boot).
Config g_cfg = {};

// Linear scan: return true iff `cmdline` contains a whitespace-
// delimited token `key=value`; copy the value into `out` (up to
// `cap-1` bytes, NUL-terminated). nullptr cmdline → false. A
// minimal parser mirroring the style of CmdlineMatches in main.cpp;
// keeping it local sidesteps having to expose that helper or a
// fuller cmdline library before the first additional consumer.
bool CmdlineGet(const char* cmdline, const char* key, char* out, u32 cap)
{
    if (cmdline == nullptr || out == nullptr || cap == 0)
    {
        return false;
    }
    out[0] = '\0';
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
            u32 i = 0;
            while (t < p && i + 1 < cap)
            {
                out[i++] = *t++;
            }
            out[i] = '\0';
            return true;
        }
    }
    return false;
}

// Parse a non-negative decimal integer. Returns true on success; on
// failure `*out` is left untouched so the caller's default sticks.
bool ParseU32(const char* s, u32* out)
{
    if (s == nullptr || s[0] == '\0')
    {
        return false;
    }
    u32 v = 0;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
        v = v * 10 + static_cast<u32>(s[i] - '0');
    }
    *out = v;
    return true;
}

// Run-on-its-own-task entry. We deliberately leave a serial sentinel
// at start + end so a headless boot can grep for `[stress] start` and
// `[stress] done`; the body emits the existing loadtest console
// transcript which is teed to serial. Task self-exits after the
// mode finishes — nothing to clean up since the loadtest paths
// free their own allocations.
[[noreturn]] void StressDriverEntry(void* /*arg*/)
{
    // Tiny settle window so the boot log isn't interleaved with
    // late init banners that come after sched is online (heartbeat
    // first beat, drivers' deferred-init prints, etc.). 30 ticks at
    // 100 Hz = ~300 ms kernel time. Short enough that a TCG-emulated
    // run (where wall-time:kernel-time is 20:1 or worse) doesn't
    // chew the whole test window in settle; long enough that the
    // post-bring-up bursts have flushed by the time we start
    // emitting our own lines.
    sched::SchedSleepTicks(30);

    SerialWrite("[stress] start\n");
    KLOG_INFO_V("stress", "driver armed; mode=", static_cast<u32>(g_cfg.mode));

    // Snapshot pre-run heap so the post-run line tells operators
    // whether the run leaked. Loadtest also reports this internally
    // for mem mode; the duplicated tally here is intentional — it
    // lets a single grep over the boot log show "started clean,
    // ended clean" without scrolling through the per-mode body.
    const auto pre_heap = mm::KernelHeapStatsRead();
    const u64 pre_free_frames = mm::FreeFramesCount();
    // SerialLineGuard so the three Write*s emit as one logical
    // line — without it a peer CPU's `[arch/smp] AP pre-enter` /
    // worker-stat output slips between calls and corrupts the line
    // (observed under SMP=8 stress as
    // `[stress] pre  he ap_  used_KiB= sys=0x...`).
    {
        arch::SerialLineGuard guard;
        SerialWrite("[stress] pre  heap_used_KiB=");
        char buf[24];
        u32 n = 0;
        u64 v = pre_heap.used_bytes / 1024;
        if (v == 0)
        {
            buf[n++] = '0';
        }
        else
        {
            char tmp[24];
            u32 t = 0;
            while (v != 0)
            {
                tmp[t++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            }
            while (t > 0)
            {
                buf[n++] = tmp[--t];
            }
        }
        buf[n] = '\0';
        SerialWrite(buf);
        SerialWrite("\n");
    }

    switch (g_cfg.mode)
    {
    case Mode::Cpu:
        StressDriverCpu(g_cfg.secs, g_cfg.workers);
        break;
    case Mode::Mem:
        StressDriverMem(g_cfg.mib, g_cfg.secs);
        break;
    case Mode::Mix:
        StressDriverMix(g_cfg.secs, g_cfg.workers, g_cfg.mib);
        break;
    case Mode::Spin:
        StressDriverSpin(g_cfg.secs);
        break;
    case Mode::None:
        // Unreachable: Arm() only spawns when mode != None.
        break;
    }

    const auto post_heap = mm::KernelHeapStatsRead();
    const u64 post_free_frames = mm::FreeFramesCount();
    KLOG_INFO_V("stress", "post heap used bytes=", post_heap.used_bytes);
    KLOG_INFO_V("stress", "heap delta bytes=", static_cast<u64>(post_heap.used_bytes - pre_heap.used_bytes));
    KLOG_INFO_V("stress", "free frames delta=",
                static_cast<u64>(post_free_frames > pre_free_frames ? post_free_frames - pre_free_frames
                                                                    : pre_free_frames - post_free_frames));

    SerialWrite("[stress] done\n");
    sched::SchedExit();
}

} // namespace

void StressDriverStageMode(const char* cmdline)
{
    if (cmdline == nullptr || g_cfg.mode != Mode::None)
    {
        return;
    }

    char value[16] = {};
    if (!CmdlineGet(cmdline, "stress", value, sizeof(value)))
    {
        return;
    }

    if (StrEqual(value, "cpu"))
    {
        g_cfg.mode = Mode::Cpu;
    }
    else if (StrEqual(value, "mem"))
    {
        g_cfg.mode = Mode::Mem;
    }
    else if (StrEqual(value, "mix"))
    {
        g_cfg.mode = Mode::Mix;
    }
    else if (StrEqual(value, "spin"))
    {
        g_cfg.mode = Mode::Spin;
    }
    else
    {
        arch::SerialWrite("[stress] unknown mode (expected cpu|mem|mix|spin): ");
        arch::SerialWrite(value);
        arch::SerialWrite("\n");
        return;
    }

    char num[16] = {};
    if (CmdlineGet(cmdline, "stress-secs", num, sizeof(num)))
    {
        u32 v = g_cfg.secs;
        if (ParseU32(num, &v))
        {
            g_cfg.secs = v;
        }
    }
    if (CmdlineGet(cmdline, "stress-workers", num, sizeof(num)))
    {
        u32 v = g_cfg.workers;
        if (ParseU32(num, &v))
        {
            g_cfg.workers = v;
        }
    }
    if (CmdlineGet(cmdline, "stress-mib", num, sizeof(num)))
    {
        u32 v = g_cfg.mib;
        if (ParseU32(num, &v))
        {
            g_cfg.mib = v;
        }
    }
}

void StressDriverArm(const char* cmdline)
{
    // Re-parse the cmdline only if the early stage hook didn't run
    // (older callers that haven't been migrated, or unit-test paths
    // that drive Arm directly). When mode is already Cpu/Mem/Mix/Spin
    // the stage parse above already populated g_cfg; we just spawn.
    StressDriverStageMode(cmdline);

    if (g_cfg.mode == Mode::None)
    {
        return;
    }

    const char* mode_name = (g_cfg.mode == Mode::Cpu)    ? "cpu"
                            : (g_cfg.mode == Mode::Mem)  ? "mem"
                            : (g_cfg.mode == Mode::Mix)  ? "mix"
                            : (g_cfg.mode == Mode::Spin) ? "spin"
                                                         : "?";
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[stress] arming driver — mode=");
        arch::SerialWrite(mode_name);
        arch::SerialWrite("\n");
    }

    auto* t = sched::SchedCreate(&StressDriverEntry, nullptr, "stress-driver");
    if (t == nullptr)
    {
        // Scheduler refused to create the driver thread —
        // typically means the task table is full or KMalloc OOM.
        // Klog the failure so the disarm is visible in dmesg.
        KLOG_ERROR("diag/stress", "SchedCreate failed — driver not started");
        g_cfg.mode = Mode::None;
    }
}

bool StressDriverArmed()
{
    return g_cfg.mode != Mode::None;
}

} // namespace duetos::core::diag
