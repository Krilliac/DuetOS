/*
 * DuetOS — kernel shell: loadtest command.
 *
 * Sibling TU of shell.cpp. Synthesises CPU and/or memory pressure
 * so an operator can watch how the kernel behaves under sustained
 * load: scheduler fairness, preemption, heap fragmentation, OOM
 * recovery, ^C responsiveness during a hot loop.
 *
 * Modes:
 *   loadtest                       — usage + live status
 *   loadtest status                — running workers + held bytes
 *   loadtest spin   [SECS]         — busy-loop the shell task
 *                                    (single-thread CPU saturation)
 *   loadtest cpu    [SECS] [N]     — spawn N kernel workers each
 *                                    running an integer hot loop;
 *                                    main shell waits SECS then
 *                                    flags them to exit
 *   loadtest mem    [MIB] [SECS]   — KMalloc + touch every page of
 *                                    MIB MiB through the kernel heap;
 *                                    hold for SECS, then KFree
 *   loadtest mix    [SECS] [N] [MIB] — cpu + mem at the same time
 *
 * Defaults: SECS=5 (cap 60), N=2 (cap 8), MIB=4 (cap = 50 % of
 * current free heap, never more than 64 MiB).
 *
 * Admin-gated. Sustained CPU saturation by an unprivileged user
 * is a soft DoS against every other task on a single-CPU box, and
 * deliberate OOM through the kernel heap could starve drivers
 * mid-allocation.
 *
 * Diagnostic discipline (see CLAUDE.md "Diagnostic Logging"):
 * - The summary line at completion uses KLOG_INFO so a grep of
 *   the boot log shows that loadtest ran and how it ended.
 * - Per-iteration counters stay in TU-static state and are emitted
 *   only when a mode finishes — no per-tick spam.
 *
 * Single-CPU note: v0 scheduler is single-CPU, so N CPU workers
 * compete for one core via round-robin. The signal is "did the
 * scheduler stay fair / did the shell stay responsive while N
 * busy loops fought for slots", not "wall-clock parallel work".
 */

#include "shell/shell.h"
#include "shell/shell_internal.h"

#include "arch/x86_64/cpu.h"
#include "drivers/video/console.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// ------------------------------------------------------------------
// Knobs.
// ------------------------------------------------------------------
constexpr u32 kDefaultSecs = 5;
constexpr u32 kMaxSecs = 60;
constexpr u32 kDefaultCpuWorkers = 2;
constexpr u32 kMaxCpuWorkers = 8;
constexpr u32 kDefaultMemMiB = 4;
constexpr u32 kHardMemCapMiB = 64;
// Per-iteration inner loop. Tuned so each pass is a few microseconds
// on a modern CPU — the worker checks the stop flag often enough
// that ^C / deadline shutdown is responsive without flooding the
// scheduler with reschedule requests.
constexpr u64 kCpuInnerLoop = 4096;
// Memory chunk size: 64 KiB chunks let us touch every 4 KiB page
// without splaying the heap into thousands of tiny chunks.
constexpr u64 kMemChunkBytes = 64ULL * 1024;

// ------------------------------------------------------------------
// Worker bookkeeping. Single-CPU; protect the few mutating fields
// with an interrupt-disabled bracket on the writer side.
// ------------------------------------------------------------------
struct CpuWorker
{
    bool active;
    bool stop;
    u64 iterations;
    u64 sink; // dependency sink so the optimiser cannot DCE the loop
};

CpuWorker g_workers[kMaxCpuWorkers] = {};
u32 g_active_workers = 0;
u64 g_mem_held_bytes = 0;

// Volatile so the worker doesn't hoist the load; we don't need a
// full atomic on a single-CPU kernel — the timer IRQ is the only
// concurrency vector.
inline volatile bool* StopFlag(u32 i)
{
    return reinterpret_cast<volatile bool*>(&g_workers[i].stop);
}

void CpuBurnerEntry(void* arg)
{
    const u32 idx = static_cast<u32>(reinterpret_cast<uptr>(arg));
    if (idx >= kMaxCpuWorkers)
    {
        duetos::sched::SchedExit();
    }
    u64 acc = 0xCAFEBABE12345678ULL;
    while (!*StopFlag(idx))
    {
        // Cheap mixing loop. xorshift + multiply keeps the ALU busy
        // and produces a value the compiler cannot fold away because
        // we feed it back into the sink each pass.
        for (u64 j = 0; j < kCpuInnerLoop; ++j)
        {
            acc ^= acc << 13;
            acc ^= acc >> 7;
            acc ^= acc << 17;
            acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
        }
        ++g_workers[idx].iterations;
        g_workers[idx].sink ^= acc;
    }
    duetos::arch::Cli();
    g_workers[idx].active = false;
    if (g_active_workers > 0)
    {
        --g_active_workers;
    }
    duetos::arch::Sti();
    duetos::sched::SchedExit();
}

// ------------------------------------------------------------------
// Argument parsing helpers — accept positive decimal integers only,
// with a sentinel-on-error contract that lets every mode share one
// validation pattern.
// ------------------------------------------------------------------
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

u32 ClampSecs(u32 v)
{
    if (v == 0)
    {
        return 1;
    }
    return (v > kMaxSecs) ? kMaxSecs : v;
}

// ------------------------------------------------------------------
// CPU mode shared driver.
//
// Spawns `n` CPU-burner workers and waits `secs` seconds, polling
// ^C every 100 ms (one tick) so the operator can abort. Cleans up
// by setting the stop flag on every worker; the workers self-exit
// on their next loop iteration. Returns once every worker has
// flipped active=false.
// ------------------------------------------------------------------
void RunCpuLoad(u32 secs, u32 workers, bool also_mem, u32 mib)
{
    if (workers == 0)
    {
        workers = 1;
    }
    if (workers > kMaxCpuWorkers)
    {
        workers = kMaxCpuWorkers;
    }
    secs = ClampSecs(secs);

    // Reset bookkeeping for the slots we're about to use.
    duetos::arch::Cli();
    for (u32 i = 0; i < workers; ++i)
    {
        g_workers[i].active = true;
        g_workers[i].stop = false;
        g_workers[i].iterations = 0;
        g_workers[i].sink = 0;
    }
    g_active_workers = workers;
    duetos::arch::Sti();

    ConsoleWrite("LOADTEST: spawning ");
    WriteU64Dec(workers);
    ConsoleWrite(" CPU worker(s) for ");
    WriteU64Dec(secs);
    ConsoleWriteln(" s");

    static const char* const kNames[kMaxCpuWorkers] = {"loadtest-cpu0", "loadtest-cpu1", "loadtest-cpu2",
                                                       "loadtest-cpu3", "loadtest-cpu4", "loadtest-cpu5",
                                                       "loadtest-cpu6", "loadtest-cpu7"};
    for (u32 i = 0; i < workers; ++i)
    {
        duetos::sched::SchedCreate(CpuBurnerEntry, reinterpret_cast<void*>(static_cast<uptr>(i)), kNames[i]);
    }

    // Optional concurrent memory load. Allocate up front so the
    // CPU workers compete with a real memory footprint; hold until
    // the timed wait below completes.
    void* mem_chunks[kHardMemCapMiB * 16] = {}; // 16 chunks per MiB at 64 KiB each
    u32 chunks_held = 0;
    if (also_mem && mib > 0)
    {
        const u64 want_bytes = static_cast<u64>(mib) * 1024ULL * 1024ULL;
        const u64 want_chunks = want_bytes / kMemChunkBytes;
        for (u64 c = 0; c < want_chunks; ++c)
        {
            void* p = duetos::mm::KMalloc(kMemChunkBytes);
            if (p == nullptr)
            {
                ConsoleWriteln("LOADTEST: heap exhausted before target — continuing with what we have");
                break;
            }
            // Touch every page so the allocator's bookkeeping is
            // genuinely committed (and any future demand-paged path
            // gets exercised). Single byte per page is enough to
            // dirty the line.
            char* bytes = static_cast<char*>(p);
            for (u64 off = 0; off < kMemChunkBytes; off += duetos::mm::kPageSize)
            {
                bytes[off] = static_cast<char>((c + off) & 0xFF);
            }
            mem_chunks[chunks_held++] = p;
        }
        g_mem_held_bytes = static_cast<u64>(chunks_held) * kMemChunkBytes;
        ConsoleWrite("LOADTEST: holding ");
        WriteU64Dec(g_mem_held_bytes / 1024);
        ConsoleWriteln(" KiB across the test window");
    }

    // Snapshot scheduler stats so we can show the delta at exit.
    const auto before = duetos::sched::SchedStatsRead();
    const u64 t_start = duetos::sched::SchedNowTicks();

    // Wait window. 100 Hz scheduler tick → 100 ticks per second.
    // Sleep one tick at a time so ^C latency is bounded to ~10 ms.
    bool aborted = false;
    for (u32 ticks = 0; ticks < secs * 100; ++ticks)
    {
        if (ShellInterruptRequested())
        {
            aborted = true;
            break;
        }
        duetos::sched::SchedSleepTicks(1);
    }

    // Tear down CPU workers.
    for (u32 i = 0; i < workers; ++i)
    {
        *StopFlag(i) = true;
    }
    // Wait for every worker to flip active=false. Cap at one extra
    // second so a hung worker can't pin the shell forever — at that
    // point we log it and return; the worker will eventually exit
    // on its own when the next loop iteration sees the stop flag.
    for (u32 ticks = 0; ticks < 100; ++ticks)
    {
        bool any = false;
        for (u32 i = 0; i < workers; ++i)
        {
            if (g_workers[i].active)
            {
                any = true;
                break;
            }
        }
        if (!any)
        {
            break;
        }
        duetos::sched::SchedSleepTicks(1);
    }

    const u64 t_end = duetos::sched::SchedNowTicks();
    const auto after = duetos::sched::SchedStatsRead();

    // Free held memory.
    if (chunks_held > 0)
    {
        for (u32 i = 0; i < chunks_held; ++i)
        {
            duetos::mm::KFree(mem_chunks[i]);
            mem_chunks[i] = nullptr;
        }
        g_mem_held_bytes = 0;
    }

    // Summary.
    u64 total_iters = 0;
    for (u32 i = 0; i < workers; ++i)
    {
        total_iters += g_workers[i].iterations;
    }
    ConsoleWriteln(aborted ? "LOADTEST: ^C — stopped early" : "LOADTEST: window complete");
    ConsoleWrite("  workers:        ");
    WriteU64Dec(workers);
    ConsoleWriteChar('\n');
    ConsoleWrite("  elapsed ticks:  ");
    WriteU64Dec(t_end - t_start);
    ConsoleWriteChar('\n');
    ConsoleWrite("  iterations:     ");
    WriteU64Dec(total_iters);
    ConsoleWrite(" (each = ");
    WriteU64Dec(kCpuInnerLoop);
    ConsoleWriteln(" inner ops)");
    ConsoleWrite("  ctx switches:   ");
    WriteU64Dec(after.context_switches - before.context_switches);
    ConsoleWriteChar('\n');
    ConsoleWrite("  idle ticks:     ");
    WriteU64Dec(after.idle_ticks - before.idle_ticks);
    ConsoleWriteChar('\n');
    if (also_mem)
    {
        ConsoleWrite("  mem held:       ");
        WriteU64Dec(static_cast<u64>(chunks_held) * kMemChunkBytes / 1024);
        ConsoleWriteln(" KiB");
    }

    KLOG_INFO_V("loadtest", "cpu mode complete; workers=", workers);
}

// ------------------------------------------------------------------
// Memory mode — dedicated path that does NOT spawn CPU workers.
// Allocates `mib` MiB through KMalloc in 64 KiB chunks, touches
// every page, holds for `secs` seconds, then frees. Reports peak
// heap usage delta + free-frame delta so the operator can confirm
// the allocation actually landed and was returned cleanly.
// ------------------------------------------------------------------
void RunMemLoad(u32 mib, u32 secs)
{
    if (mib == 0)
    {
        ConsoleWriteln("LOADTEST: mem MiB must be > 0");
        return;
    }
    if (mib > kHardMemCapMiB)
    {
        ConsoleWrite("LOADTEST: capping request to ");
        WriteU64Dec(kHardMemCapMiB);
        ConsoleWriteln(" MiB hard ceiling");
        mib = kHardMemCapMiB;
    }
    secs = ClampSecs(secs);

    // Soft cap at 50 % of current free heap so a deliberately
    // oversized request can't starve the rest of the kernel.
    const auto pre_heap = duetos::mm::KernelHeapStatsRead();
    const u64 soft_cap_bytes = pre_heap.free_bytes / 2;
    u64 want_bytes = static_cast<u64>(mib) * 1024ULL * 1024ULL;
    if (want_bytes > soft_cap_bytes)
    {
        want_bytes = soft_cap_bytes;
        ConsoleWrite("LOADTEST: soft-capping at 50%% of free heap (");
        WriteU64Dec(soft_cap_bytes / 1024);
        ConsoleWriteln(" KiB)");
    }
    const u64 want_chunks = want_bytes / kMemChunkBytes;

    void* mem_chunks[kHardMemCapMiB * 16] = {};
    u32 chunks_held = 0;
    const u64 free_frames_before = duetos::mm::FreeFramesCount();

    ConsoleWrite("LOADTEST: allocating ");
    WriteU64Dec(want_chunks);
    ConsoleWrite(" x 64 KiB chunks (");
    WriteU64Dec(want_bytes / 1024);
    ConsoleWriteln(" KiB target)");

    for (u64 c = 0; c < want_chunks; ++c)
    {
        void* p = duetos::mm::KMalloc(kMemChunkBytes);
        if (p == nullptr)
        {
            ConsoleWrite("LOADTEST: KMalloc returned null at chunk ");
            WriteU64Dec(c);
            ConsoleWriteln(" — heap exhausted");
            break;
        }
        char* bytes = static_cast<char*>(p);
        for (u64 off = 0; off < kMemChunkBytes; off += duetos::mm::kPageSize)
        {
            bytes[off] = static_cast<char>((c + off) & 0xFF);
        }
        mem_chunks[chunks_held++] = p;
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("LOADTEST: ^C during alloc — stopping fill, freeing now");
            break;
        }
    }
    g_mem_held_bytes = static_cast<u64>(chunks_held) * kMemChunkBytes;

    const auto mid_heap = duetos::mm::KernelHeapStatsRead();
    ConsoleWrite("LOADTEST: held ");
    WriteU64Dec(g_mem_held_bytes / 1024);
    ConsoleWrite(" KiB; heap used now ");
    WriteU64Dec(mid_heap.used_bytes / 1024);
    ConsoleWriteln(" KiB");

    // Hold window with ^C polling.
    for (u32 ticks = 0; ticks < secs * 100; ++ticks)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("LOADTEST: ^C during hold — releasing");
            break;
        }
        duetos::sched::SchedSleepTicks(1);
    }

    // Free in reverse order — exercises the coalescing path more
    // visibly than forward order, since adjacent chunks are
    // generally allocated contiguously by the first-fit allocator.
    for (u32 i = chunks_held; i > 0; --i)
    {
        duetos::mm::KFree(mem_chunks[i - 1]);
        mem_chunks[i - 1] = nullptr;
    }
    g_mem_held_bytes = 0;

    const auto post_heap = duetos::mm::KernelHeapStatsRead();
    const u64 free_frames_after = duetos::mm::FreeFramesCount();

    ConsoleWriteln("LOADTEST: mem complete");
    ConsoleWrite("  chunks held:      ");
    WriteU64Dec(chunks_held);
    ConsoleWriteChar('\n');
    ConsoleWrite("  heap used pre:    ");
    WriteU64Dec(pre_heap.used_bytes / 1024);
    ConsoleWriteln(" KiB");
    ConsoleWrite("  heap used peak:   ");
    WriteU64Dec(mid_heap.used_bytes / 1024);
    ConsoleWriteln(" KiB");
    ConsoleWrite("  heap used post:   ");
    WriteU64Dec(post_heap.used_bytes / 1024);
    ConsoleWriteln(" KiB");
    ConsoleWrite("  largest free run: ");
    WriteU64Dec(post_heap.largest_free_run / 1024);
    ConsoleWriteln(" KiB");
    if (free_frames_after != free_frames_before)
    {
        // A frame-count delta after a clean free means the heap
        // grew its backing pool — fine, but worth surfacing so an
        // operator can correlate with frame-allocator stats.
        ConsoleWrite("  frame delta:      ");
        WriteI64Dec(static_cast<i64>(free_frames_after) - static_cast<i64>(free_frames_before));
        ConsoleWriteChar('\n');
    }
    KLOG_INFO_V("loadtest", "mem mode complete; chunks=", chunks_held);
}

// ------------------------------------------------------------------
// Spin mode — busy-loop the shell task itself for `secs` seconds,
// polling ^C every iteration. This is the simplest stability probe:
// no spawn, no allocation, just "can the shell yield + observe its
// own clock under sustained CPU use".
// ------------------------------------------------------------------
void RunSpin(u32 secs)
{
    secs = ClampSecs(secs);
    const u64 t_start = duetos::sched::SchedNowTicks();
    const u64 deadline = t_start + secs * 100;
    ConsoleWrite("LOADTEST: spinning shell task for ");
    WriteU64Dec(secs);
    ConsoleWriteln(" s (^C aborts)");
    u64 acc = 0xDEADBEEFCAFEBABEULL;
    u64 passes = 0;
    while (duetos::sched::SchedNowTicks() < deadline)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("LOADTEST: ^C — spin aborted");
            break;
        }
        for (u64 j = 0; j < kCpuInnerLoop; ++j)
        {
            acc ^= acc << 13;
            acc ^= acc >> 7;
            acc ^= acc << 17;
        }
        ++passes;
        // Yield once per outer pass so the timer tick still gets
        // a chance to drive scheduler bookkeeping; an unyielding
        // ring-0 loop would make ^C polling rely entirely on the
        // preemption path.
        duetos::sched::SchedYield();
    }
    ConsoleWrite("LOADTEST: spin done; passes=");
    WriteU64Dec(passes);
    ConsoleWrite(" sink=");
    WriteU64Hex(acc);
    ConsoleWriteChar('\n');
    KLOG_INFO_V("loadtest", "spin mode complete; passes=", passes);
}

void PrintStatus()
{
    duetos::arch::Cli();
    const u32 active = g_active_workers;
    const u64 held = g_mem_held_bytes;
    duetos::arch::Sti();
    ConsoleWrite("LOADTEST status:  workers=");
    WriteU64Dec(active);
    ConsoleWrite("  mem_held=");
    WriteU64Dec(held / 1024);
    ConsoleWriteln(" KiB");
}

void PrintUsage()
{
    ConsoleWriteln("LOADTEST: stress the box for stability testing");
    ConsoleWriteln("  loadtest                       — this help");
    ConsoleWriteln("  loadtest status                — live workers + held bytes");
    ConsoleWriteln("  loadtest spin   [SECS]         — busy-loop shell task");
    ConsoleWriteln("  loadtest cpu    [SECS] [N]     — N CPU workers (cap 8)");
    ConsoleWriteln("  loadtest mem    [MIB] [SECS]   — KMalloc + touch MIB MiB");
    ConsoleWriteln("  loadtest mix    [SECS] [N] [MIB] — cpu + mem combined");
    ConsoleWriteln("  defaults: SECS=5 (cap 60), N=2 (cap 8), MIB=4 (cap 64)");
    ConsoleWriteln("  ^C aborts any mode mid-run");
}

} // namespace

void CmdLoadTest(u32 argc, char** argv)
{
    if (!RequireAdmin("LOADTEST"))
    {
        return;
    }
    if (argc < 2)
    {
        PrintUsage();
        return;
    }
    const char* sub = argv[1];

    if (StrEq(sub, "status"))
    {
        PrintStatus();
        return;
    }
    if (StrEq(sub, "help") || StrEq(sub, "-h") || StrEq(sub, "--help"))
    {
        PrintUsage();
        return;
    }

    if (StrEq(sub, "spin"))
    {
        u32 secs = kDefaultSecs;
        if (argc >= 3 && !ParseU32(argv[2], &secs))
        {
            ConsoleWriteln("LOADTEST: bad SECS");
            return;
        }
        RunSpin(secs);
        return;
    }

    if (StrEq(sub, "cpu"))
    {
        u32 secs = kDefaultSecs;
        u32 n = kDefaultCpuWorkers;
        if (argc >= 3 && !ParseU32(argv[2], &secs))
        {
            ConsoleWriteln("LOADTEST: bad SECS");
            return;
        }
        if (argc >= 4 && !ParseU32(argv[3], &n))
        {
            ConsoleWriteln("LOADTEST: bad N");
            return;
        }
        RunCpuLoad(secs, n, false, 0);
        return;
    }

    if (StrEq(sub, "mem"))
    {
        u32 mib = kDefaultMemMiB;
        u32 secs = kDefaultSecs;
        if (argc >= 3 && !ParseU32(argv[2], &mib))
        {
            ConsoleWriteln("LOADTEST: bad MIB");
            return;
        }
        if (argc >= 4 && !ParseU32(argv[3], &secs))
        {
            ConsoleWriteln("LOADTEST: bad SECS");
            return;
        }
        RunMemLoad(mib, secs);
        return;
    }

    if (StrEq(sub, "mix"))
    {
        u32 secs = kDefaultSecs;
        u32 n = kDefaultCpuWorkers;
        u32 mib = kDefaultMemMiB;
        if (argc >= 3 && !ParseU32(argv[2], &secs))
        {
            ConsoleWriteln("LOADTEST: bad SECS");
            return;
        }
        if (argc >= 4 && !ParseU32(argv[3], &n))
        {
            ConsoleWriteln("LOADTEST: bad N");
            return;
        }
        if (argc >= 5 && !ParseU32(argv[4], &mib))
        {
            ConsoleWriteln("LOADTEST: bad MIB");
            return;
        }
        if (mib > kHardMemCapMiB)
        {
            mib = kHardMemCapMiB;
        }
        RunCpuLoad(secs, n, true, mib);
        return;
    }

    ConsoleWrite("LOADTEST: unknown subcommand: ");
    ConsoleWriteln(sub);
    PrintUsage();
}

} // namespace duetos::core::shell::internal
