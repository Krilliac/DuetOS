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
 * No artificial caps in v1. The natural ceiling is the kernel
 * itself — the worker bookkeeping table, every kernel stack, and
 * every memory chunk are KMalloc'd, so the test stops the moment
 * any allocation fails. The handler reports what it actually
 * achieved instead of "I refused because the number was big."
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
#include "arch/x86_64/serial.h"
#include "drivers/video/console.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "util/compiler.h"

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
constexpr u32 kDefaultCpuWorkers = 2;
constexpr u32 kDefaultMemMiB = 4;
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
//
// The worker table is KMalloc'd at the start of each cpu/mix run
// and freed once every worker has exited. The size is set by the
// caller — the only ceiling is "what KMalloc can hand back."
// ------------------------------------------------------------------
struct CpuWorker
{
    bool active;
    bool stop;
    u64 iterations;
    u64 sink; // dependency sink so the optimiser cannot DCE the loop
};

CpuWorker* g_workers = nullptr;
u32 g_workers_count = 0;
u32 g_active_workers = 0;
u64 g_mem_held_bytes = 0;

// Volatile so the worker doesn't hoist the load; we don't need a
// full atomic on a single-CPU kernel — the timer IRQ is the only
// concurrency vector.
inline volatile bool* StopFlag(u32 i)
{
    return reinterpret_cast<volatile bool*>(&g_workers[i].stop);
}

DUETOS_NO_SANITIZE_WRAP void CpuBurnerEntry(void* arg)
{
    const u32 idx = static_cast<u32>(reinterpret_cast<uptr>(arg));
    if (g_workers == nullptr || idx >= g_workers_count)
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
// Argument parsing helpers.
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

// secs == 0 is treated as a typo — bumped to 1 so the test runs
// at least one tick. There is no upper bound: the operator can
// schedule a million-second test if they want; ^C still aborts.
u32 NormaliseSecs(u32 v)
{
    return (v == 0) ? 1u : v;
}

// ------------------------------------------------------------------
// Allocate the worker bookkeeping table. Size is whatever the
// caller asked for; if KMalloc can't deliver, the test reports it
// and gives up. Sets g_workers / g_workers_count on success.
// ------------------------------------------------------------------
bool AllocWorkerTable(u32 n)
{
    if (n == 0)
    {
        return false;
    }
    const u64 bytes = static_cast<u64>(n) * sizeof(CpuWorker);
    auto* table = static_cast<CpuWorker*>(duetos::mm::KMalloc(bytes));
    if (table == nullptr)
    {
        ConsoleWrite("LOADTEST: worker table KMalloc failed (need ");
        WriteU64Dec(bytes / 1024);
        ConsoleWriteln(" KiB) — try a smaller N");
        return false;
    }
    for (u32 i = 0; i < n; ++i)
    {
        table[i].active = false;
        table[i].stop = false;
        table[i].iterations = 0;
        table[i].sink = 0;
    }
    duetos::arch::Cli();
    g_workers = table;
    g_workers_count = n;
    g_active_workers = 0;
    duetos::arch::Sti();
    return true;
}

void FreeWorkerTable()
{
    duetos::arch::Cli();
    auto* p = g_workers;
    g_workers = nullptr;
    g_workers_count = 0;
    g_active_workers = 0;
    duetos::arch::Sti();
    if (p != nullptr)
    {
        duetos::mm::KFree(p);
    }
}

// ------------------------------------------------------------------
// Allocate the chunk-pointer table for memory-mode runs. One u64
// per held chunk; sized once at the top of the run since the
// chunk count is known up front.
// ------------------------------------------------------------------
void** AllocChunkTable(u64 want_chunks)
{
    if (want_chunks == 0)
    {
        return nullptr;
    }
    const u64 bytes = want_chunks * sizeof(void*);
    void** table = static_cast<void**>(duetos::mm::KMalloc(bytes));
    if (table == nullptr)
    {
        ConsoleWrite("LOADTEST: chunk table KMalloc failed (need ");
        WriteU64Dec(bytes / 1024);
        ConsoleWriteln(" KiB) — request too large for the heap");
        return nullptr;
    }
    for (u64 i = 0; i < want_chunks; ++i)
    {
        table[i] = nullptr;
    }
    return table;
}

// ------------------------------------------------------------------
// CPU mode shared driver.
//
// Spawns up to `workers` CPU-burner workers (whatever the heap
// can deliver — both the bookkeeping table and every kernel stack
// the scheduler allocates). Waits `secs` seconds, polling ^C every
// 100 ms so the operator can abort. Cleans up by setting the stop
// flag on every worker; workers self-exit on their next loop
// iteration.
// ------------------------------------------------------------------
void RunCpuLoad(u32 secs, u32 workers, bool also_mem, u32 mib)
{
    if (workers == 0)
    {
        workers = 1;
    }
    secs = NormaliseSecs(secs);

    if (!AllocWorkerTable(workers))
    {
        return;
    }

    // SerialLineGuard so the LOADTEST status line emits atomically
    // on COM1 — without it, peer CPUs spawning workers / sched-demo
    // workers running concurrently split this line across multiple
    // physical lines (observed 2026-05-22 under SMP=8 stress as
    // `LOADTEST: requesting 8 CPU worker(s) for [sched] 8C i=0x...`).
    // ConsoleWrite's framebuffer/capture/mirror paths run inside
    // WriteCharImpl per-byte and aren't held to the guard — that's
    // fine, those targets don't have a cross-CPU racy reader. Only
    // the serial path does.
    {
        duetos::arch::SerialLineGuard guard;
        ConsoleWrite("LOADTEST: requesting ");
        WriteU64Dec(workers);
        ConsoleWrite(" CPU worker(s) for ");
        WriteU64Dec(secs);
        ConsoleWriteln(" s");
    }

    // Spawn workers one by one. Each SchedCreate allocates a kernel
    // stack — at some N the kstack allocator returns null and we
    // stop, recording how many actually launched. Set active=true
    // only on success so the cleanup-wait loop doesn't hang on
    // slots that never spawned.
    u32 spawned = 0;
    for (u32 i = 0; i < workers; ++i)
    {
        duetos::arch::Cli();
        g_workers[i].active = true;
        ++g_active_workers;
        duetos::arch::Sti();
        auto* t =
            duetos::sched::SchedCreate(CpuBurnerEntry, reinterpret_cast<void*>(static_cast<uptr>(i)), "loadtest-cpu");
        if (t == nullptr)
        {
            duetos::arch::Cli();
            g_workers[i].active = false;
            if (g_active_workers > 0)
            {
                --g_active_workers;
            }
            duetos::arch::Sti();
            ConsoleWrite("LOADTEST: SchedCreate failed at worker ");
            WriteU64Dec(i);
            ConsoleWriteln(" — kstack/heap exhausted");
            break;
        }
        ++spawned;
    }
    {
        duetos::arch::SerialLineGuard guard;
        ConsoleWrite("LOADTEST: spawned ");
        WriteU64Dec(spawned);
        ConsoleWrite(" / ");
        WriteU64Dec(workers);
        ConsoleWriteln(" worker(s)");
    }

    // Optional concurrent memory load. No soft cap — KMalloc OOM is
    // the natural ceiling. The chunk-pointer table itself goes through
    // KMalloc, so a request that's too large to even index will fail
    // up-front before any chunk is touched.
    void** mem_chunks = nullptr;
    u64 chunks_held = 0;
    if (also_mem && mib > 0)
    {
        const u64 want_bytes = static_cast<u64>(mib) * 1024ULL * 1024ULL;
        const u64 want_chunks = want_bytes / kMemChunkBytes;
        mem_chunks = AllocChunkTable(want_chunks);
        if (mem_chunks != nullptr)
        {
            for (u64 c = 0; c < want_chunks; ++c)
            {
                void* p = duetos::mm::KMalloc(kMemChunkBytes);
                if (p == nullptr)
                {
                    ConsoleWrite("LOADTEST: mix mem KMalloc returned null at chunk ");
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
            }
            g_mem_held_bytes = chunks_held * kMemChunkBytes;
            ConsoleWrite("LOADTEST: holding ");
            WriteU64Dec(g_mem_held_bytes / 1024);
            ConsoleWriteln(" KiB across the test window");
        }
    }

    // Snapshot scheduler stats so we can show the delta at exit.
    const auto before = duetos::sched::SchedStatsRead();
    const u64 t_start = duetos::sched::SchedNowTicks();

    // Wait window. 100 Hz scheduler tick → 100 ticks per second.
    // Use a u64 to allow huge SECS without overflow.
    const u64 total_ticks_to_wait = static_cast<u64>(secs) * 100ULL;
    bool aborted = false;
    for (u64 ticks = 0; ticks < total_ticks_to_wait; ++ticks)
    {
        if (ShellInterruptRequested())
        {
            aborted = true;
            break;
        }
        duetos::sched::SchedSleepTicks(1);
    }

    // Tear down CPU workers.
    for (u32 i = 0; i < g_workers_count; ++i)
    {
        *StopFlag(i) = true;
    }
    // Wait for every worker to flip active=false. Cap the wait at one
    // extra second per spawned worker so a hung worker can't pin the
    // shell forever — at that point we log it and return; the worker
    // will eventually exit on its own when its next iteration sees
    // the stop flag.
    const u64 cleanup_budget = 100ULL + static_cast<u64>(spawned) * 10ULL;
    for (u64 ticks = 0; ticks < cleanup_budget; ++ticks)
    {
        bool any = false;
        for (u32 i = 0; i < g_workers_count; ++i)
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

    // Summary while the worker table is still mapped (we read
    // iterations + sink before freeing it).
    u64 total_iters = 0;
    for (u32 i = 0; i < g_workers_count; ++i)
    {
        total_iters += g_workers[i].iterations;
    }
    // Atomic summary block — `boot-log-analyze.sh`'s STRESS section
    // greps each "workers spawned: N" / "iterations: N" / etc. line
    // as a structural sentinel, so splitting any of them under
    // peer-CPU contention breaks the analyzer's pattern match.
    {
        duetos::arch::SerialLineGuard guard;
        ConsoleWriteln(aborted ? "LOADTEST: ^C — stopped early" : "LOADTEST: window complete");
        ConsoleWrite("  workers spawned: ");
        WriteU64Dec(spawned);
        ConsoleWriteChar('\n');
        ConsoleWrite("  elapsed ticks:   ");
        WriteU64Dec(t_end - t_start);
        ConsoleWriteChar('\n');
        ConsoleWrite("  iterations:      ");
        WriteU64Dec(total_iters);
        ConsoleWrite(" (each = ");
        WriteU64Dec(kCpuInnerLoop);
        ConsoleWriteln(" inner ops)");
        ConsoleWrite("  ctx switches:    ");
        WriteU64Dec(after.context_switches - before.context_switches);
        ConsoleWriteChar('\n');
        ConsoleWrite("  idle ticks:      ");
        WriteU64Dec(after.idle_ticks - before.idle_ticks);
        ConsoleWriteChar('\n');
        if (also_mem)
        {
            ConsoleWrite("  mem held:        ");
            WriteU64Dec(chunks_held * kMemChunkBytes / 1024);
            ConsoleWriteln(" KiB");
        }
    }

    // Free held memory + the chunk table.
    if (mem_chunks != nullptr)
    {
        for (u64 i = 0; i < chunks_held; ++i)
        {
            duetos::mm::KFree(mem_chunks[i]);
            mem_chunks[i] = nullptr;
        }
        duetos::mm::KFree(mem_chunks);
        g_mem_held_bytes = 0;
    }

    FreeWorkerTable();
    KLOG_INFO_V("loadtest", "cpu mode complete; spawned=", spawned);
}

// ------------------------------------------------------------------
// Memory mode — dedicated path that does NOT spawn CPU workers.
// Allocates `mib` MiB through KMalloc in 64 KiB chunks, touches
// every page, holds for `secs` seconds, then frees. No artificial
// cap; the heap's own OOM stops the fill. Reports peak heap usage
// + free-frame delta so the operator can confirm the allocation
// landed and was returned cleanly.
// ------------------------------------------------------------------
void RunMemLoad(u32 mib, u32 secs)
{
    if (mib == 0)
    {
        ConsoleWriteln("LOADTEST: mem MiB must be > 0");
        return;
    }
    secs = NormaliseSecs(secs);

    const auto pre_heap = duetos::mm::KernelHeapStatsRead();
    const u64 want_bytes = static_cast<u64>(mib) * 1024ULL * 1024ULL;
    const u64 want_chunks = want_bytes / kMemChunkBytes;

    void** mem_chunks = AllocChunkTable(want_chunks);
    if (mem_chunks == nullptr)
    {
        return;
    }

    u64 chunks_held = 0;
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
    g_mem_held_bytes = chunks_held * kMemChunkBytes;

    const auto mid_heap = duetos::mm::KernelHeapStatsRead();
    ConsoleWrite("LOADTEST: held ");
    WriteU64Dec(g_mem_held_bytes / 1024);
    ConsoleWrite(" KiB; heap used now ");
    WriteU64Dec(mid_heap.used_bytes / 1024);
    ConsoleWriteln(" KiB");

    // Hold window with ^C polling. u64 tick counter so a million-
    // second hold doesn't wrap.
    const u64 total_ticks_to_wait = static_cast<u64>(secs) * 100ULL;
    for (u64 ticks = 0; ticks < total_ticks_to_wait; ++ticks)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("LOADTEST: ^C during hold — releasing");
            break;
        }
        duetos::sched::SchedSleepTicks(1);
    }

    // Free in reverse order — exercises the coalescing path more
    // visibly than forward order.
    for (u64 i = chunks_held; i > 0; --i)
    {
        duetos::mm::KFree(mem_chunks[i - 1]);
        mem_chunks[i - 1] = nullptr;
    }
    duetos::mm::KFree(mem_chunks);
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
        ConsoleWrite("  frame delta:      ");
        WriteI64Dec(static_cast<i64>(free_frames_after) - static_cast<i64>(free_frames_before));
        ConsoleWriteChar('\n');
    }
    KLOG_INFO_V("loadtest", "mem mode complete; chunks=", chunks_held);
}

// ------------------------------------------------------------------
// Spin mode — busy-loop the shell task itself for `secs` seconds,
// polling ^C every iteration.
// ------------------------------------------------------------------
DUETOS_NO_SANITIZE_WRAP void RunSpin(u32 secs)
{
    secs = NormaliseSecs(secs);
    const u64 t_start = duetos::sched::SchedNowTicks();
    const u64 deadline = t_start + static_cast<u64>(secs) * 100ULL;
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
        // a chance to drive scheduler bookkeeping.
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
    ConsoleWriteln("LOADTEST: stress the box for stability testing (uncapped)");
    ConsoleWriteln("  loadtest                       — this help");
    ConsoleWriteln("  loadtest status                — live workers + held bytes");
    ConsoleWriteln("  loadtest spin   [SECS]         — busy-loop shell task");
    ConsoleWriteln("  loadtest cpu    [SECS] [N]     — N CPU workers (heap-bounded)");
    ConsoleWriteln("  loadtest mem    [MIB] [SECS]   — KMalloc + touch MIB MiB (heap-bounded)");
    ConsoleWriteln("  loadtest mix    [SECS] [N] [MIB] — cpu + mem combined");
    ConsoleWriteln("  defaults: SECS=5, N=2, MIB=4");
    ConsoleWriteln("  no artificial caps — KMalloc OOM and SchedCreate failure are the ceiling");
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
        RunCpuLoad(secs, n, true, mib);
        return;
    }

    ConsoleWrite("LOADTEST: unknown subcommand: ");
    ConsoleWriteln(sub);
    PrintUsage();
}

// Boot-time stress driver entry points. Used by kernel/diag/stress_driver.cpp
// to drive the same code paths the shell's `loadtest` command exercises,
// without going through the interactive shell or the admin gate (which has
// no user logged in this early). Functions in the anon namespace above are
// visible here because they share the TU; this layer just renames them for
// callers that aren't shell-internal. The serial tee carries every
// ConsoleWrite line, so a headless boot leaves a full transcript behind.
void StressDriverCpu(u32 secs, u32 workers)
{
    RunCpuLoad(secs, workers, false, 0);
}

void StressDriverMem(u32 mib, u32 secs)
{
    RunMemLoad(mib, secs);
}

void StressDriverMix(u32 secs, u32 workers, u32 mib)
{
    RunCpuLoad(secs, workers, true, mib);
}

void StressDriverSpin(u32 secs)
{
    RunSpin(secs);
}

} // namespace duetos::core::shell::internal
