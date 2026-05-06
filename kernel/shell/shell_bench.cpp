/*
 * DuetOS — kernel shell: bench command.
 *
 * Sibling TU of shell_loadtest.cpp. Where loadtest STRESSES the kernel
 * (sustained CPU + memory pressure to surface scheduler fairness, OOM
 * recovery, ^C responsiveness), bench MEASURES specific hot paths
 * under fixed workloads — cycles/op, ns/op, ops/sec — so an operator
 * can spot performance regressions or compare configurations.
 *
 * Modes:
 *   bench                     — usage
 *   bench kmalloc [ITERS]     — KMalloc(64) + KFree round-trip
 *   bench mutex   [ITERS]     — uncontended sched::Mutex acquire/release
 *   bench syscall [ITERS]     — SyscallDispatch(SYS_GETPID) — measures
 *                               the dispatcher path minus trap entry/exit
 *                               (kernel-thread caller, no privilege
 *                               transition). Useful for catching
 *                               regressions in the dispatcher prologue
 *                               itself; the absolute number is lower
 *                               than a real ring-3 syscall would cost.
 *   bench wakeup  [ITERS]     — KEvent set/wait round-trip with the
 *                               worker pinned via SchedSetAffinity to
 *                               the next online CPU. On a single-CPU
 *                               box the worker stays here; the result
 *                               row is labelled `wakeup-same-cpu` so
 *                               the operator reads the number
 *                               correctly.
 *   bench all     [ITERS]     — runs every benchmark and prints a
 *                               formatted table.
 *
 * Defaults are tuned so each microbench completes in well under one
 * second on a modern CPU. Numbers come from `time::ReadTsc()` deltas
 * converted via `time::TscToNanos`. If TSC calibration didn't run
 * (no HPET at boot, or no invariant-TSC), `ns/op` is reported as 0
 * and a one-line WARN sentinel prints in the header.
 *
 * Admin-gated, same as loadtest — a tight CPU-bound loop spawning
 * worker tasks is a soft DoS on a busy box.
 *
 * Diagnostic discipline (see CLAUDE.md "Diagnostic Logging"):
 * - Each bench fires KLOG_INFO_V("shell/bench", "<name>", ns_per_op)
 *   on completion so a grep of the boot log surfaces every run with
 *   structured numbers — useful for CI smoke once a CI lane runs
 *   `bench all`.
 * - No per-iteration logging — that would dwarf the measurement.
 */

#include "shell/shell.h"
#include "shell/shell_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/traps.h"
#include "cpu/percpu.h"
#include "drivers/video/console.h"
#include "ipc/kevent.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "syscall/syscall.h"
#include "time/timekeeper.h"
#include "util/result.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// ------------------------------------------------------------------
// Per-bench iteration defaults. Tuned so a "well under one second"
// run completes on a modern x86_64 box. The wakeup bench is the
// outlier — every iteration crosses two ContextSwitches plus a
// reschedule-IPI on multi-CPU boxes — so its default is 100x lower.
// ------------------------------------------------------------------
constexpr u64 kDefaultKmallocIters = 100'000;
constexpr u64 kDefaultMutexIters = 100'000;
constexpr u64 kDefaultSyscallIters = 100'000;
constexpr u64 kDefaultWakeupIters = 10'000;
constexpr u64 kKmallocSize = 64;

struct BenchResult
{
    const char* name;
    u64 iters;
    u64 total_cycles;
    u64 ns_per_op;
};

// ------------------------------------------------------------------
// Local formatting helpers. The shell already exposes WriteU64Dec
// in shell_internal.h, but it doesn't pad — we want right-aligned
// columns for the bench table.
// ------------------------------------------------------------------
void WriteDecPadded(u64 value, u32 min_width)
{
    char buf[24];
    u32 len = 0;
    if (value == 0)
    {
        buf[len++] = '0';
    }
    else
    {
        u64 v = value;
        char rev[24];
        u32 rlen = 0;
        while (v > 0 && rlen < sizeof(rev))
        {
            rev[rlen++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        for (u32 i = 0; i < rlen; ++i)
        {
            buf[len++] = rev[rlen - 1 - i];
        }
    }
    for (u32 i = len; i < min_width; ++i)
    {
        ConsoleWriteChar(' ');
    }
    for (u32 i = 0; i < len; ++i)
    {
        ConsoleWriteChar(buf[i]);
    }
}

void WriteNamePadded(const char* s, u32 min_width)
{
    u32 len = 0;
    while (s[len] != '\0')
    {
        ConsoleWriteChar(s[len++]);
    }
    for (u32 i = len; i < min_width; ++i)
    {
        ConsoleWriteChar(' ');
    }
}

// ------------------------------------------------------------------
// Header. Prints column titles and (if relevant) a one-line WARN
// when TSC calibration is missing — ns columns will read 0 in that
// case but cycles columns are still meaningful as relative numbers.
// ------------------------------------------------------------------
void PrintHeader()
{
    if (!::duetos::time::TscCalibrated())
    {
        ConsoleWriteln("BENCH: WARN — TSC not calibrated; ns/op + ops/sec will read 0");
    }
    ConsoleWrite("benchmark           iters       cycles/op       ns/op        ops/sec\n");
}

void PrintRow(const BenchResult& r)
{
    WriteNamePadded(r.name, 20);
    WriteDecPadded(r.iters, 10);
    const u64 cycles_per_op = (r.iters > 0) ? (r.total_cycles / r.iters) : 0;
    WriteDecPadded(cycles_per_op, 16);
    WriteDecPadded(r.ns_per_op, 12);
    const u64 ops_per_sec = (r.ns_per_op > 0) ? (1'000'000'000ULL / r.ns_per_op) : 0;
    WriteDecPadded(ops_per_sec, 15);
    ConsoleWriteChar('\n');
}

// ------------------------------------------------------------------
// kmalloc bench — KMalloc(64) + KFree round-trip. The pointer goes
// into a volatile sink so the optimiser can't elide either call.
// ------------------------------------------------------------------
volatile void* g_sink = nullptr;

BenchResult RunKmalloc(u64 iters)
{
    BenchResult r{"kmalloc-64", iters, 0, 0};
    if (iters == 0)
    {
        return r;
    }
    const u64 t0 = ::duetos::time::ReadTsc();
    for (u64 i = 0; i < iters; ++i)
    {
        void* p = ::duetos::mm::KMalloc(kKmallocSize);
        g_sink = p;
        ::duetos::mm::KFree(p);
    }
    const u64 t1 = ::duetos::time::ReadTsc();
    r.total_cycles = t1 - t0;
    if (iters > 0)
    {
        r.ns_per_op = ::duetos::time::TscToNanos(r.total_cycles) / iters;
    }
    return r;
}

// ------------------------------------------------------------------
// mutex bench — uncontended sched::Mutex Lock/Unlock on a TU-static
// mutex. Measures the fast path: empty wait queue, immediate owner
// claim. The optimiser can't elide because MutexLock writes to the
// owner field which is read by every Mutex* op in the kernel.
// ------------------------------------------------------------------
::duetos::sched::Mutex g_bench_mutex{};

BenchResult RunMutex(u64 iters)
{
    BenchResult r{"mutex-uncontended", iters, 0, 0};
    if (iters == 0)
    {
        return r;
    }
    const u64 t0 = ::duetos::time::ReadTsc();
    for (u64 i = 0; i < iters; ++i)
    {
        ::duetos::sched::MutexLock(&g_bench_mutex);
        ::duetos::sched::MutexUnlock(&g_bench_mutex);
    }
    const u64 t1 = ::duetos::time::ReadTsc();
    r.total_cycles = t1 - t0;
    r.ns_per_op = ::duetos::time::TscToNanos(r.total_cycles) / iters;
    return r;
}

// ------------------------------------------------------------------
// syscall bench — call core::SyscallDispatch with a synthetic
// TrapFrame holding rax=SYS_GETPID. This measures the dispatcher's
// prologue (trail guard, log/trace stubs, cap gate, switch arm)
// PLUS the SYS_GETPID handler body (one CurrentTaskId() call). It
// does NOT include the trap entry/exit, GS swap, CR3 swap, or
// privilege transition that a real ring-3 syscall pays — those
// only have meaning when a userland process issues int 0x80.
// Useful for catching regressions in the dispatcher itself.
// ------------------------------------------------------------------
BenchResult RunSyscall(u64 iters)
{
    BenchResult r{"syscall-dispatch", iters, 0, 0};
    if (iters == 0)
    {
        return r;
    }
    ::duetos::arch::TrapFrame frame{};
    frame.rax = ::duetos::core::SYS_GETPID;
    const u64 t0 = ::duetos::time::ReadTsc();
    for (u64 i = 0; i < iters; ++i)
    {
        frame.rax = ::duetos::core::SYS_GETPID;
        ::duetos::core::SyscallDispatch(&frame);
        // frame.rax now holds CurrentTaskId(); read it through the
        // sink so the dispatcher call can't be DCE'd.
        g_sink = reinterpret_cast<void*>(frame.rax);
    }
    const u64 t1 = ::duetos::time::ReadTsc();
    r.total_cycles = t1 - t0;
    r.ns_per_op = ::duetos::time::TscToNanos(r.total_cycles) / iters;
    return r;
}

// ------------------------------------------------------------------
// wakeup bench — measures KEvent set/wait round-trip latency, with
// the worker thread (typically) on a peer CPU so each wakeup goes
// through TargetPerCpuFor + reschedule-IPI rather than the same-
// CPU fast path.
//
// Protocol per iteration:
//   shell:   KEventSet(go)            // wakes worker
//   worker:  KEventWait(go)           // wakes
//            KEventSet(done)          // wakes shell
//            (loops)
//   shell:   KEventWait(done)         // wakes
//
// Both events are auto-reset so each iteration consumes exactly
// one signal. The worker reads its iteration count from a shared
// volatile so it knows when to exit.
// ------------------------------------------------------------------
struct WakeupCtx
{
    ::duetos::ipc::KEvent* go;
    ::duetos::ipc::KEvent* done;
    volatile u64 remaining;
    volatile bool worker_exited;
};

void WakeupWorkerEntry(void* arg)
{
    auto* c = static_cast<WakeupCtx*>(arg);
    while (true)
    {
        ::duetos::ipc::KEventWait(c->go);
        if (c->remaining == 0)
        {
            break;
        }
        --c->remaining;
        ::duetos::ipc::KEventSet(c->done);
    }
    c->worker_exited = true;
    ::duetos::ipc::KEventSet(c->done); // unblock final shell wait
    ::duetos::sched::SchedExit();
}

BenchResult RunWakeup(u64 iters)
{
    const u32 online = static_cast<u32>(::duetos::arch::SmpCpusOnline());
    const u32 self_cpu = ::duetos::cpu::CurrentCpu()->cpu_id;
    bool cross_cpu = false;
    u32 peer_cpu = self_cpu;
    if (online > 1)
    {
        // Pick the next online CPU id, wrapping past self.
        peer_cpu = (self_cpu + 1) % online;
        cross_cpu = true;
    }
    BenchResult r{cross_cpu ? "wakeup-cross-cpu" : "wakeup-same-cpu", iters, 0, 0};
    if (iters == 0)
    {
        return r;
    }
    auto go_r = ::duetos::ipc::KEventCreate(/*manual_reset=*/false, /*initially_signaled=*/false);
    if (!go_r.has_value())
    {
        ConsoleWriteln("BENCH: KEventCreate(go) failed — heap exhausted");
        return r;
    }
    auto done_r = ::duetos::ipc::KEventCreate(/*manual_reset=*/false, /*initially_signaled=*/false);
    if (!done_r.has_value())
    {
        ConsoleWriteln("BENCH: KEventCreate(done) failed — heap exhausted");
        return r;
    }
    WakeupCtx ctx{};
    ctx.go = go_r.value();
    ctx.done = done_r.value();
    ctx.remaining = iters;
    ctx.worker_exited = false;

    auto* worker = ::duetos::sched::SchedCreate(WakeupWorkerEntry, &ctx, "bench-wake");
    if (worker == nullptr)
    {
        ConsoleWriteln("BENCH: SchedCreate(worker) failed — kstack/heap exhausted");
        return r;
    }
    if (cross_cpu)
    {
        // Hint the scheduler to route the worker's first wake onto
        // the peer CPU. After the first ContextSwitch the
        // scheduler's own last_cpu update keeps it pinned there
        // until something migrates it.
        ::duetos::sched::SchedSetAffinity(worker, peer_cpu);
    }

    const u64 t0 = ::duetos::time::ReadTsc();
    for (u64 i = 0; i < iters; ++i)
    {
        ::duetos::ipc::KEventSet(ctx.go);
        ::duetos::ipc::KEventWait(ctx.done);
    }
    const u64 t1 = ::duetos::time::ReadTsc();
    // Drain the worker. ctx.remaining is already 0; one more Set
    // tips it past the loop guard, the worker exits and signals
    // done one last time so we don't block here on a dead worker.
    ::duetos::ipc::KEventSet(ctx.go);
    ::duetos::ipc::KEventWait(ctx.done);

    r.total_cycles = t1 - t0;
    r.ns_per_op = ::duetos::time::TscToNanos(r.total_cycles) / iters;

    // KEvents are KObjects — release the references we hold from
    // KEventCreate so the kernel heap reclaims them.
    ::duetos::ipc::KObjectRelease(&ctx.go->base);
    ::duetos::ipc::KObjectRelease(&ctx.done->base);
    return r;
}

// ------------------------------------------------------------------
// Summary emit — one boot-log greppable line per bench. Uses
// KLOG_INFO_V so default log levels surface it; CI smoke can grep
// for "shell/bench" to confirm the harness ran.
// ------------------------------------------------------------------
void EmitSummary(const BenchResult& r)
{
    KLOG_INFO_V("shell/bench", r.name, r.ns_per_op);
}

void PrintUsage()
{
    ConsoleWriteln("BENCH: kernel hot-path microbenchmarks (admin)");
    ConsoleWriteln("  bench                       — this help");
    ConsoleWriteln("  bench kmalloc [ITERS]       — KMalloc(64) + KFree round-trip");
    ConsoleWriteln("  bench mutex   [ITERS]       — uncontended sched::Mutex acq/rel");
    ConsoleWriteln("  bench syscall [ITERS]       — SyscallDispatch(SYS_GETPID)");
    ConsoleWriteln("  bench wakeup  [ITERS]       — KEvent set/wait, worker on peer CPU");
    ConsoleWriteln("  bench all     [ITERS]       — run every benchmark, print table");
    ConsoleWrite("  defaults: kmalloc/mutex/syscall=");
    WriteDecPadded(kDefaultKmallocIters, 0);
    ConsoleWrite(", wakeup=");
    WriteDecPadded(kDefaultWakeupIters, 0);
    ConsoleWriteChar('\n');
    ConsoleWriteln("  reports cycles/op, ns/op, ops/sec; ^C is not honoured (loops are short)");
}

} // namespace

void CmdBench(u32 argc, char** argv)
{
    if (!RequireAdmin("BENCH"))
    {
        return;
    }
    if (argc < 2)
    {
        PrintUsage();
        return;
    }
    const char* sub = argv[1];

    if (StrEq(sub, "help") || StrEq(sub, "-h") || StrEq(sub, "--help"))
    {
        PrintUsage();
        return;
    }

    auto resolve_iters = [&](u64 fallback) -> u64
    {
        if (argc < 3)
        {
            return fallback;
        }
        u64 v = 0;
        if (!ParseU64Str(argv[2], &v) || v == 0)
        {
            ConsoleWriteln("BENCH: bad ITERS");
            return 0;
        }
        return v;
    };

    if (StrEq(sub, "kmalloc"))
    {
        const u64 iters = resolve_iters(kDefaultKmallocIters);
        if (iters == 0)
        {
            return;
        }
        PrintHeader();
        const auto r = RunKmalloc(iters);
        PrintRow(r);
        EmitSummary(r);
        return;
    }
    if (StrEq(sub, "mutex"))
    {
        const u64 iters = resolve_iters(kDefaultMutexIters);
        if (iters == 0)
        {
            return;
        }
        PrintHeader();
        const auto r = RunMutex(iters);
        PrintRow(r);
        EmitSummary(r);
        return;
    }
    if (StrEq(sub, "syscall"))
    {
        const u64 iters = resolve_iters(kDefaultSyscallIters);
        if (iters == 0)
        {
            return;
        }
        PrintHeader();
        const auto r = RunSyscall(iters);
        PrintRow(r);
        EmitSummary(r);
        return;
    }
    if (StrEq(sub, "wakeup"))
    {
        const u64 iters = resolve_iters(kDefaultWakeupIters);
        if (iters == 0)
        {
            return;
        }
        PrintHeader();
        const auto r = RunWakeup(iters);
        PrintRow(r);
        EmitSummary(r);
        return;
    }
    if (StrEq(sub, "all"))
    {
        const u64 iters_short = resolve_iters(kDefaultKmallocIters);
        if (iters_short == 0)
        {
            return;
        }
        // The wakeup bench costs ~100x per op vs the others; if the
        // operator passed an explicit ITERS, scale it down for the
        // wakeup row so the total run still completes promptly.
        const u64 iters_long = (argc >= 3) ? (iters_short / 10 + 1) : kDefaultWakeupIters;

        PrintHeader();
        BenchResult rows[4];
        rows[0] = RunKmalloc(iters_short);
        PrintRow(rows[0]);
        rows[1] = RunMutex(iters_short);
        PrintRow(rows[1]);
        rows[2] = RunSyscall(iters_short);
        PrintRow(rows[2]);
        rows[3] = RunWakeup(iters_long);
        PrintRow(rows[3]);
        for (const auto& r : rows)
        {
            EmitSummary(r);
        }
        KLOG_INFO("shell/bench", "all complete");
        return;
    }

    ConsoleWrite("BENCH: unknown subcommand: ");
    ConsoleWriteln(sub);
    PrintUsage();
}

} // namespace duetos::core::shell::internal
