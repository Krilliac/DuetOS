#include "runtime_checker.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/serial.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"
#include "../security/guard.h"
#include "klog.h"
#include "panic.h"

// __stack_chk_guard symbol is C-linkage.
extern "C" customos::u64 __stack_chk_guard;

namespace customos::core
{

namespace
{

HealthReport g_report = {};

// Baselines captured at boot. Each is the expected-set/clear
// state of a security-critical bit; drift from baseline counts
// as a finding. We capture instead of hardcoding because the
// boot init path itself is what sets these, and later slices
// may add/remove features — the baseline tracks whatever was
// active when the checker went live.
constinit u64 g_baseline_cr0 = 0;
constinit u64 g_baseline_cr4 = 0;
constinit u64 g_baseline_efer = 0;
constinit u64 g_baseline_idt_hash = 0;
constinit u64 g_baseline_gdt_hash = 0;
constinit u64 g_baseline_text_spot_hash = 0;

constexpr u64 kCr0Wp = 1ULL << 16;
constexpr u64 kCr4Smep = 1ULL << 20;
constexpr u64 kCr4Smap = 1ULL << 21;
constexpr u32 kMsrEfer = 0xC0000080;
constexpr u64 kEferNxe = 1ULL << 11;

// Sanity caps on scheduler state. Beyond these we flag the
// scan rather than panic — a runaway leak warrants visibility
// long before it DoS's the allocator.
constexpr u64 kSchedTasksLiveCap = 256;

// Heap fragmentation ceiling. More than 256 distinct free
// chunks with 2 MiB pool means the freelist has worn into
// splinters — probably a miscoalescing bug or a workload that
// churns many odd-sized allocations. Flag for investigation.
constexpr u64 kHeapFreelistFragmentationCap = 256;

// Grace period for the "timer is firing" heuristic. Scheduler
// tick starts ~100 ms into boot; we give it 500 ms before
// flagging "no context switches" as a real finding.
constexpr u64 kContextSwitchGraceTicks = 50; // 0.5 s @ 100 Hz

u64 ReadCr0()
{
    u64 v;
    asm volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}
u64 ReadCr4()
{
    u64 v;
    asm volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}
u64 ReadMsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (u64(hi) << 32) | lo;
}

// Issues that indicate the system's security posture has been
// degraded at the hardware level — a rootkit, a catastrophic
// driver bug, or a DoS attempt. Escalate the guard to Enforce
// on first observation so any subsequent image load is held to
// the stricter policy. Irreversible until the next reboot.
bool IsSecurityCritical(HealthIssue issue)
{
    switch (issue)
    {
    case HealthIssue::Cr0WpCleared:
    case HealthIssue::Cr4SmepCleared:
    case HealthIssue::Cr4SmapCleared:
    case HealthIssue::EferNxeCleared:
    case HealthIssue::IdtModified:
    case HealthIssue::GdtModified:
    case HealthIssue::KernelTextModified:
    case HealthIssue::StackCanaryZero:
    case HealthIssue::TaskStackOverflow:
    case HealthIssue::TaskRspOutOfRange:
        return true;
    default:
        return false;
    }
}

void Report(HealthIssue issue)
{
    const u32 idx = u32(issue);
    if (idx < u32(HealthIssue::Count))
    {
        ++g_report.per_issue_count[idx];
    }
    ++g_report.issues_found_total;
    g_report.last_issue = issue;
    Log(LogLevel::Warn, "health", HealthIssueName(issue));

    // Guard escalation. Any security-critical finding forces
    // the guard into Enforce mode so the next image load is
    // prompt-or-deny. A log line records the transition.
    if (IsSecurityCritical(issue) && security::GuardMode() != security::Mode::Enforce)
    {
        arch::SerialWrite("[health] ESCALATE: guard -> Enforce (critical finding)\n");
        security::SetGuardMode(security::Mode::Enforce);
    }
}

bool CheckHeap()
{
    const auto s = mm::KernelHeapStatsRead();
    bool ok = true;
    // pool ≈ used + free (headers eat a few bytes but the sum
    // should stay within ~0.1% of pool_bytes). We just check
    // that used + free doesn't EXCEED pool (that would mean
    // bookkeeping corruption where the counters disagree with
    // reality).
    if (s.used_bytes + s.free_bytes > s.pool_bytes + 4096)
    {
        Report(HealthIssue::HeapPoolMismatch);
        ok = false;
    }
    if (s.free_count > s.alloc_count)
    {
        Report(HealthIssue::HeapUnderflow);
        ok = false;
    }
    if (s.free_chunk_count == 0 && s.used_bytes < s.pool_bytes)
    {
        Report(HealthIssue::HeapFreelistEmpty);
        ok = false;
    }
    if (s.free_chunk_count > kHeapFreelistFragmentationCap)
    {
        Report(HealthIssue::HeapFragmentationHigh);
        ok = false;
    }
    return ok;
}

bool CheckFrames()
{
    const u64 total = mm::TotalFrames();
    const u64 free_ = mm::FreeFramesCount();
    bool ok = true;
    if (free_ > total)
    {
        Report(HealthIssue::FramesOverflow);
        ok = false;
    }
    if (total > 0 && free_ == 0)
    {
        Report(HealthIssue::FramesAllAllocated);
        ok = false;
    }
    return ok;
}

bool CheckSched()
{
    const auto s = sched::SchedStatsRead();
    bool ok = true;
    if (s.tasks_exited > s.tasks_created)
    {
        Report(HealthIssue::SchedExitedMoreThanCreated);
        ok = false;
    }
    if (s.tasks_reaped > s.tasks_exited)
    {
        Report(HealthIssue::SchedReapedMoreThanExited);
        ok = false;
    }
    if (s.tasks_live > kSchedTasksLiveCap)
    {
        Report(HealthIssue::SchedLiveUnreasonable);
        ok = false;
    }
    if (s.total_ticks > kContextSwitchGraceTicks && s.context_switches == 0)
    {
        Report(HealthIssue::SchedNoContextSwitches);
        ok = false;
    }
    return ok;
}

bool CheckControlRegisters()
{
    bool ok = true;
    const u64 cr0 = ReadCr0();
    const u64 cr4 = ReadCr4();
    const u64 efer = ReadMsr(kMsrEfer);
    // Only check bits that WERE set at baseline. If boot didn't
    // enable a feature (e.g. CPU without SMEP), we don't flag
    // its absence later.
    if ((g_baseline_cr0 & kCr0Wp) != 0 && (cr0 & kCr0Wp) == 0)
    {
        Report(HealthIssue::Cr0WpCleared);
        ok = false;
    }
    if ((g_baseline_cr4 & kCr4Smep) != 0 && (cr4 & kCr4Smep) == 0)
    {
        Report(HealthIssue::Cr4SmepCleared);
        ok = false;
    }
    if ((g_baseline_cr4 & kCr4Smap) != 0 && (cr4 & kCr4Smap) == 0)
    {
        Report(HealthIssue::Cr4SmapCleared);
        ok = false;
    }
    if ((g_baseline_efer & kEferNxe) != 0 && (efer & kEferNxe) == 0)
    {
        Report(HealthIssue::EferNxeCleared);
        ok = false;
    }
    return ok;
}

bool CheckCanary()
{
    if (__stack_chk_guard == 0)
    {
        Report(HealthIssue::StackCanaryZero);
        return false;
    }
    return true;
}

bool CheckIdt()
{
    const u64 now = arch::IdtHash();
    if (now != g_baseline_idt_hash)
    {
        Report(HealthIssue::IdtModified);
        return false;
    }
    return true;
}

bool CheckGdt()
{
    const u64 now = arch::GdtHash();
    if (now != g_baseline_gdt_hash)
    {
        Report(HealthIssue::GdtModified);
        return false;
    }
    return true;
}

// Kernel .text section spot-check. FNV-1a over the first and
// last 4 KiB of .text. NOT a full hash — that would take ~1 ms
// for a multi-MiB text section; spot-checking the entry page
// + trailing page catches the 99% case (boot-path + tail-end
// handler modifications) in ~2 µs.
extern "C" const u8 _text_start[];
extern "C" const u8 _text_end[];

u64 ComputeTextSpotHash()
{
    constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
    constexpr u64 kFnvPrime = 0x100000001b3ULL;
    constexpr u64 kSpotBytes = 4096;
    u64 h = kFnvOffset;
    const u8* s = _text_start;
    const u8* e = _text_end;
    const u64 text_bytes = u64(e - s);
    const u64 head_bytes = (text_bytes < kSpotBytes) ? text_bytes : kSpotBytes;
    for (u64 i = 0; i < head_bytes; ++i)
    {
        h ^= s[i];
        h *= kFnvPrime;
    }
    if (text_bytes > 2 * kSpotBytes)
    {
        for (u64 i = 0; i < kSpotBytes; ++i)
        {
            h ^= e[-i64(kSpotBytes) + i64(i)];
            h *= kFnvPrime;
        }
    }
    return h;
}

bool CheckKernelText()
{
    const u64 now = ComputeTextSpotHash();
    if (now != g_baseline_text_spot_hash)
    {
        Report(HealthIssue::KernelTextModified);
        return false;
    }
    return true;
}

bool CheckTaskStacks()
{
    // Sched walker returns canary + rsp-range counts. Each maps
    // to a distinct HealthIssue code so operators can grep the
    // logs for the specific class of failure.
    const auto h = sched::SchedCheckTaskStacks();
    bool ok = true;
    if (h.canary_broken != 0)
    {
        Report(HealthIssue::TaskStackOverflow);
        ok = false;
    }
    if (h.rsp_out_of_range != 0)
    {
        Report(HealthIssue::TaskRspOutOfRange);
        ok = false;
    }
    return ok;
}

} // namespace

const char* HealthIssueName(HealthIssue i)
{
    switch (i)
    {
    case HealthIssue::None:
        return "ok";
    case HealthIssue::HeapPoolMismatch:
        return "heap: used+free exceeds pool (bookkeeping drift)";
    case HealthIssue::HeapUnderflow:
        return "heap: free_count > alloc_count (double-free or overflow)";
    case HealthIssue::HeapFreelistEmpty:
        return "heap: freelist empty but pool not fully used";
    case HealthIssue::HeapFragmentationHigh:
        return "heap: freelist fragmented (> 256 chunks)";
    case HealthIssue::FramesOverflow:
        return "frames: free > total (bitmap corruption)";
    case HealthIssue::FramesAllAllocated:
        return "frames: none free (leak or legitimate memory pressure)";
    case HealthIssue::SchedExitedMoreThanCreated:
        return "sched: tasks_exited > tasks_created (counter drift)";
    case HealthIssue::SchedReapedMoreThanExited:
        return "sched: tasks_reaped > tasks_exited (counter drift)";
    case HealthIssue::SchedLiveUnreasonable:
        return "sched: tasks_live exceeds cap (leak or fork bomb)";
    case HealthIssue::SchedNoContextSwitches:
        return "sched: no context switches after grace period (timer stuck?)";
    case HealthIssue::Cr0WpCleared:
        return "cr0.WP cleared since baseline (kernel can now write RO pages)";
    case HealthIssue::Cr4SmepCleared:
        return "cr4.SMEP cleared since baseline (kernel can exec user pages)";
    case HealthIssue::Cr4SmapCleared:
        return "cr4.SMAP cleared since baseline (kernel can read user pages unguarded)";
    case HealthIssue::EferNxeCleared:
        return "efer.NXE cleared since baseline (NX bit in PTEs now ignored)";
    case HealthIssue::StackCanaryZero:
        return "__stack_chk_guard is zero (canary defanged)";
    case HealthIssue::TaskStackOverflow:
        return "task stack overflow detected (bottom canary scribbled)";
    case HealthIssue::IdtModified:
        return "IDT hash changed since baseline (handler swap or stray write)";
    case HealthIssue::GdtModified:
        return "GDT descriptor hash changed since baseline (segment swap or stray write)";
    case HealthIssue::KernelTextModified:
        return "kernel .text spot-check hash changed since baseline (W^X bypassed)";
    case HealthIssue::TaskRspOutOfRange:
        return "task saved rsp outside [stack_base, stack_top) (control block scribbled)";
    default:
        return "(unnamed issue)";
    }
}

void RuntimeCheckerInit()
{
    KASSERT(g_report.baseline_captured == 0, "core/runtime_checker", "RuntimeCheckerInit called twice");
    g_baseline_cr0 = ReadCr0();
    g_baseline_cr4 = ReadCr4();
    g_baseline_efer = ReadMsr(kMsrEfer);
    g_baseline_idt_hash = arch::IdtHash();
    g_baseline_gdt_hash = arch::GdtHash();
    g_baseline_text_spot_hash = ComputeTextSpotHash();
    g_report.baseline_captured = 1;
    arch::SerialWrite("[health] baseline cr0=");
    arch::SerialWriteHex(g_baseline_cr0);
    arch::SerialWrite(" cr4=");
    arch::SerialWriteHex(g_baseline_cr4);
    arch::SerialWrite(" efer=");
    arch::SerialWriteHex(g_baseline_efer);
    arch::SerialWrite("\n[health] idt=");
    arch::SerialWriteHex(g_baseline_idt_hash);
    arch::SerialWrite(" gdt=");
    arch::SerialWriteHex(g_baseline_gdt_hash);
    arch::SerialWrite(" text_spot=");
    arch::SerialWriteHex(g_baseline_text_spot_hash);
    arch::SerialWrite("\n");
}

u64 RuntimeCheckerScan()
{
    const u64 before = g_report.issues_found_total;
    ++g_report.scans_run;
    // Each check is independent — all run every scan so a
    // single report covers every invariant.
    (void)CheckHeap();
    (void)CheckFrames();
    (void)CheckSched();
    if (g_report.baseline_captured != 0)
    {
        (void)CheckControlRegisters();
        (void)CheckIdt();
        (void)CheckGdt();
        (void)CheckKernelText();
    }
    (void)CheckCanary();
    (void)CheckTaskStacks();
    const u64 delta = g_report.issues_found_total - before;
    g_report.last_scan_issues = delta;
    return delta;
}

void RuntimeCheckerTick()
{
    (void)RuntimeCheckerScan();
}

const HealthReport& RuntimeCheckerStatusRead()
{
    return g_report;
}

} // namespace customos::core
