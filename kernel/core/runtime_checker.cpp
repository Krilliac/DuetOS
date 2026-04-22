#include "runtime_checker.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../arch/x86_64/traps.h"
#include "../drivers/storage/block.h"
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
// Syscall MSR baselines. These are the post-boot "golden"
// values; any later change signals a syscall-hook rootkit.
// LSTAR = Linux 64-bit SYSCALL entry (IA32_LSTAR, 0xC0000082)
// STAR  = SYSCALL CS/SS pair      (IA32_STAR,  0xC0000081)
// CSTAR = compat-mode SYSCALL     (IA32_CSTAR, 0xC0000083)
// SYSENTER_EIP = 32-bit SYSENTER entry (0x176)
// SYSENTER_CS  = 32-bit SYSENTER CS   (0x174)
// FEATURE_CONTROL = IA32_FEATURE_CONTROL (0x3A, bit 0 = lock)
constinit u64 g_baseline_lstar = 0;
constinit u64 g_baseline_star = 0;
constinit u64 g_baseline_cstar = 0;
constinit u64 g_baseline_sysenter_eip = 0;
constinit u64 g_baseline_sysenter_cs = 0;
constinit u64 g_baseline_feature_control = 0;
// Baseline valid only if the MSR was readable at init time.
// A few MSRs #GP on platforms that don't implement them (old
// AMD / VM without vmx). Track per-MSR so the checker can
// skip silently.
constinit bool g_baseline_feature_control_valid = false;

// Per-block-device disk-image baseline. We hash LBA 0 (MBR /
// GPT protective MBR) + LBA 1 (GPT primary header) on every
// block device at init. 16 devices × 2 LBAs = 32 hashes max.
// A drift on any of them = bootkit write.
constexpr u64 kMaxBlockDevicesForHealth = 16;
constinit u64 g_baseline_disk_hash[kMaxBlockDevicesForHealth][2] = {};
constinit bool g_baseline_disk_valid[kMaxBlockDevicesForHealth][2] = {};
// DMA scratch buffer — kernel stack isn't in the direct map,
// so BlockDeviceRead requires a direct-mapped destination. 4 KiB
// covers 8 × 512-byte sectors; we only ever read 1 at a time.
alignas(16) constinit u8 g_health_scratch[4096] = {};

// Previous-scan values for monotonic counters. Each entry
// should only ever grow; a scan that sees a smaller value
// than last time flags `CounterWentBackwards` with the
// counter's name. Zero-initialised; the first scan populates
// baselines without reporting.
constinit u64 g_prev_alloc_count = 0;
constinit u64 g_prev_free_count = 0;
constinit u64 g_prev_tasks_created = 0;
constinit u64 g_prev_tasks_reaped = 0;
constinit u64 g_prev_ctx_switches = 0;
constinit u64 g_prev_hpet_counter = 0;
constinit u64 g_prev_timer_ticks = 0;
constinit bool g_prev_populated = false;

constexpr u64 kCr0Wp = 1ULL << 16;
constexpr u64 kCr4Smep = 1ULL << 20;
constexpr u64 kCr4Smap = 1ULL << 21;
constexpr u32 kMsrEfer = 0xC0000080;
// Syscall-hook detection MSRs. Each is written at most once
// during boot (SyscallInit for STAR/LSTAR/CSTAR, firmware for
// SYSENTER, firmware for FEATURE_CONTROL lock).
constexpr u32 kMsrIa32FeatureControl = 0x3A;
constexpr u32 kMsrIa32SysenterCs = 0x174;
constexpr u32 kMsrIa32SysenterEip = 0x176;
constexpr u32 kMsrIa32Star = 0xC0000081;
constexpr u32 kMsrIa32Lstar = 0xC0000082;
constexpr u32 kMsrIa32Cstar = 0xC0000083;
constexpr u64 kFeatureControlLockBit = 1ULL << 0;
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

// IRQ nesting ceiling. Set high enough that exception-path
// decrement gaps during adversarial smoke tests (tasks that
// deliberately #PF / #GP) don't trip the check. 32 is a soft
// wall — a real runaway re-entry would blow past it within
// milliseconds.
constexpr u64 kIrqNestingCeiling = 32;

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
    case HealthIssue::SyscallMsrHijacked:
    case HealthIssue::FeatureControlUnlocked:
    case HealthIssue::BootSectorModified:
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

    // Bootkit-specific escalation: any boot-sector drift or
    // syscall-MSR-hook flips the block-layer write guard from
    // Advisory to Deny so a subsequent write attempt by the
    // attacker is refused rather than just logged.
    if ((issue == HealthIssue::BootSectorModified || issue == HealthIssue::SyscallMsrHijacked) &&
        drivers::storage::BlockWriteGuardMode() != drivers::storage::WriteGuardMode::Deny)
    {
        arch::SerialWrite("[health] ESCALATE: blockguard -> Deny (rootkit indicator)\n");
        drivers::storage::BlockWriteGuardSetMode(drivers::storage::WriteGuardMode::Deny);
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

// Syscall-MSR baseline check. Catches the dominant rootkit
// persistence pattern: overwrite IA32_LSTAR (or STAR / CSTAR /
// SYSENTER_EIP) with a hook that inspects every syscall before
// routing to the real handler. None of these MSRs are
// legitimately rewritten after SyscallInit; any drift is an
// attack.
bool CheckSyscallMsrs()
{
    bool ok = true;
    auto check = [&ok](u32 msr, u64 baseline, const char* name)
    {
        const u64 now = ReadMsr(msr);
        if (now != baseline)
        {
            arch::SerialWrite("[health] syscall MSR hijacked: ");
            arch::SerialWrite(name);
            arch::SerialWrite(" baseline=");
            arch::SerialWriteHex(baseline);
            arch::SerialWrite(" now=");
            arch::SerialWriteHex(now);
            arch::SerialWrite("\n");
            Report(HealthIssue::SyscallMsrHijacked);
            ok = false;
        }
    };
    check(kMsrIa32Lstar, g_baseline_lstar, "IA32_LSTAR");
    check(kMsrIa32Star, g_baseline_star, "IA32_STAR");
    check(kMsrIa32Cstar, g_baseline_cstar, "IA32_CSTAR");
    check(kMsrIa32SysenterEip, g_baseline_sysenter_eip, "IA32_SYSENTER_EIP");
    check(kMsrIa32SysenterCs, g_baseline_sysenter_cs, "IA32_SYSENTER_CS");
    return ok;
}

// FNV-1a over a 512-byte sector buffer. Same hash family as
// the IDT/GDT/.text checkers so operators can cross-reference.
u64 HashSector(const u8* p)
{
    constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
    constexpr u64 kFnvPrime = 0x100000001b3ULL;
    u64 h = kFnvOffset;
    for (u64 i = 0; i < 512; ++i)
    {
        h ^= p[i];
        h *= kFnvPrime;
    }
    return h;
}

// Populate the per-device boot-sector hashes AND arm the
// block-layer write guard for the same LBAs so any later write
// is either logged (Advisory) or refused (Deny). Called from
// RuntimeCheckerInit.
void CaptureDiskBaselines()
{
    const u32 n = drivers::storage::BlockDeviceCount();
    const u32 cap = (n < kMaxBlockDevicesForHealth) ? n : u32(kMaxBlockDevicesForHealth);
    for (u32 i = 0; i < cap; ++i)
    {
        for (u32 lba = 0; lba < 2; ++lba)
        {
            const i32 rc = drivers::storage::BlockDeviceRead(i, lba, 1, g_health_scratch);
            if (rc == 0)
            {
                g_baseline_disk_hash[i][lba] = HashSector(g_health_scratch);
                g_baseline_disk_valid[i][lba] = true;
            }
        }
        // Arm the write guard. Two rules per device — LBA 0
        // (MBR / protective MBR) and LBA 1 (GPT primary header).
        // A future enhancement adds the last two LBAs (GPT
        // backup header + backup table) once we teach the block
        // layer how to compute a device's trailing offsets.
        drivers::storage::BlockWriteGuardAddRule(i, 0, 1, "MBR / protective MBR");
        drivers::storage::BlockWriteGuardAddRule(i, 1, 1, "GPT primary header");
    }
    drivers::storage::BlockWriteGuardSetMode(drivers::storage::WriteGuardMode::Advisory);
}

bool CheckBootSectors()
{
    bool ok = true;
    const u32 n = drivers::storage::BlockDeviceCount();
    const u32 cap = (n < kMaxBlockDevicesForHealth) ? n : u32(kMaxBlockDevicesForHealth);
    for (u32 i = 0; i < cap; ++i)
    {
        for (u32 lba = 0; lba < 2; ++lba)
        {
            if (!g_baseline_disk_valid[i][lba])
                continue;
            const i32 rc = drivers::storage::BlockDeviceRead(i, lba, 1, g_health_scratch);
            if (rc != 0)
                continue;
            const u64 now = HashSector(g_health_scratch);
            if (now != g_baseline_disk_hash[i][lba])
            {
                arch::SerialWrite("[health] boot sector modified: dev=");
                arch::SerialWriteHex(i);
                arch::SerialWrite(" lba=");
                arch::SerialWriteHex(lba);
                arch::SerialWrite(" baseline=");
                arch::SerialWriteHex(g_baseline_disk_hash[i][lba]);
                arch::SerialWrite(" now=");
                arch::SerialWriteHex(now);
                arch::SerialWrite("\n");
                Report(HealthIssue::BootSectorModified);
                ok = false;
            }
        }
    }
    return ok;
}

bool CheckFeatureControlLock()
{
    if (!g_baseline_feature_control_valid)
        return true;
    const u64 now = ReadMsr(kMsrIa32FeatureControl);
    // If the baseline had the lock bit set, require it still set.
    if ((g_baseline_feature_control & kFeatureControlLockBit) != 0 && (now & kFeatureControlLockBit) == 0)
    {
        Report(HealthIssue::FeatureControlUnlocked);
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

// Verify that a counter hasn't gone backwards between scans.
// Logs the name so the operator sees WHICH counter drifted.
void VerifyMonotonic(const char* name, u64 prev, u64 now, bool& any_backwards)
{
    if (now < prev)
    {
        arch::SerialWrite("[health] counter regressed: ");
        arch::SerialWrite(name);
        arch::SerialWrite(" prev=");
        arch::SerialWriteHex(prev);
        arch::SerialWrite(" now=");
        arch::SerialWriteHex(now);
        arch::SerialWrite("\n");
        any_backwards = true;
    }
}

bool CheckMonotonicCounters()
{
    const auto heap = mm::KernelHeapStatsRead();
    const auto sched_stats = sched::SchedStatsRead();
    const u64 hpet_now = arch::HpetReadCounter();
    const u64 ticks_now = arch::TimerTicks();

    if (!g_prev_populated)
    {
        // First scan — populate baselines, emit nothing.
        g_prev_alloc_count = heap.alloc_count;
        g_prev_free_count = heap.free_count;
        g_prev_tasks_created = sched_stats.tasks_created;
        g_prev_tasks_reaped = sched_stats.tasks_reaped;
        g_prev_ctx_switches = sched_stats.context_switches;
        g_prev_hpet_counter = hpet_now;
        g_prev_timer_ticks = ticks_now;
        g_prev_populated = true;
        return true;
    }

    bool any_backwards = false;
    VerifyMonotonic("heap.alloc_count", g_prev_alloc_count, heap.alloc_count, any_backwards);
    VerifyMonotonic("heap.free_count", g_prev_free_count, heap.free_count, any_backwards);
    VerifyMonotonic("sched.tasks_created", g_prev_tasks_created, sched_stats.tasks_created, any_backwards);
    VerifyMonotonic("sched.tasks_reaped", g_prev_tasks_reaped, sched_stats.tasks_reaped, any_backwards);
    VerifyMonotonic("sched.context_switches", g_prev_ctx_switches, sched_stats.context_switches, any_backwards);

    bool ok = true;
    if (any_backwards)
    {
        Report(HealthIssue::CounterWentBackwards);
        ok = false;
    }

    // Clock stall detection — HPET should advance every
    // nanosecond, timer ticks every 10 ms. If either is
    // unchanged across a 5-second heartbeat, the timer IRQ
    // path or the HPET MMIO window is broken.
    if (hpet_now == g_prev_hpet_counter)
    {
        arch::SerialWrite("[health] HPET counter stalled at ");
        arch::SerialWriteHex(hpet_now);
        arch::SerialWrite("\n");
        Report(HealthIssue::ClockStalled);
        ok = false;
    }
    if (ticks_now == g_prev_timer_ticks)
    {
        arch::SerialWrite("[health] LAPIC tick counter stalled at ");
        arch::SerialWriteHex(ticks_now);
        arch::SerialWrite("\n");
        Report(HealthIssue::ClockStalled);
        ok = false;
    }

    g_prev_alloc_count = heap.alloc_count;
    g_prev_free_count = heap.free_count;
    g_prev_tasks_created = sched_stats.tasks_created;
    g_prev_tasks_reaped = sched_stats.tasks_reaped;
    g_prev_ctx_switches = sched_stats.context_switches;
    g_prev_hpet_counter = hpet_now;
    g_prev_timer_ticks = ticks_now;
    return ok;
}

bool CheckIrqNesting()
{
    if (arch::IrqNestMax() > kIrqNestingCeiling)
    {
        Report(HealthIssue::IrqNestingExcessive);
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
    case HealthIssue::IrqNestingExcessive:
        return "IRQ nesting depth exceeded ceiling (runaway re-entry or storm)";
    case HealthIssue::CounterWentBackwards:
        return "a monotonic counter regressed (arithmetic underflow or corruption)";
    case HealthIssue::ClockStalled:
        return "HPET or LAPIC tick counter didn't advance between scans";
    case HealthIssue::SyscallMsrHijacked:
        return "syscall MSR (LSTAR/STAR/CSTAR/SYSENTER) changed since baseline (rootkit hook)";
    case HealthIssue::FeatureControlUnlocked:
        return "IA32_FEATURE_CONTROL lock bit cleared since baseline (VMX-based attack setup)";
    case HealthIssue::BootSectorModified:
        return "MBR or GPT header modified since baseline (bootkit / disk-persistence malware)";
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
    g_baseline_lstar = ReadMsr(kMsrIa32Lstar);
    g_baseline_star = ReadMsr(kMsrIa32Star);
    g_baseline_cstar = ReadMsr(kMsrIa32Cstar);
    g_baseline_sysenter_eip = ReadMsr(kMsrIa32SysenterEip);
    g_baseline_sysenter_cs = ReadMsr(kMsrIa32SysenterCs);
    // FEATURE_CONTROL only exists on VMX-capable CPUs. Gate on
    // CPUID.1.ECX bit 5; reading it on a CPU that doesn't
    // support VMX would #GP. On QEMU TCG + AuthenticAMD-TCG
    // the bit is clear (VMX not advertised), so we skip the
    // baseline entirely there.
    u32 eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    if (ecx & (1u << 5)) // VMX supported
    {
        g_baseline_feature_control = ReadMsr(kMsrIa32FeatureControl);
        g_baseline_feature_control_valid = true;
    }

    // Per-disk boot-sector baselines. Done last because it
    // touches the block layer, which may not be ready until
    // well into boot (we're past SmpStartAps so it is).
    CaptureDiskBaselines();
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
    arch::SerialWrite("\n[health] lstar=");
    arch::SerialWriteHex(g_baseline_lstar);
    arch::SerialWrite(" star=");
    arch::SerialWriteHex(g_baseline_star);
    arch::SerialWrite(" sysenter_eip=");
    arch::SerialWriteHex(g_baseline_sysenter_eip);
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
    (void)CheckIrqNesting();
    (void)CheckMonotonicCounters();
    if (g_report.baseline_captured != 0)
    {
        (void)CheckSyscallMsrs();
        (void)CheckFeatureControlLock();
        (void)CheckBootSectors();
    }
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
