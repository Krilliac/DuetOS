#include "cpu/percpu.h"

#include "acpi/acpi.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "log/klog.h"

namespace duetos::cpu
{

namespace
{

constexpr u32 kIa32GsBaseMsr = 0xC0000101u;

// Static BSP struct. Every AP will have its own heap-allocated one.
constinit PerCpu g_bsp_percpu = {
    .cpu_id = 0,
    .lapic_id = 0,
    .current_task = nullptr,
    .current_as = nullptr, // kernel AS = boot PML4, until a process is activated
    .need_resched = false,
    ._pad = {},
    .kernel_rsp = 0,           // filled on first ring3 task switch-in (sched + ring3 smoke)
    .user_rsp_scratch = 0,     // touched only by the syscall entry stub
    .panic_snapshot_valid = 0, // capture is filled lazily by the NMI peer-snapshot path
    ._pad2 = {},
    .panic_snapshot_rip = 0,
    .panic_snapshot_rsp = 0,
    .panic_snapshot_task = nullptr,
    .panic_snapshot_cr2 = 0,
    .panic_snapshot_rflags = 0,
    .panic_snapshot_irq_depth = 0,
    .panic_snapshot_held_lock_count = 0,
    .panic_snapshot_topmost_lock_acq_rip = 0,
    .panic_snapshot_topmost_lock_addr = nullptr,
    .held_locks_count = 0,
    ._pad3 = 0,
    .held_locks = {},
    .held_lock_rips = {},
    .gdb_frozen = 0,
    ._pad4 = {},
    .gdb_snapshot_rip = 0,
    .gdb_snapshot_rsp = 0,
    .gdb_snapshot_rflags = 0,
    .gdb_frozen_frame = nullptr,
    .ctxsw_lock_to_release = nullptr,
    .ctxsw_lock_flags = 0,
    .ctxsw_dying_task_to_zombie = nullptr,
    .runq_head_normal = nullptr,
    .runq_tail_normal = nullptr,
    .runq_head_idle = nullptr,
    .runq_tail_idle = nullptr,
    .tss = nullptr,
    .cluster_id = 0,
    .online = false, // PerCpuInitBsp flips this to true after the BSP installs itself
    ._pad_topo = {},
    .runq_normal_len = 0,
    ._pad_runq_len = {},
    .sched_tasks_live = 0,
    .sched_tasks_sleeping = 0,
    .sched_tasks_blocked = 0,
    .sched_tasks_created = 0,
    .sched_tasks_reaped = 0,
    .sched_total_ticks = 0,
    .sched_idle_ticks = 0,
    .idle_task = nullptr,     // published by SchedStartIdle on each CPU
    .scheduler_ready = false, // flipped to true at the end of SchedStartIdle / SchedEnterOnAp
    ._pad_sched_ready = {},
    .this_cpu_selftest_counter = 0,
    .critnest = 0,                // steady-state: no critical section active
    .deferred_preempt = 0,        // no pending preempt at boot
    .critical_enter_count = 0,    // stats — bumped by CriticalEnter
    .critical_exit_count = 0,     // stats — bumped by CriticalExit
    .critical_deferred_count = 0, // stats — bumped on deferred preempt
    .critical_max_nesting = 0,    // high-water mark across the boot
    ._pad_critical = {},
};

// One-shot flag so CurrentCpuIdOrBsp can return a sane value before
// PerCpuInitBsp has run. Without it, reading GSBASE would return 0
// and CurrentCpu() would dereference a null pointer.
constinit bool g_bsp_installed = false;

// Count of times CurrentCpu() saw a non-kernel GSBASE in a kernel
// context on a NON-BSP CPU and recovered via LAPIC-ID resolution.
// A clean SMP boot stays at (or near) zero; a non-zero value marks
// a swapgs / AP-GS-reestablishment gap. Surfaced from SmpStartAps
// (kernel-GSBASE-safe context) — NOT logged from inside CurrentCpu()
// itself, which would recurse through klog's CurrentCpuIdOrBsp tag.
constinit u64 g_gsbase_fallback_nonbsp = 0;

inline void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

} // namespace

void PerCpuInitBsp()
{
    KLOG_TRACE_SCOPE("cpu/percpu", "PerCpuInitBsp");
    // Stamp the LAPIC ID from the LAPIC register — the MADT also
    // reports LAPIC IDs, but the register is the authoritative source
    // for the CPU we're actually executing on.
    g_bsp_percpu.lapic_id = arch::LapicCurrentId();

    WriteMsr(kIa32GsBaseMsr, reinterpret_cast<u64>(&g_bsp_percpu));
    // BSP TSS pointer wired here (TssInit ran before PerCpuInitBsp,
    // so the TSS body is fully populated). All TssSetRsp0 calls from
    // here on go through cpu::CurrentCpu()->tss; the static BSP TSS
    // remains the same object — just routed via PerCpu now.
    g_bsp_percpu.tss = arch::BspTssPtr();
    // BSP is online from boot — the wake-side routing predicate
    // (`PickClusterPlacement`) honours this so the BSP slot is
    // always a legal target.
    g_bsp_percpu.online = true;
    g_bsp_installed = true;

    arch::SerialWrite("[cpu] BSP PerCpu installed: cpu_id=0 lapic_id=");
    arch::SerialWriteHex(g_bsp_percpu.lapic_id);
    arch::SerialWrite(" addr=");
    arch::SerialWriteHex(reinterpret_cast<u64>(&g_bsp_percpu));
    arch::SerialWrite("\n");
}

PerCpu* CurrentCpu()
{
    // Before BSP install, callers (early-boot self-tests reaching
    // sched::Current() / mm::AddressSpaceCurrent() through inline
    // accessors) would read GSBASE = 0 and the next `->field`
    // deref would be a null-deref UB — UBSAN flagged this with
    // a type-mismatch report at sched.cpp:390 / address_space.cpp:644.
    // Falling back to the static BSP slot here gives every accessor
    // a non-null pointer with valid `current_task` /
    // `current_as` slots before BSP install completes, removing
    // the early-boot UB while the post-install path is unchanged.
    if (!g_bsp_installed)
    {
        return &g_bsp_percpu;
    }
    PerCpu* p;
    // "mov %%gs:0, %0" reads the first qword of the per-CPU region
    // treating it as an offset from GSBASE — but we want the BASE
    // itself. `rdgsbase` is the direct instruction; since we don't
    // gate on CPUID.EBX.FSGSBASE yet, use RDMSR instead.
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000101u));
    p = reinterpret_cast<PerCpu*>((static_cast<u64>(hi) << 32) | lo);
    // The GS base can hold a NON-KERNEL value even AFTER BSP install:
    // a ring-3 -> ring-0 transition executes a few kernel
    // instructions with the *user* GS base before the entry stub's
    // swapgs runs. Observed on VirtualBox, two distinct stale values:
    //   * GSBASE == 0          (user GS never set) — nat_sysinfo
    //     time-syscall path; #PF CR2=0.
    //   * GSBASE == 0x70000000 (the user TEB fixed VA) — PE-spawn
    //     path; #PF CR2=0x70000000.
    // A valid per-CPU pointer is always a kernel higher-half address
    // (g_bsp_percpu and every heap-allocated AP struct live in the
    // kernel half, >= 0xffff800000000000). So validating "is this a
    // kernel-canonical pointer" — not merely "is it non-null" —
    // catches BOTH stale forms (and any future user-range leak).
    constexpr u64 kKernelHalfBase = 0xffff800000000000ULL;
    if (reinterpret_cast<u64>(p) < kKernelHalfBase)
    {
        // GSBASE holds a stale / user value: a ring3->ring0 swapgs
        // window, or an AP that has not (yet / again) re-established
        // its kernel GS. Returning &g_bsp_percpu here was correct
        // ONLY while DuetOS booted a single CPU. On SMP it silently
        // mis-attributes an AP to the BSP, so the AP then reads and
        // writes the BSP's current_task / ctxsw_lock_to_release /
        // per-CPU runqueue selection. That cross-CPU per-CPU-state
        // corruption is the root of the intermittent SMP double-run
        // (MUTEX-NONOWNER / sync-spinlock release-out-of-order under
        // tools/qemu/gui-fuzz.sh): an AP sentinel / idle-range TID
        // ends up Current() on the CPU running a real worker's
        // stack, so that worker's MutexUnlock fails the owner test.
        //
        // The LAPIC ID is hardware-authoritative and independent of
        // GSBASE, so resolve the REAL executing CPU from it. Every
        // online PerCpu has its lapic_id stamped before the CPU runs
        // any code (BSP in PerCpuInitBsp, each AP in SmpStartAps
        // before SIPI), so the scan is valid for any caller that got
        // here. Fall back to the BSP slot only when no CPU matches —
        // genuine single-CPU boot, where the BSP is the only and
        // therefore correct answer. SmpGetPercpu(id) for id>=1 reads
        // g_ap_percpus[id] directly and SmpGetPercpu(0) returns
        // &g_bsp_percpu, so this never recurses back into
        // CurrentCpu(); likewise LapicCurrentId() reads LAPIC MMIO,
        // not GSBASE.
        //
        // Scan the FULL allocated-slot space (acpi::kMaxCpus), NOT
        // arch::SmpCpuIdLimit(). SmpCpuIdLimit() is the SCHEDULER's
        // wake-routing iteration bound and is deliberately NOT bumped
        // until an AP signals online (SmpStartAps defers the
        // g_cpu_id_limit bump until after WaitForApOnline, gated
        // additionally by the PerCpu::online routing predicate). But
        // an AP runs its ENTIRE CpuhpBringUp chain — including the
        // StartingGdt / StartingGsBase states — BEFORE CpuhpStartGsBase
        // programs a kernel GSBASE, so every cpu::CurrentCpu() in that
        // window has GSBASE=0 and lands HERE. Bounding the scan by
        // SmpCpuIdLimit() (which does NOT yet cover the booting AP)
        // made the lapic match FAIL and silently returned
        // &g_bsp_percpu — so the AP pushed g_state_lock / g_frame_lock
        // onto the BSP's per-CPU held-locks stack and stamped
        // owner_cpu=BSP. Once CpuhpStartGsBase ran, GSBASE became valid
        // and the AP's later releases hit its OWN slot, leaving the
        // BSP's held-stack with a phantom entry — surfacing as the
        // intermittent `sync/spinlock : release out-of-order` under the
        // lockdep audit build, escalating to a serial self-deadlock
        // when the raw-serial diagnostic re-entered g_serial_lock. The
        // 2026-05-19 LAPIC fallback was correct in principle but its
        // SmpCpuIdLimit() bound was defeated by the (separately
        // correct) 2026-05-22 deferred-limit-bump fix. The AP's
        // g_ap_percpus[cpu_id] + lapic_id are stamped before SIPI, so
        // scanning to kMaxCpus finds the booting AP's real slot;
        // unallocated (nullptr) slots are skipped by the guard below.
        const u32 lapic = arch::LapicCurrentId();
        for (u32 id = 0; id < acpi::kMaxCpus; ++id)
        {
            PerCpu* cand = arch::SmpGetPercpu(id);
            if (cand != nullptr && cand->lapic_id == lapic)
            {
                if (cand != &g_bsp_percpu)
                {
                    // A non-BSP CPU reached kernel C++ with a
                    // non-kernel GSBASE — a real swapgs / AP-GS gap
                    // on THIS cpu. Recovered (correct CPU resolved),
                    // but count it: a clean boot must stay at zero
                    // now the AP-bring-up GS ordering + AP lidt are
                    // fixed; a non-zero value is a regression.
                    // No klog / probe here — klog tags lines via
                    // CurrentCpuIdOrBsp() which would re-enter this
                    // path while GSBASE is still stale (unbounded
                    // recursion). The count is surfaced + probed from
                    // OnTimerTick, a kernel-GSBASE-safe site.
                    __atomic_add_fetch(&g_gsbase_fallback_nonbsp, 1, __ATOMIC_RELAXED);
                }
                return cand;
            }
        }
        return &g_bsp_percpu;
    }
    return p;
}

u32 CurrentCpuIdOrBsp()
{
    if (!g_bsp_installed)
    {
        return 0;
    }
    return CurrentCpu()->cpu_id;
}

bool BspInstalled()
{
    return g_bsp_installed;
}

PerCpu* BspPercpu()
{
    return &g_bsp_percpu;
}

u64 CurrentCpuGsbaseFallbackCount()
{
    return __atomic_load_n(&g_gsbase_fallback_nonbsp, __ATOMIC_RELAXED);
}

} // namespace duetos::cpu
