#pragma once

#include "util/types.h"

/*
 * DuetOS — per-CPU data (v0).
 *
 * Each CPU gets its own `PerCpu` struct. The struct pointer lives in
 * the `IA32_GS_BASE` MSR (0xC0000101), so any CPU can read its own
 * per-CPU data via `mov rax, gs:[offset]` with zero synchronization.
 *
 * Today (pre-SMP) only the BSP's struct exists; `PerCpuInitBsp` is
 * called from `kernel_main` before `SchedInit`. When SMP AP bring-up
 * lands, each AP trampoline will allocate its own PerCpu and write
 * GSBASE with its address before jumping into kernel code.
 *
 * Context: kernel. Safe at any interrupt level — accessing GSBASE is
 * a straight MSR read on every CPU that supports long mode.
 */

namespace duetos::sched
{
struct Task; // forward decl; defined in kernel/sched/sched.cpp
}

namespace duetos::mm
{
struct AddressSpace; // forward decl; defined in kernel/mm/address_space.h
}

namespace duetos::arch
{
struct TrapFrame; // forward decl; defined in kernel/arch/x86_64/traps.h
}

namespace duetos::cpu
{

// Maximum spinlocks we track per CPU at once. Real kernel paths
// rarely nest more than ~3 (heap → freelist → page-table); 8 gives
// generous headroom. Exceeding the cap drops tracking for the
// excess locks (logged once) rather than panicking — a deep nest
// is itself a signal worth surfacing, but not at the cost of
// taking the box down on lock-debug overflow.
inline constexpr u32 kPerCpuMaxHeldLocks = 8;

struct PerCpu
{
    u32 cpu_id;                   // 0 = BSP; APs number 1..N in bring-up order
    u32 lapic_id;                 // APIC ID as read from LAPIC ID register
    sched::Task* current_task;    // currently-running Task (was g_current)
    mm::AddressSpace* current_as; // AS currently loaded in CR3 (nullptr = kernel AS / boot PML4)
    bool need_resched;            // set by TimerHandler / wake paths
    u8 _pad[7];                   // keep 8-byte alignment after bool

    // Linux-ABI syscall entry support. The `syscall` instruction
    // doesn't consult the TSS — it jumps to MSR_LSTAR with the user
    // RSP unchanged. The entry stub reads kernel_rsp from here to
    // switch stacks and stashes the caller's RSP into
    // user_rsp_scratch across the dispatcher call. `kernel_rsp`
    // is updated by the scheduler in lockstep with TssSetRsp0 so
    // the two entry paths (int 0x80 and syscall) resolve to the
    // same kernel stack for a given task. See
    // kernel/subsystems/linux/syscall_entry.S.
    u64 kernel_rsp;
    u64 user_rsp_scratch;

    // Cross-CPU panic snapshot. The panicking CPU broadcasts an NMI
    // (`arch::PanicBroadcastNmi`); each peer's vector-2 handler
    // captures its own state into these fields BEFORE halting, so
    // the panicking CPU can include peer RIP/RSP/task in the dump.
    // `panic_snapshot_valid` flips from 0 → 1 once captured, so the
    // dumper can distinguish "peer hung before NMI hit" (valid=0)
    // from a clean snapshot. Layout intentionally placed AFTER the
    // syscall-entry fields so kPerCpuKernelRsp / kPerCpuUserRspScratch
    // stay at +32 / +40 — adding fields here doesn't disturb the
    // hand-written assembly stub.
    u8 panic_snapshot_valid;
    u8 _pad2[7];
    u64 panic_snapshot_rip;
    u64 panic_snapshot_rsp;
    sched::Task* panic_snapshot_task;
    // Extended state captured at the same instant as RIP/RSP/task.
    // The trap dispatcher's NMI handler reads from existing per-CPU
    // counters, so this costs only a few extra MOVs.
    u64 panic_snapshot_cr2;             // last-faulting VA (#PF context)
    u64 panic_snapshot_rflags;          // captures IF/IOPL/AC/etc.
    u32 panic_snapshot_irq_depth;       // IrqNestDepthRaw at NMI entry
    u32 panic_snapshot_held_lock_count; // value of held_locks_count
    // For the topmost held lock (if any), capture the acquirer's
    // RIP so the dump shows WHICH lock-acquiring function the peer
    // was stuck inside. The full held-locks stack is per-CPU local
    // and is already dumped by the peer itself; this gives the
    // CROSS-CPU view a one-line summary.
    u64 panic_snapshot_topmost_lock_acq_rip;
    void* panic_snapshot_topmost_lock_addr;

    // Spinlock holder tracking for the panic dump's `held locks`
    // section. Push on SpinLockAcquire (with the acquirer's RIP),
    // pop on SpinLockRelease. Same scoping rule as the snapshot
    // fields: lives behind PerCpuInit, so SpinLock acquires before
    // BSP install simply skip the bookkeeping. `void*` for the lock
    // pointer keeps cpu/percpu.h free of a sync/spinlock.h include.
    u32 held_locks_count;
    u32 _pad3;
    void* held_locks[kPerCpuMaxHeldLocks];
    u64 held_lock_rips[kPerCpuMaxHeldLocks];

    // GDB stop-rendezvous snapshot. Distinct from panic_snapshot_*
    // because the panic path halts peers forever — the GDB stop
    // path freezes them on a release flag and resumes them when
    // the BSP exits its stop loop. The vector-2 handler checks
    // arch::SmpGdbStopActive() and, when set, captures rip/rsp
    // here BEFORE spinning on the same flag. `gdb_frozen` flips
    // 0 → 1 once a peer has entered the freeze spin so the BSP
    // knows the rendezvous converged before pumping packets.
    //
    // `gdb_frozen_frame` points at the peer's live trap frame
    // (on its kernel stack) for the duration of the freeze spin.
    // The CPU running the GDB stop loop reads it through
    // arch::SmpGetPercpu(peer_id)->gdb_frozen_frame to populate
    // a per-CPU register snapshot when the operator switches
    // threads via `Hg <tid>` — that's the multi-thread GDB
    // surface peers show up in. Cleared back to nullptr when the
    // peer exits the freeze spin.
    u8 gdb_frozen;
    u8 _pad4[7];
    u64 gdb_snapshot_rip;
    u64 gdb_snapshot_rsp;
    u64 gdb_snapshot_rflags;
    arch::TrapFrame* gdb_frozen_frame;

    // Lock to release after the next ContextSwitch on this CPU. The
    // scheduler holds g_sched_lock across ContextSwitch and stashes
    // the lock pointer + saved IRQ flags here while still on prev's
    // stack. Once ContextSwitch returns — on whatever task we just
    // resumed — SchedFinishTaskSwitch reads this slot, clears it,
    // and calls SpinLockRelease. The slot is per-CPU (not per-task)
    // because it identifies "the lock THIS CPU just acquired"; the
    // resumed task is irrelevant to which lock needs releasing.
    //
    // ctxsw_lock_to_release is void* to keep cpu/percpu.h free of a
    // sync/spinlock.h include; sched.cpp casts it back to SpinLock*.
    // nullptr = no pending release (e.g., not currently inside
    // Schedule). ctxsw_lock_flags is the IrqFlags::rflags value
    // captured at acquire — required by SpinLockRelease's signature.
    void* ctxsw_lock_to_release;
    u64 ctxsw_lock_flags;

    // Deferred-zombie slot: a dying task pushed here by SchedExit
    // BEFORE the context switch, then promoted to the global zombie
    // list by SchedFinishTaskSwitch AFTER the switch has committed.
    // Closes the SMP use-after-free race where the reaper on a peer
    // CPU could pop the dying task off `g_zombies` and call
    // `FreeKernelStack` on its stack pages WHILE the dying CPU was
    // still mid-ContextSwitch, executing on those very pages. (See
    // the comment in `sched::SchedExit` for the historical
    // "SMP bring-up will need to ..." note that pre-dated this.)
    //
    // void* to keep cpu/percpu.h free of the sched::Task definition;
    // sched.cpp casts back to Task*. nullptr = the previous task did
    // not exit during the just-completed switch.
    void* ctxsw_dying_task_to_zombie;

    // Per-CPU runqueues. Two priority bands (Normal + Idle), each a
    // FIFO with head + tail pointers. A task enqueued on this CPU's
    // runqueue is owned by THIS CPU until popped — no migration in
    // v0 (work-stealing in commit 6 changes that). All four slots
    // are still protected by the global g_sched_lock; the per-CPU
    // structure here is the data-layout half of the per-CPU runqueue
    // refactor — lock-granularity decomposition is deferred until
    // contention shows up in profiles. Pointers are typed as void*
    // to avoid pulling sched/sched.h's Task forward decl into every
    // includer of percpu.h; sched.cpp casts back to Task*.
    void* runq_head_normal;
    void* runq_tail_normal;
    void* runq_head_idle;
    void* runq_tail_idle;

    // Pointer to this CPU's TSS struct (arch::Tss*). BSP's slot
    // points at the static g_bsp_tss; each AP's slot points at a
    // heap-allocated AP TSS (allocated by arch::AllocateApGdt
    // alongside the per-AP GDT clone + IST stacks). TssSetRsp0
    // dereferences this on every user→kernel transition prep so
    // the right CPU's TSS RSP0 slot gets updated. void* to avoid
    // pulling arch/x86_64/gdt.h into every includer of percpu.h;
    // gdt.cpp casts back to arch::Tss*.
    void* tss;

    // Scheduler-locality cluster index. Read by the work-stealing
    // hot path (`StealNormalFromPeer`) to bias steals to peers in
    // the same cluster as `self`. Populated once at boot by
    // `cpu::TopologyAssignClusters` after every AP has decoded its
    // own CPUID/SRAT topology — until then, every CPU's slot is 0
    // (the steal path's two-pass scan still works: pass 0 visits
    // every peer with cluster_id==0, pass 1 finds nothing). 0 is
    // also the canonical single-cluster value, so a UMA single-
    // package box never needs to write this field after init.
    //
    // Placed AFTER `tss` to keep the syscall-stub offsets at +32
    // and +40 stable; appending past line 159 doesn't disturb
    // kPerCpuKernelRsp / kPerCpuUserRspScratch.
    u16 cluster_id;

    // Liveness flag. The BSP's slot is true from boot (PerCpuInitBsp);
    // each AP's slot stays false from KMalloc(PerCpu) all the way
    // through INIT/SIPI bring-up, then flips to true at the end of
    // `SmpStartAps`'s per-AP loop after `WaitForApOnline` succeeds
    // (kernel/arch/x86_64/smp.cpp). Read by the wake-side routing
    // (`PickClusterPlacement`, `TargetPerCpuFor`) to skip slots
    // whose AP isn't actually servicing a runqueue yet — closes the
    // 2026-05-22 SMP=8 boot-determinism `aps=?` hang at the
    // predicate level (the matching fix at the iteration-key level
    // is the `g_cpu_id_limit` deferred bump). Defence-in-depth: a
    // future feature that brings a CPU offline at runtime (hot-plug,
    // power-management quiesce, watchdog kill) can flip this flag
    // false to immediately stop the scheduler routing wakes to it
    // without having to coordinate the iteration limit.
    //
    // `bool` is fine; reads are unsynchronised — a stale `false`
    // just costs one wake routed to a fresh-but-running AP, which
    // the active load balancer corrects on the next periodic pass.
    // Stale `true` only fires when the AP has already serviced one
    // schedule (the flag flip races a one-tick gap), which means
    // the runqueue is being drained — no deadlock risk.
    bool online;
    u8 _pad_topo[5];

    // Length of this CPU's Normal-band runqueue (does NOT count the
    // currently-running task). Maintained by the scheduler under
    // `g_sched_lock` alongside the head/tail pointers; readable
    // without the lock for placement decisions (a stale read just
    // costs a slightly suboptimal routing — the next wake corrects).
    // Exists so wake placement (`RunqueuePush`) can pick the least-
    // loaded peer in the parent's cluster instead of always routing
    // to `last_cpu`. Idle-band tasks are pinned per-CPU and never
    // load-balanced, so they get no counter — counting them would
    // bias placement toward CPUs whose only "load" is their own
    // idle thread.
    u32 runq_normal_len;
    u8 _pad_runq_len[4];

    // Per-CPU scheduler stat counters. Maintained under
    // g_sched_lock on the CPU that does the state transition,
    // read by SchedStats via a cross-CPU sum-walk. Splitting these
    // off the global g_tasks_* counters removes the cache-line
    // ping-pong that was happening every time any CPU touched the
    // global counter line while the sched lock was held.
    //
    // Increments and decrements may land on different CPUs (a task
    // created on CPU 0 might be reaped on CPU 3); per-CPU partial
    // sums can therefore go transiently negative. The cross-CPU
    // SUM is always non-negative and correct.
    u64 sched_tasks_live;
    u64 sched_tasks_sleeping;
    u64 sched_tasks_blocked;
    u64 sched_tasks_created;
    u64 sched_tasks_reaped;

    // This CPU's idle task. Set by `SchedStartIdle` (BSP via
    // `SchedInit`, each AP via `SchedEnterOnAp`). Read by
    // `ScheduleLockedHandoff` as a last-resort fallback when the
    // runqueue's Normal AND Idle bands are both empty AND the
    // current task is no longer Running — without this safety net
    // the schedule path panics ("no runnable task available").
    // The intermittent symptom: an SMP race where the idle band
    // briefly shows empty between the previous Schedule() pop and
    // the next preemption re-enqueueing prev. Treating this slot
    // as the per-CPU safety net is the smallest correct fix; the
    // proper long-term shape (per-CPU runqueue + atomic idle
    // dispatch) lives behind the global g_sched_lock split (see
    // wiki Roadmap "B2-followup — split g_sched_lock per-CPU").
    sched::Task* idle_task;

    // Per-CPU "scheduler ready" gate. False after PerCpu alloc /
    // memset, flipped to true at the end of `SchedStartIdle` once
    // `idle_task` is published. Wake-side routing
    // (`PickClusterPlacement`), periodic balance
    // (`PickBalanceVictim`), and work-steal (`StealNormalFromPeer`)
    // all skip a CPU whose flag is false — this closes the AP-
    // bringup race where the BSP would otherwise push tasks onto
    // an AP that hasn't yet published `idle_task` and finished
    // `SchedEnterOnAp`. Without this gate the AP could dispatch a
    // routed task on its first timer IRQ, the task could sleep
    // before its own `idle_task` was visible, and
    // `ScheduleLockedHandoff` would panic "no runnable task
    // available" (observed: 3/10 debug-preset boots).
    bool scheduler_ready;
    u8 _pad_sched_ready[7];

    // Single-instruction per-CPU access self-test slot. Bumped by
    // `arch::ThisCpuOpsSelfTest` (kernel/arch/x86_64/percpu_ops.h)
    // 1000 times via the `incq %gs:offset` macro, then read back
    // and KASSERT'd against the expected value. Placed at the
    // tail so its offset isn't ABI-frozen against any hand-written
    // assembly stub — the offset is computed at compile time via
    // `DUETOS_THIS_CPU_OFFSET(PerCpu, this_cpu_selftest_counter)`.
    u64 this_cpu_selftest_counter;

    // Everything below this line will grow as SMP matures:
    //   - per-CPU runqueue spinlock (today: shared g_sched_lock)
    //   - per-CPU heap magazine (when the heap grows per-CPU caching)
    //   - idle stack pointer
    //   - stats (ticks, context switches, irqs served)
};

// Byte offsets into PerCpu — consumed by hand-written assembly in
// subsystems/linux/syscall_entry.S. Any change to PerCpu's layout
// MUST update these constants OR the entry stub will dereference
// wrong fields.
// cpu_id(4) + lapic_id(4) + current_task(8) + current_as(8)
// + need_resched(1) + _pad(7) = 32 → kernel_rsp at +32.
inline constexpr u32 kPerCpuKernelRsp = 32;
inline constexpr u32 kPerCpuUserRspScratch = 40;

// Belt-and-braces for the syscall-entry stub: trip the build the
// instant a future PerCpu reshuffle drifts these offsets, rather
// than corrupting kernel_rsp at runtime.
static_assert(__builtin_offsetof(PerCpu, kernel_rsp) == kPerCpuKernelRsp,
              "PerCpu.kernel_rsp offset must match kPerCpuKernelRsp (subsystems/linux/syscall_entry.S)");
static_assert(__builtin_offsetof(PerCpu, user_rsp_scratch) == kPerCpuUserRspScratch,
              "PerCpu.user_rsp_scratch offset must match kPerCpuUserRspScratch (subsystems/linux/syscall_entry.S)");

/// Install the BSP's PerCpu struct and write its address to GSBASE.
/// Called once from kernel_main before SchedInit so that CurrentCpu()
/// is valid when the scheduler comes up. Also records the BSP's APIC
/// ID (read from the LAPIC register — LapicInit must have run).
void PerCpuInitBsp();

/// Return a pointer to the currently-executing CPU's PerCpu struct.
/// Reads GSBASE — constant-time, no locks. Safe from IRQ context.
PerCpu* CurrentCpu();

/// Convenience wrapper. Returns `CurrentCpu()->cpu_id` if GSBASE is
/// set, or 0 (BSP) if it isn't. Used by very-early code (e.g. the
/// spinlock primitive during BSP bring-up, before PerCpuInitBsp has
/// run) so that lock-owner tracking still produces a meaningful value.
u32 CurrentCpuIdOrBsp();

/// True iff `PerCpuInitBsp` has run. Subsystems that touch per-CPU
/// state from a path that may run before BSP install (early spinlock
/// acquires from frame-allocator init, NMI from the watchdog
/// pre-percpu) gate on this.
bool BspInstalled();

/// Pointer to the BSP's static PerCpu. Always non-null. Used by
/// the SMP enumerator so the panic dump path can iterate every
/// CPU's snapshot buffer (BSP at index 0, APs from arch/smp.cpp's
/// table). Reading PerCpu fields off this pointer from a CPU OTHER
/// than the BSP is fine — they're plain memory; the only caller
/// today (panic dump) is the panicking CPU and it accesses its own
/// fields via CurrentCpu(), peer fields via this enumerator.
PerCpu* BspPercpu();

/// Number of times CurrentCpu() recovered from a non-kernel GSBASE
/// on a NON-BSP CPU by resolving the real PerCpu via the LAPIC ID
/// (instead of the old, incorrect, "assume BSP" fallback). Zero on
/// a clean SMP boot; non-zero marks a swapgs / AP-GS-reestablishment
/// gap. Read from a kernel-GSBASE-safe context only (SmpStartAps).
u64 CurrentCpuGsbaseFallbackCount();

} // namespace duetos::cpu
