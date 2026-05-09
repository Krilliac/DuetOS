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
    u8 _pad_topo[6];

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

} // namespace duetos::cpu
