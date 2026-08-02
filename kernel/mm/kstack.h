#pragma once

#include "util/types.h"
#include "mm/frame_allocator.h"

/*
 * DuetOS kernel-stack arena — v0.
 *
 * Every task spawned via SchedCreate needs a 128 KiB kernel stack.
 * Before this module, those stacks came from the kernel heap
 * (mm::KMalloc). An overflow silently scribbled the next heap
 * chunk — typically another task's stack or its header — and was
 * only caught either (a) by the runtime invariant checker's
 * bottom-sentinel scan every ~5 s, or (b) by the reaper when
 * the task exited. Between those checks the kernel ran on
 * corrupted memory.
 *
 * This module allocates each stack from a dedicated virtual-
 * address arena with a DELIBERATELY-UNMAPPED guard page at the
 * low edge of every slot. Stack grows down; on overflow, the
 * first byte that falls into the guard page takes an immediate
 * kernel-mode #PF. The trap dispatcher recognises the guard-page
 * VA range (see IsKernelStackGuardFault below) and emits a named
 * panic with the offending task id — no more silent corruption
 * window.
 *
 * Layout (each slot, stride = kKernelStackSlotBytes = 132 KiB):
 *
 *   +0x00000  guard page (unmapped; #PF on access)
 *   +0x01000  usable base returned by AllocateKernelStack
 *              32 stack pages (RW+NX)
 *   +0x21000  top of stack (128 KiB above the usable base)
 *
 * Arena base is 0xFFFFFFFFE0000000 (the "reserved for future
 * use" range documented in paging.h). 512 slots * 132 KiB =
 * 66 MiB of kernel virtual space — covers 512 simultaneously-
 * live tasks, well above anything today's boot creates, and
 * leaves the rest of the reserved range for future use (per-CPU
 * IST stacks, for instance).
 *
 * Scope limits (v0):
 *   - Boot task (task 0) keeps its boot.S-provisioned stack and the
 *     dedicated guard page installed by InstallBootStackGuard.
 *   - SMP AP bootstrap stacks use guarded arena slots. They remain
 *     mapped for the CPU lifetime because a rejected AP parks on its
 *     stack and the admitted path has no post-switch reclamation owner.
 *   - TLB reclamation barrier on FreeKernelStack: clear every stack
 *     PTE, wait for confirmed per-target invalidation on each IPI-ready
 *     peer, and only then return the physical frames to the allocator.
 *     A slow peer is waited out; it is never converted into permission
 *     to reuse a frame behind a stale translation. The boot-tail wild-RIP
 *     bug (Roadmap entry) was caused by exactly this race.
 *   - Single slot size (128 KiB usable). If a task needs more,
 *     add a new size class; don't parameterise on the fly.
 *
 * Context: kernel. Safe from any kernel code that is NOT in IRQ
 * context (uses a spinlock + MapPage/UnmapPage, which are not
 * IRQ-safe). Allocation callers are sched::SchedCreate and
 * arch::SmpStartAps; the reaper releases ordinary task stacks.
 */

namespace duetos::mm
{

/// Base of the kernel-stack arena. Picked from the "reserved"
/// block documented in paging.h so it doesn't collide with the
/// direct map (PML4[511] low half), the MMIO arena (PML4[511]
/// middle), or the current kernel image (low end of direct map).
inline constexpr uptr kKernelStackArenaBase = 0xFFFFFFFFE0000000ULL;

/// Number of 4 KiB guard pages at the low edge of every slot.
/// One is enough — overflow hits it on the very first push. Two
/// would only help if a push skipped past a single 4 KiB page in
/// one go, which the ABI's 16-byte alignment guarantees cannot
/// happen.
inline constexpr u64 kKernelStackGuardPages = 1;

/// Usable stack pages per slot. 32 * 4 KiB = 128 KiB. History:
/// 4 (16 KiB) originally; bumped to 16 (64 KiB) on 2026-04-25 for
/// the PE-loader path (SpawnRing3Pe's ~5 KiB DllImage[48] preload +
/// DllLoad → AddressSpaceMapUserPage deep page-table recursion);
/// bumped to 32 (128 KiB) on 2026-06-08 because the browser-fetch
/// worker's live-network path (DoFetch → TLS handshake → cert-verify
/// tower → TCP/IP TX → firewall conntrack) overran 64 KiB under the
/// debug build's KASAN+UBSAN frame inflation, double-faulting the box
/// on the first fetch to a real host. This is the "deep cert-verify
/// tower" the tripwire (below) was added to watch.
inline constexpr u64 kKernelStackPages = 32;

/// Total bytes consumed by one slot, guard + stack.
inline constexpr u64 kKernelStackSlotBytes = (kKernelStackGuardPages + kKernelStackPages) * kPageSize;

/// Usable stack bytes per slot. Matches sched.cpp's
/// kKernelStackBytes — the scheduler passes this same value to
/// AllocateKernelStack and we assert the contract.
inline constexpr u64 kKernelStackUsableBytes = kKernelStackPages * kPageSize;

/// Maximum number of simultaneously-live stacks. 512 is ~50x
/// the tasks any current boot creates; each unused slot costs
/// only a VA range (no backing frames until first allocation).
inline constexpr u64 kKernelStackMaxSlots = 512;

/// Total arena virtual footprint.
inline constexpr u64 kKernelStackArenaBytes = kKernelStackMaxSlots * kKernelStackSlotBytes;

/// Allocate one stack slot. Returns the LOWEST USABLE byte of
/// the stack (slot_base + guard page). The top-of-stack pointer
/// the caller will push an initial frame at is base + stack_bytes.
///
/// `stack_bytes` MUST equal kKernelStackUsableBytes in v0. Passing
/// any other value is a kernel bug — rejected with a panic so
/// scheduler-side mistakes surface loudly instead of creating a
/// mis-sized stack that aliases a neighbour's guard page.
///
/// Returns nullptr if the arena is full (>512 live stacks) — the
/// scheduler treats this as fatal today, same contract as the
/// previous mm::KMalloc path.
void* AllocateKernelStack(u64 stack_bytes);

/// Release a stack slot. `base` is the pointer AllocateKernelStack
/// returned; `stack_bytes` must match. Unmaps every stack page, completes
/// the cross-CPU TLB reclamation barrier, then frees the backing frames and
/// pushes the slot index onto the freelist so the next AllocateKernelStack
/// reuses the same VA range (LIFO).
///
/// The guard-page PTE is never mapped in the first place, so
/// nothing to unmap there — but because UnmapPage is a no-op on
/// an unmapped VA (paging.h contract), an accidental call covering
/// the guard would be silent rather than corrupt.
void FreeKernelStack(void* base, u64 stack_bytes);

/// Deep-usage canary. True if the kernel thread whose stack usable-base is
/// `base` has crossed the 75% tripwire — a sentinel word written at the
/// 96 KiB-used line on allocation has been overwritten by downward stack
/// growth. O(1) (one read); `base` must be a value AllocateKernelStack
/// returned. FreeKernelStack checks this automatically and WARNs + fires the
/// kKernelStackDeepUsage probe; this accessor lets a diagnostic scan LIVE
/// (still-running, never-freed) worker threads — e.g. a future shell command
/// auditing the net/TLS workers that run the deep cert-verify tower.
bool KernelStackTripwireTripped(void* base);

/// True iff `fault_va` lies inside the kernel-stack arena AND
/// inside the guard-page region of its slot (the first
/// kKernelStackGuardPages pages of the slot). Faults inside the
/// stack pages themselves (real PTE damage, wild pointer hitting
/// a live stack) return false so the normal trap-dump path
/// surfaces them with full context instead of being misreported
/// as an overflow.
///
/// Inline so the trap dispatcher can call it without a link-time
/// dependency on kstack.cpp (traps.cpp already includes this
/// header's siblings via paging.h).
inline bool IsKernelStackGuardFault(u64 fault_va)
{
    if (fault_va < kKernelStackArenaBase)
    {
        return false;
    }
    if (fault_va >= kKernelStackArenaBase + kKernelStackArenaBytes)
    {
        return false;
    }
    const u64 off_in_slot = (fault_va - kKernelStackArenaBase) % kKernelStackSlotBytes;
    return off_in_slot < (kKernelStackGuardPages * kPageSize);
}

/// Snapshot of arena state. Cheap; read-only under the arena lock.
struct KernelStackStats
{
    u64 slots_in_use;         // currently live stacks
    u64 slots_ever_allocated; // lifetime AllocateKernelStack calls that succeeded
    u64 slots_freed;          // lifetime FreeKernelStack calls that did anything
    u64 high_water_slots;     // peak slots_in_use since boot
    u64 next_unseen_slot;     // bump cursor — slots above this were never touched
    u64 freelist_depth;       // slots currently on the freelist
};
KernelStackStats KernelStackStatsRead();

/// Non-destructive self-test: allocate a slot, write/read a byte
/// at both ends of the usable stack range, free, re-allocate and
/// assert the freelist returned the same VA (LIFO), free again,
/// assert stats land back at baseline. Panics on any mismatch.
/// Intended for boot-time use only.
void KernelStackSelfTest();

} // namespace duetos::mm
