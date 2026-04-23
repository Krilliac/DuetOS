#pragma once

#include "../core/types.h"
#include "frame_allocator.h"

/*
 * CustomOS kernel-stack arena — v0.
 *
 * Every task spawned via SchedCreate needs a 16 KiB kernel stack.
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
 * Layout (each slot, stride = kKernelStackSlotBytes = 20 KiB):
 *
 *   +0x0000 ┌─────────────────────────┐
 *           │  guard page (unmapped)  │   #PF on any access
 *   +0x1000 ├─────────────────────────┤  <-- AllocateKernelStack returns this
 *           │   stack page 0   (RW+NX)│
 *   +0x2000 ├─────────────────────────┤
 *           │   stack page 1   (RW+NX)│
 *   +0x3000 ├─────────────────────────┤
 *           │   stack page 2   (RW+NX)│
 *   +0x4000 ├─────────────────────────┤
 *           │   stack page 3   (RW+NX)│
 *   +0x5000 └─────────────────────────┘   <-- top-of-stack (16 KiB above base)
 *
 * Arena base is 0xFFFFFFFFE0000000 (the "reserved for future
 * use" range documented in paging.h). 512 slots * 20 KiB =
 * 10 MiB of kernel virtual space — covers 512 simultaneously-
 * live tasks, well above anything today's boot creates, and
 * leaves the rest of the reserved range for future use (per-CPU
 * IST stacks, for instance).
 *
 * Scope limits (v0):
 *   - Boot task (task 0) keeps its boot.S-provisioned stack; it
 *     is not relocated onto a guarded slot. Boot-stack hardening
 *     is a separate slice.
 *   - SMP AP bootstrap stacks (arch/x86_64/smp.cpp) still come
 *     from mm::KMalloc. APs today only run `cli; hlt` so they
 *     cannot overflow; swap to AllocateKernelStack when APs join
 *     the scheduler.
 *   - No TLB shootdown on FreeKernelStack — UnmapPage invalidates
 *     only the local core. Same gap as the existing MMIO arena;
 *     not introduced by this module.
 *   - Single slot size (16 KiB usable). If a task needs more,
 *     add a new size class; don't parameterise on the fly.
 *
 * Context: kernel. Safe from any kernel code that is NOT in IRQ
 * context (uses a spinlock + MapPage/UnmapPage, which are not
 * IRQ-safe). The sole caller today is sched::SchedCreate and
 * the reaper.
 */

namespace customos::mm
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

/// Usable stack pages per slot. 4 * 4 KiB = 16 KiB — identical
/// to the previous heap-backed size (kKernelStackBytes in
/// sched.cpp). Keeping the usable size unchanged means no task
/// that fit before overflows now.
inline constexpr u64 kKernelStackPages = 4;

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
/// returned; `stack_bytes` must match. Unmaps the four stack
/// pages, frees the backing frames, pushes the slot index onto
/// the freelist so the next AllocateKernelStack reuses the same
/// VA range (LIFO).
///
/// The guard-page PTE is never mapped in the first place, so
/// nothing to unmap there — but because UnmapPage is a no-op on
/// an unmapped VA (paging.h contract), an accidental call covering
/// the guard would be silent rather than corrupt.
void FreeKernelStack(void* base, u64 stack_bytes);

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

} // namespace customos::mm
