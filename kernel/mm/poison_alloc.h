#pragma once

#include "util/types.h"

/*
 * DuetOS — guard-page poison allocator (v0).
 *
 * WHAT
 *   A sibling allocator to `KMalloc` aimed at catching memory-
 *   corruption bugs at the WRITE site instead of letting them
 *   corrupt random heap neighbours and surface later as an
 *   inscrutable triple-fault. Each allocation gets:
 *
 *     [ guard page ][ data page ][ guard page ]
 *
 *   The two flanking guard pages are reserved-but-unmapped: a
 *   read or write past either boundary takes a #PF that the
 *   trap dispatcher recognises (CR2 inside the poison VA range)
 *   and routes through FaultReactDispatch with
 *   FaultKind::PoisonGuardHit -> Halt.
 *
 *   On Free, the data page is UNMAPPED (not zeroed-and-recycled),
 *   so any use-after-free hit on the freed VA also takes a #PF
 *   on the very next dereference. The VA is NOT recycled — the
 *   poison allocator burns address space deliberately to make
 *   UAF reproducible. ~256 MiB of kernel VA reserved gives
 *   ~64 k outstanding allocations, more than enough for debug
 *   builds; once exhausted, `PoisonAlloc` returns nullptr so
 *   the caller falls back to KMalloc (or asserts, for code that
 *   only runs under the poison allocator).
 *
 * MODES
 *   `OverrunDetect`  — the returned pointer is positioned so
 *                      `ptr + size` lands on the FIRST byte of
 *                      the upper guard page. Use when the
 *                      suspected bug is a write past the end
 *                      of a buffer.
 *
 *   `UnderrunDetect` — the returned pointer is the BASE of the
 *                      data page, i.e. one byte before the
 *                      pointer is the LAST byte of the lower
 *                      guard page. Use when the suspected bug
 *                      is a negative-offset write.
 *
 *   Default: `OverrunDetect`. Most buffer-corruption bugs in
 *   kernel code are tail overruns (memcpy length, strcpy
 *   without bounds, off-by-one terminator); the underrun mode
 *   is the rarer "wrote at index -1" variant.
 *
 * COST
 *   3 pages of VA per allocation (12 KiB), 1 physical frame per
 *   allocation (the two guards consume no frames). The metadata
 *   header lives inside the data page, so no separate hash
 *   table is needed.
 *
 *   This is a DIAGNOSTIC allocator. Production kernel paths
 *   should keep using KMalloc / Slab / Frame — switching a hot
 *   path to the poison allocator costs 12 KiB of VA per object
 *   and consumes the 64 k-outstanding budget rapidly.
 *
 * CONTEXT
 *   Kernel. IRQ-off OK (uses a spinlock, not a mutex). MUST NOT
 *   be called before `PoisonAllocInit()` — that's wired into the
 *   boot bring-up after PagingInit, before any AddressSpace is
 *   created so the PML4[384] entry the region lives under is
 *   inherited by every per-process address space.
 *
 *   Prior art: Windows Driver Verifier's "Special Pool" and
 *   XNU Mach zone-quarantine both use this same end-of-page +
 *   guard-page idiom.
 */

namespace duetos::mm
{

enum class PoisonMode : u8
{
    OverrunDetect = 0,  // align allocation to END of page; overrun hits upper guard
    UnderrunDetect = 1, // align allocation to START of page; underrun hits lower guard
};

/// Allocate `size` bytes with guard pages on both sides.
///
/// Returns nullptr on:
///   - `size == 0` (poison allocator doesn't model zero-byte allocs)
///   - `size > 4096` (single data page; oversize is rejected, not split)
///   - VA region exhausted (~64 k live allocations — see header doc)
///   - physical frame OOM (caller must fall back)
///
/// Caller checks for nullptr; this is a KMalloc-style API.
///
/// Context: kernel, IRQ-off OK.
void* PoisonAlloc(u64 size, PoisonMode mode = PoisonMode::OverrunDetect);

/// Free a pointer obtained from `PoisonAlloc`. The DATA page is
/// unmapped; the VA is leaked (intentional — touching the pointer
/// after this call takes a #PF that the trap dispatcher routes to
/// FaultKind::PoisonGuardHit -> Halt).
///
/// `ptr == nullptr` is a no-op (KFree-style).
/// `ptr` not from the poison region panics — a bad caller doesn't
/// get to silently corrupt the heap.
void PoisonFree(void* ptr);

/// Diagnostic counters since boot.
struct PoisonStats
{
    u64 allocs_total;       // lifetime PoisonAlloc successes
    u64 frees_total;        // lifetime PoisonFree successes
    u64 live_count;         // allocs_total - frees_total
    u64 va_exhausted_count; // PoisonAlloc returns nullptr from VA exhaustion
    u64 frame_oom_count;    // PoisonAlloc returns nullptr from physical-frame OOM
};
PoisonStats PoisonStatsRead();

/// Initialise the poison-allocator VA region. Idempotent; only
/// the first call has effect. MUST run after `PagingInit` and
/// BEFORE the first `AddressSpaceCreate` so the PML4 entry the
/// region lives under is propagated into every per-process AS
/// at AS-create time.
void PoisonAllocInit();

/// Boot self-test. Allocates a small buffer, writes through it
/// at both ends (must work — the data page is mapped writable),
/// frees it, allocates ANOTHER and verifies it has a DIFFERENT
/// VA (the bump cursor never reuses a freed slot — VA-leak by
/// design). Underrun-mode is also exercised. Does NOT trigger
/// a guard-page #PF — that path is verified live by the trap
/// dispatcher's runtime check; here we just verify the alloc /
/// write / free / re-alloc round-trip and the stats deltas.
///
/// Panics on mismatch. Emits a structural sentinel on success.
void PoisonAllocSelfTest();

/// Returns true iff `va` lies inside the poison-allocator VA
/// region. Used by the trap dispatcher to decide whether a #PF
/// should be reported as PoisonGuardHit. Safe from trap context
/// (a couple of compares against constants — no locks, no
/// allocation).
bool IsPoisonRegionAddress(u64 va);

/// Base / size of the poison region, exposed for the trap
/// dispatcher's range check and for the shell's `mem` command.
inline constexpr u64 kPoisonRegionBase = 0xFFFFC00000000000ULL;
inline constexpr u64 kPoisonRegionBytes = 256ULL * 1024 * 1024;
inline constexpr u64 kPoisonSlotBytes = 3ULL * 4096; // [guard][data][guard]

} // namespace duetos::mm
