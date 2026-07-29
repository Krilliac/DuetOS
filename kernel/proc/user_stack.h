/**
 * @file kernel/proc/user_stack.h
 * @brief Demand-grown ring-3 stacks: reservation descriptor + #PF service.
 *
 * A Win32 PE declares how much stack it wants in the Optional
 * Header (`SizeOfStackReserve` / `SizeOfStackCommit`). Windows
 * *reserves* that much address space and *commits* only the top of
 * it, growing the committed part a page at a time as the thread's
 * stack pointer walks down. DuetOS does the same, for the same
 * reason: committing a PE's full 1 MiB reserve up front would cost
 * 256 frames per spawn across every boot PE and every PE-compat
 * battery row, and almost all of it would never be touched.
 *
 * The reservation for a PE's main thread looks like this, growing
 * downward from `top`:
 *
 *     guard_lo        reserve_lo         commit_lo            top
 *        |                 |                  |                |
 *        [  guard region ][ reserved, uncommitted ][ committed ]
 *        <--  fatal   -->  <-- grows on demand -->  <-- mapped -->
 *
 * `top` is fixed (`kUserStackTopVa`); `reserve_lo` comes from the
 * image's own `SizeOfStackReserve`, clamped; `commit_lo` starts at
 * `top - SizeOfStackCommit` (clamped) and walks down as the thread
 * faults; `[guard_lo, reserve_lo)` is the guard region, which growth
 * may NEVER extend into, so a genuine runaway still dies loudly
 * instead of quietly eating address space.
 *
 * Growth is deliberately narrow — see UserStackClassify. A
 * mis-classified fault that silently commits memory is worse than
 * a crash, so the only fault that grows is a not-present fault
 * naming the page immediately below the committed region, taken by
 * the thread whose own rsp is inside this reservation.
 *
 * Concurrency: there is none, and that is a property of the
 * classifier rather than a lock. Growth requires the faulting
 * thread's own rsp to be inside this reservation (condition 4), and
 * every other thread in the process runs on the Win32 thread-stack
 * arena at 0x68000000 — strictly below this reservation — so no
 * other thread can ever satisfy condition 4 against it. The main
 * thread is therefore the sole writer of `commit_lo`, whether it faults
 * in user mode or the kernel pre-commits on its behalf from the
 * SEH dispatcher. A spinlock here would be worse than useless: the
 * commit path calls into mm, whose regions lock can park the task,
 * and parking while holding a spinlock with interrupts off is a
 * deadlock. The present-probe inside the commit helper is the
 * remaining net against a double map.
 *
 * GAP: only the PE main-thread stack is growable — Win32
 * CreateThread stacks come off the fixed-size thread-stack arena
 * (Process::thread_stack_cursor, 0x68000000) and still overflow
 * into the next thread's slot.
 */
#pragma once

#include "util/types.h"

namespace duetos::core
{

/// One-past-last byte of a PE main-thread stack reservation.
/// Sits immediately below KUSER_SHARED_DATA (0x7FFE0000) so the
/// reservation can grow downward through the empty span between
/// the TLS trampoline page (0x73000000) and here without meeting
/// another fixed loader VA. Kept inside the loader-reserved band
/// (0x60000000..0x80000000) that PeLoad refuses to let an image
/// overlap.
inline constexpr u64 kUserStackTopVa = 0x7FFE0000ULL;

/// Clamp on `SizeOfStackReserve`. Address space is free, frames
/// are not — but an unbounded reservation would still let a
/// crafted PE push `reserve_lo` down into the TLS/TEB fixed VAs.
/// 4 MiB is 4x the Windows default and leaves 0x73000000+ clear.
inline constexpr u64 kUserStackReserveMax = 4ULL * 1024 * 1024;

/// Floor on the reservation. A PE that declares a tiny (or zero)
/// `SizeOfStackReserve` still gets at least the 64 KiB that the
/// pre-growth fixed stack handed every image, so nothing that used
/// to run regresses.
inline constexpr u64 kUserStackReserveMin = 64ULL * 1024;

/// Bounds on how much of the reservation is committed at spawn.
/// `SizeOfStackCommit` picks the value inside this window. Two
/// pages is the floor because ring-3 entry lands rsp near `top`
/// and the first prologue writes a shadow-save area below it; the
/// ceiling stops a PE from demanding its whole reserve at spawn
/// under the guise of "commit".
inline constexpr u64 kUserStackCommitMinPages = 2;
inline constexpr u64 kUserStackCommitMaxPages = 16;

/// Size of the guard region below the reservation, in pages.
///
/// One page detects the overflow just as well, but the region is
/// also the ONLY stack the STATUS_STACK_OVERFLOW handler has to run
/// on: Windows commits the guard at the moment it raises the
/// exception so the thread's __except can execute, and our
/// KiUserExceptionDispatcher -> __C_specific_handler -> RtlUnwindEx
/// tower needs more than 4 KiB to do that (measured: a single page
/// ran out inside the dispatcher and the second fault task-killed
/// the thread). Four pages leaves headroom without materially
/// widening the window in which an overflow is still detected — the
/// detection boundary is `reserve_lo`, unchanged.
inline constexpr u64 kUserStackGuardPages = 4;

/// How far below the committed region a fault may name and still
/// count as stack growth: exactly one page. MSVC emits a
/// `__chkstk` call for any frame >= 4 KiB, and `__chkstk` probes
/// the stack one page at a time downward, so every legitimate
/// growth fault is adjacent to the committed region. A fault that
/// skips uncommitted pages is a wild pointer, not a stack probe.
inline constexpr u64 kUserStackGrowStep = 4096;

/// Ceiling on a single UserStackCommitRange call. The largest
/// kernel-side user-stack write is the SEH frame (an
/// EXCEPTION_RECORD + a CONTEXT + alignment, well under 8 KiB), so
/// four pages is generous; the bound exists so a bug in a caller
/// cannot turn one call into a whole-reservation commit.
inline constexpr u64 kUserStackKernelCommitMax = 4;

/// Per-process ring-3 stack reservation. All-zero means "this
/// process has no growable stack" (native ring-3 smoke payloads,
/// ELF tasks) and every fault classifies as NotStack.
struct UserStackRange
{
    u64 top;        // one-past-last byte of the reservation
    u64 reserve_lo; // lowest VA that may ever be committed by growth
    u64 commit_lo;  // lowest VA currently committed
    u64 guard_lo;   // guard region occupies [guard_lo, reserve_lo)
    // Set once, the first time the guard region is hit. Windows
    // commits the guard at the moment it raises
    // STATUS_STACK_OVERFLOW so the thread's __except handler has
    // somewhere to run; we do the same. It is a ONE-SHOT: the
    // recursion that overflowed still dies (the classifier returns
    // Guard, never Grow), and a second runaway walks off the bottom
    // of the now-committed guard region into unmapped space, where
    // it classifies NotStack and takes the ordinary task-kill.
    bool guard_taken;
};

/// Outcome of classifying a ring-3 #PF against a stack reservation.
enum class UserStackFault : u8
{
    NotStack, // fault is unrelated to the stack reservation — caller
              // must fall through to its existing handling unchanged
    Grow,     // classification only: this fault warrants a commit
    Grew,     // a page was committed; retry the faulting instruction
    Guard,    // fault landed in the guard region — stack overflow, fatal
    Failed,   // growth was warranted but the commit could not be done
              // (frame OOM / AS frame budget). Treat as fatal.
};

/// Compute the reservation layout an image asking for
/// `reserve_bytes` / `commit_bytes` gets, applying every clamp
/// above. Both inputs come straight off the PE Optional Header and
/// are untrusted. `clamped` (optional, may be null) is set true
/// when a clamp actually changed the requested reserve, so the
/// caller can log it.
///
/// Defined inline (with UserStackClassify below) so both stay pure
/// and freestanding — no kernel headers, no allocation, no locking
/// — and can be unit-tested directly off this header. See
/// tests/host/test_user_stack.cpp.
inline UserStackRange UserStackPlan(u64 reserve_bytes, u64 commit_bytes, bool* clamped)
{
    constexpr u64 kPage = 4096;
    auto align_up = [](u64 v) { return (v + kPage - 1) & ~(kPage - 1); };

    u64 reserve = align_up(reserve_bytes);
    if (reserve < kUserStackReserveMin)
    {
        reserve = kUserStackReserveMin;
    }
    if (reserve > kUserStackReserveMax)
    {
        reserve = kUserStackReserveMax;
    }
    if (clamped != nullptr)
    {
        *clamped = (reserve != align_up(reserve_bytes));
    }

    // Initial commit: honour SizeOfStackCommit, but inside the
    // [min, max] window and never past the reservation itself.
    u64 commit_pages = align_up(commit_bytes) / kPage;
    if (commit_pages < kUserStackCommitMinPages)
    {
        commit_pages = kUserStackCommitMinPages;
    }
    if (commit_pages > kUserStackCommitMaxPages)
    {
        commit_pages = kUserStackCommitMaxPages;
    }
    if (commit_pages * kPage > reserve)
    {
        commit_pages = reserve / kPage;
    }

    UserStackRange r{};
    r.top = kUserStackTopVa;
    r.reserve_lo = kUserStackTopVa - reserve;
    r.commit_lo = kUserStackTopVa - commit_pages * kPage;
    r.guard_lo = r.reserve_lo - kUserStackGuardPages * kPage;
    r.guard_taken = false;
    return r;
}

/// Decide what a ring-3 page fault means for `s`. Pure — no
/// mapping, no allocation, no locking — so the decision can be
/// unit-tested exhaustively without a live address space.
///
/// `fault_va` is cr2, `err_code` the #PF error code, `rsp` the
/// faulting thread's stack pointer from the trap frame.
///
/// Returns Guard for any fault inside the guard region
/// `[guard_lo, reserve_lo)`.
/// Returns Grow only when ALL of:
///   1. the fault is not-present (err bit 0 clear) — a protection
///      fault on an already-committed stack page is a real error;
///   2. `reserve_lo <= fault_va < commit_lo` — inside the
///      reservation but not yet committed;
///   3. `commit_lo - fault_va <= kUserStackGrowStep` — the fault
///      names the page immediately below the committed region;
///   4. `reserve_lo <= rsp <= top` — the faulting thread is the one
///      actually running on this stack.
/// Everything else is NotStack and the caller's existing
/// behaviour applies untouched.
inline UserStackFault UserStackClassify(const UserStackRange& s, u64 fault_va, u64 err_code, u64 rsp)
{
    if (s.top == 0)
    {
        return UserStackFault::NotStack; // no growable stack on this process
    }

    // The guard region is checked FIRST and independently of the
    // error code: whatever the access was, landing there means the
    // thread walked off the bottom of its own reservation.
    if (fault_va >= s.guard_lo && fault_va < s.reserve_lo)
    {
        return UserStackFault::Guard;
    }

    // Condition 1 — a present-bit-set fault is a protection
    // violation on an already-committed page (write to RO, NX
    // fetch). Never growth.
    if ((err_code & 0x1u) != 0)
    {
        return UserStackFault::NotStack;
    }
    // Condition 2 — inside the reservation, below the committed edge.
    if (fault_va < s.reserve_lo || fault_va >= s.commit_lo)
    {
        return UserStackFault::NotStack;
    }
    // Condition 3 — the page immediately below the committed edge.
    // A fault that skips over uncommitted pages is a wild pointer.
    if (s.commit_lo - fault_va > kUserStackGrowStep)
    {
        return UserStackFault::NotStack;
    }
    // Condition 4 — the faulting thread is the one running on THIS
    // stack: its rsp lies inside the reservation.
    //
    // The tempting phrasing is "the access is below rsp", and it is
    // wrong: only `push` / `call` fault below rsp. A compiler that
    // has already done `sub rsp, N` writes at `[rsp + k]`, so the
    // faulting address is at or ABOVE rsp — that is what a real
    // recursion looks like, and rejecting it would refuse every
    // growth a normal function prologue asks for. (Observed live:
    // cr2 = rsp on the first frame of a recursing PE.)
    //
    // Anchoring on rsp's own location instead is both correct and
    // stronger. It is what proves no OTHER thread can ever grow this
    // reservation: every other thread in the process runs on the
    // Win32 thread-stack arena at 0x68000000, far below reserve_lo,
    // so none of them can satisfy this. That is the whole
    // no-locking argument (see the concurrency note above).
    if (rsp < s.reserve_lo || rsp > s.top)
    {
        return UserStackFault::NotStack;
    }
    return UserStackFault::Grow;
}

/// Classify (as above) against the CURRENT task's reservation and
/// act on the verdict: Grow becomes Grew (or Failed if the commit
/// could not be done), Guard commits the one-shot guard page so a
/// __except handler has room to run and still reports Guard.
UserStackFault UserStackServiceFault(u64 fault_va, u64 err_code, u64 rsp);

/// Commit every page covering `[lo, hi)` in the current task's
/// stack reservation, for a kernel-side write the thread cannot
/// fault in itself. The Win32 SEH dispatcher uses this: it builds
/// the EXCEPTION_RECORD + CONTEXT on the faulting thread's own
/// user stack via mm::CopyToUser, which pre-checks accessibility
/// and returns false rather than faulting — so exception delivery
/// itself can be the thing that needs a page.
///
/// Returns true if the whole range is committed on return (already
/// was, or now is). Returns false if the range is not wholly inside
/// the reservation, reaches more than `kUserStackKernelCommitMax`
/// pages past the committed edge, or a frame allocation fails.
bool UserStackCommitRange(u64 lo, u64 hi);

/// Human-readable name for a UserStackFault — boot-log use.
const char* UserStackFaultName(UserStackFault f);

} // namespace duetos::core
