/*
 * DuetOS — hardware-poison frame blacklist (v1 minimal).
 *
 * See `kernel/mm/poison.h` for the contract. This TU owns the
 * record-only blacklist consulted by:
 *   - `FreeFrame` (kernel/mm/frame_allocator.cpp): drops a frame
 *     instead of returning it to the free pool if its PFN is on
 *     the list.
 *   - `MachineCheckReport` (kernel/arch/x86_64/machine_check.cpp):
 *     calls `PoisonFrame` on the failing PFN when an SRAR fires
 *     (MCi_STATUS.AR=1, ADDRV=1, no PCC).
 *
 * The list is a small fixed-size array protected by a spinlock.
 * Lookup is linear; capacity is 32 entries — enough for a healthy
 * machine that sees corrected-error escalations on a small number
 * of bad DRAM cells, well under the threshold where the OS isn't
 * the load-bearing layer anymore.
 */

#include "mm/poison.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sync/spinlock.h"

namespace duetos::mm
{

namespace
{

constexpr u64 kPageSizeBytes = 4096;
constexpr u64 kPageMask = ~(kPageSizeBytes - 1);

// Storage — fixed-size, constinit so we don't rely on dynamic init
// ordering. The spinlock protects both `g_count` and the array slot
// contents; readers (IsFramePoisoned) take the same lock for a
// snapshot view.
constinit u64 g_poisoned[kFramePoisonCapacity] = {};
constinit u32 g_count = 0;
constinit sync::SpinLock g_poison_lock = {};

// Set during `PoisonFrameSelfTest` to suppress the per-PFN WARN
// log line — the selftest exercises the round-trip with synthetic
// PFNs that aren't real DRAM frames, so emitting "frame poisoned
// (excluded from future allocation)" would mislead operators
// reading the boot log. The selftest restores the table to its
// original state afterwards; the suppression flag is restored too.
constinit bool g_selftest_in_progress = false;

// Linear scan helper called under the lock.
bool ContainsLocked(u64 frame_phys)
{
    for (u32 i = 0; i < g_count; ++i)
    {
        if (g_poisoned[i] == frame_phys)
            return true;
    }
    return false;
}

} // namespace

bool PoisonFrame(u64 frame_phys)
{
    const u64 pfn = frame_phys & kPageMask;
    sync::SpinLockGuard guard(g_poison_lock);
    if (ContainsLocked(pfn))
    {
        // Idempotent — already recorded.
        return true;
    }
    if (g_count >= kFramePoisonCapacity)
    {
        KLOG_WARN_V("mm/poison", "frame poison list saturated; dropping new entry phys", pfn);
        return false;
    }
    g_poisoned[g_count++] = pfn;
    if (!g_selftest_in_progress)
    {
        // Log even at the high level: a frame transitioning into
        // poisoned-state is a non-recoverable event whose log line
        // should survive any reasonable kernel log level filtering.
        // Suppressed during the boot selftest (synthetic PFNs would
        // mis-attribute a hardware-failure event).
        KLOG_WARN_V("mm/poison", "frame poisoned (excluded from future allocation) phys", pfn);
    }
    return true;
}

bool IsFramePoisoned(u64 frame_phys)
{
    const u64 pfn = frame_phys & kPageMask;
    sync::SpinLockGuard guard(g_poison_lock);
    return ContainsLocked(pfn);
}

u32 PoisonedFrameCount()
{
    sync::SpinLockGuard guard(g_poison_lock);
    return g_count;
}

void PoisonFrameSelfTest()
{
    using arch::SerialWrite;

    // The test must round-trip without polluting the live record:
    // snapshot the current state, run the checks, restore.
    constexpr u64 kFakePfn1 = 0x123456000ull;
    constexpr u64 kFakePfn2 = 0x789ABC000ull;

    // The fake PFNs must not already be on the list (extremely
    // unlikely, but bail loud if they were).
    if (IsFramePoisoned(kFakePfn1) || IsFramePoisoned(kFakePfn2))
    {
        core::Panic("mm/poison", "selftest: fake PFN collided with live entry");
    }

    const u32 saved_count = PoisonedFrameCount();

    // Suppress the per-PFN WARN log during the synthetic-PFN
    // round-trip; restored before any real-SRAR path can run.
    {
        sync::SpinLockGuard guard(g_poison_lock);
        g_selftest_in_progress = true;
    }

    // (1) Insert.
    if (!PoisonFrame(kFakePfn1))
    {
        core::Panic("mm/poison", "selftest: PoisonFrame(pfn1) returned false (list saturated?)");
    }
    if (!IsFramePoisoned(kFakePfn1))
    {
        core::Panic("mm/poison", "selftest: IsFramePoisoned(pfn1) false after PoisonFrame");
    }
    if (PoisonedFrameCount() != saved_count + 1)
    {
        core::PanicWithValue("mm/poison", "selftest: count not incremented", PoisonedFrameCount());
    }

    // (2) Idempotent re-poison — count must not move.
    if (!PoisonFrame(kFakePfn1))
    {
        core::Panic("mm/poison", "selftest: idempotent re-poison returned false");
    }
    if (PoisonedFrameCount() != saved_count + 1)
    {
        core::Panic("mm/poison", "selftest: idempotent re-poison double-counted");
    }

    // (3) Page-mask normalisation — a byte-precise address inside
    // the same frame must hash to the same PFN.
    if (!IsFramePoisoned(kFakePfn1 + 0xAB))
    {
        core::Panic("mm/poison", "selftest: byte-offset within frame missed match");
    }

    // (4) Second distinct PFN.
    if (!PoisonFrame(kFakePfn2))
    {
        core::Panic("mm/poison", "selftest: PoisonFrame(pfn2) returned false");
    }
    if (!IsFramePoisoned(kFakePfn2))
    {
        core::Panic("mm/poison", "selftest: second PFN not visible");
    }
    if (PoisonedFrameCount() != saved_count + 2)
    {
        core::Panic("mm/poison", "selftest: count after two distinct insertions wrong");
    }

    // (5) Negative lookup — a third PFN we never inserted is NOT
    // poisoned.
    if (IsFramePoisoned(0xDEADBEEF000ull))
    {
        core::Panic("mm/poison", "selftest: spurious positive on never-inserted PFN");
    }

    // Restore — remove the two test entries. We don't expose a
    // remove API (production callers never need it), so do it in
    // place under the lock by compacting the array. This is the
    // only path that mutates the list outside PoisonFrame.
    {
        sync::SpinLockGuard guard(g_poison_lock);
        u32 dst = 0;
        for (u32 src = 0; src < g_count; ++src)
        {
            if (g_poisoned[src] == kFakePfn1 || g_poisoned[src] == kFakePfn2)
                continue;
            g_poisoned[dst++] = g_poisoned[src];
        }
        g_count = dst;
    }
    if (PoisonedFrameCount() != saved_count)
    {
        core::Panic("mm/poison", "selftest: restore-original-state failed");
    }

    // Clear the suppress flag so a real SRAR after the selftest
    // emits its WARN sentinel.
    {
        sync::SpinLockGuard guard(g_poison_lock);
        g_selftest_in_progress = false;
    }

    SerialWrite("[mm/poison-selftest] PASS\n");
}

} // namespace duetos::mm
