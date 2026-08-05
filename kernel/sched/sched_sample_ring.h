#pragma once

#include "util/types.h"

/*
 * DuetOS — per-second CPU-utilisation sample ring.
 *
 * FREESTANDING on purpose: pure struct + inline methods over a fixed
 * array, no kernel headers, no globals. `tests/host/test_sched_sample_ring.cpp`
 * exercises Push/Read/Count directly; the kernel caller is the 1 Hz
 * UiTickerTask in `kernel/core/boot_tasks.cpp`.
 *
 * The ring stores 60 u8 samples (one per second, one minute of history)
 * and is the single data source for:
 *
 *   - The gadget column's 46-px CPU sparkline
 *   - The taskbar stats pill's 52-px sparkline
 *   - The gadget column's "CPU NN%" stat row
 *
 * A global instance is pushed once per second from UiTickerTask.
 * Consumers read under the compositor lock (same thread), so no
 * separate synchronisation is needed.
 */

namespace duetos::sched
{

struct CpuSampleRing
{
    static constexpr u32 kCapacity = 60;

    u8 samples[kCapacity]{};
    u32 head{0};
    u32 count{0};

    /// Push a new utilisation sample (0..100). Advances the write head
    /// and clamps count at kCapacity.
    void Push(u8 pct)
    {
        samples[head] = pct;
        head = (head + 1U) % kCapacity;
        if (count < kCapacity)
        {
            ++count;
        }
    }

    /// Read a sample by age. age=0 is the newest sample, age=1 the
    /// one before that, and so on. Returns 0 for ages past the valid
    /// count (not-yet-filled region or out-of-range).
    u8 Read(u32 age) const
    {
        if (age >= count)
        {
            return 0;
        }
        // head points to the NEXT write slot, so the newest sample is
        // at (head - 1) mod kCapacity.
        const u32 idx = (head + kCapacity - 1U - age) % kCapacity;
        return samples[idx];
    }

    /// Number of valid samples in the ring (0..kCapacity).
    u32 Count() const { return count; }
};

/// Global CPU sample ring. Pushed once per second from UiTickerTask;
/// read by the compositor (gadgets, taskbar) under the same lock.
/// Declared here so both the push site (boot_tasks.cpp) and the
/// consumers (desktop_gadgets.cpp, taskbar.cpp) share the instance.
inline CpuSampleRing g_cpu_sample_ring{};

} // namespace duetos::sched
