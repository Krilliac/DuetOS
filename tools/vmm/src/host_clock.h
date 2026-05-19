// Monotonic host nanosecond clock (QueryPerformanceCounter). The
// PIT channel-2 calibration models its countdown against real host
// time so the ratio the kernel measures against WHP's real-time
// LAPIC counter stays correct.
#pragma once

#include <windows.h>

#include <cstdint>

namespace duetos::vmm
{

inline uint64_t HostNanos()
{
    static const int64_t freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return f.QuadPart;
    }();
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    // (counter / freq) seconds -> ns, ordered to avoid overflow.
    return static_cast<uint64_t>(
        (c.QuadPart / freq) * 1000000000ull +
        ((c.QuadPart % freq) * 1000000000ull) / freq);
}

} // namespace duetos::vmm
