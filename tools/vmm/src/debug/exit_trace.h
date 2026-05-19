// Fixed-size ring of recent vmexits. Always on (negligible cost) —
// dumped via `monitor trace` and printed automatically on a fatal
// or unexpected exit so a crash leaves the last-N-exit history
// behind, the host-side analogue of the kernel's boot-log trail.
#pragma once

#include <cstdint>
#include <functional>

namespace duetos::vmm
{

class ExitTrace
{
public:
    static constexpr uint32_t kCap = 256;

    struct Entry
    {
        uint64_t seq  = 0;
        uint32_t reason = 0;
        uint64_t rip  = 0;
        uint64_t aux  = 0; // port / GPA / exception type, by reason
    };

    void Record(uint32_t reason, uint64_t rip, uint64_t aux);

    // Oldest -> newest. `sink` receives each live entry.
    void ForEach(const std::function<void(const Entry&)>& sink) const;

    uint64_t total() const { return m_seq; }

private:
    Entry    m_ring[kCap];
    uint32_t m_head = 0;   // next write slot
    uint64_t m_seq  = 0;   // monotonic exit counter
};

} // namespace duetos::vmm
