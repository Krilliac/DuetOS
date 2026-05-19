#include "debug/exit_trace.h"

namespace duetos::vmm
{

void ExitTrace::Record(uint32_t reason, uint64_t rip, uint64_t aux)
{
    Entry& e = m_ring[m_head];
    e.seq = m_seq++;
    e.reason = reason;
    e.rip = rip;
    e.aux = aux;
    m_head = (m_head + 1) % kCap;
}

void ExitTrace::ForEach(
    const std::function<void(const Entry&)>& sink) const
{
    const uint64_t live = (m_seq < kCap) ? m_seq : kCap;
    // Oldest live slot: when wrapped, that's m_head; otherwise 0.
    uint32_t idx = (m_seq < kCap) ? 0 : m_head;
    for (uint64_t i = 0; i < live; ++i)
    {
        sink(m_ring[idx]);
        idx = (idx + 1) % kCap;
    }
}

} // namespace duetos::vmm
