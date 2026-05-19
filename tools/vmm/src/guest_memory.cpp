#include "guest_memory.h"

#include <cstring>
#include <stdexcept>

namespace duetos::vmm
{

GuestMemory::GuestMemory(Partition& part, uint64_t bytes) : m_bytes(bytes)
{
    m_base = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE));
    if (m_base == nullptr)
    {
        throw std::runtime_error("VirtualAlloc for guest RAM failed");
    }
    part.MapGpaRange(m_base, /*gpa=*/0, bytes);
}

GuestMemory::~GuestMemory()
{
    if (m_base != nullptr)
    {
        VirtualFree(m_base, 0, MEM_RELEASE);
    }
}

void* GuestMemory::HostPtr(uint64_t gpa, uint64_t len) const
{
    if (gpa > m_bytes || len > m_bytes || gpa + len > m_bytes)
    {
        return nullptr;
    }
    return m_base + gpa;
}

void GuestMemory::Write(uint64_t gpa, const void* src, uint64_t len)
{
    void* dst = HostPtr(gpa, len);
    if (dst == nullptr)
    {
        throw std::out_of_range("GuestMemory::Write past end of RAM");
    }
    std::memcpy(dst, src, static_cast<size_t>(len));
}

} // namespace duetos::vmm
