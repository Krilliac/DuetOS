#include "guest_memory.h"

#include <cstring>
#include <stdexcept>

namespace duetos::vmm
{

uint64_t GuestMemory::ReserveFramebuffer(uint32_t width, uint32_t height)
{
    if (m_fbGpa != 0)
    {
        return m_fbGpa;
    }
    uint64_t gpa   = 0;
    uint64_t bytes = 0;
    if (!ComputeFbRegion(m_bytes, width, height, gpa, bytes))
    {
        throw std::runtime_error("ReserveFramebuffer: region does not fit in guest RAM");
    }
    m_fbGpa   = gpa;
    m_fbBytes = bytes;
    return m_fbGpa;
}

uint8_t* GuestMemory::FramebufferHost()
{
    if (m_fbGpa == 0)
    {
        return nullptr;
    }
    return static_cast<uint8_t*>(HostPtr(m_fbGpa, m_fbBytes));
}

uint64_t GuestMemory::FramebufferGpa() const
{
    return m_fbGpa;
}

uint64_t GuestMemory::FramebufferBytes() const
{
    return m_fbBytes;
}

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
