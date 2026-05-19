// Guest physical RAM: one contiguous host allocation mapped 1:1 at
// GPA 0. Identity host<->guest translation keeps the firmware/ELF
// blitting code trivial and matches boot.S's identity map of the
// low 1 GiB.
#pragma once

#include <cstdint>

#include "whp.h"

namespace duetos::vmm
{

class GuestMemory
{
public:
    // Reserves+commits `bytes` of page-aligned host RAM and maps it at
    // guest physical address 0.
    GuestMemory(Partition& part, uint64_t bytes);
    ~GuestMemory();

    GuestMemory(const GuestMemory&) = delete;
    GuestMemory& operator=(const GuestMemory&) = delete;

    uint64_t size() const { return m_bytes; }

    // Host pointer to guest physical address `gpa`. Returns nullptr if
    // the range [gpa, gpa+len) is out of bounds.
    void* HostPtr(uint64_t gpa, uint64_t len = 1) const;

    // Copies `len` bytes from host `src` into guest physical `gpa`.
    // Throws std::out_of_range if the destination escapes RAM.
    void Write(uint64_t gpa, const void* src, uint64_t len);

private:
    uint8_t* m_base  = nullptr;
    uint64_t m_bytes = 0;
};

} // namespace duetos::vmm
