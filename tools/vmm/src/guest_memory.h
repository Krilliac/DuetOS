// Guest physical RAM: one contiguous host allocation mapped 1:1 at
// GPA 0. Identity host<->guest translation keeps the firmware/ELF
// blitting code trivial and matches boot.S's identity map of the
// low 1 GiB.
#pragma once

#include <cstdint>

#include "whp.h"

namespace duetos::vmm
{

// Compute a page-aligned framebuffer region just below the top of
// guest RAM. Pure function — no WHP dependency — so the test harness
// can exercise it without a live partition.
// On return: gpa = guest-physical base (page-aligned), bytes = byte
// length (page-rounded up from width*height*4).
// Returns false and leaves gpa/bytes unchanged if the region would
// not fit inside ramBytes.
bool ComputeFbRegion(uint64_t ramBytes, uint32_t width, uint32_t height,
                     uint64_t& gpa, uint64_t& bytes);

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

    // Carve a page-aligned framebuffer region just below the top of
    // guest RAM. Returns the guest-physical base; host-side pointer
    // via FramebufferHost(). Idempotent: a second call with the same
    // size returns the same base. Must be called before the MB2 mmap
    // is built so the region can be flagged reserved.
    uint64_t ReserveFramebuffer(uint32_t width, uint32_t height);
    uint8_t* FramebufferHost();        // nullptr if not reserved
    uint64_t FramebufferGpa() const;   // 0 if not reserved
    uint64_t FramebufferBytes() const; // 0 if not reserved

private:
    uint8_t* m_base    = nullptr;
    uint64_t m_bytes   = 0;
    uint64_t m_fbGpa   = 0;
    uint64_t m_fbBytes = 0;
};

} // namespace duetos::vmm
