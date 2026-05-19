// Top-level VMM: owns the partition, lays out guest RAM, loads the
// kernel + synthesised firmware, brings the vCPU up in the 32-bit
// protected-mode state Multiboot2 mandates, and runs the exit loop.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "devices/serial16550.h"
#include "guest_memory.h"
#include "whp.h"

namespace duetos::vmm
{

struct VmConfig
{
    std::string kernelPath;
    std::string cmdline   = "console=ttyS0";
    uint64_t    ramBytes  = 512ull * 1024 * 1024;
};

// Fixed guest-physical homes for the synthesised firmware blobs.
// Both sit below the kernel's 1 MiB load address and inside the
// region the mmap marks reserved, so the frame allocator never
// reclaims them.
constexpr uint64_t kMbInfoGpa = 0x00010000; // 64 KiB
constexpr uint64_t kAcpiGpa   = 0x00080000; // 512 KiB

class Vmm
{
public:
    explicit Vmm(VmConfig cfg);

    // Boots the guest and runs the exit loop until the guest halts,
    // faults, or hits a slice boundary. Returns a process exit code.
    int Run();

private:
    void SetupVcpu(uint64_t entry, uint64_t mbInfoGpa);
    bool HandleIoPort(const WHV_RUN_VP_EXIT_CONTEXT& exit);

    VmConfig                       m_cfg;
    Partition                      m_part;
    std::unique_ptr<GuestMemory>   m_mem;
    Serial16550                    m_com1;
};

} // namespace duetos::vmm
