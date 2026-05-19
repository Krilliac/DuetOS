// Top-level VMM: owns the partition, lays out guest RAM, loads the
// kernel + synthesised firmware, brings the vCPU up in the 32-bit
// protected-mode state Multiboot2 mandates, and runs the exit loop.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include "devices/ioapic.h"
#include "devices/pit8254.h"
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
    // Break the run after this many seconds of COM1 silence. 0
    // disables the watchdog (the default — an interactive shell is
    // legitimately silent while waiting at a prompt). Headless/CI
    // runs pass a positive value to bound a wedged boot.
    uint32_t    idleSecs  = 0;
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
    ~Vmm();

    // Boots the guest and runs the exit loop until the guest halts,
    // faults, or the idle watchdog fires. Returns a process exit code.
    int Run();

private:
    void SetupVcpu(uint64_t entry, uint64_t mbInfoGpa);
    void HandleIoPort(const WHV_RUN_VP_EXIT_CONTEXT& exit);
    void StartHelperThreads();

    VmConfig                       m_cfg;
    Partition                      m_part;
    std::unique_ptr<GuestMemory>   m_mem;
    Serial16550                    m_com1;
    Pit8254                        m_pit;
    IoApic                         m_ioapic;

    std::atomic<bool>     m_stop{false};
    std::atomic<uint64_t> m_lastTxNs{0}; // last COM1 output, for watchdog
    std::thread           m_stdinThread;
    std::thread           m_timerThread;
    std::thread           m_watchdogThread;
};

} // namespace duetos::vmm
