// WHP partition + virtual-processor lifecycle, thin RAII over the
// Windows Hypervisor Platform C API. No DuetOS specifics here — this
// is a reusable hypervisor handle.
#pragma once

#include <windows.h>
#include <WinHvPlatform.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace duetos::vmm
{

// Throws std::runtime_error with a decoded message on FAILED(hr).
void ThrowIfFailed(HRESULT hr, const char* what);

// Returns true iff the Windows hypervisor is present and WHP is usable.
// Call before constructing a Partition so the failure is a clean
// diagnostic, not a deep WHvCreatePartition error.
bool HypervisorPresent();

class Partition
{
public:
    // Creates + sets up a partition with `cpuCount` vCPUs and the
    // local-APIC emulation mode required for timer/IRQ delivery.
    // When `debugExits` is set, #DB/#BP raise Exception exits so the
    // GDB stub can own them — left OFF otherwise so the kernel's own
    // int3-based probes keep trapping into the kernel, not the VMM.
    Partition(uint32_t cpuCount, bool debugExits);
    ~Partition();

    Partition(const Partition&) = delete;
    Partition& operator=(const Partition&) = delete;

    WHV_PARTITION_HANDLE handle() const { return m_handle; }

    // Maps `bytes` of host memory at `hostBase` into the guest physical
    // address space at `gpa`, read/write/execute.
    void MapGpaRange(void* hostBase, uint64_t gpa, uint64_t bytes);

    // Register get/set for vCPU 0 (single-vCPU v0; index is explicit so
    // SMP slices can widen it without an API change).
    void GetRegisters(uint32_t vp, const WHV_REGISTER_NAME* names,
                       uint32_t count, WHV_REGISTER_VALUE* out) const;
    void SetRegisters(uint32_t vp, const WHV_REGISTER_NAME* names,
                      uint32_t count, const WHV_REGISTER_VALUE* in);

    // Runs vCPU `vp` until the next exit. Caller dispatches on
    // exit.ExitReason.
    WHV_RUN_VP_EXIT_CONTEXT Run(uint32_t vp);

    // Asks WHP to make a thread-safe out-of-band run cancellation so
    // the host can break a guest that wedged with interrupts off.
    void CancelRun(uint32_t vp);

    // Injects an interrupt via the emulated LAPIC (xApic mode). Used
    // for IOAPIC-routed lines (serial IRQ4, PIT-ch0 IRQ0). The LAPIC
    // timer itself is delivered by WHP's own emulation.
    void RequestInterrupt(uint32_t vector, uint32_t destApicId,
                          bool levelTriggered);

    // General-purpose register access by x86 encoding index
    // (0=RAX,1=RCX,2=RDX,3=RBX,4=RSP,5=RBP,6=RSI,7=RDI,8..15=R8..R15).
    // Used by the MMIO instruction emulator.
    uint64_t GetGpr(uint32_t vp, uint32_t idx) const;
    void SetGpr(uint32_t vp, uint32_t idx, uint64_t value);
    uint64_t GetRip(uint32_t vp) const;
    void SetRip(uint32_t vp, uint64_t rip);

    // Walks the vCPU's active page tables. Returns true and sets
    // `gpa` (page offset preserved) on success; false if the GVA is
    // not mapped — used by the GDB stub's m/M packets.
    bool TranslateGva(uint32_t vp, uint64_t gva, uint64_t& gpa) const;

private:
    WHV_PARTITION_HANDLE m_handle = nullptr;
    uint32_t             m_cpuCount = 0;
};

} // namespace duetos::vmm
