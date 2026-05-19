#include "whp.h"

#include <cstdio>

namespace duetos::vmm
{

void ThrowIfFailed(HRESULT hr, const char* what)
{
    if (SUCCEEDED(hr))
    {
        return;
    }
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%s failed: hr=0x%08lX",
                  what, static_cast<unsigned long>(hr));
    throw std::runtime_error(buf);
}

bool HypervisorPresent()
{
    BOOL present = FALSE;
    UINT32 written = 0;
    HRESULT hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent,
                                  &present, sizeof(present), &written);
    return SUCCEEDED(hr) && written == sizeof(present) && present;
}

Partition::Partition(uint32_t cpuCount) : m_cpuCount(cpuCount)
{
    ThrowIfFailed(WHvCreatePartition(&m_handle), "WHvCreatePartition");

    WHV_PARTITION_PROPERTY prop = {};
    prop.ProcessorCount = cpuCount;
    ThrowIfFailed(WHvSetPartitionProperty(
                      m_handle, WHvPartitionPropertyCodeProcessorCount,
                      &prop, sizeof(prop)),
                  "SetPartitionProperty(ProcessorCount)");

    // Built-in xAPIC emulation: needed so the guest's LAPIC timer / IPI
    // path works without us emulating the whole APIC by hand. Slice 2
    // builds the timer on top of this.
    WHV_PARTITION_PROPERTY apic = {};
    apic.LocalApicEmulationMode = WHvX64LocalApicEmulationModeXApic;
    ThrowIfFailed(WHvSetPartitionProperty(
                      m_handle, WHvPartitionPropertyCodeLocalApicEmulationMode,
                      &apic, sizeof(apic)),
                  "SetPartitionProperty(LocalApicEmulationMode)");

    ThrowIfFailed(WHvSetupPartition(m_handle), "WHvSetupPartition");

    for (uint32_t i = 0; i < cpuCount; ++i)
    {
        ThrowIfFailed(WHvCreateVirtualProcessor(m_handle, i, 0),
                      "WHvCreateVirtualProcessor");
    }
}

Partition::~Partition()
{
    if (m_handle == nullptr)
    {
        return;
    }
    for (uint32_t i = 0; i < m_cpuCount; ++i)
    {
        WHvDeleteVirtualProcessor(m_handle, i);
    }
    WHvDeletePartition(m_handle);
}

void Partition::MapGpaRange(void* hostBase, uint64_t gpa, uint64_t bytes)
{
    const auto flags = static_cast<WHV_MAP_GPA_RANGE_FLAGS>(
        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite |
        WHvMapGpaRangeFlagExecute);
    ThrowIfFailed(
        WHvMapGpaRange(m_handle, hostBase, gpa, bytes, flags),
        "WHvMapGpaRange");
}

void Partition::GetRegisters(uint32_t vp, const WHV_REGISTER_NAME* names,
                             uint32_t count, WHV_REGISTER_VALUE* out) const
{
    ThrowIfFailed(
        WHvGetVirtualProcessorRegisters(m_handle, vp, names, count, out),
        "WHvGetVirtualProcessorRegisters");
}

void Partition::SetRegisters(uint32_t vp, const WHV_REGISTER_NAME* names,
                             uint32_t count, const WHV_REGISTER_VALUE* in)
{
    ThrowIfFailed(
        WHvSetVirtualProcessorRegisters(m_handle, vp, names, count, in),
        "WHvSetVirtualProcessorRegisters");
}

WHV_RUN_VP_EXIT_CONTEXT Partition::Run(uint32_t vp)
{
    WHV_RUN_VP_EXIT_CONTEXT exit = {};
    ThrowIfFailed(
        WHvRunVirtualProcessor(m_handle, vp, &exit, sizeof(exit)),
        "WHvRunVirtualProcessor");
    return exit;
}

} // namespace duetos::vmm
