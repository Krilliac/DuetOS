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

void Partition::CancelRun(uint32_t vp)
{
    WHvCancelRunVirtualProcessor(m_handle, vp, 0);
}

void Partition::RequestInterrupt(uint32_t vector, uint32_t destApicId,
                                 bool levelTriggered)
{
    WHV_INTERRUPT_CONTROL ic = {};
    ic.Type = WHvX64InterruptTypeFixed;
    ic.DestinationMode = WHvX64InterruptDestinationModePhysical;
    ic.TriggerMode = levelTriggered ? WHvX64InterruptTriggerModeLevel
                                    : WHvX64InterruptTriggerModeEdge;
    ic.Destination = destApicId;
    ic.Vector = vector;
    ThrowIfFailed(WHvRequestInterrupt(m_handle, &ic, sizeof(ic)),
                  "WHvRequestInterrupt");
}

namespace
{
// x86 GPR encoding order -> WHP register name.
constexpr WHV_REGISTER_NAME kGpr[16] = {
    WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
    WHvX64RegisterRbx, WHvX64RegisterRsp, WHvX64RegisterRbp,
    WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterR8,
    WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
    WHvX64RegisterR15};
} // namespace

uint64_t Partition::GetGpr(uint32_t vp, uint32_t idx) const
{
    WHV_REGISTER_VALUE v = {};
    GetRegisters(vp, &kGpr[idx & 15], 1, &v);
    return v.Reg64;
}

void Partition::SetGpr(uint32_t vp, uint32_t idx, uint64_t value)
{
    WHV_REGISTER_VALUE v = {};
    v.Reg64 = value;
    SetRegisters(vp, &kGpr[idx & 15], 1, &v);
}

uint64_t Partition::GetRip(uint32_t vp) const
{
    WHV_REGISTER_NAME n = WHvX64RegisterRip;
    WHV_REGISTER_VALUE v = {};
    GetRegisters(vp, &n, 1, &v);
    return v.Reg64;
}

void Partition::SetRip(uint32_t vp, uint64_t rip)
{
    WHV_REGISTER_NAME n = WHvX64RegisterRip;
    WHV_REGISTER_VALUE v = {};
    v.Reg64 = rip;
    SetRegisters(vp, &n, 1, &v);
}

} // namespace duetos::vmm
