#include "hypervisor.h"

#include "../../core/klog.h"
#include "../../core/panic.h"
#include "serial.h"

namespace duetos::arch
{

namespace
{

constinit HypervisorInfo g_info = {};

struct CpuidRegs
{
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
};

inline CpuidRegs Cpuid(u32 leaf, u32 subleaf = 0)
{
    CpuidRegs r{};
    asm volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx) : "a"(leaf), "c"(subleaf));
    return r;
}

bool VendorEquals(const char* a, const char* b)
{
    for (u32 i = 0; i < 12; ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

HypervisorKind Classify(const char* vendor)
{
    // Vendor strings per each VMM's public documentation. Order
    // picked by frequency of occurrence in a developer's life —
    // KVM and TCG first because a DuetOS dev on Linux hits
    // these constantly.
    if (VendorEquals(vendor, "KVMKVMKVM\0\0\0"))
        return HypervisorKind::Kvm;
    if (VendorEquals(vendor, "TCGTCGTCGTCG"))
        return HypervisorKind::QemuTcg;
    if (VendorEquals(vendor, "VMwareVMware"))
        return HypervisorKind::VmwareEsx;
    if (VendorEquals(vendor, "VBoxVBoxVBox"))
        return HypervisorKind::VirtualBox;
    if (VendorEquals(vendor, "Microsoft Hv"))
        return HypervisorKind::HyperV;
    if (VendorEquals(vendor, "XenVMMXenVMM"))
        return HypervisorKind::Xen;
    if (VendorEquals(vendor, " lrpepyh  vr"))
        return HypervisorKind::Parallels;
    if (VendorEquals(vendor, "ACRNACRNACRN"))
        return HypervisorKind::Acrn;
    if (VendorEquals(vendor, "bhyve bhyve "))
        return HypervisorKind::Bhyve;
    if (VendorEquals(vendor, "QNXQVMBSQG\0\0"))
        return HypervisorKind::Qnx;
    return HypervisorKind::Unknown;
}

} // namespace

const char* HypervisorName(HypervisorKind k)
{
    switch (k)
    {
    case HypervisorKind::None:
        return "bare-metal";
    case HypervisorKind::Kvm:
        return "KVM";
    case HypervisorKind::QemuTcg:
        return "QEMU/TCG";
    case HypervisorKind::VmwareEsx:
        return "VMware";
    case HypervisorKind::VirtualBox:
        return "VirtualBox";
    case HypervisorKind::HyperV:
        return "Hyper-V";
    case HypervisorKind::Xen:
        return "Xen";
    case HypervisorKind::Parallels:
        return "Parallels";
    case HypervisorKind::Acrn:
        return "ACRN";
    case HypervisorKind::Bhyve:
        return "bhyve";
    case HypervisorKind::Qnx:
        return "QNX";
    default:
        return "unknown-hypervisor";
    }
}

void HypervisorProbe()
{
    KLOG_TRACE_SCOPE("arch/hypervisor", "Probe");
    KASSERT(!g_info.valid, "arch/hypervisor", "HypervisorProbe called twice");

    const CpuidRegs leaf1 = Cpuid(1);
    const bool hv_present = (leaf1.ecx & (1u << 31)) != 0;
    if (!hv_present)
    {
        g_info.kind = HypervisorKind::None;
        g_info.vendor[0] = '\0';
        g_info.max_leaf = 0;
        g_info.valid = true;
        SerialWrite("[hv] bare metal (CPUID.1.ECX[31]=0)\n");
        return;
    }

    // Vendor string lives in EBX:ECX:EDX of leaf 0x40000000 — same
    // layout as the CPU vendor string at leaf 0. Some VMMs return
    // an all-zero max_leaf; treat that as Unknown.
    const CpuidRegs hv_leaf = Cpuid(0x40000000);
    g_info.max_leaf = hv_leaf.eax;
    for (u32 i = 0; i < 4; ++i)
    {
        g_info.vendor[0 + i] = char((hv_leaf.ebx >> (i * 8)) & 0xFF);
        g_info.vendor[4 + i] = char((hv_leaf.ecx >> (i * 8)) & 0xFF);
        g_info.vendor[8 + i] = char((hv_leaf.edx >> (i * 8)) & 0xFF);
    }
    g_info.vendor[12] = '\0';
    g_info.kind = Classify(g_info.vendor);
    g_info.valid = true;

    SerialWrite("[hv] hypervisor present vendor=\"");
    SerialWrite(g_info.vendor);
    SerialWrite("\" kind=");
    SerialWrite(HypervisorName(g_info.kind));
    SerialWrite(" max_leaf=");
    SerialWriteHex(g_info.max_leaf);
    SerialWrite("\n");
}

const HypervisorInfo& HypervisorInfoGet()
{
    return g_info;
}

bool IsBareMetal()
{
    return g_info.valid && g_info.kind == HypervisorKind::None;
}

bool IsEmulator()
{
    return g_info.valid && g_info.kind != HypervisorKind::None;
}

} // namespace duetos::arch
