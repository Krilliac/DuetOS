#include "arch/x86_64/hypervisor.h"

#include "arch/x86_64/cpu.h"
#include "log/klog.h"
#include "core/panic.h"
#include "arch/x86_64/serial.h"

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
    case HypervisorKind::Bochs:
        return "Bochs";
    default:
        return "unknown-hypervisor";
    }
}

namespace
{

// Bochs detection. Bochs's CPUID does NOT set leaf 1 ECX[31] (the
// standard hypervisor-present bit), so the leaf-0x40000000 vendor-
// string probe never fires. Bochs DOES respond to a read on I/O
// port 0xE9 — its built-in port_e9_hack — by returning 0xE9.
// Bare hardware leaves port 0xE9 unmapped (returns 0xFF). QEMU's
// debugcon device on the same port is write-only and reads 0xFF.
// So `inb(0xE9) == 0xE9` is a clean Bochs-only signal.
//
// The diff-boot harness's bochs row enables port_e9_hack in its
// generated bochsrc; without that the probe silently misses Bochs
// (and the kernel falls back to "bare metal" defaults, including
// the production-grade 100k PBKDF2 iteration count that turns
// boot into a multi-minute affair under Bochs's 50M-IPS pacing).
bool DetectBochsViaPortE9()
{
    return Inb(0xE9) == 0xE9;
}

} // namespace

void HypervisorProbe()
{
    KLOG_TRACE_SCOPE("arch/hypervisor", "Probe");
    KASSERT(!g_info.valid, "arch/hypervisor", "HypervisorProbe called twice");

    const CpuidRegs leaf1 = Cpuid(1);
    const bool hv_present = (leaf1.ecx & (1u << 31)) != 0;
    if (!hv_present)
    {
        // Secondary probe: Bochs doesn't set leaf 1 ECX[31] but
        // does answer port 0xE9 reads with 0xE9. Worth checking
        // before declaring bare metal — the difference matters
        // for downstream code that wants to dial back PBKDF2,
        // skip pentest brute-force probes, etc.
        if (DetectBochsViaPortE9())
        {
            g_info.kind = HypervisorKind::Bochs;
            const char bochs_vendor[] = "BochsBochsBoc"; // 12 chars
            for (u32 i = 0; i < 12; ++i)
            {
                g_info.vendor[i] = bochs_vendor[i];
            }
            g_info.vendor[12] = '\0';
            g_info.max_leaf = 0;
            g_info.valid = true;
            SerialWrite("[hv] Bochs (port 0xE9 read-back)\n");
            return;
        }
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
