#include "ahci.h"

#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

namespace customos::drivers::storage
{

namespace
{

// AHCI HBA (Host Bus Adapter) MMIO register offsets.
// Full spec: Serial ATA AHCI 1.3.1 §3.
constexpr u64 kHbaRegCap = 0x00; // Capabilities
constexpr u64 kHbaRegGhc = 0x04; // Global Host Control
constexpr u64 kHbaRegIs = 0x08;  // Interrupt Status
constexpr u64 kHbaRegPi = 0x0C;  // Ports Implemented (bitmap, 1 bit / port)
constexpr u64 kHbaRegVs = 0x10;  // Version
constexpr u64 kHbaPortsBase = 0x100;
constexpr u64 kHbaPortStride = 0x80;

// Per-port register offsets (relative to PortsBase + port_index * PortStride).
constexpr u64 kPortRegClb = 0x00;  // Command List Base (low 32)
constexpr u64 kPortRegCmd = 0x18;  // Command + Status
constexpr u64 kPortRegTfd = 0x20;  // Task File Data
constexpr u64 kPortRegSig = 0x24;  // Signature (SATA device type fingerprint)
constexpr u64 kPortRegSsts = 0x28; // SATA Status (DET field in bits 3..0)

// Signature values the spec defines for AHCI ports.
//   0x00000101 — SATA direct-attached drive (the only one we care about in v0)
//   0xEB140101 — SATA ATAPI (optical)
//   0xC33C0101 — Enclosure Management Bridge
//   0x96690101 — Port Multiplier
constexpr u32 kAhciSigSata = 0x00000101u;
constexpr u32 kAhciSigAtapi = 0xEB140101u;

// SATA Status DET field values (bits 3..0 of SSTS).
//   0x0  no device detected, no PHY
//   0x1  device present, PHY not established
//   0x3  device present, PHY established — ready for use
//   0x4  offline mode (disabled)
constexpr u32 kSstsDetReady = 0x3;

// AHCI is PCI class 0x01 / subclass 0x06 / prog_if 0x01.
constexpr u8 kPciClassMassStorage = 0x01;
constexpr u8 kPciSubclassSata = 0x06;
constexpr u8 kPciProgIfAhci = 0x01;

const pci::Device* FindAhci()
{
    for (u64 i = 0; i < pci::PciDeviceCount(); ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code == kPciClassMassStorage && d.subclass == kPciSubclassSata && d.prog_if == kPciProgIfAhci)
        {
            return &d;
        }
    }
    return nullptr;
}

const char* SignatureName(u32 sig)
{
    switch (sig)
    {
    case kAhciSigSata:
        return "SATA";
    case kAhciSigAtapi:
        return "SATA-ATAPI";
    case 0xC33C0101u:
        return "SEMB";
    case 0x96690101u:
        return "port-multiplier";
    case 0xFFFFFFFFu:
        return "empty";
    default:
        return "unknown";
    }
}

inline volatile u32& HbaReg(volatile u8* base, u64 offset)
{
    return *reinterpret_cast<volatile u32*>(base + offset);
}

void LogPort(volatile u8* hba, u32 port_idx)
{
    volatile u8* port = hba + kHbaPortsBase + port_idx * kHbaPortStride;
    const u32 ssts = HbaReg(port, kPortRegSsts);
    const u32 det = ssts & 0xF;
    const u32 sig = HbaReg(port, kPortRegSig);
    const u32 tfd = HbaReg(port, kPortRegTfd);
    const u32 cmd = HbaReg(port, kPortRegCmd);

    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  port index", port_idx);
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "    ssts(det)", det);
    if (det == kSstsDetReady)
    {
        core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "    sig", sig);
        core::Log(core::LogLevel::Info, "drivers/ahci", SignatureName(sig));
        core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "    tfd", tfd);
        core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "    cmd", cmd);
    }
}

} // namespace

void AhciInit()
{
    const pci::Device* dev = FindAhci();
    if (dev == nullptr)
    {
        core::Log(core::LogLevel::Warn, "drivers/ahci", "no AHCI controller on any PCI bus");
        return;
    }

    // BAR5 holds the HBA register window (AHCI spec §2.1.3 "AHCI
    // Base Memory Register"). BARs 0..4 are optional legacy
    // task-file I/O ports; we don't use them.
    const pci::Bar bar5 = pci::PciReadBar(dev->addr, 5);
    if (bar5.size == 0 || bar5.is_io)
    {
        core::Log(core::LogLevel::Error, "drivers/ahci", "BAR5 missing or I/O — not a valid AHCI HBA");
        return;
    }

    void* mmio = mm::MapMmio(bar5.address, bar5.size);
    if (mmio == nullptr)
    {
        core::Panic("drivers/ahci", "MapMmio failed for HBA window");
    }

    auto* hba = static_cast<volatile u8*>(mmio);
    const u32 cap = HbaReg(hba, kHbaRegCap);
    const u32 vs = HbaReg(hba, kHbaRegVs);
    const u32 pi = HbaReg(hba, kHbaRegPi);
    const u32 ghc = HbaReg(hba, kHbaRegGhc);

    // CAP bits 4..0 (NP) = number of ports - 1.
    const u32 num_ports = (cap & 0x1F) + 1;

    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "controller at pci bar5", static_cast<u64>(bar5.address));
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  abar mmio", reinterpret_cast<u64>(hba));
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  cap", cap);
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  vs ", vs);
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  pi ", pi);
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  ghc", ghc);
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  num_ports", num_ports);

    for (u32 i = 0; i < num_ports && i < 32; ++i)
    {
        if ((pi & (1U << i)) == 0)
        {
            continue; // port not implemented
        }
        LogPort(hba, i);
    }
}

} // namespace customos::drivers::storage
