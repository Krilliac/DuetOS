#include "ahci.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"
#include "block.h"

namespace customos::drivers::storage
{

namespace
{

// ---------------------------------------------------------------
// AHCI spec numbers. All offsets come from Serial ATA AHCI 1.3.1
// §3 (HBA registers) and §3.3 (port registers). ATA commands +
// FIS layouts come from ACS-4 and Serial ATA 3.3.
// ---------------------------------------------------------------

constexpr u64 kHbaRegCap = 0x00;
constexpr u64 kHbaRegGhc = 0x04;
constexpr u64 kHbaRegPi = 0x0C;
constexpr u64 kHbaRegVs = 0x10;
constexpr u64 kHbaPortsBase = 0x100;
constexpr u64 kHbaPortStride = 0x80;

constexpr u32 kGhcAe = 1u << 31; // AHCI Enable

constexpr u64 kPortRegClb = 0x00;
constexpr u64 kPortRegClbu = 0x04;
constexpr u64 kPortRegFb = 0x08;
constexpr u64 kPortRegFbu = 0x0C;
constexpr u64 kPortRegIs = 0x10;
constexpr u64 kPortRegCmd = 0x18;
constexpr u64 kPortRegTfd = 0x20;
constexpr u64 kPortRegSig = 0x24;
constexpr u64 kPortRegSsts = 0x28;
constexpr u64 kPortRegSerr = 0x30;
constexpr u64 kPortRegCi = 0x38;

constexpr u32 kCmdSt = 1u << 0;  // Start
constexpr u32 kCmdFre = 1u << 4; // FIS Receive Enable
constexpr u32 kCmdFr = 1u << 14; // FIS Receive Running
constexpr u32 kCmdCr = 1u << 15; // Command List Running

constexpr u32 kTfdBsy = 1u << 7;
constexpr u32 kTfdDrq = 1u << 3;

constexpr u32 kIsTfes = 1u << 30; // Task File Error Status

constexpr u32 kAhciSigSata = 0x00000101u;
constexpr u32 kAhciSigAtapi = 0xEB140101u;
constexpr u32 kSstsDetReady = 0x3;

constexpr u8 kPciClassMassStorage = 0x01;
constexpr u8 kPciSubclassSata = 0x06;
constexpr u8 kPciProgIfAhci = 0x01;

constexpr u8 kFisH2dRegister = 0x27;

constexpr u8 kAtaCmdIdentify = 0xEC;
constexpr u8 kAtaCmdReadDmaExt = 0x25;
constexpr u8 kAtaCmdWriteDmaExt = 0x35;

constexpr u32 kSectorSize = 512;      // v1: hard-assume 512 B sectors.
constexpr u32 kMaxSectorsPerXfer = 8; // 4 KiB — fits one frame.

constexpr u64 kCmdListOffset = 0;     // bytes 0..1023   (1 KiB)
constexpr u64 kFisOffset = 1024;      // bytes 1024..1279 (256 B, 256-aligned)
constexpr u64 kCmdTableOffset = 1280; // bytes 1280..1535 (256 B, 128-aligned)
constexpr u64 kIdentOffset = 1536;    // bytes 1536..2047 (512 B IDENTIFY reply)

constexpr u64 kMaxPorts = 32;
constexpr u64 kMaxControllers = 4;

// ---------------------------------------------------------------
// On-wire structures. Packed / fixed-size.
// ---------------------------------------------------------------

struct [[gnu::packed]] CmdHeader
{
    u16 flags; // CFL[4:0] | A | W | P | R | B | C | RSV | PMP[3:0]
    u16 prdtl; // PRD entries
    u32 prdbc; // byte count (HBA writes on completion)
    u32 ctba;  // command table base, low
    u32 ctbau; // command table base, high
    u32 reserved[4];
};
static_assert(sizeof(CmdHeader) == 32);

struct [[gnu::packed]] PrdtEntry
{
    u32 dba;  // data base, low
    u32 dbau; // data base, high
    u32 reserved;
    u32 dbc; // bits 0..21: byte count - 1. bit 31: interrupt-on-complete.
};
static_assert(sizeof(PrdtEntry) == 16);

struct [[gnu::packed]] FisH2dReg
{
    u8 fis_type; // 0x27
    u8 pmport_c; // bit 7 = C (command), bits 0..3 = PM port
    u8 command;
    u8 featurel;
    u8 lba0;
    u8 lba1;
    u8 lba2;
    u8 device;
    u8 lba3;
    u8 lba4;
    u8 lba5;
    u8 featureh;
    u8 countl;
    u8 counth;
    u8 icc;
    u8 control;
    u32 reserved;
};
static_assert(sizeof(FisH2dReg) == 20);

struct [[gnu::packed]] CmdTable
{
    FisH2dReg cfis;
    u8 cfis_pad[64 - sizeof(FisH2dReg)];
    u8 acmd[16];
    u8 reserved[48];
    PrdtEntry prdt[1]; // v1: one PRD per command
};
static_assert(sizeof(CmdTable) == 128 + sizeof(PrdtEntry));

// ---------------------------------------------------------------
// Per-port driver state.
// ---------------------------------------------------------------

struct Port
{
    volatile u8* regs; // per-port MMIO window (hba + 0x100 + idx*0x80)
    u32 port_idx;
    u32 ctrl_idx;              // which AHCI controller this port lives on
    mm::PhysAddr scratch_phys; // 4 KiB frame holding cmd list + FIS + cmd table
    u8* scratch_virt;          // direct-map alias
    u64 sector_count;          // from IDENTIFY
    u32 block_handle;          // block layer handle, or kBlockHandleInvalid
    char name[12];             // "sata0".."sata7"
    bool online;
};

Port g_ports[kMaxPorts];
u32 g_port_count = 0;
bool g_init_done = false;

volatile u32& Reg(volatile u8* base, u64 off)
{
    return *reinterpret_cast<volatile u32*>(base + off);
}

void CpuPause()
{
    asm volatile("pause" ::: "memory");
}

// Byte-wise zero. Written through a volatile pointer so clang's
// loop idiom recognizer does NOT lower the loop to a libc memset
// call — we have no libc in the freestanding kernel. Use for every
// zero-before-use in this driver (cmd list, cmd table, scratch
// frame); using it at DMA-visible memory also inhibits reordering.
void VolatileZero(void* p, u64 n)
{
    auto* b = reinterpret_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

void PortStop(volatile u8* port)
{
    // Clear ST and FRE, then wait for CR and FR to clear.
    Reg(port, kPortRegCmd) &= ~kCmdSt;
    for (u32 i = 0; i < 10000; ++i)
    {
        if ((Reg(port, kPortRegCmd) & kCmdCr) == 0)
            break;
        CpuPause();
    }
    Reg(port, kPortRegCmd) &= ~kCmdFre;
    for (u32 i = 0; i < 10000; ++i)
    {
        if ((Reg(port, kPortRegCmd) & kCmdFr) == 0)
            break;
        CpuPause();
    }
}

bool PortStart(volatile u8* port)
{
    // Per spec: wait for BSY and DRQ in PxTFD to be clear before
    // starting. Then set FRE and ST.
    for (u32 i = 0; i < 10000; ++i)
    {
        if ((Reg(port, kPortRegTfd) & (kTfdBsy | kTfdDrq)) == 0)
            break;
        CpuPause();
    }
    if ((Reg(port, kPortRegTfd) & (kTfdBsy | kTfdDrq)) != 0)
    {
        return false;
    }
    Reg(port, kPortRegCmd) |= kCmdFre;
    Reg(port, kPortRegCmd) |= kCmdSt;
    return true;
}

// Returns true + leaves PxCI zeroed if the command issued on slot
// 0 finishes without the TFES error bit. Polls PxCI for up to a
// generous retry window; returns false on timeout or error.
bool IssueSlot0(volatile u8* port)
{
    // Clear stale interrupt status + task-file errors.
    Reg(port, kPortRegIs) = 0xFFFFFFFFu;
    Reg(port, kPortRegSerr) = 0xFFFFFFFFu;
    Reg(port, kPortRegCi) = 1u << 0;

    for (u32 i = 0; i < 1000000; ++i)
    {
        const u32 ci = Reg(port, kPortRegCi);
        const u32 is = Reg(port, kPortRegIs);
        if ((is & kIsTfes) != 0)
        {
            return false;
        }
        if ((ci & 1u) == 0)
        {
            return true;
        }
        CpuPause();
    }
    return false;
}

// Build the command header + command table for a single-PRD
// transfer. `dir_write` toggles the H bit; we only use it=false
// in v1 (no writes) but parametrise for the future write path.
void BuildCmd(Port& p, u8 ata_cmd, u64 lba, u16 sectors, mm::PhysAddr buf_phys, u32 buf_bytes, bool dir_write)
{
    auto* hdr = reinterpret_cast<CmdHeader*>(p.scratch_virt + kCmdListOffset);
    auto* tbl = reinterpret_cast<CmdTable*>(p.scratch_virt + kCmdTableOffset);
    const mm::PhysAddr tbl_phys = p.scratch_phys + kCmdTableOffset;

    VolatileZero(hdr, sizeof(CmdHeader) * 32);

    // Slot 0 only.
    hdr[0].flags = static_cast<u16>(sizeof(FisH2dReg) / 4); // CFL in DWORDs
    if (dir_write)
    {
        hdr[0].flags |= 1u << 6; // W bit
    }
    hdr[0].prdtl = 1;
    hdr[0].prdbc = 0;
    hdr[0].ctba = static_cast<u32>(tbl_phys & 0xFFFFFFFFu);
    hdr[0].ctbau = static_cast<u32>(tbl_phys >> 32);

    VolatileZero(tbl, sizeof(CmdTable));

    tbl->cfis.fis_type = kFisH2dRegister;
    tbl->cfis.pmport_c = 1u << 7; // C = 1 (Command)
    tbl->cfis.command = ata_cmd;
    tbl->cfis.device = 1u << 6; // LBA mode
    tbl->cfis.lba0 = static_cast<u8>(lba & 0xFF);
    tbl->cfis.lba1 = static_cast<u8>((lba >> 8) & 0xFF);
    tbl->cfis.lba2 = static_cast<u8>((lba >> 16) & 0xFF);
    tbl->cfis.lba3 = static_cast<u8>((lba >> 24) & 0xFF);
    tbl->cfis.lba4 = static_cast<u8>((lba >> 32) & 0xFF);
    tbl->cfis.lba5 = static_cast<u8>((lba >> 40) & 0xFF);
    tbl->cfis.countl = static_cast<u8>(sectors & 0xFF);
    tbl->cfis.counth = static_cast<u8>((sectors >> 8) & 0xFF);

    tbl->prdt[0].dba = static_cast<u32>(buf_phys & 0xFFFFFFFFu);
    tbl->prdt[0].dbau = static_cast<u32>(buf_phys >> 32);
    tbl->prdt[0].dbc = buf_bytes - 1; // HBA expects byte-count - 1
}

// Run IDENTIFY DEVICE on the port. Fills `out_sector_count`.
// Returns false on any AHCI or ATA failure.
bool IdentifyDevice(Port& p)
{
    const mm::PhysAddr ident_phys = p.scratch_phys + kIdentOffset;
    BuildCmd(p, kAtaCmdIdentify, 0, 1, ident_phys, kSectorSize, /*dir_write=*/false);

    if (!IssueSlot0(p.regs))
    {
        return false;
    }

    // IDENTIFY reply: 512 bytes of little-endian u16 words.
    const auto* words = reinterpret_cast<u16*>(p.scratch_virt + kIdentOffset);
    // Word 83 bit 10 = LBA48 supported. Word 88 bit n = UDMA mode.
    // For v1 we assume LBA48 is fine (any modern SATA disk).
    // Words 100..103 = 48-bit user addressable sectors (u64, LE).
    const u64 lba48 = static_cast<u64>(words[100]) | (static_cast<u64>(words[101]) << 16) |
                      (static_cast<u64>(words[102]) << 32) | (static_cast<u64>(words[103]) << 48);
    const u64 lba28 = static_cast<u64>(words[60]) | (static_cast<u64>(words[61]) << 16);
    p.sector_count = (lba48 != 0) ? lba48 : lba28;
    return p.sector_count > 0;
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

i32 AhciBlockRead(void* cookie, u64 lba, u32 count, void* buf)
{
    auto* p = static_cast<Port*>(cookie);
    if (!p->online)
        return -1;
    if (count == 0 || count > kMaxSectorsPerXfer)
        return -1;
    if (lba + count > p->sector_count)
        return -1;

    // Translate caller buffer to phys. Block layer guarantees
    // direct-map alias.
    const mm::PhysAddr buf_phys = mm::VirtToPhys(buf);
    if (buf_phys == 0)
    {
        core::Log(core::LogLevel::Error, "drivers/ahci", "read: VirtToPhys returned 0");
        return -1;
    }
    BuildCmd(*p, kAtaCmdReadDmaExt, lba, static_cast<u16>(count), buf_phys, count * kSectorSize,
             /*dir_write=*/false);
    if (!IssueSlot0(p->regs))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "read: slot0 failed lba=", lba);
        return -1;
    }
    return 0;
}

i32 AhciBlockWrite(void* cookie, u64 lba, u32 count, const void* buf)
{
    auto* p = static_cast<Port*>(cookie);
    if (!p->online)
        return -1;
    if (count == 0 || count > kMaxSectorsPerXfer)
        return -1;
    if (lba + count > p->sector_count)
        return -1;

    // Mirror of read path: translate caller buffer, issue slot 0
    // with WRITE_DMA_EXT + the H2D W bit. BuildCmd already toggles
    // the command-header H/W bit when dir_write=true; the FIS body
    // is identical to a read.
    const mm::PhysAddr buf_phys = mm::VirtToPhys(const_cast<void*>(buf));
    if (buf_phys == 0)
    {
        core::Log(core::LogLevel::Error, "drivers/ahci", "write: VirtToPhys returned 0");
        return -1;
    }
    BuildCmd(*p, kAtaCmdWriteDmaExt, lba, static_cast<u16>(count), buf_phys, count * kSectorSize,
             /*dir_write=*/true);
    if (!IssueSlot0(p->regs))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "write: slot0 failed lba=", lba);
        return -1;
    }
    return 0;
}

constexpr BlockOps kAhciOps{
    .read = AhciBlockRead,
    .write = AhciBlockWrite,
};

void NamePort(Port& p, u32 idx)
{
    // "sata" + decimal idx. idx < 32 so one digit (< 10) or two.
    const char* prefix = "sata";
    u32 w = 0;
    while (prefix[w] != 0)
    {
        p.name[w] = prefix[w];
        ++w;
    }
    if (idx >= 10)
    {
        p.name[w++] = static_cast<char>('0' + idx / 10);
    }
    p.name[w++] = static_cast<char>('0' + idx % 10);
    p.name[w] = 0;
}

bool BringUpPort(volatile u8* hba_base, u32 port_idx, u32 ctrl_idx)
{
    if (g_port_count >= kMaxPorts)
    {
        return false;
    }
    volatile u8* port_regs = hba_base + kHbaPortsBase + port_idx * kHbaPortStride;

    const u32 sig = Reg(port_regs, kPortRegSig);
    const u32 ssts = Reg(port_regs, kPortRegSsts);
    if ((ssts & 0xF) != kSstsDetReady)
    {
        return false;
    }
    if (sig != kAhciSigSata)
    {
        core::LogWithString(core::LogLevel::Info, "drivers/ahci", "  skipping non-SATA port", "kind",
                            SignatureName(sig));
        return false;
    }

    Port& p = g_ports[g_port_count];
    p = Port{};
    p.regs = port_regs;
    p.port_idx = port_idx;
    p.ctrl_idx = ctrl_idx;
    p.block_handle = kBlockHandleInvalid;
    NamePort(p, g_port_count);

    // Allocate the shared 4 KiB DMA frame and zero it.
    p.scratch_phys = mm::AllocateFrame();
    if (p.scratch_phys == mm::kNullFrame)
    {
        core::Log(core::LogLevel::Error, "drivers/ahci", "port OOM: AllocateFrame failed");
        return false;
    }
    p.scratch_virt = static_cast<u8*>(mm::PhysToVirt(p.scratch_phys));
    VolatileZero(p.scratch_virt, mm::kPageSize);

    // Stop the port, program CLB/FB, clear error bits, re-start.
    PortStop(port_regs);

    const mm::PhysAddr clb_phys = p.scratch_phys + kCmdListOffset;
    const mm::PhysAddr fb_phys = p.scratch_phys + kFisOffset;
    Reg(port_regs, kPortRegClb) = static_cast<u32>(clb_phys & 0xFFFFFFFFu);
    Reg(port_regs, kPortRegClbu) = static_cast<u32>(clb_phys >> 32);
    Reg(port_regs, kPortRegFb) = static_cast<u32>(fb_phys & 0xFFFFFFFFu);
    Reg(port_regs, kPortRegFbu) = static_cast<u32>(fb_phys >> 32);
    Reg(port_regs, kPortRegSerr) = 0xFFFFFFFFu;
    Reg(port_regs, kPortRegIs) = 0xFFFFFFFFu;

    if (!PortStart(port_regs))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "port start (BSY/DRQ stuck) idx", port_idx);
        mm::FreeFrame(p.scratch_phys);
        return false;
    }

    if (!IdentifyDevice(p))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "IDENTIFY DEVICE failed idx", port_idx);
        PortStop(port_regs);
        mm::FreeFrame(p.scratch_phys);
        return false;
    }

    // Register with the block layer.
    BlockDesc desc{};
    desc.name = p.name;
    desc.ops = &kAhciOps;
    desc.cookie = &p;
    desc.sector_size = kSectorSize;
    desc.sector_count = p.sector_count;
    p.block_handle = BlockDeviceRegister(desc);
    if (p.block_handle == kBlockHandleInvalid)
    {
        core::Log(core::LogLevel::Error, "drivers/ahci", "block registry full");
        PortStop(port_regs);
        mm::FreeFrame(p.scratch_phys);
        return false;
    }
    p.online = true;
    ++g_port_count;

    core::LogWith2Values(core::LogLevel::Info, "drivers/ahci", "  online", "port_idx", port_idx, "sectors",
                         p.sector_count);
    core::LogWithString(core::LogLevel::Info, "drivers/ahci", "  registered", "name", p.name);
    return true;
}

// Set the PCI Bus Master + Memory Space bits on the AHCI device
// so MMIO reads/writes and DMA by the device are permitted.
void EnableMmioAndBusMaster(pci::DeviceAddress addr)
{
    const u16 cmd = pci::PciConfigRead16(addr, 0x04);
    const u16 new_cmd = static_cast<u16>(cmd | 0x4 /*BM*/ | 0x2 /*MEM*/);
    if (new_cmd != cmd)
    {
        // Low 16 bits of the 32-bit dword at offset 4.
        const u32 dword = pci::PciConfigRead32(addr, 0x04);
        const u32 new_dword = (dword & 0xFFFF0000u) | new_cmd;
        pci::PciConfigWrite32(addr, 0x04, new_dword);
    }
}

void BringUpController(const pci::Device& dev, u32 ctrl_idx)
{
    const pci::Bar bar5 = pci::PciReadBar(dev.addr, 5);
    if (bar5.size == 0 || bar5.is_io)
    {
        core::Log(core::LogLevel::Error, "drivers/ahci", "BAR5 missing or I/O");
        return;
    }
    EnableMmioAndBusMaster(dev.addr);

    void* mmio = mm::MapMmio(bar5.address, bar5.size);
    if (mmio == nullptr)
    {
        core::Panic("drivers/ahci", "MapMmio failed for HBA window");
    }
    auto* hba = static_cast<volatile u8*>(mmio);

    // Force AHCI-mode operation (GHC.AE=1).
    Reg(hba, kHbaRegGhc) |= kGhcAe;

    const u32 cap = Reg(hba, kHbaRegCap);
    const u32 vs = Reg(hba, kHbaRegVs);
    const u32 pi = Reg(hba, kHbaRegPi);
    const u32 ghc = Reg(hba, kHbaRegGhc);
    const u32 num_ports = (cap & 0x1F) + 1;

    core::LogWith2Values(core::LogLevel::Info, "drivers/ahci", "controller", "bar5_phys",
                         static_cast<u64>(bar5.address), "abar_mmio", reinterpret_cast<u64>(hba));
    core::LogWith2Values(core::LogLevel::Info, "drivers/ahci", "  caps", "cap", cap, "vs", vs);
    core::LogWith2Values(core::LogLevel::Info, "drivers/ahci", "  state", "ghc", ghc, "pi", pi);
    core::LogWithValue(core::LogLevel::Info, "drivers/ahci", "  num_ports", num_ports);

    for (u32 i = 0; i < num_ports && i < 32; ++i)
    {
        if ((pi & (1U << i)) == 0)
        {
            continue;
        }
        BringUpPort(hba, i, ctrl_idx);
    }
}

} // namespace

void AhciInit()
{
    KLOG_TRACE_SCOPE("drivers/ahci", "AhciInit");
    if (g_init_done)
    {
        core::Log(core::LogLevel::Warn, "drivers/ahci", "AhciInit called twice (ignored)");
        return;
    }
    g_init_done = true;
    g_port_count = 0;

    u32 ctrl_idx = 0;
    u32 found = 0;
    for (u64 i = 0; i < pci::PciDeviceCount() && ctrl_idx < kMaxControllers; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassMassStorage || d.subclass != kPciSubclassSata || d.prog_if != kPciProgIfAhci)
        {
            continue;
        }
        ++found;
        BringUpController(d, ctrl_idx++);
    }
    if (found == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/ahci", "no AHCI controller on any PCI bus");
        return;
    }
    core::LogWith2Values(core::LogLevel::Info, "drivers/ahci", "summary", "controllers", found, "sata_ports_online",
                         g_port_count);
}

void AhciSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/ahci", "AhciSelfTest");
    using arch::SerialWrite;
    if (g_port_count == 0)
    {
        SerialWrite("[ahci] self-test skipped (no SATA drives online)\n");
        return;
    }

    Port& p = g_ports[0];
    if (!p.online || p.block_handle == kBlockHandleInvalid)
    {
        SerialWrite("[ahci] self-test FAILED: port 0 not online\n");
        return;
    }

    static u8 scratch[kSectorSize];
    VolatileZero(scratch, kSectorSize);

    // Mirror the NVMe self-test: LBA 0 on a GPT disk ends in 0x55AA.
    // If the attached SATA backing store isn't GPT-formatted the
    // signature check will (correctly) fail — the test image we
    // use in QEMU (`tools/qemu/run.sh`) seeds a GPT copy.
    const i32 rc = BlockDeviceRead(p.block_handle, 0, 1, scratch);
    if (rc != 0)
    {
        SerialWrite("[ahci] self-test FAILED: LBA 0 read returned error\n");
        return;
    }
    if (scratch[510] != 0x55 || scratch[511] != 0xAA)
    {
        SerialWrite("[ahci] self-test WARN: LBA 0 missing 0x55AA (backing not GPT?)\n");
        return;
    }
    SerialWrite("[ahci] self-test OK (LBA 0 read + 0x55AA signature present)\n");
}

} // namespace customos::drivers::storage
