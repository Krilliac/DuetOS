/*
 * DuetOS — AHCI / SATA storage driver: implementation.
 *
 * Companion to ahci.h — see there for the controller / port
 * record shapes and the block-layer integration.
 *
 * WHAT
 *   Drives AHCI host bus adapters: maps the ABAR MMIO window,
 *   resets each port, allocates command-list + FIS-receive
 *   buffers, IDENTIFYs the attached drive, and exposes
 *   /dev/sda* through the block layer.
 *
 * HOW
 *   Polling at v0 — same rationale as nvme.cpp. Each command is
 *   built into the port's CL slot 0, the issue register is
 *   written, and the caller polls PxCI until the slot bit
 *   clears. PxIS is checked for taskfile errors after every
 *   completion.
 */

#include "drivers/storage/ahci.h"

#include "arch/x86_64/hpet.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/kdbg.h"
#include "drivers/pci/pci.h"
#include "drivers/storage/block.h"
#include "fs/gpt.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "mm/zone.h"

namespace duetos::drivers::storage
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
constexpr u8 kAtaCmdFlushCacheExt = 0xEA;     // ACS-4 §7.10 — commit cache to media.
constexpr u8 kAtaCmdDataSetManagement = 0x06; // ACS-4 §7.11 — TRIM and friends.
constexpr u8 kAtaDsmFeatureTrim = 0x01;       // FEATURES = 0x01 selects TRIM.
constexpr u16 kAtaDsmRangeBytes = 8;          // 6-byte LBA + 2-byte count, little-endian.
// FLUSH CACHE EXT can legitimately take seconds when the drive
// commits a deep write cache. ACS-4 doesn't bound this — vendors
// document worst-case under 30 s. Use the same window as IDENTIFY
// (already 30 s in IssueSlot0) so a flush during a real-disk
// background relocation doesn't false-fail.

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
    mm::DmaBuffer scratch_dma; // owns the 4 KiB DMA-coherent allocation
    mm::PhysAddr scratch_phys; // mirror of scratch_dma.phys for tight call sites
    u8* scratch_virt;          // mirror of scratch_dma.virt for tight call sites
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

// HPET-deadline helpers, sibling to the NVMe driver's pair. Letting
// each driver carry its own copy keeps the TU self-contained and
// avoids a kernel/util/timer.h cross-cutting header. The two
// drivers will share a common helper once a third consumer arrives.
bool AhciHpetOnline()
{
    return arch::HpetPeriodFemtoseconds() != 0;
}

u64 AhciHpetDeadlineMs(u64 ms)
{
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
        return 0;
    const u64 ticks = (ms * 1'000'000'000'000ULL) / period_fs;
    return arch::HpetReadCounter() + ticks;
}

bool AhciHpetDeadlinePassed(u64 deadline)
{
    return arch::HpetReadCounter() >= deadline;
}

// Spec-faithful bounded poll. Uses HPET when available, otherwise
// falls back to a generous pause-count budget that scales with
// `max_pause_iters`. Returns true when (Reg & mask) == match held
// within the budget. Pattern matches the NVMe driver's WaitReady.
bool AhciPollMmio(volatile u8* port, u64 reg_off, u32 mask, u32 match, u64 budget_ms, u64 max_pause_iters)
{
    const bool have_hpet = AhciHpetOnline();
    const u64 deadline = have_hpet ? AhciHpetDeadlineMs(budget_ms) : 0;
    u64 iters = 0;
    for (;;)
    {
        if ((Reg(port, reg_off) & mask) == match)
            return true;
        if (have_hpet)
        {
            if (AhciHpetDeadlinePassed(deadline))
                return false;
        }
        else if (++iters >= max_pause_iters)
        {
            return false;
        }
        CpuPause();
    }
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
    // Clear ST and FRE, then wait for CR and FR to clear. AHCI 1.3.1
    // §10.3.2 mandates a 500 ms timeout for each transition; if the
    // controller misses it the port is wedged and the driver
    // should give up on it rather than burning CPU forever.
    Reg(port, kPortRegCmd) &= ~kCmdSt;
    (void)AhciPollMmio(port, kPortRegCmd, kCmdCr, 0, /*budget_ms=*/500, /*max_pause_iters=*/10000);
    Reg(port, kPortRegCmd) &= ~kCmdFre;
    (void)AhciPollMmio(port, kPortRegCmd, kCmdFr, 0, /*budget_ms=*/500, /*max_pause_iters=*/10000);
}

bool PortStart(volatile u8* port)
{
    // Per spec: wait for BSY and DRQ in PxTFD to be clear before
    // starting. Then set FRE and ST. AHCI 1.3.1 allows up to 1 s for
    // link / COMRESET to train on a slow disk; bumping our poll
    // window to that budget closes a real-hardware false-fail where
    // a healthy spinning disk gets refused at bring-up.
    if (!AhciPollMmio(port, kPortRegTfd, kTfdBsy | kTfdDrq, 0, /*budget_ms=*/1000,
                      /*max_pause_iters=*/10000))
    {
        return false;
    }
    Reg(port, kPortRegCmd) |= kCmdFre;
    Reg(port, kPortRegCmd) |= kCmdSt;
    return true;
}

// Returns true + leaves PxCI zeroed if the command issued on slot
// 0 finishes without the TFES error bit. Polls PxCI for up to the
// ATA command timeout (30 s for IDENTIFY; spec-defined floor); a
// real-hardware spinning drive servicing an internal relocation
// can legitimately take seconds to respond, and the previous
// iter-count poll declared false-fail well below that.
bool IssueSlot0(volatile u8* port)
{
    // Clear stale interrupt status + task-file errors.
    Reg(port, kPortRegIs) = 0xFFFFFFFFu;
    Reg(port, kPortRegSerr) = 0xFFFFFFFFu;
    // Memory fence: every BuildCmd write (cmd-list header, PRDT)
    // must be globally visible before PxCI tells the HBA "go".
    // QEMU TCG tolerates the missing fence; some real-hardware
    // AHCI HBAs (Marvell, JMicron) fetch the cmd table before the
    // PRDT writes drain and either error or DMA garbage.
    asm volatile("sfence" ::: "memory");
    Reg(port, kPortRegCi) = 1u << 0;

    const bool have_hpet = AhciHpetOnline();
    // 30 s spec timeout for IDENTIFY / common ATA commands. WRITE
    // FLUSH can take longer on a busy disk; we use the same window
    // for v0 (correctness over throughput) and let a future slice
    // tune per-command budgets.
    constexpr u64 kCommandBudgetMs = 30'000;
    const u64 deadline = have_hpet ? AhciHpetDeadlineMs(kCommandBudgetMs) : 0;
    u64 iters = 0;
    for (;;)
    {
        const u32 is = Reg(port, kPortRegIs);
        if ((is & kIsTfes) != 0)
        {
            // Task-file error. PxTFD carries the ATA Status (bits
            // 7:0) and ATA Error (bits 15:8) registers; PxSERR
            // carries the SATA-link error/diagnostic bits. A bare
            // `return false` left a real-disk error (UNC / IDNF /
            // ABRT, or a link CRC/PHY fault) completely undiagnosable
            // — surface both so the failure is triageable, same
            // principle as the #MC / NMI decodes. Caller still bails;
            // v0 has no per-command COMRESET retry path (GAP).
            const u32 tfd = Reg(port, kPortRegTfd);
            const u32 serr = Reg(port, kPortRegSerr);
            core::LogWith2Values(core::LogLevel::Error, "drivers/ahci", "slot0 task-file error (PxIS.TFES)", "PxTFD",
                                 tfd, "PxSERR", serr);
            return false;
        }
        const u32 ci = Reg(port, kPortRegCi);
        if ((ci & 1u) == 0)
        {
            return true;
        }
        if (have_hpet)
        {
            if (AhciHpetDeadlinePassed(deadline))
                return false;
        }
        else if (++iters >= 4'000'000ULL)
        {
            // Fallback budget when HPET isn't online (e.g. firmware
            // didn't advertise it). 4M pause iters is wallclock-
            // sloppy but bounded — better than the previous
            // 1M-iter cap which was below the spec's command-time
            // floor on any real disk.
            return false;
        }
        CpuPause();
    }
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
    KDBG_2V(Storage, "drivers/ahci", "AhciBlockRead", "lba", lba, "count", count);
    auto* p = static_cast<Port*>(cookie);
    if (!p->online)
        return -1;
    if (count == 0 || count > kMaxSectorsPerXfer)
        return -1;
    // Subtractive bound: `lba + count` could wrap if a caller passes
    // an lba near u64-max. Test the upper edge by subtracting from
    // `sector_count` instead so the sum is never computed.
    if (lba > p->sector_count || count > p->sector_count - lba)
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
    KDBG_2V(Storage, "drivers/ahci", "AhciBlockWrite", "lba", lba, "count", count);
    auto* p = static_cast<Port*>(cookie);
    if (!p->online)
        return -1;
    if (count == 0 || count > kMaxSectorsPerXfer)
        return -1;
    // Subtractive bound — mirror of the read path's overflow guard.
    if (lba > p->sector_count || count > p->sector_count - lba)
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

// Build a "no PRDT" command — used for FLUSH CACHE EXT which
// transfers no data. The command header carries PRDTL=0 and the
// command table only fills the CFIS. Spec-faithful equivalent of
// BuildCmd with sectors=0 and PRDT omitted.
void BuildNonDataCmd(Port& p, u8 ata_cmd)
{
    auto* hdr = reinterpret_cast<CmdHeader*>(p.scratch_virt + kCmdListOffset);
    auto* tbl = reinterpret_cast<CmdTable*>(p.scratch_virt + kCmdTableOffset);
    const mm::PhysAddr tbl_phys = p.scratch_phys + kCmdTableOffset;

    VolatileZero(hdr, sizeof(CmdHeader) * 32);
    hdr[0].flags = static_cast<u16>(sizeof(FisH2dReg) / 4); // CFL in DWORDs, no W bit
    hdr[0].prdtl = 0;
    hdr[0].prdbc = 0;
    hdr[0].ctba = static_cast<u32>(tbl_phys & 0xFFFFFFFFu);
    hdr[0].ctbau = static_cast<u32>(tbl_phys >> 32);

    VolatileZero(tbl, sizeof(CmdTable));
    tbl->cfis.fis_type = kFisH2dRegister;
    tbl->cfis.pmport_c = 1u << 7; // C = 1 (Command)
    tbl->cfis.command = ata_cmd;
    tbl->cfis.device = 1u << 6; // LBA mode (FLUSH CACHE EXT is LBA-addressed by spec)
}

// FLUSH CACHE EXT (ATA 0xEA) — instructs the drive to commit its
// write cache to non-volatile media. ACS-4 §7.10. Required for
// power-loss durability: without this, every write that hit the
// drive's DRAM cache can be lost on a power cut even though
// AhciBlockWrite returned 0. FAT32 / DuetFS / ext4 journal
// commit points call BlockDeviceFlush(); that routes through here.
//
// IssueSlot0 already uses a 30 s budget which is consistent with
// the ACS-4 worst-case for FLUSH CACHE on a busy drive.
i32 AhciBlockFlush(void* cookie)
{
    KDBG(Storage, "drivers/ahci", "AhciBlockFlush");
    auto* p = static_cast<Port*>(cookie);
    if (!p->online)
        return -1;
    BuildNonDataCmd(*p, kAtaCmdFlushCacheExt);
    if (!IssueSlot0(p->regs))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "flush: slot0 failed port_idx=", p->port_idx);
        return -1;
    }
    return 0;
}

// DATA SET MANAGEMENT TRIM (ATA 0x06, FEATURES=0x01). ACS-4 §7.11.
// Builds a single 512-byte LBA-range buffer with one 8-byte
// {lba48, count16} descriptor and issues the command on slot 0.
// The buffer is reused — it lives in our per-port DMA scratch
// region at the IDENTIFY-reply offset (the bring-up read of
// IDENTIFY has already finished by the time any FS layer would
// trim, and the scratch is unused between commands).
//
// v0 issues one range per call. A 16-bit COUNT field per range
// caps each at 65,535 sectors; the block layer's u32 count is
// already bounded against the device's sector_count so a 32-bit
// argument that fits the device fits one range here too. Ranges
// longer than 0xFFFF sectors are split into multiple 8-byte
// descriptors within the one 512-byte buffer (up to 64
// descriptors per command).
i32 AhciBlockDiscard(void* cookie, u64 lba, u32 count)
{
    KDBG_2V(Storage, "drivers/ahci", "AhciBlockDiscard", "lba", lba, "count", count);
    auto* p = static_cast<Port*>(cookie);
    if (!p->online)
        return -1;
    if (count == 0)
        return -1;
    if (lba > p->sector_count || count > p->sector_count - lba)
        return -1;

    // Reuse the IDENTIFY-reply slot in the per-port DMA scratch
    // (512 bytes — exactly one TRIM payload sector). The IDENTIFY
    // data is consumed once at bring-up and never read again, so
    // overwriting it here is safe.
    u8* payload = p->scratch_virt + kIdentOffset;
    for (u32 i = 0; i < kSectorSize; ++i)
        payload[i] = 0;

    // Pack [lba, count) into 8-byte descriptors. Each descriptor:
    //   bytes 0..5 = starting LBA (48-bit, little-endian)
    //   bytes 6..7 = range length in sectors (16-bit, little-endian)
    // A length of 0 terminates the list — we explicitly zero the
    // tail (already done above) so the drive stops at our last
    // populated entry.
    constexpr u32 kMaxRangesPerSector = kSectorSize / kAtaDsmRangeBytes; // 64
    u32 desc_count = 0;
    u64 cur_lba = lba;
    u32 remaining = count;
    while (remaining > 0 && desc_count < kMaxRangesPerSector)
    {
        const u16 chunk = (remaining > 0xFFFF) ? 0xFFFF : static_cast<u16>(remaining);
        u8* d = payload + desc_count * kAtaDsmRangeBytes;
        d[0] = static_cast<u8>(cur_lba & 0xFF);
        d[1] = static_cast<u8>((cur_lba >> 8) & 0xFF);
        d[2] = static_cast<u8>((cur_lba >> 16) & 0xFF);
        d[3] = static_cast<u8>((cur_lba >> 24) & 0xFF);
        d[4] = static_cast<u8>((cur_lba >> 32) & 0xFF);
        d[5] = static_cast<u8>((cur_lba >> 40) & 0xFF);
        d[6] = static_cast<u8>(chunk & 0xFF);
        d[7] = static_cast<u8>((chunk >> 8) & 0xFF);
        cur_lba += chunk;
        remaining -= chunk;
        ++desc_count;
    }
    if (remaining > 0)
    {
        // 64 ranges * 65535 sectors = 32 MiB-1; any caller asking
        // for more than that in one BlockDeviceDiscard should split
        // already. Refuse rather than silently dropping the tail.
        core::LogWithValue(core::LogLevel::Warn, "drivers/ahci", "discard: oversized request, tail dropped, remaining",
                           remaining);
        return -1;
    }

    // Build the command — DSM TRIM with COUNT=1 (one 512-byte
    // sector of LBA descriptors), W bit set (we transfer the
    // descriptor list to the drive), single PRD pointing at our
    // payload buffer.
    auto* hdr = reinterpret_cast<CmdHeader*>(p->scratch_virt + kCmdListOffset);
    auto* tbl = reinterpret_cast<CmdTable*>(p->scratch_virt + kCmdTableOffset);
    const mm::PhysAddr tbl_phys = p->scratch_phys + kCmdTableOffset;
    const mm::PhysAddr payload_phys = p->scratch_phys + kIdentOffset;

    VolatileZero(hdr, sizeof(CmdHeader) * 32);
    hdr[0].flags = static_cast<u16>(sizeof(FisH2dReg) / 4); // CFL DWORDs
    hdr[0].flags |= 1u << 6;                                // W bit — host writes to drive
    hdr[0].prdtl = 1;
    hdr[0].prdbc = 0;
    hdr[0].ctba = static_cast<u32>(tbl_phys & 0xFFFFFFFFu);
    hdr[0].ctbau = static_cast<u32>(tbl_phys >> 32);

    VolatileZero(tbl, sizeof(CmdTable));
    tbl->cfis.fis_type = kFisH2dRegister;
    tbl->cfis.pmport_c = 1u << 7;
    tbl->cfis.command = kAtaCmdDataSetManagement;
    tbl->cfis.featurel = kAtaDsmFeatureTrim; // FEATURES = TRIM
    tbl->cfis.device = 1u << 6;              // LBA mode
    tbl->cfis.countl = 1;                    // 1 × 512 B payload sector
    tbl->cfis.counth = 0;

    tbl->prdt[0].dba = static_cast<u32>(payload_phys & 0xFFFFFFFFu);
    tbl->prdt[0].dbau = static_cast<u32>(payload_phys >> 32);
    tbl->prdt[0].dbc = kSectorSize - 1; // byte count - 1

    if (!IssueSlot0(p->regs))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "discard: slot0 failed lba=", lba);
        return -1;
    }
    return 0;
}

constexpr BlockOps kAhciOps{
    .read = AhciBlockRead,
    .write = AhciBlockWrite,
    .flush = AhciBlockFlush,
    .discard = AhciBlockDiscard,
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

    // Allocate the shared 4 KiB DMA-coherent region. AHCI is 32-bit
    // DMA-addressable for command-list / FIS-receive / command-table
    // pointers (the actual data buffers can be 64-bit), so Dma32 is
    // the right zone. AllocDmaCoherent zeroes the buffer for us.
    {
        auto r = mm::AllocDmaCoherent(mm::kPageSize, mm::Zone::Dma32);
        if (!r.has_value())
        {
            core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "port OOM: AllocDmaCoherent failed",
                               static_cast<u64>(r.error()));
            return false;
        }
        p.scratch_dma = r.value();
        p.scratch_phys = p.scratch_dma.phys;
        p.scratch_virt = static_cast<u8*>(p.scratch_dma.virt);
    }

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
        mm::FreeDmaCoherent(p.scratch_dma);
        return false;
    }

    if (!IdentifyDevice(p))
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/ahci", "IDENTIFY DEVICE failed idx", port_idx);
        PortStop(port_regs);
        mm::FreeDmaCoherent(p.scratch_dma);
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
        mm::FreeDmaCoherent(p.scratch_dma);
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
        // Debug: panic. Release: log and skip this controller —
        // matches the "BAR5 missing" early-return above and lets
        // the rest of the storage subsystem keep enumerating.
        core::DebugPanicOrWarn("drivers/ahci", "MapMmio failed for HBA window");
        return;
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
    // Decoded register breakdown — surface the bits a reader needs
    // to triage. CAP is the controller's capability snapshot
    // (NCQ / 64-bit DMA / hot-plug / max ports), VS is major.minor
    // (e.g. 0x00010300 = 1.3.0), GHC is the live mode (AE/IE/HR)
    // and PI is the bitmask of populated ports.
    arch::SerialWrite("[I] drivers/ahci :   cap [");
    bool first = true;
    auto cap_bit = [&](u32 b, const char* n)
    {
        if ((cap & (1U << b)) == 0)
            return;
        if (!first)
            arch::SerialWrite("|");
        arch::SerialWrite(n);
        first = false;
    };
    cap_bit(13, "PMD");
    cap_bit(17, "PSC");
    cap_bit(18, "SSC");
    cap_bit(19, "PMP");
    cap_bit(20, "FBSS");
    cap_bit(24, "SCLO");
    cap_bit(25, "SAL");
    cap_bit(26, "SALP");
    cap_bit(27, "SSS");
    cap_bit(28, "SMPS");
    cap_bit(29, "SSNTF");
    cap_bit(30, "SNCQ");
    cap_bit(31, "S64A");
    if (!first)
        arch::SerialWrite("|");
    arch::SerialWrite("NP=");
    {
        char d[3] = {0, 0, 0};
        u32 n = (cap & 0x1F) + 1;
        if (n >= 10)
        {
            d[0] = static_cast<char>('0' + (n / 10));
            d[1] = static_cast<char>('0' + (n % 10));
        }
        else
        {
            d[0] = static_cast<char>('0' + n);
        }
        arch::SerialWrite(d);
    }
    arch::SerialWrite("]\n");

    arch::SerialWrite("[I] drivers/ahci :   vs ");
    {
        const u32 maj = (vs >> 16) & 0xFFFF;
        const u32 min = (vs >> 8) & 0xFF;
        const u32 sub = vs & 0xFF;
        char buf[6] = {0, 0, 0, 0, 0, 0};
        buf[0] = static_cast<char>('0' + (maj % 10));
        buf[1] = '.';
        buf[2] = static_cast<char>('0' + ((min >> 4) & 0xF));
        buf[3] = static_cast<char>('0' + (min & 0xF));
        buf[4] = '.';
        buf[5] = 0;
        arch::SerialWrite(buf);
        char tail[3] = {static_cast<char>('0' + ((sub >> 4) & 0xF)), static_cast<char>('0' + (sub & 0xF)), 0};
        arch::SerialWrite(tail);
    }
    arch::SerialWrite("\n");

    arch::SerialWrite("[I] drivers/ahci :   ghc [");
    bool gfirst = true;
    auto gbit = [&](u32 b, const char* n)
    {
        if ((ghc & (1U << b)) == 0)
            return;
        if (!gfirst)
            arch::SerialWrite("|");
        arch::SerialWrite(n);
        gfirst = false;
    };
    gbit(31, "AE");
    gbit(2, "MRSM");
    gbit(1, "IE");
    gbit(0, "HR");
    if (gfirst)
        arch::SerialWrite("none");
    arch::SerialWrite("]\n");

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
        // Idempotent: a re-init without an intervening AhciTeardown
        // is a no-op so single-call boot paths keep their fast
        // return. The driver-fault-domain restart path runs
        // Teardown first which clears g_init_done.
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

void AhciTeardown()
{
    KLOG_TRACE_SCOPE("drivers/ahci", "AhciTeardown");
    if (!g_init_done)
    {
        return;
    }
    // Free every per-port DMA-coherent scratch buffer + reset
    // the row to its constinit defaults. The block-layer handle
    // (p.block_handle) leaks because BlockDeviceRegister has no
    // matching BlockDeviceUnregister yet — same caveat the
    // framebuffer / pci teardowns document for their MMIO
    // mappings; a future block-layer slice can wire in the
    // matching unregister hook here.
    for (u32 i = 0; i < g_port_count; ++i)
    {
        Port& p = g_ports[i];
        if (p.scratch_dma.virt != nullptr)
        {
            mm::FreeDmaCoherent(p.scratch_dma);
        }
        p = Port{};
        p.block_handle = kBlockHandleInvalid;
    }
    g_port_count = 0;
    g_init_done = false;
    KLOG_INFO("drivers/ahci", "teardown — all SATA ports offline");
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

// ---------------------------------------------------------------
// Panic-time surface — mirrors NVMe's contract.
// ---------------------------------------------------------------

namespace
{

// Outcome of the most recent AhciPanicWriteDump call. Read by
// the `lastdump` shell + the panic-path fallback chain.
constinit bool g_panic_last_ok = false;
constinit u64 g_panic_last_bytes = 0;

// First online port — the panic path writes here. Recomputed on
// every call (the port table can change across teardown / re-init).
Port* PanicPrimaryPort()
{
    for (u32 i = 0; i < g_port_count; ++i)
    {
        if (g_ports[i].online && g_ports[i].block_handle != kBlockHandleInvalid)
        {
            return &g_ports[i];
        }
    }
    return nullptr;
}

// Walk a byte buffer through BuildCmd + IssueSlot0 in chunks
// of up to kMaxSectorsPerXfer sectors. No allocations, no log
// emission on the hot path — safe to call from panic context.
// Returns the number of bytes successfully landed; sets the
// global ok flag.
u64 PanicWriteChunked(Port& p, u64 base_lba, const u8* bytes, u64 len, u64 reserved_first, u64 reserved_last)
{
    g_panic_last_ok = false;
    g_panic_last_bytes = 0;
    if (bytes == nullptr || len == 0)
    {
        return 0;
    }
    if (base_lba < reserved_first || base_lba >= reserved_last)
    {
        return 0;
    }
    u64 written = 0;
    u64 cur_lba = base_lba;
    while (written < len)
    {
        const u64 chunk_bytes_raw = len - written;
        const u32 chunk_bytes = chunk_bytes_raw > (kMaxSectorsPerXfer * kSectorSize)
                                    ? (kMaxSectorsPerXfer * kSectorSize)
                                    : static_cast<u32>(chunk_bytes_raw);
        const u32 sectors = (chunk_bytes + kSectorSize - 1) / kSectorSize;
        if (sectors == 0)
        {
            break;
        }
        if (cur_lba + sectors > reserved_last)
        {
            break;
        }
        // BuildCmd reads from `bytes + written` via PRD physical
        // address. The caller buffer (typically minidump's BSS
        // staging buffer) is direct-mapped in the kernel's address
        // space, so VirtToPhys returns a valid PA.
        const mm::PhysAddr buf_phys = mm::VirtToPhys(const_cast<u8*>(bytes + written));
        if (buf_phys == 0)
        {
            g_panic_last_bytes = written;
            return written;
        }
        BuildCmd(p, kAtaCmdWriteDmaExt, cur_lba, static_cast<u16>(sectors), buf_phys, sectors * kSectorSize,
                 /*dir_write=*/true);
        if (!IssueSlot0(p.regs))
        {
            g_panic_last_bytes = written;
            return written;
        }
        written += chunk_bytes;
        cur_lba += sectors;
    }
    g_panic_last_ok = (written == len);
    g_panic_last_bytes = written;
    return written;
}

} // namespace

bool AhciAvailable()
{
    return PanicPrimaryPort() != nullptr;
}

u32 AhciNamespaceSectorSize()
{
    return AhciAvailable() ? kSectorSize : 0u;
}

u64 AhciNamespaceSectorCount()
{
    Port* p = PanicPrimaryPort();
    return (p != nullptr) ? p->sector_count : 0ULL;
}

u64 AhciDumpReservedLba()
{
    Port* p = PanicPrimaryPort();
    if (p == nullptr)
    {
        return 0;
    }
    // Prefer a GPT-recorded reservation when one exists. Same
    // policy as NvmeDumpReservedLba — the legacy "tail of drive"
    // path is a fallback for early-boot disks that haven't been
    // partitioned yet.
    u64 gpt_first = 0;
    u64 gpt_count = 0;
    if (fs::gpt::GptFindCrashDumpRegion(p->block_handle, &gpt_first, &gpt_count) &&
        gpt_count >= kAhciDumpReservedSectors)
    {
        return gpt_first;
    }
    if (p->sector_count <= kAhciDumpReservedSectors)
    {
        return 0;
    }
    return p->sector_count - kAhciDumpReservedSectors;
}

bool AhciPanicWriteDump(const u8* bytes, u64 len)
{
    Port* p = PanicPrimaryPort();
    if (p == nullptr)
    {
        g_panic_last_ok = false;
        g_panic_last_bytes = 0;
        return false;
    }
    const u64 base_lba = AhciDumpReservedLba();
    if (base_lba == 0)
    {
        g_panic_last_ok = false;
        g_panic_last_bytes = 0;
        return false;
    }
    // Determine the reservation's extent so writes can't escape
    // the recorded region. Mirror NvmeDumpReservedLba's policy.
    u64 reserved_count = kAhciDumpReservedSectors;
    {
        u64 gpt_first = 0;
        u64 gpt_count = 0;
        if (fs::gpt::GptFindCrashDumpRegion(p->block_handle, &gpt_first, &gpt_count) && gpt_first == base_lba)
        {
            reserved_count = gpt_count;
        }
    }
    const u64 reserved_last = base_lba + reserved_count;
    const u64 reserved_bytes = reserved_count * kSectorSize;
    const u64 capped_len = (len > reserved_bytes) ? reserved_bytes : len;
    const u64 written = PanicWriteChunked(*p, base_lba, bytes, capped_len, base_lba, reserved_last);
    // Compare against what was actually attempted (capped_len), not
    // the uncapped len: an oversize-but-fully-persisted dump writes
    // capped_len bytes successfully and must report success, or the
    // crash-dump caller falls back as if the persist failed.
    return written == capped_len;
}

bool AhciPanicWriteSucceededLast()
{
    return g_panic_last_ok;
}

u64 AhciPanicLastWriteBytes()
{
    return g_panic_last_bytes;
}

} // namespace duetos::drivers::storage
