#include "nvme.h"

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

// --- NVMe controller register offsets (NVMe base spec 1.4, §3.1) -------------

constexpr u64 kRegCap = 0x00;  // Capabilities (u64)
constexpr u64 kRegVs = 0x08;   // Version (u32)
constexpr u64 kRegCc = 0x14;   // Controller Configuration (u32)
constexpr u64 kRegCsts = 0x1C; // Controller Status (u32)
constexpr u64 kRegAqa = 0x24;  // Admin Queue Attributes (u32)
constexpr u64 kRegAsq = 0x28;  // Admin SQ Base Address (u64)
constexpr u64 kRegAcq = 0x30;  // Admin CQ Base Address (u64)
constexpr u64 kDoorbellBase = 0x1000;

// CC bits.
constexpr u32 kCcEnable = 1U << 0;
// CSTS bits.
constexpr u32 kCstsReady = 1U << 0;
constexpr u32 kCstsCfs = 1U << 1; // Controller Fatal Status

// PCI class/subclass/prog_if for NVMe.
constexpr u8 kPciClassMassStorage = 0x01;
constexpr u8 kPciSubclassNvm = 0x08;
constexpr u8 kPciProgIfNvme = 0x02;

// PCI command register (offset 0x04) bits we care about.
constexpr u16 kPciCmdMmio = 1U << 1;
constexpr u16 kPciCmdBusMaster = 1U << 2;

// Admin command opcodes. Delete SQ/CQ (0x00/0x04) will land with
// teardown; v0 bring-up only creates.
constexpr u8 kAdminOpCreateSq = 0x01;
constexpr u8 kAdminOpCreateCq = 0x05;
constexpr u8 kAdminOpIdentify = 0x06;

// NVM I/O opcodes.
constexpr u8 kIoOpWrite = 0x01;
constexpr u8 kIoOpRead = 0x02;

// Queue sizing. Deliberately tiny — one command in flight at a time is
// plenty for v0. Keep both SQ + CQ on one page each even with larger
// entries so the layout stays obvious.
constexpr u32 kAdminQueueEntries = 8;
constexpr u32 kIoQueueEntries = 8;

constexpr u32 kSqEntryBytes = 64;
constexpr u32 kCqEntryBytes = 16;

// Busy-wait bounds. NVMe spec timeout (CAP.TO) is in 500 ms units; QEMU
// completes these actions in microseconds, but we want a bound that
// works even on slow real silicon. 50M pause-loops is ~1 second on a
// modern CPU; we repeat that bound as a ceiling.
constexpr u64 kPauseLoopBudget = 50ULL * 1000ULL * 1000ULL;

struct alignas(64) SqEntry
{
    u32 cdw0;
    u32 nsid;
    u64 rsvd;
    u64 mptr;
    u64 prp1;
    u64 prp2;
    u32 cdw10;
    u32 cdw11;
    u32 cdw12;
    u32 cdw13;
    u32 cdw14;
    u32 cdw15;
};
static_assert(sizeof(SqEntry) == kSqEntryBytes, "NVMe SQ entry must be 64 bytes");

struct alignas(16) CqEntry
{
    u32 cmd_specific;
    u32 rsvd;
    u32 sqhd_sqid;        // bits 0..15 SQHD, bits 16..31 SQID
    u32 cid_phase_status; // bits 0..15 CID, bit 16 P, bits 17..31 status
};
static_assert(sizeof(CqEntry) == kCqEntryBytes, "NVMe CQ entry must be 16 bytes");

struct Queue
{
    volatile SqEntry* sq;
    volatile CqEntry* cq;
    mm::PhysAddr sq_phys;
    mm::PhysAddr cq_phys;
    u32 entries; // identical for sq + cq in this driver
    u32 sq_tail;
    u32 cq_head;
    u32 expected_phase; // 1 on first pass; flips on wrap
    u32 id;             // queue id (0 = admin, >=1 = I/O)
};

struct Controller
{
    volatile u8* mmio;
    u64 cap;
    u32 doorbell_stride_bytes; // 4 << CAP.DSTRD
    u32 max_queue_entries;     // CAP.MQES + 1
    u64 cap_to_ms;             // CAP.TO * 500
    Queue admin;
    Queue io;
    u64 ns_sector_count;
    u32 ns_sector_size;
    u32 next_cid;
    mm::PhysAddr io_buf_phys;
    u8* io_buf_virt;
    u32 block_handle;
    bool online;
};

constinit Controller g_ctrl = {};

// Compute doorbell virtual address for a queue.
volatile u32* SqTailDoorbell(u32 qid)
{
    const u64 off = kDoorbellBase + (2 * qid) * g_ctrl.doorbell_stride_bytes;
    return reinterpret_cast<volatile u32*>(g_ctrl.mmio + off);
}

volatile u32* CqHeadDoorbell(u32 qid)
{
    const u64 off = kDoorbellBase + (2 * qid + 1) * g_ctrl.doorbell_stride_bytes;
    return reinterpret_cast<volatile u32*>(g_ctrl.mmio + off);
}

inline volatile u32& Reg32(u64 offset)
{
    return *reinterpret_cast<volatile u32*>(g_ctrl.mmio + offset);
}

inline volatile u64& Reg64(u64 offset)
{
    return *reinterpret_cast<volatile u64*>(g_ctrl.mmio + offset);
}

void CpuPause()
{
    asm volatile("pause" ::: "memory");
}

// Wait for CSTS.RDY to reach `expected` (0 or 1). Returns false on timeout
// or controller fatal status; caller should bail out of bring-up.
bool WaitReady(u32 expected)
{
    for (u64 i = 0; i < kPauseLoopBudget; ++i)
    {
        const u32 csts = Reg32(kRegCsts);
        if (csts & kCstsCfs)
        {
            core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "CSTS.CFS set during wait", csts);
            return false;
        }
        if ((csts & kCstsReady) == expected)
        {
            return true;
        }
        CpuPause();
    }
    core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "CSTS.RDY wait timed out; expected", expected);
    return false;
}

// Zero a page via its direct-map alias.
void ZeroFrame(mm::PhysAddr phys)
{
    auto* bytes = static_cast<u8*>(mm::PhysToVirt(phys));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        bytes[i] = 0;
}

// Allocate + zero one DMA-safe page. Returns 0 on OOM.
mm::PhysAddr AllocZeroedPage()
{
    const mm::PhysAddr p = mm::AllocateFrame();
    if (p == mm::kNullFrame)
    {
        return 0;
    }
    ZeroFrame(p);
    return p;
}

// Stand up a Queue with one page each for SQ + CQ. Caller fills `id`.
bool QueueInit(Queue& q, u32 entries, u32 id)
{
    if (entries * kSqEntryBytes > mm::kPageSize || entries * kCqEntryBytes > mm::kPageSize)
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "queue entries exceed one page");
        return false;
    }
    const mm::PhysAddr sq_phys = AllocZeroedPage();
    if (sq_phys == 0)
    {
        return false;
    }
    const mm::PhysAddr cq_phys = AllocZeroedPage();
    if (cq_phys == 0)
    {
        mm::FreeFrame(sq_phys);
        return false;
    }
    q.sq = static_cast<volatile SqEntry*>(mm::PhysToVirt(sq_phys));
    q.cq = static_cast<volatile CqEntry*>(mm::PhysToVirt(cq_phys));
    q.sq_phys = sq_phys;
    q.cq_phys = cq_phys;
    q.entries = entries;
    q.sq_tail = 0;
    q.cq_head = 0;
    q.expected_phase = 1;
    q.id = id;
    return true;
}

// Submit one command into `q` and poll its completion. `entry.cdw0` must
// carry opcode; this helper fills in CID and returns true iff the
// completion status field is zero. The status word is logged on error.
bool SubmitAndWait(Queue& q, SqEntry entry)
{
    const u16 cid = static_cast<u16>(g_ctrl.next_cid++ & 0xFFFF);
    // Preserve caller-supplied opcode; fuse = 0; CID in upper 16.
    entry.cdw0 = (entry.cdw0 & 0x0000FFFFu) | (static_cast<u32>(cid) << 16);

    const u32 tail = q.sq_tail;
    // Field-by-field to satisfy volatile — no implicit volatile
    // assignment operator. Each write is a single 32/64-bit MMIO
    // store, which is what the device expects anyway.
    volatile SqEntry& sq_slot = q.sq[tail];
    sq_slot.cdw0 = entry.cdw0;
    sq_slot.nsid = entry.nsid;
    sq_slot.rsvd = entry.rsvd;
    sq_slot.mptr = entry.mptr;
    sq_slot.prp1 = entry.prp1;
    sq_slot.prp2 = entry.prp2;
    sq_slot.cdw10 = entry.cdw10;
    sq_slot.cdw11 = entry.cdw11;
    sq_slot.cdw12 = entry.cdw12;
    sq_slot.cdw13 = entry.cdw13;
    sq_slot.cdw14 = entry.cdw14;
    sq_slot.cdw15 = entry.cdw15;
    const u32 new_tail = (tail + 1) % q.entries;
    q.sq_tail = new_tail;
    *SqTailDoorbell(q.id) = new_tail;

    // Poll the CQ slot at cq_head until its phase flips.
    const u32 head = q.cq_head;
    volatile CqEntry& cq_slot = q.cq[head];
    for (u64 i = 0; i < kPauseLoopBudget; ++i)
    {
        const u32 dw3 = cq_slot.cid_phase_status;
        const u32 phase = (dw3 >> 16) & 0x1;
        if (phase == q.expected_phase)
        {
            const u32 status = (dw3 >> 17) & 0x7FFF;
            const u32 new_head = (head + 1) % q.entries;
            q.cq_head = new_head;
            if (new_head == 0)
            {
                q.expected_phase ^= 1;
            }
            *CqHeadDoorbell(q.id) = new_head;
            if (status != 0)
            {
                core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "command failed; status", status);
                return false;
            }
            return true;
        }
        CpuPause();
    }
    core::Log(core::LogLevel::Error, "drivers/nvme", "command completion timed out");
    return false;
}

// --- PCI discovery + controller enable --------------------------------------

const pci::Device* FindNvme()
{
    for (u64 i = 0; i < pci::PciDeviceCount(); ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code == kPciClassMassStorage && d.subclass == kPciSubclassNvm && d.prog_if == kPciProgIfNvme)
        {
            return &d;
        }
    }
    return nullptr;
}

void EnablePciBusMaster(pci::DeviceAddress addr)
{
    // Command register is 16 bits at offset 0x04; Status is 16 bits at 0x06.
    // Read both via PciConfigRead32 so we can write them back together.
    const u32 cmd_status = pci::PciConfigRead32(addr, 0x04);
    const u16 status = static_cast<u16>(cmd_status >> 16);
    u16 cmd = static_cast<u16>(cmd_status & 0xFFFF);
    cmd |= (kPciCmdMmio | kPciCmdBusMaster);
    const u32 updated = static_cast<u32>(cmd) | (static_cast<u32>(status) << 16);
    pci::PciConfigWrite32(addr, 0x04, updated);
}

bool ResetAndEnable(const pci::Device* dev)
{
    // Clear CC.EN, wait for CSTS.RDY = 0.
    const u32 cc_pre = Reg32(kRegCc);
    Reg32(kRegCc) = cc_pre & ~kCcEnable;
    if (!WaitReady(0))
    {
        return false;
    }

    // Allocate admin queues.
    if (!QueueInit(g_ctrl.admin, kAdminQueueEntries, 0))
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "admin queue allocation failed");
        return false;
    }

    // AQA: Admin SQ size in bits 0..11, CQ size in bits 16..27, both 0-based.
    const u32 aqa = ((kAdminQueueEntries - 1) & 0xFFF) | (((kAdminQueueEntries - 1) & 0xFFF) << 16);
    Reg32(kRegAqa) = aqa;
    Reg64(kRegAsq) = g_ctrl.admin.sq_phys;
    Reg64(kRegAcq) = g_ctrl.admin.cq_phys;

    // CC: MPS=0 (4 KiB), CSS=000 (NVM command set), AMS=000 (round robin),
    // IOSQES=6 (64 bytes, log2), IOCQES=4 (16 bytes, log2), EN=1.
    u32 cc = 0;
    cc |= (6U << 16); // IOSQES
    cc |= (4U << 20); // IOCQES
    cc |= kCcEnable;
    Reg32(kRegCc) = cc;

    if (!WaitReady(kCstsReady))
    {
        return false;
    }

    core::Log(core::LogLevel::Info, "drivers/nvme", "controller enabled");
    (void)dev;
    return true;
}

// --- Identify + I/O queue creation ------------------------------------------

bool IdentifyControllerLogOnly()
{
    const mm::PhysAddr buf = AllocZeroedPage();
    if (buf == 0)
    {
        return false;
    }
    SqEntry e{};
    e.cdw0 = kAdminOpIdentify;
    e.nsid = 0;
    e.prp1 = buf;
    e.cdw10 = 0x1; // CNS = Identify Controller
    const bool ok = SubmitAndWait(g_ctrl.admin, e);
    if (ok)
    {
        // Model number is at byte offset 24, 40 bytes, space-padded ASCII.
        // Log the first 16 characters of the serial (byte 4) or model
        // (byte 24). Stick with a short field for a single log line.
        const u8* bytes = static_cast<const u8*>(mm::PhysToVirt(buf));
        arch::SerialWrite("[drivers/nvme] controller model: ");
        for (u32 i = 0; i < 20; ++i)
        {
            const char c = static_cast<char>(bytes[24 + i]);
            const char printable = (c >= 0x20 && c < 0x7F) ? c : '.';
            const char s[2] = {printable, 0};
            arch::SerialWrite(s);
        }
        arch::SerialWrite("\n");
    }
    mm::FreeFrame(buf);
    return ok;
}

bool IdentifyNamespaceOne()
{
    const mm::PhysAddr buf = AllocZeroedPage();
    if (buf == 0)
    {
        return false;
    }
    SqEntry e{};
    e.cdw0 = kAdminOpIdentify;
    e.nsid = 1;
    e.prp1 = buf;
    e.cdw10 = 0x0; // CNS = Identify Namespace
    const bool ok = SubmitAndWait(g_ctrl.admin, e);
    if (ok)
    {
        const u8* bytes = static_cast<const u8*>(mm::PhysToVirt(buf));
        // NSZE: 8 bytes at offset 0 — namespace size in LBAs.
        u64 nsze = 0;
        for (u32 i = 0; i < 8; ++i)
            nsze |= static_cast<u64>(bytes[i]) << (8 * i);
        // FLBAS (byte 26) bits 0..3 select LBAF index.
        const u8 flbas = bytes[26];
        const u32 lbaf_idx = flbas & 0xF;
        // LBAF table starts at byte 128, each entry is 4 bytes.
        const u32 lbaf_off = 128 + lbaf_idx * 4;
        // LBADS (LBA Data Size exp) is byte lbaf_off + 2 (bits 16..23 of DW0).
        const u8 lbads = bytes[lbaf_off + 2];
        const u32 sector_size = (lbads >= 9 && lbads <= 12) ? (1U << lbads) : 512;
        g_ctrl.ns_sector_count = nsze;
        g_ctrl.ns_sector_size = sector_size;
        core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "namespace 1 sector count", nsze);
        core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "namespace 1 sector size", sector_size);
    }
    mm::FreeFrame(buf);
    return ok;
}

bool CreateIoQueues()
{
    if (!QueueInit(g_ctrl.io, kIoQueueEntries, 1))
    {
        return false;
    }

    // Create I/O CQ first — the SQ references it.
    SqEntry cq_cmd{};
    cq_cmd.cdw0 = kAdminOpCreateCq;
    cq_cmd.prp1 = g_ctrl.io.cq_phys;
    // DW10: bits 0..15 = QID, bits 16..31 = Queue Size (0-based).
    cq_cmd.cdw10 = (1 & 0xFFFF) | (((kIoQueueEntries - 1) & 0xFFFF) << 16);
    // DW11: bit 0 = PC (physically contiguous); IEN=0 (no IRQ); IV=0.
    cq_cmd.cdw11 = 0x1;
    if (!SubmitAndWait(g_ctrl.admin, cq_cmd))
    {
        return false;
    }

    SqEntry sq_cmd{};
    sq_cmd.cdw0 = kAdminOpCreateSq;
    sq_cmd.prp1 = g_ctrl.io.sq_phys;
    sq_cmd.cdw10 = (1 & 0xFFFF) | (((kIoQueueEntries - 1) & 0xFFFF) << 16);
    // DW11: bit 0 = PC, bits 16..31 = CQID = 1.
    sq_cmd.cdw11 = 0x1 | (1U << 16);
    if (!SubmitAndWait(g_ctrl.admin, sq_cmd))
    {
        return false;
    }

    core::Log(core::LogLevel::Info, "drivers/nvme", "I/O queue pair online (qid=1)");
    return true;
}

// --- BlockDevice vtable -----------------------------------------------------

i32 NvmeDoIo(bool write, u64 lba, u32 count, void* user_buf)
{
    if (count == 0)
    {
        return 0;
    }
    if (!g_ctrl.online)
    {
        return -1;
    }
    const u32 ss = g_ctrl.ns_sector_size;
    // v0: single command per call, sized to one page of data. Higher
    // layers that want larger transfers can loop. PRP1-only means
    // bytes <= 4 KiB per command.
    const u32 per_cmd_max = mm::kPageSize / ss;
    if (count > per_cmd_max)
    {
        return -1;
    }

    auto* bytes = static_cast<u8*>(user_buf);
    const u64 total_bytes = static_cast<u64>(count) * ss;

    if (write)
    {
        for (u64 i = 0; i < total_bytes; ++i)
            g_ctrl.io_buf_virt[i] = bytes[i];
    }

    SqEntry e{};
    e.cdw0 = write ? kIoOpWrite : kIoOpRead;
    e.nsid = 1;
    e.prp1 = g_ctrl.io_buf_phys;
    e.prp2 = 0;
    // DW10/11: SLBA low/high.
    e.cdw10 = static_cast<u32>(lba & 0xFFFFFFFFu);
    e.cdw11 = static_cast<u32>((lba >> 32) & 0xFFFFFFFFu);
    // DW12: NLB (0-based) in bits 0..15. FUA/LR flags zero.
    e.cdw12 = (count - 1) & 0xFFFF;

    if (!SubmitAndWait(g_ctrl.io, e))
    {
        return -1;
    }

    if (!write)
    {
        for (u64 i = 0; i < total_bytes; ++i)
            bytes[i] = g_ctrl.io_buf_virt[i];
    }
    return 0;
}

i32 NvmeBlockRead(void* /*cookie*/, u64 lba, u32 count, void* buf)
{
    return NvmeDoIo(/*write=*/false, lba, count, buf);
}

i32 NvmeBlockWrite(void* /*cookie*/, u64 lba, u32 count, const void* buf)
{
    return NvmeDoIo(/*write=*/true, lba, count, const_cast<void*>(buf));
}

constinit const BlockOps kNvmeBlockOps = {
    /*.read = */ &NvmeBlockRead,
    /*.write = */ &NvmeBlockWrite,
};

bool RegisterAsBlockDevice()
{
    g_ctrl.io_buf_phys = AllocZeroedPage();
    if (g_ctrl.io_buf_phys == 0)
    {
        return false;
    }
    g_ctrl.io_buf_virt = static_cast<u8*>(mm::PhysToVirt(g_ctrl.io_buf_phys));

    BlockDesc desc{};
    desc.name = "nvme0n1";
    desc.ops = &kNvmeBlockOps;
    desc.cookie = &g_ctrl;
    desc.sector_size = g_ctrl.ns_sector_size;
    desc.sector_count = g_ctrl.ns_sector_count;
    const u32 h = BlockDeviceRegister(desc);
    if (h == kBlockHandleInvalid)
    {
        return false;
    }
    g_ctrl.block_handle = h;
    return true;
}

} // namespace

void NvmeInit()
{
    const pci::Device* dev = FindNvme();
    if (dev == nullptr)
    {
        core::Log(core::LogLevel::Info, "drivers/nvme", "no NVMe controller on PCI bus");
        return;
    }
    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "controller found; pci bus", dev->addr.bus);

    EnablePciBusMaster(dev->addr);

    const pci::Bar bar0 = pci::PciReadBar(dev->addr, 0);
    if (bar0.size == 0 || bar0.is_io)
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "BAR0 missing or I/O — not a valid NVMe controller");
        return;
    }

    void* mmio = mm::MapMmio(bar0.address, bar0.size);
    if (mmio == nullptr)
    {
        core::Panic("drivers/nvme", "MapMmio failed for BAR0");
    }
    g_ctrl.mmio = static_cast<volatile u8*>(mmio);

    g_ctrl.cap = Reg64(kRegCap);
    const u32 vs = Reg32(kRegVs);
    g_ctrl.max_queue_entries = static_cast<u32>((g_ctrl.cap & 0xFFFF) + 1);
    const u32 dstrd = static_cast<u32>((g_ctrl.cap >> 32) & 0xF);
    g_ctrl.doorbell_stride_bytes = 4U << dstrd;
    g_ctrl.cap_to_ms = ((g_ctrl.cap >> 24) & 0xFF) * 500;
    g_ctrl.next_cid = 1;

    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "version", vs);
    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "cap.mqes+1", g_ctrl.max_queue_entries);
    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "cap.dstrd bytes", g_ctrl.doorbell_stride_bytes);
    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "cap.to ms", g_ctrl.cap_to_ms);

    if (g_ctrl.max_queue_entries < kAdminQueueEntries || g_ctrl.max_queue_entries < kIoQueueEntries)
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "controller MQES below our queue depth");
        return;
    }

    if (!ResetAndEnable(dev))
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "reset / enable sequence failed");
        return;
    }

    if (!IdentifyControllerLogOnly())
    {
        return;
    }
    if (!IdentifyNamespaceOne())
    {
        return;
    }
    if (g_ctrl.ns_sector_count == 0 || g_ctrl.ns_sector_size == 0)
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "namespace reports zero geometry");
        return;
    }

    if (!CreateIoQueues())
    {
        return;
    }

    if (!RegisterAsBlockDevice())
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "block-layer registration failed");
        return;
    }

    g_ctrl.online = true;
    core::Log(core::LogLevel::Info, "drivers/nvme", "online as nvme0n1");
}

void NvmeSelfTest()
{
    using arch::SerialWrite;
    if (!g_ctrl.online)
    {
        SerialWrite("[nvme] self-test skipped (no controller online)\n");
        return;
    }

    const u32 ss = g_ctrl.ns_sector_size;
    u8 scratch[4096];
    if (ss > sizeof(scratch))
    {
        SerialWrite("[nvme] self-test FAILED: sector size exceeds scratch\n");
        return;
    }
    for (u32 i = 0; i < ss; ++i)
        scratch[i] = 0;

    // LBA 0 on a GPT disk is the Protective MBR, which ends in the classic
    // 0x55 0xAA boot signature at offset 510/511. This is the cheapest
    // "real disk content" assertion we can make without parsing the GPT
    // — `fs/gpt::GptSelfTest` does the full parse after we return.
    const i32 rc = BlockDeviceRead(g_ctrl.block_handle, 0, 1, scratch);
    if (rc != 0)
    {
        SerialWrite("[nvme] self-test FAILED: LBA 0 read returned error\n");
        return;
    }
    if (scratch[510] != 0x55 || scratch[511] != 0xAA)
    {
        SerialWrite("[nvme] self-test FAILED: LBA 0 missing 0x55AA boot signature\n");
        return;
    }
    SerialWrite("[nvme] self-test OK (LBA 0 read + 0x55AA signature present)\n");
}

} // namespace customos::drivers::storage
