/*
 * DuetOS — NVMe storage driver: implementation.
 *
 * Companion to nvme.h — see there for the device-record shape,
 * block-layer integration, and v0 polling-IO contract.
 *
 * WHAT
 *   Drives NVMe-over-PCIe controllers: discovers the doorbell
 *   stride, posts the admin SQ/CQ, identifies the controller
 *   and namespace 1, then stands up an I/O SQ/CQ for read/write.
 *   Hooks the block layer so /dev/nvme0n1 appears with a working
 *   ReadBlock / WriteBlock path.
 *
 * HOW
 *   Polling at v0 — no MSI-X, no interrupt thread. Each
 *   submission rings the doorbell; the caller spins on the CQ
 *   head. Acceptable because v0 has only one outstanding I/O
 *   at a time. MSI-X lands when the block layer grows
 *   queue-depth > 1.
 *
 *   Self-test (`NvmeMarkerSelfTest`) writes + reads a sentinel
 *   block at boot; failure quarantines the device instead of
 *   letting later writes corrupt user data.
 */

#include "nvme.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/hpet.h"
#include "../../arch/x86_64/serial.h"
#include "../../core/kdbg.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"
#include "../pci/pci.h"
#include "block.h"

namespace duetos::drivers::storage
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

// Host page size (4 KiB for x86_64) expressed as CC.MPS encoding:
// MPS = log2(page_bytes) - 12. For 4 KiB pages, MPS = 0.
constexpr u32 kHostMpsEncoding = 0;

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

// Queue sizing. One 4 KiB page per SQ (64-byte entries -> 64 entries
// fit) and one page per CQ (16-byte entries -> 256 entries fit). Cap
// both at 64 so the SQ is the binding constraint and the CQ has
// headroom that outpaces the SQ's in-flight limit. Controllers that
// report CAP.MQES below these caps have their reported max used
// instead.
constexpr u32 kAdminQueueEntriesCap = 8;
constexpr u32 kIoQueueEntriesCap = 64;

constexpr u32 kSqEntryBytes = 64;
constexpr u32 kCqEntryBytes = 16;

// I/O staging buffer geometry. 16 pages = 64 KiB is a sweet spot:
// big enough that a FAT cluster (4/8/16 KiB) or a GPT entry array
// (16 KiB) lands in one command, small enough that a contiguous
// frame-allocator run is practically always available.
constexpr u32 kIoBufPages = 16;
constexpr u32 kIoBufBytes = kIoBufPages * mm::kPageSize;

// PRP list page entry count — 4 KiB / 8 bytes per entry.
constexpr u32 kPrpListEntryCount = mm::kPageSize / sizeof(u64);
static_assert(kIoBufPages <= kPrpListEntryCount + 1, "staging buffer exceeds single-level PRP list reach");

// Absolute fallback budget — even respecting CAP.TO we won't poll
// forever if firmware is wedged. Roughly 10 seconds at a modern
// CPU's pause cost; re-used only if HPET isn't available.
constexpr u64 kFallbackPauseBudget = 500ULL * 1000ULL * 1000ULL;

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
    u32 admin_queue_entries;   // min(kAdminQueueEntriesCap, max_queue_entries)
    u32 io_queue_entries;      // min(kIoQueueEntriesCap, max_queue_entries)
    u32 mps_min;               // CAP.MPSMIN (2^(12+MPSMIN) bytes)
    u32 mps_max;               // CAP.MPSMAX
    u32 mdts_max_bytes;        // Identify Controller MDTS translated to bytes; 0 = unlimited
    Queue admin;
    Queue io;
    u64 ns_sector_count;
    u32 ns_sector_size;
    u32 next_cid;
    // Staging buffer + single-level PRP list. Allocated once at init.
    mm::PhysAddr io_buf_phys;
    u8* io_buf_virt;
    mm::PhysAddr prp_list_phys;
    u64* prp_list_virt;
    u32 block_handle;
    bool online;
    // MSI-X state. `irq_vector` is non-zero when
    // `PciMsixBindSimple` succeeded; in that case the I/O CQ is
    // created with IEN=1 and SubmitAndWait blocks on `cq_wait`
    // between polls instead of burning CPU. Polling-only fallback
    // preserved for controllers that don't expose MSI-X.
    u8 irq_vector;
    duetos::sched::WaitQueue cq_wait;
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

// True if HPET is online and ready to tell time. HpetReadCounter
// returns 0 when HpetInit didn't land; we treat that as "no
// wall-clock available" and fall back to a pause-count budget.
bool HpetOnline()
{
    return arch::HpetPeriodFemtoseconds() != 0;
}

// Compute an HPET counter deadline `ms` milliseconds in the future.
// Only meaningful when HpetOnline() — caller must check.
u64 HpetDeadlineMs(u64 ms)
{
    // ticks = ms * 1e12 / period_fs. Keep the divide last so the
    // intermediate multiply doesn't lose precision.
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    const u64 ticks = (ms * 1'000'000'000'000ULL) / period_fs;
    return arch::HpetReadCounter() + ticks;
}

// Test whether `deadline` (as returned by HpetDeadlineMs) has passed.
bool HpetDeadlinePassed(u64 deadline)
{
    return arch::HpetReadCounter() >= deadline;
}

// Wait for CSTS.RDY to reach `expected` (0 or 1). Returns false on
// timeout or controller fatal status; caller should bail out of
// bring-up. Uses CAP.TO * 500 ms as the upper bound when HPET is
// available; otherwise falls back to a fixed pause-count budget.
bool WaitReady(u32 expected)
{
    const bool have_hpet = HpetOnline();
    // CAP.TO is the worst-case wall-clock the controller is allowed
    // to miss the transition by. Add a 500 ms cushion so we don't
    // race the controller's own tick boundary.
    const u64 budget_ms = g_ctrl.cap_to_ms + 500;
    const u64 deadline = have_hpet ? HpetDeadlineMs(budget_ms) : 0;
    u64 pause_iters = 0;
    for (;;)
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
        if (have_hpet)
        {
            if (HpetDeadlinePassed(deadline))
            {
                core::LogWith2Values(core::LogLevel::Error, "drivers/nvme", "CSTS.RDY wait timed out", "expected",
                                     expected, "budget_ms", budget_ms);
                return false;
            }
        }
        else if (++pause_iters >= kFallbackPauseBudget)
        {
            core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "CSTS.RDY wait timed out (no HPET); expected",
                               expected);
            return false;
        }
        CpuPause();
    }
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

// Submit one command into `q` and poll its completion. `entry.cdw0`
// must carry opcode; this helper fills in CID and returns true iff
// the completion status field is zero. On failure the split SC/SCT
// fields are logged so a real-disk error is triageable from the
// boot log alone. Poll deadline is driven by CAP.TO (via HPET) with
// a pause-count fallback for hosts that missed HPET init.
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

    // Poll the CQ slot at cq_head until its phase flips. CAP.TO is
    // the spec-defined worst-case command completion time; add a
    // 500 ms cushion the same way WaitReady does.
    const bool have_hpet = HpetOnline();
    const u64 budget_ms = g_ctrl.cap_to_ms + 500;
    const u64 deadline = have_hpet ? HpetDeadlineMs(budget_ms) : 0;
    const u32 head = q.cq_head;
    volatile CqEntry& cq_slot = q.cq[head];
    u64 pause_iters = 0;
    for (;;)
    {
        const u32 dw3 = cq_slot.cid_phase_status;
        const u32 phase = (dw3 >> 16) & 0x1;
        if (phase == q.expected_phase)
        {
            const u32 status_full = (dw3 >> 17) & 0x7FFF;
            // Decode per NVMe spec §4.6.1:
            //   SC  = bits 0..7  (status code)
            //   SCT = bits 8..10 (status code type)
            //   M   = bit 13     (more)
            //   DNR = bit 14     (do not retry)
            const u32 sc = status_full & 0xFF;
            const u32 sct = (status_full >> 8) & 0x7;
            const u32 new_head = (head + 1) % q.entries;
            q.cq_head = new_head;
            if (new_head == 0)
            {
                q.expected_phase ^= 1;
            }
            *CqHeadDoorbell(q.id) = new_head;
            if (status_full != 0)
            {
                core::LogWith2Values(core::LogLevel::Error, "drivers/nvme", "command failed", "sct", sct, "sc", sc);
                return false;
            }
            return true;
        }
        if (have_hpet)
        {
            if (HpetDeadlinePassed(deadline))
            {
                core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "completion timed out (ms)", budget_ms);
                return false;
            }
        }
        else if (++pause_iters >= kFallbackPauseBudget)
        {
            core::Log(core::LogLevel::Error, "drivers/nvme", "completion timed out (no HPET)");
            return false;
        }

        // When MSI-X is bound AND we're on the I/O queue, block on
        // the IRQ-signalled wait queue instead of burning CPU. The
        // admin queue stays strictly polled — it's only used for
        // bring-up, and blocking on a wait queue before the task
        // scheduler is fully running would deadlock. Lost-wakeup
        // guard: re-check the phase bit under Cli before blocking.
        if (g_ctrl.irq_vector != 0 && q.id != 0)
        {
            duetos::arch::Cli();
            const u32 dw3_recheck = cq_slot.cid_phase_status;
            const u32 phase_recheck = (dw3_recheck >> 16) & 0x1;
            if (phase_recheck == q.expected_phase)
            {
                duetos::arch::Sti();
                continue;
            }
            duetos::sched::WaitQueueBlock(&g_ctrl.cq_wait);
        }
        else
        {
            CpuPause();
        }
    }
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

    // Allocate admin queues using the per-controller cap derived
    // from CAP.MQES. Fitness self-check first — if the controller
    // reports MQES below our smallest admin queue, we can't bring
    // it up.
    if (g_ctrl.admin_queue_entries < 2)
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "admin queue floor (2 entries) exceeds CAP.MQES+1",
                           g_ctrl.admin_queue_entries);
        return false;
    }
    if (!QueueInit(g_ctrl.admin, g_ctrl.admin_queue_entries, 0))
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "admin queue allocation failed");
        return false;
    }

    // AQA: Admin SQ size in bits 0..11, CQ size in bits 16..27, both 0-based.
    const u32 aqs0 = (g_ctrl.admin_queue_entries - 1) & 0xFFF;
    const u32 aqa = aqs0 | (aqs0 << 16);
    Reg32(kRegAqa) = aqa;
    Reg64(kRegAsq) = g_ctrl.admin.sq_phys;
    Reg64(kRegAcq) = g_ctrl.admin.cq_phys;

    // CC: MPS = host page size encoding (0 for 4 KiB), CSS = 000
    // (NVM command set), AMS = 000 (round robin), IOSQES = 6
    // (64 bytes, log2), IOCQES = 4 (16 bytes, log2), EN = 1.
    u32 cc = 0;
    cc |= (kHostMpsEncoding & 0xF) << 7;
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

bool IdentifyController()
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
        const u8* bytes = static_cast<const u8*>(mm::PhysToVirt(buf));

        // Model number is at byte offset 24, 40 bytes, space-padded
        // ASCII. Copy the first 20 printable chars into a local
        // NUL-terminated buffer and ship it through LogWithString
        // — fixed-width padding stays, non-printables become '.'
        // for safety.
        static char model[21];
        for (u32 i = 0; i < 20; ++i)
        {
            const char c = static_cast<char>(bytes[24 + i]);
            model[i] = (c >= 0x20 && c < 0x7F) ? c : '.';
        }
        model[20] = 0;
        core::LogWithString(core::LogLevel::Info, "drivers/nvme", "identify controller", "model", model);

        // MDTS (byte 77): Maximum Data Transfer Size in units of
        // CAP.MPSMIN pages. 0 == unlimited. We translate to bytes
        // against the HOST page size since that's the unit every
        // I/O caller will care about; MPSMIN and our host page are
        // both 4 KiB when validation passed, so the translation is
        // a pass-through. A controller with MPSMIN > 0 that still
        // accepted enable is a contradiction, so we'd refuse it
        // further down the init path.
        const u8 mdts = bytes[77];
        g_ctrl.mdts_max_bytes = (mdts == 0) ? 0 : (mm::kPageSize << mdts);
        core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "MDTS max bytes (0=unlimited)", g_ctrl.mdts_max_bytes);
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
        core::LogWith2Values(core::LogLevel::Info, "drivers/nvme", "namespace 1 geometry", "sectors", nsze, "bytes/sec",
                             sector_size);
    }
    mm::FreeFrame(buf);
    return ok;
}

// MSI-X IRQ handler. Hardware asserts the vector whenever an
// entry lands on the I/O CQ with its phase bit flipped; the
// handler's only job is to wake any task blocked in
// SubmitAndWait. Acknowledgement happens on the CQ side via the
// head-doorbell write the completion-processing path already
// does. NVMe has no device-level "IRQ pending" register to clear
// (unlike xHCI's IMAN.IP); the head-doorbell + CQ phase bits are
// the only state.
void NvmeIrqHandler()
{
    duetos::sched::WaitQueueWakeOne(&g_ctrl.cq_wait);
}

bool CreateIoQueues()
{
    if (g_ctrl.io_queue_entries < 2)
    {
        core::LogWithValue(core::LogLevel::Error, "drivers/nvme", "I/O queue floor (2 entries) exceeds CAP.MQES+1",
                           g_ctrl.io_queue_entries);
        return false;
    }
    if (!QueueInit(g_ctrl.io, g_ctrl.io_queue_entries, 1))
    {
        return false;
    }

    const u32 qs0 = (g_ctrl.io_queue_entries - 1) & 0xFFFF;

    // Create I/O CQ first — the SQ references it.
    SqEntry cq_cmd{};
    cq_cmd.cdw0 = kAdminOpCreateCq;
    cq_cmd.prp1 = g_ctrl.io.cq_phys;
    // DW10: bits 0..15 = QID, bits 16..31 = Queue Size (0-based).
    cq_cmd.cdw10 = (1 & 0xFFFF) | (qs0 << 16);
    // DW11: bit 0 = PC (physically contiguous); bit 1 = IEN
    // (Interrupt Enable); bits 16..31 = IV (Interrupt Vector,
    // index into the MSI-X table we programmed). Arm IEN + IV=0
    // only when we successfully bound a vector; otherwise leave
    // IEN clear so the controller never generates MSIs we can't
    // receive.
    cq_cmd.cdw11 = 0x1;
    if (g_ctrl.irq_vector != 0)
    {
        cq_cmd.cdw11 |= (1u << 1); // IEN
        // IV already 0 (we use MSI-X table entry 0).
    }
    if (!SubmitAndWait(g_ctrl.admin, cq_cmd))
    {
        return false;
    }

    SqEntry sq_cmd{};
    sq_cmd.cdw0 = kAdminOpCreateSq;
    sq_cmd.prp1 = g_ctrl.io.sq_phys;
    sq_cmd.cdw10 = (1 & 0xFFFF) | (qs0 << 16);
    // DW11: bit 0 = PC, bits 16..31 = CQID = 1.
    sq_cmd.cdw11 = 0x1 | (1U << 16);
    if (!SubmitAndWait(g_ctrl.admin, sq_cmd))
    {
        return false;
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "I/O queue pair online (qid=1), entries",
                       g_ctrl.io_queue_entries);
    return true;
}

// --- BlockDevice vtable -----------------------------------------------------

// Build PRP1 / PRP2 for a staging-buffer-backed transfer of
// `byte_count` bytes. The staging buffer is always page-aligned, so
// PRP1 is the staging base and PRP2 either references a second page
// directly (two-page transfers) or a PRP list page populated with
// each remaining page's physical address. The PRP list is single-
// level — one 4 KiB page holds 512 entries, reaching 2 MiB of
// payload past PRP1, well above our 16-page (64 KiB) staging cap.
void BuildPrp(u32 byte_count, u64* prp1_out, u64* prp2_out)
{
    const u64 base = g_ctrl.io_buf_phys;
    if (byte_count <= mm::kPageSize)
    {
        *prp1_out = base;
        *prp2_out = 0;
        return;
    }
    if (byte_count <= 2 * mm::kPageSize)
    {
        *prp1_out = base;
        *prp2_out = base + mm::kPageSize;
        return;
    }
    // 3+ pages — use the PRP list. List entries cover pages 2..N-1
    // (0-indexed). Page 0 goes in PRP1; each subsequent page's
    // physical address lands in prp_list[i-1].
    const u32 page_count = (byte_count + mm::kPageSize - 1) / mm::kPageSize;
    *prp1_out = base;
    *prp2_out = g_ctrl.prp_list_phys;
    for (u32 i = 1; i < page_count; ++i)
    {
        g_ctrl.prp_list_virt[i - 1] = base + static_cast<u64>(i) * mm::kPageSize;
    }
}

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
    // Per-command cap is the lesser of our staging-buffer size and
    // the controller's MDTS (when set). Callers doing larger I/O
    // must loop over this limit — the block layer already does.
    u32 per_cmd_bytes = kIoBufBytes;
    if (g_ctrl.mdts_max_bytes != 0 && g_ctrl.mdts_max_bytes < per_cmd_bytes)
    {
        per_cmd_bytes = g_ctrl.mdts_max_bytes;
    }
    const u32 per_cmd_max_sectors = per_cmd_bytes / ss;
    if (count > per_cmd_max_sectors)
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

    u64 prp1 = 0;
    u64 prp2 = 0;
    BuildPrp(static_cast<u32>(total_bytes), &prp1, &prp2);

    SqEntry e{};
    e.cdw0 = write ? kIoOpWrite : kIoOpRead;
    e.nsid = 1;
    e.prp1 = prp1;
    e.prp2 = prp2;
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
    KDBG_2V(Storage, "drivers/nvme", "NvmeBlockRead", "lba", lba, "count", count);
    return NvmeDoIo(/*write=*/false, lba, count, buf);
}

i32 NvmeBlockWrite(void* /*cookie*/, u64 lba, u32 count, const void* buf)
{
    KDBG_2V(Storage, "drivers/nvme", "NvmeBlockWrite", "lba", lba, "count", count);
    return NvmeDoIo(/*write=*/true, lba, count, const_cast<void*>(buf));
}

constinit const BlockOps kNvmeBlockOps = {
    /*.read = */ &NvmeBlockRead,
    /*.write = */ &NvmeBlockWrite,
};

bool RegisterAsBlockDevice()
{
    // Contiguous 16-page staging buffer so PRP list entries point
    // at consecutive physical pages without per-page allocation.
    const mm::PhysAddr stage_phys = mm::AllocateContiguousFrames(kIoBufPages);
    if (stage_phys == mm::kNullFrame)
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "contiguous staging buffer allocation failed");
        return false;
    }
    g_ctrl.io_buf_phys = stage_phys;
    g_ctrl.io_buf_virt = static_cast<u8*>(mm::PhysToVirt(stage_phys));
    for (u64 i = 0; i < kIoBufBytes; ++i)
        g_ctrl.io_buf_virt[i] = 0;

    // One PRP list page. Entries are written on demand by BuildPrp,
    // but the backing page has to exist up-front because its
    // physical address is what we hand the controller.
    const mm::PhysAddr list_phys = AllocZeroedPage();
    if (list_phys == 0)
    {
        mm::FreeContiguousFrames(stage_phys, kIoBufPages);
        core::Log(core::LogLevel::Error, "drivers/nvme", "PRP list page allocation failed");
        return false;
    }
    g_ctrl.prp_list_phys = list_phys;
    g_ctrl.prp_list_virt = static_cast<u64*>(mm::PhysToVirt(list_phys));

    BlockDesc desc{};
    desc.name = "nvme0n1";
    desc.ops = &kNvmeBlockOps;
    desc.cookie = &g_ctrl;
    desc.sector_size = g_ctrl.ns_sector_size;
    desc.sector_count = g_ctrl.ns_sector_count;
    const u32 h = BlockDeviceRegister(desc);
    if (h == kBlockHandleInvalid)
    {
        mm::FreeContiguousFrames(stage_phys, kIoBufPages);
        mm::FreeFrame(list_phys);
        return false;
    }
    g_ctrl.block_handle = h;
    return true;
}

} // namespace

void NvmeInit()
{
    KLOG_TRACE_SCOPE("drivers/nvme", "NvmeInit");
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
    g_ctrl.mps_min = static_cast<u32>((g_ctrl.cap >> 48) & 0xF);
    g_ctrl.mps_max = static_cast<u32>((g_ctrl.cap >> 52) & 0xF);
    g_ctrl.next_cid = 1;

    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "version", vs);
    core::LogWith2Values(core::LogLevel::Info, "drivers/nvme", "capabilities", "max_queue_entries",
                         g_ctrl.max_queue_entries, "doorbell_stride", g_ctrl.doorbell_stride_bytes);
    core::LogWith2Values(core::LogLevel::Info, "drivers/nvme", "page-size support", "mps_min", g_ctrl.mps_min,
                         "mps_max", g_ctrl.mps_max);
    core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "timeout (ms)", g_ctrl.cap_to_ms);

    // We run a 4 KiB host page size (MPS encoding 0). The controller
    // must accept that value: MPSMIN <= 0 <= MPSMAX. Any silicon
    // that needs a bigger host page is rejected cleanly rather
    // than producing mysterious CSTS.CFS a few commands later.
    if (g_ctrl.mps_min > kHostMpsEncoding || g_ctrl.mps_max < kHostMpsEncoding)
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "controller cannot operate at 4 KiB host page size");
        return;
    }

    // Derive per-controller queue depths. Cap at our compile-time
    // ceilings; clip at MQES when the controller reports a smaller
    // ceiling. The admin queue only services bring-up + occasional
    // namespace/queue commands, so its floor is tiny.
    g_ctrl.admin_queue_entries = kAdminQueueEntriesCap;
    if (g_ctrl.admin_queue_entries > g_ctrl.max_queue_entries)
    {
        g_ctrl.admin_queue_entries = g_ctrl.max_queue_entries;
    }
    g_ctrl.io_queue_entries = kIoQueueEntriesCap;
    if (g_ctrl.io_queue_entries > g_ctrl.max_queue_entries)
    {
        g_ctrl.io_queue_entries = g_ctrl.max_queue_entries;
    }

    if (!ResetAndEnable(dev))
    {
        core::Log(core::LogLevel::Error, "drivers/nvme", "reset / enable sequence failed");
        return;
    }

    if (!IdentifyController())
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

    // MSI-X for the I/O CQ — bind BEFORE CreateIoQueues so the
    // Create I/O CQ command can flip IEN=1 with IV=0 from the
    // outset. Failure falls back to polling.
    {
        pci::DeviceAddress pci_addr{};
        pci_addr.bus = dev->addr.bus;
        pci_addr.device = dev->addr.device;
        pci_addr.function = dev->addr.function;
        auto r = pci::PciMsixBindSimple(pci_addr, /*entry_index=*/0, NvmeIrqHandler, /*out_route=*/nullptr);
        if (r.has_value())
        {
            g_ctrl.irq_vector = r.value();
            core::LogWithValue(core::LogLevel::Info, "drivers/nvme", "MSI-X bound vector", g_ctrl.irq_vector);
        }
        else
        {
            core::Log(core::LogLevel::Info, "drivers/nvme", "MSI-X unavailable — polling I/O completion");
        }
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
    KLOG_TRACE_SCOPE("drivers/nvme", "NvmeSelfTest");
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

} // namespace duetos::drivers::storage
