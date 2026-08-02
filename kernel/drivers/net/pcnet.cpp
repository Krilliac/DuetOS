#include "drivers/net/pcnet.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/net/net.h"
#include "drivers/net/wireless_watch.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/string.h"

/*
 * Restart-safe AMD PCnet-PCI (1022:2000) backend. The controller is polled,
 * but its worker, stack callback, PCI command ownership, and DMA lifetime all
 * have explicit join points so NetShutdown/NetInit may safely reuse a slot.
 */

namespace duetos::drivers::net
{

namespace
{

namespace arch = ::duetos::arch;
namespace mm = ::duetos::mm;
namespace stack = ::duetos::net;
namespace contract = ::duetos::drivers::net::pcnet_contract;

constexpr u16 kRdp = 0x10;
constexpr u16 kRap = 0x14;
constexpr u16 kResetDwio = 0x18;
constexpr u16 kResetWio = 0x14;
constexpr u16 kBdp = 0x1C;
constexpr u64 kIoExtent = 0x20;
constexpr u16 kPciCommandIoSpace = 1u << 0;
constexpr u16 kPciCommandBusMaster = 1u << 2;
constexpr u16 kBcr20Ssize32 = 1u << 8;
constexpr u16 kCsr0RuntimeFaults = 0x7800;
constexpr u32 kRingLog2 = 3;
constexpr u32 kContextCount = 4;
constexpr u32 kPollBudget = contract::kRxRingSlots;
constexpr u32 kJoinBudgetTicks = 200;
constexpr u64 kInterruptEnable = 1ULL << 9;

struct PcnetCtx
{
    // These four synchronization objects are stable storage and are never
    // aggregate-overwritten between generations.
    DriverOperationGate operations;
    DriverWorkerLease rx_worker;
    sync::SpinLock tx_lock;
    sync::SpinLock csr_lock;

    pci::DeviceAddress pci_address;
    u16 pci_command_original;
    u16 io;
    u64 io_bytes;
    bool pci_command_saved;
    bool dma_armed;
    bool dma_published;
    bool stack_bound;
    bool quarantined;
    bool online;

    mm::DmaBuffer init_dma;
    mm::DmaBuffer rx_ring_dma;
    mm::DmaBuffer tx_ring_dma;
    mm::DmaBuffer rx_buf_dma;
    mm::DmaBuffer tx_buf_dma;
    contract::PcnetInitBlock* init_block;
    contract::PcnetDescriptor* rx_ring;
    contract::PcnetDescriptor* tx_ring;
    u8* rx_buffers;
    u8* tx_buffers;
    u32 rx_cursor;
    bool rx_discard_until_end;
    contract::TxCursor tx_cursor;
    stack::NetInterfaceBinding stack_binding;
    u32 iface_index;
};

PcnetCtx g_pcnet[kContextCount] = {};
u32 g_pcnet_count = 0;

void DelayController()
{
    for (u32 i = 0; i < 1024; ++i)
        asm volatile("pause" ::: "memory");
}

bool AcquireOperation(PcnetCtx& ctx)
{
    return DriverOperationGateTryAcquire(&ctx.operations);
}

void ReleaseOperation(PcnetCtx& ctx)
{
    KASSERT(DriverOperationGateRelease(&ctx.operations), "drivers/net/pcnet", "operation pin underflow");
}

u16 ReadCsr(PcnetCtx& ctx, u16 index)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.csr_lock);
    arch::Outl(ctx.io + kRap, index);
    const u16 value = static_cast<u16>(arch::Inl(ctx.io + kRdp));
    sync::SpinLockRelease(ctx.csr_lock, flags);
    return value;
}

void WriteCsr(PcnetCtx& ctx, u16 index, u16 value)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.csr_lock);
    arch::Outl(ctx.io + kRap, index);
    arch::Outl(ctx.io + kRdp, value);
    sync::SpinLockRelease(ctx.csr_lock, flags);
}

u16 ReadBcr(PcnetCtx& ctx, u16 index)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.csr_lock);
    arch::Outl(ctx.io + kRap, index);
    const u16 value = static_cast<u16>(arch::Inl(ctx.io + kBdp));
    sync::SpinLockRelease(ctx.csr_lock, flags);
    return value;
}

void WriteBcr(PcnetCtx& ctx, u16 index, u16 value)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.csr_lock);
    arch::Outl(ctx.io + kRap, index);
    arch::Outl(ctx.io + kBdp, value);
    sync::SpinLockRelease(ctx.csr_lock, flags);
}

void AckRuntimeCauses(PcnetCtx& ctx)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.csr_lock);
    arch::Outl(ctx.io + kRap, 0);
    const u16 status = static_cast<u16>(arch::Inl(ctx.io + kRdp));
    const u16 ack = contract::Csr0RuntimeAckValue(status);
    if (ack != 0)
        arch::Outl(ctx.io + kRdp, ack);
    sync::SpinLockRelease(ctx.csr_lock, flags);
}

void ClearRuntimeFields(PcnetCtx& ctx)
{
    KASSERT(!DriverOperationGateIsOpen(&ctx.operations), "drivers/net/pcnet", "clear with gate open");
    KASSERT(DriverOperationGatePinCount(&ctx.operations) == 0, "drivers/net/pcnet", "clear with operation pins");
    KASSERT(DriverWorkerLeaseActiveGeneration(&ctx.rx_worker) == 0, "drivers/net/pcnet", "clear with worker");
    KASSERT(!ctx.dma_armed && !ctx.dma_published, "drivers/net/pcnet", "clear before DMA proof");

    ctx.pci_address = {};
    ctx.pci_command_original = 0;
    ctx.io = 0;
    ctx.io_bytes = 0;
    ctx.pci_command_saved = false;
    ctx.dma_armed = false;
    ctx.dma_published = false;
    ctx.stack_bound = false;
    ctx.quarantined = false;
    ctx.online = false;
    ctx.init_dma = {};
    ctx.rx_ring_dma = {};
    ctx.tx_ring_dma = {};
    ctx.rx_buf_dma = {};
    ctx.tx_buf_dma = {};
    ctx.init_block = nullptr;
    ctx.rx_ring = nullptr;
    ctx.tx_ring = nullptr;
    ctx.rx_buffers = nullptr;
    ctx.tx_buffers = nullptr;
    ctx.rx_cursor = 0;
    ctx.rx_discard_until_end = false;
    ctx.tx_cursor = {};
    ctx.stack_binding = {};
    ctx.iface_index = 0;
}

bool UpdatePciCommand(PcnetCtx& ctx, u16 set_bits, u16 clear_bits)
{
    const u16 current = pci::PciConfigRead16(ctx.pci_address, 0x04);
    const u16 desired = static_cast<u16>((current | set_bits) & ~clear_bits);
    // Status is the upper half of dword 0x04 and contains W1C bits. Write
    // zero there rather than echoing a status snapshot while changing Command.
    pci::PciConfigWrite32(ctx.pci_address, 0x04, static_cast<u32>(desired));
    const u16 observed = pci::PciConfigRead16(ctx.pci_address, 0x04);
    return (observed & set_bits) == set_bits && (observed & clear_bits) == 0;
}

bool SaveAndDisarmPci(PcnetCtx& ctx)
{
    ctx.pci_command_original = pci::PciConfigRead16(ctx.pci_address, 0x04);
    ctx.pci_command_saved = true;
    return UpdatePciCommand(ctx, 0, kPciCommandBusMaster);
}

bool EnableIoDecode(PcnetCtx& ctx)
{
    return UpdatePciCommand(ctx, kPciCommandIoSpace, kPciCommandBusMaster);
}

bool EnableBusMaster(PcnetCtx& ctx)
{
    if (!UpdatePciCommand(ctx, kPciCommandIoSpace | kPciCommandBusMaster, 0))
        return false;
    ctx.dma_armed = true;
    return true;
}

bool DisableBusMaster(PcnetCtx& ctx)
{
    const bool disabled = UpdatePciCommand(ctx, 0, kPciCommandBusMaster);
    if (disabled)
        ctx.dma_armed = false;
    return disabled;
}

bool RestoreSafePciCommand(PcnetCtx& ctx)
{
    if (!ctx.pci_command_saved)
        return true;
    const u16 desired = static_cast<u16>(ctx.pci_command_original & ~kPciCommandBusMaster);
    pci::PciConfigWrite32(ctx.pci_address, 0x04, static_cast<u32>(desired));
    const u16 observed = pci::PciConfigRead16(ctx.pci_address, 0x04);
    if ((observed & kPciCommandBusMaster) == 0)
        ctx.dma_armed = false;
    const u16 owned = kPciCommandIoSpace | kPciCommandBusMaster;
    return (observed & owned) == (desired & owned);
}

bool BarIsUsable(const pci::Bar& bar)
{
    return bar.is_io && bar.address != 0 && bar.size >= kIoExtent && (bar.address & (kIoExtent - 1)) == 0 &&
           bar.address <= 0xFFFFu && bar.address <= 0x10000u - kIoExtent;
}

bool LivePciIdentityMatches(const NicInfo& nic)
{
    pci::DeviceAddress address{};
    address.bus = nic.bus;
    address.device = nic.device;
    address.function = nic.function;

    const pci::Device* cached = nullptr;
    for (u64 i = 0; i < pci::PciDeviceCount(); ++i)
    {
        const pci::Device& candidate = pci::PciDevice(i);
        if (candidate.addr.bus == address.bus && candidate.addr.device == address.device &&
            candidate.addr.function == address.function)
        {
            cached = &candidate;
            break;
        }
    }
    if (cached == nullptr || cached->vendor_id != nic.vendor_id || cached->device_id != nic.device_id ||
        cached->class_code != 0x02 || cached->subclass != nic.subclass || (cached->header_type & 0x7Fu) != 0)
        return false;

    const u32 expected_vendor_device =
        static_cast<u32>(cached->vendor_id) | (static_cast<u32>(cached->device_id) << 16);
    const u32 expected_class_revision =
        static_cast<u32>(cached->revision_id) | (static_cast<u32>(cached->programming_interface) << 8) |
        (static_cast<u32>(cached->subclass) << 16) | (static_cast<u32>(cached->class_code) << 24);
    if (pci::PciConfigRead32(address, 0x00) != expected_vendor_device ||
        pci::PciConfigRead32(address, 0x08) != expected_class_revision ||
        (pci::PciConfigRead8(address, 0x0E) & 0x7Fu) != (cached->header_type & 0x7Fu))
        return false;
    const u32 live_subsystem = pci::PciConfigRead32(address, 0x2C);
    if (cached->subsystem_known)
    {
        const u32 expected_subsystem =
            static_cast<u32>(cached->subsystem_vendor_id) | (static_cast<u32>(cached->subsystem_device_id) << 16);
        if (live_subsystem != expected_subsystem)
            return false;
    }
    else
    {
        // The cache intentionally canonicalizes an absent subsystem tuple.
        // Fail closed on every non-sentinel live dword because no exact tuple
        // was retained to distinguish a replacement from the original row.
        if (live_subsystem != 0 && live_subsystem != 0xFFFFFFFFu)
            return false;
    }
    return true;
}

bool MacIsUsable(const NicInfo& nic)
{
    if (!nic.mac_valid || (nic.mac[0] & 1u) != 0)
        return false;
    bool all_zero = true;
    bool all_ones = true;
    for (u32 i = 0; i < 6; ++i)
    {
        all_zero = all_zero && nic.mac[i] == 0;
        all_ones = all_ones && nic.mac[i] == 0xFFu;
    }
    return !all_zero && !all_ones;
}

PcnetCtx* AllocateContext()
{
    if (g_pcnet_count >= kContextCount)
        return nullptr;
    return &g_pcnet[g_pcnet_count++];
}

bool ResetAndSelectStyle(PcnetCtx& ctx)
{
    // A device may still be in either word-I/O or dword-I/O mode. Read both
    // reset ports, then a dword RDP write selects DWIO for all later access.
    (void)arch::Inw(ctx.io + kResetWio);
    (void)arch::Inl(ctx.io + kResetDwio);
    for (volatile u32 i = 0; i < 20000; i = i + 1)
    {
    }
    arch::Outl(ctx.io + kRdp, 0);

    arch::Outl(ctx.io + kRap, 88);
    if ((arch::Inl(ctx.io + kRap) & 0xFFFFu) != 88)
        return false;

    WriteCsr(ctx, 0, contract::kCsr0Stop);
    WriteBcr(ctx, 20, 2); // SWSTYLE=2: 32-bit addresses, 16-byte descriptors.
    const u16 style = ReadBcr(ctx, 20);
    if ((style & 0x00FFu) != 2 || (style & kBcr20Ssize32) == 0)
        return false;
    WriteCsr(ctx, 4, 0x0915); // Linux pcnet32 baseline, including auto-pad.
    return true;
}

bool DmaFits32(const mm::DmaBuffer& buffer)
{
    return buffer.virt != nullptr && buffer.bytes != 0 && (buffer.phys >> 32) == 0 &&
           buffer.phys + buffer.bytes >= buffer.phys && buffer.phys + buffer.bytes <= (u64(1) << 32);
}

void FreeDmaStorage(PcnetCtx& ctx)
{
    KASSERT(!ctx.dma_armed, "drivers/net/pcnet", "freeing DMA while BME may be enabled");
    KASSERT(!ctx.dma_published, "drivers/net/pcnet", "freeing DMA before STOP proof");
    mm::FreeDmaCoherent(ctx.init_dma);
    mm::FreeDmaCoherent(ctx.rx_ring_dma);
    mm::FreeDmaCoherent(ctx.tx_ring_dma);
    mm::FreeDmaCoherent(ctx.rx_buf_dma);
    mm::FreeDmaCoherent(ctx.tx_buf_dma);
    ctx.init_dma = {};
    ctx.rx_ring_dma = {};
    ctx.tx_ring_dma = {};
    ctx.rx_buf_dma = {};
    ctx.tx_buf_dma = {};
    ctx.init_block = nullptr;
    ctx.rx_ring = nullptr;
    ctx.tx_ring = nullptr;
    ctx.rx_buffers = nullptr;
    ctx.tx_buffers = nullptr;
}

bool AllocateDmaStorage(PcnetCtx& ctx, const NicInfo& nic)
{
    auto init = mm::AllocDmaCoherent(sizeof(contract::PcnetInitBlock), mm::Zone::Dma32);
    if (!init)
        return false;
    ctx.init_dma = init.value();

    auto rx_ring = mm::AllocDmaCoherent(contract::kRxRingSlots * sizeof(contract::PcnetDescriptor), mm::Zone::Dma32);
    if (!rx_ring)
        return false;
    ctx.rx_ring_dma = rx_ring.value();
    auto tx_ring = mm::AllocDmaCoherent(contract::kTxRingSlots * sizeof(contract::PcnetDescriptor), mm::Zone::Dma32);
    if (!tx_ring)
        return false;
    ctx.tx_ring_dma = tx_ring.value();

    auto rx_buffers = mm::AllocDmaCoherent(u64(contract::kRxRingSlots) * contract::kBufferBytes, mm::Zone::Dma32);
    if (!rx_buffers)
        return false;
    ctx.rx_buf_dma = rx_buffers.value();
    auto tx_buffers = mm::AllocDmaCoherent(u64(contract::kTxRingSlots) * contract::kBufferBytes, mm::Zone::Dma32);
    if (!tx_buffers)
        return false;
    ctx.tx_buf_dma = tx_buffers.value();

    if (!DmaFits32(ctx.init_dma) || !DmaFits32(ctx.rx_ring_dma) || !DmaFits32(ctx.tx_ring_dma) ||
        !DmaFits32(ctx.rx_buf_dma) || !DmaFits32(ctx.tx_buf_dma))
        return false;

    ctx.init_block = static_cast<contract::PcnetInitBlock*>(ctx.init_dma.virt);
    ctx.rx_ring = static_cast<contract::PcnetDescriptor*>(ctx.rx_ring_dma.virt);
    ctx.tx_ring = static_cast<contract::PcnetDescriptor*>(ctx.tx_ring_dma.virt);
    ctx.rx_buffers = static_cast<u8*>(ctx.rx_buf_dma.virt);
    ctx.tx_buffers = static_cast<u8*>(ctx.tx_buf_dma.virt);

    for (u32 i = 0; i < contract::kRxRingSlots; ++i)
    {
        contract::PcnetDescriptor& descriptor = ctx.rx_ring[i];
        descriptor.address = static_cast<u32>(ctx.rx_buf_dma.phys + u64(i) * contract::kBufferBytes);
        descriptor.buffer_count = contract::EncodeBufferCount(contract::kBufferBytes);
        descriptor.message = 0;
        descriptor.reserved = 0;
        descriptor.status = contract::kDescriptorOwn;
    }
    for (u32 i = 0; i < contract::kTxRingSlots; ++i)
    {
        contract::PcnetDescriptor& descriptor = ctx.tx_ring[i];
        descriptor.address = static_cast<u32>(ctx.tx_buf_dma.phys + u64(i) * contract::kBufferBytes);
        descriptor.buffer_count = 0;
        descriptor.status = 0;
        descriptor.message = 0;
        descriptor.reserved = 0;
    }

    ctx.init_block->mode = 0;
    ctx.init_block->rx_ring_length = static_cast<u8>(kRingLog2 << 4);
    ctx.init_block->tx_ring_length = static_cast<u8>(kRingLog2 << 4);
    for (u32 i = 0; i < 6; ++i)
        ctx.init_block->physical_address[i] = nic.mac[i];
    ctx.init_block->reserved = 0;
    ctx.init_block->logical_filter_low = 0;
    ctx.init_block->logical_filter_high = 0;
    ctx.init_block->rx_ring_address = static_cast<u32>(ctx.rx_ring_dma.phys);
    ctx.init_block->tx_ring_address = static_cast<u32>(ctx.tx_ring_dma.phys);
    ctx.init_block->padding = 0;

    mm::DmaSyncForDevice(ctx.init_dma, 0, sizeof(contract::PcnetInitBlock));
    mm::DmaSyncForDevice(ctx.rx_ring_dma, 0, contract::kRxRingSlots * sizeof(contract::PcnetDescriptor));
    mm::DmaSyncForDevice(ctx.tx_ring_dma, 0, contract::kTxRingSlots * sizeof(contract::PcnetDescriptor));
    mm::DmaSyncForDevice(ctx.rx_buf_dma, 0, ctx.rx_buf_dma.bytes);
    mm::DmaSyncForDevice(ctx.tx_buf_dma, 0, ctx.tx_buf_dma.bytes);
    return true;
}

bool SendFrame(PcnetCtx& ctx, const u8* data, u32 len)
{
    if (data == nullptr || len == 0 || len > contract::kMaximumFrameBytes)
        return false;
    if (!AcquireOperation(ctx))
        return false;

    const sync::IrqFlags flags = sync::SpinLockAcquire(ctx.tx_lock);
    while (ctx.tx_cursor.in_flight != 0)
    {
        const u32 clean = ctx.tx_cursor.clean;
        const u64 descriptor_offset = u64(clean) * sizeof(contract::PcnetDescriptor);
        mm::DmaSyncForCpu(ctx.tx_ring_dma, descriptor_offset, sizeof(contract::PcnetDescriptor));
        if ((ctx.tx_ring[clean].status & contract::kDescriptorOwn) != 0)
            break;
        KASSERT(contract::TxReclaimOne(ctx.tx_cursor), "drivers/net/pcnet", "TX reclaim underflow");
    }

    if (contract::TxRingFull(ctx.tx_cursor))
    {
        sync::SpinLockRelease(ctx.tx_lock, flags);
        ReleaseOperation(ctx);
        return false;
    }

    const u32 slot = contract::TxProducerSlot(ctx.tx_cursor);
    const u64 buffer_offset = u64(slot) * contract::kBufferBytes;
    const u64 descriptor_offset = u64(slot) * sizeof(contract::PcnetDescriptor);
    u8* buffer = ctx.tx_buffers + buffer_offset;
    for (u32 i = 0; i < len; ++i)
        buffer[i] = data[i];

    contract::PcnetDescriptor& descriptor = ctx.tx_ring[slot];
    descriptor.address = static_cast<u32>(ctx.tx_buf_dma.phys + buffer_offset);
    descriptor.buffer_count = contract::EncodeBufferCount(len);
    descriptor.message = 0;
    descriptor.reserved = 0;
    descriptor.status = contract::kDescriptorStart | contract::kDescriptorEnd;
    mm::DmaSyncForDevice(ctx.tx_buf_dma, buffer_offset, len);
    mm::DmaSyncForDevice(ctx.tx_ring_dma, descriptor_offset, sizeof(contract::PcnetDescriptor));

    // OWN is the publication point and is synchronised separately so the
    // controller cannot observe a partially prepared descriptor.
    descriptor.status |= contract::kDescriptorOwn;
    mm::DmaSyncForDevice(ctx.tx_ring_dma, descriptor_offset + 6, sizeof(descriptor.status));
    KASSERT(contract::TxCommit(ctx.tx_cursor), "drivers/net/pcnet", "TX commit after capacity check");
    sync::SpinLockRelease(ctx.tx_lock, flags);

    // Do not nest the TX lock with the shared RAP/RDP address-pair lock.
    WriteCsr(ctx, 0, contract::kCsr0TransmitDemand);
    ReleaseOperation(ctx);
    return true;
}

bool StackTransmit(void* context, u32 iface_index, const void* frame, u64 len)
{
    auto* ctx = static_cast<PcnetCtx*>(context);
    if (ctx == nullptr || frame == nullptr || iface_index != ctx->iface_index || len > contract::kMaximumFrameBytes)
        return false;
    return SendFrame(*ctx, static_cast<const u8*>(frame), static_cast<u32>(len));
}

u32 DrainRx(PcnetCtx& ctx)
{
    if (!AcquireOperation(ctx))
        return 0;

    u32 delivered = 0;
    for (u32 checked = 0; checked < kPollBudget; ++checked)
    {
        const u32 slot = ctx.rx_cursor;
        const u64 descriptor_offset = u64(slot) * sizeof(contract::PcnetDescriptor);
        mm::DmaSyncForCpu(ctx.rx_ring_dma, descriptor_offset, sizeof(contract::PcnetDescriptor));
        contract::PcnetDescriptor& descriptor = ctx.rx_ring[slot];
        const contract::RxInspection inspection =
            contract::InspectRx(descriptor.status, descriptor.message, ctx.rx_discard_until_end);
        if (inspection.disposition == contract::RxDisposition::NotReady)
            break;

        ctx.rx_discard_until_end = inspection.discard_until_end;
        if (inspection.disposition == contract::RxDisposition::Deliver)
        {
            const u64 buffer_offset = u64(slot) * contract::kBufferBytes;
            mm::DmaSyncForCpu(ctx.rx_buf_dma, buffer_offset, inspection.frame_bytes);
            // No driver spinlock is held across stack ingress.
            stack::NetStackInjectRx(ctx.stack_binding, ctx.rx_buffers + buffer_offset, inspection.frame_bytes);
            ++delivered;
        }

        descriptor.address = static_cast<u32>(ctx.rx_buf_dma.phys + u64(slot) * contract::kBufferBytes);
        descriptor.buffer_count = contract::EncodeBufferCount(contract::kBufferBytes);
        descriptor.message = 0;
        descriptor.reserved = 0;
        descriptor.status = 0;
        mm::DmaSyncForDevice(ctx.rx_ring_dma, descriptor_offset, sizeof(contract::PcnetDescriptor));
        descriptor.status = contract::kDescriptorOwn;
        mm::DmaSyncForDevice(ctx.rx_ring_dma, descriptor_offset + 6, sizeof(descriptor.status));
        ctx.rx_cursor = (ctx.rx_cursor + 1) % contract::kRxRingSlots;
    }

    AckRuntimeCauses(ctx);
    ReleaseOperation(ctx);
    return delivered;
}

void RxPollEntry(void* argument)
{
    auto* ctx = static_cast<PcnetCtx*>(argument);
    if (ctx == nullptr)
        return;
    const u64 generation = DriverWorkerLeaseActiveGeneration(&ctx->rx_worker);
    if (generation == 0)
        return;

    while (DriverWorkerLeaseShouldRun(&ctx->rx_worker, generation))
    {
        const u32 delivered = DrainRx(*ctx);
        if (delivered == kPollBudget)
            continue;
        if (!DriverWorkerLeaseShouldRun(&ctx->rx_worker, generation))
            break;
        ::duetos::sched::SchedSleepTicks(1);
    }
    (void)DriverWorkerLeaseAcknowledge(&ctx->rx_worker, generation);
}

bool UnbindStack(PcnetCtx& ctx)
{
    if (!ctx.stack_bound)
        return true;
    const stack::NetInterfaceUnbindResult result = stack::NetStackUnbindInterface(ctx.stack_binding, kJoinBudgetTicks);
    if (result != stack::NetInterfaceUnbindResult::Unbound)
    {
        KLOG_ERROR_V("drivers/net/pcnet", "exact stack binding did not drain", static_cast<u64>(result));
        return false;
    }
    ctx.stack_bound = false;
    ctx.stack_binding = {};
    return true;
}

bool RetireUnstartedWorker(PcnetCtx& ctx, u64 generation)
{
    if (generation == 0)
        return true;
    return DriverWorkerLeaseRequestRetire(&ctx.rx_worker, generation) &&
           DriverWorkerLeaseAcknowledge(&ctx.rx_worker, generation);
}

bool WaitForJoins(PcnetCtx& ctx, u64 generation)
{
    bool worker_done = generation == 0;
    bool operations_done = false;
    for (u32 waited = 0; waited <= kJoinBudgetTicks; ++waited)
    {
        worker_done = generation == 0 || DriverWorkerLeaseIsAcknowledged(&ctx.rx_worker, generation);
        operations_done = DriverOperationGatePinCount(&ctx.operations) == 0;
        if (worker_done && operations_done)
            return true;
        if (waited != kJoinBudgetTicks)
            ::duetos::sched::SchedSleepTicks(1);
    }
    KLOG_ERROR_2V("drivers/net/pcnet", "join timed out; context and DMA retained", "worker-done", worker_done ? 1 : 0,
                  "operation-pins", DriverOperationGatePinCount(&ctx.operations));
    return false;
}

bool StopHardwareAndDisarm(PcnetCtx& ctx)
{
    if (!ctx.pci_command_saved)
        return !ctx.dma_armed && !ctx.dma_published;

    bool stopped = !ctx.dma_published;
    if (ctx.dma_published)
    {
        // Keep the current BME state until STOP has been posted and observed.
        // If a previous failed attempt already cleared BME, enabling I/O alone
        // is enough to retry the proof without re-arming DMA.
        const bool io_enabled = UpdatePciCommand(ctx, kPciCommandIoSpace, 0);
        if (io_enabled)
        {
            WriteCsr(ctx, 0, contract::kCsr0Stop);
            for (u32 tries = 0; tries < 10000; ++tries)
            {
                const u16 status = ReadCsr(ctx, 0);
                if ((status & contract::kCsr0Stop) != 0 && (status & (contract::kCsr0RxOn | contract::kCsr0TxOn)) == 0)
                {
                    stopped = true;
                    break;
                }
                DelayController();
            }
        }
    }

    const bool bus_master_disabled = DisableBusMaster(ctx);
    const bool command_restored = RestoreSafePciCommand(ctx);
    if (stopped && bus_master_disabled && command_restored)
        ctx.dma_published = false;
    if (!stopped || !bus_master_disabled || !command_restored)
    {
        KLOG_ERROR_2V("drivers/net/pcnet", "hardware stop unconfirmed; DMA retained", "stopped", stopped ? 1 : 0,
                      "bus-master-off", bus_master_disabled ? 1 : 0);
        return false;
    }
    return true;
}

bool InitializeAndStart(PcnetCtx& ctx)
{
    WriteCsr(ctx, 1, static_cast<u16>(ctx.init_dma.phys & 0xFFFFu));
    WriteCsr(ctx, 2, static_cast<u16>((ctx.init_dma.phys >> 16) & 0xFFFFu));
    if (!EnableBusMaster(ctx))
        return false;

    // From this point the controller has access to our DMA addresses. Every
    // rollback must prove STOP before this storage can be freed.
    ctx.dma_published = true;
    WriteCsr(ctx, 0, contract::kCsr0Init);
    bool initialized = false;
    for (u32 tries = 0; tries < 10000; ++tries)
    {
        const u16 status = ReadCsr(ctx, 0);
        if ((status & contract::kCsr0InitDone) != 0)
        {
            initialized = true;
            break;
        }
        if ((status & kCsr0RuntimeFaults) != 0)
            break;
        DelayController();
    }
    if (!initialized)
        return false;

    // Exact CSR0 control writes avoid echoing the register's W1C causes.
    WriteCsr(ctx, 0, contract::kCsr0Start);
    for (u32 tries = 0; tries < 10000; ++tries)
    {
        const u16 status = ReadCsr(ctx, 0);
        const u16 running = contract::kCsr0RxOn | contract::kCsr0TxOn;
        if ((status & running) == running && (status & contract::kCsr0Stop) == 0)
            return true;
        if ((status & kCsr0RuntimeFaults) != 0)
            break;
        DelayController();
    }
    return false;
}

void AbortUnstartedBringUp(PcnetCtx& ctx, u32 saved_count, u64 worker_generation)
{
    (void)DriverOperationGateClose(&ctx.operations);
    const bool worker_retired = RetireUnstartedWorker(ctx, worker_generation);
    const bool joined = worker_retired && WaitForJoins(ctx, worker_generation);
    const bool stack_unbound = joined && UnbindStack(ctx);
    const bool worker_released =
        stack_unbound && (worker_generation == 0 || DriverWorkerLeaseRelease(&ctx.rx_worker, worker_generation));
    // A stack callback admitted before unbind may still be approaching the
    // driver gate. Never reset or revoke BME beneath that receipt: retain the
    // live device and DMA until every join + exact unbind proof is complete.
    const bool hardware_safe = worker_released && StopHardwareAndDisarm(ctx);

    if (!joined || !stack_unbound || !worker_released || !hardware_safe)
    {
        ctx.quarantined = true;
        KLOG_ERROR("drivers/net/pcnet", "failed bring-up retained as quarantined context");
        return;
    }
    FreeDmaStorage(ctx);
    ClearRuntimeFields(ctx);
    g_pcnet_count = saved_count;
}

bool QuiesceOne(PcnetCtx& ctx)
{
    if (!ctx.pci_command_saved)
        return true;
    if ((arch::ReadRflags() & kInterruptEnable) == 0)
    {
        KLOG_ERROR("drivers/net/pcnet", "shutdown requires task context with interrupts enabled");
        return false;
    }

    ctx.online = false;
    (void)DriverOperationGateClose(&ctx.operations);
    const u64 generation = DriverWorkerLeaseActiveGeneration(&ctx.rx_worker);
    if (generation != 0 && !DriverWorkerLeaseRequestRetire(&ctx.rx_worker, generation))
    {
        ctx.quarantined = true;
        return false;
    }
    if (!WaitForJoins(ctx, generation))
    {
        ctx.quarantined = true;
        return false;
    }

    // The worker is joined before its exact receipt is unbound. The lease is
    // released only after the stack independently drains callback admission.
    if (!UnbindStack(ctx))
    {
        ctx.quarantined = true;
        return false;
    }
    if (generation != 0 && !DriverWorkerLeaseRelease(&ctx.rx_worker, generation))
    {
        ctx.quarantined = true;
        return false;
    }
    if (!StopHardwareAndDisarm(ctx))
    {
        ctx.quarantined = true;
        return false;
    }

    FreeDmaStorage(ctx);
    ClearRuntimeFields(ctx);
    arch::SerialWrite("[pcnet] quiesced: stack/worker drained, STOP proved, BME off\n");
    return true;
}

} // namespace

bool PcnetBringUp(NicInfo& nic, u32 iface_index)
{
    if (nic.vendor_id != 0x1022u || nic.device_id != 0x2000u)
        return false;

    const u32 saved_count = g_pcnet_count;
    PcnetCtx* ctx = AllocateContext();
    if (ctx == nullptr)
    {
        KLOG_WARN_V("drivers/net/pcnet", "PCnet context limit reached", iface_index);
        return false;
    }
    ClearRuntimeFields(*ctx);
    ctx->pci_address.bus = nic.bus;
    ctx->pci_address.device = nic.device;
    ctx->pci_address.function = nic.function;
    ctx->iface_index = iface_index;

    // The registry row came from an earlier PCI walk. Revalidate its exact
    // live endpoint identity before the first command-register write or BAR
    // sizing cycle so a stale/replaced BDF is rejected without mutation.
    if (!LivePciIdentityMatches(nic))
    {
        KLOG_ERROR("drivers/net/pcnet", "live PCI identity no longer matches registry receipt");
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    // BME is cleared before BAR sizing: the BAR probe temporarily writes all
    // ones and must never race an already-bus-mastering function.
    if (!SaveAndDisarmPci(*ctx))
    {
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }
    const pci::Bar bar = pci::PciReadBar(ctx->pci_address, 0);
    if (!BarIsUsable(bar))
    {
        KLOG_ERROR("drivers/net/pcnet", "BAR0 is not a bounded 32-byte I/O aperture");
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }
    ctx->io = static_cast<u16>(bar.address);
    ctx->io_bytes = bar.size;
    if (!EnableIoDecode(*ctx))
    {
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    nic.mac_valid = false;
    for (u32 i = 0; i < 6; ++i)
        nic.mac[i] = arch::Inb(ctx->io + static_cast<u16>(i));
    nic.mac_valid = true;
    if (!MacIsUsable(nic))
    {
        // Preserve a successfully read address for probe-only inventory on
        // later failures, but never advertise a hostile/all-zero address as
        // usable merely because the six I/O reads completed.
        nic.mac_valid = false;
        KLOG_ERROR("drivers/net/pcnet", "device exposed an unusable MAC address");
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }
    if (!ResetAndSelectStyle(*ctx) || !AllocateDmaStorage(*ctx, nic))
    {
        KLOG_ERROR("drivers/net/pcnet", "reset/style or DMA preparation failed");
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    const u64 worker_generation = DriverWorkerLeasePrepare(&ctx->rx_worker);
    if (worker_generation == 0)
    {
        AbortUnstartedBringUp(*ctx, saved_count, 0);
        return false;
    }

    stack::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = nic.mac[i];
    const stack::Ipv4Address ip{{0, 0, 0, 0}};
    if (!stack::NetStackBindInterfaceOwned(iface_index, mac, ip, StackTransmit, ctx, &ctx->stack_binding))
    {
        AbortUnstartedBringUp(*ctx, saved_count, worker_generation);
        return false;
    }
    ctx->stack_bound = true;

    if (!InitializeAndStart(*ctx) || !DriverOperationGateOpen(&ctx->operations))
    {
        AbortUnstartedBringUp(*ctx, saved_count, worker_generation);
        return false;
    }

    const auto worker = ::duetos::sched::SchedCreate(RxPollEntry, ctx, "pcnet-rx-poll");
    if (worker == nullptr)
    {
        AbortUnstartedBringUp(*ctx, saved_count, worker_generation);
        return false;
    }

    ctx->online = true;
    nic.link_up = true; // PCnet has no common, reliable v0 link-status CSR.
    nic.driver_online = true;
    nic.firmware_pending = false;
    nic.wireless_fw_state = NicInfo::WirelessFwState::NotApplicable;
    (void)stack::DhcpStart(iface_index);

    arch::SerialWrite("[pcnet] online iface=");
    arch::SerialWriteHex(iface_index);
    arch::SerialWrite(" io=");
    arch::SerialWriteHex(ctx->io);
    arch::SerialWrite(" pci=");
    arch::SerialWriteHex(nic.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(nic.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(nic.function);
    arch::SerialWrite(" mac=");
    for (u32 i = 0; i < 6; ++i)
    {
        if (i != 0)
            arch::SerialWrite(":");
        arch::SerialWriteHex(nic.mac[i]);
    }
    arch::SerialWrite(" mode=DWIO/SWSTYLE2/poll\n");
    return true;
}

bool PcnetQuiesceAll()
{
    bool all_quiesced = true;
    for (u32 i = 0; i < g_pcnet_count; ++i)
    {
        if (!QuiesceOne(g_pcnet[i]))
            all_quiesced = false;
    }
    if (all_quiesced)
        g_pcnet_count = 0;
    return all_quiesced;
}

} // namespace duetos::drivers::net
