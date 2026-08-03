#include "drivers/virtio/virtio_net.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/net/wireless_watch.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

/*
 * Restart-safe virtio-net v0. One stable context owns the queue memory,
 * exact stack receipt, operation admission, and polling worker generation.
 * The transport has no detach callback, so VirtioNetQuiesce is the truthful
 * explicit boundary for orderly shutdown/re-probe; surprise removal remains
 * a documented gap in virtio_net.h.
 */

namespace duetos::drivers::virtio
{

inline constexpr u64 kNetFeatureMac = 1ULL << 5;
inline constexpr u64 kNetFeatureStatus = 1ULL << 16;

namespace
{

namespace driver_lifetime = ::duetos::drivers::net;
namespace stack = ::duetos::net;
namespace contract = ::duetos::drivers::virtio::virtio_net_contract;

constexpr u64 kDeviceStatusOffset = 0x14;
constexpr u64 kDeviceFeatureSelectOffset = 0x00;
constexpr u64 kDeviceFeatureOffset = 0x04;
constexpr u64 kNumQueuesOffset = 0x12;
constexpr u64 kNetStatusOffset = 0x06;
constexpr u16 kNetStatusLinkUp = 1u << 0;
constexpr u8 kPciCapabilityVirtio = 0x09;
constexpr u8 kVirtioCfgCommon = 1;
constexpr u8 kVirtioCfgNotify = 2;
constexpr u8 kVirtioCfgIsr = 3;
constexpr u8 kVirtioCfgDevice = 4;
constexpr u8 kPciCapabilitiesPointer = 0x34;
constexpr u16 kPciStatusCapabilitiesList = 1u << 4;
constexpr u8 kPciCommandOffset = 0x04;
constexpr u16 kPciCommandBusMaster = 1u << 2;
constexpr u32 kInvalidInterface = ~u32(0);
constexpr u32 kRxBuffersPerFrame = static_cast<u32>(mm::kPageSize / contract::kRxBufferBytes);
static_assert(kRxBuffersPerFrame != 0);
static_assert(contract::kRxSlots % kRxBuffersPerFrame == 0);
constexpr u32 kRxFrames = contract::kRxSlots / kRxBuffersPerFrame;
constexpr u32 kRxPollSleepTicks = 1;
constexpr u32 kRxPollBudget = 16;
constexpr u64 kInterruptEnable = 1ULL << 9;

enum class LifecyclePhase : u8
{
    Idle,
    Starting,
    Running,
    Stopping,
    Quarantined,
};

struct NetState
{
    // Stable synchronization domains: never aggregate-overwrite these.
    driver_lifetime::DriverOperationGate operations;
    driver_lifetime::DriverWorkerLease rx_worker;
    sync::SpinLock lifecycle_lock;
    sync::SpinLock tx_lock;

    LifecyclePhase phase;
    // The PCI fabric and MMIO arena are boot-epoch lifetime today. Keep an
    // immutable transport receipt across network-domain restarts; every
    // activation revalidates its BDF and capability/BAR fingerprint before
    // dereferencing these retained pointers.
    VirtioPciLayout layout;
    contract::TransportFingerprint transport_fingerprint;
    u16 pci_command_safe;
    bool transport_staged;
    VirtioQueue txq;
    VirtioQueue rxq;
    stack::NetInterfaceBinding stack_binding;
    bool stack_bound;
    bool dma_armed;
    bool dma_published;
    bool device_faulted;
    u32 iface_index;
    VirtioNetActivation activation;
    u8 mac[6];
    mm::PhysAddr header_phys;
    u8* header_virt;
    mm::PhysAddr tx_buffer_phys;
    u8* tx_buffer_virt;
    mm::PhysAddr rx_frame_phys[kRxFrames];
    mm::PhysAddr rx_buffer_phys[contract::kRxSlots];
    u8* rx_buffer_virt[contract::kRxSlots];
};

constinit NetState g_net = {
    .operations = {},
    .rx_worker = {},
    .lifecycle_lock = {.next_ticket = 0,
                       .now_serving = 0,
                       .owner_cpu = 0xFFFFFFFFu,
                       .class_id = sync::kLockClassUnclassified},
    .tx_lock = {.next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified},
    .phase = LifecyclePhase::Idle,
    .layout = {},
    .transport_fingerprint = {},
    .pci_command_safe = 0,
    .transport_staged = false,
    .txq = {},
    .rxq = {},
    .stack_binding = stack::kInvalidNetInterfaceBinding,
    .stack_bound = false,
    .dma_armed = false,
    .dma_published = false,
    .device_faulted = false,
    .iface_index = kInvalidInterface,
    .activation = {},
    .mac = {},
    .header_phys = mm::kNullFrame,
    .header_virt = nullptr,
    .tx_buffer_phys = mm::kNullFrame,
    .tx_buffer_virt = nullptr,
    .rx_frame_phys = {},
    .rx_buffer_phys = {},
    .rx_buffer_virt = {},
};

bool WritePciCommand(pci::DeviceAddress address, u16 safe_command, bool bus_master_enabled)
{
    const u16 desired = bus_master_enabled ? static_cast<u16>(safe_command | kPciCommandBusMaster)
                                           : static_cast<u16>(safe_command & ~kPciCommandBusMaster);
    // PCI Status shares this dword and contains W1C bits. Never echo the
    // sampled upper half while changing Command.
    pci::PciConfigWrite32(address, kPciCommandOffset, static_cast<u32>(desired));
    return pci::PciConfigRead16(address, kPciCommandOffset) == desired;
}

bool ReadCapabilityFingerprint(pci::DeviceAddress address, u8 capability_offset, u8 capability_length, u8 bir,
                               u32 offset, u32 length, contract::CapabilityFingerprint* out)
{
    if (out == nullptr || bir >= 6 || length == 0)
        return false;
    const pci::Bar bar = pci::PciReadBar(address, bir);
    if (bar.size == 0 || bar.is_io || static_cast<u64>(offset) + static_cast<u64>(length) > bar.size)
        return false;
    *out = {
        .bar_address = bar.address,
        .bar_size = bar.size,
        .physical = bar.address + offset,
        .offset = offset,
        .length = length,
        .bir = bir,
        .capability_offset = capability_offset,
        .capability_length = capability_length,
        .present = true,
        .bar_is_64bit = bar.is_64bit,
        .bar_is_prefetchable = bar.is_prefetchable,
    };
    return true;
}

bool ReadTransportFingerprint(pci::DeviceAddress address, contract::TransportFingerprint* out)
{
    if (out == nullptr || address.device >= 32 || address.function >= 8)
        return false;

    contract::TransportFingerprint fingerprint{};
    fingerprint.address = address;
    fingerprint.address._pad = 0;
    fingerprint.vendor_device = pci::PciConfigRead32(address, 0x00);
    fingerprint.class_revision = pci::PciConfigRead32(address, 0x08);
    fingerprint.subsystem = pci::PciConfigRead32(address, 0x2C);
    const u32 expected_vendor_device =
        static_cast<u32>(kVirtioVendorId) | (static_cast<u32>(VirtioModernDeviceId(VirtioClass::kNetwork)) << 16);
    if (fingerprint.vendor_device != expected_vendor_device || (fingerprint.class_revision >> 24) != 0x02 ||
        (pci::PciConfigRead16(address, 0x06) & kPciStatusCapabilitiesList) == 0)
        return false;

    u8 cursor = static_cast<u8>(pci::PciConfigRead8(address, kPciCapabilitiesPointer) & 0xFCu);
    for (u32 hops = 0; hops < 48 && cursor != 0; ++hops)
    {
        if (cursor < 0x40 || cursor > 0xF0)
            return false;
        const u8 id = pci::PciConfigRead8(address, cursor);
        const u8 next = static_cast<u8>(pci::PciConfigRead8(address, static_cast<u8>(cursor + 1)) & 0xFCu);
        if (id == kPciCapabilityVirtio)
        {
            const u8 cap_length = pci::PciConfigRead8(address, static_cast<u8>(cursor + 2));
            const u8 cfg_type = pci::PciConfigRead8(address, static_cast<u8>(cursor + 3));
            if (cap_length < 16)
                return false;
            const u8 bir = pci::PciConfigRead8(address, static_cast<u8>(cursor + 4));
            const u32 offset = pci::PciConfigRead32(address, static_cast<u8>(cursor + 8));
            const u32 length = pci::PciConfigRead32(address, static_cast<u8>(cursor + 12));
            contract::CapabilityFingerprint capability{};
            if (!ReadCapabilityFingerprint(address, cursor, cap_length, bir, offset, length, &capability))
                return false;
            switch (cfg_type)
            {
            case kVirtioCfgCommon:
                fingerprint.common = capability;
                break;
            case kVirtioCfgNotify:
                if (cap_length < 20 || cursor > 0xEC)
                    return false;
                fingerprint.notify = capability;
                fingerprint.notify_off_multiplier = pci::PciConfigRead32(address, static_cast<u8>(cursor + 16));
                break;
            case kVirtioCfgIsr:
                fingerprint.isr = capability;
                break;
            case kVirtioCfgDevice:
                fingerprint.device = capability;
                break;
            default:
                break;
            }
        }
        if (next == cursor)
            return false;
        cursor = next;
    }

    if (cursor != 0 || !fingerprint.common.present || fingerprint.common.length < 0x38 || !fingerprint.notify.present ||
        fingerprint.notify.length < sizeof(u16) || fingerprint.notify_off_multiplier == 0)
        return false;
    *out = fingerprint;
    return true;
}

bool FingerprintMatchesLayout(const contract::TransportFingerprint& fingerprint, const VirtioPciLayout& layout)
{
    if (!contract::SameDeviceAddress(fingerprint.address, layout.addr) || !layout.present ||
        layout.cls != VirtioClass::kNetwork || layout.common_cfg == nullptr || layout.notify == nullptr ||
        fingerprint.common.physical != layout.common_cfg_phys || fingerprint.notify.physical != layout.notify_phys ||
        fingerprint.notify_off_multiplier != layout.notify_off_multiplier)
        return false;
    const bool isr_matches = fingerprint.isr.present == (layout.isr != nullptr) &&
                             (!fingerprint.isr.present || fingerprint.isr.physical == layout.isr_phys);
    const bool device_matches = fingerprint.device.present == (layout.device_cfg != nullptr) &&
                                (!fingerprint.device.present || fingerprint.device.physical == layout.device_cfg_phys);
    return isr_matches && device_matches;
}

enum class StartDisposition : u8
{
    Begin,
    AlreadyRunning,
    Reject,
};

StartDisposition TryBeginStart(NetState& state, pci::DeviceAddress expected_address, u32 iface_index,
                               VirtioNetActivation* out_activation)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(state.lifecycle_lock);
    StartDisposition disposition = StartDisposition::Reject;
    if (state.phase == LifecyclePhase::Idle && state.transport_staged &&
        contract::SameDeviceAddress(state.transport_fingerprint.address, expected_address))
    {
        state.phase = LifecyclePhase::Starting;
        disposition = StartDisposition::Begin;
    }
    else if (state.phase == LifecyclePhase::Running && state.transport_staged && state.iface_index == iface_index &&
             contract::SameDeviceAddress(state.transport_fingerprint.address, expected_address) &&
             !state.device_faulted && state.stack_bound && state.dma_published &&
             driver_lifetime::DriverOperationGateIsOpen(&state.operations))
    {
        *out_activation = state.activation;
        disposition = StartDisposition::AlreadyRunning;
    }
    sync::SpinLockRelease(state.lifecycle_lock, flags);
    return disposition;
}

bool TryBeginStop(NetState& state, bool* already_idle)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(state.lifecycle_lock);
    *already_idle = state.phase == LifecyclePhase::Idle;
    const bool allowed = state.phase == LifecyclePhase::Running || state.phase == LifecyclePhase::Quarantined;
    if (allowed)
        state.phase = LifecyclePhase::Stopping;
    sync::SpinLockRelease(state.lifecycle_lock, flags);
    return allowed;
}

void SetPhase(NetState& state, LifecyclePhase phase)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(state.lifecycle_lock);
    state.phase = phase;
    sync::SpinLockRelease(state.lifecycle_lock, flags);
}

bool CompleteStart(NetState& state)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(state.lifecycle_lock);
    const bool complete = state.phase == LifecyclePhase::Starting && !state.device_faulted && state.stack_bound &&
                          state.dma_published && driver_lifetime::DriverOperationGateIsOpen(&state.operations);
    if (complete)
        state.phase = LifecyclePhase::Running;
    sync::SpinLockRelease(state.lifecycle_lock, flags);
    return complete;
}

void ClearRuntimeFields(NetState& state)
{
    KASSERT(!driver_lifetime::DriverOperationGateIsOpen(&state.operations), "drivers/virtio/net",
            "clear with operation admission open");
    KASSERT(driver_lifetime::DriverOperationGatePinCount(&state.operations) == 0, "drivers/virtio/net",
            "clear with live operation pins");
    KASSERT(driver_lifetime::DriverWorkerLeaseActiveGeneration(&state.rx_worker) == 0, "drivers/virtio/net",
            "clear with live worker generation");
    KASSERT(!state.dma_armed && !state.dma_published, "drivers/virtio/net", "clear before DMA stop proof");

    state.txq = {};
    state.rxq = {};
    state.stack_binding = stack::kInvalidNetInterfaceBinding;
    state.stack_bound = false;
    state.device_faulted = false;
    state.iface_index = kInvalidInterface;
    state.activation = {};
    for (u32 i = 0; i < 6; ++i)
        state.mac[i] = 0;
    state.header_phys = mm::kNullFrame;
    state.header_virt = nullptr;
    state.tx_buffer_phys = mm::kNullFrame;
    state.tx_buffer_virt = nullptr;
    for (u32 i = 0; i < kRxFrames; ++i)
        state.rx_frame_phys[i] = mm::kNullFrame;
    for (u32 i = 0; i < contract::kRxSlots; ++i)
    {
        state.rx_buffer_phys[i] = mm::kNullFrame;
        state.rx_buffer_virt[i] = nullptr;
    }
}

bool SetBusMaster(NetState& state, bool enabled)
{
    return state.transport_staged && WritePciCommand(state.layout.addr, state.pci_command_safe, enabled);
}

u8 ReadDeviceStatus(const NetState& state)
{
    if (state.layout.common_cfg == nullptr)
        return 0xFF;
    return *reinterpret_cast<volatile u8*>(state.layout.common_cfg + kDeviceStatusOffset);
}

void WriteDeviceStatus(NetState& state, u8 status)
{
    *reinterpret_cast<volatile u8*>(state.layout.common_cfg + kDeviceStatusOffset) = status;
}

bool ResetDevice(NetState& state)
{
    if (state.layout.common_cfg == nullptr)
        return false;
    WriteDeviceStatus(state, 0);
    for (u32 tries = 0; tries < 10000; ++tries)
    {
        if (ReadDeviceStatus(state) == 0)
            return true;
        asm volatile("pause" ::: "memory");
    }
    return false;
}

bool PrepareDevice(NetState& state)
{
    if (!state.transport_staged || !state.layout.present || state.layout.common_cfg == nullptr ||
        state.layout.notify == nullptr || state.layout.cls != VirtioClass::kNetwork)
        return false;
    // Queue addresses are configured with BME off. Only the final datapath
    // publication enables bus mastering, immediately before DRIVER_OK.
    if (!SetBusMaster(state, false) || !ResetDevice(state))
        return false;
    WriteDeviceStatus(state, kStatusAck);
    WriteDeviceStatus(state, kStatusAck | kStatusDriver);
    if (ReadDeviceStatus(state) != (kStatusAck | kStatusDriver))
        return false;
    *reinterpret_cast<volatile u32*>(state.layout.common_cfg + kDeviceFeatureSelectOffset) = 0;
    state.layout.device_features_lo = *reinterpret_cast<volatile u32*>(state.layout.common_cfg + kDeviceFeatureOffset);
    *reinterpret_cast<volatile u32*>(state.layout.common_cfg + kDeviceFeatureSelectOffset) = 1;
    state.layout.device_features_hi = *reinterpret_cast<volatile u32*>(state.layout.common_cfg + kDeviceFeatureOffset);
    state.layout.num_queues = *reinterpret_cast<volatile u16*>(state.layout.common_cfg + kNumQueuesOffset);
    return true;
}

void FreeQueueFrames(VirtioQueue& queue)
{
    if (queue.desc_phys != mm::kNullFrame)
        mm::FreeFrame(queue.desc_phys);
    if (queue.avail_phys != mm::kNullFrame)
        mm::FreeFrame(queue.avail_phys);
    if (queue.used_phys != mm::kNullFrame)
        mm::FreeFrame(queue.used_phys);
    queue = {};
}

void FreeDmaStorage(NetState& state)
{
    KASSERT(!state.dma_published, "drivers/virtio/net", "free while device can DMA");
    if (!state.dma_armed)
        return;

    FreeQueueFrames(state.txq);
    FreeQueueFrames(state.rxq);
    if (state.header_phys != mm::kNullFrame)
        mm::FreeFrame(state.header_phys);
    if (state.tx_buffer_phys != mm::kNullFrame)
        mm::FreeFrame(state.tx_buffer_phys);
    for (u32 i = 0; i < kRxFrames; ++i)
    {
        if (state.rx_frame_phys[i] != mm::kNullFrame)
            mm::FreeFrame(state.rx_frame_phys[i]);
    }
    state.dma_armed = false;
}

bool AllocatePacketBuffers(NetState& state)
{
    auto header = mm::AllocateFrame();
    if (!header)
        return false;
    state.header_phys = header.value();
    state.header_virt = static_cast<u8*>(mm::PhysToVirt(state.header_phys));
    *reinterpret_cast<contract::NetHeader*>(state.header_virt) = {};

    auto tx = mm::AllocateFrame();
    if (!tx)
        return false;
    state.tx_buffer_phys = tx.value();
    state.tx_buffer_virt = static_cast<u8*>(mm::PhysToVirt(state.tx_buffer_phys));

    for (u32 frame = 0; frame < kRxFrames; ++frame)
    {
        auto allocated = mm::AllocateFrame();
        if (!allocated)
            return false;
        state.rx_frame_phys[frame] = allocated.value();
        u8* const base = static_cast<u8*>(mm::PhysToVirt(allocated.value()));
        for (u32 offset = 0; offset < kRxBuffersPerFrame; ++offset)
        {
            const u32 slot = frame * kRxBuffersPerFrame + offset;
            state.rx_buffer_phys[slot] = allocated.value() + offset * contract::kRxBufferBytes;
            state.rx_buffer_virt[slot] = base + offset * contract::kRxBufferBytes;
        }
    }
    return true;
}

bool DeviceFaulted(NetState& state)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(state.lifecycle_lock);
    const bool faulted = state.device_faulted;
    sync::SpinLockRelease(state.lifecycle_lock, flags);
    return faulted;
}

void MarkDeviceFaulted(NetState& state)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(state.lifecycle_lock);
    state.device_faulted = true;
    if (state.phase == LifecyclePhase::Running || state.phase == LifecyclePhase::Starting)
        state.phase = LifecyclePhase::Quarantined;
    sync::SpinLockRelease(state.lifecycle_lock, flags);
}

bool MacIsUsable(const u8* mac)
{
    if (mac == nullptr || (mac[0] & 1u) != 0)
        return false;
    bool all_zero = true;
    bool all_ones = true;
    for (u32 i = 0; i < 6; ++i)
    {
        all_zero = all_zero && mac[i] == 0;
        all_ones = all_ones && mac[i] == 0xFF;
    }
    return !all_zero && !all_ones;
}

void GenerateLocalMac(pci::DeviceAddress address, u8* mac)
{
    mac[0] = 0x02; // locally administered, unicast
    mac[1] = 0x1A;
    mac[2] = 0xF4;
    mac[3] = address.bus;
    mac[4] = static_cast<u8>((address.device << 3) | address.function);
    mac[5] = 0x01;
}

bool ReadActivation(NetState& state, u64 negotiated_features, VirtioNetActivation* activation)
{
    if (activation == nullptr)
        return false;
    *activation = {};
    activation->link_up = true; // STATUS absent means link is assumed up by the specification.

    const bool read_mac = (negotiated_features & kNetFeatureMac) != 0;
    const bool read_status = (negotiated_features & kNetFeatureStatus) != 0;
    if (read_mac || read_status)
    {
        if (state.layout.device_cfg == nullptr)
            return false;
        bool stable = false;
        for (u32 attempt = 0; attempt < 8 && !stable; ++attempt)
        {
            const u8 before = *reinterpret_cast<volatile u8*>(state.layout.common_cfg + 0x15);
            if (read_mac)
            {
                for (u32 i = 0; i < 6; ++i)
                    activation->mac[i] = state.layout.device_cfg[i];
            }
            if (read_status)
            {
                const u16 status = *reinterpret_cast<volatile u16*>(state.layout.device_cfg + kNetStatusOffset);
                activation->link_up = (status & kNetStatusLinkUp) != 0;
            }
            asm volatile("mfence" ::: "memory");
            const u8 after = *reinterpret_cast<volatile u8*>(state.layout.common_cfg + 0x15);
            stable = before == after;
        }
        if (!stable)
            return false;
    }
    if (!read_mac || !MacIsUsable(activation->mac))
        GenerateLocalMac(state.layout.addr, activation->mac);
    activation->mac_valid = MacIsUsable(activation->mac);
    return activation->mac_valid;
}

void PostRxDescriptor(NetState& state, u16 descriptor)
{
    VirtqDesc* const descriptors = const_cast<VirtqDesc*>(state.rxq.desc);
    descriptors[descriptor].addr = state.rx_buffer_phys[descriptor];
    descriptors[descriptor].len = contract::kRxBufferBytes;
    descriptors[descriptor].flags = kVirtqDescWrite;
    descriptors[descriptor].next = 0;
    VirtioQueuePublish(&state.layout, &state.rxq, descriptor);
}

void ReleaseOperation(NetState& state)
{
    KASSERT(driver_lifetime::DriverOperationGateRelease(&state.operations), "drivers/virtio/net",
            "operation pin underflow");
}

bool SendFrame(NetState& state, const void* frame, u32 len)
{
    if (frame == nullptr || len == 0 || len > contract::kMaximumFrameBytes ||
        !driver_lifetime::DriverOperationGateTryAcquire(&state.operations))
        return false;

    const sync::IrqFlags flags = sync::SpinLockAcquire(state.tx_lock);
    bool completed = false;
    if (!DeviceFaulted(state) && state.dma_published && state.txq.up)
    {
        const u8* const source = static_cast<const u8*>(frame);
        for (u32 i = 0; i < len; ++i)
            state.tx_buffer_virt[i] = source[i];

        VirtqDesc* const descriptors = const_cast<VirtqDesc*>(state.txq.desc);
        descriptors[0].addr = state.header_phys;
        descriptors[0].len = sizeof(contract::NetHeader);
        descriptors[0].flags = kVirtqDescNext;
        descriptors[0].next = 1;
        descriptors[1].addr = state.tx_buffer_phys;
        descriptors[1].len = len;
        descriptors[1].flags = 0;
        descriptors[1].next = 0;
        VirtioQueuePublish(&state.layout, &state.txq, 0);

        for (u32 spin = 0; spin < 2000000; ++spin)
        {
            u32 head = 0;
            u32 used_bytes = 0;
            if (VirtioQueueTryPop(&state.txq, &head, &used_bytes))
            {
                completed = head == 0;
                break;
            }
            asm volatile("pause" ::: "memory");
        }
    }
    if (!completed)
    {
        MarkDeviceFaulted(state);
        (void)driver_lifetime::DriverOperationGateClose(&state.operations);
    }
    sync::SpinLockRelease(state.tx_lock, flags);
    ReleaseOperation(state);

    if (!completed)
        KLOG_WARN("drivers/virtio/net", "TX failed; device held for explicit quiesce");
    return completed;
}

bool StackTransmit(void* context, u32 iface_index, const void* frame, u64 len)
{
    auto* const state = static_cast<NetState*>(context);
    if (state == nullptr || iface_index != state->iface_index || len > contract::kMaximumFrameBytes)
        return false;
    return SendFrame(*state, frame, static_cast<u32>(len));
}

u32 DrainRx(NetState& state, u32 budget)
{
    if (!driver_lifetime::DriverOperationGateTryAcquire(&state.operations))
        return 0;

    u32 processed = 0;
    for (u32 checked = 0; checked < budget; ++checked)
    {
        u32 head = 0;
        u32 used_bytes = 0;
        if (!VirtioQueueTryPop(&state.rxq, &head, &used_bytes))
            break;
        ++processed;
        const contract::RxInspection inspection = contract::InspectRxCompletion(state.rxq.queue_size, head, used_bytes);
        if (inspection.close_admission)
        {
            MarkDeviceFaulted(state);
            (void)driver_lifetime::DriverOperationGateClose(&state.operations);
            break;
        }
        if (inspection.disposition == contract::RxDisposition::Deliver)
        {
            const auto* const header = reinterpret_cast<const contract::NetHeader*>(state.rx_buffer_virt[head]);
            // No checksum/GSO/mergeable-buffer feature is negotiated. Treat
            // nonzero offload metadata as a hostile device completion rather
            // than handing an incomplete frame to the shared stack.
            if (contract::HeaderIsSupported(*header))
            {
                // No driver lock is held across stack ingress.
                stack::NetStackInjectRx(state.stack_binding, state.rx_buffer_virt[head] + sizeof(contract::NetHeader),
                                        inspection.frame_bytes);
            }
        }
        PostRxDescriptor(state, static_cast<u16>(head));
    }
    ReleaseOperation(state);
    return processed;
}

void RxPollEntry(void* context)
{
    auto* const state = static_cast<NetState*>(context);
    if (state == nullptr)
        return;
    const u64 generation = driver_lifetime::DriverWorkerLeaseActiveGeneration(&state->rx_worker);
    if (generation == 0)
        return;

    while (driver_lifetime::DriverWorkerLeaseShouldRun(&state->rx_worker, generation))
    {
        const u32 processed = DrainRx(*state, kRxPollBudget);
        if (processed == kRxPollBudget)
            continue;
        if (!driver_lifetime::DriverWorkerLeaseShouldRun(&state->rx_worker, generation))
            break;
        sched::SchedSleepTicks(kRxPollSleepTicks);
    }
    (void)driver_lifetime::DriverWorkerLeaseAcknowledge(&state->rx_worker, generation);
}

bool WaitForJoins(NetState& state, u64 worker_generation)
{
    bool worker_joined = worker_generation == 0;
    bool operations_drained = false;
    for (u32 waited = 0; waited <= contract::kJoinBudgetTicks; ++waited)
    {
        worker_joined = worker_generation == 0 ||
                        driver_lifetime::DriverWorkerLeaseIsAcknowledged(&state.rx_worker, worker_generation);
        operations_drained = driver_lifetime::DriverOperationGatePinCount(&state.operations) == 0;
        if (worker_joined && operations_drained)
            return true;
        if (waited != contract::kJoinBudgetTicks)
            sched::SchedSleepTicks(1);
    }
    KLOG_ERROR_2V("drivers/virtio/net", "join timed out; DMA retained", "worker-joined", worker_joined ? 1 : 0,
                  "operation-pins", driver_lifetime::DriverOperationGatePinCount(&state.operations));
    return false;
}

bool UnbindStack(NetState& state)
{
    if (!state.stack_bound)
        return true;
    const stack::NetInterfaceUnbindResult result =
        stack::NetStackUnbindInterface(state.stack_binding, contract::kJoinBudgetTicks);
    if (result != stack::NetInterfaceUnbindResult::Unbound)
    {
        KLOG_ERROR_V("drivers/virtio/net", "exact stack binding did not drain", static_cast<u64>(result));
        return false;
    }
    state.stack_bound = false;
    state.stack_binding = stack::kInvalidNetInterfaceBinding;
    return true;
}

bool RetireUnstartedWorker(NetState& state, u64 generation)
{
    if (generation == 0)
        return true;
    return driver_lifetime::DriverWorkerLeaseRequestRetire(&state.rx_worker, generation) &&
           driver_lifetime::DriverWorkerLeaseAcknowledge(&state.rx_worker, generation);
}

contract::TeardownProof StopHardwareAndDisarm(NetState& state, bool joins_complete, bool stack_unbound)
{
    contract::TeardownProof proof{};
    proof.worker_joined = joins_complete;
    proof.operations_drained = driver_lifetime::DriverOperationGatePinCount(&state.operations) == 0;
    proof.stack_unbound = stack_unbound;
    // Polling is the only completion path, so joining the exact worker is the
    // interrupt-equivalent stop. Clear BME before the device reset, then
    // require both independent read-back proofs before releasing DMA.
    proof.bus_master_disabled = SetBusMaster(state, false);
    proof.device_reset = ResetDevice(state);
    if (proof.device_reset && proof.bus_master_disabled)
        state.dma_published = false;
    return proof;
}

bool AbortBringUp(NetState& state, u64 worker_generation)
{
    (void)driver_lifetime::DriverOperationGateClose(&state.operations);
    const bool worker_retired = RetireUnstartedWorker(state, worker_generation);
    const bool joined = worker_retired && WaitForJoins(state, worker_generation);
    const bool stack_unbound = joined && UnbindStack(state);
    const bool worker_released =
        stack_unbound &&
        (worker_generation == 0 || driver_lifetime::DriverWorkerLeaseRelease(&state.rx_worker, worker_generation));
    contract::TeardownProof proof{};
    proof.worker_joined = joined;
    proof.operations_drained = driver_lifetime::DriverOperationGatePinCount(&state.operations) == 0;
    proof.stack_unbound = stack_unbound;
    // Retain live hardware and all DMA if a pre-close stack callback receipt
    // has not drained. Reset/BME-off is legal only after every software owner
    // has joined and the exact binding is gone.
    if (worker_released)
        proof = StopHardwareAndDisarm(state, true, true);

    if (!worker_released || !contract::MayReleaseDma(proof))
    {
        SetPhase(state, LifecyclePhase::Quarantined);
        KLOG_ERROR("drivers/virtio/net", "bring-up rollback incomplete; context quarantined");
        return false;
    }
    FreeDmaStorage(state);
    ClearRuntimeFields(state);
    SetPhase(state, LifecyclePhase::Idle);
    return true;
}

bool QuiesceStartedContext(NetState& state)
{
    (void)driver_lifetime::DriverOperationGateClose(&state.operations);
    const u64 generation = driver_lifetime::DriverWorkerLeaseActiveGeneration(&state.rx_worker);
    if (generation != 0 && !driver_lifetime::DriverWorkerLeaseRequestRetire(&state.rx_worker, generation))
        return false;
    if (!WaitForJoins(state, generation))
        return false;
    if (!UnbindStack(state))
        return false;
    if (generation != 0 && !driver_lifetime::DriverWorkerLeaseRelease(&state.rx_worker, generation))
        return false;

    const contract::TeardownProof proof = StopHardwareAndDisarm(state, true, true);
    if (!contract::MayReleaseDma(proof))
    {
        KLOG_ERROR_2V("drivers/virtio/net", "DMA stop proof failed; context retained", "device-reset",
                      proof.device_reset ? 1 : 0, "bus-master-off", proof.bus_master_disabled ? 1 : 0);
        return false;
    }
    FreeDmaStorage(state);
    ClearRuntimeFields(state);
    return true;
}

} // namespace

bool VirtioNetProbe(const VirtioPciLayout& layout)
{
    if (!layout.present || layout.common_cfg == nullptr || layout.notify == nullptr ||
        layout.cls != VirtioClass::kNetwork)
        return false;

    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(g_net.lifecycle_lock);
        if (g_net.transport_staged)
        {
            const bool same = FingerprintMatchesLayout(g_net.transport_fingerprint, layout);
            sync::SpinLockRelease(g_net.lifecycle_lock, flags);
            return same;
        }
        if (g_net.phase != LifecyclePhase::Idle)
        {
            sync::SpinLockRelease(g_net.lifecycle_lock, flags);
            return false;
        }
        g_net.phase = LifecyclePhase::Starting;
        sync::SpinLockRelease(g_net.lifecycle_lock, flags);
    }

    // VirtioPciProbe historically arrives with BME enabled. Remove it before
    // BAR sizing/fingerprinting and retain only a W1C-safe Command snapshot.
    const u16 safe_command =
        static_cast<u16>(pci::PciConfigRead16(layout.addr, kPciCommandOffset) & ~kPciCommandBusMaster);
    contract::TransportFingerprint fingerprint{};
    if (!WritePciCommand(layout.addr, safe_command, false) || !ReadTransportFingerprint(layout.addr, &fingerprint) ||
        !FingerprintMatchesLayout(fingerprint, layout))
    {
        SetPhase(g_net, LifecyclePhase::Idle);
        KLOG_ERROR("drivers/virtio/net", "transport staging fingerprint rejected");
        return false;
    }

    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(g_net.lifecycle_lock);
        g_net.layout = layout;
        g_net.transport_fingerprint = fingerprint;
        g_net.pci_command_safe = safe_command;
        g_net.transport_staged = true;
        sync::SpinLockRelease(g_net.lifecycle_lock, flags);
    }
    if (!ResetDevice(g_net) || !SetBusMaster(g_net, false))
    {
        SetPhase(g_net, LifecyclePhase::Quarantined);
        KLOG_ERROR("drivers/virtio/net", "staged transport did not reach reset+BME-off state");
        return false;
    }
    SetPhase(g_net, LifecyclePhase::Idle);
    KLOG_INFO("drivers/virtio/net", "transport staged for network-registry activation");
    return true;
}

bool VirtioNetRestart(pci::DeviceAddress expected_address, u32 iface_index, VirtioNetActivation* out_activation)
{
    if (out_activation == nullptr)
        return false;
    *out_activation = {};

    const StartDisposition disposition = TryBeginStart(g_net, expected_address, iface_index, out_activation);
    if (disposition == StartDisposition::AlreadyRunning)
        return true;
    if (disposition != StartDisposition::Begin)
        return false;

    ClearRuntimeFields(g_net);
    g_net.iface_index = iface_index;

    // First use only PCI config space to clear current BME. Only after the
    // complete capability/BAR fingerprint matches do we trust retained MMIO.
    const u32 vendor_device = pci::PciConfigRead32(expected_address, 0x00);
    const u32 class_revision = pci::PciConfigRead32(expected_address, 0x08);
    const u32 expected_vendor_device =
        static_cast<u32>(kVirtioVendorId) | (static_cast<u32>(VirtioModernDeviceId(VirtioClass::kNetwork)) << 16);
    if (vendor_device != expected_vendor_device || (class_revision >> 24) != 0x02)
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(g_net.lifecycle_lock);
        g_net.transport_staged = false;
        g_net.layout = {};
        g_net.transport_fingerprint = {};
        g_net.pci_command_safe = 0;
        g_net.phase = LifecyclePhase::Idle;
        sync::SpinLockRelease(g_net.lifecycle_lock, flags);
        KLOG_ERROR("drivers/virtio/net", "staged BDF identity disappeared");
        return false;
    }
    const u16 current_safe =
        static_cast<u16>(pci::PciConfigRead16(expected_address, kPciCommandOffset) & ~kPciCommandBusMaster);
    if (!WritePciCommand(expected_address, current_safe, false))
    {
        // The exact function is still present, but we failed to prove BME is
        // off. Retain the staged transport and force shutdown through the
        // reset/readback proof instead of letting Idle skip disarm entirely.
        SetPhase(g_net, LifecyclePhase::Quarantined);
        return false;
    }
    contract::TransportFingerprint current_fingerprint{};
    if (!ReadTransportFingerprint(expected_address, &current_fingerprint) ||
        !contract::SameTransport(g_net.transport_fingerprint, current_fingerprint))
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(g_net.lifecycle_lock);
        g_net.transport_staged = false;
        g_net.layout = {};
        g_net.transport_fingerprint = {};
        g_net.pci_command_safe = 0;
        g_net.phase = LifecyclePhase::Idle;
        sync::SpinLockRelease(g_net.lifecycle_lock, flags);
        KLOG_ERROR("drivers/virtio/net", "staged capability/BAR fingerprint changed");
        return false;
    }
    // The exact function/capability receipt still matches, so adopt current
    // non-BME Command bits instead of replaying a staging-era snapshot over
    // legitimate same-device changes made by another transport facility.
    g_net.pci_command_safe = current_safe;
    if (!PrepareDevice(g_net))
    {
        (void)AbortBringUp(g_net, 0);
        return false;
    }

    const u64 device_features =
        (static_cast<u64>(g_net.layout.device_features_hi) << 32) | static_cast<u64>(g_net.layout.device_features_lo);
    u64 optional_features = 0;
    if (g_net.transport_fingerprint.device.present && g_net.transport_fingerprint.device.length >= 6)
        optional_features |= kNetFeatureMac;
    if (g_net.transport_fingerprint.device.present && g_net.transport_fingerprint.device.length >= 8)
        optional_features |= kNetFeatureStatus;
    const u64 wanted_features = kFeatureVersion1 | (device_features & optional_features);
    if (!VirtioNegotiate(&g_net.layout, wanted_features) || g_net.layout.num_queues < 2)
    {
        KLOG_WARN("drivers/virtio/net", "feature negotiation or queue count rejected");
        (void)AbortBringUp(g_net, 0);
        return false;
    }

    // Queue setup publishes physical addresses into device registers while
    // BME remains off. Every failure from here uses reset+BME-off rollback.
    g_net.dma_armed = true;
    if (!VirtioQueueSetup(&g_net.layout, &g_net.rxq, 0, contract::kRxSlots) ||
        !VirtioQueueSetup(&g_net.layout, &g_net.txq, 1, kVirtqDefaultSize) || g_net.txq.queue_size < 2 ||
        !AllocatePacketBuffers(g_net))
    {
        KLOG_WARN("drivers/virtio/net", "queue or packet-buffer allocation failed");
        (void)AbortBringUp(g_net, 0);
        return false;
    }
    const u64 rx_notify_bytes =
        static_cast<u64>(g_net.rxq.notify_off) * g_net.transport_fingerprint.notify_off_multiplier + sizeof(u16);
    const u64 tx_notify_bytes =
        static_cast<u64>(g_net.txq.notify_off) * g_net.transport_fingerprint.notify_off_multiplier + sizeof(u16);
    if (rx_notify_bytes > g_net.transport_fingerprint.notify.length ||
        tx_notify_bytes > g_net.transport_fingerprint.notify.length)
    {
        KLOG_ERROR("drivers/virtio/net", "queue notify offset escaped staged capability");
        (void)AbortBringUp(g_net, 0);
        return false;
    }

    VirtioNetActivation activation{};
    if (!ReadActivation(g_net, wanted_features, &activation))
    {
        (void)AbortBringUp(g_net, 0);
        return false;
    }
    for (u32 i = 0; i < 6; ++i)
        g_net.mac[i] = activation.mac[i];

    const u64 worker_generation = driver_lifetime::DriverWorkerLeasePrepare(&g_net.rx_worker);
    if (worker_generation == 0)
    {
        (void)AbortBringUp(g_net, 0);
        return false;
    }

    stack::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = activation.mac[i];
    const stack::Ipv4Address ip{{0, 0, 0, 0}};
    if (!stack::NetStackBindInterfaceOwned(iface_index, mac, ip, StackTransmit, &g_net, &g_net.stack_binding))
    {
        (void)AbortBringUp(g_net, worker_generation);
        return false;
    }
    g_net.stack_bound = true;

    // BME and DRIVER_OK are the only points after which the device may consume
    // queue addresses. Publish ownership first so any immediate failure takes
    // the reset+BME-off retention path.
    g_net.dma_published = true;
    if (!SetBusMaster(g_net, true))
    {
        (void)AbortBringUp(g_net, worker_generation);
        return false;
    }
    VirtioMarkDriverOk(&g_net.layout);
    if ((ReadDeviceStatus(g_net) & kStatusDriverOk) == 0)
    {
        (void)AbortBringUp(g_net, worker_generation);
        return false;
    }
    for (u16 descriptor = 0; descriptor < g_net.rxq.queue_size; ++descriptor)
        PostRxDescriptor(g_net, descriptor);

    g_net.activation = activation;
    if (!driver_lifetime::DriverOperationGateOpen(&g_net.operations))
    {
        (void)AbortBringUp(g_net, worker_generation);
        return false;
    }
    const auto worker = sched::SchedCreate(RxPollEntry, &g_net, "virtio-net-rx-poll");
    if (worker == nullptr)
    {
        (void)AbortBringUp(g_net, worker_generation);
        return false;
    }
    if (!CompleteStart(g_net))
    {
        if (!QuiesceStartedContext(g_net))
            SetPhase(g_net, LifecyclePhase::Quarantined);
        else
            SetPhase(g_net, LifecyclePhase::Idle);
        return false;
    }

    (void)stack::DhcpStart(iface_index);
    *out_activation = activation;
    u64 packed_mac = 0;
    for (u32 i = 0; i < 6; ++i)
        packed_mac = (packed_mac << 8) | activation.mac[i];
    KLOG_INFO_2V("drivers/virtio/net", "attached exact registry binding", "iface", iface_index, "mac", packed_mac);
    return true;
}

bool VirtioNetTransmit(const void* frame, u32 len)
{
    return SendFrame(g_net, frame, len);
}

bool VirtioNetQuiesce()
{
    if ((arch::ReadRflags() & kInterruptEnable) == 0)
    {
        KLOG_ERROR("drivers/virtio/net", "quiesce requires task context with interrupts enabled");
        return false;
    }
    bool already_idle = false;
    if (!TryBeginStop(g_net, &already_idle))
        return already_idle;
    if (!QuiesceStartedContext(g_net))
    {
        SetPhase(g_net, LifecyclePhase::Quarantined);
        return false;
    }
    SetPhase(g_net, LifecyclePhase::Idle);
    arch::SerialWrite("[virtio-net] quiesced: worker/stack joined, device reset, BME off\n");
    return true;
}

} // namespace duetos::drivers::virtio
