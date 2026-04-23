#include "xhci.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/result.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "usb.h"

namespace customos::drivers::usb::xhci
{

namespace
{

constexpr u32 kMaxControllers = 4;
constinit ControllerInfo g_controllers[kMaxControllers] = {};
constinit u32 g_controller_count = 0;
// File-scope "is Init live" flag so XhciShutdown can clear it and
// a subsequent XhciInit re-runs. Previously this was a function-
// static constinit bool that made Init idempotent; restartable
// drivers need the flag to be rewindable.
constinit bool g_init_done = false;

// xHCI capability-reg offsets (xHCI 1.2 §5.3).
constexpr u64 kCapHciVersion = 0x00; // u32 = caplen | (rsvd) | hciver
constexpr u64 kCapHcsParams1 = 0x04;
constexpr u64 kCapHcsParams2 = 0x08;
constexpr u64 kCapHccParams1 = 0x10;
constexpr u64 kCapDbOff = 0x14;
constexpr u64 kCapRtsOff = 0x18;

// Operational-reg offsets (relative to opbase = mmio + caplen).
constexpr u64 kOpUsbCmd = 0x00;
constexpr u64 kOpUsbSts = 0x04;
constexpr u64 kOpDnCtrl = 0x14;
constexpr u64 kOpCrcr = 0x18;   // u64
constexpr u64 kOpDcbaap = 0x30; // u64
constexpr u64 kOpConfig = 0x38;

// USBCMD bits.
constexpr u32 kCmdRunStop = 1u << 0;
constexpr u32 kCmdHcReset = 1u << 1;

// USBSTS bits.
constexpr u32 kStsHcHalted = 1u << 0;
constexpr u32 kStsCnr = 1u << 11;

// HCCPARAMS1 bits.
constexpr u32 kHccParams1Csz = 1u << 2; // context size: 0=32 B, 1=64 B

// TRB types (control field bits 15:10). xHCI 1.2 §6.4.
// kTrbTypeNormal / kTrbTypePortStatusChange aren't emitted or
// matched against by this slice but are real spec-defined types
// the next slice (HID transfers) will consume — keep them named.
[[maybe_unused]] constexpr u32 kTrbTypeNormal = 1;
constexpr u32 kTrbTypeSetupStage = 2;
constexpr u32 kTrbTypeDataStage = 3;
constexpr u32 kTrbTypeStatusStage = 4;
constexpr u32 kTrbTypeLink = 6;
constexpr u32 kTrbTypeEnableSlot = 9;
constexpr u32 kTrbTypeAddressDevice = 11;
constexpr u32 kTrbTypeNoOp = 23; // command-ring NoOp
constexpr u32 kTrbTypeTransferEvent = 32;
constexpr u32 kTrbTypeCmdCompletion = 33;
[[maybe_unused]] constexpr u32 kTrbTypePortStatusChange = 34;

// Setup Stage TRB control bits.
constexpr u32 kTrbCtlIdt = 1u << 6; // Immediate Data (setup packet is inline)
constexpr u32 kTrbCtlIoc = 1u << 5; // Interrupt On Completion
// "Transfer Type" field in Setup/Status Stage control bits 17:16.
// Only In-Data is emitted this slice; the other three are kept
// named for the Config-descriptor / SET_CONFIGURATION slice.
[[maybe_unused]] constexpr u32 kTransferTypeNoData = 0;
[[maybe_unused]] constexpr u32 kTransferTypeReservedBulk = 1; // invalid for control
[[maybe_unused]] constexpr u32 kTransferTypeOutData = 2;
constexpr u32 kTransferTypeInData = 3;
// Data/Status Stage "DIR" bit is bit 16 (1 = IN, 0 = OUT).
constexpr u32 kTrbCtlDirIn = 1u << 16;

// USB standard setup packet fields.
constexpr u8 kUsbReqGetDescriptor = 0x06;
constexpr u16 kUsbDescriptorDevice = 0x0100; // type=1, index=0
constexpr u32 kDeviceDescriptorBytes = 18;

// PORTSC bit layout we care about.
constexpr u32 kPortScCcs = 1u << 0; // current-connect status (RO)
constexpr u32 kPortScPed = 1u << 1; // port enabled/disabled (RW1C)
constexpr u32 kPortScPr = 1u << 4;  // port reset (RW1S)

// PORTSC RW1C bits (PED + the 7 change bits at 17..23). When we
// modify PORTSC we mask these out of our writeback so a status-
// change bit that the controller has set doesn't get cleared as
// a side effect of "I just wanted to write PR=1".
constexpr u32 kPortScRw1cMask = (1u << 1) | (0x7Fu << 17);

// Command Completion event: status bits 31:24 carry a completion
// code; 1 = success. Bits 23:16 carry the slot ID for commands that
// allocate one (Enable Slot in particular).
constexpr u32 kCompletionCodeSuccess = 1;

// One TRB = 16 bytes: { u32 param_lo, u32 param_hi, u32 status, u32 control }.
struct alignas(16) Trb
{
    u32 param_lo;
    u32 param_hi;
    u32 status;
    u32 control;
};

// One ERST entry = 16 bytes: { u64 ring_phys, u32 ring_size, u32 rsvd }.
struct alignas(16) ErstEntry
{
    u64 ring_phys;
    u32 ring_size;
    u32 _rsvd;
};

// Per-controller submit/complete state. Lives in the stack frame of
// InitOne but gets passed by reference to the command / transfer
// helpers so they don't have to close over lambdas.
struct Runtime
{
    volatile u8* mmio;
    volatile u8* op;
    volatile u8* intr0;
    volatile u32* db_base; // &DB[0]; DB[n] is db_base + n

    Trb* cmd_ring;
    u64 cmd_phys;
    u32 cmd_slots;
    u32 cmd_idx;
    u32 cmd_cycle;

    Trb* evt_ring;
    u64 evt_phys;
    u32 evt_slots;
    u32 evt_idx;
    u32 evt_cycle;

    u64* dcbaa;    // kernel-virtual pointer to the DCBAA page
    u32 ctx_bytes; // 32 or 64, from HCCPARAMS1.CSZ
    u8 max_slots;  // for bounds
    ControllerInfo* info;
};

// Per-device state allocated at Address Device time. We only keep
// as many as fit in the fixed-size table below; extra ports beyond
// the cap silently skip enumeration. Tuned high enough to cover the
// kMaxXhciPortsPerController * kMaxControllers product so a real
// box with every port populated still fits.
constexpr u32 kMaxDevicesTotal = 32;

struct DeviceState
{
    bool in_use;
    u8 slot_id;
    u8 port_num;
    u8 speed;
    u8 ctrlr_idx; // index into g_controllers
    mm::PhysAddr device_ctx_phys;
    mm::PhysAddr input_ctx_phys;
    void* input_ctx_virt;
    mm::PhysAddr ep0_ring_phys;
    Trb* ep0_ring;
    u32 ep0_slots;
    u32 ep0_idx;
    u32 ep0_cycle;
    mm::PhysAddr scratch_phys;
    u8* scratch_virt;
};
constinit DeviceState g_devices[kMaxDevicesTotal] = {};
constinit u32 g_device_count = 0;

DeviceState* AllocDeviceSlot()
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        if (!g_devices[i].in_use)
        {
            g_devices[i] = {};
            g_devices[i].in_use = true;
            if (i >= g_device_count)
                g_device_count = i + 1;
            return &g_devices[i];
        }
    }
    return nullptr;
}

inline volatile u8* OpBase(const HostControllerInfo& h, u8 caplen)
{
    return static_cast<volatile u8*>(h.mmio_virt) + caplen;
}

inline u32 ReadMmio32(volatile u8* base, u64 offset)
{
    return *reinterpret_cast<volatile u32*>(base + offset);
}
inline void WriteMmio32(volatile u8* base, u64 offset, u32 value)
{
    *reinterpret_cast<volatile u32*>(base + offset) = value;
}
[[maybe_unused]] inline u64 ReadMmio64(volatile u8* base, u64 offset)
{
    return *reinterpret_cast<volatile u64*>(base + offset);
}
inline void WriteMmio64(volatile u8* base, u64 offset, u64 value)
{
    *reinterpret_cast<volatile u64*>(base + offset) = value;
}

// Allocate one zeroed 4 KiB frame; return both phys + kernel-virtual
// pointer. Returns false on out-of-memory.
bool AllocZeroPage(mm::PhysAddr* out_phys, void** out_virt)
{
    const mm::PhysAddr phys = mm::AllocateFrame();
    if (phys == mm::kNullFrame)
        return false;
    void* virt = mm::PhysToVirt(phys);
    if (virt == nullptr)
        return false;
    auto* p = static_cast<volatile u8*>(virt);
    for (u64 i = 0; i < mm::kPageSize; ++i)
        p[i] = 0;
    *out_phys = phys;
    *out_virt = virt;
    return true;
}

// Wait for a u32 MMIO register to satisfy `(value & mask) == match`.
// Returns true if the predicate held within `iters` polls. iters is
// a busy-loop count; tuned conservatively (1M ≈ tens of ms on QEMU)
// because we're called from boot context with the timer not yet
// running self-test logic that would care about the exact wall time.
bool PollUntil(volatile u8* base, u64 reg_off, u32 mask, u32 match, u64 iters)
{
    for (u64 i = 0; i < iters; ++i)
    {
        const u32 v = ReadMmio32(base, reg_off);
        if ((v & mask) == match)
            return true;
        // tight-spin: a `pause` reduces power + signals the CPU
        // we're in a wait loop.
        asm volatile("pause" : : : "memory");
    }
    return false;
}

// Doorbell write. xHCI DB[0] rings the command ring; DB[slot_id] rings
// a device's endpoints. `target` is the DB Target field (bits 0..7);
// stream_id is 0 for non-stream endpoints.
void RingDoorbell(Runtime& rt, u32 db_index, u32 target, u32 stream_id = 0)
{
    rt.db_base[db_index] = (stream_id << 16) | (target & 0xFF);
}

// Enqueue one TRB into a ring and return the physical address of the
// enqueued slot. Caller supplies the final value of the cycle bit
// IN LOWEST BIT of `control` (we OR in the producer cycle). The
// command ring has a trailing Link TRB so we reserve one slot. For
// v0 we never wrap — a boot session issues tens of commands / ctl
// transfers total — so ring-exhaustion logs and returns 0.
u64 EnqueueRingTrb(Trb* ring, u64 ring_phys, u32 slots, u32& idx, u32& cycle, u32 type, u32 param_lo, u32 param_hi,
                   u32 status, u32 extra_control)
{
    if (idx >= slots - 1)
    {
        arch::SerialWrite("[xhci] ring exhausted (link-TRB wrap not implemented for v0)\n");
        return 0;
    }
    Trb& slot = ring[idx];
    slot.param_lo = param_lo;
    slot.param_hi = param_hi;
    slot.status = status;
    slot.control = (type << 10) | (extra_control & ~1u) | (cycle & 1u);
    const u64 phys = ring_phys + u64(idx) * sizeof(Trb);
    ++idx;
    return phys;
}

u64 SubmitCmd(Runtime& rt, u32 type, u32 param_lo, u32 param_hi, u32 status, u32 extra_control)
{
    const u64 phys = EnqueueRingTrb(rt.cmd_ring, rt.cmd_phys, rt.cmd_slots, rt.cmd_idx, rt.cmd_cycle, type, param_lo,
                                    param_hi, status, extra_control);
    if (phys == 0)
        return 0;
    RingDoorbell(rt, 0, 0);
    return phys;
}

// Advance the consumer side of the event ring and push the updated
// dequeue pointer back to ERDP (with the "event handler busy" bit
// cleared — write 1 to clear per spec).
void AdvanceEventRing(Runtime& rt)
{
    ++rt.evt_idx;
    if (rt.evt_idx >= rt.evt_slots)
    {
        rt.evt_idx = 0;
        rt.evt_cycle ^= 1;
    }
    const u64 erdp = rt.evt_phys + u64(rt.evt_idx) * sizeof(Trb);
    WriteMmio64(rt.intr0, /*kIntrErdpLo=*/0x18, erdp | (1ull << 3));
}

// Drain events until one whose TRB pointer equals `expect_phys` and
// whose type matches `expect_type` lands in the consumer slot.
// Irrelevant events are consumed + dropped (port-status changes, etc.).
// `out` captures the matching TRB by value. Returns false on timeout.
bool WaitEvent(Runtime& rt, u64 expect_phys, u32 expect_type, Trb* out, u64 iters)
{
    for (u64 i = 0; i < iters; ++i)
    {
        const Trb& e = rt.evt_ring[rt.evt_idx];
        const bool valid = (e.control & 1u) == (rt.evt_cycle & 1u);
        if (!valid)
        {
            asm volatile("pause" : : : "memory");
            continue;
        }
        const u32 type = (e.control >> 10) & 0x3F;
        const u64 ptr = (u64(e.param_hi) << 32) | u64(e.param_lo);
        if (type == expect_type && ptr == expect_phys)
        {
            if (out != nullptr)
                *out = e;
            AdvanceEventRing(rt);
            return true;
        }
        // Non-matching event — drop it. A Port Status Change event
        // can land between an Enable Slot completion and the next
        // command; we don't care.
        AdvanceEventRing(rt);
    }
    return false;
}

bool WaitCmdCompletion(Runtime& rt, u64 expect_phys, u32* out_status, u8* out_slot_id)
{
    Trb e{};
    if (!WaitEvent(rt, expect_phys, kTrbTypeCmdCompletion, &e, 4'000'000))
        return false;
    if (out_status != nullptr)
        *out_status = e.status;
    if (out_slot_id != nullptr)
        *out_slot_id = u8((e.control >> 24) & 0xFF);
    return true;
}

// ---------------------------------------------------------------
// Device enumeration: Address Device + GET_DESCRIPTOR(Device).
// ---------------------------------------------------------------

// EP0 max-packet-size default derived from PORTSC-reported speed.
// Low/Full: 8. High: 64. Super+: 512. These are the values the xHCI
// spec recommends using in the Input Context before the device's
// actual descriptor is available — the controller will either
// accept them outright or ask us to re-submit with the corrected
// value (which we handle lazily in v0: if a device needs a
// different MPS0, the GET_DESCRIPTOR read of 18 bytes still works
// because MPS0 just bounds the per-packet payload).
u32 DefaultMaxPacketSize0(u8 speed)
{
    switch (speed)
    {
    case 4: // Super Speed
    case 5: // Super Speed+
        return 512;
    case 3: // High Speed
        return 64;
    default: // Low / Full / unknown
        return 8;
    }
}

// Build Input Context for Address Device. ctx_bytes is 32 or 64 per
// HCCPARAMS1.CSZ. Layout (indexes are 0-based in units of ctx_bytes):
//   [0] Input Control Context — A0|A1 set (add slot + EP0)
//   [1] Slot Context          — root-hub port, speed, ctx entries=1
//   [2] EP0 Endpoint Context  — EP type=Control, MPS, TR deq ptr
// EP2..31 stay zero (not being added).
void BuildAddressDeviceInputContext(void* input_ctx_virt, u32 ctx_bytes, u8 port_num, u8 speed, u32 mps0,
                                    u64 ep0_ring_phys)
{
    auto* base = static_cast<volatile u8*>(input_ctx_virt);
    // Zero the whole region we'll touch (control + slot + EP0 contexts).
    for (u32 i = 0; i < 3 * ctx_bytes; ++i)
        base[i] = 0;

    volatile u32* icc = reinterpret_cast<volatile u32*>(base + 0 * ctx_bytes);
    // D0 (drop) = 0, D1 = 0. A0 = add slot context, A1 = add EP0
    // context. xHCI 1.2 §6.2.5.1.
    icc[1] = (1u << 0) | (1u << 1);

    volatile u32* slot = reinterpret_cast<volatile u32*>(base + 1 * ctx_bytes);
    // DW0: route string (bits 0..19) = 0, speed (bits 20..23),
    // context entries (bits 27..31) = 1 (just EP0).
    slot[0] = (u32(speed) << 20) | (1u << 27);
    // DW1: root hub port number (bits 16..23).
    slot[1] = u32(port_num) << 16;

    volatile u32* ep0 = reinterpret_cast<volatile u32*>(base + 2 * ctx_bytes);
    // DW0: EP State (bits 0..2) = 0 (Disabled initial).
    ep0[0] = 0;
    // DW1: EP Type = 4 (Control) in bits 3..5. CErr (error count) =
    // 3 in bits 1..2. Max Packet Size in bits 16..31.
    ep0[1] = (3u << 1) | (4u << 3) | (mps0 << 16);
    // DW2/DW3: TR Dequeue Pointer (64-bit, bit 0 = Dequeue Cycle
    // State = 1 on first use).
    const u64 tr_dcs = ep0_ring_phys | 1ull;
    ep0[2] = u32(tr_dcs);
    ep0[3] = u32(tr_dcs >> 32);
    // DW4: Average TRB Length (bits 0..15) — we guess 8 for control
    // since every packet is an 8-byte setup packet or small status.
    ep0[4] = 8;
}

bool AddressDevice(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = AllocDeviceSlot();
    if (dev == nullptr)
    {
        arch::SerialWrite("[xhci]   device table full, skipping port ");
        arch::SerialWriteHex(port.port_num);
        arch::SerialWrite("\n");
        return false;
    }
    dev->slot_id = port.slot_id;
    dev->port_num = port.port_num;
    dev->speed = port.speed;

    // Device Context — sized ctx_bytes per entry, 32 entries, must
    // be 64-byte aligned. One 4 KiB page covers both 32B and 64B
    // contexts with room to spare.
    void* devctx_virt = nullptr;
    if (!AllocZeroPage(&dev->device_ctx_phys, &devctx_virt))
        return false;

    // Input Context — 1 control + 32 context slots.
    if (!AllocZeroPage(&dev->input_ctx_phys, &dev->input_ctx_virt))
        return false;

    // EP0 transfer ring — one page of Trb entries.
    void* ep0_virt = nullptr;
    if (!AllocZeroPage(&dev->ep0_ring_phys, &ep0_virt))
        return false;
    dev->ep0_ring = static_cast<Trb*>(ep0_virt);
    dev->ep0_slots = mm::kPageSize / sizeof(Trb);
    dev->ep0_idx = 0;
    dev->ep0_cycle = 1;
    // Install a trailing Link TRB so a future workload that fills
    // the ring doesn't crash — we don't expect to wrap during boot
    // but the structure should match spec.
    Trb& link = dev->ep0_ring[dev->ep0_slots - 1];
    link.param_lo = u32(dev->ep0_ring_phys);
    link.param_hi = u32(dev->ep0_ring_phys >> 32);
    link.status = 0;
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    // Scratch page for descriptor reads.
    void* scratch_virt = nullptr;
    if (!AllocZeroPage(&dev->scratch_phys, &scratch_virt))
        return false;
    dev->scratch_virt = static_cast<u8*>(scratch_virt);

    // Hand the device context to the controller via DCBAA[slot_id].
    rt.dcbaa[dev->slot_id] = dev->device_ctx_phys;

    // Build Input Context + submit Address Device.
    const u32 mps0 = DefaultMaxPacketSize0(dev->speed);
    BuildAddressDeviceInputContext(dev->input_ctx_virt, rt.ctx_bytes, dev->port_num, dev->speed, mps0,
                                   dev->ep0_ring_phys);

    // Address Device TRB: param = input_ctx_phys, control extra =
    // (slot_id << 24). BSR (Block Set Address Request) bit 9 is 0 —
    // we want the controller to both enable the slot AND issue the
    // SET_ADDRESS request in one shot.
    const u64 cmd_phys = SubmitCmd(rt, kTrbTypeAddressDevice, u32(dev->input_ctx_phys), u32(dev->input_ctx_phys >> 32),
                                   0, u32(dev->slot_id) << 24);
    if (cmd_phys == 0)
        return false;
    u32 status = 0;
    u8 slot_out = 0;
    if (!WaitCmdCompletion(rt, cmd_phys, &status, &slot_out))
    {
        arch::SerialWrite("[xhci]   Address Device timed out for slot ");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   Address Device failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    port.addressed = true;
    return true;
}

bool FetchDeviceDescriptor(Runtime& rt, PortRecord& port)
{
    // Find the DeviceState for this port — allocated by
    // AddressDevice, indexed by slot_id.
    DeviceState* dev = nullptr;
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        if (g_devices[i].in_use && g_devices[i].slot_id == port.slot_id)
        {
            dev = &g_devices[i];
            break;
        }
    }
    if (dev == nullptr)
        return false;

    // Zero the scratch bytes we'll compare against.
    for (u32 i = 0; i < kDeviceDescriptorBytes; ++i)
        dev->scratch_virt[i] = 0;

    // Three-TRB control transfer on EP0.
    //
    // Setup Stage — the 8-byte USB SETUP packet packed into the
    // TRB's first two u32 fields (IDT=1 means the data is
    // immediate, no buffer pointer needed):
    //   bmRequestType = 0x80   (Device-to-Host, Standard, Device)
    //   bRequest      = 0x06   (GET_DESCRIPTOR)
    //   wValue        = 0x0100 (Descriptor type 1 = Device, index 0)
    //   wIndex        = 0x0000
    //   wLength       = 18
    const u32 setup_lo = 0x80u | (u32(kUsbReqGetDescriptor) << 8) | (u32(kUsbDescriptorDevice) << 16);
    const u32 setup_hi = u32(kDeviceDescriptorBytes) << 16; // wIndex=0, wLength=18
    // Setup Stage status: interrupt target = 0, TRB transfer length = 8.
    const u32 setup_status = 8u;
    // Setup Stage control: type << 10 | Transfer Type | IDT.
    const u32 setup_ctl = (kTransferTypeInData << 16) | kTrbCtlIdt;
    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    // Data Stage — IN direction, points at the scratch page.
    const u32 data_ctl = kTrbCtlDirIn;
    const u64 data_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                         dev->ep0_cycle, kTrbTypeDataStage, u32(dev->scratch_phys),
                                         u32(dev->scratch_phys >> 32), kDeviceDescriptorBytes, data_ctl);
    (void)data_phys;

    // Status Stage — direction OPPOSITE of data (so OUT here) with
    // IOC set so the event ring reports completion. Param/Status
    // are zero. This is the TRB whose physical address we'll
    // match in the Transfer Event.
    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc);
    if (status_phys == 0)
        return false;

    // Ring the EP0 doorbell on this slot. DB target 1 = EP0
    // bidirectional control.
    RingDoorbell(rt, dev->slot_id, 1);

    // Wait for the Transfer Event whose pointer matches status_phys.
    Trb event{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &event, 4'000'000))
    {
        arch::SerialWrite("[xhci]   GET_DESCRIPTOR(Device) timed out for slot ");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 xfer_code = (event.status >> 24) & 0xFF;
    if (xfer_code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   GET_DESCRIPTOR(Device) failed code=");
        arch::SerialWriteHex(xfer_code);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }

    // Parse the 18-byte USB device descriptor.
    const u8* d = dev->scratch_virt;
    port.max_packet_size_0 = d[7];
    port.vendor_id = u16(d[8]) | (u16(d[9]) << 8);
    port.product_id = u16(d[10]) | (u16(d[11]) << 8);
    port.device_class = d[4];
    port.device_subclass = d[5];
    port.device_protocol = d[6];
    port.descriptor_ok = true;
    return true;
}

bool InitOne(const HostControllerInfo& h, ControllerInfo& out)
{
    out.bus = h.bus;
    out.device = h.device;
    out.function = h.function;
    out.init_ok = false;
    out.noop_ok = false;

    if (h.kind != HciKind::Xhci || h.mmio_virt == nullptr)
        return false;

    auto* mmio = static_cast<volatile u8*>(h.mmio_virt);
    const u32 cap_word = ReadMmio32(mmio, kCapHciVersion);
    const u8 caplen = u8(cap_word & 0xFF);
    if (caplen < 0x20)
    {
        arch::SerialWrite("[xhci] caplen below spec minimum, skipping\n");
        return false;
    }
    volatile u8* op = OpBase(h, caplen);

    // Spec §4.2: stop the controller before reset (RUN/STOP=0 then
    // wait for HCH=1), then HCRST=1 and wait for it to clear and
    // for CNR=0.
    u32 cmd = ReadMmio32(op, kOpUsbCmd);
    if (cmd & kCmdRunStop)
    {
        WriteMmio32(op, kOpUsbCmd, cmd & ~kCmdRunStop);
        if (!PollUntil(op, kOpUsbSts, kStsHcHalted, kStsHcHalted, 1'000'000))
        {
            arch::SerialWrite("[xhci] timed out waiting for HCH=1 before reset\n");
            return false;
        }
    }
    WriteMmio32(op, kOpUsbCmd, ReadMmio32(op, kOpUsbCmd) | kCmdHcReset);
    // After reset both HCRST and CNR must be 0.
    if (!PollUntil(op, kOpUsbCmd, kCmdHcReset, 0, 1'000'000))
    {
        arch::SerialWrite("[xhci] HCRST never cleared\n");
        return false;
    }
    if (!PollUntil(op, kOpUsbSts, kStsCnr, 0, 1'000'000))
    {
        arch::SerialWrite("[xhci] CNR never cleared after reset\n");
        return false;
    }

    // Cache geometry the spec requires before allocating data structures.
    const u32 hcs1 = ReadMmio32(mmio, kCapHcsParams1);
    const u32 hcs2 = ReadMmio32(mmio, kCapHcsParams2);
    out.max_slots = u8(hcs1 & 0xFF);
    out.max_intrs = u16((hcs1 >> 8) & 0x7FF);
    out.max_ports = u8((hcs1 >> 24) & 0xFF);
    const u32 sp_lo = (hcs2 >> 27) & 0x1F;
    const u32 sp_hi = (hcs2 >> 21) & 0x1F;
    out.max_scratchpad = (sp_hi << 5) | sp_lo;

    if (out.max_scratchpad != 0)
    {
        // QEMU q35 default doesn't ask for scratchpad; if a real
        // controller does, bail v0 (proper handling needs N more
        // pages + a pointer-array page).
        arch::SerialWrite("[xhci] controller requests scratchpad buffers — v0 doesn't allocate, skipping\n");
        return false;
    }
    if (out.max_slots == 0)
    {
        arch::SerialWrite("[xhci] controller reports max_slots=0, skipping\n");
        return false;
    }

    // Allocate DCBAA, command ring, event ring, ERST.
    mm::PhysAddr dcbaa_phys = 0;
    void* dcbaa_virt = nullptr;
    if (!AllocZeroPage(&dcbaa_phys, &dcbaa_virt))
        return false;
    mm::PhysAddr cmd_phys = 0;
    void* cmd_virt = nullptr;
    if (!AllocZeroPage(&cmd_phys, &cmd_virt))
        return false;
    mm::PhysAddr evt_phys = 0;
    void* evt_virt = nullptr;
    if (!AllocZeroPage(&evt_phys, &evt_virt))
        return false;
    mm::PhysAddr erst_phys = 0;
    void* erst_virt = nullptr;
    if (!AllocZeroPage(&erst_phys, &erst_virt))
        return false;

    out.dcbaa_phys = dcbaa_phys;
    out.cmd_ring_phys = cmd_phys;
    out.event_ring_phys = evt_phys;
    out.erst_phys = erst_phys;

    // Command ring: install a Link TRB at the last slot pointing
    // back to ring base, with Toggle Cycle = 1 so the controller
    // flips its own cycle bit when it wraps.
    auto* cmd_ring = static_cast<Trb*>(cmd_virt);
    constexpr u32 kRingSlots = mm::kPageSize / sizeof(Trb);
    Trb& link = cmd_ring[kRingSlots - 1];
    link.param_lo = u32(cmd_phys);
    link.param_hi = u32(cmd_phys >> 32);
    link.status = 0;
    // control = (TRB type << 10) | TC=1 (bit 1) | C=1 (bit 0).
    // We set the cycle bit so the link entry matches our initial
    // "producer cycle" state of 1.
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    // ERST entry 0 points at the event ring with size = ring slots.
    auto* erst = static_cast<ErstEntry*>(erst_virt);
    erst[0].ring_phys = evt_phys;
    erst[0].ring_size = kRingSlots;
    erst[0]._rsvd = 0;

    // Wire op-regs.
    // CONFIG.MaxSlotsEn = max_slots (cap-reported limit).
    WriteMmio32(op, kOpConfig, out.max_slots);
    // DCBAAP — physical base; alignment is 64 bytes, our page is
    // 4 KiB so safely aligned.
    WriteMmio64(op, kOpDcbaap, dcbaa_phys);
    // CRCR — command-ring base | bit 0 (Ring Cycle State = 1).
    // Other bits (Command Stop, Command Abort) start cleared.
    WriteMmio64(op, kOpCrcr, cmd_phys | 1u);
    // DNCTRL: enable bus-master notification for slot 0 only (default).
    WriteMmio32(op, kOpDnCtrl, 0x2);

    // Interrupter 0 lives in the runtime register set: rt_base =
    // mmio + RTSOFF; per-interrupter stride 32 B starting at +0x20.
    const u32 rtsoff = ReadMmio32(mmio, kCapRtsOff) & ~0x1Fu;
    volatile u8* intr0 = mmio + rtsoff + 0x20;
    constexpr u64 kIntrErstSz = 0x08;                    // u32
    constexpr u64 kIntrErstBaLo = 0x10;                  // u32 (low half of u64)
    [[maybe_unused]] constexpr u64 kIntrErstBaHi = 0x14; // high half; paired WriteMmio64 writes both
    constexpr u64 kIntrErdpLo = 0x18;                    // u64
    WriteMmio32(intr0, kIntrErstSz, 1);
    // ERDP must be written BEFORE ERSTBA per spec §4.9.4.
    WriteMmio64(intr0, kIntrErdpLo, evt_phys);
    WriteMmio64(intr0, kIntrErstBaLo, erst_phys);

    // Start the controller. RS=1, then wait for HCH=0.
    WriteMmio32(op, kOpUsbCmd, ReadMmio32(op, kOpUsbCmd) | kCmdRunStop);
    if (!PollUntil(op, kOpUsbSts, kStsHcHalted, 0, 1'000'000))
    {
        arch::SerialWrite("[xhci] HCH never cleared after RS=1\n");
        return false;
    }
    out.init_ok = true;

    // Pack the ring / doorbell / interrupter state into a Runtime
    // so helpers (SubmitCmd, WaitCmdCompletion, WaitEvent) don't
    // have to close over lambdas. Context-size bit governs whether
    // device / input contexts are 32 or 64 bytes per element.
    constexpr u32 kRingSlotsLocal = mm::kPageSize / sizeof(Trb);
    const u32 hcc1 = ReadMmio32(mmio, kCapHccParams1);
    const u32 dboff = ReadMmio32(mmio, kCapDbOff) & ~0x3u;

    Runtime rt{};
    rt.mmio = mmio;
    rt.op = op;
    rt.intr0 = intr0;
    rt.db_base = reinterpret_cast<volatile u32*>(mmio + dboff);
    rt.cmd_ring = cmd_ring;
    rt.cmd_phys = cmd_phys;
    rt.cmd_slots = kRingSlotsLocal;
    rt.cmd_idx = 0;
    rt.cmd_cycle = 1;
    rt.evt_ring = static_cast<Trb*>(evt_virt);
    rt.evt_phys = evt_phys;
    rt.evt_slots = kRingSlotsLocal;
    rt.evt_idx = 0;
    rt.evt_cycle = 1;
    rt.dcbaa = static_cast<u64*>(dcbaa_virt);
    rt.ctx_bytes = (hcc1 & kHccParams1Csz) ? 64 : 32;
    rt.max_slots = out.max_slots;
    rt.info = &out;
    out.context_bytes = rt.ctx_bytes;

    // NoOp roundtrip — proves the submit/complete plumbing works
    // before we issue commands that allocate state on the controller.
    {
        const u64 noop_phys = SubmitCmd(rt, kTrbTypeNoOp, 0, 0, 0, 0);
        u32 status = 0;
        u8 slot = 0;
        out.noop_ok = (noop_phys != 0) && WaitCmdCompletion(rt, noop_phys, &status, &slot);
    }

    arch::SerialWrite("[xhci] init pci=");
    arch::SerialWriteHex(h.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(h.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(h.function);
    arch::SerialWrite(" max_slots=");
    arch::SerialWriteHex(out.max_slots);
    arch::SerialWrite(" max_ports=");
    arch::SerialWriteHex(out.max_ports);
    arch::SerialWrite(" max_intrs=");
    arch::SerialWriteHex(out.max_intrs);
    arch::SerialWrite(" dcbaa=");
    arch::SerialWriteHex(out.dcbaa_phys);
    arch::SerialWrite(" cmd_ring=");
    arch::SerialWriteHex(out.cmd_ring_phys);
    arch::SerialWrite(" event_ring=");
    arch::SerialWriteHex(out.event_ring_phys);
    arch::SerialWrite("\n");
    arch::SerialWrite(out.noop_ok ? "[xhci] NoOp roundtrip PASS\n"
                                  : "[xhci] NoOp roundtrip FAIL — no Command Completion event\n");

    if (!out.noop_ok)
        return true;

    // Walk PORTSC for every port. Per-port PORTSC starts at
    // opbase + 0x400 + (port_idx * 0x10). For each port that
    // shows CCS=1: kick PR=1 if not already enabled, wait for
    // PED=1, then issue Enable Slot Command.
    out.ports_connected = 0;
    out.slots_enabled = 0;
    const u8 ports_to_scan = (out.max_ports < kMaxXhciPortsPerController) ? out.max_ports : kMaxXhciPortsPerController;
    for (u8 i = 0; i < ports_to_scan; ++i)
    {
        const u64 portsc_off = 0x400 + u64(i) * 0x10;
        u32 portsc = ReadMmio32(op, portsc_off);
        PortRecord& rec = out.ports[i];
        rec.port_num = u8(i + 1);
        rec.connected = (portsc & kPortScCcs) != 0;
        rec.portsc_at_scan = portsc;
        rec.speed = (portsc >> 10) & 0xF;
        if (!rec.connected)
            continue;
        ++out.ports_connected;

        // Reset only if PED is not already set. USB 3 ports usually
        // self-train and arrive with PED=1; USB 2 ports require PR=1.
        if ((portsc & kPortScPed) == 0)
        {
            const u32 wr = (portsc & ~kPortScRw1cMask) | kPortScPr;
            WriteMmio32(op, portsc_off, wr);
            // Wait for PR to clear (reset done) and PED to set.
            for (u64 j = 0; j < 1'000'000; ++j)
            {
                const u32 cur = ReadMmio32(op, portsc_off);
                if ((cur & kPortScPr) == 0 && (cur & kPortScPed) != 0)
                {
                    portsc = cur;
                    break;
                }
                asm volatile("pause" : : : "memory");
            }
        }
        rec.reset_ok = (ReadMmio32(op, portsc_off) & kPortScPed) != 0;
        if (!rec.reset_ok)
        {
            arch::SerialWrite("[xhci]   port ");
            arch::SerialWriteHex(rec.port_num);
            arch::SerialWrite(" connected but PED never set after reset\n");
            continue;
        }

        // Send Enable Slot Command. param_lo/hi/status all zero.
        const u64 cmd_p = SubmitCmd(rt, kTrbTypeEnableSlot, 0, 0, 0, 0);
        u32 cs = 0;
        u8 slot_id = 0;
        if (cmd_p != 0 && WaitCmdCompletion(rt, cmd_p, &cs, &slot_id))
        {
            const u32 code = (cs >> 24) & 0xFF;
            if (code == kCompletionCodeSuccess && slot_id != 0)
            {
                rec.slot_ok = true;
                rec.slot_id = slot_id;
                ++out.slots_enabled;
            }
            else
            {
                arch::SerialWrite("[xhci]   port ");
                arch::SerialWriteHex(rec.port_num);
                arch::SerialWrite(" Enable Slot completed with code=");
                arch::SerialWriteHex(code);
                arch::SerialWrite("\n");
            }
        }
        else
        {
            arch::SerialWrite("[xhci]   port ");
            arch::SerialWriteHex(rec.port_num);
            arch::SerialWrite(" Enable Slot timed out\n");
        }

        arch::SerialWrite("[xhci]   port ");
        arch::SerialWriteHex(rec.port_num);
        arch::SerialWrite(" connected speed=");
        arch::SerialWriteHex(rec.speed);
        arch::SerialWrite(rec.slot_ok ? " slot_id=" : " slot=fail");
        if (rec.slot_ok)
            arch::SerialWriteHex(rec.slot_id);
        arch::SerialWrite("\n");
    }
    arch::SerialWrite("[xhci] port scan: connected=");
    arch::SerialWriteHex(out.ports_connected);
    arch::SerialWrite(" slots_enabled=");
    arch::SerialWriteHex(out.slots_enabled);
    arch::SerialWrite("\n");

    // Enumerate every successfully-enabled slot: assign a USB
    // address, then read its 18-byte device descriptor. Each
    // success bumps the matching counter on ControllerInfo so the
    // boot log has a one-shot "devices online" signal.
    for (u8 i = 0; i < ports_to_scan; ++i)
    {
        PortRecord& rec = out.ports[i];
        if (!rec.slot_ok)
            continue;
        if (!AddressDevice(rt, rec))
            continue;
        ++out.devices_addressed;
        if (!FetchDeviceDescriptor(rt, rec))
            continue;
        ++out.descriptors_fetched;
        arch::SerialWrite("[xhci]   device port=");
        arch::SerialWriteHex(rec.port_num);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(rec.slot_id);
        arch::SerialWrite(" vid=");
        arch::SerialWriteHex(rec.vendor_id);
        arch::SerialWrite(" pid=");
        arch::SerialWriteHex(rec.product_id);
        arch::SerialWrite(" class=");
        arch::SerialWriteHex(rec.device_class);
        arch::SerialWrite("/");
        arch::SerialWriteHex(rec.device_subclass);
        arch::SerialWrite("/");
        arch::SerialWriteHex(rec.device_protocol);
        arch::SerialWrite(" mps0=");
        arch::SerialWriteHex(rec.max_packet_size_0);
        arch::SerialWrite("\n");
    }
    arch::SerialWrite("[xhci] enumeration: addressed=");
    arch::SerialWriteHex(out.devices_addressed);
    arch::SerialWrite(" descriptors=");
    arch::SerialWriteHex(out.descriptors_fetched);
    arch::SerialWrite("\n");

    return true;
}

} // namespace

void XhciInit()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci", "XhciInit");
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = HostControllerCount();
    for (u64 i = 0; i < n && g_controller_count < kMaxControllers; ++i)
    {
        const HostControllerInfo& h = HostController(i);
        if (h.kind != HciKind::Xhci)
            continue;
        ControllerInfo& slot = g_controllers[g_controller_count];
        if (InitOne(h, slot))
            ++g_controller_count;
    }
    if (g_controller_count == 0)
    {
        arch::SerialWrite("[xhci] no controllers brought up\n");
    }
    else
    {
        arch::SerialWrite("[xhci] controllers brought up: ");
        arch::SerialWriteHex(g_controller_count);
        arch::SerialWrite("\n");
    }
}

::customos::core::Result<void> XhciShutdown()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci", "XhciShutdown");
    using ::customos::core::Err;
    using ::customos::core::ErrorCode;
    // For each live controller: clear RUN/STOP, wait for HCH=1,
    // write CRCR / DCBAAP / ERSTBA to 0 so the hardware forgets
    // our ring addresses. The kernel frames behind the rings stay
    // leaked in v0 (intentional — AllocateFrame can't safely take
    // back a frame the controller might still DMA to until we've
    // proven HCH latched; freeing them conservatively is a
    // follow-up). g_controller_count resets so the next Init
    // starts with fresh slot indices.
    bool any_stuck = false;
    for (u32 i = 0; i < g_controller_count; ++i)
    {
        ControllerInfo& c = g_controllers[i];
        if (!c.init_ok)
            continue;
        // Re-derive MMIO base from the USB-driver record so we
        // don't have to cache a volatile pointer on ControllerInfo.
        const u64 pci_n = HostControllerCount();
        volatile u8* mmio = nullptr;
        for (u64 k = 0; k < pci_n; ++k)
        {
            const HostControllerInfo& h = HostController(k);
            if (h.bus == c.bus && h.device == c.device && h.function == c.function && h.mmio_virt != nullptr)
            {
                mmio = static_cast<volatile u8*>(h.mmio_virt);
                break;
            }
        }
        if (mmio == nullptr)
        {
            any_stuck = true;
            continue;
        }
        const u32 cap_word = ReadMmio32(mmio, kCapHciVersion);
        const u8 caplen = u8(cap_word & 0xFF);
        if (caplen < 0x20)
        {
            any_stuck = true;
            continue;
        }
        volatile u8* op = mmio + caplen;
        // Clear RUN/STOP then wait for HCH. Spec says this
        // completes within 16 ms; cap at 1M iterations (~tens of ms
        // on QEMU).
        u32 cmd = ReadMmio32(op, kOpUsbCmd);
        WriteMmio32(op, kOpUsbCmd, cmd & ~kCmdRunStop);
        if (!PollUntil(op, kOpUsbSts, kStsHcHalted, kStsHcHalted, 1'000'000))
        {
            arch::SerialWrite("[xhci] shutdown: HCH never set on pci=");
            arch::SerialWriteHex(c.bus);
            arch::SerialWrite(":");
            arch::SerialWriteHex(c.device);
            arch::SerialWrite(".");
            arch::SerialWriteHex(c.function);
            arch::SerialWrite("\n");
            any_stuck = true;
            continue;
        }
        // Zero out the ring-pointer registers. New init will
        // repopulate them with fresh frames.
        WriteMmio64(op, kOpDcbaap, 0);
        WriteMmio64(op, kOpCrcr, 0);
        // Interrupter 0's ERSTBA / ERDP / ERSTSZ.
        const u32 rtsoff = ReadMmio32(mmio, kCapRtsOff) & ~0x1Fu;
        volatile u8* intr0 = mmio + rtsoff + 0x20;
        WriteMmio32(intr0, /*kIntrErstSz=*/0x08, 0);
        WriteMmio64(intr0, /*kIntrErdp=*/0x18, 0);
        WriteMmio64(intr0, /*kIntrErstBa=*/0x10, 0);
        c.init_ok = false;
        c.noop_ok = false;
    }
    g_controller_count = 0;
    g_init_done = false;
    // Reset the device table so a subsequent XhciInit re-allocates
    // slots cleanly. Frames behind the rings are leaked until we
    // teach the allocator to take them back after a full HCH
    // quiesce — intentional, matches the per-controller TODO above.
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
        g_devices[i] = {};
    g_device_count = 0;
    arch::SerialWrite(any_stuck ? "[xhci] shutdown partial (some controllers wouldn't halt)\n"
                                : "[xhci] shutdown ok — all controllers quiesced\n");
    if (any_stuck)
        return Err{ErrorCode::BadState};
    return {};
}

::customos::core::Result<void> XhciRestart()
{
    if (auto r = XhciShutdown(); !r)
        return r;
    XhciInit();
    return {};
}

u32 XhciCount()
{
    return g_controller_count;
}

const ControllerInfo* XhciControllerAt(u32 i)
{
    if (i >= g_controller_count)
        return nullptr;
    return &g_controllers[i];
}

} // namespace customos::drivers::usb::xhci
