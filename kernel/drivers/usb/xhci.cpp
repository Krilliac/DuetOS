/*
 * DuetOS — xHCI USB host controller driver: implementation.
 *
 * Companion to xhci.h — see there for the controller record,
 * device-context shape, and the public API used by class
 * drivers (HID keyboard, MSC SCSI, CDC-ECM, RNDIS).
 *
 * WHAT
 *   Owns xHCI bring-up + a polling enumerator that walks every
 *   port, addresses each connected device, fetches its device
 *   descriptor, and dispatches to the matching class driver.
 *   Provides the per-device transfer ring API (control / bulk
 *   / interrupt) class drivers use to talk to their endpoints.
 *
 * HOW
 *   Each transfer ring is a TRB queue with a software-managed
 *   producer cycle bit; the controller's consumer cycle bit
 *   tells you when the entry has been consumed. Doorbell
 *   writes kick the controller after enqueue. Completions land
 *   in the event ring which we walk in `XhciPollEvents`.
 *
 *   Class-driver dispatch is by USB class code in the device
 *   descriptor; first match wins, no driver loops. Bulk
 *   transfer concurrency is serialised today (one outstanding
 *   per device) to avoid a TRB-queue race noted in
 *   .claude/knowledge/usb-rndis-driver-v0.md.
 *
 * WHY THIS FILE IS LARGE
 *   xHCI is intricate — context arrays, TRB types, ring
 *   wrap-around, completion-code translation, port reset
 *   sequencing. Plus the per-class probe chains live here too.
 */

#include "xhci.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../core/cleanroom_trace.h"
#include "../../core/klog.h"
#include "../../core/result.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../sched/sched.h"
#include "../input/ps2kbd.h"
#include "../input/ps2mouse.h"
#include "../pci/pci.h"
#include "usb.h"

namespace duetos::drivers::usb::xhci
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
constexpr u32 kCmdIntrEnable = 1u << 2; // Interrupter Enable — gates all MSI/MSI-X delivery

// Interrupter register block (offset 0x00 of each interrupter at
// rt_base + 0x20 * N). IMAN: bit 0 = IP (interrupt pending, RW1C),
// bit 1 = IE (interrupt enable).
constexpr u64 kIntrIman = 0x00;
constexpr u32 kImanIp = 1u << 0;
constexpr u32 kImanIe = 1u << 1;

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
constexpr u16 kUsbDescriptorConfig = 0x0200; // type=2, index=0
constexpr u32 kDeviceDescriptorBytes = 18;
constexpr u32 kConfigDescriptorHeaderBytes = 9; // bLength..wTotalLength fits in 9 bytes

// Config-descriptor tree tags — byte 1 (bDescriptorType) of each
// sub-descriptor. Config + HID sub-descriptors aren't matched
// against in this slice but are part of the spec set the parser
// walks past; the next slice (Configure Endpoint) reads the HID
// descriptor's country code, so keep the name.
[[maybe_unused]] constexpr u8 kDescTypeConfig = 0x02;
constexpr u8 kDescTypeInterface = 0x04;
constexpr u8 kDescTypeEndpoint = 0x05;
[[maybe_unused]] constexpr u8 kDescTypeHid = 0x21;

// Interface class 3 = HID; subclass 1 = Boot Interface; protocol
// 1 = Keyboard, 2 = Mouse. Finding the boot triple lets us skip
// HID report-descriptor parsing: both devices use fixed report
// formats (8 bytes keyboard, 3 bytes mouse).
constexpr u8 kIfaceClassHid = 0x03;
constexpr u8 kIfaceSubclassBoot = 0x01;
constexpr u8 kIfaceProtocolKeyboard = 0x01;
constexpr u8 kIfaceProtocolMouse = 0x02;

// Endpoint descriptor bmAttributes bits 0..1 = transfer type
// (0=control, 1=iso, 2=bulk, 3=interrupt). bEndpointAddress bit 7
// is direction (1=IN, 0=OUT).
constexpr u8 kEpAttrTypeMask = 0x03;
constexpr u8 kEpAttrTypeInterrupt = 0x03;
constexpr u8 kEpAddrDirIn = 0x80;

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
    // HID boot state — set once the HID bring-up finishes
    // (SET_CONFIGURATION + Configure Endpoint succeeded). The
    // polling task iterates the device table looking for
    // `hid_ready`; `hid_is_mouse` decides which report parser
    // to invoke (3-byte mouse vs 8-byte keyboard).
    bool hid_ready;
    bool hid_is_mouse;
    u8 hid_ep_addr;        // e.g. 0x81 = EP1 IN
    u8 hid_ep_xhci_idx;    // DCI for Input Context + doorbell target
    u16 hid_ep_max_packet; // from the endpoint descriptor
    mm::PhysAddr hid_ring_phys;
    Trb* hid_ring;
    u32 hid_ring_slots;
    u32 hid_ring_idx;
    u32 hid_ring_cycle;
    mm::PhysAddr hid_buf_phys;
    u8* hid_buf_virt;         // report buffer (8 bytes keyboard, 3 bytes mouse)
    u8 hid_prev[8];           // keyboard: previous report (mouse is stateless on keys)
    u64 hid_outstanding_phys; // TRB phys addr we're waiting on, or 0

    // Bulk endpoint state. One pair (IN + OUT) per device is enough
    // for every v0 USB-net class we care about (CDC-ECM, RTL8150,
    // AX88xxx). Configured by XhciConfigureBulkEndpoint; used by
    // XhciBulkSubmit + XhciBulkPoll.
    bool bulk_in_ready;
    u8 bulk_in_ep_addr;
    u8 bulk_in_dci;
    u16 bulk_in_mps;
    mm::PhysAddr bulk_in_ring_phys;
    Trb* bulk_in_ring;
    u32 bulk_in_ring_slots;
    u32 bulk_in_ring_idx;
    u32 bulk_in_ring_cycle;

    bool bulk_out_ready;
    u8 bulk_out_ep_addr;
    u8 bulk_out_dci;
    u16 bulk_out_mps;
    mm::PhysAddr bulk_out_ring_phys;
    Trb* bulk_out_ring;
    u32 bulk_out_ring_slots;
    u32 bulk_out_ring_idx;
    u32 bulk_out_ring_cycle;

    // Class/subclass for device-by-class lookup (populated during
    // descriptor parse).
    u8 dev_class;
    u8 dev_subclass;
};
constinit DeviceState g_devices[kMaxDevicesTotal] = {};
constinit u32 g_device_count = 0;

// Byte-wise zero for arbitrary POD — the freestanding toolchain has
// no libc memset and implicit struct zeroing (`x = {}`) on a large
// struct lowers to a memset call the linker can't resolve. Keep
// this local to the xHCI TU; a kernel-wide memset is a larger
// design decision than "reset my driver's per-device record".
void ZeroBytes(void* p, u64 n)
{
    auto* b = static_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

DeviceState* AllocDeviceSlot()
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        if (!g_devices[i].in_use)
        {
            ZeroBytes(&g_devices[i], sizeof(DeviceState));
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
// enqueued slot. The ring's last slot is reserved for a Link TRB
// that was installed at ring setup; when the producer would write
// there we instead flip its cycle bit (so the controller follows
// the link) and wrap the producer index to 0 with a toggled cycle.
// This is the canonical TRB ring protocol from xHCI 1.2 §4.9.
u64 EnqueueRingTrb(Trb* ring, u64 ring_phys, u32 slots, u32& idx, u32& cycle, u32 type, u32 param_lo, u32 param_hi,
                   u32 status, u32 extra_control)
{
    // If we're about to land on the Link TRB slot, refresh its
    // cycle bit to match the current producer cycle (so the
    // consumer follows it), then wrap. Link TRB's type + TC bit
    // were set at ring init; only bit 0 (cycle) moves here.
    if (idx == slots - 1)
    {
        ring[slots - 1].control = (ring[slots - 1].control & ~1u) | (cycle & 1u);
        idx = 0;
        cycle ^= 1;
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

// Forward declaration for the side cache helpers defined further
// down the TU. WaitEvent stashes Transfer Events that aren't for
// the current expect_phys so a concurrent poller can claim them.
void TrbEventCacheStash(u64 trb_phys, u32 completion_code, u32 residual, u32 trb_len);
bool TrbEventCacheTake(u64 trb_phys, u32* completion_code, u32* residual, u32* trb_len);

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
        // Non-matching event. If it's another Transfer Event, stash
        // it into the side cache so a concurrent XhciBulkPoll waiter
        // can claim it. Other event types (port status, command
        // completions destined for the synchronous command path)
        // are dropped — those callers either run during init when
        // no other consumer exists, or have their own dedicated
        // pollers.
        if (type == kTrbTypeTransferEvent)
        {
            const u32 code = (e.status >> 24) & 0xFF;
            const u32 residual = e.status & 0x00FFFFFF;
            TrbEventCacheStash(ptr, code, residual, /*trb_len=*/0);
        }
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

DeviceState* DeviceForSlot(u8 slot_id)
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        if (g_devices[i].in_use && g_devices[i].slot_id == slot_id)
            return &g_devices[i];
    }
    return nullptr;
}

// Generic USB control-IN transfer on EP0. Builds a three-TRB chain
// (Setup / Data / Status), rings DB[slot_id] target=1, and waits
// for the Transfer Event matching the Status Stage TRB. On success
// the device has written `wLength` bytes into `dev->scratch_virt`.
//
// bmRequestType / bRequest / wValue / wIndex / wLength map to the
// USB 2.0 §9.3 Setup Packet. Direction bit is expected to be IN
// (bmRequestType & 0x80); IN is the only variant this slice needs.
bool DoControlIn(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, u16 wLength,
                 const char* diag)
{
    const u32 setup_lo = u32(bmRequestType) | (u32(bRequest) << 8) | (u32(wValue) << 16);
    const u32 setup_hi = u32(wIndex) | (u32(wLength) << 16);
    const u32 setup_status = 8u;
    const u32 setup_ctl = (kTransferTypeInData << 16) | kTrbCtlIdt;
    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    const u64 data_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeDataStage, u32(dev->scratch_phys), u32(dev->scratch_phys >> 32), wLength, kTrbCtlDirIn);
    (void)data_phys;

    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc);
    if (status_phys == 0)
        return false;

    RingDoorbell(rt, dev->slot_id, 1);

    Trb event{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &event, 4'000'000))
    {
        arch::SerialWrite("[xhci]   control-IN ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" timed out slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (event.status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   control-IN ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

// Generic USB control transfer with NO data stage. Used by
// SET_CONFIGURATION + HID class-specific SET_PROTOCOL / SET_IDLE.
// bmRequestType is HOST-to-device (bit 7 = 0). The status stage
// for a no-data control transfer travels in the IN direction
// (opposite of what would have been the data direction, which
// for host-to-device is OUT — so status is IN).
bool DoControlNoData(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex,
                     const char* diag)
{
    const u32 setup_lo = u32(bmRequestType) | (u32(bRequest) << 8) | (u32(wValue) << 16);
    const u32 setup_hi = u32(wIndex); // wLength = 0 for no-data transfer
    const u32 setup_status = 8u;
    const u32 setup_ctl = (kTransferTypeNoData << 16) | kTrbCtlIdt;
    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    // Status Stage IN (direction opposite of implied OUT data), IOC=1.
    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc | kTrbCtlDirIn);
    if (status_phys == 0)
        return false;

    RingDoorbell(rt, dev->slot_id, 1);

    Trb event{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &event, 4'000'000))
    {
        arch::SerialWrite("[xhci]   control-NoData ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" timed out slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (event.status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   control-NoData ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

bool FetchDeviceDescriptor(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = DeviceForSlot(port.slot_id);
    if (dev == nullptr)
        return false;

    for (u32 i = 0; i < kDeviceDescriptorBytes; ++i)
        dev->scratch_virt[i] = 0;

    if (!DoControlIn(rt, dev, /*bmRequestType=*/0x80, kUsbReqGetDescriptor, kUsbDescriptorDevice, /*wIndex=*/0,
                     /*wLength=*/u16(kDeviceDescriptorBytes), "GET_DESCRIPTOR(Device)"))
        return false;

    const u8* d = dev->scratch_virt;
    port.max_packet_size_0 = d[7];
    port.vendor_id = u16(d[8]) | (u16(d[9]) << 8);
    port.product_id = u16(d[10]) | (u16(d[11]) << 8);
    port.device_class = d[4];
    port.device_subclass = d[5];
    port.device_protocol = d[6];
    port.descriptor_ok = true;
    dev->dev_class = port.device_class;
    dev->dev_subclass = port.device_subclass;
    return true;
}

// Walk a USB Configuration descriptor looking for the first HID
// Boot Keyboard interface and its first interrupt-IN endpoint.
// `buf[0..len)` is the wTotalLength-bytes-long descriptor tree (a
// flat stream of sub-descriptors each prefixed with {bLength,
// bDescriptorType}). Populates port fields iff a keyboard is found.
// Returns true on keyboard found.
bool ParseConfigForHidBoot(const u8* buf, u32 len, PortRecord& port)
{
    if (len < kConfigDescriptorHeaderBytes)
        return false;
    // Top-level Configuration descriptor: byte 5 = bConfigurationValue
    // (the argument we'll pass to SET_CONFIGURATION below).
    port.hid_config_value = buf[5];

    u32 off = buf[0]; // skip the Configuration descriptor itself
    bool in_hid_iface = false;
    while (off + 2 <= len)
    {
        const u8 dlen = buf[off];
        if (dlen < 2 || off + dlen > len)
            break;
        const u8 dtype = buf[off + 1];
        if (dtype == kDescTypeInterface && dlen >= 9)
        {
            const u8 bInterfaceNumber = buf[off + 2];
            const u8 bInterfaceClass = buf[off + 5];
            const u8 bInterfaceSubClass = buf[off + 6];
            const u8 bInterfaceProtocol = buf[off + 7];
            in_hid_iface = false;
            if (bInterfaceClass == kIfaceClassHid && bInterfaceSubClass == kIfaceSubclassBoot)
            {
                if (bInterfaceProtocol == kIfaceProtocolKeyboard && !port.hid_keyboard)
                {
                    port.hid_interface_num = bInterfaceNumber;
                    port.hid_keyboard = true;
                    in_hid_iface = true;
                }
                else if (bInterfaceProtocol == kIfaceProtocolMouse && !port.hid_mouse)
                {
                    port.hid_interface_num = bInterfaceNumber;
                    port.hid_mouse = true;
                    in_hid_iface = true;
                }
            }
        }
        else if (in_hid_iface && dtype == kDescTypeEndpoint && dlen >= 7 && port.hid_ep_addr == 0)
        {
            const u8 bEndpointAddress = buf[off + 2];
            const u8 bmAttributes = buf[off + 3];
            const u16 wMaxPacketSize = u16(buf[off + 4]) | (u16(buf[off + 5]) << 8);
            const u8 bInterval = buf[off + 6];
            if ((bmAttributes & kEpAttrTypeMask) == kEpAttrTypeInterrupt && (bEndpointAddress & kEpAddrDirIn))
            {
                port.hid_ep_addr = bEndpointAddress;
                port.hid_ep_max_packet = wMaxPacketSize & 0x7FF;
                port.hid_ep_interval = bInterval;
            }
        }
        off += dlen;
    }
    return (port.hid_keyboard || port.hid_mouse) && port.hid_ep_addr != 0;
}

// Fetch the Configuration descriptor in two phases: first the
// 9-byte header to learn wTotalLength, then the full
// wTotalLength-byte tree (capped by the scratch page size). Then
// parse for a HID boot keyboard. On success the port record is
// populated with hid_* fields.
bool FetchAndParseConfig(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = DeviceForSlot(port.slot_id);
    if (dev == nullptr)
        return false;

    // Phase 1 — just the 9-byte header so we can read wTotalLength.
    for (u32 i = 0; i < kConfigDescriptorHeaderBytes; ++i)
        dev->scratch_virt[i] = 0;
    if (!DoControlIn(rt, dev, /*bmRequestType=*/0x80, kUsbReqGetDescriptor, kUsbDescriptorConfig, /*wIndex=*/0,
                     /*wLength=*/u16(kConfigDescriptorHeaderBytes), "GET_DESCRIPTOR(Config,hdr)"))
        return false;
    const u16 total_len = u16(dev->scratch_virt[2]) | (u16(dev->scratch_virt[3]) << 8);
    if (total_len < kConfigDescriptorHeaderBytes)
        return false;

    // Phase 2 — full tree. Cap at the scratch page so a pathological
    // device (wTotalLength > 4 KiB) doesn't overflow.
    u16 want = total_len;
    if (want > mm::kPageSize)
        want = u16(mm::kPageSize);
    for (u32 i = 0; i < want; ++i)
        dev->scratch_virt[i] = 0;
    if (!DoControlIn(rt, dev, /*bmRequestType=*/0x80, kUsbReqGetDescriptor, kUsbDescriptorConfig, /*wIndex=*/0,
                     /*wLength=*/want, "GET_DESCRIPTOR(Config,full)"))
        return false;
    port.config_desc_ok = true;
    port.config_desc_bytes = want;

    return ParseConfigForHidBoot(dev->scratch_virt, want, port);
}

// ---------------------------------------------------------------
// HID Boot Keyboard — SET_CONFIGURATION, Configure Endpoint,
// interrupt-IN transfer ring, periodic Normal TRB submission,
// report diff, KeyEvent injection.
// ---------------------------------------------------------------

// USB-standard request for SET_CONFIGURATION (§9.4.7).
constexpr u8 kUsbReqSetConfiguration = 0x09;
// xHCI Configure Endpoint command TRB type (§6.4.3.5).
constexpr u32 kTrbTypeConfigureEndpoint = 12;
// xHCI EP Type = Interrupt IN (§6.2.3, table 6-9).
constexpr u32 kEpTypeInterruptIn = 7;
// Bulk endpoint types (§6.2.3 table 6-9). Symmetric IN / OUT
// distinguished by direction nibble in the input context.
constexpr u32 kEpTypeBulkOut = 2;
constexpr u32 kEpTypeBulkIn = 6;

// Translate a USB bEndpointAddress into the xHCI Device Context
// Index (DCI) used for both the input-context layout and the
// doorbell target. DCI = (ep_num * 2) + (direction==IN ? 1 : 0),
// with EP0 occupying DCI 1 regardless of direction.
u8 EndpointDci(u8 ep_addr)
{
    const u8 ep_num = ep_addr & 0x0F;
    const bool is_in = (ep_addr & 0x80) != 0;
    return u8((ep_num * 2) + (is_in ? 1 : 0));
}

// Translate raw USB bInterval (spec differs per speed) into the
// xHCI Interval field (ep context DW0 bits 16..23), which is
// always encoded as 2^interval × 125 µs. We map conservatively:
// - Low/Full-speed interrupt: bInterval is in 1 ms units, so
//   Interval = log2(bInterval * 8). Clip to [3, 15].
// - High-speed and above: bInterval is already a log2 value
//   in 125 µs microframes; Interval = bInterval - 1.
// Keyboards send reports on change + at bInterval cadence; at
// 16 ms (our worst-case) the ReadEvent loop still keeps up.
u32 HidXhciInterval(u8 speed, u8 bInterval)
{
    if (bInterval == 0)
        return 3; // spec-illegal for interrupt endpoints; pick sane default
    if (speed >= 3)
    {
        // HS / SS / SS+: already log2-encoded in USB units.
        u32 v = u32(bInterval - 1);
        if (v > 15)
            v = 15;
        return v;
    }
    // LS / FS: linear ms. Walk up to log2(bInterval * 8).
    u32 microframes = u32(bInterval) * 8;
    u32 log = 0;
    while ((1u << log) < microframes)
        ++log;
    if (log > 15)
        log = 15;
    return log;
}

bool SetConfiguration(Runtime& rt, DeviceState* dev, u8 config_value)
{
    return DoControlNoData(rt, dev, /*bmRequestType=*/0x00, kUsbReqSetConfiguration, /*wValue=*/u16(config_value),
                           /*wIndex=*/0, "SET_CONFIGURATION");
}

// Build a Configure Endpoint Input Context for adding ONE new
// endpoint on top of the EP0 context already established at
// Address Device time. Only the slot context (A0) and the new
// endpoint (A_dci) are flagged — EP0 stays untouched because
// it's already in Running state from Address Device. Marking A1
// here would try to reconfigure a live EP0 and the controller
// rejects it as TRB Error.
void BuildConfigureEndpointInputContext(void* input_ctx_virt, u32 ctx_bytes, u8 port_num, u8 speed, u8 new_dci,
                                        u32 new_ep_type, u32 new_mps, u32 new_interval, u64 new_ring_phys)
{
    auto* base = static_cast<volatile u8*>(input_ctx_virt);
    // Zero the range we'll touch (Input Control + Slot + up to new_dci endpoint ctx).
    const u32 end = (new_dci + 1) * ctx_bytes;
    for (u32 i = 0; i < end; ++i)
        base[i] = 0;

    volatile u32* icc = reinterpret_cast<volatile u32*>(base + 0 * ctx_bytes);
    // Add flags — A0 (slot context has new context-entries
    // high-water) + A(new_dci) (the endpoint we're adding).
    // A1 deliberately NOT set: re-flagging a running EP0 fails.
    icc[1] = (1u << 0) | (1u << new_dci);

    // Slot Context — context-entries high-water raised to new_dci.
    volatile u32* slot = reinterpret_cast<volatile u32*>(base + 1 * ctx_bytes);
    slot[0] = (u32(speed) << 20) | (u32(new_dci) << 27);
    slot[1] = u32(port_num) << 16;

    // New endpoint context at index new_dci.
    volatile u32* ep = reinterpret_cast<volatile u32*>(base + new_dci * ctx_bytes);
    // DW0: Interval in bits 16..23 (xHCI encoding, 2^N × 125 µs).
    ep[0] = (new_interval & 0xFF) << 16;
    // DW1: CErr=3, EP Type, Max Packet Size.
    ep[1] = (3u << 1) | (new_ep_type << 3) | (new_mps << 16);
    const u64 ep_dcs = new_ring_phys | 1ull;
    ep[2] = u32(ep_dcs);
    ep[3] = u32(ep_dcs >> 32);
    // DW4: Average TRB Length (bits 0..15) + Max ESIT Payload Lo
    // (bits 16..31). Periodic endpoints MUST set MaxESITPayload or
    // the controller rejects Configure Endpoint as TRB Error. For
    // HID Boot Keyboard: MPS × Max Burst Size = 8 × 1 = 8, which
    // is also a fine value for Average TRB Length.
    ep[4] = (new_mps & 0xFFFFu) | (new_mps << 16);
}

// Enqueue one Normal TRB on the HID transfer ring. The controller
// reads `len` bytes into the buffer at `buf_phys`; we set IOC so
// the completion lands as a Transfer Event we can diff against the
// previous report.
u64 HidEnqueueNormalTrb(DeviceState* dev, u64 buf_phys, u32 len)
{
    return EnqueueRingTrb(dev->hid_ring, dev->hid_ring_phys, dev->hid_ring_slots, dev->hid_ring_idx,
                          dev->hid_ring_cycle, kTrbTypeNormal, u32(buf_phys), u32(buf_phys >> 32), len, kTrbCtlIoc);
}

// Bring a HID Boot Keyboard all the way up: allocate its
// interrupt-IN transfer ring + 8-byte report buffer, build +
// submit the Configure Endpoint command, seed the first Normal
// TRB, mark the device hid_ready. The per-controller polling task
// picks up from there.
bool BringUpHidKeyboard(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = DeviceForSlot(port.slot_id);
    if (dev == nullptr)
        return false;

    // SET_CONFIGURATION first so the HID interface is selected.
    if (!SetConfiguration(rt, dev, port.hid_config_value))
        return false;

    // Allocate the transfer ring + report buffer.
    mm::PhysAddr ring_phys = 0;
    void* ring_virt = nullptr;
    if (!AllocZeroPage(&ring_phys, &ring_virt))
        return false;
    mm::PhysAddr buf_phys = 0;
    void* buf_virt = nullptr;
    if (!AllocZeroPage(&buf_phys, &buf_virt))
        return false;

    dev->hid_ring_phys = ring_phys;
    dev->hid_ring = static_cast<Trb*>(ring_virt);
    dev->hid_ring_slots = mm::kPageSize / sizeof(Trb);
    dev->hid_ring_idx = 0;
    dev->hid_ring_cycle = 1;
    Trb& link = dev->hid_ring[dev->hid_ring_slots - 1];
    link.param_lo = u32(ring_phys);
    link.param_hi = u32(ring_phys >> 32);
    link.status = 0;
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    dev->hid_buf_phys = buf_phys;
    dev->hid_buf_virt = static_cast<u8*>(buf_virt);
    dev->hid_ep_addr = port.hid_ep_addr;
    dev->hid_ep_xhci_idx = EndpointDci(port.hid_ep_addr);
    dev->hid_ep_max_packet = port.hid_ep_max_packet;
    dev->hid_is_mouse = port.hid_mouse;

    // Configure Endpoint command — uses the command ring, not EP0.
    const u32 interval = HidXhciInterval(dev->speed, port.hid_ep_interval);
    BuildConfigureEndpointInputContext(dev->input_ctx_virt, rt.ctx_bytes, dev->port_num, dev->speed,
                                       dev->hid_ep_xhci_idx, kEpTypeInterruptIn, port.hid_ep_max_packet, interval,
                                       dev->hid_ring_phys);
    const u64 cmd_phys = SubmitCmd(rt, kTrbTypeConfigureEndpoint, u32(dev->input_ctx_phys),
                                   u32(dev->input_ctx_phys >> 32), 0, u32(dev->slot_id) << 24);
    if (cmd_phys == 0)
        return false;
    u32 cc = 0;
    u8 slot_out = 0;
    if (!WaitCmdCompletion(rt, cmd_phys, &cc, &slot_out))
    {
        arch::SerialWrite("[xhci]   Configure Endpoint timed out slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (cc >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   Configure Endpoint failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }

    // Seed the first Normal TRB + ring doorbell so the endpoint
    // has a TRB to fill when the keyboard has something to report.
    const u64 trb_phys = HidEnqueueNormalTrb(dev, dev->hid_buf_phys, dev->hid_ep_max_packet);
    if (trb_phys == 0)
        return false;
    dev->hid_outstanding_phys = trb_phys;
    for (u32 i = 0; i < 8; ++i)
        dev->hid_prev[i] = 0;
    RingDoorbell(rt, dev->slot_id, dev->hid_ep_xhci_idx);

    dev->hid_ready = true;
    return true;
}

// Translate a USB HID Keyboard/Keypad page usage ID (§10 of HUT
// 1.4) to the KeyEvent `code` field the shell expects. Returns
// ASCII when there's a direct printable mapping (letters, digits,
// common punctuation) pre-shifted by the HID modifier byte; the
// KeyCode enum for non-printable keys (arrows, F-keys, Esc /
// Tab / Backspace / Enter). Unmapped usage → kKeyNone.
u16 TranslateHidUsage(u8 usage, bool shift)
{
    if (usage >= 0x04 && usage <= 0x1D)
    {
        // A..Z
        return shift ? u16('A' + (usage - 0x04)) : u16('a' + (usage - 0x04));
    }
    if (usage >= 0x1E && usage <= 0x27)
    {
        // 1..0 (0x27 is zero, not after nine)
        static constexpr char kDigitsLower[] = "1234567890";
        static constexpr char kDigitsUpper[] = "!@#$%^&*()";
        const u32 i = (usage - 0x1E);
        return shift ? u16(kDigitsUpper[i]) : u16(kDigitsLower[i]);
    }
    using namespace duetos::drivers::input;
    switch (usage)
    {
    case 0x28:
        return u16(kKeyEnter);
    case 0x29:
        return u16(kKeyEsc);
    case 0x2A:
        return u16(kKeyBackspace);
    case 0x2B:
        return u16(kKeyTab);
    case 0x2C:
        return u16(' ');
    case 0x2D:
        return shift ? u16('_') : u16('-');
    case 0x2E:
        return shift ? u16('+') : u16('=');
    case 0x2F:
        return shift ? u16('{') : u16('[');
    case 0x30:
        return shift ? u16('}') : u16(']');
    case 0x31:
        return shift ? u16('|') : u16('\\');
    case 0x33:
        return shift ? u16(':') : u16(';');
    case 0x34:
        return shift ? u16('"') : u16('\'');
    case 0x35:
        return shift ? u16('~') : u16('`');
    case 0x36:
        return shift ? u16('<') : u16(',');
    case 0x37:
        return shift ? u16('>') : u16('.');
    case 0x38:
        return shift ? u16('?') : u16('/');
    case 0x3A:
        return u16(kKeyF1);
    case 0x3B:
        return u16(kKeyF2);
    case 0x3C:
        return u16(kKeyF3);
    case 0x3D:
        return u16(kKeyF4);
    case 0x3E:
        return u16(kKeyF5);
    case 0x3F:
        return u16(kKeyF6);
    case 0x40:
        return u16(kKeyF7);
    case 0x41:
        return u16(kKeyF8);
    case 0x42:
        return u16(kKeyF9);
    case 0x43:
        return u16(kKeyF10);
    case 0x44:
        return u16(kKeyF11);
    case 0x45:
        return u16(kKeyF12);
    case 0x4F:
        return u16(kKeyArrowRight);
    case 0x50:
        return u16(kKeyArrowLeft);
    case 0x51:
        return u16(kKeyArrowDown);
    case 0x52:
        return u16(kKeyArrowUp);
    default:
        return u16(duetos::drivers::input::kKeyNone);
    }
}

u8 TranslateHidModifiers(u8 hid_mod)
{
    using namespace duetos::drivers::input;
    u8 m = 0;
    if (hid_mod & 0x11u) // LCtrl | RCtrl
        m |= kKeyModCtrl;
    if (hid_mod & 0x22u) // LShift | RShift
        m |= kKeyModShift;
    if (hid_mod & 0x44u) // LAlt | RAlt
        m |= kKeyModAlt;
    if (hid_mod & 0x88u) // LMeta | RMeta
        m |= kKeyModMeta;
    return m;
}

bool UsageInReport(u8 usage, const u8 report[8])
{
    for (u32 i = 2; i < 8; ++i)
    {
        if (report[i] == usage)
            return true;
    }
    return false;
}

// Diff previous vs current HID boot keyboard report. Emit a
// release KeyEvent for every usage in prev-not-in-curr, a press
// Parse a 3-byte HID Boot Mouse report. Layout:
//   byte 0 = buttons (bit 0 = left, 1 = right, 2 = middle, rest
//            reserved)
//   byte 1 = signed dx in mickeys (device-defined units; QEMU
//            treats them as pixels on the host display)
//   byte 2 = signed dy (positive = down; matches our
//            Ps2KeyboardReadPacket convention)
// Inject one MousePacket per report. Boot mouse reports come
// in every tick even when nothing moves; we do NOT filter
// zero-motion reports so a driver looking for button edges
// still sees the right stream.
void HidMouseInject(const u8 report[3])
{
    using namespace duetos::drivers::input;
    MousePacket p{};
    p.buttons = 0;
    if (report[0] & 0x01)
        p.buttons |= kMouseButtonLeft;
    if (report[0] & 0x02)
        p.buttons |= kMouseButtonRight;
    if (report[0] & 0x04)
        p.buttons |= kMouseButtonMiddle;
    // Sign-extend the int8 deltas into our int32 fields.
    p.dx = static_cast<i32>(static_cast<i8>(report[1]));
    p.dy = static_cast<i32>(static_cast<i8>(report[2]));
    MouseInjectPacket(p);
}

// for every usage in curr-not-in-prev. Modifier edges emit
// modifier-only events (code=kKeyNone) so downstream can refresh
// any "Ctrl held" UI cues without polling.
void HidDiffAndInject(const u8 prev[8], const u8 curr[8])
{
    using namespace duetos::drivers::input;
    const u8 prev_mod = prev[0];
    const u8 curr_mod = curr[0];
    const bool shift = (curr_mod & 0x22u) != 0;
    const u8 kernel_mods = TranslateHidModifiers(curr_mod);

    // Modifier-only event on any modifier-byte change — mirrors
    // what the PS/2 decoder emits on Shift / Ctrl / Alt / Meta
    // edges so downstream "modifier held" cues update.
    if (prev_mod != curr_mod)
    {
        KeyEvent ev{};
        ev.code = kKeyNone;
        ev.modifiers = kernel_mods;
        ev.is_release = false;
        KeyboardInjectEvent(ev);
    }

    // Release edges — usages in prev that aren't in curr.
    for (u32 i = 2; i < 8; ++i)
    {
        const u8 u = prev[i];
        if (u == 0 || u == 0x01 /* ErrorRollOver */)
            continue;
        if (UsageInReport(u, curr))
            continue;
        KeyEvent ev{};
        ev.code = TranslateHidUsage(u, shift);
        ev.modifiers = kernel_mods;
        ev.is_release = true;
        KeyboardInjectEvent(ev);
    }
    // Press edges — usages in curr that weren't in prev.
    for (u32 i = 2; i < 8; ++i)
    {
        const u8 u = curr[i];
        if (u == 0 || u == 0x01)
            continue;
        if (UsageInReport(u, prev))
            continue;
        KeyEvent ev{};
        ev.code = TranslateHidUsage(u, shift);
        ev.modifiers = kernel_mods;
        ev.is_release = false;
        KeyboardInjectEvent(ev);
    }
}

// Non-blocking single-step of the event ring. If a valid TRB is
// present under the current consumer cycle, copy it out + advance.
// Returns false if the ring is empty.
bool TryReadEvent(Runtime& rt, Trb* out)
{
    const Trb& e = rt.evt_ring[rt.evt_idx];
    const bool valid = (e.control & 1u) == (rt.evt_cycle & 1u);
    if (!valid)
        return false;
    if (out != nullptr)
        *out = e;
    AdvanceEventRing(rt);
    return true;
}

// Per-controller polling task state. With MSI-X bound the task
// blocks on `wait` and the device's IRQ handler wakes it; without
// MSI-X it falls back to tick-cadence polling so a controller that
// doesn't expose the capability still functions.
struct PollTaskArg
{
    Runtime* rt;
    ControllerInfo* info;
    duetos::sched::WaitQueue wait;
    u8 irq_vector; // 0 == MSI-X not bound, polling fallback
};

constinit PollTaskArg g_poll_args[kMaxControllers] = {};
constinit Runtime g_poll_rt[kMaxControllers] = {};

// Side cache for Transfer Events that arrive on the ring but aren't
// for HID endpoints. HidPollEntry is the designated runtime
// event-ring owner; it routes non-HID transfer completions here so
// bulk/control waiters can claim them by TRB pointer.
struct TrbEventCacheEntry
{
    volatile u64 trb_phys;
    volatile u32 completion_code;
    volatile u32 residual; // status bits 0..23 = remaining bytes (for short packets)
    volatile u32 trb_len;  // length we put in the original TRB
    volatile u8 valid;
};
constinit TrbEventCacheEntry g_trb_event_cache[32] = {};

// Cache an unrelated event for someone else's poll to claim.
void TrbEventCacheStash(u64 trb_phys, u32 completion_code, u32 residual, u32 trb_len)
{
    for (auto& e : g_trb_event_cache)
    {
        if (e.valid)
            continue;
        e.trb_phys = trb_phys;
        e.completion_code = completion_code;
        e.residual = residual;
        e.trb_len = trb_len;
        e.valid = 1;
        return;
    }
    // Cache full — drop oldest (slot 0) so we always have room.
    g_trb_event_cache[0].trb_phys = trb_phys;
    g_trb_event_cache[0].completion_code = completion_code;
    g_trb_event_cache[0].residual = residual;
    g_trb_event_cache[0].trb_len = trb_len;
    g_trb_event_cache[0].valid = 1;
}

// Try to claim a cached event for this TRB. Returns true on hit.
bool TrbEventCacheTake(u64 trb_phys, u32* completion_code, u32* residual, u32* trb_len)
{
    for (auto& e : g_trb_event_cache)
    {
        if (e.valid && e.trb_phys == trb_phys)
        {
            if (completion_code)
                *completion_code = e.completion_code;
            if (residual)
                *residual = e.residual;
            if (trb_len)
                *trb_len = e.trb_len;
            e.valid = 0;
            e.trb_phys = 0;
            return true;
        }
    }
    return false;
}

// Acknowledge interrupter 0's IMAN.IP (the device-side pending
// bit). LAPIC EOI is handled by the generic IRQ dispatcher; this
// clears the xHCI-internal pending bit so a subsequent event
// re-asserts the line instead of being coalesced into the
// already-pending state. Keeps IE set so future events still
// trigger interrupts.
void XhciAckInterrupter(Runtime& rt)
{
    if (rt.intr0 == nullptr)
        return;
    const u32 iman = ReadMmio32(rt.intr0, kIntrIman);
    WriteMmio32(rt.intr0, kIntrIman, (iman & ~kImanIp) | kImanIp | kImanIe);
}

// One C handler per controller so the generic IrqHandler signature
// (no context) can still route to the right wait queue. The max
// controller count is small; explicit stamps are clearer than
// building a vector → controller-idx map.
void XhciIrq0()
{
    XhciAckInterrupter(g_poll_rt[0]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[0].wait);
}
void XhciIrq1()
{
    XhciAckInterrupter(g_poll_rt[1]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[1].wait);
}
void XhciIrq2()
{
    XhciAckInterrupter(g_poll_rt[2]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[2].wait);
}
void XhciIrq3()
{
    XhciAckInterrupter(g_poll_rt[3]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[3].wait);
}

static_assert(kMaxControllers == 4, "per-controller IRQ stamps must match kMaxControllers");
constexpr ::duetos::arch::IrqHandler kXhciIrqStamps[kMaxControllers] = {&XhciIrq0, &XhciIrq1, &XhciIrq2, &XhciIrq3};

// Attempt MSI-X bring-up for one controller. On success the
// controller fires IRQs at `vector` whenever an event is posted
// to interrupter 0. On failure the caller falls back to
// tick-cadence polling.
bool XhciBindMsix(Runtime& rt, const HostControllerInfo& h, u32 ctrlr_idx, u8* out_vector)
{
    using namespace duetos::drivers::pci;
    DeviceAddress addr{};
    addr.bus = h.bus;
    addr.device = h.device;
    addr.function = h.function;
    auto r = PciMsixBindSimple(addr, /*entry_index=*/0, kXhciIrqStamps[ctrlr_idx], /*out_route=*/nullptr);
    if (!r.has_value())
        return false;
    const u8 vector = r.value();

    // Enable the device's interrupt machinery:
    //   - USBCMD.INTE so the controller delivers MSI at all.
    //   - IMAN.IE on interrupter 0 so its event ring raises the
    //     vector we just bound. Clear any stale IP bit in the same
    //     write (bit 0 is RW1C).
    WriteMmio32(rt.op, kOpUsbCmd, ReadMmio32(rt.op, kOpUsbCmd) | kCmdIntrEnable);
    WriteMmio32(rt.intr0, kIntrIman, kImanIe | kImanIp);

    *out_vector = vector;
    return true;
}

void HidPollEntry(void* raw)
{
    auto* arg = static_cast<PollTaskArg*>(raw);
    Runtime& rt = *arg->rt;
    const bool have_msix = (arg->irq_vector != 0);
    for (;;)
    {
        // Drain every event currently available, then sleep.
        Trb e{};
        while (TryReadEvent(rt, &e))
        {
            const u32 type = (e.control >> 10) & 0x3F;
            if (type != kTrbTypeTransferEvent)
                continue;
            const u64 ptr = (u64(e.param_hi) << 32) | u64(e.param_lo);
            const u32 completion_code = (e.status >> 24) & 0xFF;
            const u32 residual = e.status & 0x00FFFFFF;
            // Find which HID device this TRB belongs to.
            bool consumed_by_hid = false;
            for (u32 i = 0; i < kMaxDevicesTotal; ++i)
            {
                DeviceState& dev = g_devices[i];
                if (!dev.in_use || !dev.hid_ready)
                    continue;
                if (dev.hid_outstanding_phys == 0 || dev.hid_outstanding_phys != ptr)
                    continue;
                consumed_by_hid = true;
                // Parse + inject. Mice skip the diff state — each
                // report is a standalone delta + button snapshot,
                // so we push the packet as-is.
                if (dev.hid_is_mouse)
                {
                    u8 mouse_rep[3] = {
                        dev.hid_buf_virt[0],
                        dev.hid_buf_virt[1],
                        dev.hid_buf_virt[2],
                    };
                    HidMouseInject(mouse_rep);
                }
                else
                {
                    u8 curr[8] = {};
                    for (u32 b = 0; b < 8; ++b)
                        curr[b] = dev.hid_buf_virt[b];
                    HidDiffAndInject(dev.hid_prev, curr);
                    for (u32 b = 0; b < 8; ++b)
                        dev.hid_prev[b] = curr[b];
                }
                // Re-queue a Normal TRB + ring the endpoint doorbell.
                const u64 trb = HidEnqueueNormalTrb(&dev, dev.hid_buf_phys, dev.hid_ep_max_packet);
                dev.hid_outstanding_phys = trb;
                if (trb != 0)
                    RingDoorbell(rt, dev.slot_id, dev.hid_ep_xhci_idx);
                break;
            }
            if (!consumed_by_hid)
                TrbEventCacheStash(ptr, completion_code, residual, /*trb_len=*/0);
        }
        if (have_msix)
        {
            // Block until the IRQ handler signals us. WaitQueueBlock
            // requires interrupts disabled on entry; the scheduler
            // re-enables them across the context switch. Spurious
            // wakes are fine — the drain-loop above handles them.
            //
            // Lost-wakeup guard: if an event arrived between the
            // above `while (TryReadEvent)` returning false and our
            // Cli, the handler's WakeOne fired into an unparked
            // task. Re-check the event ring once under Cli before
            // committing to the block. If something's there we
            // fall through to the next iteration, Sti-free (the
            // scheduler's Schedule path re-enables on switch).
            duetos::arch::Cli();
            if ((rt.evt_ring[rt.evt_idx].control & 1u) == (rt.evt_cycle & 1u))
            {
                duetos::arch::Sti();
                continue;
            }
            duetos::sched::WaitQueueBlock(&arg->wait);
        }
        else
        {
            duetos::sched::SchedSleepTicks(1);
        }
    }
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

        // Pull down the configuration descriptor tree and walk it
        // for a HID Boot Keyboard interface. Failure here isn't
        // fatal for the port — some devices might not respond to
        // GET_DESCRIPTOR(Config) at this point on real hardware —
        // so we log + continue.
        if (FetchAndParseConfig(rt, rec))
        {
            ++out.configs_parsed;
        }
        if (rec.hid_keyboard || rec.hid_mouse)
        {
            const char* kind_tag = rec.hid_mouse ? "HID-BOOT-MOUSE" : "HID-BOOT-KEYBOARD";
            if (rec.hid_keyboard)
                ++out.hid_keyboards_found;
            if (rec.hid_mouse)
                ++out.hid_mice_found;
            arch::SerialWrite("[xhci]   ");
            arch::SerialWrite(kind_tag);
            arch::SerialWrite(" port=");
            arch::SerialWriteHex(rec.port_num);
            arch::SerialWrite(" iface=");
            arch::SerialWriteHex(rec.hid_interface_num);
            arch::SerialWrite(" ep=");
            arch::SerialWriteHex(rec.hid_ep_addr);
            arch::SerialWrite(" mps=");
            arch::SerialWriteHex(rec.hid_ep_max_packet);
            arch::SerialWrite(" interval=");
            arch::SerialWriteHex(rec.hid_ep_interval);
            arch::SerialWrite(" config=");
            arch::SerialWriteHex(rec.hid_config_value);
            arch::SerialWrite("\n");
            if (BringUpHidKeyboard(rt, rec))
            {
                if (rec.hid_keyboard)
                    ++out.hid_keyboards_bound;
                if (rec.hid_mouse)
                    ++out.hid_mice_bound;
                arch::SerialWrite("[xhci]   ");
                arch::SerialWrite(kind_tag);
                arch::SerialWrite(" bound; polling task will pick up slot=");
                arch::SerialWriteHex(rec.slot_id);
                arch::SerialWrite("\n");
            }
        }
    }
    arch::SerialWrite("[xhci] enumeration: addressed=");
    arch::SerialWriteHex(out.devices_addressed);
    arch::SerialWrite(" descriptors=");
    arch::SerialWriteHex(out.descriptors_fetched);
    arch::SerialWrite(" configs=");
    arch::SerialWriteHex(out.configs_parsed);
    arch::SerialWrite(" kbd-found=");
    arch::SerialWriteHex(out.hid_keyboards_found);
    arch::SerialWrite(" kbd-bound=");
    arch::SerialWriteHex(out.hid_keyboards_bound);
    arch::SerialWrite(" mouse-found=");
    arch::SerialWriteHex(out.hid_mice_found);
    arch::SerialWrite(" mouse-bound=");
    arch::SerialWriteHex(out.hid_mice_bound);
    arch::SerialWrite("\n");

    // Always publish this controller's Runtime into g_poll_rt so
    // that public APIs (XhciControlIn / XhciBulkSubmit) can reach
    // the event + command rings even when no HID device drove a
    // task spawn. Without this, a USB-net-only board leaves
    // g_poll_rt[idx] zeroed and every user-issued transfer's
    // WaitEvent polls a nullptr ring + times out.
    {
        const u32 idx_any = u32(&out - g_controllers);
        if (idx_any < kMaxControllers)
            g_poll_rt[idx_any] = rt;
    }

    // Spawn the per-controller HID polling task if any device
    // came up. The Runtime struct lives in our stack frame here;
    // copy it into file-scope storage so the task's entry point
    // has a stable pointer past this function's return. We also
    // try to bind MSI-X interrupter 0 here so the task can block
    // on a wait queue the IRQ handler signals instead of polling
    // at tick cadence — order matters, the task has to see the
    // final irq_vector when it first runs.
    if (out.hid_keyboards_bound + out.hid_mice_bound > 0)
    {
        const u32 idx = u32(&out - g_controllers);
        if (idx < kMaxControllers)
        {
            // g_poll_rt[idx] is already populated by the
            // unconditional publish above — just wire the arg.
            g_poll_args[idx].rt = &g_poll_rt[idx];
            g_poll_args[idx].info = &out;
            g_poll_args[idx].wait = {};
            g_poll_args[idx].irq_vector = 0;

            u8 bound_vec = 0;
            if (XhciBindMsix(g_poll_rt[idx], h, idx, &bound_vec))
            {
                g_poll_args[idx].irq_vector = bound_vec;
                arch::SerialWrite("[xhci] MSI-X bound ctrlr=");
                arch::SerialWriteHex(idx);
                arch::SerialWrite(" vector=");
                arch::SerialWriteHex(bound_vec);
                arch::SerialWrite("\n");
            }
            else
            {
                arch::SerialWrite("[xhci] MSI-X unavailable ctrlr=");
                arch::SerialWriteHex(idx);
                arch::SerialWrite(" — falling back to tick-cadence polling\n");
            }

            duetos::sched::SchedCreate(HidPollEntry, &g_poll_args[idx], "xhci-hid-poll");
        }
    }

    return true;
}

// -------------------------------------------------------------------
// USB-net class-driver primitives. Exposed via xhci.h. These are the
// minimal slice of xHCI needed by a Bulk-In / Bulk-Out USB class
// driver (CDC-ECM, RTL8150, AX88xxx, ...). They thunk into the
// internal helpers above and return bool / out-params instead of
// Result<> to keep the cross-driver surface narrow.
// -------------------------------------------------------------------

bool ControlOutWithData(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex,
                        const void* buf, u16 len, const char* diag)
{
    // bmRequestType bit 7 must be 0 (host-to-device).
    const u32 setup_lo = u32(bmRequestType) | (u32(bRequest) << 8) | (u32(wValue) << 16);
    const u32 setup_hi = u32(wIndex) | (u32(len) << 16);
    const u32 setup_status = 8u;
    const bool has_data = buf != nullptr && len > 0;
    const u32 transfer_type = has_data ? kTransferTypeOutData : kTransferTypeNoData;
    const u32 setup_ctl = (transfer_type << 16) | kTrbCtlIdt;

    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    if (has_data)
    {
        // Copy payload into the device's scratch page for DMA.
        const auto* src = static_cast<const u8*>(buf);
        for (u16 i = 0; i < len; ++i)
            dev->scratch_virt[i] = src[i];
        const u64 data_phys =
            EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                           kTrbTypeDataStage, u32(dev->scratch_phys), u32(dev->scratch_phys >> 32), len, /*ctl=*/0);
        (void)data_phys;
    }

    // Status stage IN (opposite of OUT data), IOC=1.
    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc | kTrbCtlDirIn);
    if (status_phys == 0)
        return false;
    RingDoorbell(rt, dev->slot_id, 1);
    Trb e{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &e, 4'000'000))
    {
        arch::SerialWrite("[xhci]   control-OUT ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" timed out\n");
        return false;
    }
    const u32 code = (e.status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   control-OUT ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

} // namespace

u8 XhciFindDeviceByClass(u8 class_code, u8 subclass)
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        const DeviceState& d = g_devices[i];
        if (!d.in_use || d.slot_id == 0)
            continue;
        if (class_code != 0xFF && d.dev_class != class_code)
            continue;
        if (subclass != 0xFF && d.dev_subclass != subclass)
            continue;
        return d.slot_id;
    }
    return 0;
}

void XhciPauseEventConsumer(bool pause)
{
    // Router-backed runtime path: HidPollEntry is the event-ring
    // owner and forwards non-HID completions into the side cache
    // for bulk waiters. Keep this API as a compatibility no-op so
    // existing class-driver call-sites stay source-compatible.
    (void)pause;
}

u32 XhciEnumerateDevices(u8* out, u32 max)
{
    u32 n = 0;
    for (u32 i = 0; i < kMaxDevicesTotal && n < max; ++i)
    {
        const DeviceState& d = g_devices[i];
        if (!d.in_use || d.slot_id == 0)
            continue;
        if (out != nullptr)
            out[n] = d.slot_id;
        ++n;
    }
    return n;
}

bool XhciControlIn(u8 slot_id, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, void* buf, u16 len)
{
    if ((bmRequestType & 0x80) == 0 || len > mm::kPageSize)
        return false;
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return false;
    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    if (!DoControlIn(rt, dev, bmRequestType, bRequest, wValue, wIndex, len, "user-control-IN"))
        return false;
    if (buf != nullptr && len > 0)
    {
        auto* dst = static_cast<u8*>(buf);
        for (u16 i = 0; i < len; ++i)
            dst[i] = dev->scratch_virt[i];
    }
    return true;
}

bool XhciControlOut(u8 slot_id, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, const void* buf, u16 len)
{
    if ((bmRequestType & 0x80) != 0 || len > mm::kPageSize)
        return false;
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return false;
    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    return ControlOutWithData(rt, dev, bmRequestType, bRequest, wValue, wIndex, buf, len, "user-control-OUT");
}

bool XhciConfigureBulkEndpoint(u8 slot_id, u8 ep_addr, u16 max_packet)
{
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return false;
    const bool is_in = (ep_addr & 0x80) != 0;
    if (is_in && dev->bulk_in_ready)
        return true;
    if (!is_in && dev->bulk_out_ready)
        return true;

    mm::PhysAddr ring_phys = 0;
    void* ring_virt = nullptr;
    if (!AllocZeroPage(&ring_phys, &ring_virt))
        return false;

    auto* ring = static_cast<Trb*>(ring_virt);
    const u32 slots = mm::kPageSize / sizeof(Trb);
    Trb& link = ring[slots - 1];
    link.param_lo = u32(ring_phys);
    link.param_hi = u32(ring_phys >> 32);
    link.status = 0;
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    const u8 dci = EndpointDci(ep_addr);
    const u32 ep_type = is_in ? kEpTypeBulkIn : kEpTypeBulkOut;
    const u32 interval = 0; // bulk endpoints don't use the interval field

    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    BuildConfigureEndpointInputContext(dev->input_ctx_virt, rt.ctx_bytes, dev->port_num, dev->speed, dci, ep_type,
                                       max_packet, interval, ring_phys);
    const u64 cmd_phys = SubmitCmd(rt, kTrbTypeConfigureEndpoint, u32(dev->input_ctx_phys),
                                   u32(dev->input_ctx_phys >> 32), 0, u32(slot_id) << 24);
    if (cmd_phys == 0)
        return false;
    u32 cc = 0;
    u8 sl = 0;
    if (!WaitCmdCompletion(rt, cmd_phys, &cc, &sl))
        return false;
    const u32 code = (cc >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci] bulk-EP configure failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" slot=");
        arch::SerialWriteHex(slot_id);
        arch::SerialWrite(" ep=");
        arch::SerialWriteHex(ep_addr);
        arch::SerialWrite("\n");
        return false;
    }

    if (is_in)
    {
        dev->bulk_in_ep_addr = ep_addr;
        dev->bulk_in_dci = dci;
        dev->bulk_in_mps = max_packet;
        dev->bulk_in_ring_phys = ring_phys;
        dev->bulk_in_ring = ring;
        dev->bulk_in_ring_slots = slots;
        dev->bulk_in_ring_idx = 0;
        dev->bulk_in_ring_cycle = 1;
        dev->bulk_in_ready = true;
    }
    else
    {
        dev->bulk_out_ep_addr = ep_addr;
        dev->bulk_out_dci = dci;
        dev->bulk_out_mps = max_packet;
        dev->bulk_out_ring_phys = ring_phys;
        dev->bulk_out_ring = ring;
        dev->bulk_out_ring_slots = slots;
        dev->bulk_out_ring_idx = 0;
        dev->bulk_out_ring_cycle = 1;
        dev->bulk_out_ready = true;
    }
    return true;
}

u64 XhciBulkSubmit(u8 slot_id, u8 ep_addr, u64 buf_phys, u32 len)
{
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return 0;
    const bool is_in = (ep_addr & 0x80) != 0;
    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    u64 trb_phys = 0;
    if (is_in)
    {
        if (!dev->bulk_in_ready || ep_addr != dev->bulk_in_ep_addr)
            return 0;
        trb_phys = EnqueueRingTrb(dev->bulk_in_ring, dev->bulk_in_ring_phys, dev->bulk_in_ring_slots,
                                  dev->bulk_in_ring_idx, dev->bulk_in_ring_cycle, kTrbTypeNormal, u32(buf_phys),
                                  u32(buf_phys >> 32), len, kTrbCtlIoc);
        RingDoorbell(rt, slot_id, dev->bulk_in_dci);
    }
    else
    {
        if (!dev->bulk_out_ready || ep_addr != dev->bulk_out_ep_addr)
            return 0;
        trb_phys = EnqueueRingTrb(dev->bulk_out_ring, dev->bulk_out_ring_phys, dev->bulk_out_ring_slots,
                                  dev->bulk_out_ring_idx, dev->bulk_out_ring_cycle, kTrbTypeNormal, u32(buf_phys),
                                  u32(buf_phys >> 32), len, kTrbCtlIoc);
        RingDoorbell(rt, slot_id, dev->bulk_out_dci);
    }
    return trb_phys;
}

bool XhciBulkPoll(u8 slot_id, u8 ep_addr, u64 trb_phys, u32* out_bytes, u64 timeout_us)
{
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr || trb_phys == 0)
        return false;

    // Helper to compute bytes-actually-transferred from the
    // residual byte count + the TRB length we enqueued.
    auto compute_bytes = [&](u32 residual) -> u32
    {
        const Trb* ring = (ep_addr & 0x80) ? dev->bulk_in_ring : dev->bulk_out_ring;
        const u32 slots = (ep_addr & 0x80) ? dev->bulk_in_ring_slots : dev->bulk_out_ring_slots;
        const u64 ring_phys_base = (ep_addr & 0x80) ? dev->bulk_in_ring_phys : dev->bulk_out_ring_phys;
        u32 trb_idx = 0;
        if (trb_phys >= ring_phys_base && trb_phys < ring_phys_base + slots * sizeof(Trb))
            trb_idx = u32((trb_phys - ring_phys_base) / sizeof(Trb));
        const u32 trb_len = ring[trb_idx].status & 0x0001FFFF;
        return trb_len > residual ? trb_len - residual : 0;
    };

    // Runtime event-ring ownership belongs to HidPollEntry; bulk
    // waiters poll for their completion in the transfer-event cache.
    const u64 timeout_ticks = (timeout_us + 9'999) / 10'000; // 100 Hz kernel tick
    const u64 polls = timeout_ticks == 0 ? 1 : timeout_ticks;
    for (u64 i = 0; i < polls; ++i)
    {
        u32 code = 0;
        u32 residual = 0;
        u32 len_unused = 0;
        if (TrbEventCacheTake(trb_phys, &code, &residual, &len_unused))
        {
            if (out_bytes != nullptr)
                *out_bytes = compute_bytes(residual);
            core::CleanroomTraceRecord("xhci", "bulk-cache-hit", trb_phys, code, residual);
            return code == kCompletionCodeSuccess || code == 13 /* Short Packet */;
        }
        if (timeout_ticks != 0)
            duetos::sched::SchedSleepTicks(1);
    }
    core::CleanroomTraceRecord("xhci", "bulk-timeout", trb_phys, timeout_us, 0);
    return false;
}

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

::duetos::core::Result<void> XhciShutdown()
{
    KLOG_TRACE_SCOPE("drivers/usb/xhci", "XhciShutdown");
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
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
        ZeroBytes(&g_devices[i], sizeof(DeviceState));
    g_device_count = 0;
    arch::SerialWrite(any_stuck ? "[xhci] shutdown partial (some controllers wouldn't halt)\n"
                                : "[xhci] shutdown ok — all controllers quiesced\n");
    if (any_stuck)
        return Err{ErrorCode::BadState};
    return {};
}

::duetos::core::Result<void> XhciRestart()
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

} // namespace duetos::drivers::usb::xhci
