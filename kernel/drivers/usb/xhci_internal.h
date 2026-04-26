#pragma once

// Private cross-TU surface for the xHCI driver. xhci.cpp is being
// decomposed into per-aspect sibling translation units (see the
// refactor plan in .claude/knowledge/refactor-codebase-plan.md);
// anything in `namespace duetos::drivers::usb::xhci::internal` is
// intended for those TUs only — never include this header from
// outside kernel/drivers/usb/.
//
// Slice 1 (this commit): completion-code → human-name lookup.
// Future slices will lift the shared structs (Trb, ErstEntry,
// Runtime, ControllerInfo, PortRecord, DeviceState) and the MMIO
// helpers here as well.

#include "arch/x86_64/traps.h"
#include "util/types.h"
#include "mm/page.h"
#include "sched/sched.h"
#include "drivers/usb/xhci.h"

namespace duetos::drivers::usb::xhci::internal
{

// =====================================================================
// Hardware register constants (xHCI 1.2 spec §5)
// =====================================================================

inline constexpr u32 kMaxControllers = 4;

// Capability-reg offsets (relative to mmio_virt). xHCI 1.2 §5.3.
inline constexpr u64 kCapHciVersion = 0x00; // u32 = caplen | (rsvd) | hciver
inline constexpr u64 kCapHcsParams1 = 0x04;
inline constexpr u64 kCapHcsParams2 = 0x08;
inline constexpr u64 kCapHccParams1 = 0x10;
inline constexpr u64 kCapDbOff = 0x14;
inline constexpr u64 kCapRtsOff = 0x18;

// Operational-reg offsets (relative to opbase = mmio + caplen).
inline constexpr u64 kOpUsbCmd = 0x00;
inline constexpr u64 kOpUsbSts = 0x04;
inline constexpr u64 kOpDnCtrl = 0x14;
inline constexpr u64 kOpCrcr = 0x18;   // u64
inline constexpr u64 kOpDcbaap = 0x30; // u64
inline constexpr u64 kOpConfig = 0x38;

// USBCMD bits.
inline constexpr u32 kCmdRunStop = 1u << 0;
inline constexpr u32 kCmdHcReset = 1u << 1;
inline constexpr u32 kCmdIntrEnable = 1u << 2; // Interrupter Enable — gates all MSI/MSI-X delivery

// Interrupter register block (offset 0x00 of each interrupter at
// rt_base + 0x20 * N). IMAN: bit 0 = IP (interrupt pending, RW1C),
// bit 1 = IE (interrupt enable).
inline constexpr u64 kIntrIman = 0x00;
inline constexpr u32 kImanIp = 1u << 0;
inline constexpr u32 kImanIe = 1u << 1;

// USBSTS bits.
inline constexpr u32 kStsHcHalted = 1u << 0;
inline constexpr u32 kStsCnr = 1u << 11;

// HCCPARAMS1 bits.
inline constexpr u32 kHccParams1Csz = 1u << 2; // context size: 0=32 B, 1=64 B

// TRB types (control field bits 15:10). xHCI 1.2 §6.4.
[[maybe_unused]] inline constexpr u32 kTrbTypeNormal = 1;
inline constexpr u32 kTrbTypeSetupStage = 2;
inline constexpr u32 kTrbTypeDataStage = 3;
inline constexpr u32 kTrbTypeStatusStage = 4;
inline constexpr u32 kTrbTypeLink = 6;
inline constexpr u32 kTrbTypeEnableSlot = 9;
inline constexpr u32 kTrbTypeAddressDevice = 11;
inline constexpr u32 kTrbTypeNoOp = 23; // command-ring NoOp
inline constexpr u32 kTrbTypeTransferEvent = 32;
inline constexpr u32 kTrbTypeCmdCompletion = 33;
[[maybe_unused]] inline constexpr u32 kTrbTypePortStatusChange = 34;

// Setup Stage TRB control bits.
inline constexpr u32 kTrbCtlIdt = 1u << 6; // Immediate Data (setup packet is inline)
inline constexpr u32 kTrbCtlIoc = 1u << 5; // Interrupt On Completion
// "Transfer Type" field in Setup/Status Stage control bits 17:16.
[[maybe_unused]] inline constexpr u32 kTransferTypeNoData = 0;
[[maybe_unused]] inline constexpr u32 kTransferTypeReservedBulk = 1; // invalid for control
[[maybe_unused]] inline constexpr u32 kTransferTypeOutData = 2;
inline constexpr u32 kTransferTypeInData = 3;
// Data/Status Stage "DIR" bit is bit 16 (1 = IN, 0 = OUT).
inline constexpr u32 kTrbCtlDirIn = 1u << 16;

// USB standard setup packet fields.
inline constexpr u8 kUsbReqGetDescriptor = 0x06;
inline constexpr u16 kUsbDescriptorDevice = 0x0100; // type=1, index=0
inline constexpr u16 kUsbDescriptorConfig = 0x0200; // type=2, index=0
inline constexpr u32 kDeviceDescriptorBytes = 18;
inline constexpr u32 kConfigDescriptorHeaderBytes = 9; // bLength..wTotalLength fits in 9 bytes

// Config-descriptor tree tags — byte 1 (bDescriptorType) of each
// sub-descriptor.
[[maybe_unused]] inline constexpr u8 kDescTypeConfig = 0x02;
inline constexpr u8 kDescTypeInterface = 0x04;
inline constexpr u8 kDescTypeEndpoint = 0x05;
[[maybe_unused]] inline constexpr u8 kDescTypeHid = 0x21;

// Interface class 3 = HID; subclass 1 = Boot Interface; protocol
// 1 = Keyboard, 2 = Mouse.
inline constexpr u8 kIfaceClassHid = 0x03;
inline constexpr u8 kIfaceSubclassBoot = 0x01;
inline constexpr u8 kIfaceProtocolKeyboard = 0x01;
inline constexpr u8 kIfaceProtocolMouse = 0x02;

// Endpoint descriptor bmAttributes bits 0..1 = transfer type
// (0=control, 1=iso, 2=bulk, 3=interrupt). bEndpointAddress bit 7
// is direction (1=IN, 0=OUT).
inline constexpr u8 kEpAttrTypeMask = 0x03;
inline constexpr u8 kEpAttrTypeInterrupt = 0x03;
inline constexpr u8 kEpAddrDirIn = 0x80;

// PORTSC bit layout we care about.
inline constexpr u32 kPortScCcs = 1u << 0; // current-connect status (RO)
inline constexpr u32 kPortScPed = 1u << 1; // port enabled/disabled (RW1C)
inline constexpr u32 kPortScPr = 1u << 4;  // port reset (RW1S)

// PORTSC RW1C bits (PED + the 7 change bits at 17..23).
inline constexpr u32 kPortScRw1cMask = (1u << 1) | (0x7Fu << 17);

// Command Completion event: status bits 31:24 carry a completion
// code; 1 = success.
inline constexpr u32 kCompletionCodeSuccess = 1;

// USB-standard request for SET_CONFIGURATION (§9.4.7).
inline constexpr u8 kUsbReqSetConfiguration = 0x09;
// xHCI Configure Endpoint command TRB type (§6.4.3.5).
inline constexpr u32 kTrbTypeConfigureEndpoint = 12;
// xHCI EP Type = Interrupt IN (§6.2.3, table 6-9).
inline constexpr u32 kEpTypeInterruptIn = 7;
// Bulk endpoint types (§6.2.3 table 6-9). Symmetric IN / OUT
// distinguished by direction nibble in the input context.
inline constexpr u32 kEpTypeBulkOut = 2;
inline constexpr u32 kEpTypeBulkIn = 6;


// Map an xHCI completion-code byte from a Transfer Event / Command
// Completion TRB into a short human-readable string. Used only by
// failure-path log lines so a reader doesn't have to hand-decode
// `code=4` to "USB Transaction Error". The returned pointer points
// at static storage; callers must not free it.
const char* CompletionCodeName(u32 code);

// HID-class input bridge. Boot-protocol mouse and keyboard reports
// arriving on the interrupt-IN ring funnel through these into the
// kernel's PS/2-shaped input queues so the rest of the system
// doesn't care that the device is USB. HidPollEntry in xhci.cpp
// is the only caller.
void HidMouseInject(const u8 report[3]);
void HidDiffAndInject(const u8 prev[8], const u8 curr[8]);

// MMIO accessors. xHCI registers are word- or qword-sized and
// require strict-aliased volatile access so the compiler doesn't
// reorder, fuse, or elide them. Inline + header-resident so every
// xhci_*.cpp TU shares one definition.
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

// Speed-derived constants used by the enum + HID-class setup paths.
// EP0 max-packet-size default by PORTSC speed; HID interrupt-EP poll
// interval converted into the xHCI Interval encoding (2^n × 125 µs).
u32 DefaultMaxPacketSize0(u8 speed);
u32 HidXhciInterval(u8 speed, u8 bInterval);

// =====================================================================
// Hardware data structures
// =====================================================================

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

// Per-device state allocated at Address Device time. Tuned to cover
// the kMaxXhciPortsPerController * kMaxControllers product so a real
// box with every port populated still fits.
inline constexpr u32 kMaxDevicesTotal = 32;

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
    // (SET_CONFIGURATION + Configure Endpoint succeeded).
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
    // for every v0 USB-net class (CDC-ECM, RTL8150, AX88xxx).
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

// =====================================================================
// File-scope globals — definitions live in xhci.cpp (one TU only).
// =====================================================================

extern constinit ControllerInfo g_controllers[kMaxControllers];
extern constinit u32 g_controller_count;
extern constinit bool g_init_done;
extern constinit DeviceState g_devices[kMaxDevicesTotal];
extern constinit u32 g_device_count;

// Per-controller poll-task arg + IRQ-routing state. The HID poll
// task in xhci.cpp blocks on `g_poll_args[i].wait`; the per-controller
// IRQ stubs in xhci_irq.cpp wake it. Runtime mirrors live in
// g_poll_rt[i] so the public xfer surface (XhciControlIn,
// XhciBulkSubmit, etc.) can reach the controller without going
// back through ControllerInfo.
struct PollTaskArg
{
    Runtime* rt;
    ControllerInfo* info;
    duetos::sched::WaitQueue wait;
    u8 irq_vector; // 0 == MSI-X not bound, polling fallback
};

extern constinit PollTaskArg g_poll_args[kMaxControllers];
extern constinit Runtime g_poll_rt[kMaxControllers];

// IRQ stamps. One C handler per controller so the generic
// IrqHandler signature (no context) can route to the right wait
// queue. XhciBindMsix indexes this table by controller-idx.
extern const ::duetos::arch::IrqHandler kXhciIrqStamps[kMaxControllers];

// =====================================================================
// Ring primitives (xhci_ring.cpp)
// =====================================================================

// Allocate one zeroed 4 KiB frame; return both phys + kernel-virtual
// pointer. False on out-of-memory.
bool AllocZeroPage(mm::PhysAddr* out_phys, void** out_virt);

// Wait for a u32 MMIO register to satisfy `(value & mask) == match`.
// Returns true if the predicate held within `iters` polls.
bool PollUntil(volatile u8* base, u64 reg_off, u32 mask, u32 match, u64 iters);

// Doorbell write. xHCI DB[0] rings the command ring; DB[slot_id]
// rings a device's endpoints. `target` is the DB Target field
// (bits 0..7); stream_id is 0 for non-stream endpoints.
void RingDoorbell(Runtime& rt, u32 db_index, u32 target, u32 stream_id = 0);

// Enqueue one TRB into a ring and return the physical address of
// the enqueued slot. Handles the Link TRB wrap automatically.
u64 EnqueueRingTrb(Trb* ring, u64 ring_phys, u32 slots, u32& idx, u32& cycle, u32 type, u32 param_lo, u32 param_hi,
                   u32 status, u32 extra_control);

// Submit one TRB on the command ring and ring DB[0]. Returns the
// TRB's physical address (used by callers to match the completion).
u64 SubmitCmd(Runtime& rt, u32 type, u32 param_lo, u32 param_hi, u32 status, u32 extra_control);

// Advance the consumer side of the event ring and push the updated
// dequeue pointer back to ERDP (with the event-handler-busy bit
// cleared — write-1-to-clear per spec).
void AdvanceEventRing(Runtime& rt);

// =====================================================================
// Event-ring waiters + side cache (xhci_event.cpp)
// =====================================================================

// Drain events until one whose TRB pointer equals `expect_phys` and
// whose type matches `expect_type` lands in the consumer slot.
// Irrelevant events are consumed + dropped (port-status changes,
// etc.). `out` captures the matching TRB by value. Returns false on
// timeout.
bool WaitEvent(Runtime& rt, u64 expect_phys, u32 expect_type, Trb* out, u64 iters);

// WaitEvent specialised for command-completion events. 4M iter cap.
bool WaitCmdCompletion(Runtime& rt, u64 expect_phys, u32* out_status, u8* out_slot_id);

// Side cache for Transfer Events that arrive on the ring but aren't
// for HID endpoints. HidPollEntry routes non-HID transfer completions
// here so bulk/control waiters can claim them by TRB pointer.
void TrbEventCacheStash(u64 trb_phys, u32 completion_code, u32 residual, u32 trb_len);
bool TrbEventCacheTake(u64 trb_phys, u32* completion_code, u32* residual, u32* trb_len);

// =====================================================================
// USB descriptor parsing (xhci_descparse.cpp)
// =====================================================================

// Walk a USB Configuration descriptor looking for the first HID
// Boot Keyboard / Mouse interface and its first interrupt-IN
// endpoint. `buf[0..len)` is the wTotalLength-bytes-long descriptor
// tree. Populates `port` fields iff a HID boot device is found.
// Returns true on found.
bool ParseConfigForHidBoot(const u8* buf, u32 len, PortRecord& port);

// =====================================================================
// Input Context builders (xhci_context.cpp)
// =====================================================================

// Build Input Context for Address Device. ctx_bytes is 32 or 64 per
// HCCPARAMS1.CSZ. Lays out [InputControl] [Slot] [EP0] in the
// caller's input_ctx_virt frame.
void BuildAddressDeviceInputContext(void* input_ctx_virt, u32 ctx_bytes, u8 port_num, u8 speed, u32 mps0,
                                    u64 ep0_ring_phys);

// Build a Configure Endpoint Input Context for adding ONE new
// endpoint on top of the EP0 context already established at
// Address Device time. Only the slot context (A0) and the new
// endpoint (A_dci) are flagged; A1 stays clear so the running EP0
// isn't reconfigured.
void BuildConfigureEndpointInputContext(void* input_ctx_virt, u32 ctx_bytes, u8 port_num, u8 speed, u8 new_dci,
                                        u32 new_ep_type, u32 new_mps, u32 new_interval, u64 new_ring_phys);

// =====================================================================
// Control transfers on EP0 (xhci_control.cpp)
// =====================================================================

// USB control-IN transfer on EP0. Builds Setup/Data/Status TRBs,
// rings DB[slot_id]/target=1, waits for the Status Stage transfer
// event. On success the device has written `wLength` bytes into
// `dev->scratch_virt`. `diag` is a short tag for failure-path log
// lines.
bool DoControlIn(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, u16 wLength,
                 const char* diag);

// USB control transfer with NO data stage. SET_CONFIGURATION,
// HID SET_PROTOCOL / SET_IDLE, etc.
bool DoControlNoData(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex,
                     const char* diag);

// USB control-OUT with optional data payload. Used by class
// drivers to push small bulk-class control requests (e.g. CDC-ECM
// SET_ETHERNET_MULTICAST_FILTERS).
bool ControlOutWithData(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex,
                        const void* buf, u16 len, const char* diag);

// =====================================================================
// Slot/endpoint accessors (xhci_xfer.cpp + xhci.cpp callers)
// =====================================================================

// Linear scan of g_devices for the entry whose slot_id matches.
// Returns nullptr on miss.
DeviceState* DeviceForSlot(u8 slot_id);

// Translate a USB bEndpointAddress into the xHCI Device Context
// Index (DCI). DCI = (ep_num * 2) + (direction == IN ? 1 : 0);
// EP0 occupies DCI 1 regardless of direction.
u8 EndpointDci(u8 ep_addr);

// Enqueue one Normal TRB on the device's HID interrupt-IN ring.
// IOC bit set so the completion lands as a Transfer Event the
// HID poll task can match against the previous report.
u64 HidEnqueueNormalTrb(DeviceState* dev, u64 buf_phys, u32 len);

// =====================================================================
// Device enumeration pipeline (xhci_enum.cpp)
// =====================================================================

// Volatile-byte zeroer — the freestanding toolchain has no libc
// memset and `x = {}` on a large struct lowers to a memset call
// the linker can't resolve.
void ZeroBytes(void* p, u64 n);

// Allocate the next free entry in g_devices, mark it in_use, bump
// g_device_count if we landed beyond the current high-water mark.
DeviceState* AllocDeviceSlot();

// Issue Enable Slot + Address Device for a freshly reset port.
// Allocates the device's slot, EP0 ring, input + device contexts,
// fetches the BOS speed-derived MPS0, populates dev->slot_id +
// dev->speed.
bool AddressDevice(Runtime& rt, PortRecord& port);

// GET_DESCRIPTOR(Device) on EP0; populates port->dev_class / etc.
bool FetchDeviceDescriptor(Runtime& rt, PortRecord& port);

// Two-phase Configuration descriptor fetch (header + full tree),
// then ParseConfigForHidBoot to find a HID Boot Keyboard / Mouse
// interface + interrupt-IN endpoint.
bool FetchAndParseConfig(Runtime& rt, PortRecord& port);

// USB SET_CONFIGURATION on EP0.
bool SetConfiguration(Runtime& rt, DeviceState* dev, u8 config_value);

// Stand up the HID Boot endpoint: allocate ring + buffer, issue
// Configure Endpoint, prime the first IN TRB, mark dev->hid_ready.
bool BringUpHidKeyboard(Runtime& rt, PortRecord& port);

} // namespace duetos::drivers::usb::xhci::internal
