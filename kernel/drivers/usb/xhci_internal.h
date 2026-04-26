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

#include "../../core/types.h"

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

} // namespace duetos::drivers::usb::xhci::internal
