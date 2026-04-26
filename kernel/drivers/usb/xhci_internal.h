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

} // namespace duetos::drivers::usb::xhci::internal
