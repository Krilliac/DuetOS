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

} // namespace duetos::drivers::usb::xhci::internal
